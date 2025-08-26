import express from "express";
import bodyParser from "body-parser";
import mysql from "mysql2/promise";
import cors from "cors";
import dotenv from "dotenv";
import fetch from "node-fetch";
import path from 'path';
import { fileURLToPath } from 'url';

// --- CONFIGURATION INITIALE ---
dotenv.config();

const app = express();

// Middlewares
app.use(cors());
app.use(bodyParser.json());

// --- CONNEXIONS EXTERNES (BASE DE DONNÉES & IA) ---

// Connexion sécurisée à la DB
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    port: process.env.DB_PORT,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    ssl: { rejectUnauthorized: false }
});

// --- FONCTIONS UTILITAIRES ---

// Fonction pour sécuriser les noms de table
const sanitizeTableName = (name) => {
    return name.replace(/[^a-zA-Z0-9_]/g, '_');
};

// Fonction pour créer une table de connaissance si elle n'existe pas
const createKnowledgeTable = async (tableName) => {
    const sanitizedTableName = sanitizeTableName(tableName);
    const query = `
        CREATE TABLE IF NOT EXISTS ${sanitizedTableName} (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(255) NOT NULL UNIQUE,
            content TEXT,
            context TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )`;
    await pool.execute(query);
    console.log(`Table '${sanitizedTableName}' vérifiée ou créée.`);
    return sanitizedTableName;
};

// --- ROUTES DE L'API ---

// Vercel a besoin d'un point d'entrée pour les requêtes HTTP, donc nous définissons les routes directement sur l'objet app.

app.post("/api/ask", async (req, res) => {
    const { question } = req.body;
    if (!question) {
        return res.status(400).json({ reply: "❌ Une question est requise !" });
    }

    try {
        const [tables] = await pool.query("SHOW TABLES");
        for (const table of tables) {
            const tableName = Object.values(table)[0];
            if (tableName === 'knowledge' || tableName === 'learn_queue') continue;

            const [rows] = await pool.execute(`SELECT content FROM ${tableName} WHERE title = ? LIMIT 1`, [question]);
            if (rows.length > 0) {
                console.log(`💡 Réponse trouvée dans la DB (Table: ${tableName})`);
                return res.json({ reply: rows[0].content });
            }
        }

        try {
            console.log("🧠 Réponse non trouvée en local, appel du modèle Hugging Face...");
            const localAIEndpoint = "http://localhost:5000/generate";
            const response = await fetch(localAIEndpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ prompt: question }),
            });

            if (!response.ok) {
                throw new Error(`Erreur HTTP: ${response.status}`);
            }

            const data = await response.json();
            const text = data.generated_text;

            await createKnowledgeTable('general');
            const sql = `INSERT INTO general (title, content) VALUES (?, ?) ON DUPLICATE KEY UPDATE content = ?`;
            await pool.execute(sql, [question, text, text]);
            console.log("📚 Auto-apprentissage réussi !");

            return res.json({ reply: text });
        } catch (apiError) {
            console.error("❌ Erreur lors de l'appel au modèle Hugging Face local:", apiError.message);
            const fallbackMessage = "Je n'ai pas trouvé la réponse et mon intelligence locale est indisponible.";
            return res.status(503).json({ reply: fallbackMessage });
        }

    } catch (dbError) {
        console.error("❌ Erreur serveur sur /api/ask :", dbError);
        res.status(500).json({ reply: "⚠️ Une erreur est survenue sur le serveur." });
    }
});

app.post("/api/teach", async (req, res) => {
    let { question, answer, category } = req.body;
    if (!question || !answer || !category) {
        return res.status(400).json({ reply: "❌ Question, réponse et catégorie sont requises !" });
    }

    try {
        const tableName = await createKnowledgeTable(category);

        const sql = `
            INSERT INTO ${tableName} (title, content) VALUES (?, ?)
            ON DUPLICATE KEY UPDATE content = ?, updated_at = NOW()
        `;
        await pool.execute(sql, [question, answer, answer]);

        res.status(201).json({ reply: `✅ Mangrat a appris cette connaissance dans la catégorie '${tableName}' !` });
    } catch (err) {
        console.error("❌ Erreur serveur sur /api/teach :", err);
        res.status(500).json({ reply: "⚠️ Une erreur est survenue lors de l'apprentissage." });
    }
});

// Vercel ne gère pas les fichiers statiques de la même manière que Express.
// Pour servir une page HTML, vous devez la placer dans un dossier `public`
// et Vercel la servira automatiquement. La route `/admin` ne sera donc plus nécessaire
// pour servir le fichier.
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(path.join(__dirname, 'public')));

// Ceci est l'export principal que Vercel utilisera.
export default app;
