// Server.js - Version Ultra Boostée

import express from "express";
import bodyParser from "body-parser";
import mysql from "mysql2/promise";
import cors from "cors";
import dotenv from "dotenv";
import { GoogleGenerativeAI } from "@google/generative-ai";
import path from 'path';
import { fileURLToPath } from 'url';

// --- CONFIGURATION INITIALE ---
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration pour servir les fichiers statiques (HTML, CSS)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(path.join(__dirname, 'public')));

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

// Initialisation du client Google Gemini AI
let genAI;
if (process.env.GEMINI_API_KEY) {
    genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
    console.log("✅ Client Google Gemini AI initialisé.");
} else {
    console.warn("⚠️ Clé API Gemini non trouvée. Le mode IA est désactivé.");
}


// --- FONCTIONS UTILITAIRES ---

// Fonction pour sécuriser les noms de table
const sanitizeTableName = (name) => {
    // Garde uniquement les lettres, chiffres et remplace les espaces/caractères spéciaux par _
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

// Route pour l'interface d'administration
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Route POST /ask (avec fallback)
app.post("/ask", async (req, res) => {
    const { question } = req.body;
    if (!question) {
        return res.status(400).json({ reply: "❌ Une question est requise !" });
    }

    try {
        // Étape 1 : Chercher dans TOUTES les tables de la DB une correspondance
        const [tables] = await pool.query("SHOW TABLES");
        for (const table of tables) {
            const tableName = Object.values(table)[0];
            // On exclut les tables de service
            if (tableName === 'knowledge' || tableName === 'learn_queue') continue;

            const [rows] = await pool.execute(`SELECT content FROM ${tableName} WHERE title = ? LIMIT 1`, [question]);
            if (rows.length > 0) {
                console.log(`💡 Réponse trouvée dans la DB (Table: ${tableName})`);
                return res.json({ reply: rows[0].content });
            }
        }

        // Étape 2 : Si rien dans la DB, appeler l'IA (si la clé est configurée)
        if (genAI) {
            try {
                console.log("🧠 Réponse non trouvée en local, appel de l'IA Gemini...");
                const model = genAI.getGenerativeModel({ model: "gemini-pro" });
                const result = await model.generateContent(question);
                const response = result.response;
                const text = response.text();
                
                // Auto-apprentissage : on stocke la nouvelle réponse dans la catégorie "general"
                await createKnowledgeTable('general');
                const sql = `INSERT INTO general (title, content) VALUES (?, ?) ON DUPLICATE KEY UPDATE content = ?`;
                await pool.execute(sql, [question, text, text]);
                console.log("📚 Auto-apprentissage réussi !");

                return res.json({ reply: text });
            } catch (apiError) {
                // Étape 3 : Si l'API échoue (crédits épuisés, etc.), utiliser le fallback
                console.error("❌ Erreur API Gemini:", apiError.message);
                const fallbackMessage = "Je n'ai pas trouvé la réponse dans ma mémoire et je ne peux pas chercher plus loin pour le moment. Mon intelligence externe est peut-être indisponible.";
                return res.status(503).json({ reply: fallbackMessage });
            }
        } else {
             // Étape 4 : Si pas de clé API du tout
             const fallbackMessage = "Je ne connais pas la réponse et mon intelligence externe n'est pas configurée.";
             return res.status(404).json({ reply: fallbackMessage });
        }

    } catch (dbError) {
        console.error("❌ Erreur serveur sur /ask :", dbError);
        res.status(500).json({ reply: "⚠️ Une erreur est survenue sur le serveur." });
    }
});

// Route POST /teach (avec création de table dynamique)
app.post("/teach", async (req, res) => {
    let { question, answer, category } = req.body;
    if (!question || !answer || !category) {
        return res.status(400).json({ reply: "❌ Question, réponse et catégorie sont requises !" });
    }

    try {
        // Crée la table pour la catégorie si elle n'existe pas
        const tableName = await createKnowledgeTable(category);

        const sql = `
            INSERT INTO ${tableName} (title, content) VALUES (?, ?)
            ON DUPLICATE KEY UPDATE content = ?, updated_at = NOW()
        `;
        await pool.execute(sql, [question, answer, answer]);

        res.status(201).json({ reply: `✅ Mangrat a appris cette connaissance dans la catégorie '${tableName}' !` });
    } catch (err) {
        console.error("❌ Erreur serveur sur /teach :", err);
        res.status(500).json({ reply: "⚠️ Une erreur est survenue lors de l'apprentissage." });
    }
});

// --- DÉMARRAGE DU SERVEUR ---
app.listen(PORT, () => {
    console.log(`🚀 Mangrat Server est lancé sur http://localhost:${PORT}`);
    console.log(`👉 Interface Admin disponible sur http://localhost:${PORT}/admin`);
});
