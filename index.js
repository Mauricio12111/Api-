import express from "express";
import mysql from "mysql2/promise";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { OAuth2Client } from "google-auth-library";
import crypto from "crypto";
import dotenv from "dotenv";
import rateLimit from "express-rate-limit";
import { body, validationResult } from "express-validator";

dotenv.config();

const app = express();
app.use(express.json());

const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW || "900000"),
  max: parseInt(process.env.RATE_LIMIT_MAX || "100")
});
app.use(limiter);

const db = await mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: parseInt(process.env.DB_PORT || "3306"),
  ssl: { rejectUnauthorized: true }
});

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

const JWT_SECRET = process.env.JWT_SECRET;
const DUREE_TOKEN = process.env.DUREE_TOKEN || "7d";

async function créerTables() {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(255) UNIQUE,
      password VARCHAR(255),
      username VARCHAR(255),
      googleId VARCHAR(255),
      avatar TEXT,
      status ENUM('en_ligne','hors_ligne','occupé','absent') DEFAULT 'hors_ligne',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await db.execute(`
    CREATE TABLE IF NOT EXISTS sessions (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT,
      token VARCHAR(500),
      ip_address VARCHAR(100),
      device VARCHAR(100),
      expires_at TIMESTAMP,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await db.execute(`
    CREATE TABLE IF NOT EXISTS coffre_fort (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT,
      amount DECIMAL(10,2),
      currency VARCHAR(10) DEFAULT 'EUR',
      type ENUM('abonnement','achat','cadeau','autre') DEFAULT 'autre',
      status ENUM('en_attente','complété','échoué') DEFAULT 'en_attente',
      details JSON,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await db.execute(`
    CREATE TABLE IF NOT EXISTS api_keys (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT,
      api_key VARCHAR(255) UNIQUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  console.log("Tables créées avec succès!");
}

await créerTables();

const verifierToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ erreur: "Authentification requise" });
  jwt.verify(token, JWT_SECRET, (err, utilisateur) => {
    if (err) return res.status(403).json({ erreur: "Token invalide" });
    req.utilisateur = utilisateur;
    next();
  });
};

app.post("/inscription", async (req, res) => {
  try {
    const { email, password, username } = req.body;
    const motDePasseHashé = await bcrypt.hash(password, parseInt(process.env.PASSWORD_HASH_ROUNDS || "10"));
    await db.execute("INSERT INTO users (email, password, username) VALUES (?,?,?)", [email, motDePasseHashé, username]);
    res.json({ message: "Compte créé avec succès!" });
  } catch (err) {
    res.status(400).json({ erreur: "Erreur lors de l'inscription", details: err.message });
  }
});

app.post("/connexion", async (req, res) => {
  try {
    const { email, password } = req.body;
    const [utilisateurs] = await db.execute("SELECT * FROM users WHERE email = ?", [email]);
    if (utilisateurs.length === 0) return res.status(400).json({ erreur: "Utilisateur non trouvé" });
    const utilisateur = utilisateurs[0];
    const validPassword = await bcrypt.compare(password, utilisateur.password);
    if (!validPassword) return res.status(400).json({ erreur: "Mot de passe incorrect" });
    const token = jwt.sign({ id: utilisateur.id }, JWT_SECRET, { expiresIn: DUREE_TOKEN });
    res.json({ message: "Connexion réussie!", token });
  } catch (err) {
    res.status(500).json({ erreur: "Erreur de connexion", details: err.message });
  }
});

app.post("/connexion-google", async (req, res) => {
  try {
    const { tokenId } = req.body;
    const ticket = await client.verifyIdToken({ idToken: tokenId, audience: GOOGLE_CLIENT_ID });
    const { sub: googleId, email, name, picture } = ticket.getPayload();
    let [utilisateurs] = await db.execute("SELECT * FROM users WHERE googleId = ?", [googleId]);
    if (utilisateurs.length === 0) {
      await db.execute("INSERT INTO users (email, googleId, username, avatar, status) VALUES (?,?,?,?,?)", [email, googleId, name, picture, "en_ligne"]);
      [utilisateurs] = await db.execute("SELECT * FROM users WHERE googleId = ?", [googleId]);
    }
    const token = jwt.sign({ id: utilisateurs[0].id }, JWT_SECRET, { expiresIn: DUREE_TOKEN });
    res.json({ message: "Connexion Google réussie!", token, utilisateur: utilisateurs[0] });
  } catch (err) {
    res.status(400).json({ erreur: "Échec de la connexion Google", details: err.message });
  }
});

app.use("/api", verifierToken);

app.post("/api/generer-cle", async (req, res) => {
  try {
    const userId = req.utilisateur.id;
    const apiKey = crypto.randomBytes(parseInt(process.env.API_KEY_LENGTH || "32")).toString("hex");
    await db.execute("INSERT INTO api_keys (user_id, api_key) VALUES (?, ?)", [userId, apiKey]);
    res.json({ message: "Clé API générée avec succès", apiKey });
  } catch (err) {
    res.status(500).json({ erreur: "Erreur lors de la génération de la clé API" });
  }
});

app.post("/api/coffre/ajouter", async (req, res) => {
  try {
    const { amount, currency, type, details } = req.body;
    const userId = req.utilisateur.id;
    await db.execute("INSERT INTO coffre_fort (user_id, amount, currency, type, details) VALUES (?, ?, ?, ?, ?)", [userId, amount, currency, type, JSON.stringify(details)]);
    res.json({ message: "Transaction ajoutée au coffre-fort" });
  } catch (err) {
    res.status(500).json({ erreur: "Erreur lors de l'ajout de la transaction" });
  }
});

app.get("/api/coffre", async (req, res) => {
  try {
    const userId = req.utilisateur.id;
    const [transactions] = await db.execute("SELECT * FROM coffre_fort WHERE user_id = ?", [userId]);
    res.json(transactions);
  } catch (err) {
    res.status(500).json({ erreur: "Erreur lors de la consultation du coffre-fort" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serveur démarré sur http://localhost:${PORT}`));
