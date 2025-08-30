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

// Rate limiter
const limiter = rateLimit({ windowMs: 15*60*1000, max: 100 });
app.use(limiter);

// DB connection
const db = await mysql.createConnection({
  host: process.env.DB_HOST || "mysql-1a36101-botwii.c.aivencloud.com",
  user: process.env.DB_USER || "avnadmin",
  password: process.env.DB_PASSWORD || "AVNS_BvVULOCxM7CcMQd0Aqw",
  database: process.env.DB_NAME || "defaultdb",
  port: process.env.DB_PORT || 14721,
  ssl: { rejectUnauthorized: true }
});

// Google OAuth
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "855054001146-oo88bdvkb1e4hh386c2mjngk4s1mq7ff.apps.googleusercontent.com";
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

// JWT
const JWT_SECRET = process.env.JWT_SECRET || "super-secret-key";
const DUREE_TOKEN = "7d";

// --- CREATE TABLES ---
async function créerTables() {
  // USERS
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

  // SESSIONS
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

  // JWT BLACKLIST
  await db.execute(`
    CREATE TABLE IF NOT EXISTS token_blacklist (
      id INT AUTO_INCREMENT PRIMARY KEY,
      token VARCHAR(500),
      expired_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // COFFRE-FORT
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

  // API KEYS
  await db.execute(`
    CREATE TABLE IF NOT EXISTS api_keys (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT,
      api_key VARCHAR(255) UNIQUE,
      expires_at TIMESTAMP,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // SOCIAL TABLES
  await db.execute(`
    CREATE TABLE IF NOT EXISTS friends (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT,
      friend_id INT,
      status ENUM('pending','accepted','blocked') DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS messages (
      id INT AUTO_INCREMENT PRIMARY KEY,
      sender_id INT,
      receiver_id INT,
      content TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS guilds (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(255),
      description TEXT,
      owner_id INT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS guild_members (
      id INT AUTO_INCREMENT PRIMARY KEY,
      guild_id INT,
      user_id INT,
      role ENUM('member','officer','leader') DEFAULT 'member',
      joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // GAME TABLES
  await db.execute(`
    CREATE TABLE IF NOT EXISTS achievements (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT,
      title VARCHAR(255),
      description TEXT,
      unlocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS leaderboard (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT,
      score INT DEFAULT 0,
      rank INT DEFAULT 0,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS shop_items (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(255),
      description TEXT,
      price DECIMAL(10,2),
      rarity ENUM('common','rare','epic','legendary') DEFAULT 'common',
      available BOOLEAN DEFAULT TRUE
    )
  `);

  // AI LLM TABLES
  await db.execute(`
    CREATE TABLE IF NOT EXISTS logs_ai (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT,
      prompt TEXT,
      response TEXT,
      model VARCHAR(255),
      tokens_used INT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS models (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(255),
      provider VARCHAR(255),
      version VARCHAR(50),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  console.log("✅ Full Start tables créées !");
}

await créerTables();

// --- AUTH MIDDLEWARE ---
const verifierToken = async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ erreur: "Authentification requise" });

  // Vérifie blacklist
  const [blacklist] = await db.execute("SELECT * FROM token_blacklist WHERE token = ?", [token]);
  if(blacklist.length > 0) return res.status(403).json({ erreur: "Token invalide ou expiré" });

  jwt.verify(token, JWT_SECRET, (err, utilisateur) => {
    if(err) return res.status(403).json({ erreur: "Token invalide" });
    req.utilisateur = utilisateur;
    next();
  });
};

// --- ROUTES AUTH ---

// Inscription
app.post("/inscription",
  body("email").isEmail(),
  body("password").isLength({ min: 8 }),
  body("username").notEmpty(),
  async (req, res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()) return res.status(400).json({ erreurs: errors.array() });

    try {
      const { email, password, username } = req.body;
      const hashed = await bcrypt.hash(password, 10);
      await db.execute("INSERT INTO users (email,password,username) VALUES (?,?,?)", [email, hashed, username]);
      res.json({ message: "✅ Compte créé !" });
    } catch(err) {
      res.status(400).json({ erreur: err.message });
    }
  }
);

// Connexion email
app.post("/connexion", async (req, res) => {
  const { email, password } = req.body;
  const [rows] = await db.execute("SELECT * FROM users WHERE email = ?", [email]);
  if(rows.length === 0) return res.status(400).json({ erreur: "Utilisateur non trouvé" });

  const valid = await bcrypt.compare(password, rows[0].password);
  if(!valid) return res.status(400).json({ erreur: "Mot de passe incorrect" });

  const token = jwt.sign({ id: rows[0].id }, JWT_SECRET, { expiresIn: DUREE_TOKEN });
  res.json({ message: "✅ Connecté !", token });
});

// Connexion Google
app.post("/connexion-google", async (req,res)=>{
  const { tokenId } = req.body;
  try {
    const ticket = await client.verifyIdToken({ idToken: tokenId, audience: GOOGLE_CLIENT_ID });
    const { sub: googleId, email, name, picture } = ticket.getPayload();
    let [rows] = await db.execute("SELECT * FROM users WHERE googleId = ?", [googleId]);
    if(rows.length === 0){
      await db.execute("INSERT INTO users (email, googleId, username, avatar, status) VALUES (?,?,?,?,?)", [email, googleId, name, picture, "en_ligne"]);
      [rows] = await db.execute("SELECT * FROM users WHERE googleId = ?", [googleId]);
    }
    const token = jwt.sign({ id: rows[0].id }, JWT_SECRET, { expiresIn: DUREE_TOKEN });
    res.json({ message: "✅ Connecté avec Google", token, utilisateur: rows[0] });
  } catch(err){
    res.status(400).json({ erreur: "Échec Google", details: err.message });
  }
});

// --- ROUTES PROTÉGÉES ---
app.use("/api", verifierToken);

// Générer API Key
app.post("/api/generer-cle", async (req,res)=>{
  const apiKey = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(); expiresAt.setFullYear(expiresAt.getFullYear()+1);
  await db.execute("INSERT INTO api_keys (user_id, api_key, expires_at) VALUES (?,?,?)", [req.utilisateur.id, apiKey, expiresAt]);
  res.json({ message: "✅ Clé API générée", apiKey });
});

// Ajouter transaction au coffre
app.post("/api/coffre/ajouter", async (req,res)=>{
  const { amount, currency, type, details } = req.body;
  await db.execute("INSERT INTO coffre_fort (user_id, amount, currency, type, details) VALUES (?,?,?,?,?)",
    [req.utilisateur.id, amount, currency, type, JSON.stringify(details)]);
  res.json({ message: "✅ Transaction ajoutée au coffre" });
});

// Consulter coffre
app.get("/api/coffre", async (req,res)=>{
  const [rows] = await db.execute("SELECT * FROM coffre_fort WHERE user_id = ?", [req.utilisateur.id]);
  res.json(rows);
});

// Lancer serveur
const PORT = process.env.PORT || 3000;
app.listen(PORT,()=>console.log(`🚀 Server Full Start running on http://localhost:${PORT}`));
