import express from "express";
import mysql from "mysql2/promise";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { OAuth2Client } from "google-auth-library";
import crypto from "crypto";

const app = express();
app.use(express.json());

// DB connection
const db = await mysql.createConnection({
  host: "mysql-1a36101-botwii.c.aivencloud.com",
  user: "avnadmin",
  password: "AVNS_BvVULOCxM7CcMQd0Aqw",
  database: "defaultdb",
  port: 14721,
  ssl: { rejectUnauthorized: true }
});

// Google OAuth
const GOOGLE_CLIENT_ID = "855054001146-oo88bdvkb1e4hh386c2mjngk4s1mq7ff.apps.googleusercontent.com";
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

// JWT secret
const JWT_SECRET = "super-secret-key"; // change this in production

// --- CREATE TABLES ---
async function createTables() {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(255) UNIQUE,
      password VARCHAR(255),
      username VARCHAR(255),
      googleId VARCHAR(255),
      avatar TEXT,
      status ENUM('online','offline','busy','away') DEFAULT 'offline',
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
      currency VARCHAR(10) DEFAULT 'USD',
      type ENUM('subscription','purchase','gift','other') DEFAULT 'other',
      status ENUM('pending','completed','failed') DEFAULT 'pending',
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

  console.log("✅ Tables principales créées !");
}

await createTables();

// --- REGISTER EMAIL ---
app.post("/register", async (req, res) => {
  const { email, password, username } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    await db.execute("INSERT INTO users (email, password, username) VALUES (?,?,?)", [email, hashedPassword, username]);
    res.json({ message: "✅ Compte créé !" });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// --- LOGIN EMAIL ---
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const [rows] = await db.execute("SELECT * FROM users WHERE email = ?", [email]);
  if(rows.length === 0) return res.status(400).json({ error: "Utilisateur introuvable" });

  const user = rows[0];
  const valid = await bcrypt.compare(password, user.password);
  if(!valid) return res.status(400).json({ error: "Mot de passe incorrect" });

  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ message: "✅ Connecté !", token });
});

// --- GOOGLE LOGIN ---
app.post("/google-login", async (req, res) => {
  const { tokenId } = req.body;
  try {
    const ticket = await client.verifyIdToken({ idToken: tokenId, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const { sub: googleId, email, name, picture } = payload;

    let [rows] = await db.execute("SELECT * FROM users WHERE googleId = ?", [googleId]);
    if(rows.length === 0){
      await db.execute(
        "INSERT INTO users (email, googleId, username, avatar, status) VALUES (?,?,?,?,?)",
        [email, googleId, name, picture, "online"]
      );
      [rows] = await db.execute("SELECT * FROM users WHERE googleId = ?", [googleId]);
    }

    const user = rows[0];
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ message: "✅ Connecté avec Google", token, user });
  } catch(err) {
    res.status(400).json({ error: "Google login échoué", details: err.message });
  }
});

// --- GENERATE API KEY ---
app.post("/generate-api-key", async (req, res) => {
  const { userId } = req.body;
  const apiKey = crypto.randomBytes(32).toString("hex");

  await db.execute("INSERT INTO api_keys (user_id, api_key) VALUES (?, ?)", [userId, apiKey]);
  res.json({ message: "✅ API Key générée", apiKey });
});

// --- ADD TRANSACTION TO COFFRE ---
app.post("/coffre/add", async (req, res) => {
  const { userId, amount, currency, type, details } = req.body;

  await db.execute(
    "INSERT INTO coffre_fort (user_id, amount, currency, type, details, status) VALUES (?, ?, ?, ?, ?, 'pending')",
    [userId, amount, currency, type, JSON.stringify(details)]
  );

  res.json({ message: "✅ Transaction ajoutée au coffre-fort" });
});

// --- GET COFFRE ---
app.get("/coffre/:userId", async (req, res) => {
  const { userId } = req.params;
  const [rows] = await db.execute("SELECT * FROM coffre_fort WHERE user_id = ?", [userId]);
  res.json(rows);
});

app.listen(3000, () => console.log("🚀 Server running on http://localhost:3000"));
