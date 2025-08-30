import express from "express";
import cors from "cors";
import mysql from "mysql2/promise";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { OAuth2Client } from "google-auth-library";
import crypto from "crypto";
import dotenv from "dotenv";
import rateLimit from "express-rate-limit";
import { body, validationResult } from "express-validator";

dotenv.config();

/* ====== CONFIG ====== */
const app = express();
app.use(express.json());
app.set("trust proxy", 1); // Render/Proxies

// CORS (origines multiples via env, sinon tout autorisé en dev)
const ALLOWED_ORIGINS = (process.env.CORS_ORIGINS || "*")
  .split(",")
  .map(s => s.trim());
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin || ALLOWED_ORIGINS.includes("*") || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      return cb(new Error("Origin not allowed by CORS"));
    },
    credentials: true
  })
);

// Rate limit global
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW || "900000", 10), // 15 min
  max: parseInt(process.env.RATE_LIMIT_MAX || "100", 10)
});
app.use(limiter);

// Rate limit plus strict pour l’auth
const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20,
  message: { error: "Trop de tentatives, réessayez plus tard." }
});

const PORT = parseInt(process.env.PORT || "3000", 10);
const JWT_SECRET = process.env.JWT_SECRET || "change-me";
const TOKEN_TTL = process.env.DUREE_TOKEN || "7d";
const HASH_ROUNDS = parseInt(process.env.PASSWORD_HASH_ROUNDS || "10", 10);
const API_KEY_LENGTH = parseInt(process.env.API_KEY_LENGTH || "32", 10);
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

/* ====== DB CONNEXION ====== */
let db;
async function connectDB() {
  db = await mysql.createConnection({
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT || "3306", 10),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: {
      // Aiven utilise un cert auto-signé. Permettre le handshake si false.
      rejectUnauthorized: process.env.DB_SSL_REJECT_UNAUTHORIZED !== "false"
    }
  });
  console.log("✅ Connecté à MySQL");
}
await connectDB();

/* ====== CRÉATION DES TABLES ====== */
async function createTables() {
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
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      INDEX (user_id),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS coffre_fort (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      amount DECIMAL(10,2) NOT NULL,
      currency VARCHAR(10) DEFAULT 'EUR',
      type ENUM('abonnement','achat','cadeau','autre') DEFAULT 'autre',
      status ENUM('en_attente','complété','échoué') DEFAULT 'en_attente',
      details JSON,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      INDEX (user_id),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS api_keys (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      api_key VARCHAR(255) UNIQUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      INDEX (user_id),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT,
      action VARCHAR(255),
      details JSON,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      INDEX (user_id),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    )
  `);

  console.log("🗄️ Tables vérifiées/créées");
}
await createTables();

/* ====== HELPERS ====== */
function signToken(userId) {
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: TOKEN_TTL });
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Authentification requise" });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = { id: payload.id };
    next();
  } catch {
    return res.status(403).json({ error: "Token invalide" });
  }
}

async function logAction(userId, action, details = {}) {
  try {
    await db.execute(
      "INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)",
      [userId || null, action, JSON.stringify(details)]
    );
  } catch (e) {
    console.warn("Audit log error:", e.message);
  }
}

/* ====== ROUTES PUBLIQUES ====== */
app.get("/", (req, res) => {
  res.json({ ok: true, service: "GamerHubX API", version: "1.0.0" });
});

app.get("/health", async (req, res) => {
  try {
    const [rows] = await db.query("SELECT NOW() AS now");
    res.json({ status: "ok", now: rows[0].now });
  } catch (e) {
    res.status(500).json({ status: "db_error", error: e.message });
  }
});

/* ====== AUTH ====== */
// Inscription
app.post(
  "/inscription",
  authLimiter,
  body("email").isEmail().withMessage("Email invalide"),
  body("password").isLength({ min: 6 }).withMessage("Mot de passe trop court"),
  body("username").isLength({ min: 3, max: 32 }).withMessage("Username invalide"),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { email, password, username } = req.body;
    try {
      const hash = await bcrypt.hash(password, HASH_ROUNDS);
      await db.execute(
        "INSERT INTO users (email, password, username, status) VALUES (?, ?, ?, 'en_ligne')",
        [email, hash, username]
      );

      const [[user]] = await db.query("SELECT * FROM users WHERE email = ?", [email]);
      const token = signToken(user.id);

      // session
      await db.execute(
        "INSERT INTO sessions (user_id, token, ip_address, device, expires_at) VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 7 DAY))",
        [user.id, token, req.ip || null, req.get("User-Agent") || null]
      );

      await logAction(user.id, "register", { email, username });
      res.json({ message: "Compte créé", token, user: { id: user.id, email, username } });
    } catch (e) {
      if (e && e.code === "ER_DUP_ENTRY") {
        return res.status(409).json({ error: "Email ou username déjà utilisé" });
      }
      res.status(500).json({ error: "Erreur inscription", details: e.message });
    }
  }
);

// Connexion email
app.post(
  "/connexion",
  authLimiter,
  body("email").isEmail(),
  body("password").isLength({ min: 6 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { email, password } = req.body;
    try {
      const [rows] = await db.execute("SELECT * FROM users WHERE email = ?", [email]);
      if (!rows.length) return res.status(400).json({ error: "Utilisateur introuvable" });

      const user = rows[0];
      if (!user.password) return res.status(400).json({ error: "Compte lié à Google, utilisez Google" });

      const ok = await bcrypt.compare(password, user.password);
      if (!ok) return res.status(400).json({ error: "Mot de passe incorrect" });

      const token = signToken(user.id);
      await db.execute(
        "INSERT INTO sessions (user_id, token, ip_address, device, expires_at) VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 7 DAY))",
        [user.id, token, req.ip || null, req.get("User-Agent") || null]
      );
      await logAction(user.id, "login_email");
      res.json({ message: "Connexion réussie", token, user: { id: user.id, email: user.email, username: user.username } });
    } catch (e) {
      res.status(500).json({ error: "Erreur de connexion", details: e.message });
    }
  }
);

// Connexion Google
app.post("/connexion-google", authLimiter, async (req, res) => {
  try {
    if (!googleClient) return res.status(500).json({ error: "GOOGLE_CLIENT_ID non configuré" });

    const { tokenId } = req.body;
    if (!tokenId) return res.status(400).json({ error: "tokenId requis" });

    const ticket = await googleClient.verifyIdToken({
      idToken: tokenId,
      audience: GOOGLE_CLIENT_ID
    });
    const payload = ticket.getPayload();
    const { sub: googleId, email, name, picture } = payload;

    let [rows] = await db.execute("SELECT * FROM users WHERE googleId = ?", [googleId]);

    if (!rows.length) {
      await db.execute(
        "INSERT INTO users (email, googleId, username, avatar, status) VALUES (?,?,?,?, 'en_ligne')",
        [email, googleId, name || null, picture || null]
      );
      [rows] = await db.execute("SELECT * FROM users WHERE googleId = ?", [googleId]);
    }

    const user = rows[0];
    const token = signToken(user.id);
    await db.execute(
      "INSERT INTO sessions (user_id, token, ip_address, device, expires_at) VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 7 DAY))",
      [user.id, token, req.ip || null, req.get("User-Agent") || null]
    );
    await logAction(user.id, "login_google");
    res.json({ message: "Connexion Google réussie", token, user: { id: user.id, email: user.email, username: user.username, avatar: user.avatar } });
  } catch (e) {
    res.status(400).json({ error: "Échec connexion Google", details: e.message });
  }
});

/* ====== ROUTES PROTÉGÉES ====== */
app.use("/api", authMiddleware);

// Générer une clé API
app.post("/api/generer-cle", async (req, res) => {
  try {
    const apiKey = crypto.randomBytes(API_KEY_LENGTH).toString("hex"); // 32 bytes -> 64 chars
    await db.execute("INSERT INTO api_keys (user_id, api_key) VALUES (?, ?)", [req.user.id, apiKey]);
    await logAction(req.user.id, "api_key_generate");
    res.json({ message: "Clé API générée", apiKey });
  } catch (e) {
    if (e && e.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ error: "Vous avez déjà une clé (ou collision rare)" });
    }
    res.status(500).json({ error: "Erreur génération clé", details: e.message });
  }
});

// Ajouter une transaction au coffre-fort
app.post(
  "/api/coffre/ajouter",
  body("amount").isFloat({ gt: 0 }).withMessage("Montant invalide"),
  body("currency").optional().isString().isLength({ min: 3, max: 10 }),
  body("type").optional().isIn(["abonnement", "achat", "cadeau", "autre"]),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { amount, currency = "EUR", type = "autre", details = {} } = req.body;
    try {
      await db.execute(
        "INSERT INTO coffre_fort (user_id, amount, currency, type, status, details) VALUES (?, ?, ?, ?, 'en_attente', ?)",
        [req.user.id, amount, currency, type, JSON.stringify(details)]
      );
      await logAction(req.user.id, "vault_add", { amount, currency, type });
      res.json({ message: "Transaction ajoutée au coffre-fort" });
    } catch (e) {
      res.status(500).json({ error: "Erreur ajout coffre", details: e.message });
    }
  }
);

// Lister les transactions du coffre-fort
app.get("/api/coffre", async (req, res) => {
  try {
    const [rows] = await db.execute(
      "SELECT id, amount, currency, type, status, details, created_at FROM coffre_fort WHERE user_id = ? ORDER BY id DESC",
      [req.user.id]
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: "Erreur lecture coffre", details: e.message });
  }
});

// Profil
app.get("/api/me", async (req, res) => {
  try {
    const [[me]] = await db.query(
      "SELECT id, email, username, avatar, status, created_at FROM users WHERE id = ?",
      [req.user.id]
    );
    res.json(me || {});
  } catch (e) {
    res.status(500).json({ error: "Erreur profil", details: e.message });
  }
});

/* ====== HANDLERS ====== */
app.use((req, res) => res.status(404).json({ error: "Route introuvable" }));
app.use((err, req, res, next) => {
  console.error("Erreur serveur:", err);
  res.status(500).json({ error: "Erreur serveur" });
});

/* ====== START ====== */
app.listen(PORT, () => {
  console.log(`🚀 Serveur démarré sur http://localhost:${PORT}`);
});
