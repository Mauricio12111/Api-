import express from "express";
import cors from "cors";
import pg from "pg";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { OAuth2Client } from "google-auth-library";
import crypto from "crypto";
import rateLimit from "express-rate-limit";
import { body, validationResult } from "express-validator";

/* ====== CONFIG ====== */
const app = express();
app.use(express.json());
app.set("trust proxy", 1);

// CORS
const ALLOWED_ORIGINS = ["*"];
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin || ALLOWED_ORIGINS.includes("*") || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      return cb(new Error("Origin not allowed by CORS"));
    },
    credentials: true,
  })
);

// Rate limit global
const limiter = rateLimit({
  windowMs: 900000,
  max: 100
});
app.use(limiter);

// Rate limit plus strict pour l’auth
const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20,
  message: { error: "Trop de tentatives, réessayez plus tard." }
});

const PORT = 3000;
const JWT_SECRET = "super-secret-key";
const TOKEN_TTL = "7d";
const HASH_ROUNDS = 10;
const API_KEY_LENGTH = 32;
const GOOGLE_CLIENT_ID = "855054001146-oo88bdvkb1e4hh386c2mjngk4s1mq7ff.apps.googleusercontent.com";
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

// Connexion PostgreSQL
const DB_CONNECTION_STRING = "postgres://avnadmin:AVNS_BvVULOCxM7CcMQd0Aqw@mysql-1a36101-botwii.c.aivencloud.com:14721/defaultdb?sslmode=require";
const DB_SSL_REJECT_UNAUTHORIZED = false;

/* ====== DB CONNEXION ====== */
let db;
async function connectDB() {
  db = new pg.Client({
    connectionString: DB_CONNECTION_STRING,
    ssl: {
      rejectUnauthorized: DB_SSL_REJECT_UNAUTHORIZED,
    },
  });
  await db.connect();
  console.log("✅ Connecté à PostgreSQL");
}
await connectDB();

/* ====== CRÉATION DES TABLES ====== */
async function createTables() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email VARCHAR(255) UNIQUE,
      password VARCHAR(255),
      username VARCHAR(255),
      google_id VARCHAR(255),
      avatar TEXT,
      status VARCHAR(50) DEFAULT 'hors_ligne',
      created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      id SERIAL PRIMARY KEY,
      user_id INT,
      token VARCHAR(500),
      ip_address VARCHAR(100),
      device VARCHAR(100),
      expires_at TIMESTAMP WITH TIME ZONE,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS coffre_fort (
      id SERIAL PRIMARY KEY,
      user_id INT NOT NULL,
      amount DECIMAL(10,2) NOT NULL,
      currency VARCHAR(10) DEFAULT 'EUR',
      type VARCHAR(50) DEFAULT 'autre',
      status VARCHAR(50) DEFAULT 'en_attente',
      details JSONB,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS api_keys (
      id SERIAL PRIMARY KEY,
      user_id INT NOT NULL,
      api_key VARCHAR(255) UNIQUE,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id SERIAL PRIMARY KEY,
      user_id INT,
      action VARCHAR(255),
      details JSONB,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
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
    await db.query(
      "INSERT INTO audit_logs (user_id, action, details) VALUES ($1, $2, $3)",
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
    const { rows } = await db.query("SELECT NOW()");
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
      const { rows } = await db.query(
        "INSERT INTO users (email, password, username, status) VALUES ($1, $2, $3, 'en_ligne') RETURNING id, email, username",
        [email, hash, username]
      );
      const user = rows[0];

      const token = signToken(user.id);
      await db.query(
        "INSERT INTO sessions (user_id, token, ip_address, device, expires_at) VALUES ($1, $2, $3, $4, NOW() + INTERVAL '7 days')",
        [user.id, token, req.ip || null, req.get("User-Agent") || null]
      );

      await logAction(user.id, "register", { email, username });
      res.json({ message: "Compte créé", token, user: { id: user.id, email, username } });
    } catch (e) {
      if (e.code === "23505") {
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
      const { rows } = await db.query("SELECT * FROM users WHERE email = $1", [email]);
      if (rows.length === 0) return res.status(400).json({ error: "Utilisateur introuvable" });

      const user = rows[0];
      if (!user.password) return res.status(400).json({ error: "Compte lié à Google, utilisez Google" });

      const ok = await bcrypt.compare(password, user.password);
      if (!ok) return res.status(400).json({ error: "Mot de passe incorrect" });

      const token = signToken(user.id);
      await db.query(
        "INSERT INTO sessions (user_id, token, ip_address, device, expires_at) VALUES ($1, $2, $3, $4, NOW() + INTERVAL '7 days')",
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
      audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const { sub: googleId, email, name, picture } = payload;

    let { rows } = await db.query("SELECT * FROM users WHERE google_id = $1", [googleId]);

    if (rows.length === 0) {
      const result = await db.query(
        "INSERT INTO users (email, google_id, username, avatar, status) VALUES ($1, $2, $3, $4, 'en_ligne') RETURNING id",
        [email, googleId, name || null, picture || null]
      );
      rows = await db.query("SELECT * FROM users WHERE id = $1", [result.rows[0].id]);
    }

    const user = rows[0];
    const token = signToken(user.id);
    await db.query(
      "INSERT INTO sessions (user_id, token, ip_address, device, expires_at) VALUES ($1, $2, $3, $4, NOW() + INTERVAL '7 days')",
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
    const apiKey = crypto.randomBytes(API_KEY_LENGTH).toString("hex");
    await db.query("INSERT INTO api_keys (user_id, api_key) VALUES ($1, $2)", [req.user.id, apiKey]);
    await logAction(req.user.id, "api_key_generate");
    res.json({ message: "Clé API générée", apiKey });
  } catch (e) {
    if (e.code === "23505") {
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
      await db.query(
        "INSERT INTO coffre_fort (user_id, amount, currency, type, status, details) VALUES ($1, $2, $3, $4, 'en_attente', $5)",
        [req.user.id, amount, currency, type, details]
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
    const { rows } = await db.query(
      "SELECT id, amount, currency, type, status, details, created_at FROM coffre_fort WHERE user_id = $1 ORDER BY id DESC",
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
    const { rows } = await db.query(
      "SELECT id, email, username, avatar, status, created_at FROM users WHERE id = $1",
      [req.user.id]
    );
    res.json(rows[0] || {});
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
