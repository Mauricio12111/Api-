// src/index.js

// Importe dotenv pour charger les variables d'environnement du fichier .env en local
import 'dotenv/config'; 
import express from "express";
import cors from "cors";
import pg from "pg"; // Note: l'import change légèrement ici
const { Pool } = pg;
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { OAuth2Client } from "google-auth-library";
import crypto from "crypto";
import rateLimit from "express-rate-limit";
import { body, validationResult } from "express-validator";

/* ====== CONFIG ====== */

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;

if (!DATABASE_URL || !JWT_SECRET) {
  console.error("ERREUR: Les variables d'environnement DATABASE_URL et JWT_SECRET sont requises.");
  process.exit(1);
}

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

// Rate limit
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
const authLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 20, message: { error: "Trop de tentatives, réessayez plus tard." } });

// Constantes
const TOKEN_TTL = "7d";
const HASH_ROUNDS = 10;
const API_KEY_LENGTH = 32;

// Google Client
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

// PostgreSQL Pool
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

/* ====== HELPERS ====== */
function signToken(userId) {
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: TOKEN_TTL });
}

async function logAction(userId, action, details = {}) {
  try {
    await pool.query("INSERT INTO audit_logs (user_id, action, details) VALUES ($1, $2, $3)", [userId, action, details]);
  } catch (e) {
    console.warn("Audit log error:", e.message);
  }
}

async function authMiddleware(req, res, next) {
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

/* ====== ROUTES PUBLIQUES ====== */
app.get("/", (req, res) => res.json({ ok: true, service: "GamerHubX API", version: "1.0.0" }));
app.get("/health", async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT NOW()");
    res.json({ status: "ok", now: rows[0].now });
  } catch (e) {
    res.status(503).json({ status: "db_error", error: e.message });
  }
});

/* ====== AUTH EMAIL ====== */
app.post(
  "/inscription",
  authLimiter,
  body("email").isEmail(),
  body("password").isLength({ min: 6 }),
  body("username").isLength({ min: 3, max: 32 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { email, password, username } = req.body;
    try {
      const hash = await bcrypt.hash(password, HASH_ROUNDS);
      const { rows } = await pool.query(
        "INSERT INTO users (email, password, username, status) VALUES ($1, $2, $3, 'en_ligne') RETURNING id, email, username",
        [email, hash, username]
      );
      const user = rows[0];
      const token = signToken(user.id);

      await pool.query(
        "INSERT INTO sessions (user_id, token, ip_address, device, expires_at) VALUES ($1, $2, $3, $4, NOW() + INTERVAL '7 days')",
        [user.id, token, req.ip || null, req.get("User-Agent") || null]
      );

      await logAction(user.id, "register", { email, username });
      res.status(201).json({ message: "Compte créé", token, user });
    } catch (e) {
      if (e.code === "23505") return res.status(409).json({ error: "Email ou username déjà utilisé" });
      console.error("Erreur inscription:", e);
      res.status(500).json({ error: "Erreur lors de l'inscription", details: e.message });
    }
  }
);

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
      const { rows } = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
      if (rows.length === 0) return res.status(404).json({ error: "Utilisateur introuvable" });

      const user = rows[0];
      if (!user.password) return res.status(400).json({ error: "Ce compte utilise une connexion sociale (Google/Solana)." });

      const ok = await bcrypt.compare(password, user.password);
      if (!ok) return res.status(401).json({ error: "Mot de passe incorrect" });

      const token = signToken(user.id);
      await pool.query(
        "INSERT INTO sessions (user_id, token, ip_address, device, expires_at) VALUES ($1, $2, $3, $4, NOW() + INTERVAL '7 days')",
        [user.id, token, req.ip || null, req.get("User-Agent") || null]
      );

      await logAction(user.id, "login_email");
      res.json({ message: "Connexion réussie", token, user: { id: user.id, email: user.email, username: user.username } });
    } catch (e) {
      console.error("Erreur connexion:", e);
      res.status(500).json({ error: "Erreur de connexion", details: e.message });
    }
  }
);

/* ====== AUTH GOOGLE ====== */
app.post("/connexion-google", authLimiter, async (req, res) => {
  if (!googleClient) return res.status(500).json({ error: "La connexion Google n'est pas configurée côté serveur." });

  const { tokenId } = req.body;
  if (!tokenId) return res.status(400).json({ error: "tokenId manquant" });
  
  try {
    const ticket = await googleClient.verifyIdToken({ idToken: tokenId, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    if (!payload || !payload.sub || !payload.email) return res.status(400).json({ error: "Token Google invalide ou informations manquantes" });

    const { sub: googleId, email, name, picture } = payload;

    let user;
    const existingUserResult = await pool.query("SELECT * FROM users WHERE google_id = $1 OR email = $2", [googleId, email]);
    
    if (existingUserResult.rows.length === 0) {
      const result = await pool.query(
        "INSERT INTO users (email, google_id, username, avatar, status) VALUES ($1, $2, $3, $4, 'en_ligne') RETURNING *",
        [email, googleId, name || `user_${googleId}`, picture || null]
      );
      user = result.rows[0];
    } else {
      user = existingUserResult.rows[0];
      if (!user.google_id) {
        const result = await pool.query("UPDATE users SET google_id = $1, avatar = COALESCE($2, avatar) WHERE id = $3 RETURNING *", [googleId, picture, user.id]);
        user = result.rows[0];
      }
    }

    const token = signToken(user.id);
    await pool.query(
      "INSERT INTO sessions (user_id, token, ip_address, device, expires_at) VALUES ($1, $2, $3, $4, NOW() + INTERVAL '7 days')",
      [user.id, token, req.ip || null, req.get("User-Agent") || null]
    );

    await logAction(user.id, "login_google");
    res.json({ message: "Connexion Google réussie", token, user: { id: user.id, email: user.email, username: user.username, avatar: user.avatar } });
  } catch (e) {
    console.error("Erreur connexion Google:", e);
    res.status(400).json({ error: "Échec de la connexion Google", details: e.message });
  }
});

/* ====== AUTH SOLANA ====== */
app.post("/connexion-solana", async (req, res) => {
  try {
    const { publicKey, signature, message } = req.body;
    if (!publicKey || !signature || !message) return res.status(400).json({ error: "publicKey, signature et message requis" });
    
    let { rows } = await pool.query("SELECT * FROM users WHERE solana_pubkey=$1", [publicKey]);
    let user;
    if (rows.length === 0) {
      const result = await pool.query(
        "INSERT INTO users (solana_pubkey, username, status) VALUES ($1, $2, 'en_ligne') RETURNING *",
        [publicKey, `sol_${publicKey.slice(0, 8)}`]
      );
      user = result.rows[0];
    } else {
      user = rows[0];
    }

    const token = signToken(user.id);
    await pool.query(
      "INSERT INTO sessions (user_id, token, ip_address, device, expires_at) VALUES ($1, $2, $3, $4, NOW() + INTERVAL '7 days')",
      [user.id, token, req.ip || null, req.get("User-Agent") || null]
    );

    await logAction(user.id, "login_solana", { publicKey });
    res.json({ message: "Connexion Solana réussie", token, user: { id: user.id, solana_pubkey: publicKey } });
  } catch (e) {
    console.error("Erreur connexion Solana:", e);
    res.status(500).json({ error: "Erreur connexion Solana", details: e.message });
  }
});


/* ====== ROUTES PROTÉGÉES ====== */
app.use("/api", authMiddleware);

app.get("/api/me", async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT id, email, username, avatar, status, solana_pubkey, created_at FROM users WHERE id=$1", [req.user.id]);
    if (rows.length === 0) return res.status(404).json({ error: "Utilisateur non trouvé" });
    res.json(rows[0]);
  } catch (e) {
    console.error("Erreur /api/me:", e);
    res.status(500).json({ error: "Erreur lors de la récupération du profil", details: e.message });
  }
});

app.post("/api/generer-cle", async (req, res) => {
  try {
    const apiKey = crypto.randomBytes(API_KEY_LENGTH).toString("hex");
    await pool.query("INSERT INTO api_keys (user_id, api_key) VALUES ($1, $2)", [req.user.id, apiKey]);
    await logAction(req.user.id, "api_key_generate");
    res.json({ message: "Clé API générée", apiKey });
  } catch (e) {
    console.error("Erreur /api/generer-cle:", e);
    res.status(500).json({ error: "Erreur lors de la génération de la clé", details: e.message });
  }
});

app.post("/api/coffre/ajouter", body("amount").isFloat({ gt: 0 }), async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { amount, currency = "EUR", type = "autre", details = {} } = req.body;
  try {
    await pool.query("INSERT INTO coffre_fort (user_id, amount, currency, type, status, details) VALUES ($1,$2,$3,$4,'en_attente',$5)", [req.user.id, amount, currency, type, details]);
    await logAction(req.user.id, "vault_add", { amount, currency, type });
    res.status(201).json({ message: "Transaction ajoutée au coffre-fort" });
  } catch (e) {
    console.error("Erreur /api/coffre/ajouter:", e);
    res.status(500).json({ error: "Erreur lors de l'ajout au coffre", details: e.message });
  }
});

app.get("/api/coffre", async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT id, amount, currency, type, status, details, created_at FROM coffre_fort WHERE user_id=$1 ORDER BY created_at DESC", [req.user.id]);
    res.json(rows);
  } catch (e) {
    console.error("Erreur /api/coffre:", e);
    res.status(500).json({ error: "Erreur lors de la lecture du coffre", details: e.message });
  }
});

/* ====== HANDLERS ====== */
app.use((req, res, next) => {
  res.status(404).json({ error: "Route introuvable" });
});

app.use((err, req, res, next) => {
  console.error("Erreur serveur non gérée:", err);
  res.status(500).json({ error: "Une erreur interne est survenue" });
});

/* ====== START ====== */
app.listen(PORT, () => {
  console.log(`🚀 Serveur démarré et à l'écoute sur le port ${PORT}`);
});
