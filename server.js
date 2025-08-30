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
app.set("trust proxy", 1); // Nécessaire pour Render et autres proxies

// CORS
const ALLOWED_ORIGINS = (process.env.CORS_ORIGINS || "*")
  .split(",")
  .map(s => s.trim());
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin || ALLOWED_ORIGINS.includes("*") || ALLOWED_ORIGINS.includes(origin)) {
        return cb(null, true);
      }
      return cb(new Error("Origin not allowed by CORS"));
    },
    credentials: true,
  })
);

// Rate Limiters
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX || "100", 10),
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 20,
  message: { error: "Trop de tentatives de connexion, réessayez plus tard." },
  standardHeaders: true,
  legacyHeaders: false,
});

// Variables d'environnement
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const TOKEN_TTL = process.env.DUREE_TOKEN || "7d";
const HASH_ROUNDS = parseInt(process.env.PASSWORD_HASH_ROUNDS || "12", 10);
const API_KEY_LENGTH = 32;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;

// Initialisation du client Google
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

// Vérification des variables critiques au démarrage
if (!JWT_SECRET) {
  console.error("ERREUR FATALE: La variable d'environnement JWT_SECRET n'est pas définie.");
  process.exit(1);
}

/* ====== DB CONNEXION ====== */
let db;
try {
  db = await mysql.createConnection({
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT || "3306", 10),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    // AMÉLIORATION: Utilise le parsing de boolean pour la variable d'env
    ssl: {
      rejectUnauthorized: process.env.DB_SSL_REJECT_UNAUTHORIZED !== "false",
    },
  });
  console.log("✅ Connecté à la base de données MySQL.");
} catch (error) {
  console.error("❌ Erreur de connexion à la base de données:", error.message);
  process.exit(1); // Arrête l'application si la connexion DB échoue
}

/* ====== ⚠️ ATTENTION: CRÉATION DES TABLES ⚠️ ====== */
// La création des tables ne doit PAS être dans le code de démarrage du serveur.
// Exécutez ce code une seule fois manuellement via un client SQL ou un script séparé.
/*
async function createTables() {
  const tablesSQL = [
    `CREATE TABLE IF NOT EXISTS users (...)`,
    `CREATE TABLE IF NOT EXISTS sessions (...)`,
    // etc.
  ];
  for (const sql of tablesSQL) {
    await db.execute(sql);
  }
  console.log("🗄️ Tables vérifiées/créées");
}
// await createTables(); // NE PAS appeler cette fonction ici !
*/


/* ====== HELPERS ====== */
const signToken = (userId) => {
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: TOKEN_TTL });
};

const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Authentification requise" });
  }

  const token = authHeader.split(" ")[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = { id: payload.id };
    next();
  } catch (err) {
    return res.status(403).json({ error: "Token invalide ou expiré" });
  }
};

const logAction = async (userId, action, details = {}) => {
  try {
    await db.execute(
      "INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)",
      [userId || null, action, JSON.stringify(details)]
    );
  } catch (e) {
    console.warn(`Audit log a échoué pour l'action '${action}':`, e.message);
  }
};

/* ====== ROUTES PUBLIQUES ====== */
app.get("/", (req, res) => {
  res.json({ service: "GamerHubX API", version: "1.0.0", status: "ok" });
});

app.get("/health", async (req, res) => {
  try {
    await db.query("SELECT 1");
    res.json({ status: "ok", database: "connected" });
  } catch (e) {
    res.status(503).json({ status: "error", database: "disconnected", details: e.message });
  }
});

/* ====== AUTH ROUTES ====== */

// Inscription
app.post(
  "/inscription",
  authLimiter,
  body("email").isEmail().normalizeEmail().withMessage("Email invalide"),
  body("password").isLength({ min: 8 }).withMessage("Le mot de passe doit contenir au moins 8 caractères"),
  body("username").trim().isLength({ min: 3, max: 32 }).withMessage("Le pseudo doit contenir entre 3 et 32 caractères"),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { email, password, username } = req.body;
    try {
      const hash = await bcrypt.hash(password, HASH_ROUNDS);
      
      const [result] = await db.execute(
        "INSERT INTO users (email, password, username, status) VALUES (?, ?, ?, 'en_ligne')",
        [email, hash, username]
      );
      const userId = result.insertId;

      const token = signToken(userId);
      await db.execute(
        "INSERT INTO sessions (user_id, token, ip_address, device, expires_at) VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 7 DAY))",
        [userId, token, req.ip, req.get("User-Agent")]
      );
      
      await logAction(userId, "register", { email, username });
      res.status(201).json({ message: "Compte créé avec succès", token, user: { id: userId, email, username } });
    } catch (e) {
      if (e?.code === "ER_DUP_ENTRY") {
        return res.status(409).json({ error: "Cet email ou pseudo est déjà utilisé." });
      }
      console.error("Erreur inscription:", e);
      res.status(500).json({ error: "Erreur interne du serveur." });
    }
  }
);

// Connexion
app.post(
  "/connexion",
  authLimiter,
  body("email").isEmail().normalizeEmail(),
  body("password").notEmpty(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { email, password } = req.body;
    try {
      const [[user]] = await db.execute("SELECT * FROM users WHERE email = ?", [email]);
      if (!user) return res.status(401).json({ error: "Identifiants incorrects" });
      if (!user.password) return res.status(400).json({ error: "Ce compte a été créé avec Google. Veuillez utiliser la connexion Google." });
      
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(401).json({ error: "Identifiants incorrects" });
      
      const token = signToken(user.id);
      await db.execute(
        "INSERT INTO sessions (user_id, token, ip_address, device, expires_at) VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 7 DAY))",
        [user.id, token, req.ip, req.get("User-Agent")]
      );
      
      await logAction(user.id, "login_email");
      res.json({ message: "Connexion réussie", token, user: { id: user.id, email: user.email, username: user.username } });
    } catch (e) {
      console.error("Erreur connexion:", e);
      res.status(500).json({ error: "Erreur interne du serveur." });
    }
  }
);

// Google Connexion
app.post("/connexion-google", authLimiter, async (req, res) => {
  if (!googleClient) return res.status(501).json({ error: "La connexion Google n'est pas configurée sur ce serveur." });
  
  const { tokenId } = req.body;
  if (!tokenId) return res.status(400).json({ error: "Le 'tokenId' est manquant." });

  try {
    const ticket = await googleClient.verifyIdToken({ idToken: tokenId, audience: GOOGLE_CLIENT_ID });
    const { sub: googleId, email, name, picture } = ticket.getPayload();
    
    let [[user]] = await db.execute("SELECT * FROM users WHERE googleId = ? OR email = ?", [googleId, email]);

    if (!user) {
      const [result] = await db.execute(
        "INSERT INTO users (email, googleId, username, avatar, status) VALUES (?, ?, ?, ?, 'en_ligne')",
        [email, googleId, name, picture]
      );
      user = { id: result.insertId, email, username: name, avatar: picture };
      await logAction(user.id, "register_google");
    }

    const token = signToken(user.id);
    await db.execute(
      "INSERT INTO sessions (user_id, token, ip_address, device, expires_at) VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 7 DAY))",
      [user.id, token, req.ip, req.get("User-Agent")]
    );
    
    await logAction(user.id, "login_google");
    res.json({ message: "Connexion Google réussie", token, user: { id: user.id, email: user.email, username: user.username, avatar: user.avatar } });
  } catch (e) {
    console.error("Erreur connexion Google:", e);
    res.status(400).json({ error: "Token Google invalide ou expiré" });
  }
});


/* ====== ROUTES PROTÉGÉES (/api/*) ====== */
app.use("/api", authMiddleware);

// Profil utilisateur
app.get("/api/me", async (req, res) => {
  try {
    const [[me]] = await db.query(
      "SELECT id, email, username, avatar, status, created_at FROM users WHERE id = ?",
      [req.user.id]
    );
    if (!me) return res.status(404).json({ error: "Utilisateur non trouvé" });
    res.json(me);
  } catch (e) {
    console.error("Erreur /api/me:", e);
    res.status(500).json({ error: "Erreur interne du serveur." });
  }
});

// ... Ajoutez ici les autres routes protégées comme /api/coffre, etc. ...


/* ====== GESTION DES ERREURS ET DÉMARRAGE ====== */
app.use((req, res) => {
  res.status(404).json({ error: "Route non trouvée" });
});

app.use((err, req, res, next) => {
  console.error("Erreur non gérée:", err);
  res.status(500).json({ error: "Une erreur inattendue est survenue." });
});

const server = app.listen(PORT, () => {
  console.log(`🚀 Serveur démarré et à l'écoute sur le port ${PORT}`);
});

// AMÉLIORATION: Arrêt propre du serveur (Graceful Shutdown)
process.on('SIGINT', async () => {
  console.log("\nSIGINT reçu. Fermeture du serveur...");
  server.close(async () => {
    console.log("Serveur HTTP fermé.");
    if (db) await db.end();
    console.log("Connexion à la base de données fermée.");
    process.exit(0);
  });
});
