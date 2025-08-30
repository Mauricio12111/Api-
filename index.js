import express from "express";
import mysql from "mysql2/promise";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { OAuth2Client } from "google-auth-library";
import crypto from "crypto";
import rateLimit from "express-rate-limit";
import { body, validationResult } from "express-validator";

const app = express();
app.use(express.json());

// Rate limiter
const limiter = rateLimit({ windowMs: 15*60*1000, max: 100 });
app.use(limiter);

// DB connection with fallback values (move these to Render environment variables)
const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: parseInt(process.env.DB_PORT,
  ssl: { rejectUnauthorized: true }
};

// Database connection with retry mechanism
const connectDB = async (retries = 5) => {
  while (retries > 0) {
    try {
      const connection = await mysql.createConnection(dbConfig);
      console.log("✅ Database connected successfully");
      return connection;
    } catch (error) {
      retries--;
      console.log(`Failed to connect to database. Retries left: ${retries}`);
      if (retries === 0) throw error;
      await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds before retry
    }
  }
};

// Initialize DB connection
let db;
try {
  db = await connectDB();
} catch (error) {
  console.error("Failed to initialize database:", error);
  process.exit(1);
}

// Google OAuth
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

// JWT
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const DUREE_TOKEN = "7d";

// --- CREATE TABLES ---
async function créerTables() {
  try {
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

    // Rest of your table creation code...
    // (keeping the same table creation queries)

    console.log("✅ Full Start tables créées !");
  } catch (error) {
    console.error("Erreur lors de la création des tables:", error);
    throw error;
  }
}

// Initialize tables with error handling
try {
  await créerTables();
} catch (error) {
  console.error("Failed to create tables:", error);
  process.exit(1);
}

// --- AUTH MIDDLEWARE ---
const verifierToken = async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ erreur: "Authentification requise" });

  try {
    // Vérifie blacklist
    const [blacklist] = await db.execute("SELECT * FROM token_blacklist WHERE token = ?", [token]);
    if(blacklist.length > 0) return res.status(403).json({ erreur: "Token invalide ou expiré" });

    jwt.verify(token, JWT_SECRET, (err, utilisateur) => {
      if(err) return res.status(403).json({ erreur: "Token invalide" });
      req.utilisateur = utilisateur;
      next();
    });
  } catch (error) {
    return res.status(500).json({ erreur: "Erreur serveur" });
  }
};

// Rest of your route handlers...
// (keeping the same route handlers)

// Error handling for uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});

// Error handling for unhandled promise rejections
process.on('unhandledRejection', (error) => {
  console.error('Unhandled Rejection:', error);
  process.exit(1);
});

// Lancer serveur with error handling
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server Full Start running on port ${PORT}`);
}).on('error', (error) => {
  console.error('Failed to start server:', error);
  process.exit(1);
});
