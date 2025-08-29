import express from "express";
import mysql from "mysql2/promise";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json());

// Connexion MySQL
const db = await mysql.createConnection({
  host: "mysql-1a36101-botwii.c.aivencloud.com",
  user: "avnadmin",
  password: "AVNS_BvVULOCxM7CcMQd0Aqw",
  port: 14721,
  database: "defaultdb",
  ssl: { rejectUnauthorized: true }
});

// Route inscription
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  await db.execute("INSERT INTO users (email, password) VALUES (?, ?)", [email, password]);
  res.json({ success: true });
});

// Route connexion
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const [rows] = await db.execute("SELECT * FROM users WHERE email=? AND password=?", [email, password]);
  if (rows.length > 0) {
    res.json({ success: true, user: rows[0] });
  } else {
    res.json({ success: false, message: "Invalid credentials" });
  }
});

// Lancer serveur
app.listen(3000, () => console.log("API running on http://localhost:3000"));
