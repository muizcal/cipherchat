// gmpc-backend/index.js
import express from "express";
import cors from "cors";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { v4 as uuidv4 } from "uuid";
import bcrypt from "bcrypt";
import crypto from "crypto";
import Database from "better-sqlite3";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ----------------------
// SQLite DB Setup
// ----------------------
const dbPath = path.join(__dirname, "cipherchat.db");
const db = new Database(dbPath);

// Create tables if not exist
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    publicKey TEXT NOT NULL,
    passwordHash TEXT NOT NULL,
    encryptedPrivateKey TEXT NOT NULL
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    encryptedMessage TEXT NOT NULL,
    nonce TEXT NOT NULL,
    senderPublicKey TEXT NOT NULL,
    ts INTEGER NOT NULL
  )
`).run();

// ----------------------
// Helper functions
// ----------------------
function encryptPrivateKey(privateKey, password) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, salt, 32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(privateKey, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return JSON.stringify({
    data: encrypted.toString("base64"),
    iv: iv.toString("base64"),
    salt: salt.toString("base64"),
    tag: tag.toString("base64"),
  });
}

function decryptPrivateKey(encString, password) {
  const encObj = JSON.parse(encString);
  const { data, iv, salt, tag } = encObj;
  const key = crypto.scryptSync(password, Buffer.from(salt, "base64"), 32);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64"));
  decipher.setAuthTag(Buffer.from(tag, "base64"));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(data, "base64")),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
}

// ----------------------
// Express setup
// ----------------------
const app = express();
app.use(cors());
app.use(express.json());

// ----------------------
// API ROUTES
// ----------------------

// Register
app.post("/register", async (req, res) => {
  const { username, password, publicKey, privateKey } = req.body;
  if (!username || !password || !publicKey || !privateKey)
    return res.status(400).json({ error: "Missing fields" });

  const userExists = db.prepare("SELECT username FROM users WHERE username=?").get(username);
  if (userExists) return res.status(400).json({ error: "Username already exists" });

  const passwordHash = await bcrypt.hash(password, 10);
  const encryptedPrivateKey = encryptPrivateKey(privateKey, password);

  db.prepare("INSERT INTO users (username, publicKey, passwordHash, encryptedPrivateKey) VALUES (?, ?, ?, ?)")
    .run(username, publicKey, passwordHash, encryptedPrivateKey);

  res.json({ ok: true, publicKey });
});

// Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Missing username or password" });

  const user = db.prepare("SELECT * FROM users WHERE username=?").get(username);
  if (!user) return res.status(400).json({ error: "User not found" });

  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) return res.status(401).json({ error: "Invalid password" });

  let decryptedPrivateKey;
  try {
    decryptedPrivateKey = decryptPrivateKey(user.encryptedPrivateKey, password);
  } catch {
    return res.status(500).json({ error: "Failed to decrypt private key" });
  }

  res.json({ ok: true, publicKey: user.publicKey, privateKey: decryptedPrivateKey });
});

// Get user's public key
app.get("/publicKey", (req, res) => {
  const { username } = req.query;
  if (!username) return res.status(400).json({ error: "Missing username" });

  const user = db.prepare("SELECT publicKey FROM users WHERE username=?").get(username);
  if (!user) return res.status(404).json({ error: "User not found" });

  res.json({ publicKey: user.publicKey });
});

// Send messages
app.post("/send", (req, res) => {
  const { sender, encryptedMessages } = req.body;
  if (!sender || !Array.isArray(encryptedMessages)) return res.status(400).json({ error: "Missing fields" });

  const stmt = db.prepare(`
    INSERT INTO messages (id, sender, recipient, encryptedMessage, nonce, senderPublicKey, ts)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  const insert = db.transaction(() => {
    encryptedMessages.forEach(m => {
      const { recipient, encryptedMessage, nonce, senderPublicKey } = m;
      if (!recipient || !encryptedMessage || !nonce || !senderPublicKey) return;
      stmt.run(uuidv4(), sender, recipient, encryptedMessage, nonce, senderPublicKey, Date.now());
    });
  });

  insert();
  res.json({ ok: true });
});

// Fetch messages
app.get("/messages", (req, res) => {
  const { username } = req.query;
  if (!username) return res.status(400).json({ error: "Missing username" });

  const rows = db.prepare("SELECT * FROM messages WHERE recipient=? ORDER BY ts DESC").all(username);
  res.json(rows.reverse());
});

// Reset messages only
app.post("/reset", (req, res) => {
  db.prepare("DELETE FROM messages").run();
  res.json({ ok: true });
});

// Reset all users + messages
app.post("/resetAll", (req, res) => {
  db.prepare("DELETE FROM messages").run();
  db.prepare("DELETE FROM users").run();
  res.json({ ok: true, msg: "All users and messages wiped!" });
});

// List users
app.get("/users", (req, res) => {
  const rows = db.prepare("SELECT username FROM users").all();
  res.json(rows.map(r => r.username));
});

// Health check
app.get("/health", (req, res) => res.json({ ok: true }));

// ----------------------
// Serve frontend if present
// ----------------------

const built1 = path.join(__dirname, "dist");
const built2 = path.join(__dirname, "../gmpc-frontend/dist");

const frontendPath = fs.existsSync(built1)
  ? built1
  : fs.existsSync(built2)
  ? built2
  : null;

if (frontendPath) {
  app.use(express.static(frontendPath));

  app.get(/.*/, (req, res) => {
    res.sendFile(path.join(frontendPath, "index.html"));
  });
} else {
  console.log("⚠️ Frontend build not found. App will run API only.");
}


// ----------------------
// Start server
// ----------------------
const PORT = process.env.PORT || 4000;
app.listen(PORT, "0.0.0.0", () =>
  console.log(`CipherChat backend listening on port ${PORT}`)
);
