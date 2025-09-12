// gmpc-backend/index.js
import express from "express";
import cors from "cors";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { v4 as uuidv4 } from "uuid";
import bcrypt from "bcrypt";

const DB_FILE = path.join(process.cwd(), "data.json");
let db = { users: {}, messages: [] };

// Load DB or create fresh
if (fs.existsSync(DB_FILE)) {
  try {
    db = JSON.parse(fs.readFileSync(DB_FILE));
  } catch {
    db = { users: {}, messages: [] };
  }
} else {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function save() {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

const app = express();
app.use(cors());
app.use(express.json());

// --- ROUTES ---

// Register (signup)
app.post("/register", async (req, res) => {
  const { username, password, publicKey } = req.body;
  if (!username || !password || !publicKey)
    return res.status(400).json({ error: "Missing fields" });

  if (db.users[username])
    return res.status(400).json({ error: "Username already exists" });

  const passwordHash = await bcrypt.hash(password, 10);

  db.users[username] = { publicKey, passwordHash };
  save();
  res.json({ ok: true, publicKey });
});

// Login user
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: "Missing username or password" });

  const user = db.users[username];
  if (!user) return res.status(400).json({ error: "User not found" });

  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) return res.status(401).json({ error: "Invalid password" });

  res.json({ ok: true, publicKey: user.publicKey });
});

// Get user's public key
app.get("/publicKey", (req, res) => {
  const { username } = req.query;
  if (!username || !db.users[username])
    return res.status(404).json({ error: "User not found" });

  res.json({ publicKey: db.users[username].publicKey });
});

// Send encrypted message to multiple recipients
app.post("/send", (req, res) => {
  const { sender, encryptedMessages } = req.body;
  if (!sender || !Array.isArray(encryptedMessages))
    return res.status(400).json({ error: "Missing fields" });

  encryptedMessages.forEach((m) => {
    const { recipient, encryptedMessage, nonce, senderPublicKey } = m;
    if (!recipient || !encryptedMessage || !nonce || !senderPublicKey) return;

    db.messages.unshift({
      id: uuidv4(),
      sender,
      recipient,
      encryptedMessage,
      nonce,
      senderPublicKey,
      ts: Date.now(),
    });
  });

  save();
  res.json({ ok: true });
});

// Fetch messages for a specific user
app.get("/messages", (req, res) => {
  const { username } = req.query;
  if (!username) return res.status(400).json({ error: "Missing username" });

  const userMessages = db.messages
    .filter((m) => m.recipient === username)
    .map((m) => ({
      id: m.id,
      sender: m.sender,
      encryptedMessage: m.encryptedMessage,
      nonce: m.nonce,
      senderPublicKey: m.senderPublicKey,
      ts: m.ts,
    }));

  res.json(userMessages.reverse()); // newest first
});

// Reset messages only
app.post("/reset", (req, res) => {
  db.messages = [];
  save();
  res.json({ ok: true });
});

// Reset ALL users + messages
app.post("/resetAll", (req, res) => {
  db = { users: {}, messages: [] };
  save();
  res.json({ ok: true, msg: "All users and messages wiped!" });
});

// List users
app.get("/users", (req, res) => {
  res.json(Object.keys(db.users));
});

// Health check
app.get("/health", (req, res) => res.json({ ok: true }));

// --- Serve frontend build if present ---
// look in two places: ./dist (if copied) or ../gmpc-frontend/dist (if built in place)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const built1 = path.join(__dirname, "dist");
const built2 = path.join(__dirname, "../gmpc-frontend/dist");

if (fs.existsSync(built1)) {
  app.use(express.static(built1));
  app.get("*", (req, res) => res.sendFile(path.join(built1, "index.html")));
} else if (fs.existsSync(built2)) {
  app.use(express.static(built2));
  app.get("*", (req, res) => res.sendFile(path.join(built2, "index.html")));
} else {
  // No build found — API only
  console.log("⚠️ Frontend build not found. App will run API only.");
}

// Start server
const PORT = process.env.PORT || 4000;
app.listen(PORT, "0.0.0.0", () =>
  console.log(`CipherChat backend listening on port ${PORT}`)
);
