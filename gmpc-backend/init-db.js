// init-db.js
import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const dbPath = path.join(__dirname, 'cipherchat.db');
const db = new Database(dbPath);

// Create users table
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    publicKey TEXT NOT NULL,
    passwordHash TEXT NOT NULL
  )
`).run();

// Create messages table
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

console.log('✅ Database initialized');
db.close();
