const Database = require("better-sqlite3")
const path = require("path")

const db = new Database(path.join(__dirname, "../database.sqlite"))

db.exec(`
    CREATED TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        login_attempts INTEGER DEFAULT 0,
        locked_until TEXT DEFAULT NULL,
        created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        FOREING KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS csrf_tokens (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now'))
    );
    `)

module.exports = db