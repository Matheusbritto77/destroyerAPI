import { Database } from "bun:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { config } from "./config";

mkdirSync(dirname(config.databasePath), { recursive: true });

export const db = new Database(config.databasePath, { create: true });

db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  PRAGMA busy_timeout = 5000;

  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    google_sub_hash TEXT NOT NULL UNIQUE,
    google_issuer TEXT NOT NULL,
    email TEXT,
    email_verified INTEGER NOT NULL DEFAULT 0,
    full_name TEXT,
    avatar_url TEXT,
    nickname TEXT,
    nickname_normalized TEXT UNIQUE,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS refresh_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER,
    user_agent TEXT,
    ip_address TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS world_records (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    difficulty TEXT NOT NULL,
    score INTEGER NOT NULL,
    level INTEGER NOT NULL,
    played_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(user_id, difficulty),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_world_records_difficulty_score
    ON world_records(difficulty, score DESC, level DESC, played_at ASC, updated_at ASC);

  CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user
    ON refresh_tokens(user_id, expires_at);
`);
