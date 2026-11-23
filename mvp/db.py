"""SQLite database setup for Slice 4: Users, Files, and Time-Restricted/Revocable Shares."""

import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "mvp.db"
STORAGE_DIR = BASE_DIR / "storage"


def get_conn() -> sqlite3.Connection:
    """Open a SQLite connection with row access by column name."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create local storage directory and schema for Slice 4."""
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                role TEXT NOT NULL,
                public_key_pem TEXT NOT NULL,
                private_key_pem TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                original_name TEXT NOT NULL,
                content_type TEXT NOT NULL,
                plaintext_size INTEGER NOT NULL,
                ciphertext_size INTEGER NOT NULL,
                storage_path TEXT NOT NULL,
                nonce_hex TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(owner_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS file_shares (
                id TEXT PRIMARY KEY,
                file_id TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                wrapped_key_hex TEXT NOT NULL,
                expires_at TEXT,
                revoked INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                revoked_at TEXT,
                UNIQUE(file_id, recipient_id),
                FOREIGN KEY(file_id) REFERENCES files(id),
                FOREIGN KEY(recipient_id) REFERENCES users(id)
            );
            """
        )
        conn.commit()
