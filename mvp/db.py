"""SQLite database setup and helpers for MVP Slice 2 (AES-GCM Encryption)."""

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
    """Create local storage directory and required database tables."""
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                original_name TEXT NOT NULL,
                content_type TEXT NOT NULL,
                plaintext_size INTEGER NOT NULL,
                ciphertext_size INTEGER NOT NULL,
                storage_path TEXT NOT NULL,
                nonce_hex TEXT NOT NULL,
                key_hex TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()
