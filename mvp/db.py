"""SQLite database setup for Slice 5: adding tamper-evident Audit Log."""

import hashlib
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "mvp.db"
STORAGE_DIR = BASE_DIR / "storage"

# Genesis hash for the initial entry in the audit hash chain
GENESIS_HASH = "0" * 64


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
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

            CREATE TABLE IF NOT EXISTS audit_logs (
                sequence_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user_id TEXT NOT NULL,
                file_id TEXT,
                action TEXT NOT NULL,
                details TEXT,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            );
            """
        )
        conn.commit()


def compute_entry_hash(
    seq_id: int, timestamp: str, user_id: str, file_id: str, action: str, details: str, prev_hash: str
) -> str:
    """Compute SHA-256 over all fields of the audit log row chained to prev_hash."""
    payload = f"{seq_id}|{timestamp}|{user_id}|{file_id or ''}|{action}|{details or ''}|{prev_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_audit_log(
    conn: sqlite3.Connection,
    timestamp: str,
    user_id: str,
    action: str,
    file_id: str = None,
    details: str = None,
) -> dict:
    """
    Append an entry to the tamper-evident hash chain.
    Retrieves the last entry's hash (or GENESIS_HASH) and links the new entry.
    """
    last_row = conn.execute(
        "SELECT sequence_id, entry_hash FROM audit_logs ORDER BY sequence_id DESC LIMIT 1"
    ).fetchone()

    seq_id = 1 if last_row is None else last_row["sequence_id"] + 1
    prev_hash = GENESIS_HASH if last_row is None else last_row["entry_hash"]

    entry_hash = compute_entry_hash(seq_id, timestamp, user_id, file_id, action, details, prev_hash)

    conn.execute(
        """
        INSERT INTO audit_logs (sequence_id, timestamp, user_id, file_id, action, details, prev_hash, entry_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (seq_id, timestamp, user_id, file_id, action, details, prev_hash, entry_hash),
    )
    return {
        "sequence_id": seq_id,
        "action": action,
        "entry_hash": entry_hash,
        "prev_hash": prev_hash,
    }
