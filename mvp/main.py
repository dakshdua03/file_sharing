"""Slice 3 MVP: Envelope / Hybrid Encryption with Users and File Sharing.

- Files encrypted with unique AES-256-GCM symmetric keys.
- Symmetric key is NEVER stored in plaintext.
- Symmetric key is wrapped (RSA-OAEP) for the owner upon upload.
- Sharing a file creates a new recipient-wrapped key in `file_shares`.
- Only authorized users with their matching RSA private key can decrypt.
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
import uuid

from cryptography.exceptions import InvalidTag
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel

from crypto import (
    decrypt_file,
    encrypt_file,
    generate_file_key,
    generate_rsa_keypair,
    unwrap_key,
    wrap_key,
)
from db import STORAGE_DIR, get_conn, init_db


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Secure File Sharing MVP (Slice 3 - Envelope Encryption & Sharing)",
    description="User keypairs, AES bulk file encryption, and RSA key wrapping for authorized sharing.",
    version="0.3.0",
    lifespan=lifespan,
)


class UserCreate(BaseModel):
    username: str
    role: str = "student"  # e.g., professor, student, admin


class ShareRequest(BaseModel):
    file_id: str
    owner_id: str
    recipient_id: str


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "slice": "3-key-wrapping"}


# ---------------- User Management ----------------


@app.post("/users")
def register_user(req: UserCreate) -> dict:
    """Register a new user and generate their RSA keypair."""
    user_id = uuid.uuid4().hex
    created_at = datetime.now(timezone.utc).isoformat()
    private_pem, public_pem = generate_rsa_keypair()

    with get_conn() as conn:
        try:
            conn.execute(
                """
                INSERT INTO users (id, username, role, public_key_pem, private_key_pem, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (user_id, req.username.strip(), req.role.strip(), public_pem, private_pem, created_at),
            )
            conn.commit()
        except Exception:
            raise HTTPException(status_code=400, detail="Username already exists")

    return {
        "user_id": user_id,
        "username": req.username,
        "role": req.role,
        "public_key_pem": public_pem,
        "created_at": created_at,
    }


@app.get("/users")
def list_users() -> list[dict]:
    """List registered users (without exposing private keys)."""
    with get_conn() as conn:
        rows = conn.execute("SELECT id, username, role, public_key_pem, created_at FROM users").fetchall()
    return [dict(row) for row in rows]


# ---------------- Upload with Envelope Encryption ----------------


@app.post("/upload")
async def upload_file(
    owner_id: str = Form(...),
    file: UploadFile = File(...),
) -> dict:
    """
    1. Verify owner exists and fetch their public key.
    2. Encrypt file with fresh random AES-256 key Kc.
    3. Wrap Kc using owner's RSA public key (stored in file_shares for owner).
    4. Save ciphertext to disk (raw file and raw Kc are never saved unencrypted).
    """
    with get_conn() as conn:
        owner = conn.execute("SELECT id, public_key_pem FROM users WHERE id = ?", (owner_id,)).fetchone()
        if not owner:
            raise HTTPException(status_code=404, detail="Owner user not found")

    plaintext = await file.read()
    if not plaintext:
        raise HTTPException(status_code=400, detail="Cannot upload empty file")

    file_id = uuid.uuid4().hex
    safe_name = Path(file.filename or "unnamed.bin").name
    dest_path = STORAGE_DIR / f"{file_id}_{safe_name}.enc"

    # Step A: Encrypt bulk data with symmetric AES key
    file_key = generate_file_key()
    ciphertext, nonce = encrypt_file(plaintext, file_key)
    dest_path.write_bytes(ciphertext)

    # Step B: Wrap file_key with owner's RSA public key
    wrapped_owner_key = wrap_key(file_key, owner["public_key_pem"])

    created_at = datetime.now(timezone.utc).isoformat()
    content_type = file.content_type or "application/octet-stream"

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO files (
                id, owner_id, original_name, content_type,
                plaintext_size, ciphertext_size, storage_path, nonce_hex, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                file_id,
                owner_id,
                safe_name,
                content_type,
                len(plaintext),
                len(ciphertext),
                str(dest_path),
                nonce.hex(),
                created_at,
            ),
        )
        # Authorize owner themselves via file_shares
        conn.execute(
            """
            INSERT INTO file_shares (id, file_id, recipient_id, wrapped_key_hex, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (uuid.uuid4().hex, file_id, owner_id, wrapped_owner_key.hex(), created_at),
        )
        conn.commit()

    return {
        "file_id": file_id,
        "owner_id": owner_id,
        "filename": safe_name,
        "plaintext_size": len(plaintext),
        "ciphertext_size": len(ciphertext),
        "created_at": created_at,
    }


# ---------------- Sharing (Key Wrapping for Recipient) ----------------


@app.post("/share")
def share_file(req: ShareRequest) -> dict:
    """
    Owner shares file with recipient:
    1. Authenticate owner has rights to the file.
    2. Unwrap Kc using owner's private key.
    3. Re-wrap Kc using recipient's public key.
    4. Store wrapped key in file_shares table.
    (Bulk ciphertext on disk is NOT touched or re-encrypted).
    """
    with get_conn() as conn:
        # Check file exists and owner matches
        file_row = conn.execute("SELECT id, owner_id FROM files WHERE id = ?", (req.file_id,)).fetchone()
        if not file_row:
            raise HTTPException(status_code=404, detail="File not found")
        if file_row["owner_id"] != req.owner_id:
            raise HTTPException(status_code=403, detail="Only the file owner can share this file")

        # Fetch owner's private key and wrapped key
        owner_share = conn.execute(
            """
            SELECT s.wrapped_key_hex, u.private_key_pem
            FROM file_shares s
            JOIN users u ON s.recipient_id = u.id
            WHERE s.file_id = ? AND s.recipient_id = ?
            """,
            (req.file_id, req.owner_id),
        ).fetchone()

        # Fetch recipient's public key
        recipient = conn.execute("SELECT id, public_key_pem FROM users WHERE id = ?", (req.recipient_id,)).fetchone()
        if not recipient:
            raise HTTPException(status_code=404, detail="Recipient user not found")

    # Unwrap Kc using owner private key
    file_key = unwrap_key(
        bytes.fromhex(owner_share["wrapped_key_hex"]),
        owner_share["private_key_pem"],
    )

    # Wrap Kc with recipient public key
    wrapped_recipient_key = wrap_key(file_key, recipient["public_key_pem"])
    created_at = datetime.now(timezone.utc).isoformat()
    share_id = uuid.uuid4().hex

    with get_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO file_shares (id, file_id, recipient_id, wrapped_key_hex, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (share_id, req.file_id, req.recipient_id, wrapped_recipient_key.hex(), created_at),
        )
        conn.commit()

    return {
        "share_id": share_id,
        "file_id": req.file_id,
        "recipient_id": req.recipient_id,
        "status": "shared_successfully",
    }


# ---------------- Download & Decrypt ----------------


@app.get("/download/{file_id}")
def download_file(file_id: str, user_id: str) -> Response:
    """
    Download and decrypt:
    1. Check user has an entry in file_shares.
    2. Unwrap Kc using recipient's private key.
    3. Decrypt ciphertext from storage using unwrapped Kc.
    4. Return plaintext.
    """
    with get_conn() as conn:
        file_row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
        if not file_row:
            raise HTTPException(status_code=404, detail="File not found")

        share = conn.execute(
            """
            SELECT s.wrapped_key_hex, u.private_key_pem
            FROM file_shares s
            JOIN users u ON s.recipient_id = u.id
            WHERE s.file_id = ? AND s.recipient_id = ?
            """,
            (file_id, user_id),
        ).fetchone()

    if not share:
        raise HTTPException(status_code=403, detail="Access denied: user is not authorized to access this file")

    # Unwrap Kc with user's private key
    try:
        file_key = unwrap_key(bytes.fromhex(share["wrapped_key_hex"]), share["private_key_pem"])
    except Exception:
        raise HTTPException(status_code=400, detail="Key unwrapping failed")

    # Read ciphertext and decrypt
    ciphertext_path = Path(file_row["storage_path"])
    ciphertext = ciphertext_path.read_bytes()
    nonce = bytes.fromhex(file_row["nonce_hex"])

    try:
        plaintext = decrypt_file(ciphertext, file_key, nonce)
    except InvalidTag:
        raise HTTPException(status_code=400, detail="Tamper check failed on download")

    headers = {
        "Content-Disposition": f'attachment; filename="{file_row["original_name"]}"'
    }
    return Response(content=plaintext, media_type=file_row["content_type"], headers=headers)
