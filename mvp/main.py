"""Slice 4 MVP: Time-Restricted Access & Immediate Revocation.

Features added on top of Slice 3:
1. Time-to-Live / Expiry: Data owner can specify an expiry timestamp (`expires_at`) when sharing.
2. Immediate Revocation: Data owner can explicitly revoke access (`POST /revoke`), rendering the share inactive immediately.
3. Access Policy Enforcement: Download endpoint strictly verifies:
   - Share exists
   - `revoked == 0`
   - `expires_at > current_utc_time` (if set)
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
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
    title="Secure File Sharing MVP (Slice 4 - Time-Restricted Access & Revocation)",
    description="Envelope encryption with automated time-based access expiration and owner revocation.",
    version="0.4.0",
    lifespan=lifespan,
)


class UserCreate(BaseModel):
    username: str
    role: str = "student"


class ShareRequest(BaseModel):
    file_id: str
    owner_id: str
    recipient_id: str
    expires_at: Optional[str] = None  # ISO 8601 format: e.g. "2026-12-31T23:59:59Z"


class RevokeRequest(BaseModel):
    file_id: str
    owner_id: str
    recipient_id: str


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "slice": "4-expiry-revocation"}


# ---------------- User Endpoints ----------------


@app.post("/users")
def register_user(req: UserCreate) -> dict:
    """Register user and generate 2048-bit RSA keypair."""
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
    with get_conn() as conn:
        rows = conn.execute("SELECT id, username, role, public_key_pem, created_at FROM users").fetchall()
    return [dict(row) for row in rows]


# ---------------- Upload Endpoint ----------------


@app.post("/upload")
async def upload_file(
    owner_id: str = Form(...),
    file: UploadFile = File(...),
) -> dict:
    """Upload bulk-encrypted file and wrap Kc with owner's public key."""
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

    # Symmetric bulk encryption (AES-256-GCM)
    file_key = generate_file_key()
    ciphertext, nonce = encrypt_file(plaintext, file_key)
    dest_path.write_bytes(ciphertext)

    # Wrap symmetric key for owner
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
        conn.execute(
            """
            INSERT INTO file_shares (id, file_id, recipient_id, wrapped_key_hex, expires_at, revoked, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (uuid.uuid4().hex, file_id, owner_id, wrapped_owner_key.hex(), None, 0, created_at),
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


# ---------------- Sharing & Revocation ----------------


@app.post("/share")
def share_file(req: ShareRequest) -> dict:
    """
    Share file with a recipient and optionally set an expiry timestamp.
    """
    # Validate expiry format if provided
    expires_at_iso = None
    if req.expires_at:
        try:
            # Parse and normalize to UTC
            dt = datetime.fromisoformat(req.expires_at.replace("Z", "+00:00"))
            expires_at_iso = dt.astimezone(timezone.utc).isoformat()
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid ISO 8601 format for expires_at")

    with get_conn() as conn:
        file_row = conn.execute("SELECT id, owner_id FROM files WHERE id = ?", (req.file_id,)).fetchone()
        if not file_row:
            raise HTTPException(status_code=404, detail="File not found")
        if file_row["owner_id"] != req.owner_id:
            raise HTTPException(status_code=403, detail="Only the file owner can share this file")

        owner_share = conn.execute(
            """
            SELECT s.wrapped_key_hex, u.private_key_pem
            FROM file_shares s
            JOIN users u ON s.recipient_id = u.id
            WHERE s.file_id = ? AND s.recipient_id = ?
            """,
            (req.file_id, req.owner_id),
        ).fetchone()

        recipient = conn.execute("SELECT id, public_key_pem FROM users WHERE id = ?", (req.recipient_id,)).fetchone()
        if not recipient:
            raise HTTPException(status_code=404, detail="Recipient user not found")

    # Unwrap Kc using owner's private key and wrap for recipient
    file_key = unwrap_key(bytes.fromhex(owner_share["wrapped_key_hex"]), owner_share["private_key_pem"])
    wrapped_recipient_key = wrap_key(file_key, recipient["public_key_pem"])

    created_at = datetime.now(timezone.utc).isoformat()
    share_id = uuid.uuid4().hex

    with get_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO file_shares (
                id, file_id, recipient_id, wrapped_key_hex, expires_at, revoked, created_at, revoked_at
            )
            VALUES (?, ?, ?, ?, ?, 0, ?, NULL)
            """,
            (share_id, req.file_id, req.recipient_id, wrapped_recipient_key.hex(), expires_at_iso, created_at),
        )
        conn.commit()

    return {
        "share_id": share_id,
        "file_id": req.file_id,
        "recipient_id": req.recipient_id,
        "expires_at": expires_at_iso,
        "revoked": False,
        "status": "shared_successfully",
    }


@app.post("/revoke")
def revoke_access(req: RevokeRequest) -> dict:
    """
    Data owner revokes a recipient's access immediately.
    """
    with get_conn() as conn:
        file_row = conn.execute("SELECT owner_id FROM files WHERE id = ?", (req.file_id,)).fetchone()
        if not file_row:
            raise HTTPException(status_code=404, detail="File not found")
        if file_row["owner_id"] != req.owner_id:
            raise HTTPException(status_code=403, detail="Only owner can revoke access")
        if req.owner_id == req.recipient_id:
            raise HTTPException(status_code=400, detail="Cannot revoke owner's own access")

        revoked_at = datetime.now(timezone.utc).isoformat()
        cur = conn.execute(
            """
            UPDATE file_shares
            SET revoked = 1, revoked_at = ?
            WHERE file_id = ? AND recipient_id = ?
            """,
            (revoked_at, req.file_id, req.recipient_id),
        )
        conn.commit()

        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="No active share found for this recipient")

    return {
        "file_id": req.file_id,
        "recipient_id": req.recipient_id,
        "revoked": True,
        "revoked_at": revoked_at,
        "status": "revoked_successfully",
    }


# ---------------- Download with Expiry & Revocation Check ----------------


@app.get("/download/{file_id}")
def download_file(file_id: str, user_id: str) -> Response:
    """
    Verify access policy:
    1. Share must exist.
    2. Share must NOT be revoked (`revoked == 0`).
    3. Current time must be strictly BEFORE `expires_at` (if set).
    """
    with get_conn() as conn:
        file_row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
        if not file_row:
            raise HTTPException(status_code=404, detail="File not found")

        share = conn.execute(
            """
            SELECT s.wrapped_key_hex, s.expires_at, s.revoked, u.private_key_pem
            FROM file_shares s
            JOIN users u ON s.recipient_id = u.id
            WHERE s.file_id = ? AND s.recipient_id = ?
            """,
            (file_id, user_id),
        ).fetchone()

    if not share:
        raise HTTPException(status_code=403, detail="Access denied: user is not authorized to access this file")

    # Policy Check 1: Explicit Revocation
    if share["revoked"] == 1:
        raise HTTPException(status_code=403, detail="Access denied: access to this file has been revoked by the owner")

    # Policy Check 2: Expiry Check
    if share["expires_at"]:
        now = datetime.now(timezone.utc)
        expires_at = datetime.fromisoformat(share["expires_at"])
        if now >= expires_at:
            raise HTTPException(
                status_code=403,
                detail=f"Access denied: access link expired at {share['expires_at']}",
            )

    # Unwrap key and decrypt
    try:
        file_key = unwrap_key(bytes.fromhex(share["wrapped_key_hex"]), share["private_key_pem"])
    except Exception:
        raise HTTPException(status_code=400, detail="Key unwrapping failed")

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
