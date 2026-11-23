"""Slice 6 MVP: IPFS Decentralized Storage + Web Dashboard Interface.

Complete Semester 1 Baseline Prototype:
- Bulk Encryption: AES-256-GCM.
- Key Wrapping: RSA-OAEP for authorized recipients.
- Decentralized Storage: Ciphertexts stored with real IPFS CIDv1 identifiers (Pinata cloud or local IPFS node).
- Policy: Time-to-Live Expiry + Immediate Revocation.
- Tamper-Evident Audit Log: Hash-chained audit entries with cryptographic verification.
- User Dashboard: Full Single-Page Web UI served at `/`.
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import uuid

from cryptography.exceptions import InvalidTag
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, Response
from pydantic import BaseModel

from crypto import (
    decrypt_file,
    encrypt_file,
    generate_file_key,
    generate_rsa_keypair,
    unwrap_key,
    wrap_key,
)
from db import (
    GENESIS_HASH,
    append_audit_log,
    compute_entry_hash,
    get_conn,
    init_db,
)
from ipfs import IPFSClient

BASE_DIR = Path(__file__).resolve().parent
HTML_INDEX = BASE_DIR / "templates" / "index.html"
ipfs_client = IPFSClient()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Secure University File Sharing — MVP (Slice 6)",
    description="AES-GCM encryption, RSA envelope sharing, IPFS decentralized storage, and hash-chain audit.",
    version="0.6.0",
    lifespan=lifespan,
)


class UserCreate(BaseModel):
    username: str
    role: str = "student"


class ShareRequest(BaseModel):
    file_id: str
    owner_id: str
    recipient_id: str
    expires_at: Optional[str] = None


class RevokeRequest(BaseModel):
    file_id: str
    owner_id: str
    recipient_id: str


# ---------------- Web Interface Dashboard ----------------


@app.get("/", response_class=HTMLResponse)
def index_view():
    """Serve the single-page user web dashboard."""
    if not HTML_INDEX.is_file():
        raise HTTPException(status_code=404, detail="Web dashboard template not found")
    return HTMLResponse(content=HTML_INDEX.read_text(encoding="utf-8"))


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "slice": "6-ipfs-ui"}


# ---------------- User Endpoints ----------------


@app.post("/users")
def register_user(req: UserCreate) -> dict:
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
            append_audit_log(
                conn,
                timestamp=created_at,
                user_id=user_id,
                action="USER_REGISTERED",
                details=f"username={req.username}, role={req.role}",
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


# ---------------- Upload to IPFS with Envelope Encryption ----------------


@app.post("/upload")
async def upload_file(
    owner_id: str = Form(...),
    file: UploadFile = File(...),
) -> dict:
    with get_conn() as conn:
        owner = conn.execute("SELECT id, public_key_pem FROM users WHERE id = ?", (owner_id,)).fetchone()
        if not owner:
            raise HTTPException(status_code=404, detail="Owner user not found")

    plaintext = await file.read()
    if not plaintext:
        raise HTTPException(status_code=400, detail="Cannot upload empty file")

    file_id = uuid.uuid4().hex
    safe_name = Path(file.filename or "unnamed.bin").name

    # 1. Symmetric encryption of bulk bytes
    file_key = generate_file_key()
    ciphertext, nonce = encrypt_file(plaintext, file_key)

    # 2. Push ciphertext to IPFS (returns CIDv1)
    ipfs_meta = ipfs_client.upload_encrypted(ciphertext, safe_name)
    cid = ipfs_meta["cid"]

    # 3. Wrap file_key with owner's RSA public key
    wrapped_owner_key = wrap_key(file_key, owner["public_key_pem"])
    created_at = datetime.now(timezone.utc).isoformat()
    content_type = file.content_type or "application/octet-stream"

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO files (
                id, owner_id, original_name, content_type,
                plaintext_size, ciphertext_size, ipfs_cid, storage_path, nonce_hex, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                file_id,
                owner_id,
                safe_name,
                content_type,
                len(plaintext),
                len(ciphertext),
                cid,
                ipfs_meta["storage_path"],
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
        append_audit_log(
            conn,
            timestamp=created_at,
            user_id=owner_id,
            action="FILE_UPLOADED_TO_IPFS",
            file_id=file_id,
            details=f"filename={safe_name}, cid={cid}",
        )
        conn.commit()

    return {
        "file_id": file_id,
        "owner_id": owner_id,
        "filename": safe_name,
        "ipfs_cid": cid,
        "plaintext_size": len(plaintext),
        "ciphertext_size": len(ciphertext),
        "created_at": created_at,
    }


@app.get("/files")
def list_files() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT f.id, f.owner_id, u.username as owner_name, f.original_name,
                   f.content_type, f.plaintext_size, f.ciphertext_size, f.ipfs_cid, f.created_at
            FROM files f
            JOIN users u ON f.owner_id = u.id
            ORDER BY f.created_at DESC
            """
        ).fetchall()
    return [dict(row) for row in rows]


# ---------------- Sharing & Revocation ----------------


@app.post("/share")
def share_file(req: ShareRequest) -> dict:
    expires_at_iso = None
    if req.expires_at:
        try:
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
        append_audit_log(
            conn,
            timestamp=created_at,
            user_id=req.owner_id,
            action="FILE_SHARED",
            file_id=req.file_id,
            details=f"recipient_id={req.recipient_id}, expires_at={expires_at_iso}",
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
    with get_conn() as conn:
        file_row = conn.execute("SELECT owner_id FROM files WHERE id = ?", (req.file_id,)).fetchone()
        if not file_row:
            raise HTTPException(status_code=404, detail="File not found")
        if file_row["owner_id"] != req.owner_id:
            raise HTTPException(status_code=403, detail="Only owner can revoke access")

        revoked_at = datetime.now(timezone.utc).isoformat()
        cur = conn.execute(
            """
            UPDATE file_shares
            SET revoked = 1, revoked_at = ?
            WHERE file_id = ? AND recipient_id = ?
            """,
            (revoked_at, req.file_id, req.recipient_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="No active share found for this recipient")

        append_audit_log(
            conn,
            timestamp=revoked_at,
            user_id=req.owner_id,
            action="ACCESS_REVOKED",
            file_id=req.file_id,
            details=f"recipient_id={req.recipient_id}",
        )
        conn.commit()

    return {"status": "revoked_successfully", "revoked_at": revoked_at}


# ---------------- Download & Decrypt from IPFS ----------------


@app.get("/download/{file_id}")
def download_file(file_id: str, user_id: str) -> Response:
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        file_row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
        if not file_row:
            append_audit_log(conn, now_iso, user_id, "DOWNLOAD_DENIED", file_id, "file_not_found")
            conn.commit()
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
            append_audit_log(conn, now_iso, user_id, "DOWNLOAD_DENIED", file_id, "not_authorized")
            conn.commit()
            raise HTTPException(status_code=403, detail="Access denied: user is not authorized to access this file")

        if share["revoked"] == 1:
            append_audit_log(conn, now_iso, user_id, "DOWNLOAD_DENIED", file_id, "access_revoked")
            conn.commit()
            raise HTTPException(status_code=403, detail="Access denied: access to this file has been revoked by the owner")

        if share["expires_at"]:
            now = datetime.now(timezone.utc)
            expires_at = datetime.fromisoformat(share["expires_at"])
            if now >= expires_at:
                append_audit_log(conn, now_iso, user_id, "DOWNLOAD_DENIED", file_id, "link_expired")
                conn.commit()
                raise HTTPException(status_code=403, detail=f"Access denied: access link expired at {share['expires_at']}")

        append_audit_log(conn, now_iso, user_id, "DOWNLOAD_GRANTED", file_id, f"ipfs_cid={file_row['ipfs_cid']}")
        conn.commit()

    # 1. Unwrap symmetric file key with recipient's private key
    try:
        file_key = unwrap_key(bytes.fromhex(share["wrapped_key_hex"]), share["private_key_pem"])
    except Exception:
        raise HTTPException(status_code=400, detail="Key unwrapping failed")

    # 2. Fetch encrypted ciphertext from IPFS via CID
    try:
        ciphertext = ipfs_client.fetch_encrypted(file_row["ipfs_cid"])
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Ciphertext not found on IPFS")

    # 3. Decrypt ciphertext with AES-256-GCM
    nonce = bytes.fromhex(file_row["nonce_hex"])
    try:
        plaintext = decrypt_file(ciphertext, file_key, nonce)
    except InvalidTag:
        raise HTTPException(status_code=400, detail="Tamper check failed on IPFS download")

    headers = {
        "Content-Disposition": f'attachment; filename="{file_row["original_name"]}"'
    }
    return Response(content=plaintext, media_type=file_row["content_type"], headers=headers)


# ---------------- Audit Endpoints ----------------


@app.get("/audit/logs")
def get_audit_logs() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM audit_logs ORDER BY sequence_id ASC").fetchall()
    return [dict(row) for row in rows]


@app.get("/audit/verify")
def verify_audit_chain() -> dict:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM audit_logs ORDER BY sequence_id ASC").fetchall()

    if not rows:
        return {"status": "VALID", "total_entries": 0, "message": "Audit log is empty"}

    expected_prev = GENESIS_HASH
    for row in rows:
        seq = row["sequence_id"]
        if row["prev_hash"] != expected_prev:
            return {
                "status": "TAMPERED",
                "broken_sequence_id": seq,
                "error": f"Broken chain link at seq {seq}",
            }

        recalculated = compute_entry_hash(
            seq_id=seq,
            timestamp=row["timestamp"],
            user_id=row["user_id"],
            file_id=row["file_id"],
            action=row["action"],
            details=row["details"],
            prev_hash=row["prev_hash"],
        )
        if recalculated != row["entry_hash"]:
            return {
                "status": "TAMPERED",
                "broken_sequence_id": seq,
                "error": f"Tampered digest at seq {seq}",
            }

        expected_prev = row["entry_hash"]

    return {
        "status": "VALID",
        "total_entries": len(rows),
        "latest_hash": expected_prev,
        "message": "Audit chain is 100% cryptographically intact.",
    }
