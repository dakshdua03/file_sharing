"""Slice 2 MVP: FastAPI + SQLite with AES-256-GCM file encryption."""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
import uuid

from cryptography.exceptions import InvalidTag
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import Response

from crypto import decrypt_file, encrypt_file, generate_file_key
from db import STORAGE_DIR, get_conn, init_db


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Secure File Sharing MVP (Slice 2 - AES-GCM Encryption)",
    description="Encrypted upload and download using AES-256-GCM with tamper detection.",
    version="0.2.0",
    lifespan=lifespan,
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "slice": "2-encryption"}


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)) -> dict:
    """
    Encrypt uploaded file bytes using AES-256-GCM before saving to disk.
    Raw plaintext is never written to disk.
    """
    plaintext = await file.read()
    if not plaintext:
        raise HTTPException(status_code=400, detail="Cannot upload an empty file")

    file_id = uuid.uuid4().hex
    safe_name = Path(file.filename or "unnamed.bin").name
    dest_path = STORAGE_DIR / f"{file_id}_{safe_name}.enc"

    # Generate random 256-bit symmetric key and encrypt with AES-GCM
    key = generate_file_key()
    ciphertext, nonce = encrypt_file(plaintext, key)

    dest_path.write_bytes(ciphertext)

    created_at = datetime.now(timezone.utc).isoformat()
    content_type = file.content_type or "application/octet-stream"

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO files (
                id, original_name, content_type, plaintext_size,
                ciphertext_size, storage_path, nonce_hex, key_hex, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                file_id,
                safe_name,
                content_type,
                len(plaintext),
                len(ciphertext),
                str(dest_path),
                nonce.hex(),
                key.hex(),
                created_at,
            ),
        )
        conn.commit()

    return {
        "file_id": file_id,
        "filename": safe_name,
        "plaintext_size": len(plaintext),
        "ciphertext_size": len(ciphertext),
        "created_at": created_at,
        "encryption": "AES-256-GCM",
    }


@app.get("/files")
def list_files() -> list[dict]:
    """List uploaded files metadata (excluding key for security)."""
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, original_name, content_type, plaintext_size,
                   ciphertext_size, created_at
            FROM files ORDER BY created_at DESC
            """
        ).fetchall()
    return [dict(row) for row in rows]


@app.get("/download/{file_id}")
def download_decrypted_file(file_id: str) -> Response:
    """Read encrypted ciphertext from disk, decrypt using AES-GCM, and return plaintext."""
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT original_name, content_type, storage_path, nonce_hex, key_hex
            FROM files WHERE id = ?
            """,
            (file_id,),
        ).fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="File not found")

    path = Path(row["storage_path"])
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Encrypted file missing on storage")

    ciphertext = path.read_bytes()
    key = bytes.fromhex(row["key_hex"])
    nonce = bytes.fromhex(row["nonce_hex"])

    try:
        plaintext = decrypt_file(ciphertext, key, nonce)
    except InvalidTag:
        raise HTTPException(
            status_code=400,
            detail="Integrity check failed: ciphertext or key was tampered with",
        )

    headers = {
        "Content-Disposition": f'attachment; filename="{row["original_name"]}"'
    }
    return Response(
        content=plaintext,
        media_type=row["content_type"],
        headers=headers,
    )


@app.get("/inspect-ciphertext/{file_id}")
def inspect_ciphertext(file_id: str) -> dict:
    """Inspect stored ciphertext without decrypting to demonstrate raw encrypted storage."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT storage_path, ciphertext_size, nonce_hex FROM files WHERE id = ?",
            (file_id,),
        ).fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="File not found")

    path = Path(row["storage_path"])
    raw_bytes = path.read_bytes() if path.is_file() else b""

    return {
        "file_id": file_id,
        "storage_path": row["storage_path"],
        "ciphertext_size": row["ciphertext_size"],
        "nonce_hex": row["nonce_hex"],
        "first_32_bytes_hex": raw_bytes[:32].hex(),
        "is_readable_text": False,
    }
