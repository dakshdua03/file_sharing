"""Slice 1 MVP: FastAPI + SQLite plain file upload and download."""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
import uuid

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse

from db import STORAGE_DIR, get_conn, init_db


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Secure File Sharing MVP (Slice 1)",
    description="Plain upload/download pipeline with FastAPI + SQLite.",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)) -> dict:
    """Save an uploaded file to local storage and record metadata in SQLite."""
    file_id = uuid.uuid4().hex
    safe_name = Path(file.filename or "unnamed.bin").name
    dest_path = STORAGE_DIR / f"{file_id}_{safe_name}"

    data = await file.read()
    dest_path.write_bytes(data)

    created_at = datetime.now(timezone.utc).isoformat()
    content_type = file.content_type or "application/octet-stream"

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO files (id, original_name, content_type, size_bytes, storage_path, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (file_id, safe_name, content_type, len(data), str(dest_path), created_at),
        )
        conn.commit()

    return {
        "file_id": file_id,
        "filename": safe_name,
        "size_bytes": len(data),
        "created_at": created_at,
    }


@app.get("/files")
def list_files() -> list[dict]:
    """List all uploaded files."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, original_name, content_type, size_bytes, created_at FROM files ORDER BY created_at DESC"
        ).fetchall()
    return [dict(row) for row in rows]


@app.get("/download/{file_id}")
def download_file(file_id: str) -> FileResponse:
    """Download a previously uploaded file by ID."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT original_name, content_type, storage_path FROM files WHERE id = ?",
            (file_id,),
        ).fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="File not found")

    path = Path(row["storage_path"])
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Stored file missing on disk")

    return FileResponse(
        path=path,
        media_type=row["content_type"],
        filename=row["original_name"],
    )
