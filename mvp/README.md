# Secure File Sharing MVP — Slice 1

Minimal FastAPI + SQLite backend for plain file upload and download.

## Setup & Run

```bash
cd mvp
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

## Test

1. Open `http://127.0.0.1:8000/docs` in your browser.
2. Try `POST /upload` to upload any file and note the returned `file_id`.
3. Try `GET /files` to see the metadata stored in `mvp.db`.
4. Try `GET /download/{file_id}` to download the file back.
