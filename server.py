"""
server.py — FastAPI video upload + HUD player backend (works on Windows + Render)

Features:
- Serves the web UI at /
- Upload videos at POST /api/upload
- Lists uploaded videos at GET /api/videos
- Serves uploaded files at /uploads/<filename>
- Serves static files (index.html, etc.) from /static

Run locally (Windows):
  python -m pip install fastapi uvicorn python-multipart
  uvicorn server:app --reload --host 0.0.0.0 --port 8000

Render Start Command:
  uvicorn server:app --host 0.0.0.0 --port $PORT
"""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path
from typing import List, Dict

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

APP_TITLE = "Video Upload HUD"
ALLOWED_EXTS = {".mp4", ".webm", ".ogg"}  # browser-friendly formats

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
UPLOAD_DIR = BASE_DIR / "uploads"

STATIC_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title=APP_TITLE)

# Serve uploaded videos and static assets
app.mount("/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def _safe_filename(name: str) -> str:
    """
    Make filename safe for URLs/filesystems.
    """
    name = os.path.basename(name).strip()
    name = name.replace("\x00", "")
    # keep letters, numbers, dash, underscore, dot, space; replace others with underscore
    name = re.sub(r"[^A-Za-z0-9._ -]+", "_", name)
    # avoid empty names
    return name or "upload"


def _unique_path(directory: Path, filename: str) -> Path:
    """
    If filename exists, append _1, _2, ... to avoid overwrite.
    """
    target = directory / filename
    if not target.exists():
        return target

    stem = target.stem
    ext = target.suffix
    for i in range(1, 10000):
        candidate = directory / f"{stem}_{i}{ext}"
        if not candidate.exists():
            return candidate
    raise HTTPException(status_code=500, detail="Too many files with same name")


@app.get("/", response_class=HTMLResponse)
def home():
    """
    Serve your HUD player page.
    Put your frontend file at: static/index.html
    """
    index_path = STATIC_DIR / "index.html"
    if not index_path.exists():
        return HTMLResponse(
            """
            <h1>Missing static/index.html</h1>
            <p>Create a folder named <b>static</b> next to server.py and place <b>index.html</b> inside it.</p>
            <p>Then restart the server.</p>
            """,
            status_code=500,
        )
    return HTMLResponse(index_path.read_text(encoding="utf-8"))


@app.get("/index.html")
def redirect_index():
    return RedirectResponse(url="/")


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/api/videos", response_class=JSONResponse)
def list_videos() -> List[Dict[str, str]]:
    """
    Return list of uploaded videos for the frontend playlist.
    Output format:
      [{ "name": "file.mp4", "url": "/uploads/file.mp4" }, ...]
    """
    items: List[Dict[str, str]] = []
    for p in sorted(UPLOAD_DIR.iterdir()):
        if p.is_file() and p.suffix.lower() in ALLOWED_EXTS:
            items.append({"name": p.name, "url": f"/uploads/{p.name}"})
    return items


@app.post("/api/upload", response_class=JSONResponse)
async def upload_video(file: UploadFile = File(...)):
    """
    Upload a single video file (mp4/webm/ogg).
    Returns:
      {"ok": true, "name": "...", "url": "..."}
    """
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    original = file.filename
    safe = _safe_filename(original)
    ext = Path(safe).suffix.lower()

    if ext not in ALLOWED_EXTS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Allowed: {', '.join(sorted(ALLOWED_EXTS))}",
        )

    save_path = _unique_path(UPLOAD_DIR, safe)

    # Stream save to disk (safe for big files)
    try:
        with save_path.open("wb") as out:
            shutil.copyfileobj(file.file, out)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {e}") from e
    finally:
        try:
            file.file.close()
        except Exception:
            pass

    return {"ok": True, "name": save_path.name, "url": f"/uploads/{save_path.name}"}
