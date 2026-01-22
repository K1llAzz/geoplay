from __future__ import annotations

import os
import re
import hmac
import hashlib
import secrets
import shutil
import sqlite3
from pathlib import Path
from typing import Optional, List, Dict

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from itsdangerous import URLSafeSerializer, BadSignature


# -----------------------
# Config
# -----------------------
APP_TITLE = "GeoPlay"
ALLOWED_EXTS = {".mp4", ".webm", ".ogg"}

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
UPLOAD_DIR = BASE_DIR / "uploads"

STATIC_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Render Free: /tmp is writable. App folder may not persist.
DB_PATH = Path(os.environ.get("DB_PATH", "/tmp/geoplay.db"))

SECRET_KEY = os.environ.get("SECRET_KEY", "CHANGE_ME_ON_RENDER_TO_RANDOM_LONG_TEXT")
SESSION_COOKIE = "geoplay_session"

signer = URLSafeSerializer(SECRET_KEY, salt="geoplay-session")

app = FastAPI(title=APP_TITLE)
app.mount("/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# -----------------------
# DB helpers
# -----------------------
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS videos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            uploader TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

init_db()


# -----------------------
# Password hashing (no external libs)
# PBKDF2-HMAC-SHA256
# -----------------------
def hash_password(password: str, salt_hex: Optional[str] = None) -> tuple[str, str]:
    if salt_hex is None:
        salt = secrets.token_bytes(16)
        salt_hex = salt.hex()
    else:
        salt = bytes.fromhex(salt_hex)

    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return salt_hex, dk.hex()

def verify_password(password: str, salt_hex: str, expected_hash_hex: str) -> bool:
    _, got = hash_password(password, salt_hex=salt_hex)
    return hmac.compare_digest(got, expected_hash_hex)


# -----------------------
# Utility
# -----------------------
def safe_filename(name: str) -> str:
    name = os.path.basename(name).strip().replace("\x00", "")
    name = re.sub(r"[^A-Za-z0-9._ -]+", "_", name)
    return name or "upload"

def unique_path(directory: Path, filename: str) -> Path:
    p = directory / filename
    if not p.exists():
        return p
    stem = p.stem
    ext = p.suffix
    for i in range(1, 10000):
        cand = directory / f"{stem}_{i}{ext}"
        if not cand.exists():
            return cand
    raise HTTPException(500, "Too many duplicates")

def get_current_user(request: Request) -> Optional[str]:
    cookie = request.cookies.get(SESSION_COOKIE)
    if not cookie:
        return None
    try:
        data = signer.loads(cookie)
        return data.get("username")
    except BadSignature:
        return None

def require_user(request: Request) -> str:
    u = get_current_user(request)
    if not u:
        raise HTTPException(status_code=401, detail="Login required")
    return u


# -----------------------
# Pages
# -----------------------
@app.get("/", response_class=HTMLResponse)
def home_page():
    p = STATIC_DIR / "index.html"
    if not p.exists():
        return HTMLResponse("<h1>Missing static/index.html</h1>", status_code=500)
    return HTMLResponse(p.read_text(encoding="utf-8"))

@app.get("/login", response_class=HTMLResponse)
def login_page():
    p = STATIC_DIR / "login.html"
    if not p.exists():
        return HTMLResponse("<h1>Missing static/login.html</h1>", status_code=500)
    return HTMLResponse(p.read_text(encoding="utf-8"))

@app.get("/upload", response_class=HTMLResponse)
def upload_page():
    p = STATIC_DIR / "upload.html"
    if not p.exists():
        return HTMLResponse("<h1>Missing static/upload.html</h1>", status_code=500)
    return HTMLResponse(p.read_text(encoding="utf-8"))

@app.get("/health")
def health():
    return {"ok": True, "app": APP_TITLE, "db": str(DB_PATH)}


# -----------------------
# Auth API
# -----------------------
@app.get("/api/me")
def api_me(request: Request):
    u = get_current_user(request)
    return {"logged_in": bool(u), "username": u}

@app.post("/api/register")
def api_register(username: str = Form(...), password: str = Form(...)):
    username = username.strip()
    if len(username) < 3:
        raise HTTPException(400, "Username too short (min 3)")
    if len(password) < 6:
        raise HTTPException(400, "Password too short (min 6)")

    salt_hex, hash_hex = hash_password(password)

    conn = db()
    try:
        conn.execute(
            "INSERT INTO users(username, password_salt, password_hash) VALUES(?,?,?)",
            (username, salt_hex, hash_hex),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(400, "Username already exists")
    finally:
        conn.close()

    return {"ok": True}

@app.post("/api/login")
def api_login(response: Response, username: str = Form(...), password: str = Form(...)):
    username = username.strip()
    conn = db()
    row = conn.execute(
        "SELECT password_salt, password_hash FROM users WHERE username=?",
        (username,),
    ).fetchone()
    conn.close()

    if not row or not verify_password(password, row["password_salt"], row["password_hash"]):
        raise HTTPException(401, "Invalid username/password")

    token = signer.dumps({"username": username})
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        httponly=True,
        samesite="lax",
        secure=True,   # Render is HTTPS
        max_age=60 * 60 * 24 * 14,
    )
    return {"ok": True, "username": username}

@app.post("/api/logout")
def api_logout(response: Response):
    response.delete_cookie(SESSION_COOKIE)
    return {"ok": True}


# -----------------------
# Video API
# -----------------------
@app.get("/api/categories")
def api_categories():
    conn = db()
    rows = conn.execute("SELECT DISTINCT category FROM videos ORDER BY category ASC").fetchall()
    conn.close()
    return {"categories": [r["category"] for r in rows]}

@app.get("/api/videos")
def api_videos(category: Optional[str] = None) -> List[Dict[str, str]]:
    conn = db()
    if category and category.strip():
        rows = conn.execute(
            "SELECT * FROM videos WHERE category=? ORDER BY created_at DESC, id DESC",
            (category.strip(),),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM videos ORDER BY created_at DESC, id DESC"
        ).fetchall()
    conn.close()

    out = []
    for r in rows:
        out.append({
            "id": r["id"],
            "title": r["title"],
            "category": r["category"],
            "uploader": r["uploader"],
            "created_at": r["created_at"],
            "url": f"/uploads/{r['filename']}",
            "filename": r["filename"],
        })
    return out

@app.post("/api/upload")
async def api_upload(
    request: Request,
    file: UploadFile = File(...),
    title: str = Form(...),
    category: str = Form(...),
):
    uploader = require_user(request)

    title = title.strip() or "Untitled"
    category = category.strip() or "Uncategorized"

    if not file.filename:
        raise HTTPException(400, "No file")

    fname = safe_filename(file.filename)
    ext = Path(fname).suffix.lower()
    if ext not in ALLOWED_EXTS:
        raise HTTPException(400, f"Only: {', '.join(sorted(ALLOWED_EXTS))}")

    save_path = unique_path(UPLOAD_DIR, fname)

    try:
        with save_path.open("wb") as out:
            shutil.copyfileobj(file.file, out)
    finally:
        try:
            file.file.close()
        except Exception:
            pass

    conn = db()
    conn.execute(
        "INSERT INTO videos(filename, title, category, uploader) VALUES(?,?,?,?)",
        (save_path.name, title, category, uploader),
    )
    conn.commit()
    conn.close()

    return {"ok": True, "url": f"/uploads/{save_path.name}", "filename": save_path.name}
