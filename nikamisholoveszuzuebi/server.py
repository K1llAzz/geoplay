from __future__ import annotations

import os
import re
import hmac
import time
import json
import math
import hashlib
import secrets
import shutil
import sqlite3
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from itsdangerous import URLSafeSerializer, BadSignature

# OAuth (works only if you set provider env vars)
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config


# -----------------------
# Basic config
# -----------------------
APP_TITLE = "GeoPlay"
ALLOWED_EXTS = {".mp4", ".webm", ".ogg"}

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
UPLOAD_DIR = BASE_DIR / "uploads"

STATIC_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Render Free: /tmp is writable. App folder may reset.
DB_PATH = Path(os.environ.get("DB_PATH", "/tmp/geoplay.db"))

SECRET_KEY = os.environ.get("SECRET_KEY", "CHANGE_ME_ON_RENDER_LONG_RANDOM")
SESSION_COOKIE = "geoplay_session"
signer = URLSafeSerializer(SECRET_KEY, salt="geoplay-session")

app = FastAPI(title=APP_TITLE)
app.mount("/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# -----------------------
# OAuth setup (optional)
# -----------------------
config = Config(environ=os.environ)
oauth = OAuth(config)

# You must set these env vars in Render for each provider:
# GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
# GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET
# FACEBOOK_CLIENT_ID, FACEBOOK_CLIENT_SECRET
# X_CLIENT_ID, X_CLIENT_SECRET (X OAuth is more complex; this is a placeholder)
#
# Also set OAUTH_REDIRECT_BASE=https://geoplay.onrender.com
OAUTH_REDIRECT_BASE = os.environ.get("OAUTH_REDIRECT_BASE", "http://localhost:8000")

def _maybe_register_oauth():
    # Google
    if os.environ.get("GOOGLE_CLIENT_ID") and os.environ.get("GOOGLE_CLIENT_SECRET"):
        oauth.register(
            name="google",
            client_id=os.environ["GOOGLE_CLIENT_ID"],
            client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )

    # GitHub
    if os.environ.get("GITHUB_CLIENT_ID") and os.environ.get("GITHUB_CLIENT_SECRET"):
        oauth.register(
            name="github",
            client_id=os.environ["GITHUB_CLIENT_ID"],
            client_secret=os.environ["GITHUB_CLIENT_SECRET"],
            access_token_url="https://github.com/login/oauth/access_token",
            authorize_url="https://github.com/login/oauth/authorize",
            api_base_url="https://api.github.com/",
            client_kwargs={"scope": "user:email"},
        )

    # Facebook (basic)
    if os.environ.get("FACEBOOK_CLIENT_ID") and os.environ.get("FACEBOOK_CLIENT_SECRET"):
        oauth.register(
            name="facebook",
            client_id=os.environ["FACEBOOK_CLIENT_ID"],
            client_secret=os.environ["FACEBOOK_CLIENT_SECRET"],
            access_token_url="https://graph.facebook.com/v18.0/oauth/access_token",
            authorize_url="https://www.facebook.com/v18.0/dialog/oauth",
            api_base_url="https://graph.facebook.com/",
            client_kwargs={"scope": "email,public_profile"},
        )

    # X/Twitter: placeholder (real X OAuth setup varies by app type)
    # Keep the routes but you’ll need to adjust provider details later.

_maybe_register_oauth()


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
        display_name TEXT NOT NULL,
        password_salt TEXT,
        password_hash TEXT,
        oauth_provider TEXT,
        oauth_subject TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS follows (
        follower TEXT NOT NULL,
        following TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(follower, following)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS videos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        uploader TEXT NOT NULL,
        visibility TEXT NOT NULL,   -- public | friends | private
        rating TEXT NOT NULL,       -- clean | mature
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        views INTEGER NOT NULL DEFAULT 0
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS reactions (
        username TEXT NOT NULL,
        video_id INTEGER NOT NULL,
        value INTEGER NOT NULL,     -- 1 like, -1 dislike
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(username, video_id)
    )
    """)

    conn.commit()
    conn.close()

init_db()


# -----------------------
# Password hashing (PBKDF2, no external libs)
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
# Auth + session
# -----------------------
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

def set_session_cookie(response: Response, username: str):
    token = signer.dumps({"username": username})
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        httponly=True,
        samesite="lax",
        secure=bool(os.environ.get("RENDER")),  # Render HTTPS
        max_age=60 * 60 * 24 * 14,
    )

def is_friends(conn: sqlite3.Connection, a: str, b: str) -> bool:
    # friends = mutual follow
    r1 = conn.execute("SELECT 1 FROM follows WHERE follower=? AND following=?", (a, b)).fetchone()
    r2 = conn.execute("SELECT 1 FROM follows WHERE follower=? AND following=?", (b, a)).fetchone()
    return bool(r1 and r2)


# -----------------------
# Utilities
# -----------------------
BAD_WORDS = {"fuck", "shit", "bitch", "cunt", "nigger"}  # basic example list (you can expand)

def censor_text(s: str) -> str:
    words = s.split()
    out = []
    for w in words:
        lw = re.sub(r"[^a-zA-Z]", "", w).lower()
        if lw in BAD_WORDS and len(w) > 2:
            # mask inner letters
            out.append(w[0] + "*" * (len(w) - 2) + w[-1])
        else:
            out.append(w)
    return " ".join(out)

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


# -----------------------
# Pages
# -----------------------
def _read_static(name: str) -> HTMLResponse:
    p = STATIC_DIR / name
    if not p.exists():
        return HTMLResponse(f"<h1>Missing static/{name}</h1>", status_code=500)
    return HTMLResponse(p.read_text(encoding="utf-8"))

@app.get("/", response_class=HTMLResponse)
def home_page():
    return _read_static("index.html")

@app.get("/login", response_class=HTMLResponse)
def login_page():
    return _read_static("login.html")

@app.get("/upload", response_class=HTMLResponse)
def upload_page():
    return _read_static("upload.html")

@app.get("/u/{username}", response_class=HTMLResponse)
def profile_page(username: str):
    return _read_static("profile.html")

@app.get("/v/{video_id}", response_class=HTMLResponse)
def video_page(video_id: int):
    return _read_static("video.html")

@app.get("/health")
def health():
    return {"ok": True, "app": APP_TITLE, "db": str(DB_PATH)}


# -----------------------
# OAuth routes (optional)
# -----------------------
@app.get("/auth/{provider}/login")
async def oauth_login(provider: str, request: Request):
    if provider not in oauth._clients:
        raise HTTPException(400, f"Provider not configured: {provider}")
    client = oauth.create_client(provider)
    redirect_uri = f"{OAUTH_REDIRECT_BASE}/auth/{provider}/callback"
    return await client.authorize_redirect(request, redirect_uri)

@app.get("/auth/{provider}/callback")
async def oauth_callback(provider: str, request: Request):
    if provider not in oauth._clients:
        raise HTTPException(400, f"Provider not configured: {provider}")

    client = oauth.create_client(provider)

    # token fetch
    token = await client.authorize_access_token(request)

    # user info per provider
    if provider == "google":
        user = await client.parse_id_token(request, token)
        subject = user.get("sub")
        email = user.get("email") or f"google_{subject}"
        username = _oauth_username(provider, email, subject)
        display = user.get("name") or username

    elif provider == "github":
        resp = await client.get("user", token=token)
        gh = resp.json()
        subject = str(gh.get("id"))
        login = gh.get("login") or f"github_{subject}"
        username = _oauth_username(provider, login, subject)
        display = gh.get("name") or login

    elif provider == "facebook":
        resp = await client.get("me?fields=id,name,email", token=token)
        fb = resp.json()
        subject = str(fb.get("id"))
        email = fb.get("email") or f"facebook_{subject}"
        username = _oauth_username(provider, email, subject)
        display = fb.get("name") or username

    else:
        raise HTTPException(400, "Provider callback not implemented fully")

    # upsert user
    conn = db()
    row = conn.execute(
        "SELECT username FROM users WHERE oauth_provider=? AND oauth_subject=?",
        (provider, subject),
    ).fetchone()

    if row:
        username = row["username"]
    else:
        # create if username not taken
        base = re.sub(r"[^a-zA-Z0-9_]+", "_", username.lower())[:20] or "user"
        candidate = base
        for i in range(0, 10000):
            try_name = candidate if i == 0 else f"{base}{i}"
            try:
                conn.execute(
                    "INSERT INTO users(username, display_name, oauth_provider, oauth_subject) VALUES(?,?,?,?)",
                    (try_name, display, provider, subject),
                )
                conn.commit()
                username = try_name
                break
            except sqlite3.IntegrityError:
                continue

    conn.close()

    resp = RedirectResponse(url="/")
    set_session_cookie(resp, username)
    return resp

def _oauth_username(provider: str, raw: str, subject: str) -> str:
    raw = (raw or subject or "").strip()
    raw = raw.split("@")[0]
    raw = re.sub(r"[^a-zA-Z0-9_]+", "_", raw).strip("_").lower()
    return raw[:24] or f"{provider}_{subject}"


# -----------------------
# Auth API
# -----------------------
@app.get("/api/me")
def api_me(request: Request):
    u = get_current_user(request)
    if not u:
        return {"logged_in": False, "username": None}
    conn = db()
    row = conn.execute("SELECT display_name FROM users WHERE username=?", (u,)).fetchone()
    conn.close()
    return {"logged_in": True, "username": u, "display_name": row["display_name"] if row else u}

@app.post("/api/register")
def api_register(username: str = Form(...), password: str = Form(...), display_name: str = Form("")):
    username = username.strip().lower()
    display_name = (display_name.strip() or username)

    if len(username) < 3:
        raise HTTPException(400, "Username too short (min 3)")
    if len(password) < 6:
        raise HTTPException(400, "Password too short (min 6)")
    if not re.fullmatch(r"[a-z0-9_]+", username):
        raise HTTPException(400, "Username allowed: a-z 0-9 _")

    salt_hex, hash_hex = hash_password(password)

    conn = db()
    try:
        conn.execute(
            "INSERT INTO users(username, display_name, password_salt, password_hash) VALUES(?,?,?,?)",
            (username, display_name, salt_hex, hash_hex),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(400, "Username already exists")
    finally:
        conn.close()

    return {"ok": True}

@app.post("/api/login")
def api_login(response: Response, username: str = Form(...), password: str = Form(...)):
    username = username.strip().lower()
    conn = db()
    row = conn.execute(
        "SELECT password_salt, password_hash FROM users WHERE username=?",
        (username,),
    ).fetchone()
    conn.close()

    if not row or not row["password_salt"] or not verify_password(password, row["password_salt"], row["password_hash"]):
        raise HTTPException(401, "Invalid username/password")

    set_session_cookie(response, username)
    return {"ok": True}

@app.post("/api/logout")
def api_logout(response: Response):
    response.delete_cookie(SESSION_COOKIE)
    return {"ok": True}


# -----------------------
# Social: follow + profile
# -----------------------
@app.get("/api/user/{username}")
def api_user(username: str, request: Request):
    viewer = get_current_user(request)
    conn = db()

    u = conn.execute("SELECT username, display_name, created_at FROM users WHERE username=?", (username,)).fetchone()
    if not u:
        conn.close()
        raise HTTPException(404, "User not found")

    followers = conn.execute("SELECT COUNT(*) c FROM follows WHERE following=?", (username,)).fetchone()["c"]
    following = conn.execute("SELECT COUNT(*) c FROM follows WHERE follower=?", (username,)).fetchone()["c"]

    is_following = False
    are_friends = False
    if viewer:
        is_following = bool(conn.execute("SELECT 1 FROM follows WHERE follower=? AND following=?", (viewer, username)).fetchone())
        if viewer != username:
            are_friends = is_friends(conn, viewer, username)

    conn.close()
    return {
        "username": u["username"],
        "display_name": u["display_name"],
        "created_at": u["created_at"],
        "followers": followers,
        "following": following,
        "viewer_is_following": is_following,
        "viewer_are_friends": are_friends,
    }

@app.post("/api/follow/{username}")
def api_follow(username: str, request: Request):
    me = require_user(request)
    if me == username:
        raise HTTPException(400, "Cannot follow yourself")
    conn = db()
    try:
        conn.execute("INSERT OR IGNORE INTO follows(follower, following) VALUES(?,?)", (me, username))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}

@app.post("/api/unfollow/{username}")
def api_unfollow(username: str, request: Request):
    me = require_user(request)
    conn = db()
    try:
        conn.execute("DELETE FROM follows WHERE follower=? AND following=?", (me, username))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}


# -----------------------
# Videos: upload, list, react, view
# -----------------------
def _counts(conn: sqlite3.Connection, video_id: int) -> tuple[int, int]:
    likes = conn.execute("SELECT COUNT(*) c FROM reactions WHERE video_id=? AND value=1", (video_id,)).fetchone()["c"]
    dislikes = conn.execute("SELECT COUNT(*) c FROM reactions WHERE video_id=? AND value=-1", (video_id,)).fetchone()["c"]
    return int(likes), int(dislikes)

def _can_view(conn: sqlite3.Connection, viewer: Optional[str], vrow: sqlite3.Row) -> bool:
    vis = vrow["visibility"]
    uploader = vrow["uploader"]
    if vis == "public":
        return True
    if viewer is None:
        return False
    if viewer == uploader:
        return True
    if vis == "private":
        return False
    # friends
    return is_friends(conn, viewer, uploader)

def _trending_score(views: int, likes: int, dislikes: int, created_at: str) -> float:
    # Simple score with time decay.
    # New videos get a boost; older need more engagement.
    # created_at is sqlite datetime string; we approximate age using "now - last modified" if parsing fails.
    # Safer: use views+likes-dislikes with decay.
    base = views + 3 * likes - 2 * dislikes
    # crude decay: assume created_at exists; use hours since epoch fallback
    # If parsing fails, no decay.
    decay = 1.0
    try:
        # sqlite "YYYY-MM-DD HH:MM:SS"
        t = time.strptime(created_at.split(".")[0], "%Y-%m-%d %H:%M:%S")
        age_hours = max(0.0, (time.time() - time.mktime(t)) / 3600.0)
        decay = 1.0 / math.pow(1.0 + age_hours / 24.0, 1.2)  # ~days decay
    except Exception:
        pass
    return float(base) * decay

@app.post("/api/upload")
async def api_upload(
    request: Request,
    file: UploadFile = File(...),
    title: Optional[str] = Form(None),
    category: Optional[str] = Form(None),
    visibility: Optional[str] = Form("public"),    # public|friends|private
    rating: Optional[str] = Form("clean"),         # clean|mature
    censor: Optional[str] = Form("off"),           # "on"/"off"
):
    uploader = require_user(request)

    title = (title or "").strip() or (file.filename or "Untitled")
    category = (category or "").strip() or "Uncategorized"
    visibility = (visibility or "public").strip().lower()
    rating = (rating or "clean").strip().lower()
    censor_on = (censor or "off").lower() == "on"

    if visibility not in {"public", "friends", "private"}:
        raise HTTPException(400, "visibility must be public|friends|private")
    if rating not in {"clean", "mature"}:
        raise HTTPException(400, "rating must be clean|mature")

    if censor_on:
        title = censor_text(title)

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
        "INSERT INTO videos(filename, title, category, uploader, visibility, rating) VALUES(?,?,?,?,?,?)",
        (save_path.name, title, category, uploader, visibility, rating),
    )
    vid = conn.execute("SELECT last_insert_rowid() id").fetchone()["id"]
    conn.commit()
    conn.close()

    return {"ok": True, "id": int(vid), "url": f"/uploads/{save_path.name}"}

@app.get("/api/video/{video_id}")
def api_video(video_id: int, request: Request):
    viewer = get_current_user(request)
    conn = db()
    v = conn.execute("SELECT * FROM videos WHERE id=?", (video_id,)).fetchone()
    if not v:
        conn.close()
        raise HTTPException(404, "Not found")

    if not _can_view(conn, viewer, v):
        conn.close()
        raise HTTPException(403, "Not allowed")

    likes, dislikes = _counts(conn, video_id)

    my_react = 0
    if viewer:
        r = conn.execute("SELECT value FROM reactions WHERE username=? AND video_id=?", (viewer, video_id)).fetchone()
        my_react = int(r["value"]) if r else 0

    conn.close()
    return {
        "id": int(v["id"]),
        "title": v["title"],
        "category": v["category"],
        "uploader": v["uploader"],
        "visibility": v["visibility"],
        "rating": v["rating"],
        "created_at": v["created_at"],
        "views": int(v["views"]),
        "likes": likes,
        "dislikes": dislikes,
        "my_reaction": my_react,
        "url": f"/uploads/{v['filename']}",
    }

@app.post("/api/video/{video_id}/view")
def api_view(video_id: int, request: Request):
    viewer = get_current_user(request)
    conn = db()
    v = conn.execute("SELECT * FROM videos WHERE id=?", (video_id,)).fetchone()
    if not v:
        conn.close()
        raise HTTPException(404, "Not found")
    if not _can_view(conn, viewer, v):
        conn.close()
        raise HTTPException(403, "Not allowed")

    conn.execute("UPDATE videos SET views = views + 1 WHERE id=?", (video_id,))
    conn.commit()
    views = conn.execute("SELECT views FROM videos WHERE id=?", (video_id,)).fetchone()["views"]
    conn.close()
    return {"ok": True, "views": int(views)}

@app.post("/api/video/{video_id}/react")
def api_react(video_id: int, request: Request, value: int = Form(...)):
    # value: 1 like, -1 dislike, 0 clear
    me = require_user(request)
    if value not in (-1, 0, 1):
        raise HTTPException(400, "value must be -1,0,1")

    conn = db()
    v = conn.execute("SELECT * FROM videos WHERE id=?", (video_id,)).fetchone()
    if not v:
        conn.close()
        raise HTTPException(404, "Not found")
    if not _can_view(conn, me, v):
        conn.close()
        raise HTTPException(403, "Not allowed")

    if value == 0:
        conn.execute("DELETE FROM reactions WHERE username=? AND video_id=?", (me, video_id))
    else:
        conn.execute(
            "INSERT INTO reactions(username, video_id, value) VALUES(?,?,?) "
            "ON CONFLICT(username, video_id) DO UPDATE SET value=excluded.value",
            (me, video_id, value),
        )
    conn.commit()

    likes, dislikes = _counts(conn, video_id)
    conn.close()
    return {"ok": True, "likes": likes, "dislikes": dislikes, "my_reaction": value}

@app.get("/api/categories")
def api_categories():
    conn = db()
    rows = conn.execute("SELECT DISTINCT category FROM videos ORDER BY category ASC").fetchall()
    conn.close()
    return {"categories": [r["category"] for r in rows]}

@app.get("/api/videos")
def api_videos(
    request: Request,
    category: Optional[str] = None,
    sort: str = "trending",  # trending|most_liked|most_viewed|least_liked|least_viewed
):
    viewer = get_current_user(request)
    category = (category or "").strip()
    sort = (sort or "trending").strip()

    conn = db()

    # fetch candidates
    if category:
        rows = conn.execute("SELECT * FROM videos WHERE category=? ORDER BY created_at DESC, id DESC", (category,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM videos ORDER BY created_at DESC, id DESC").fetchall()

    items = []
    for v in rows:
        if not _can_view(conn, viewer, v):
            continue
        vid = int(v["id"])
        likes, dislikes = _counts(conn, vid)
        views = int(v["views"])
        score = _trending_score(views, likes, dislikes, v["created_at"])
        items.append({
            "id": vid,
            "title": v["title"],
            "category": v["category"],
            "uploader": v["uploader"],
            "visibility": v["visibility"],
            "rating": v["rating"],
            "created_at": v["created_at"],
            "views": views,
            "likes": likes,
            "dislikes": dislikes,
            "score": score,
            "url": f"/uploads/{v['filename']}",
        })

    # apply sorting
    if sort == "most_liked":
        items.sort(key=lambda x: (x["likes"], x["views"]), reverse=True)
    elif sort == "most_viewed":
        items.sort(key=lambda x: (x["views"], x["likes"]), reverse=True)
    elif sort == "least_liked":
        items.sort(key=lambda x: (x["likes"], x["views"]))
    elif sort == "least_viewed":
        items.sort(key=lambda x: (x["views"], x["likes"]))
    else:
        # trending default
        items.sort(key=lambda x: (x["score"], x["views"]), reverse=True)

    conn.close()
    return items
conn = db()
init_db(conn.execute("""
CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  video_id INTEGER NOT NULL,
  username TEXT NOT NULL,
  text TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

)
@app.get("/api/video/{video_id}/comments")
def api_get_comments(video_id: int, request: Request):
    viewer = get_current_user(request)
    conn = db()
    v = conn.execute("SELECT * FROM videos WHERE id=?", (video_id,)).fetchone()
    if not v:
        conn.close()
        raise HTTPException(404, "Not found")
    if not _can_view(conn, viewer, v):
        conn.close()
        raise HTTPException(403, "Not allowed")

    rows = conn.execute(
        "SELECT id, username, text, created_at FROM comments WHERE video_id=? ORDER BY id DESC LIMIT 200",
        (video_id,),
    ).fetchall()
    conn.close()
    return [{"id": int(r["id"]), "username": r["username"], "text": r["text"], "created_at": r["created_at"]} for r in rows]


@app.post("/api/video/{video_id}/comments")
def api_add_comment(video_id: int, request: Request, text: str = Form(...)):
    me = require_user(request)
    text = (text or "").strip()
    if len(text) < 1:
        raise HTTPException(400, "Empty comment")
    if len(text) > 500:
        raise HTTPException(400, "Comment too long (max 500)")

    conn = db()
    v = conn.execute("SELECT * FROM videos WHERE id=?", (video_id,)).fetchone()
    if not v:
        conn.close()
        raise HTTPException(404, "Not found")
    if not _can_view(conn, me, v):
        conn.close()
        raise HTTPException(403, "Not allowed")

    conn.execute(
        "INSERT INTO comments(video_id, username, text) VALUES(?,?,?)",
        (video_id, me, text),
    )
    conn.commit()
    conn.close()
    return {"ok": True}
