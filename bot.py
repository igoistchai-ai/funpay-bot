"""NEZZX AI Telegram Conv — single-file FastAPI dashboard + Telegram bot.

Deploy as one file (bot.py) on Render. See the deployment notes that ship with it.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import collections
import difflib
import hashlib
import hmac
import html
import json
import logging
import os
import re
import secrets
import sqlite3
import time
import urllib.request
import urllib.error
import urllib.parse
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, parse_qsl, urljoin, urlparse

from bs4 import BeautifulSoup
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, StreamingResponse
from typing import AsyncIterator
from pydantic import BaseModel, Field

try:  # optional: .env files for local runs
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover
    pass

try:  # encryption of stored FunPay keys
    from cryptography.fernet import Fernet, InvalidToken
except Exception:  # pragma: no cover
    Fernet = None  # type: ignore[assignment]
    InvalidToken = Exception  # type: ignore[assignment,misc]


# ---------------------------------------------------------------- configuration
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "")
SESSION_SECRET = os.getenv("SESSION_SECRET", "").strip()
TELEGRAM_API_ID = os.getenv("TELEGRAM_API_ID", "").strip()
TELEGRAM_API_HASH = os.getenv("TELEGRAM_API_HASH", "").strip()
TELEGRAM_BOT_USERNAME = os.getenv("TELEGRAM_BOT_USERNAME", "").strip().lstrip("@")
PORT = int(os.getenv("PORT", "8000"))
RENDER_EXTERNAL_URL = os.getenv("RENDER_EXTERNAL_URL", "").strip().rstrip("/")
# The Telegram webhook secret is derived from the bot token unless WEBHOOK_SECRET is set,
# so the webhook is always protected and no extra variable is needed.
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "").strip() or (
    hmac.new(TELEGRAM_BOT_TOKEN.encode(), b"funpay-lister-webhook", hashlib.sha256).hexdigest()[:48]
    if TELEGRAM_BOT_TOKEN else None
)
FUNPAY_USER_AGENT_DEFAULT = os.getenv("FUNPAY_USER_AGENT", "").strip()
FUNPAY_GOLDEN_KEY_ENV = os.getenv("FUNPAY_GOLDEN_KEY", "").strip()
FUNPAY_TIMEOUT = float(os.getenv("FUNPAY_TIMEOUT", "15"))
APP_VERSION = "7.0.0"
ADMIN_TELEGRAM_ID = int(os.getenv("ADMIN_TELEGRAM_ID", "8357023784"))
# admin key: full admin rights and no time limit. Set ADMIN_ACCESS_KEY in the environment to replace it.
ADMIN_ACCESS_KEY = os.getenv("ADMIN_ACCESS_KEY", "").strip() or "888CC-2747"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
)
START_TIME = time.monotonic()

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("DATA_DIR", str(BASE_DIR))).expanduser()
LICENSE_DB_PATH = os.getenv("LICENSE_DB_PATH", str(DATA_DIR / "licenses.sqlite3"))
CATALOG_PATH = DATA_DIR / "catalog_cache.json"
SECRET_FILE = DATA_DIR / "app_secret.key"

FREE_PLAN_SECONDS = 30 * 60            # strict 30 minutes from first sign-in
FOREVER_SESSION_SECONDS = 365 * 24 * 3600
ADMIN_SESSION_SECONDS = 7 * 24 * 3600
SESSION_COOKIE = "fpl_session"
SESSION_TOUCH_SECONDS = 60             # how often last_seen is written
IDLE_CONNECTION_SECONDS = 2 * 60 * 60  # evict FunPay connections idle for 2 h
POLL_INTERVAL_SECONDS = 20
CATALOG_MAX_AGE_SECONDS = 6 * 60 * 60
CATALOG_WAIT_SECONDS = 9.0
FP_READ_TIMEOUT = FUNPAY_TIMEOUT
FP_WRITE_TIMEOUT = max(FUNPAY_TIMEOUT, 20.0)
KEEPALIVE_SECONDS = 10 * 60

STAR_PLANS: dict[str, dict[str, Any]] = {
    "day": {"title": "1 день", "stars": 15, "seconds": 24 * 60 * 60},
    "day_half": {"title": "1,5 дня", "stars": 25, "seconds": 36 * 60 * 60},
    "three_days": {"title": "3 дня", "stars": 50, "seconds": 3 * 24 * 60 * 60},
    "week": {"title": "1 неделя", "stars": 100, "seconds": 7 * 24 * 60 * 60},
    "month": {"title": "1 месяц", "stars": 400, "seconds": 30 * 24 * 60 * 60},
    "forever": {"title": "Навсегда", "stars": 1000, "seconds": None},
}

ADMIN_LICENSE_DURATIONS: dict[str, tuple[str, int | None]] = {
    "1h": ("1 час", 3600),
    "6h": ("6 часов", 6 * 3600),
    "12h": ("12 часов", 12 * 3600),
    "24h": ("1 день", 24 * 3600),
    "36h": ("1,5 дня", 36 * 3600),
    "3d": ("3 дня", 3 * 24 * 3600),
    "7d": ("7 дней", 7 * 24 * 3600),
    "30d": ("30 дней", 30 * 24 * 3600),
    "forever": ("Навсегда", None),
}

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger("nezzx_ai_telegram_conv")


# ---------------------------------------------------------------- small helpers
def now_ts() -> int:
    return int(time.time())


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def format_expiry(expires_at: int | None) -> str:
    if expires_at is None:
        return "без срока действия"
    return datetime.fromtimestamp(expires_at, timezone.utc).strftime("%d.%m.%Y в %H:%M UTC")


def clean_model(value: Any) -> Any:
    """Convert library models, enums and nested containers into JSON-compatible values."""
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {str(k): clean_model(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [clean_model(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "value") and isinstance(getattr(value, "value"), (str, int, float, bool)):
        return value.value
    if hasattr(value, "__dict__") and not callable(value):
        return {k: clean_model(v) for k, v in vars(value).items() if not k.startswith("_")}
    return str(value)


def create_license_key() -> str:
    token = secrets.token_hex(12).upper()
    return "FP-" + "-".join(token[i:i + 6] for i in range(0, len(token), 6))


def public_url() -> str:
    return RENDER_EXTERNAL_URL or f"http://127.0.0.1:{PORT}"


# ---------------------------------------------------------------- database
@contextmanager
def db():
    """Short-lived SQLite connection. Each call is one transaction."""
    Path(LICENSE_DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(LICENSE_DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


_DB_READY: dict[str, bool] = {}


def init_db() -> None:
    """Create tables and apply in-place migrations from v4 installations (once per process)."""
    if _DB_READY.get(LICENSE_DB_PATH):
        return
    _DB_READY[LICENSE_DB_PATH] = True
    with db() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""CREATE TABLE IF NOT EXISTS license_keys (
            license_key TEXT PRIMARY KEY,
            telegram_user_id INTEGER NOT NULL DEFAULT 0,
            plan_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER,
            telegram_payment_charge_id TEXT UNIQUE,
            activated_at INTEGER,
            duration_seconds INTEGER,
            revoked INTEGER NOT NULL DEFAULT 0,
            expiry_notified INTEGER NOT NULL DEFAULT 0
        )""")
        cols = _columns(conn, "license_keys")
        for name, ddl in (
            ("activated_at", "ALTER TABLE license_keys ADD COLUMN activated_at INTEGER"),
            ("duration_seconds", "ALTER TABLE license_keys ADD COLUMN duration_seconds INTEGER"),
            ("revoked", "ALTER TABLE license_keys ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0"),
            ("expiry_notified", "ALTER TABLE license_keys ADD COLUMN expiry_notified INTEGER NOT NULL DEFAULT 0"),
        ):
            if name not in cols:
                conn.execute(ddl)
        conn.execute("""CREATE TABLE IF NOT EXISTS free_claims (
            telegram_user_id INTEGER PRIMARY KEY,
            license_key TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS sent_chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id TEXT NOT NULL,
            message_id TEXT NOT NULL,
            text TEXT NOT NULL,
            author TEXT NOT NULL DEFAULT 'Вы',
            timestamp TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            image_link TEXT,
            UNIQUE(chat_id, message_id)
        )""")
        if "image_link" not in _columns(conn, "sent_chat_messages"):
            conn.execute("ALTER TABLE sent_chat_messages ADD COLUMN image_link TEXT")
        conn.execute("""CREATE TABLE IF NOT EXISTS web_sessions (
            token_hash TEXT PRIMARY KEY,
            owner TEXT NOT NULL,
            plan_id TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            license_key TEXT,
            created_at INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            user_agent TEXT
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_owner ON web_sessions(owner)")
        conn.execute("""CREATE TABLE IF NOT EXISTS fp_accounts (
            owner TEXT PRIMARY KEY,
            golden_enc TEXT NOT NULL,
            user_agent TEXT,
            updated_at INTEGER NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS telegram_accounts (
            owner TEXT PRIMARY KEY,
            phone TEXT NOT NULL,
            username TEXT NOT NULL DEFAULT '',
            session_enc TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS ai_chat_settings (
            owner TEXT NOT NULL,
            chat_id TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0,
            mode TEXT NOT NULL DEFAULT 'friendly',
            updated_at INTEGER NOT NULL,
            PRIMARY KEY(owner, chat_id)
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS ai_owner_prompt (
            owner TEXT PRIMARY KEY,
            prompt TEXT NOT NULL DEFAULT '',
            updated_at INTEGER NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS ai_message_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            chat_id TEXT NOT NULL,
            direction TEXT NOT NULL,
            mode TEXT NOT NULL DEFAULT 'friendly',
            created_at INTEGER NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS user_backgrounds (
            owner TEXT PRIMARY KEY,
            mime TEXT NOT NULL,
            data BLOB NOT NULL,
            version INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS music_playlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            provider TEXT NOT NULL,
            kind TEXT NOT NULL,
            embed_id TEXT NOT NULL,
            source_url TEXT NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            artist TEXT NOT NULL DEFAULT '',
            thumb_url TEXT NOT NULL DEFAULT '',
            added_at INTEGER NOT NULL,
            UNIQUE(owner, provider, embed_id)
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS music_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            name TEXT NOT NULL DEFAULT '',
            mime TEXT NOT NULL,
            size INTEGER NOT NULL,
            data BLOB NOT NULL,
            added_at INTEGER NOT NULL
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS music_files_owner ON music_files(owner)")
        # Legacy free keys (v4) were issued for 24 h from creation. Re-base them to the
        # strict 30-minute rule measured from creation, then keep the flag consistent.
        conn.execute(
            """UPDATE license_keys SET activated_at = created_at,
               expires_at = MIN(COALESCE(expires_at, created_at + ?), created_at + ?),
               duration_seconds = ?
               WHERE plan_id = 'free' AND activated_at IS NULL""",
            (FREE_PLAN_SECONDS, FREE_PLAN_SECONDS, FREE_PLAN_SECONDS),
        )


# ---------------------------------------------------------------- licenses
def claim_free_license(user_id: int) -> tuple[str, bool, bool]:
    """Return (key, created, activated). One FREE PLAN key per Telegram account."""
    init_db()
    now = now_ts()
    with db() as conn:
        row = conn.execute("SELECT license_key FROM free_claims WHERE telegram_user_id=?", (user_id,)).fetchone()
        if row:
            key_row = conn.execute(
                "SELECT activated_at FROM license_keys WHERE license_key=?", (row["license_key"],)
            ).fetchone()
            return row["license_key"], False, bool(key_row and key_row["activated_at"])
        key = create_license_key()
        conn.execute(
            """INSERT INTO license_keys(license_key,telegram_user_id,plan_id,created_at,expires_at,duration_seconds)
               VALUES(?,?,?,?,?,?)""",
            (key, user_id, "free", now, None, FREE_PLAN_SECONDS),
        )
        conn.execute(
            "INSERT INTO free_claims(telegram_user_id,license_key,created_at) VALUES(?,?,?)", (user_id, key, now)
        )
        return key, True, False


def issue_paid_license(user_id: int, plan_id: str, charge_id: str) -> tuple[str, int | None, bool]:
    init_db()
    if plan_id not in STAR_PLANS:
        raise ValueError("Unknown license plan")
    now = now_ts()
    plan = STAR_PLANS[plan_id]
    seconds = plan["seconds"]
    expires = now + int(seconds) if seconds is not None else None
    with db() as conn:
        existing = conn.execute(
            "SELECT license_key, expires_at FROM license_keys WHERE telegram_payment_charge_id=?", (charge_id,)
        ).fetchone()
        if existing:
            return existing["license_key"], existing["expires_at"], False
        key = create_license_key()
        conn.execute(
            """INSERT INTO license_keys(license_key,telegram_user_id,plan_id,created_at,expires_at,
               telegram_payment_charge_id,activated_at,duration_seconds) VALUES(?,?,?,?,?,?,?,?)""",
            (key, user_id, plan_id, now, expires, charge_id, now, seconds),
        )
    return key, expires, True


def create_admin_license(duration: str, telegram_user_id: int | None = None) -> dict[str, Any]:
    if duration not in ADMIN_LICENSE_DURATIONS:
        raise ValueError("Неизвестный срок ключа.")
    title, seconds = ADMIN_LICENSE_DURATIONS[duration]
    now = now_ts()
    expires = now + seconds if seconds is not None else None
    key = create_license_key()
    owner_id = int(telegram_user_id or 0)
    init_db()
    with db() as conn:
        conn.execute(
            """INSERT INTO license_keys(license_key,telegram_user_id,plan_id,created_at,expires_at,activated_at,duration_seconds)
               VALUES(?,?,?,?,?,?,?)""",
            (key, owner_id, f"admin_{duration}", now, expires, now, seconds),
        )
    return {"key": key, "duration": duration, "duration_title": title, "telegram_user_id": owner_id,
            "created_at": now, "expires_at": expires, "active": expires is None or expires > now}


def license_status(row: sqlite3.Row | dict[str, Any], now: int | None = None) -> tuple[bool, str]:
    """Return (valid, reason) for a license row."""
    now = now or now_ts()
    if row["revoked"]:
        return False, "revoked"
    if row["plan_id"] == "free" and row["activated_at"] is None:
        return True, "not_activated"
    if row["expires_at"] is not None and int(row["expires_at"]) <= now:
        return False, "expired"
    return True, "ok"


def activate_license_if_needed(key: str) -> None:
    """A FREE PLAN key starts its 30-minute clock at the first successful sign-in."""
    now = now_ts()
    with db() as conn:
        conn.execute(
            """UPDATE license_keys SET activated_at = ?, expires_at = ?, duration_seconds = ?
               WHERE license_key = ? AND plan_id = 'free' AND activated_at IS NULL""",
            (now, now + FREE_PLAN_SECONDS, FREE_PLAN_SECONDS, key),
        )


def find_license(key: str) -> sqlite3.Row | None:
    with db() as conn:
        return conn.execute(
            "SELECT * FROM license_keys WHERE license_key = ? COLLATE NOCASE", (key,)
        ).fetchone()


# ---------------------------------------------------------------- encryption of FunPay keys
def _fernet():
    if Fernet is None:
        return None
    material = SESSION_SECRET or TELEGRAM_BOT_TOKEN or DASHBOARD_PASSWORD
    if not material:
        if not SECRET_FILE.exists():
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            SECRET_FILE.write_text(secrets.token_urlsafe(48), encoding="utf-8")
        material = SECRET_FILE.read_text(encoding="utf-8").strip()
    key = base64.urlsafe_b64encode(hashlib.sha256(("fpl-v5:" + material).encode()).digest())
    return Fernet(key)


def encrypt_secret(value: str) -> str | None:
    fernet = _fernet()
    if fernet is None:
        log.warning("cryptography is not installed; FunPay key is kept only in memory")
        return None
    return fernet.encrypt(value.encode()).decode()


def decrypt_secret(token: str) -> str | None:
    fernet = _fernet()
    if fernet is None:
        return None
    try:
        return fernet.decrypt(token.encode()).decode()
    except (InvalidToken, ValueError):
        log.warning("Stored FunPay key could not be decrypted; reconnect the account")
        return None


def save_fp_account(owner: str, golden_key: str, user_agent: str) -> bool:
    encrypted = encrypt_secret(golden_key)
    if encrypted is None:
        return False
    init_db()
    with db() as conn:
        conn.execute(
            """INSERT INTO fp_accounts(owner,golden_enc,user_agent,updated_at) VALUES(?,?,?,?)
               ON CONFLICT(owner) DO UPDATE SET golden_enc=excluded.golden_enc,
               user_agent=excluded.user_agent, updated_at=excluded.updated_at""",
            (owner, encrypted, user_agent, now_ts()),
        )
    return True


def load_fp_account(owner: str) -> tuple[str, str] | None:
    init_db()
    with db() as conn:
        row = conn.execute("SELECT golden_enc, user_agent FROM fp_accounts WHERE owner=?", (owner,)).fetchone()
    if not row:
        return None
    golden = decrypt_secret(row["golden_enc"])
    return (golden, row["user_agent"] or "") if golden else None


def delete_fp_account(owner: str) -> None:
    init_db()
    with db() as conn:
        conn.execute("DELETE FROM fp_accounts WHERE owner=?", (owner,))


# ---------------------------------------------------------------- local sent-message ledger
def save_sent_chat_message(
    chat_id: int | str,
    message_id: str | int | None,
    text: str,
    author: str = "Вы",
    image_link: str | None = None,
) -> dict[str, Any]:
    init_db()
    now = now_ts()
    stable_id = str(message_id) if message_id is not None else f"local-{now}-{secrets.token_hex(5)}"
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with db() as conn:
        conn.execute(
            """INSERT OR IGNORE INTO sent_chat_messages(chat_id,message_id,text,author,timestamp,created_at,image_link)
               VALUES(?,?,?,?,?,?,?)""",
            (str(chat_id), stable_id, text or "", author or "Вы", stamp, now, image_link),
        )
    return {"id": stable_id, "chat_id": str(chat_id), "text": text or "", "author": author or "Вы",
            "author_id": None, "is_incoming": False, "image_link": image_link, "timestamp": stamp,
            "status": "sent" if message_id is not None else "pending"}


# ---------------------------------------------------------------- Telegram WebApp verification
def verify_telegram_init_data(init_data: str) -> dict[str, Any] | None:
    """Validate Telegram WebApp initData with the bot token (HMAC-SHA256 scheme)."""
    if not TELEGRAM_BOT_TOKEN or not init_data or len(init_data) > 8192:
        return None
    try:
        values = dict(parse_qsl(init_data, keep_blank_values=True, strict_parsing=True))
        supplied_hash = values.pop("hash", "")
        auth_date = int(values.get("auth_date", "0"))
        now = now_ts()
        if not supplied_hash or auth_date <= 0 or auth_date > now + 30 or now - auth_date > 86400:
            return None
        check_string = "\n".join(f"{key}={value}" for key, value in sorted(values.items()))
        secret_key = hmac.new(b"WebAppData", TELEGRAM_BOT_TOKEN.encode(), hashlib.sha256).digest()
        expected = hmac.new(secret_key, check_string.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, supplied_hash):
            return None
        user_raw = values.get("user", "")
        user = json.loads(user_raw) if user_raw else None
        return user if isinstance(user, dict) else None
    except Exception:
        return None


# ---------------------------------------------------------------- web sessions (HttpOnly cookie)
LOGIN_ATTEMPTS: dict[str, list[float]] = {}


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def plan_title(plan_id: str) -> str:
    if plan_id == "free":
        return "FREE PLAN"
    if plan_id in ("admin", "admin_key"):
        return "Администратор"
    if plan_id in STAR_PLANS:
        return str(STAR_PLANS[plan_id]["title"])
    if plan_id.startswith("admin_"):
        return ADMIN_LICENSE_DURATIONS.get(plan_id[len("admin_"):], ("Ключ", None))[0]
    return "Ключ"


def cookie_is_secure(request: Request) -> bool:
    forwarded = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    return RENDER_EXTERNAL_URL.startswith("https://") or forwarded == "https"


def create_web_session(
    owner: str,
    plan_id: str,
    is_admin: bool,
    license_key: str | None,
    expires_at: int,
    user_agent: str,
) -> str:
    token = secrets.token_urlsafe(32)
    now = now_ts()
    init_db()
    with db() as conn:
        conn.execute("DELETE FROM web_sessions WHERE expires_at <= ?", (now,))
        conn.execute(
            """INSERT INTO web_sessions(token_hash,owner,plan_id,is_admin,license_key,created_at,last_seen,expires_at,user_agent)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (_token_hash(token), owner, plan_id, 1 if is_admin else 0, license_key, now, now, expires_at,
             (user_agent or "")[:300]),
        )
    return token


class SessionInfo:
    """Resolved, validated session for one request."""

    def __init__(self, row: sqlite3.Row, token_hash: str):
        self.owner: str = row["owner"]
        self.plan_id: str = row["plan_id"]
        self.is_admin: bool = bool(row["is_admin"])
        self.license_key: str | None = row["license_key"]
        self.expires_at: int = int(row["expires_at"])
        self.token_hash = token_hash

    def payload(self) -> dict[str, Any]:
        now = now_ts()
        forever = self.plan_id in ("forever", "admin_forever", "admin_key")
        key_hint = (self.license_key or "")[-4:] if self.license_key else ""
        return {
            "plan_id": self.plan_id,
            "plan_title": plan_title(self.plan_id),
            "is_admin": self.is_admin,
            "free": self.plan_id == "free",
            "forever": forever,
            "license_hint": key_hint,
            "expires_at": self.expires_at,
            "remaining_seconds": max(0, self.expires_at - now),
            "server_time": now,
            "version": APP_VERSION,
        }


def _expire_session(token_hash: str) -> None:
    with db() as conn:
        conn.execute("DELETE FROM web_sessions WHERE token_hash=?", (token_hash,))


def get_session(request: Request) -> SessionInfo:
    """Dependency: validate the HttpOnly cookie and enforce license expiry server-side."""
    token = request.cookies.get(SESSION_COOKIE, "")
    if not token or len(token) > 200:
        raise HTTPException(status_code=401, detail={"code": "no_session", "message": "Войдите по ключу доступа."})
    token_hash = _token_hash(token)
    init_db()
    with db() as conn:
        row = conn.execute("SELECT * FROM web_sessions WHERE token_hash=?", (token_hash,)).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail={"code": "session_revoked", "message": "Сессия завершена. Войдите снова."})
    now = now_ts()
    if int(row["expires_at"]) <= now:
        _expire_session(token_hash)
        raise HTTPException(status_code=401, detail={"code": "session_expired", "message": "Срок действия ключа истёк."})
    if row["license_key"]:
        lic = find_license(row["license_key"])
        valid, reason = (license_status(lic, now) if lic is not None else (False, "revoked"))
        if not valid:
            _expire_session(token_hash)
            message = ("Срок действия ключа истёк." if reason == "expired"
                       else "Ключ отозван. Обратитесь к администратору.")
            raise HTTPException(status_code=401, detail={"code": f"session_{reason}", "message": message})
    if now - int(row["last_seen"]) >= SESSION_TOUCH_SECONDS:
        with db() as conn:
            conn.execute("UPDATE web_sessions SET last_seen=? WHERE token_hash=?", (now, token_hash))
    return SessionInfo(row, token_hash)


def get_admin_session(session: SessionInfo = Depends(get_session)) -> SessionInfo:
    if not session.is_admin:
        raise HTTPException(status_code=403, detail="Этот раздел доступен только администратору.")
    return session


# ---------------------------------------------------------------- in-app notifications
NOTIF_SEQ = 0
NOTIFS: dict[str, collections.deque] = {}


def push_notification(owner: str, kind: str, title: str, text: str, chat_id: Any = None) -> dict[str, Any]:
    global NOTIF_SEQ
    NOTIF_SEQ += 1
    item = {
        "seq": NOTIF_SEQ,
        "type": kind,
        "title": title[:120],
        "text": (text or "")[:600],
        "chat_id": str(chat_id) if chat_id is not None else None,
        "created_at": now_ts(),
    }
    NOTIFS.setdefault(owner, collections.deque(maxlen=150)).append(item)
    return item


def notifications_after(owner: str, after: int) -> tuple[list[dict[str, Any]], int]:
    items = [item for item in NOTIFS.get(owner, []) if item["seq"] > after]
    if after <= 0:
        items = items[-60:]
    return items, NOTIF_SEQ


def check_login_rate(host: str) -> None:
    now = time.time()
    attempts = [t for t in LOGIN_ATTEMPTS.get(host, []) if now - t < 300]
    LOGIN_ATTEMPTS[host] = attempts
    if len(attempts) >= 8:
        raise HTTPException(status_code=429, detail="Слишком много попыток. Подождите пять минут.")


def note_failed_login(host: str) -> None:
    LOGIN_ATTEMPTS.setdefault(host, []).append(time.time())



# ---------------------------------------------------------------- FunPay connections
class FunPayError(Exception):
    """Upstream FunPay failure that a background caller may swallow."""


class FPConn:
    def __init__(self, client: Any, account: Any, profile: dict[str, Any], user_agent: str):
        self.owner = ""
        self.client = client
        self.account = account
        self.profile = profile
        self.balance: Any = None
        self.user_agent = user_agent
        self.lock = asyncio.Lock()
        self.connected_at = utc_now()
        self.last_used = time.time()
        self.closed = False
        self.chat_seen: dict[str, tuple[str, str]] = {}
        self.chat_baseline = False
        self.sale_seen: set[str] = set()
        self.sale_baseline = False
        self.tick = 0
        self.error_notified_at = 0.0

    @property
    def username(self) -> str:
        return str(self.profile.get("username") or self.profile.get("name") or "")


FP_CONNS: dict[str, FPConn] = {}
FP_CONN_LOCKS: dict[str, asyncio.Lock] = {}


def _library():
    try:
        from funpay_api_python import FunPayAccount, FunPayClient
    except ImportError as exc:
        raise HTTPException(
            status_code=503,
            detail="FunPay-клиент не установлен на сервере. Разделы FunPay недоступны, остальное работает.",
        ) from exc
    return FunPayClient, FunPayAccount


async def _close_client(client: Any) -> None:
    try:
        await client.close()
    except Exception:
        pass


async def open_account(golden_key: str, user_agent: str) -> FPConn:
    """Build a client, verify the session with get_me(), and return a live connection."""
    FunPayClient, FunPayAccount = _library()
    if len(golden_key.strip()) < 8:
        raise HTTPException(status_code=422, detail="Проверьте значение golden_key.")
    ua = (user_agent or "").strip() or FUNPAY_USER_AGENT_DEFAULT or DEFAULT_USER_AGENT
    client = FunPayClient(
        golden_key=golden_key.strip(),
        user_agent=ua,
        timeout=FUNPAY_TIMEOUT,
        locale="ru",
        min_interval=0.45,
    )
    account = FunPayAccount(client)
    try:
        profile = await asyncio.wait_for(account.get_me(), timeout=FP_READ_TIMEOUT)
    except Exception as exc:
        await _close_client(client)
        reason = str(exc)
        log.warning("FunPay sign-in failed: %s", type(exc).__name__)
        if "Unauthorized" in reason or "Profile not detected" in reason or "401" in reason:
            message = "FunPay не принял сессию. Проверьте golden_key и User-Agent."
        else:
            message = "Не удалось подключиться к FunPay. Проверьте сессию и попробуйте ещё раз."
        raise HTTPException(status_code=401, detail=message) from exc
    conn = FPConn(client, account, clean_model(profile) or {}, ua)
    try:
        conn.balance = clean_model(await asyncio.wait_for(account.get_balance(), timeout=FP_READ_TIMEOUT))
    except Exception:
        conn.balance = None
    return conn


async def connect_owner(owner: str, golden_key: str, user_agent: str) -> FPConn:
    conn = await open_account(golden_key, user_agent)
    conn.owner = owner
    old = FP_CONNS.get(owner)
    FP_CONNS[owner] = conn
    if old is not None and old is not conn:
        old.closed = True
        await _close_client(old.client)
    if not save_fp_account(owner, golden_key.strip(), conn.user_agent):
        log.warning("FunPay account kept in memory only (install cryptography to persist it)")
    log.info("FunPay account connected for owner %s", owner.split(":")[0])
    return conn


async def close_owner(owner: str) -> None:
    conn = FP_CONNS.pop(owner, None)
    if conn is not None:
        conn.closed = True
        await _close_client(conn.client)


async def conn_for(owner: str) -> FPConn:
    """Return the live FunPay connection for an owner, restoring it from encrypted storage if needed."""
    conn = FP_CONNS.get(owner)
    if conn is not None and not conn.closed:
        conn.last_used = time.time()
        return conn
    stored = load_fp_account(owner)
    if not stored:
        raise HTTPException(status_code=409, detail="Сначала подключите аккаунт FunPay в разделе «Настройки».")
    lock = FP_CONN_LOCKS.setdefault(owner, asyncio.Lock())
    async with lock:
        conn = FP_CONNS.get(owner)
        if conn is not None and not conn.closed:
            return conn
        golden, ua = stored
        try:
            conn = await open_account(golden, ua)
        except HTTPException as exc:
            raise HTTPException(
                status_code=409,
                detail="Не удалось переподключить аккаунт FunPay. Откройте «Настройки» и подключите его заново.",
            ) from exc
        conn.owner = owner
        FP_CONNS[owner] = conn
        return conn


async def fp_call(
    conn: FPConn,
    factory: Any,
    label: str | None,
    *,
    write: bool = False,
    timeout: float | None = None,
    retries: int | None = None,
) -> Any:
    """Run one FunPay coroutine under a hard timeout.

    Reads retry on failure. Writes never retry automatically, because a retry after a
    timeout could create a duplicate lot or message. label=None raises FunPayError instead
    of HTTP 502 (used by background pollers).
    """
    if retries is None:
        retries = 0 if write else 1
    limit = timeout or (FP_WRITE_TIMEOUT if write else FP_READ_TIMEOUT)
    attempt = 0
    while True:
        attempt += 1
        try:
            async with conn.lock:
                return await asyncio.wait_for(factory(), timeout=limit)
        except HTTPException:
            raise
        except Exception as exc:
            reason = "timeout" if isinstance(exc, asyncio.TimeoutError) else type(exc).__name__
            if attempt > retries:
                if label is None:
                    raise FunPayError(reason) from exc
                if "unauthorized" in str(exc).lower() or "401" in str(exc):
                    push_error(conn.owner, "FunPay больше не принимает сессию. Переподключите аккаунт в «Настройках».")
                push_error(conn.owner, f"{label}: FunPay не ответил вовремя ({reason}).")
                raise HTTPException(
                    status_code=502,
                    detail=f"{label}. FunPay не ответил вовремя — попробуйте ещё раз.",
                ) from exc
        await asyncio.sleep(0.8 * attempt)


def push_error(owner: str, text: str) -> None:
    if not owner:
        return
    conn = FP_CONNS.get(owner)
    if conn is not None:
        if time.time() - conn.error_notified_at < 60:
            return
        conn.error_notified_at = time.time()
    push_notification(owner, "error", "Ошибка FunPay", text)


# ---------------------------------------------------------------- catalogue (games and categories)
CATALOG: dict[str, Any] = {"items": [], "fetched_at": 0.0, "error": "", "refreshing": False}
CATALOG_TASK: asyncio.Task | None = None


def load_catalog_cache() -> None:
    try:
        data = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("items"), list):
            CATALOG["items"] = data["items"]
            CATALOG["fetched_at"] = float(data.get("fetched_at", 0))
    except (OSError, ValueError):
        pass


def save_catalog_cache() -> None:
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = CATALOG_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps({"items": CATALOG["items"], "fetched_at": CATALOG["fetched_at"]},
                                  ensure_ascii=False), encoding="utf-8")
        tmp.replace(CATALOG_PATH)
    except OSError:
        log.warning("Catalogue cache could not be written to disk")


def _as_id(value: Any) -> Any:
    text = str(value).strip()
    return int(text) if text.isdigit() else text


def normalize_catalog(values: Any) -> list[dict[str, Any]]:
    categories: list[dict[str, Any]] = []
    for raw in values or []:
        data = clean_model(raw)
        if not isinstance(data, dict) or data.get("id") is None or not str(data.get("name") or "").strip():
            continue
        subs = []
        for sub in data.get("subcategories") or []:
            item = clean_model(sub)
            if isinstance(item, dict) and item.get("id") is not None and str(item.get("name") or "").strip():
                subs.append({"id": _as_id(item["id"]), "name": str(item["name"]).strip(), "icon": None})
        categories.append({"id": _as_id(data["id"]), "name": str(data["name"]).strip(), "icon": None,
                           "subcategories": subs})
    return categories


async def _icon_map(conn: FPConn) -> dict[str, str]:
    """Best-effort: map FunPay node ids to the game images shown on the public storefront."""
    response = await fp_call(conn, lambda: conn.client.get("", raise_not_200=True), None, timeout=20, retries=0)
    soup = BeautifulSoup(response.text, "html.parser")
    icons: dict[str, str] = {}
    for link in soup.select('a[href*="/lots/"]'):
        match = re.search(r"/lots/(\d+)/?", link.get("href") or "")
        image = link.find("img")
        src = (image.get("src") or image.get("data-src") or "") if image else ""
        if match and src:
            icons.setdefault(match.group(1), urljoin("https://funpay.com", src))
    return icons


async def refresh_catalog(conn: FPConn) -> None:
    values = await fp_call(conn, lambda: conn.account.get_categories(), "Не удалось получить каталог FunPay",
                           timeout=max(FP_READ_TIMEOUT, 25), retries=2)
    categories = normalize_catalog(values)
    if not categories:
        raise HTTPException(status_code=502, detail="FunPay вернул пустой каталог. Попробуйте обновить позже.")
    try:
        icons = await _icon_map(conn)
    except Exception:
        icons = {}
    for category in categories:
        for sub in category["subcategories"]:
            sub["icon"] = icons.get(str(sub["id"]))
        found = [s["icon"] for s in category["subcategories"] if s["icon"]]
        category["icon"] = found[0] if found else None
    CATALOG.update(items=categories, fetched_at=time.time(), error="")
    save_catalog_cache()


async def _catalog_job(owner: str) -> None:
    CATALOG["refreshing"] = True
    try:
        conn = await conn_for(owner)
        await refresh_catalog(conn)
    except HTTPException as exc:
        detail = exc.detail.get("message") if isinstance(exc.detail, dict) else exc.detail
        CATALOG["error"] = str(detail)
    except Exception as exc:
        log.warning("Catalogue refresh failed: %s", type(exc).__name__)
        CATALOG["error"] = "Не удалось обновить каталог FunPay."
    finally:
        CATALOG["refreshing"] = False


async def ensure_catalog(owner: str) -> None:
    """Serve the cache at once; start a refresh when stale and wait only a few seconds for it."""
    global CATALOG_TASK
    fresh = CATALOG["items"] and time.time() - CATALOG["fetched_at"] < CATALOG_MAX_AGE_SECONDS
    if fresh:
        return
    if CATALOG_TASK is None or CATALOG_TASK.done():
        CATALOG_TASK = asyncio.create_task(_catalog_job(owner), name="funpay-catalog")
    try:
        await asyncio.wait_for(asyncio.shield(CATALOG_TASK), timeout=CATALOG_WAIT_SECONDS)
    except (asyncio.TimeoutError, Exception):
        pass


_WORD = re.compile(r"\s+")


def _norm(text: str) -> str:
    return _WORD.sub(" ", str(text or "").casefold()).strip()


def rank_text(query: str, name: str) -> float:
    """Score one query token against one name. 0 means no match."""
    n = _norm(name)
    if not query or not n:
        return 0.0
    if n == query:
        return 200.0
    if n.startswith(query):
        return 150.0 - min(len(n), 80) / 10
    words = n.split()
    if any(w.startswith(query) for w in words):
        return 120.0
    if query in n:
        return 100.0 - n.index(query) / 10
    ratio = max([difflib.SequenceMatcher(None, query, w).ratio() for w in words + [n]] or [0.0])
    if len(query) >= 3 and ratio >= 0.72:
        return 60.0 * ratio
    if len(query) >= 2 and ratio >= 0.5:
        return 40.0 * ratio
    return 0.0


def search_catalog(query: str) -> list[dict[str, Any]]:
    tokens = [t for t in _norm(query).split(" ") if t][:6]
    results: list[tuple[float, dict[str, Any]]] = []
    for category in CATALOG["items"]:
        cat_name = category["name"]
        if not tokens:
            results.append((1.0, {"type": "category", "id": category["id"], "name": cat_name,
                                  "category_id": category["id"], "category_name": cat_name,
                                  "icon": category.get("icon"), "subcategories": category["subcategories"]}))
            continue
        scores = [rank_text(t, cat_name) for t in tokens]
        if all(s > 0 for s in scores):
            results.append((min(scores), {"type": "category", "id": category["id"], "name": cat_name,
                                          "category_id": category["id"], "category_name": cat_name,
                                          "icon": category.get("icon"), "subcategories": category["subcategories"]}))
        for sub in category["subcategories"]:
            text = f"{sub['name']} {cat_name}"
            sub_scores = [rank_text(t, text) for t in tokens]
            if all(s > 0 for s in sub_scores):
                results.append((min(sub_scores) + 1.0, {
                    "type": "subcategory", "id": sub["id"], "name": sub["name"],
                    "category_id": category["id"], "category_name": cat_name,
                    "subcategory_id": sub["id"], "icon": sub.get("icon") or category.get("icon"),
                    "subcategories": []}))
    results.sort(key=lambda pair: (-pair[0], str(pair[1]["name"]).casefold()))
    limit = 60 if tokens else len(results)
    return [item for _score, item in results[:limit]]


# ---------------------------------------------------------------- normalizers for FunPay data
def normalize_lot(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": data.get("id") or data.get("lot_id") or data.get("offer_id"),
        "title": data.get("description") or data.get("title") or data.get("name") or "Без названия",
        "price": data.get("price"),
        "amount": data.get("amount"),
        "active": bool(data.get("active", True)),
        "currency": data.get("currency") or "RUB",
        "subcategory_id": data.get("subcategory_id"),
        "subcategory_name": data.get("subcategory_name") or "",
        "server": data.get("server") or "",
    }


def normalize_order(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": data.get("id") or data.get("order_id"),
        "title": data.get("description") or data.get("title") or "Заказ FunPay",
        "game": data.get("game") or data.get("subcategory_name") or "",
        "server": data.get("server") or "",
        "buyer_username": data.get("buyer_username") or data.get("buyer") or "",
        "status": str(data.get("status") or ""),
        "date": str(data.get("date") or data.get("created_at") or ""),
        "price": data.get("price"),
        "amount": data.get("amount"),
        "currency": data.get("currency") or "RUB",
    }


def normalize_chat(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(data.get("id", "")),
        "name": data.get("name") or "Пользователь",
        "last_message_id": str(data.get("last_message_id") or ""),
        "last_message_text": data.get("last_message_text") or "",
        "last_message_author": data.get("last_message_author") or "",
        "unread_count": int(data.get("unread_count") or 0) if str(data.get("unread_count") or "0").isdigit() else 0,
        "interlocutor_id": data.get("interlocutor_id"),
    }


def normalize_message(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(data.get("id", "")),
        "text": data.get("text") or "",
        "author": data.get("author") or "",
        "author_id": data.get("author_id"),
        "is_incoming": bool(data.get("is_incoming", False)),
        "image_link": data.get("image_link") or None,
        "timestamp": str(data.get("timestamp") or ""),
        "status": data.get("status") or "received",
    }


def _message_id_from_runner_result(payload: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    """Return (new message id, FunPay error text, image link) from a runner response."""
    response_data = payload.get("response")
    error_text = None
    if payload.get("error"):
        error_text = str(payload.get("msg") or payload.get("error"))[:300]
    elif isinstance(response_data, dict) and response_data.get("error"):
        error_text = str(response_data.get("error"))[:300]
    last_message: dict[str, Any] | None = None
    for obj in payload.get("objects") if isinstance(payload.get("objects"), list) else []:
        data = obj.get("data") if isinstance(obj, dict) and isinstance(obj.get("data"), dict) else {}
        messages = data.get("messages") if isinstance(data.get("messages"), list) else []
        if messages and isinstance(messages[-1], dict):
            last_message = messages[-1]
    image_link = None
    if last_message and last_message.get("html"):
        try:
            node = BeautifulSoup(str(last_message.get("html")), "html.parser").select_one("a.chat-img-link")
            if node and node.get("href"):
                image_link = urljoin("https://funpay.com", node.get("href"))
        except Exception:
            pass
    raw_id = last_message.get("id") if last_message else None
    return (str(raw_id) if raw_id is not None else None), error_text, image_link


async def chat_history(conn: FPConn, chat_id: Any, label: str | None = "Не удалось открыть историю чата") -> list[dict[str, Any]]:
    values = await fp_call(conn, lambda: conn.account.get_chat_history(_as_id(chat_id)), label, retries=1)
    return [normalize_message(clean_model(m)) for m in values or [] if isinstance(clean_model(m), dict)]


async def send_runner(conn: FPConn, chat_id: Any, text: str, image_id: int | None = None,
                      known_ids: set[str] | None = None, image_mode: bool = False) -> dict[str, Any]:
    """Send through the FunPay runner.

    A runner response without an error counts as sent. Verification through history is
    best-effort: failing to see the message yet is reported as verified=False, not as an error.
    Only an explicit FunPay error, or an ambiguous timeout that is not visible in history,
    fails the request, and writes are never retried automatically.
    """
    client = conn.client
    node_id = _as_id(chat_id)
    data: dict[str, Any] = {"node": node_id, "content": text or ""}
    if image_id is not None:
        data["image_id"] = int(image_id)
        data["content"] = ""
    objects = [{"type": "chat_node", "id": node_id, "tag": "00000000",
                "data": {"node": node_id, "last_message": "", "content": text or ""}}]
    headers = {"accept": "*/*", "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
               "x-requested-with": "XMLHttpRequest"}
    for index, action in enumerate(("message_send", "chat_message")):
        form = {
            "objects": json.dumps(objects, ensure_ascii=False),
            "request": json.dumps({"action": action, "data": dict(data)}, ensure_ascii=False),
            "csrf_token": getattr(client, "csrf_token", "") or "",
        }
        try:
            response = await fp_call(conn, lambda: client.post("runner/", data=form, headers=headers,
                                                              raise_not_200=True),
                                     None, write=True)
            payload = response.json()
        except (FunPayError, HTTPException, ValueError):
            payload = None
        if not isinstance(payload, dict):
            # Ambiguous: the request may have reached FunPay. Look for the message before failing.
            await asyncio.sleep(2.0)
            found = await _find_sent(conn, chat_id, text, image_mode, known_ids)
            if found:
                return {"message_id": found["id"], "verified": True, "image_link": found.get("image_link")}
            raise HTTPException(status_code=502, detail=(
                "FunPay не подтвердил отправку. Проверьте чат перед повторной отправкой, "
                "чтобы не получить дубль."))
        message_id, error_text, image_link = _message_id_from_runner_result(payload)
        if error_text:
            lowered = error_text.casefold()
            unsupported = any(token in lowered for token in (
                "unknown action", "unsupported action", "action not found", "неизвестн", "not implemented"))
            if index == 0 and unsupported:
                continue
            raise HTTPException(status_code=422, detail=f"FunPay отклонил отправку: {error_text}")
        if message_id and (known_ids is None or message_id not in known_ids):
            return {"message_id": message_id, "verified": True, "image_link": image_link}
        for delay in (1.5, 3.0):
            await asyncio.sleep(delay)
            found = await _find_sent(conn, chat_id, text, image_mode, known_ids)
            if found:
                return {"message_id": found["id"], "verified": True, "image_link": found.get("image_link")}
        return {"message_id": None, "verified": False, "image_link": image_link}
    raise HTTPException(status_code=502, detail="FunPay отклонил отправку: действие не поддерживается.")


async def _find_sent(conn: FPConn, chat_id: Any, text: str, image_mode: bool,
                     known_ids: set[str] | None) -> dict[str, Any] | None:
    if known_ids is None:
        return None
    try:
        history = await chat_history(conn, chat_id, label=None)
    except Exception:
        return None
    for item in reversed(history):
        if item["is_incoming"] or not item["id"] or item["id"] in known_ids:
            continue
        if image_mode and item.get("image_link"):
            return item
        if not image_mode and item["text"].strip() == text.strip():
            return item
    return None


# ---------------------------------------------------------------- request models
class LoginBody(BaseModel):
    key: str = Field(default="", max_length=300)
    password: str = Field(default="", max_length=300)
    init_data: str = Field(default="", max_length=8192)


class FunPayConnectBody(BaseModel):
    golden_key: str = Field(min_length=8, max_length=1000)
    user_agent: str = Field(default="", max_length=1000)


class MessageBody(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


class ChatPhotoBody(BaseModel):
    filename: str = Field(default="photo.jpg", min_length=1, max_length=180)
    mime_type: str = Field(default="image/jpeg", min_length=3, max_length=100)
    data: str = Field(min_length=20, max_length=12_000_000)


class LotCreateBody(BaseModel):
    subcategory_id: int = Field(gt=0)
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)
    price: float = Field(gt=0, le=1_000_000_000)
    amount: int = Field(default=1, ge=1, le=1_000_000)
    active: bool = True


class LotEditBody(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)
    price: float = Field(gt=0, le=1_000_000_000)
    amount: int = Field(default=1, ge=0, le=1_000_000)
    active: bool = True


class RaiseBody(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=100)


class AdminLicenseCreateBody(BaseModel):
    duration: str = Field(default="24h", min_length=1, max_length=20)
    telegram_user_id: int | None = Field(default=None, ge=0)


class AdminRevokeBody(BaseModel):
    key: str = Field(min_length=5, max_length=100)


app = FastAPI(title="NEZZX AI Telegram Conv", version=APP_VERSION, docs_url=None, redoc_url=None, openapi_url=None)


def _dicts(values: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for value in values or []:
        data = clean_model(value)
        if isinstance(data, dict):
            out.append(data)
    return out


def balance_value(balance: Any) -> float | None:
    if isinstance(balance, (int, float)) and not isinstance(balance, bool):
        return float(balance)
    if isinstance(balance, dict):
        for key in ("total_rub", "rub", "balance", "total", "value", "amount"):
            value = balance.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return float(value)
    return None


def session_summary(plan_id: str, is_admin: bool, license_key: str | None, expires_at: int) -> dict[str, Any]:
    now = now_ts()
    return {
        "plan_id": plan_id,
        "plan_title": plan_title(plan_id),
        "is_admin": is_admin,
        "free": plan_id == "free",
        "forever": plan_id in ("forever", "admin_forever", "admin_key"),
        "license_hint": (license_key or "")[-4:],
        "expires_at": expires_at,
        "remaining_seconds": max(0, expires_at - now),
        "server_time": now,
        "version": APP_VERSION,
    }


def is_admin_access_key(value: str) -> bool:
    """True only for the admin key. Compared case-insensitively as bytes, so any input is safe."""
    if not value:
        return False
    return hmac.compare_digest(value.upper().encode("utf-8"), ADMIN_ACCESS_KEY.upper().encode("utf-8"))


# ---------------------------------------------------------------- auth and session
@app.post("/api/login")
async def login(payload: LoginBody, request: Request, response: Response) -> dict[str, Any]:
    host = request.client.host if request.client else "unknown"
    check_login_rate(host)
    supplied = (payload.key or payload.password or "").strip()
    now = now_ts()
    user_agent = request.headers.get("user-agent", "")
    tg_user = verify_telegram_init_data(payload.init_data)
    is_tg_admin = bool(tg_user and int(tg_user.get("id", 0) or 0) == ADMIN_TELEGRAM_ID)
    password_ok = bool(DASHBOARD_PASSWORD and supplied and hmac.compare_digest(supplied.encode("utf-8"), DASHBOARD_PASSWORD.encode("utf-8")))
    admin_key_ok = is_admin_access_key(supplied)

    if is_tg_admin or password_ok:
        expires = now + ADMIN_SESSION_SECONDS
        token = create_web_session("admin", "admin", True, None, expires, user_agent)
        plan_id, is_admin, license_key = "admin", True, None
    elif admin_key_ok:
        # no limit: the key never expires, so the session lasts as long as a forever key's session
        expires = FOREVER_SESSION_SECONDS + now
        token = create_web_session("admin", "admin_key", True, None, expires, user_agent)
        plan_id, is_admin, license_key = "admin_key", True, None
    elif supplied:
        lic = find_license(supplied)
        if lic is None:
            note_failed_login(host)
            raise HTTPException(status_code=401, detail="Неверный ключ доступа. Проверьте ключ и срок его действия.")
        valid, reason = license_status(lic, now)
        if not valid:
            note_failed_login(host)
            text = {"expired": "Срок действия ключа истёк. Получите новый ключ в боте.",
                    "revoked": "Ключ отозван. Обратитесь к администратору."}.get(reason, "Ключ недействителен.")
            raise HTTPException(status_code=401, detail={"code": f"session_{reason}", "message": text})
        if reason == "not_activated":
            activate_license_if_needed(lic["license_key"])
            lic = find_license(lic["license_key"])
        license_key = lic["license_key"]
        expires = FOREVER_SESSION_SECONDS + now if lic["expires_at"] is None else int(lic["expires_at"])
        plan_id, is_admin = lic["plan_id"], False
        token = create_web_session(f"lic:{license_key}", plan_id, False, license_key, expires, user_agent)
    else:
        note_failed_login(host)
        raise HTTPException(status_code=401, detail="Введите ключ доступа.")

    LOGIN_ATTEMPTS.pop(host, None)
    response.set_cookie(
        SESSION_COOKIE, token, max_age=max(60, expires - now), httponly=True, samesite="lax",
        secure=cookie_is_secure(request), path="/",
    )
    return {"ok": True, "session": session_summary(plan_id, is_admin, license_key, expires)}


@app.post("/api/logout")
async def logout(request: Request, response: Response) -> dict[str, bool]:
    """Graceful logout: ends this session only; the FunPay connection stays for the key's other devices."""
    token = request.cookies.get(SESSION_COOKIE, "")
    if token:
        _expire_session(_token_hash(token))
    response.delete_cookie(SESSION_COOKIE, path="/", secure=cookie_is_secure(request), httponly=True, samesite="lax")
    return {"ok": True}


@app.get("/api/public/config")
async def public_config() -> dict[str, Any]:
    return {"app_name": "NEZZX AI Telegram Conv",
            "telegram_bot_url": f"https://t.me/{TELEGRAM_BOT_USERNAME}" if TELEGRAM_BOT_USERNAME else "",
            "telegram_bot_configured": bool(TELEGRAM_BOT_TOKEN)}


@app.get("/api/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "version": APP_VERSION, "uptime_seconds": int(time.monotonic() - START_TIME),
            "telegram_enabled": bool(TELEGRAM_BOT_TOKEN), "telegram_user_login_configured": bool(TELEGRAM_API_ID.isdigit() and TELEGRAM_API_HASH), "ai_configured": ai_configured(), "server_time": now_ts()}


@app.get("/api/session")
async def session_info(session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    return session.payload()


@app.get("/api/notifications")
async def notifications(after: int = 0, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    items, last_seq = notifications_after(session.owner, max(0, int(after)))
    return {"items": items, "last_seq": last_seq, "session": session.payload()}


# ---------------------------------------------------------------- Telegram MTProto + AI inbox
# Telegram client sessions are encrypted at rest; phone codes and 2FA passwords live only
# in the short-lived login flow and are never written to the database or logs.
class TelegramPhoneBody(BaseModel):
    phone: str = Field(min_length=5, max_length=40)

class TelegramCodeBody(BaseModel):
    code: str = Field(min_length=1, max_length=30)

class TelegramPasswordBody(BaseModel):
    password: str = Field(min_length=1, max_length=300)

class TelegramSendBody(BaseModel):
    text: str = Field(default="", max_length=4000)
    image: str | None = Field(default=None, max_length=12_000_000)
    mime_type: str = Field(default="image/jpeg", max_length=100)
    filename: str = Field(default="photo.jpg", max_length=180)

class ChatAISettingsBody(BaseModel):
    enabled: bool = False
    mode: str = Field(default="friendly", min_length=1, max_length=40)

class AIPromptBody(BaseModel):
    prompt: str = Field(default="", max_length=4000)


class AIDraftBody(BaseModel):
    chat_id: str = Field(min_length=1, max_length=80)
    mode: str = Field(default="friendly", min_length=1, max_length=40)

TG_CLIENTS: dict[str, Any] = {}
TG_LOGIN_FLOWS: dict[str, dict[str, Any]] = {}
TG_LISTENERS: set[str] = set()
TG_SEND_GUARD: dict[str, float] = {}
AI_MODES: dict[str, str] = {
    "friendly": "Дружелюбный игрок: общайся легко, коротко, на равных, без навязчивости.",
    "mm2_trade": "MM2 trade: обсуждай Murder Mystery 2 и возможный обмен предметами только честно; уточняй условия и не выдумывай цены или наличие предметов.",
    "looking_for_players": "Поиск игроков: помогай договориться сыграть вместе, уточняй удобный режим и время.",
    "careful_trade": "Аккуратный трейд: помогай согласовать безопасные условия обмена, подтверждай каждый важный шаг и предлагай официальные механизмы защиты, если они доступны.",
}
AI_MODE_LABELS: dict[str, str] = {
    "friendly": "Дружелюбный",
    "mm2_trade": "MM2 Trade",
    "looking_for_players": "Найти игроков",
    "careful_trade": "Безопасный трейд",
}
AI_SYSTEM_PROMPT = """Ты — NEZZX AI, ассистент для составления сообщений в Telegram о видеоиграх и честных игровых обменах.
Пиши естественно, коротко и по делу; подстраивайся под язык и стиль собеседника без чрезмерных эмодзи.
Не выдавай себя за реального человека: если собеседник спрашивает, прямо скажи, что сообщения помогает готовить ИИ. Не выдумывай возраст, опыт, инвентарь, оценки предметов, гарантии, отзывы, наличие посредника или чужое согласие. Используй сведения владельца аккаунта только если они явно указаны в настройках/контексте.
Не дави на собеседника, уважай отказ и просьбу больше не писать. Не запрашивай пароли, коды входа, 2FA, cookie, токены, платёжные данные или личные данные, не нужные для игры. Не предлагай обходить правила платформы, фальшивого гаранта, фишинговые ссылки, передачу аккаунтов или схемы с сокрытием риска. Для обмена в MM2 помогай согласовать предметы и условия честно; не обещай стоимость Robux без подтверждённой информации.
Если человек отказался или просит прекратить общение, ответь вежливо один раз и рекомендуй выключить автоматические ответы для этого чата. Никаких массовых первых сообщений: генерируй только ответ на полученное входящее сообщение в чате, который пользователь явно включил для AI. Перед ответом внимательно прочитай всю переписку: если собеседник написал несколько сообщений подряд, ответь на них все сразу, а не только на первое или последнее. Ты не знаешь инвентарь владельца, если он не указан в контексте. Не перечисляй предметы, редкость и цены, которых нет в контексте. Если спрашивают, что есть в саб или в наличии, скажи, что уточнишь у владельца, и спроси, что собеседник хочет получить взамен.
Язык: определи язык собеседника по его последним сообщениям и всегда отвечай на нём (русский, английский, украинский и любой другой). Если язык смешанный, отвечай на языке его последнего сообщения. Язык выбирает собеседник, а не режим: режим задаёт только стиль."""


def _telethon_imports():
    try:
        from telethon import TelegramClient, events
        from telethon.sessions import StringSession
        from telethon.errors import SessionPasswordNeededError
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="Telegram-клиент не установлен. Добавьте Telethon в requirements.txt.") from exc
    if not TELEGRAM_API_ID.isdigit() or not TELEGRAM_API_HASH:
        raise HTTPException(status_code=503, detail="Укажите TELEGRAM_API_ID и TELEGRAM_API_HASH в переменных окружения.")
    return TelegramClient, events, StringSession, SessionPasswordNeededError


def _tg_device_kwargs() -> dict[str, str]:
    # MTProto does not use a browser User-Agent. These are Telegram client device/app labels.
    return {"device_model": "NEZZX AI Telegram Conv", "system_version": "Web dashboard",
            "app_version": APP_VERSION, "lang_code": "en", "system_lang_code": "en-US"}


def _ai_settings(owner: str, chat_id: str) -> dict[str, Any]:
    init_db()
    with db() as conn:
        row = conn.execute("SELECT enabled, mode FROM ai_chat_settings WHERE owner=? AND chat_id=?",
                           (owner, str(chat_id))).fetchone()
    mode = row["mode"] if row and row["mode"] in AI_MODES else "friendly"
    return {"enabled": bool(row["enabled"]) if row else False, "mode": mode,
            "mode_label": AI_MODE_LABELS[mode]}


def _ai_owner_prompt(owner: str) -> str:
    init_db()
    with db() as conn:
        row = conn.execute("SELECT prompt FROM ai_owner_prompt WHERE owner=?", (owner,)).fetchone()
    return str(row["prompt"] or "") if row else ""


def _log_ai(owner: str, chat_id: str, direction: str, mode: str) -> None:
    with db() as conn:
        conn.execute("INSERT INTO ai_message_log(owner,chat_id,direction,mode,created_at) VALUES(?,?,?,?,?)",
                     (owner, str(chat_id), direction, mode, now_ts()))


def _telethon_client(session_string: str = ""):
    TelegramClient, events, StringSession, _ = _telethon_imports()
    return TelegramClient(StringSession(session_string), int(TELEGRAM_API_ID), TELEGRAM_API_HASH,
                          **_tg_device_kwargs())


AI_PENDING: dict[str, int] = {}
AI_TASKS: set = set()
# wait for the other side to stop typing, then read the whole conversation once and answer
AI_DEBOUNCE_SECONDS = 5
AI_HISTORY_MESSAGES = 40


async def _ai_reply_after_pause(owner: str, client: Any, chat_id: str, token: int, peer: Any, reply_to: int) -> None:
    key = f"{owner}:{chat_id}"
    await asyncio.sleep(AI_DEBOUNCE_SECONDS)
    if AI_PENDING.get(key) != token:
        return  # a newer message arrived; its own task answers the whole conversation
    try:
        settings = _ai_settings(owner, chat_id)
        if not settings["enabled"]:
            return
        history = await _load_tg_messages(client, chat_id, AI_HISTORY_MESSAGES)
        if history and history[-1].get("is_out"):
            return  # the owner already answered by hand; nothing to add
        variants, lang = await _generate_ai_reply(history, settings["mode"], _ai_owner_prompt(owner))
        reply = variants[0] if variants else ""
        if not reply or AI_PENDING.get(key) != token:
            return  # nothing to send, or the other side wrote again while the model was thinking
        sent = await client.send_message(peer, reply, reply_to=reply_to)
        CHATS_CACHE.pop(owner, None)
        _sse_publish(owner, {"type": "message", "chat_id": chat_id, "message": _tg_message_item(sent, "Вы", chat_id)})
        _sse_publish(owner, {"type": "ai_sent", "chat_id": chat_id, "language": lang, "text": reply[:200]})
        _log_ai(owner, chat_id, "auto_sent", settings["mode"])
    except Exception as exc:
        log.warning("AI reply failed (%s)", type(exc).__name__)


async def _install_ai_listener(owner: str, client: Any) -> None:
    marker = f"{owner}:{id(client)}"
    if marker in TG_LISTENERS:
        return
    _, events, _, _ = _telethon_imports()

    async def on_incoming(event: Any) -> None:
        if not event.is_private or not event.message or not (event.raw_text or "").strip():
            return
        chat_id = str(event.chat_id)
        if not _ai_settings(owner, chat_id)["enabled"]:
            return
        key = f"{owner}:{chat_id}"
        token = AI_PENDING.get(key, 0) + 1
        AI_PENDING[key] = token  # every new message supersedes the older pending check
        task = asyncio.create_task(
            _ai_reply_after_pause(owner, client, chat_id, token, event.chat_id, event.message.id))
        AI_TASKS.add(task)
        task.add_done_callback(AI_TASKS.discard)

    async def on_live(event: Any) -> None:
        try:
            await _push_telegram_message(owner, event)
        except Exception:
            pass

    client.add_event_handler(on_live, events.NewMessage())
    client.add_event_handler(on_incoming, events.NewMessage(incoming=True))
    TG_LISTENERS.add(marker)


# ---------------------------------------------------------------- live updates (SSE push from Telethon)
# New Telegram messages (incoming and outgoing) are pushed to open browser tabs as soon as Telethon
# receives them, so the open chat updates without polling. Frames are per owner; nothing is stored.
SSE_SUBS: dict[str, set] = {}
SSE_LOOP: Any = None
SSE_MAX_PER_OWNER = 12
WARM_TASKS: set = set()


def _sse_frame(payload: dict[str, Any]) -> str:
    return "data: " + json.dumps(payload, ensure_ascii=False) + "\n\n"


def _sse_publish(owner: str, payload: dict[str, Any]) -> None:
    subs = SSE_SUBS.get(owner)
    if not subs or SSE_LOOP is None:
        return

    def push() -> None:
        for queue in list(subs):
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            try:
                queue.put_nowait(payload)
            except asyncio.QueueFull:
                pass

    try:
        running = asyncio.get_running_loop()
    except RuntimeError:
        running = None
    if running is SSE_LOOP:
        push()
    else:
        SSE_LOOP.call_soon_threadsafe(push)


# ---------------------------------------------------------------- Telegram messages: text, media metadata, links
# Photos and videos up to this size are fetched through the media endpoint; bigger files only show a note.
TG_MEDIA_MAX_BYTES = 25 * 1024 * 1024


def _tg_media_kind(message: Any) -> str:
    """photo, video, gif, sticker, voice, audio, file or other. Empty when there is nothing to show as media."""
    media = getattr(message, "media", None)
    if not media or type(media).__name__ == "MessageMediaWebPage":  # a link preview stays text, the link is clickable
        return ""
    if getattr(message, "photo", None):
        return "photo"
    if getattr(message, "sticker", None):
        return "sticker"
    if getattr(message, "gif", None):
        return "gif"
    if getattr(message, "video", None) or getattr(message, "video_note", None):
        return "video"
    if getattr(message, "voice", None):
        return "voice"
    if getattr(message, "audio", None):
        return "audio"
    if getattr(message, "document", None):
        return "file"
    return "other"


def _tg_message_item(message: Any, author: str, chat_id: Any = None) -> dict[str, Any]:
    kind = _tg_media_kind(message)
    cid = str(chat_id) if chat_id is not None else str(getattr(message, "chat_id", "") or "")
    info = getattr(message, "file", None) if kind else None
    size = int(getattr(info, "size", 0) or 0) if info else 0
    url = ""
    if kind and cid and size <= TG_MEDIA_MAX_BYTES:
        url = f"/api/telegram/chats/{cid}/messages/{int(message.id)}/media"
    return {"id": int(message.id),
            "text": message.message or ("" if kind else "[Сообщение]"),
            "author": author, "is_out": bool(message.out),
            "timestamp": message.date.isoformat() if message.date else "",
            "media": kind, "media_url": url, "media_size": size,
            "media_mime": str(getattr(info, "mime_type", "") or "")[:80] if info else "",
            "media_name": str(getattr(info, "name", "") or "")[:120] if info else ""}


async def _push_telegram_message(owner: str, event: Any) -> None:
    if not getattr(event, "is_private", False) or not event.message:
        return
    message = event.message
    author = "Вы"
    if not message.out:
        author = "Собеседник"
        try:
            sender = await asyncio.wait_for(event.get_sender(), timeout=1.0)
            author = getattr(sender, "first_name", None) or getattr(sender, "title", None) or author
        except Exception:
            pass
    CHATS_CACHE.pop(owner, None)
    _sse_publish(owner, {"type": "message", "chat_id": str(event.chat_id), "message": _tg_message_item(message, author)})


async def _warm_telegram(owner: str) -> None:
    try:
        await _tg_client_for(owner)
    except Exception:
        pass


@app.get("/api/stream")
async def api_stream(request: Request, session: SessionInfo = Depends(get_session)) -> StreamingResponse:
    global SSE_LOOP
    SSE_LOOP = asyncio.get_running_loop()
    subs = SSE_SUBS.setdefault(session.owner, set())
    if len(subs) >= SSE_MAX_PER_OWNER:
        raise HTTPException(status_code=429, detail="Слишком много открытых вкладок.")
    queue: asyncio.Queue = asyncio.Queue(maxsize=200)
    subs.add(queue)
    task = asyncio.create_task(_warm_telegram(session.owner))
    WARM_TASKS.add(task)
    task.add_done_callback(WARM_TASKS.discard)

    async def frames() -> AsyncIterator[str]:
        try:
            yield "retry: 3000\n\n"
            yield _sse_frame({"type": "ready"})
            while True:
                if await request.is_disconnected():
                    break
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=15)
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
                    continue
                yield _sse_frame(payload)
        finally:
            subs.discard(queue)
            if not subs and SSE_SUBS.get(session.owner) is subs:
                SSE_SUBS.pop(session.owner, None)

    return StreamingResponse(frames(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


async def _tg_client_for(owner: str) -> Any:
    client = TG_CLIENTS.get(owner)
    if client is not None and client.is_connected():
        try:
            if await client.is_user_authorized():
                await _install_ai_listener(owner, client)
                return client
        except Exception:
            pass
    init_db()
    with db() as conn:
        row = conn.execute("SELECT session_enc FROM telegram_accounts WHERE owner=?", (owner,)).fetchone()
    if not row:
        raise HTTPException(status_code=409, detail="Сначала подключите Telegram-аккаунт в настройках.")
    session_string = decrypt_secret(row["session_enc"])
    if not session_string:
        raise HTTPException(status_code=503, detail="Не удалось расшифровать Telegram-сессию. Переподключите аккаунт.")
    client = _telethon_client(session_string)
    await client.connect()
    if not await client.is_user_authorized():
        await client.disconnect()
        with db() as conn:
            conn.execute("DELETE FROM telegram_accounts WHERE owner=?", (owner,))
        raise HTTPException(status_code=401, detail="Telegram-сессия истекла. Подключите аккаунт заново.")
    TG_CLIENTS[owner] = client
    await _install_ai_listener(owner, client)
    return client


async def _save_telegram_session(owner: str, phone: str, client: Any) -> dict[str, Any]:
    me = await client.get_me()
    raw_session = client.session.save()
    encrypted = encrypt_secret(raw_session)
    if not encrypted:
        raise HTTPException(status_code=503, detail="Шифрование сессии недоступно. Установите cryptography и задайте SESSION_SECRET.")
    username = (getattr(me, "username", None) or "").strip()
    with db() as conn:
        conn.execute("""INSERT INTO telegram_accounts(owner,phone,username,session_enc,updated_at)
            VALUES(?,?,?,?,?) ON CONFLICT(owner) DO UPDATE SET phone=excluded.phone, username=excluded.username,
            session_enc=excluded.session_enc, updated_at=excluded.updated_at""",
            (owner, phone, username, encrypted, now_ts()))
    TG_CLIENTS[owner] = client
    await _install_ai_listener(owner, client)
    TG_LOGIN_FLOWS.pop(owner, None)
    return {"connected": True, "phone": phone, "username": username,
            "display_name": " ".join(x for x in [getattr(me, "first_name", ""), getattr(me, "last_name", "")] if x)}


async def _load_tg_messages(client: Any, chat_id: str, limit: int = 80) -> list[dict[str, Any]]:
    try:
        entity = await client.get_entity(int(chat_id))
    except Exception:
        entity = await client.get_entity(chat_id)
    # Personal chats only: the other side's name comes from the entity, so no per-message sender lookups.
    other = getattr(entity, "first_name", None) or getattr(entity, "title", None) or "Собеседник"
    out = []
    async for message in client.iter_messages(entity, limit=max(1, min(limit, 100))):
        out.append(_tg_message_item(message, "Вы" if message.out else other))
    return list(reversed(out))


# ---------------------------------------------------------------- AI provider: tokenharbor (OpenAI-compatible gateway)
# Built in: the key and model below work with no environment setup. TOKENHARBOR_API_KEY and TOKENHARBOR_MODEL override them.
TOKENHARBOR_API_KEY = os.getenv("TOKENHARBOR_API_KEY", "").strip() or "cc_GQagkzQGWrTOYzy3sp4kVNATz0dk3oiOWnoDO1adTJsyJulF"
TOKENHARBOR_MODEL = os.getenv("TOKENHARBOR_MODEL", "").strip() or "claude-opus-4.8"
TOKENHARBOR_URL = "https://cleanapis.com/v1/chat/completions"
TOKENHARBOR_USER_AGENT = "NEZZX-Telegram-Conv/4.0"
# the newest chat turns sent to the model, counted in characters
TOKENHARBOR_HISTORY_CHARS = 8000
# optional parameters the gateway may reject; a rejected one is dropped or renamed and the call is retried
TOKENHARBOR_OPTIONAL_PARAMS = ("temperature", "max_tokens", "max_completion_tokens")
# the model answers in this shape: a language and two reply variants
AI_FORMAT_HINT = ('Формат ответа: только JSON-объект без пояснений и markdown: '
                  '{"language": "<язык собеседника, например Русский>", "replies": ["<первый вариант>", "<второй вариант>"]}. '
                  'Оба варианта пишутся на языке собеседника, отвечают на его последнее сообщение и отличаются формулировкой или тоном.')


def ai_provider() -> str:
    return "tokenharbor" if TOKENHARBOR_API_KEY else ""


def ai_configured() -> bool:
    return bool(TOKENHARBOR_API_KEY)


def ai_model_name() -> str:
    return TOKENHARBOR_MODEL if TOKENHARBOR_API_KEY else ""


def _scrub(text: str) -> str:
    """Keeps the API key out of anything that reaches a log or the browser."""
    if TOKENHARBOR_API_KEY:
        text = text.replace(TOKENHARBOR_API_KEY, "***")
    return text[:160]


def _extract_json_object(text: str) -> Optional[dict[str, Any]]:
    """Finds the JSON object in an answer, also when it sits in a code fence or has words around it."""
    candidates = []
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S | re.I)
    if fence:
        candidates.append(fence.group(1))
    candidates.append(text)
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:
        candidates.append(text[start:end + 1])
    for raw in candidates:
        try:
            data = json.loads(raw.strip())
        except (ValueError, TypeError):
            continue
        if isinstance(data, dict):
            return data
    return None


def _parse_variants(content: str) -> tuple[str, list[str]]:
    """Returns (language, up to two replies). A plain-text answer is one reply; a JSON answer keeps its own list."""
    text = (content or "").strip()
    data = _extract_json_object(text)
    if data is None:
        return "", ([text] if text else [])
    language = str(data.get("language") or "").strip()[:40]
    replies = data.get("replies", data.get("reply"))
    if isinstance(replies, str):
        replies = [replies]
    if not isinstance(replies, list):
        return language, []
    variants = [str(item).strip() for item in replies if str(item).strip()]
    return language, variants[:2]


async def _post_json(url: str, body: dict[str, Any], headers: dict[str, str], timeout: int = 40) -> Any:
    request = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")

    def do_request() -> Any:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    return await asyncio.to_thread(do_request)


def _trim_turns(turns: list[tuple[str, str]], budget: int) -> list[tuple[str, str]]:
    """Keeps the newest turns that fit the character budget. The newest turn is always kept, cut to the budget if needed."""
    kept: list[tuple[str, str]] = []
    used = 0
    for role, text in reversed(turns):
        if kept and used + len(text) > budget:
            break
        kept.append((role, text[:budget]))
        used += len(text)
    return list(reversed(kept))


def _http_error_detail(exc: urllib.error.HTTPError) -> str:
    try:
        payload = json.loads(exc.read().decode("utf-8", "replace"))
    except Exception:
        return ""
    if not isinstance(payload, dict):
        return ""
    error = payload.get("error")
    if isinstance(error, dict):
        return str(error.get("message") or "")
    if isinstance(error, str):
        return error
    return str(payload.get("message") or payload.get("detail") or "")


def _tokenharbor_error(code: int, detail: str) -> str:
    if code in (401, 403):
        return f"tokenharbor не принял ключ (HTTP {code}). Проверьте TOKENHARBOR_API_KEY."
    if code == 402:
        return "На аккаунте tokenharbor закончился баланс или лимит (HTTP 402)."
    if code == 404:
        return f"tokenharbor не знает модель {TOKENHARBOR_MODEL} (HTTP 404). Укажите рабочую в TOKENHARBOR_MODEL."
    if code == 413:
        return "Запрос слишком большой для tokenharbor (HTTP 413)."
    if code == 429:
        return "Лимит запросов tokenharbor исчерпан (HTTP 429). Подождите минуту и попробуйте снова."
    tail = f": {_scrub(detail)}" if detail else ""
    return f"tokenharbor ответил ошибкой (HTTP {code}){tail}"


async def _tokenharbor_text(system: str, turns: list[tuple[str, str]]) -> tuple[str, list[str]]:
    """One chat-completions call. Returns (language, replies)."""
    messages: list[dict[str, str]] = [{"role": "system", "content": system}]
    messages += [{"role": ("assistant" if role == "assistant" else "user"), "content": text}
                 for role, text in _trim_turns(turns, TOKENHARBOR_HISTORY_CHARS)]
    body: dict[str, Any] = {"model": TOKENHARBOR_MODEL, "messages": messages, "max_tokens": 900, "temperature": 0.8}
    headers = {"Content-Type": "application/json", "Accept": "application/json",
               "Authorization": "Bearer " + TOKENHARBOR_API_KEY, "User-Agent": TOKENHARBOR_USER_AGENT}
    content = ""
    for _ in range(4):  # a rejected parameter is dropped or renamed and retried; an empty answer is retried too
        try:
            data = await _post_json(TOKENHARBOR_URL, body, headers)
        except urllib.error.HTTPError as exc:
            detail = _http_error_detail(exc)
            log.warning("tokenharbor request failed (HTTP %s): %s", exc.code, _scrub(detail))
            if exc.code in (400, 422):
                if "max_tokens" in body and "max_tokens" in detail.lower():
                    body["max_completion_tokens"] = body.pop("max_tokens")
                    continue
                dropped = next((key for key in TOKENHARBOR_OPTIONAL_PARAMS if key in body and key in detail), "")
                if dropped:
                    body.pop(dropped)
                    continue
            raise HTTPException(status_code=502, detail=_tokenharbor_error(exc.code, detail)) from exc
        except Exception as exc:
            log.warning("tokenharbor request failed (%s)", type(exc).__name__)
            raise HTTPException(status_code=502, detail="tokenharbor не ответил. Попробуйте ещё раз.") from exc
        try:
            raw = data["choices"][0]["message"]["content"]
        except Exception as exc:
            raise HTTPException(status_code=502, detail="tokenharbor вернул ответ в неожиданном формате.") from exc
        if isinstance(raw, list):  # some gateways send the content as parts
            raw = "".join(str(part.get("text", "")) for part in raw if isinstance(part, dict))
        content = str(raw or "")
        if content.strip():
            break  # only an empty answer is retried; a filled one is parsed below
    return _parse_variants(content)


async def _generate_ai_reply(messages: list[dict[str, Any]], mode: str, owner_prompt: str = "") -> tuple[list[str], str]:
    """Returns (up to two reply variants, detected language). The first variant is the one sent automatically."""
    if not ai_configured():
        raise HTTPException(status_code=503, detail="Добавьте TOKENHARBOR_API_KEY в переменные окружения Render.")
    mode = mode if mode in AI_MODES else "friendly"
    turns = [("assistant" if m.get("is_out") else "user", str(m.get("text", ""))[:2500])
             for m in messages[-AI_HISTORY_MESSAGES:] if str(m.get("text", "")).strip()]
    if not turns:
        raise HTTPException(status_code=422, detail="В чате пока нет текстовых сообщений для ответа.")
    if turns[-1][0] == "assistant":
        turns.append(("user", "Продолжи переписку: предложи следующее сообщение от моего имени."))
    if owner_prompt.strip():
        system = owner_prompt.strip()[:4000] + "\n\n" + AI_FORMAT_HINT
    else:
        system = AI_SYSTEM_PROMPT + "\n\nСтиль выбранного режима: " + AI_MODES[mode] + "\n\n" + AI_FORMAT_HINT
    language, replies = await _tokenharbor_text(system, turns)
    replies = [reply[:4000] for reply in replies]
    if not replies:
        raise HTTPException(status_code=502, detail="ИИ вернул пустой ответ.")
    return replies, language


@app.get("/api/telegram/status")
async def telegram_status(session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    init_db()
    with db() as conn:
        row = conn.execute("SELECT phone,username,updated_at FROM telegram_accounts WHERE owner=?", (session.owner,)).fetchone()
    if not row:
        return {"connected": False, "api_configured": bool(TELEGRAM_API_ID.isdigit() and TELEGRAM_API_HASH),
                "ai_configured": ai_configured()}
    connected = False
    try:
        client = await _tg_client_for(session.owner)
        connected = bool(await client.is_user_authorized())
    except Exception:
        connected = False
    return {"connected": connected, "phone": row["phone"], "username": row["username"],
            "updated_at": row["updated_at"], "api_configured": bool(TELEGRAM_API_ID.isdigit() and TELEGRAM_API_HASH),
            "ai_configured": ai_configured()}


@app.post("/api/telegram/login/start")
async def telegram_login_start(payload: TelegramPhoneBody, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    TelegramClient, _, StringSession, _ = _telethon_imports()
    phone = re.sub(r"[\s()\-]", "", payload.phone)
    if not re.fullmatch(r"\+?[0-9]{7,20}", phone):
        raise HTTPException(status_code=422, detail="Введите номер с кодом страны, например +374XXXXXXXX.")
    old = TG_LOGIN_FLOWS.pop(session.owner, None)
    if old:
        try: await old["client"].disconnect()
        except Exception: pass
    client = TelegramClient(StringSession(), int(TELEGRAM_API_ID), TELEGRAM_API_HASH, **_tg_device_kwargs())
    await client.connect()
    try:
        sent = await client.send_code_request(phone)
    except Exception as exc:
        await client.disconnect()
        log.warning("Telegram code request failed (%s)", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Telegram не отправил код. Проверьте номер и API credentials.") from exc
    TG_LOGIN_FLOWS[session.owner] = {"client": client, "phone": phone, "phone_code_hash": sent.phone_code_hash,
                                    "created_at": time.time()}
    return {"ok": True, "message": "Код отправлен в Telegram. Введите его на следующем шаге."}


@app.post("/api/telegram/login/complete")
async def telegram_login_complete(payload: TelegramCodeBody, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    _, _, _, SessionPasswordNeededError = _telethon_imports()
    flow = TG_LOGIN_FLOWS.get(session.owner)
    if not flow or time.time() - flow["created_at"] > 600:
        TG_LOGIN_FLOWS.pop(session.owner, None)
        raise HTTPException(status_code=409, detail="Вход истёк. Запросите новый код.")
    try:
        await flow["client"].sign_in(phone=flow["phone"], code=payload.code.strip(), phone_code_hash=flow["phone_code_hash"])
        return await _save_telegram_session(session.owner, flow["phone"], flow["client"])
    except SessionPasswordNeededError:
        return {"ok": True, "needs_password": True, "message": "Telegram запросил пароль двухэтапной аутентификации."}
    except Exception as exc:
        log.warning("Telegram code sign-in failed (%s)", type(exc).__name__)
        raise HTTPException(status_code=401, detail="Код неверен или устарел. Запросите новый код и повторите вход.") from exc


@app.post("/api/telegram/login/password")
async def telegram_login_password(payload: TelegramPasswordBody, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    flow = TG_LOGIN_FLOWS.get(session.owner)
    if not flow or time.time() - flow["created_at"] > 600:
        TG_LOGIN_FLOWS.pop(session.owner, None)
        raise HTTPException(status_code=409, detail="Вход истёк. Запросите новый код.")
    try:
        await flow["client"].sign_in(password=payload.password)
        return await _save_telegram_session(session.owner, flow["phone"], flow["client"])
    except Exception as exc:
        log.warning("Telegram 2FA sign-in failed (%s)", type(exc).__name__)
        raise HTTPException(status_code=401, detail="Пароль 2FA не принят. Проверьте его и повторите.") from exc


@app.post("/api/telegram/logout")
async def telegram_logout(session: SessionInfo = Depends(get_session)) -> dict[str, bool]:
    flow = TG_LOGIN_FLOWS.pop(session.owner, None)
    if flow:
        try: await flow["client"].disconnect()
        except Exception: pass
    client = TG_CLIENTS.pop(session.owner, None)
    if client:
        try: await client.log_out()
        except Exception:
            try: await client.disconnect()
            except Exception: pass
    with db() as conn:
        conn.execute("DELETE FROM telegram_accounts WHERE owner=?", (session.owner,))
        conn.execute("DELETE FROM ai_chat_settings WHERE owner=?", (session.owner,))
    return {"ok": True}


# ---------------------------------------------------------------- chat list: short cache + one query for AI flags
CHATS_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
CHATS_TTL = 6.0


def _ai_settings_map(owner: str) -> dict[str, dict[str, Any]]:
    """All AI flags of one owner in a single query (replaces one query per dialog)."""
    init_db()
    with db() as conn:
        rows = conn.execute("SELECT chat_id, enabled, mode FROM ai_chat_settings WHERE owner=?", (owner,)).fetchall()
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        mode = row["mode"] if row["mode"] in AI_MODES else "friendly"
        out[str(row["chat_id"])] = {"enabled": bool(row["enabled"]), "mode": mode, "mode_label": AI_MODE_LABELS[mode]}
    return out


@app.get("/api/telegram/chats")
async def telegram_chats(fresh: int = 0, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    cached = CHATS_CACHE.get(session.owner)
    if cached and not fresh and time.monotonic() - cached[0] < CHATS_TTL:
        return cached[1]
    client = await _tg_client_for(session.owner)
    flags = _ai_settings_map(session.owner)
    rows = []
    async for dialog in client.iter_dialogs(limit=300):
        if not dialog.is_user:  # personal chats only: groups, channels and supergroups are skipped
            continue
        entity = dialog.entity
        title = dialog.name or getattr(entity, "username", None) or str(dialog.id)
        last = dialog.message
        settings = flags.get(str(dialog.id)) or {"enabled": False, "mode": "friendly"}
        rows.append({"id": str(dialog.id), "name": title, "username": getattr(entity, "username", None),
                     "unread_count": int(dialog.unread_count or 0),
                     "last_message_text": (getattr(last, "message", "") or ("[Медиа]" if getattr(last, "media", None) else ""))[:300] if last else "",
                     "last_message_date": last.date.isoformat() if last and last.date else "",
                     "is_user": bool(getattr(entity, "bot", None) is not None or hasattr(entity, "first_name")),
                     "ai_enabled": settings["enabled"], "ai_mode": settings["mode"]})
    payload = {"items": rows, "count": len(rows), "unread_count": sum(x["unread_count"] for x in rows),
               "ai_active_count": sum(1 for x in rows if x["ai_enabled"])}
    CHATS_CACHE[session.owner] = (time.monotonic(), payload)
    return payload


@app.get("/api/telegram/chats/{chat_id}/messages")
async def telegram_messages(chat_id: str, limit: int = 80, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    client = await _tg_client_for(session.owner)
    items = await _load_tg_messages(client, chat_id, limit)
    return {"items": items, "count": len(items), "ai": _ai_settings(session.owner, chat_id)}


@app.post("/api/telegram/chats/{chat_id}/send")
async def telegram_send_message(chat_id: str, payload: TelegramSendBody, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    import io
    text = payload.text.strip()
    image_bytes: bytes | None = None
    if payload.image:
        mime = (payload.mime_type or "").split(";", 1)[0].strip().lower()
        if mime not in {"image/jpeg", "image/png", "image/webp", "image/gif"}:
            raise HTTPException(status_code=415, detail="Поддерживаются изображения JPG, PNG, WEBP и GIF.")
        try:
            image_bytes = base64.b64decode(payload.image, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise HTTPException(status_code=422, detail="Файл изображения повреждён или имеет неверный формат.") from exc
        if len(image_bytes) > 10 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="Фото больше 10 МБ.")
    if not text and image_bytes is None:
        raise HTTPException(status_code=422, detail="Сообщение пустое.")
    client = await _tg_client_for(session.owner)
    try:
        entity = await client.get_entity(int(chat_id))
        if image_bytes is not None:
            buffer = io.BytesIO(image_bytes)
            buffer.name = (payload.filename or "photo.jpg")[:120]
            message = await client.send_file(entity, buffer, caption=text or None)
        else:
            message = await client.send_message(entity, text)
    except Exception as exc:
        log.warning("Telegram send failed (%s)", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Не удалось отправить сообщение в Telegram.") from exc
    CHATS_CACHE.pop(session.owner, None)
    _sse_publish(session.owner, {"type": "message", "chat_id": str(chat_id), "message": _tg_message_item(message, "Вы", chat_id)})
    return {"ok": True, "id": message.id, "text": message.message or text}


MAX_VOICE_BYTES = 12 * 1024 * 1024


def _wav_to_ogg_opus(wav: bytes) -> bytes | None:
    """Telegram shows a voice bubble only for OGG/Opus. Returns None when ffmpeg is not installed."""
    import shutil
    import subprocess

    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        return None
    try:
        proc = subprocess.run(
            [ffmpeg, "-hide_banner", "-loglevel", "error", "-i", "pipe:0",
             "-c:a", "libopus", "-b:a", "48k", "-ac", "1", "-f", "ogg", "pipe:1"],
            input=wav, capture_output=True, timeout=40, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0 or not proc.stdout:
        return None
    return proc.stdout


@app.post("/api/telegram/chats/{chat_id}/voice")
async def telegram_send_voice(chat_id: str, request: Request, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    import io
    data = await request.body()
    if not data:
        raise HTTPException(status_code=422, detail="Запись пустая.")
    if len(data) > MAX_VOICE_BYTES:
        raise HTTPException(status_code=413, detail="Голосовое больше 12 МБ.")
    if data[:4] != b"RIFF":
        raise HTTPException(status_code=415, detail="Нужна запись в формате WAV.")
    ogg = _wav_to_ogg_opus(data)
    client = await _tg_client_for(session.owner)
    try:
        entity = await client.get_entity(int(chat_id))
        if ogg is not None:
            buffer = io.BytesIO(ogg)
            buffer.name = "voice.ogg"
            message = await client.send_file(entity, buffer, voice_note=True)
        else:
            buffer = io.BytesIO(data)
            buffer.name = "voice.wav"
            message = await client.send_file(entity, buffer)
    except Exception as exc:
        log.warning("Telegram voice send failed (%s)", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Не удалось отправить голосовое в Telegram.") from exc
    CHATS_CACHE.pop(session.owner, None)
    _sse_publish(session.owner, {"type": "message", "chat_id": str(chat_id), "message": _tg_message_item(message, "Вы", chat_id)})
    return {"ok": True, "id": message.id, "ogg": ogg is not None}


@app.put("/api/telegram/chats/{chat_id}/ai")
async def telegram_chat_ai(chat_id: str, payload: ChatAISettingsBody, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    if payload.mode not in AI_MODES:
        raise HTTPException(status_code=422, detail="Неизвестный режим ИИ.")
    if payload.enabled and not ai_configured():
        raise HTTPException(status_code=503, detail="Добавьте TOKENHARBOR_API_KEY в переменные окружения Render.")
    with db() as conn:
        conn.execute("""INSERT INTO ai_chat_settings(owner,chat_id,enabled,mode,updated_at) VALUES(?,?,?,?,?)
            ON CONFLICT(owner,chat_id) DO UPDATE SET enabled=excluded.enabled, mode=excluded.mode, updated_at=excluded.updated_at""",
            (session.owner, str(chat_id), 1 if payload.enabled else 0, payload.mode, now_ts()))
    CHATS_CACHE.pop(session.owner, None)
    return {"ok": True, **_ai_settings(session.owner, chat_id)}


@app.post("/api/ai/draft")
async def ai_draft(payload: AIDraftBody, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    if payload.mode not in AI_MODES:
        raise HTTPException(status_code=422, detail="Неизвестный режим ИИ.")
    client = await _tg_client_for(session.owner)
    history = await _load_tg_messages(client, payload.chat_id, 20)
    variants, lang = await _generate_ai_reply(history, payload.mode, _ai_owner_prompt(session.owner))
    draft = variants[0]
    _log_ai(session.owner, payload.chat_id, "draft", payload.mode)
    return {"draft": draft, "variants": variants, "mode": payload.mode, "language": lang}


@app.get("/api/ai/status")
async def ai_status(session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    with db() as conn:
        row = conn.execute("""SELECT COUNT(*) AS total, SUM(CASE WHEN direction='auto_sent' THEN 1 ELSE 0 END) AS auto_sent,
            SUM(CASE WHEN direction='draft' THEN 1 ELSE 0 END) AS drafts FROM ai_message_log WHERE owner=? AND created_at>=?""",
            (session.owner, now_ts()-86400)).fetchone()
    return {"configured": ai_configured(), "provider": ai_provider(), "model": ai_model_name(), "modes": AI_MODE_LABELS,
            "today": {"total": int(row["total"] or 0), "auto_sent": int(row["auto_sent"] or 0), "drafts": int(row["drafts"] or 0)}}


@app.get("/api/ai/prompt")
async def ai_prompt_get(session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    return {"prompt": _ai_owner_prompt(session.owner)}


@app.put("/api/ai/prompt")
async def ai_prompt_put(payload: AIPromptBody, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    init_db()
    text = payload.prompt.strip()
    with db() as conn:
        conn.execute("""INSERT INTO ai_owner_prompt(owner,prompt,updated_at) VALUES(?,?,?)
            ON CONFLICT(owner) DO UPDATE SET prompt=excluded.prompt, updated_at=excluded.updated_at""",
            (session.owner, text, now_ts()))
    return {"ok": True, "prompt": text}


# ---------------------------------------------------------------- real Telegram avatars (cached, bounded)
AVATAR_CACHE: dict[tuple[str, str], tuple[float, Any]] = {}
AVATAR_TTL_HIT = 6 * 3600
AVATAR_TTL_MISS = 30 * 60
AVATAR_MAX_ITEMS = 600
AVATAR_SEM: Any = None


def _avatar_response(data: Any) -> Response:
    if data:
        return Response(content=data, media_type="image/jpeg", headers={"Cache-Control": "private, max-age=3600"})
    return Response(status_code=404, headers={"Cache-Control": "private, max-age=600"})


@app.get("/api/telegram/avatar/{chat_id}")
async def telegram_avatar(chat_id: str, session: SessionInfo = Depends(get_session)) -> Response:
    global AVATAR_SEM
    key = (session.owner, str(chat_id))
    hit = AVATAR_CACHE.get(key)
    if hit and time.monotonic() - hit[0] < (AVATAR_TTL_HIT if hit[1] else AVATAR_TTL_MISS):
        return _avatar_response(hit[1])
    if AVATAR_SEM is None:
        AVATAR_SEM = asyncio.Semaphore(4)
    client = await _tg_client_for(session.owner)
    data: Any = None
    try:
        async with AVATAR_SEM:
            entity = await client.get_entity(int(chat_id))
            data = await asyncio.wait_for(client.download_profile_photo(entity, file=bytes), timeout=12)
    except Exception:
        data = None
    if len(AVATAR_CACHE) >= AVATAR_MAX_ITEMS:
        for old in list(AVATAR_CACHE)[: AVATAR_MAX_ITEMS // 4]:
            AVATAR_CACHE.pop(old, None)
    AVATAR_CACHE[key] = (time.monotonic(), data or None)
    return _avatar_response(data or None)


# ---------------------------------------------------------------- personal background photo (per owner)
UI_BG_MAX_BYTES = 3_000_000


def _sniff_image(data: bytes) -> str:
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return ""


@app.get("/api/ui/background/meta")
async def ui_background_meta(session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    init_db()
    with db() as conn:
        row = conn.execute("SELECT version, mime, LENGTH(data) AS size FROM user_backgrounds WHERE owner=?",
                           (session.owner,)).fetchone()
    if not row:
        return {"custom": False, "version": 0}
    return {"custom": True, "version": int(row["version"]), "size": int(row["size"] or 0), "mime": row["mime"]}


@app.get("/api/ui/background")
async def ui_background(session: SessionInfo = Depends(get_session)) -> Response:
    init_db()
    with db() as conn:
        row = conn.execute("SELECT mime, data FROM user_backgrounds WHERE owner=?", (session.owner,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Фон не задан.")
    return Response(content=bytes(row["data"]), media_type=row["mime"], headers={"Cache-Control": "private, max-age=86400"})


@app.put("/api/ui/background")
async def ui_background_put(request: Request, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    init_db()
    try:
        declared = int(request.headers.get("content-length") or 0)
    except ValueError:
        declared = 0
    if declared > UI_BG_MAX_BYTES:
        raise HTTPException(status_code=413, detail="Фон должен весить не больше 3 МБ.")
    data = await request.body()
    if not data:
        raise HTTPException(status_code=422, detail="Файл пустой.")
    if len(data) > UI_BG_MAX_BYTES:
        raise HTTPException(status_code=413, detail="Фон должен весить не больше 3 МБ.")
    mime = _sniff_image(data)
    if not mime:
        raise HTTPException(status_code=422, detail="Поддерживаются JPEG, PNG и WebP.")
    version = int(time.time() * 1000)
    with db() as conn:
        conn.execute("""INSERT INTO user_backgrounds(owner,mime,data,version,updated_at) VALUES(?,?,?,?,?)
            ON CONFLICT(owner) DO UPDATE SET mime=excluded.mime, data=excluded.data,
            version=excluded.version, updated_at=excluded.updated_at""",
            (session.owner, mime, sqlite3.Binary(data), version, now_ts()))
    return {"ok": True, "custom": True, "version": version, "size": len(data), "mime": mime}


@app.delete("/api/ui/background")
async def ui_background_delete(session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    init_db()
    with db() as conn:
        conn.execute("DELETE FROM user_backgrounds WHERE owner=?", (session.owner,))
    return {"ok": True, "custom": False, "version": 0}


# ---------------------------------------------------------------- Telegram media on demand, read receipts
# Photos and videos are downloaded only when a browser asks for them, cached in memory with a byte budget,
# and always fetched through the owner's own Telegram client, so one owner never sees another's files.
TG_MEDIA_CACHE: dict[tuple[str, str, int], tuple[str, bytes]] = {}
TG_MEDIA_CACHE_BYTES = 64 * 1024 * 1024
TG_MEDIA_SEM: Any = None


async def _tg_entity(client: Any, chat_id: str) -> Any:
    try:
        return await client.get_entity(int(chat_id))
    except Exception:
        return await client.get_entity(chat_id)


def _tg_media_put(key: tuple[str, str, int], value: tuple[str, bytes]) -> None:
    TG_MEDIA_CACHE.pop(key, None)
    TG_MEDIA_CACHE[key] = value
    total = sum(len(item[1]) for item in TG_MEDIA_CACHE.values())
    while total > TG_MEDIA_CACHE_BYTES and len(TG_MEDIA_CACHE) > 1:
        total -= len(TG_MEDIA_CACHE.pop(next(iter(TG_MEDIA_CACHE)))[1])


def _tg_media_response(request: Request, mime: str, data: bytes) -> Response:
    """The whole file, or only the byte range a video player asks for (Safari plays video only with ranges)."""
    total = len(data)
    headers = {"Cache-Control": "private, max-age=3600", "Accept-Ranges": "bytes"}
    match = re.match(r"bytes=(\d*)-(\d*)$", request.headers.get("range", "").strip())
    if not match or not total or not (match.group(1) or match.group(2)):
        return Response(content=data, media_type=mime, headers=headers)
    first, last = match.group(1), match.group(2)
    if first:
        start = int(first)
        end = min(int(last), total - 1) if last else total - 1
    else:
        start, end = max(0, total - int(last)), total - 1
    if start >= total or start > end:
        return Response(status_code=416, headers={**headers, "Content-Range": f"bytes */{total}"})
    headers["Content-Range"] = f"bytes {start}-{end}/{total}"
    return Response(content=data[start:end + 1], status_code=206, media_type=mime, headers=headers)


@app.get("/api/telegram/chats/{chat_id}/messages/{message_id}/media")
async def telegram_media(chat_id: str, message_id: int, request: Request, session: SessionInfo = Depends(get_session)) -> Response:
    global TG_MEDIA_SEM
    key = (session.owner, str(chat_id), int(message_id))
    hit = TG_MEDIA_CACHE.get(key)
    if hit is None:
        if TG_MEDIA_SEM is None:
            TG_MEDIA_SEM = asyncio.Semaphore(3)
        client = await _tg_client_for(session.owner)
        try:
            entity = await _tg_entity(client, chat_id)
            message = await client.get_messages(entity, ids=int(message_id))
        except Exception as exc:
            raise HTTPException(status_code=404, detail="Сообщение не найдено.") from exc
        if not message or not _tg_media_kind(message):
            raise HTTPException(status_code=404, detail="В этом сообщении нет фото или видео.")
        info = message.file
        if int(getattr(info, "size", 0) or 0) > TG_MEDIA_MAX_BYTES:
            raise HTTPException(status_code=413, detail="Файл больше 25 МБ. Откройте его в Telegram.")
        try:
            async with TG_MEDIA_SEM:
                data = await asyncio.wait_for(client.download_media(message, file=bytes), timeout=60)
        except Exception as exc:
            log.warning("Telegram media download failed (%s)", type(exc).__name__)
            raise HTTPException(status_code=502, detail="Не удалось загрузить медиа из Telegram.") from exc
        if not data:
            raise HTTPException(status_code=404, detail="Медиа пустое.")
        hit = (str(getattr(info, "mime_type", "") or "application/octet-stream"), data)
        _tg_media_put(key, hit)
    return _tg_media_response(request, hit[0], hit[1])


# marking a chat read on Telegram too, so its unread badge stays cleared on every device
@app.post("/api/telegram/chats/{chat_id}/read")
async def telegram_mark_read(chat_id: str, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    client = await _tg_client_for(session.owner)
    try:
        await client.send_read_acknowledge(await _tg_entity(client, chat_id))
    except Exception as exc:
        log.warning("Telegram read receipt failed (%s)", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Не удалось отметить чат прочитанным.") from exc
    CHATS_CACHE.pop(session.owner, None)
    return {"ok": True, "chat_id": str(chat_id), "unread_count": 0}


# ---------------------------------------------------------------- music playlist: Spotify and SoundCloud links
# The server stores links and public metadata only. Audio is played by the official embeds in the browser.
MUSIC_MAX_ITEMS = 300
MUSIC_SPOTIFY_RE = re.compile(r"^/(?:intl-[a-z]{2}(?:-[a-z]{2})?/)?(track|album|playlist)/([A-Za-z0-9]{22})/?$")
MUSIC_SC_RESERVED = {"discover", "charts", "search", "stream", "you", "upload", "pages", "jobs", "popular", "mobile",
                     "settings", "messages", "notifications", "imprint", "terms-of-use", "people", "tags", "groups"}
MUSIC_SC_RESERVED_SUB = {"likes", "tracks", "albums", "reposts", "followers", "following", "comments", "popular-tracks"}
MUSIC_SC_SEG_RE = re.compile(r"^[A-Za-z0-9_\-]{1,80}$")
MUSIC_KIND_RU = {"track": "Трек", "album": "Альбом", "playlist": "Плейлист", "set": "Плейлист", "video": "Видео", "audio": "Аудио"}
MUSIC_PROVIDER_RU = {"spotify": "Spotify", "soundcloud": "SoundCloud", "file": "Файл"}


class MusicAddBody(BaseModel):
    url: str = Field(min_length=6, max_length=600)


def _music_parse(raw: Any) -> Any:
    """Turns a pasted link into a canonical Spotify or SoundCloud link. Anything else returns None."""
    text = str(raw or "").strip()
    if not text or len(text) > 600:
        return None
    if "://" not in text:
        text = "https://" + text
    parts = urllib.parse.urlsplit(text)
    host = (parts.hostname or "").lower()
    for prefix in ("www.", "m."):
        if host.startswith(prefix):
            host = host[len(prefix):]
    path = parts.path or ""
    if host == "open.spotify.com":
        match = MUSIC_SPOTIFY_RE.match(path)
        if not match:
            return None
        kind, sid = match.group(1), match.group(2)
        return {"provider": "spotify", "kind": kind, "embed_id": f"{kind}:{sid}",
                "source_url": f"https://open.spotify.com/{kind}/{sid}", "artist_hint": ""}
    if host == "soundcloud.com":
        segs = [s for s in path.split("/") if s]
        if len(segs) < 2 or segs[0].lower() in MUSIC_SC_RESERVED or not all(MUSIC_SC_SEG_RE.match(s) for s in segs[:3]):
            return None
        user, slug = segs[0], segs[1]
        if slug.lower() == "sets" and len(segs) >= 3:
            kind, key = "set", f"{user}/sets/{segs[2]}"
        elif slug.lower() in MUSIC_SC_RESERVED_SUB:
            return None
        else:
            kind, key = "track", f"{user}/{slug}"
        return {"provider": "soundcloud", "kind": kind, "embed_id": key.lower(),
                "source_url": "https://soundcloud.com/" + key, "artist_hint": user}
    return None


def _music_oembed_sync(provider: str, source_url: str) -> dict[str, str]:
    base = "https://open.spotify.com/oembed?url=" if provider == "spotify" else "https://soundcloud.com/oembed?format=json&url="
    request = urllib.request.Request(base + urllib.parse.quote(source_url, safe=""),
                                     headers={"Accept": "application/json", "User-Agent": "NEZZX-AI-Telegram-Conv/1.0"})
    with urllib.request.urlopen(request, timeout=6) as response:
        data = json.loads(response.read(200000).decode("utf-8"))
    thumb = str(data.get("thumbnail_url") or "")
    return {"title": str(data.get("title") or "").strip()[:160],
            "thumb_url": thumb if thumb.startswith("https://") and len(thumb) < 400 else ""}


async def _music_meta(parsed: dict[str, str]) -> dict[str, str]:
    fallback = f"{MUSIC_KIND_RU.get(parsed['kind'], 'Трек')} {MUSIC_PROVIDER_RU[parsed['provider']]}"
    if parsed["provider"] == "soundcloud":
        slug = parsed["embed_id"].split("/")[-1].replace("-", " ").replace("_", " ").strip()
        fallback = (slug[:1].upper() + slug[1:]) or fallback
    meta = {"title": "", "thumb_url": ""}
    try:
        meta = await asyncio.to_thread(_music_oembed_sync, parsed["provider"], parsed["source_url"])
    except Exception:
        log.info("Music metadata unavailable (%s)", parsed["provider"])
    return {"title": meta.get("title") or fallback, "thumb_url": meta.get("thumb_url", ""),
            "artist": parsed.get("artist_hint", "")}


def _music_item(row: Any) -> dict[str, Any]:
    return {"id": int(row["id"]), "provider": row["provider"], "provider_label": MUSIC_PROVIDER_RU.get(row["provider"], ""),
            "kind": row["kind"], "kind_label": MUSIC_KIND_RU.get(row["kind"], ""), "embed_id": row["embed_id"],
            "source_url": row["source_url"], "title": row["title"], "artist": row["artist"], "thumb_url": row["thumb_url"],
            "file_url": ("/api/music/files/" + row["embed_id"]) if row["provider"] == "file" else ""}


@app.get("/api/music/playlist")
async def music_list(session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    init_db()
    with db() as conn:
        rows = conn.execute("SELECT * FROM music_playlist WHERE owner=? ORDER BY added_at ASC, id ASC", (session.owner,)).fetchall()
    items = [_music_item(row) for row in rows]
    return {"items": items, "count": len(items)}


@app.post("/api/music/playlist")
async def music_add(payload: MusicAddBody, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    parsed = _music_parse(payload.url)
    if not parsed:
        raise HTTPException(status_code=422, detail="Вставьте ссылку на трек, альбом или плейлист Spotify или SoundCloud.")
    init_db()
    with db() as conn:
        found = conn.execute("SELECT * FROM music_playlist WHERE owner=? AND provider=? AND embed_id=?",
                             (session.owner, parsed["provider"], parsed["embed_id"])).fetchone()
        if found:
            return {"item": _music_item(found), "created": False}
        count = int(conn.execute("SELECT COUNT(*) AS n FROM music_playlist WHERE owner=?", (session.owner,)).fetchone()["n"])
    if count >= MUSIC_MAX_ITEMS:
        raise HTTPException(status_code=422, detail="В плейлисте уже 300 треков. Удалите лишние, чтобы добавить новые.")
    meta = await _music_meta(parsed)
    with db() as conn:
        conn.execute("""INSERT INTO music_playlist(owner,provider,kind,embed_id,source_url,title,artist,thumb_url,added_at)
            VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(owner,provider,embed_id) DO NOTHING""",
            (session.owner, parsed["provider"], parsed["kind"], parsed["embed_id"], parsed["source_url"],
             meta["title"], meta["artist"], meta["thumb_url"], now_ts()))
        row = conn.execute("SELECT * FROM music_playlist WHERE owner=? AND provider=? AND embed_id=?",
                           (session.owner, parsed["provider"], parsed["embed_id"])).fetchone()
    return {"item": _music_item(row), "created": True}


@app.delete("/api/music/playlist/{item_id}")
async def music_delete(item_id: int, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    init_db()
    with db() as conn:
        row = conn.execute("SELECT provider, embed_id FROM music_playlist WHERE owner=? AND id=?",
                           (session.owner, int(item_id))).fetchone()
        if row is not None and row["provider"] == "file":
            conn.execute("DELETE FROM music_files WHERE owner=? AND id=?", (session.owner, int(row["embed_id"])))
            MUSIC_FILE_CACHE.pop((session.owner, int(row["embed_id"])), None)
        conn.execute("DELETE FROM music_playlist WHERE owner=? AND id=?", (session.owner, int(item_id)))
    return {"ok": True}


# ---------------------------------------------------------------- music files: the owner's own MP4, M4A, MP3 or WAV
# A file is stored in the database under its owner and listed in the playlist as provider "file".
# Every query filters by owner, and playback is streamed with byte ranges so the player can seek.
MUSIC_FILE_MAX_BYTES = 50 * 1024 * 1024
MUSIC_FILES_QUOTA_BYTES = 300 * 1024 * 1024
MUSIC_FILE_CACHE_BYTES = 64 * 1024 * 1024
MUSIC_FILE_TYPES = {"mp4": ("video/mp4", "video"), "m4a": ("audio/mp4", "audio"),
                    "mp3": ("audio/mpeg", "audio"), "wav": ("audio/wav", "audio")}
MUSIC_FILE_CACHE: dict[tuple[str, int], bytes] = {}


def _music_file_name(raw: str) -> tuple[str, str]:
    """(name without extension, lowercase extension) from the X-File-Name header; ("", "") for a type we do not take."""
    name = urllib.parse.unquote(raw or "").replace("\\", "/").split("/")[-1]
    name = "".join(ch for ch in name if ch.isprintable()).strip()
    stem, dot, ext = name.rpartition(".")
    stem = stem.strip()[:160]  # the extension is split off first, so a long name keeps it
    ext = ext.lower() if dot else ""
    if ext not in MUSIC_FILE_TYPES or not stem:
        return "", ""
    return stem, ext


def _music_sniff(data: bytes) -> bool:
    """True when the bytes start like an MP4, M4A or MOV file, a WAV file or an MP3 (ID3 tag or frame sync)."""
    if data[4:8] in (b"ftyp", b"moov", b"mdat", b"wide", b"free"):
        return True
    if data[:4] == b"RIFF" and data[8:12] == b"WAVE":
        return True
    if data[:3] == b"ID3":
        return True
    return len(data) > 1 and data[0] == 0xFF and (data[1] & 0xE0) == 0xE0


async def _music_read_body(request: Request, limit: int) -> bytes:
    """The raw request body, read in pieces. Reading stops as soon as the body is larger than the limit."""
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise HTTPException(status_code=413, detail="Файл больше 50 МБ. Возьмите файл поменьше.")
        chunks.append(chunk)
    return b"".join(chunks)


def _music_cache_put(key: tuple[str, int], data: bytes) -> None:
    MUSIC_FILE_CACHE.pop(key, None)
    MUSIC_FILE_CACHE[key] = data
    total = sum(len(item) for item in MUSIC_FILE_CACHE.values())
    while total > MUSIC_FILE_CACHE_BYTES and len(MUSIC_FILE_CACHE) > 1:
        total -= len(MUSIC_FILE_CACHE.pop(next(iter(MUSIC_FILE_CACHE))))


@app.post("/api/music/upload")
async def music_upload(request: Request, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    """One file from the owner. The file itself is the request body; its name comes in the X-File-Name header."""
    stem, ext = _music_file_name(request.headers.get("x-file-name", ""))
    if not ext:
        raise HTTPException(status_code=422, detail="Поддерживаются файлы MP4, M4A, MP3 и WAV.")
    try:
        declared = int(request.headers.get("content-length") or 0)
    except ValueError:
        declared = 0
    if declared > MUSIC_FILE_MAX_BYTES:
        raise HTTPException(status_code=413, detail="Файл больше 50 МБ. Возьмите файл поменьше.")
    data = await _music_read_body(request, MUSIC_FILE_MAX_BYTES)
    if not data:
        raise HTTPException(status_code=422, detail="Файл пустой.")
    if not _music_sniff(data):
        raise HTTPException(status_code=422, detail="Это не похоже на MP4, M4A, MP3 или WAV. Проверьте файл.")
    init_db()
    mime, kind = MUSIC_FILE_TYPES[ext]
    with db() as conn:
        count = int(conn.execute("SELECT COUNT(*) AS n FROM music_playlist WHERE owner=?", (session.owner,)).fetchone()["n"])
        if count >= MUSIC_MAX_ITEMS:
            raise HTTPException(status_code=422, detail="В плейлисте уже 300 треков. Удалите лишние, чтобы добавить новые.")
        used = int(conn.execute("SELECT COALESCE(SUM(size), 0) AS n FROM music_files WHERE owner=?", (session.owner,)).fetchone()["n"])
        if used + len(data) > MUSIC_FILES_QUOTA_BYTES:
            raise HTTPException(status_code=413, detail="Для файлов не хватает места: лимит 300 МБ. Удалите ненужные файлы.")
        cur = conn.execute("INSERT INTO music_files(owner,name,mime,size,data,added_at) VALUES(?,?,?,?,?,?)",
                           (session.owner, stem, mime, len(data), sqlite3.Binary(data), now_ts()))
        file_id = str(int(cur.lastrowid))
        conn.execute("""INSERT INTO music_playlist(owner,provider,kind,embed_id,source_url,title,artist,thumb_url,added_at)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            (session.owner, "file", kind, file_id, "", stem, "", "", now_ts()))
        row = conn.execute("SELECT * FROM music_playlist WHERE owner=? AND provider=? AND embed_id=?",
                           (session.owner, "file", file_id)).fetchone()
    return {"item": _music_item(row), "created": True}


@app.get("/api/music/files/{file_id}")
async def music_file(file_id: int, request: Request, session: SessionInfo = Depends(get_session)) -> Response:
    """The owner's own file, with byte ranges so the player can seek. Anyone else gets the same 404 as for a missing file."""
    init_db()
    key = (session.owner, int(file_id))
    with db() as conn:
        meta = conn.execute("SELECT mime FROM music_files WHERE owner=? AND id=?", (session.owner, int(file_id))).fetchone()
    if meta is None:
        raise HTTPException(status_code=404, detail="Файл не найден.")
    data = MUSIC_FILE_CACHE.get(key)
    if data is None:
        with db() as conn:
            blob = conn.execute("SELECT data FROM music_files WHERE owner=? AND id=?", (session.owner, int(file_id))).fetchone()
        if blob is None:
            raise HTTPException(status_code=404, detail="Файл не найден.")
        data = bytes(blob["data"])
        _music_cache_put(key, data)
    response = _tg_media_response(request, str(meta["mime"]), data)
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


# ---------------------------------------------------------------- FunPay account
@app.get("/api/funpay/status")
async def funpay_status(session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    try:
        conn = await conn_for(session.owner)
    except HTTPException as exc:
        return {"connected": False, "message": exc.detail if isinstance(exc.detail, str) else ""}
    return {"connected": True, "username": conn.username, "balance": balance_value(conn.balance),
            "connected_at": conn.connected_at, "profile_id": conn.profile.get("id")}


@app.post("/api/funpay/connect")
async def connect_funpay(payload: FunPayConnectBody, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    conn = await connect_owner(session.owner, payload.golden_key, payload.user_agent)
    return {"connected": True, "username": conn.username, "balance": balance_value(conn.balance),
            "connected_at": conn.connected_at, "profile_id": conn.profile.get("id")}


@app.post("/api/funpay/disconnect")
async def disconnect_funpay(session: SessionInfo = Depends(get_session)) -> dict[str, bool]:
    await close_owner(session.owner)
    delete_fp_account(session.owner)
    return {"ok": True}


# ---------------------------------------------------------------- catalogue search
@app.get("/api/funpay/catalog")
async def catalog_search(q: str = "", session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    query = " ".join(q.split())[:80]
    await ensure_catalog(session.owner)
    items = search_catalog(query)
    return {
        "items": items,
        "count": len(items),
        "fetched_at": int(CATALOG["fetched_at"]),
        "refreshing": bool(CATALOG["refreshing"]),
        "error": CATALOG["error"] if not CATALOG["items"] or CATALOG["error"] else "",
    }


# ---------------------------------------------------------------- lots
@app.get("/api/funpay/lots")
async def my_lots(subcategory_id: int, session: SessionInfo = Depends(get_session)) -> list[dict[str, Any]]:
    conn = await conn_for(session.owner)
    values = await fp_call(conn, lambda: conn.account.get_my_lots(subcategory_id), "Не удалось загрузить офферы")
    return [normalize_lot(d) for d in _dicts(values)]


@app.get("/api/funpay/offers")
async def search_offers(subcategory_id: int, q: str = "", session: SessionInfo = Depends(get_session)) -> list[dict[str, Any]]:
    """Public market search: offer cards of one FunPay subcategory."""
    if len(q) > 180:
        raise HTTPException(status_code=422, detail="Поисковый запрос слишком длинный.")
    conn = await conn_for(session.owner)
    response = await fp_call(
        conn,
        lambda: conn.client.get(f"lots/{subcategory_id}/", query=q.strip() or None, raise_not_200=True),
        "Не удалось получить офферы FunPay",
    )
    return parse_market_offers(response.text)


def parse_market_offers(page_html: str) -> list[dict[str, Any]]:
    soup = BeautifulSoup(page_html, "html.parser")
    offers: list[dict[str, Any]] = []
    for node in soup.select("a.tc-item")[:100]:
        href = node.get("href") or ""
        title_node = node.select_one(".tc-desc-text")
        price_node = node.select_one(".tc-price")
        seller_node = node.select_one(".media-user-name, .tc-user, .tc-user-name")
        server_node = node.select_one(".tc-server")
        amount_node = node.select_one(".tc-amount")
        offer_id = node.get("data-offer")
        if not offer_id and href:
            offer_id = parse_qs(urlparse(href).query).get("id", [None])[0]
        price_raw = price_node.get("data-s") if price_node else None
        if not price_raw and price_node:
            price_raw = price_node.get_text(" ", strip=True).replace(" ", " ").split()[0]
        try:
            price_value = float(str(price_raw).replace(" ", "").replace(",", ".")) if price_raw else None
        except ValueError:
            price_value = None
        offers.append({
            "id": str(offer_id or ""),
            "title": title_node.get_text(" ", strip=True) if title_node else "Оффер FunPay",
            "price": price_value,
            "price_text": price_node.get_text(" ", strip=True) if price_node else "—",
            "seller": seller_node.get_text(" ", strip=True) if seller_node else "Продавец",
            "server": server_node.get_text(" ", strip=True) if server_node else "",
            "amount": amount_node.get_text(" ", strip=True) if amount_node else "",
            "url": urljoin("https://funpay.com", href) if href else "https://funpay.com/",
        })
    return offers


def extract_form_fields(form: Any) -> dict[str, str]:
    """Default values of a FunPay offer-editor form."""
    fields: dict[str, str] = {}
    for node in form.find_all(["input", "textarea", "select"]):
        name = node.get("name")
        if not name:
            continue
        if node.name == "input":
            input_type = (node.get("type") or "text").lower()
            if input_type in ("checkbox", "radio"):
                if node.has_attr("checked"):
                    fields[name] = node.get("value") or "on"
            else:
                fields[name] = node.get("value") or ""
        elif node.name == "textarea":
            fields[name] = node.get_text() or ""
        elif node.name == "select":
            selected = node.find("option", selected=True) or node.find("option")
            if selected is not None:
                fields[name] = selected.get("value") or selected.get_text(strip=True)
    return fields


@app.post("/api/funpay/lots/create")
async def create_lot(payload: LotCreateBody, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    conn = await conn_for(session.owner)
    client = conn.client
    response = await fp_call(
        conn, lambda: client.get("lots/offerEdit", node=payload.subcategory_id, raise_not_200=True),
        "Не удалось открыть форму оффера FunPay",
    )
    soup = BeautifulSoup(response.text, "html.parser")
    form = soup.select_one("form.form-offer-editor") or soup.find("form")
    if not form:
        raise HTTPException(status_code=502, detail="FunPay не вернул форму создания оффера для этой категории. "
                                                     "Попробуйте другую игру или создайте лот на сайте FunPay.")
    fields = extract_form_fields(form)
    fields["offer_id"] = fields.get("offer_id") or "0"
    fields["node_id"] = str(payload.subcategory_id)
    fields["csrf_token"] = getattr(client, "csrf_token", "") or fields.get("csrf_token", "")
    fields["fields[summary][ru]"] = payload.title.strip()
    fields["fields[desc][ru]"] = payload.description.strip()
    fields["price"] = str(payload.price)
    fields["amount"] = str(payload.amount)
    if payload.active:
        fields["active"] = "on"
    else:
        fields.pop("active", None)
    headers = {"accept": "*/*", "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
               "x-requested-with": "XMLHttpRequest"}
    saved = await fp_call(conn, lambda: client.post("lots/offerSave", data=fields, headers=headers,
                                                    raise_not_200=True),
                          "Не удалось сохранить оффер", write=True)
    try:
        result = saved.json()
    except Exception:
        raise HTTPException(status_code=502, detail="FunPay вернул неожиданный ответ при сохранении оффера.")
    if isinstance(result, dict) and (result.get("error") or result.get("errors")):
        errors = result.get("errors") or result.get("error")
        raise HTTPException(status_code=422, detail=f"FunPay не сохранил оффер: {str(errors)[:700]}")
    return {"ok": True, "subcategory_id": payload.subcategory_id}


@app.get("/api/funpay/lots/{lot_id}/fields")
async def lot_fields(lot_id: int, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    conn = await conn_for(session.owner)
    lot = await fp_call(conn, lambda: conn.account.get_lot_fields(lot_id), "Не удалось открыть редактор оффера")
    fields = dict(getattr(lot, "fields", {}) or {})
    return {
        "lot_id": lot_id,
        "title": fields.get("fields[summary][ru]", ""),
        "description": fields.get("fields[desc][ru]", ""),
        "price": fields.get("price", ""),
        "amount": fields.get("amount", "1"),
        "active": "active" in fields,
    }


@app.put("/api/funpay/lots/{lot_id}")
async def save_lot(lot_id: int, payload: LotEditBody, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    conn = await conn_for(session.owner)
    lot = await fp_call(conn, lambda: conn.account.get_lot_fields(lot_id), "Не удалось открыть редактор оффера")
    fields = dict(getattr(lot, "fields", {}) or {})
    fields["fields[summary][ru]"] = payload.title.strip()
    fields["fields[desc][ru]"] = payload.description.strip()
    fields["price"] = str(payload.price)
    fields["amount"] = str(payload.amount)
    if payload.active:
        fields["active"] = "on"
    else:
        fields.pop("active", None)
    result = await fp_call(conn, lambda: conn.account.save_lot(lot_id, fields), "Не удалось сохранить оффер", write=True)
    saved = getattr(result, "saved", None)
    if saved is None and isinstance(result, dict):
        saved = result.get("saved", True)
    return {"ok": bool(True if saved is None else saved), "lot_id": lot_id}


@app.delete("/api/funpay/lots/{lot_id}")
async def delete_lot(lot_id: int, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    conn = await conn_for(session.owner)
    result = await fp_call(conn, lambda: conn.account.delete_lot(lot_id), "Не удалось удалить оффер", write=True)
    saved = getattr(result, "saved", None)
    return {"ok": bool(True if saved is None else saved), "lot_id": lot_id}


@app.post("/api/funpay/lots/raise")
async def raise_lots(payload: RaiseBody, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    conn = await conn_for(session.owner)
    ids = [int(i) for i in payload.ids]
    result = await fp_call(conn, lambda: conn.account.raise_lots(ids),
                           "Не удалось поднять офферы. FunPay может ограничивать частоту поднятия", write=True)
    return {"ok": True, "result": clean_model(result)}


# ---------------------------------------------------------------- chats
@app.get("/api/funpay/chats")
async def chats(session: SessionInfo = Depends(get_session)) -> list[dict[str, Any]]:
    conn = await conn_for(session.owner)
    values = await fp_call(conn, lambda: conn.account.get_chats(), "Не удалось загрузить чаты FunPay")
    return [normalize_chat(d) for d in _dicts(values)]


@app.get("/api/funpay/chats/{chat_id}")
async def chat_messages(chat_id: str, session: SessionInfo = Depends(get_session)) -> list[dict[str, Any]]:
    conn = await conn_for(session.owner)
    remote = await chat_history(conn, chat_id, label="Не удалось открыть историю чата")
    remote_ids = {m["id"] for m in remote if m["id"]}
    now = now_ts()
    with db() as dbconn:
        saved = dbconn.execute(
            """SELECT message_id,text,author,timestamp,created_at,image_link FROM sent_chat_messages
               WHERE chat_id=? ORDER BY created_at ASC LIMIT 500""",
            (str(chat_id),),
        ).fetchall()
    merged = list(remote)
    for row in saved:
        mid = str(row["message_id"])
        if mid in remote_ids:
            continue
        local = mid.startswith("local-")
        age = now - int(row["created_at"])
        status = "sent" if not local else ("pending" if age < 180 else "unconfirmed")
        merged.append({"id": mid, "text": row["text"], "author": row["author"] or "Вы", "author_id": None,
                       "is_incoming": False, "image_link": row["image_link"], "timestamp": row["timestamp"],
                       "status": status})
    merged.sort(key=lambda m: (0, int(m["id"])) if m["id"].isdigit() else (1, str(m["timestamp"])))
    return merged


async def _store_sent(conn: FPConn, chat_id: str, text: str, result: dict[str, Any]) -> dict[str, Any]:
    saved = save_sent_chat_message(chat_id, result.get("message_id"), text, conn.username or "Вы",
                                   result.get("image_link"))
    if result.get("verified"):
        saved["status"] = "sent"
    return saved


@app.post("/api/funpay/chats/{chat_id}/send")
async def send_chat_message(chat_id: str, payload: MessageBody, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    text = payload.text.strip()
    if not text:
        raise HTTPException(status_code=422, detail="Введите текст сообщения.")
    conn = await conn_for(session.owner)
    try:
        known: set[str] | None = {m["id"] for m in await chat_history(conn, chat_id, label=None)}
    except Exception:
        known = None  # history unavailable: still send, but skip verification
    result = await send_runner(conn, chat_id, text, None, known)
    saved = await _store_sent(conn, chat_id, text, result)
    return {"ok": True, "verified": bool(result["verified"]), "message": saved}


async def _upload_chat_image(conn: FPConn, filename: str, image_bytes: bytes, mime_type: str) -> int:
    client = conn.client

    async def upload() -> Any:
        await client.ensure_initialized()
        await client._throttle()
        return await client._client.post(
            "file/addChatImage",
            data={"file_id": "0"},
            files={"file": (filename, image_bytes, mime_type)},
            headers={"accept": "*/*", "x-requested-with": "XMLHttpRequest"},
        )

    response = await fp_call(conn, upload, "Не удалось загрузить фотографию в FunPay", write=True)
    if response.status_code != 200:
        raise HTTPException(status_code=502, detail=f"FunPay не принял фотографию (HTTP {response.status_code}).")
    try:
        upload_data = response.json()
    except Exception:
        raise HTTPException(status_code=502, detail="FunPay вернул некорректный ответ при загрузке фотографии.")
    image_id = upload_data.get("fileId") if isinstance(upload_data, dict) else None
    if image_id is None:
        detail = str(upload_data.get("msg") or "сервер не вернул fileId") if isinstance(upload_data, dict) else "сервер не вернул fileId"
        raise HTTPException(status_code=502, detail=f"Не удалось загрузить фотографию в FunPay: {detail[:180]}")
    return int(image_id)


@app.post("/api/funpay/chats/{chat_id}/send-image")
async def send_chat_image(chat_id: str, payload: ChatPhotoBody, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    mime_type = (payload.mime_type or "").split(";", 1)[0].strip().lower()
    if mime_type not in {"image/jpeg", "image/png", "image/webp", "image/gif"}:
        raise HTTPException(status_code=415, detail="Поддерживаются изображения JPG, PNG, WEBP и GIF.")
    try:
        image_bytes = base64.b64decode(payload.data, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Файл изображения повреждён или имеет неверный формат.") from exc
    if not image_bytes:
        raise HTTPException(status_code=422, detail="Выберите непустое изображение.")
    if len(image_bytes) > 8 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Изображение слишком большое. Максимальный размер — 8 МБ.")
    filename = Path(payload.filename.replace("\\", "/")).name[:120] or "photo"
    conn = await conn_for(session.owner)
    try:
        known: set[str] | None = {m["id"] for m in await chat_history(conn, chat_id, label=None)}
    except Exception:
        known = None
    image_id = await _upload_chat_image(conn, filename, image_bytes, mime_type)
    result = await send_runner(conn, chat_id, "", image_id, known, image_mode=True)
    saved = await _store_sent(conn, chat_id, "", result)
    return {"ok": True, "verified": bool(result["verified"]), "message": saved}


# ---------------------------------------------------------------- orders
@app.get("/api/funpay/orders")
async def orders(limit: int = 50, session: SessionInfo = Depends(get_session)) -> list[dict[str, Any]]:
    limit = min(max(limit, 1), 100)
    conn = await conn_for(session.owner)
    values = await fp_call(
        conn,
        lambda: conn.account.get_sales(include_paid=True, include_closed=False, include_refunded=False, limit=limit),
        "Не удалось загрузить заказы FunPay",
    )
    return [normalize_order(d) for d in _dicts(values)]


# ---------------------------------------------------------------- admin (Telegram admin or dashboard owner)
@app.get("/api/admin/licenses")
async def admin_licenses(session: SessionInfo = Depends(get_admin_session)) -> dict[str, Any]:
    now = now_ts()
    init_db()
    with db() as conn:
        rows = conn.execute(
            """SELECT license_key,telegram_user_id,plan_id,created_at,expires_at,telegram_payment_charge_id,revoked
               FROM license_keys ORDER BY created_at DESC LIMIT 200"""
        ).fetchall()
    items = [{"key": r["license_key"], "telegram_user_id": r["telegram_user_id"] or None, "plan_id": r["plan_id"],
              "created_at": r["created_at"], "expires_at": r["expires_at"], "revoked": bool(r["revoked"]),
              "active": bool(not r["revoked"] and (r["expires_at"] is None or int(r["expires_at"]) > now)),
              "payment_id": r["telegram_payment_charge_id"]} for r in rows]
    return {"total": len(items), "items": items}


@app.post("/api/admin/licenses")
async def admin_create_license(payload: AdminLicenseCreateBody, session: SessionInfo = Depends(get_admin_session)) -> dict[str, Any]:
    if payload.duration not in ADMIN_LICENSE_DURATIONS:
        raise HTTPException(status_code=422, detail="Выберите срок из списка.")
    return create_admin_license(payload.duration, payload.telegram_user_id)


@app.post("/api/admin/licenses/revoke")
async def admin_revoke_license(payload: AdminRevokeBody, session: SessionInfo = Depends(get_admin_session)) -> dict[str, bool]:
    init_db()
    with db() as conn:
        cursor = conn.execute("UPDATE license_keys SET revoked = 1 WHERE license_key = ? COLLATE NOCASE", (payload.key.strip(),))
        changed = cursor.rowcount
    if not changed:
        raise HTTPException(status_code=404, detail="Ключ не найден.")
    return {"ok": True}


# ---------------------------------------------------------------- notifications out of the web app
TG_APP: Any = None
TG_BOT: Any = None


async def _tg_text(chat_id: int, text: str) -> None:
    bot = TG_BOT
    if bot is None or not chat_id:
        return
    try:
        await bot.send_message(chat_id=chat_id, text=text[:3800])
    except Exception as exc:
        log.warning("Telegram message could not be delivered: %s", type(exc).__name__)


def _emit_chat(conn: FPConn, chat: dict[str, Any], author: str, body: str) -> None:
    push_notification(conn.owner, "chat", chat["name"], f"{author}: {body}", chat_id=chat["id"])
    if conn.owner == "admin":
        asyncio.create_task(_tg_text(ADMIN_TELEGRAM_ID, f"💬 Новое сообщение в FunPay\n"
                                                        f"Чат: {chat['name']}\n{author}: {body}\n"
                                                        f"Чат ID: {chat['id']}"))


async def _notify_chat(conn: FPConn, chat: dict[str, Any], previous_id: str) -> None:
    incoming: list[dict[str, Any]] = []
    try:
        for message in await chat_history(conn, chat["id"], label=None):
            if not message["is_incoming"]:
                continue
            if previous_id.isdigit() and message["id"].isdigit() and int(message["id"]) <= int(previous_id):
                continue
            incoming.append(message)
    except Exception:
        incoming = []
    if incoming:
        for message in incoming[-2:]:
            body = message["text"] or ("[изображение]" if message["image_link"] else "Сообщение без текста")
            _emit_chat(conn, chat, message["author"] or chat["name"], str(body)[:500])
    elif chat["last_message_text"] and chat["last_message_author"].casefold() != conn.username.casefold():
        _emit_chat(conn, chat, chat["last_message_author"] or chat["name"], str(chat["last_message_text"])[:500])


async def _poll_sales(conn: FPConn) -> None:
    values = await fp_call(
        conn,
        lambda: conn.account.get_sales(include_paid=True, include_closed=False, include_refunded=False, limit=20),
        None, timeout=12, retries=0,
    )
    sales = [normalize_order(d) for d in _dicts(values)]
    if not conn.sale_baseline:
        conn.sale_seen = {str(s["id"]) for s in sales}
        conn.sale_baseline = True
        return
    fresh = [s for s in sales if str(s["id"]) not in conn.sale_seen]
    for sale in fresh:
        conn.sale_seen.add(str(sale["id"]))
    if len(conn.sale_seen) > 800:
        conn.sale_seen = set(list(conn.sale_seen)[-400:])
    for sale in fresh[:5]:
        text = f"{sale['title']} · {sale['price']} {sale['currency']} · покупатель {sale['buyer_username'] or '—'}"
        push_notification(conn.owner, "order", f"Новый заказ #{sale['id']}", text)
        if conn.owner == "admin":
            asyncio.create_task(_tg_text(ADMIN_TELEGRAM_ID, f"🛒 Новый заказ #{sale['id']}\n{text}"))


async def poll_connection(conn: FPConn) -> None:
    conn.tick += 1
    values = await fp_call(conn, lambda: conn.account.get_chats(), None, timeout=12, retries=0)
    chats = [normalize_chat(d) for d in _dicts(values)]
    previous = dict(conn.chat_seen)
    changed: list[tuple[dict[str, Any], str]] = []
    for chat in chats:
        current = (chat["last_message_id"], chat["last_message_text"])
        old = previous.get(chat["id"])
        if conn.chat_baseline and chat["last_message_text"]:
            if old is None and chat["last_message_author"].casefold() != conn.username.casefold():
                changed.append((chat, ""))
            elif old is not None and old != current:
                changed.append((chat, old[0]))
        conn.chat_seen[chat["id"]] = current
    conn.chat_baseline = True
    for chat, previous_id in changed[:3]:
        await _notify_chat(conn, chat, previous_id)
    if conn.tick % 3 == 1:
        await _poll_sales(conn)


async def poll_loop() -> None:
    """Background watcher: chat messages and orders for every recently used FunPay connection."""
    while True:
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
        now = time.time()
        for owner, conn in list(FP_CONNS.items()):
            if conn.closed:
                continue
            if now - conn.last_used > IDLE_CONNECTION_SECONDS:
                log.info("Closing idle FunPay connection")
                await close_owner(owner)
                continue
            try:
                await poll_connection(conn)
            except FunPayError:
                if time.time() - conn.error_notified_at > 600:
                    conn.error_notified_at = time.time()
                    push_notification(owner, "error", "FunPay временно не отвечает",
                                      "Панель повторит проверку автоматически.")
            except Exception as exc:
                log.warning("Poll step skipped: %s", type(exc).__name__)


async def expiry_loop() -> None:
    """Telegram message when a key expires, once per key."""
    while True:
        await asyncio.sleep(60)
        try:
            init_db()
            with db() as conn:
                rows = conn.execute(
                    """SELECT license_key, telegram_user_id FROM license_keys
                       WHERE expiry_notified = 0 AND revoked = 0 AND expires_at IS NOT NULL
                       AND expires_at <= ? AND telegram_user_id > 0 LIMIT 20""",
                    (now_ts(),),
                ).fetchall()
                for row in rows:
                    conn.execute("UPDATE license_keys SET expiry_notified = 1 WHERE license_key = ?",
                                 (row["license_key"],))
            for row in rows:
                await _tg_text(int(row["telegram_user_id"]),
                               f"⏰ Срок вашего ключа (…{row['license_key'][-6:]}) истёк.\n"
                               "Получите новый ключ через /start.")
        except Exception as exc:
            log.warning("Expiry check skipped: %s", type(exc).__name__)


def _ping(url: str) -> None:
    with urllib.request.urlopen(url, timeout=20) as response:
        response.read(200)


async def keepalive_loop() -> None:
    """Self-ping so a free Render instance does not sleep between visits."""
    if not RENDER_EXTERNAL_URL:
        return
    url = f"{RENDER_EXTERNAL_URL}/api/health"
    while True:
        await asyncio.sleep(KEEPALIVE_SECONDS)
        try:
            await asyncio.to_thread(_ping, url)
        except Exception:
            pass


# ---------------------------------------------------------------- Telegram bot
async def _start_telegram(app_: FastAPI) -> Any:
    global TG_APP, TG_BOT
    from telegram import (InlineKeyboardButton, InlineKeyboardMarkup, LabeledPrice, MenuButtonWebApp,
                          Update, WebAppInfo)
    from telegram.ext import (Application, CallbackQueryHandler, CommandHandler, MessageHandler,
                              PreCheckoutQueryHandler, filters)

    tg_app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    async def start_command(update: Any, context: Any) -> None:
        caption = (
            "<b>NEZZX AI TELEGRAM CONV</b>\n"
            "Telegram Inbox, управление переписками и AI-помощник в одной панели.\n\n"
            "Начните с FREE PLAN (30 минут) или оформите ключ за Telegram Stars."
        )
        target = public_url()
        keyboard = [
            [InlineKeyboardButton("Получить секретный ключ FREE PLAN", callback_data="license:free")],
            [InlineKeyboardButton("Купить ключ по лучшей цене!", callback_data="license:buy")],
        ]
        if target.startswith("https://"):
            keyboard.append([InlineKeyboardButton("Открыть панель", web_app=WebAppInfo(url=target))])
        else:
            keyboard.append([InlineKeyboardButton("Открыть панель", url=target)])
        markup = InlineKeyboardMarkup(keyboard)
        image_path = BASE_DIR / "a_sleek_dark_futuristic_cyber_neon_ui_welcome_s.png"
        message = update.effective_message
        if image_path.is_file():
            with image_path.open("rb") as photo:
                await message.reply_photo(photo=photo, caption=caption, parse_mode="HTML", reply_markup=markup)
        else:
            await message.reply_text(caption, parse_mode="HTML", reply_markup=markup)

    async def license_callback(update: Any, context: Any) -> None:
        query = update.callback_query
        await query.answer()
        user = update.effective_user
        if not user:
            return
        if query.data == "license:free":
            key, created, activated = claim_free_license(user.id)
            if created:
                state = ("✅ <b>Ваш FREE PLAN ключ создан</b>",
                         "Срок: <b>30 минут</b>. Отсчёт начнётся при первом входе в панель, "
                         "после чего доступ закроется автоматически.")
            elif activated:
                state = ("ℹ️ <b>Ваш FREE PLAN ключ</b>",
                         "Бесплатные 30 минут уже использованы. Оформите ключ за Stars, чтобы продолжить.")
            else:
                state = ("ℹ️ <b>Ваш FREE PLAN ключ</b>",
                         "Ключ ещё не активирован: 30 минут начнутся при первом входе в панель.")
            text = (f"{state[0]}\n\n<code>{html.escape(key)}</code>\n\n{state[1]}\n"
                    "Бесплатный ключ выдаётся один раз на Telegram-аккаунт. Сохраните его в безопасном месте.")
            await query.message.reply_text(text, parse_mode="HTML")
            return
        if query.data == "license:buy":
            rows = [[InlineKeyboardButton(f"{p['title']} · {p['stars']} ⭐", callback_data=f"license:plan:{pid}")]
                    for pid, p in STAR_PLANS.items()]
            await query.message.reply_text("<b>Выберите срок ключа</b>\nОплата проходит внутри Telegram в Stars.",
                                           parse_mode="HTML", reply_markup=InlineKeyboardMarkup(rows))
            return
        if query.data.startswith("license:plan:"):
            plan_id = query.data.rsplit(":", 1)[-1]
            plan = STAR_PLANS.get(plan_id)
            if not plan:
                await query.message.reply_text("Этот тариф больше недоступен. Откройте /start и выберите снова.")
                return
            payload = f"license:{plan_id}:{user.id}:{secrets.token_urlsafe(8)}"
            await context.bot.send_invoice(
                chat_id=update.effective_chat.id,
                title=f"Ключ — {plan['title']}",
                description=f"Лицензионный ключ на срок: {plan['title']}.",
                payload=payload,
                provider_token="",
                currency="XTR",
                prices=[LabeledPrice(label=f"Ключ на {plan['title']}", amount=int(plan["stars"]))],
            )

    async def pre_checkout(update: Any, context: Any) -> None:
        query = update.pre_checkout_query
        try:
            payload = query.invoice_payload.split(":")
            valid = len(payload) == 4 and payload[0] == "license" and payload[1] in STAR_PLANS and int(payload[2]) == query.from_user.id
            if valid:
                await query.answer(ok=True)
            else:
                await query.answer(ok=False, error_message="Платёж не прошёл проверку. Создайте новый счёт через /start.")
        except Exception:
            await query.answer(ok=False, error_message="Не удалось проверить оплату. Попробуйте ещё раз.")

    async def successful_payment(update: Any, context: Any) -> None:
        payment = update.effective_message.successful_payment
        try:
            payload = payment.invoice_payload.split(":")
            if len(payload) != 4 or payload[0] != "license":
                raise ValueError("invalid payment payload")
            plan_id, buyer_id = payload[1], int(payload[2])
            user = update.effective_user
            if user is None or user.id != buyer_id or plan_id not in STAR_PLANS:
                raise ValueError("payment user mismatch")
            key, expires, _created = issue_paid_license(user.id, plan_id, payment.telegram_payment_charge_id)
            plan = STAR_PLANS[plan_id]
            caption = ("✅ <b>Оплата прошла успешно!</b>\n\n"
                       f"Тариф: <b>{plan['title']}</b> · <b>{plan['stars']} ⭐</b>\n"
                       f"Ваш ключ: <code>{html.escape(key)}</code>\n"
                       f"Действует: <b>{format_expiry(expires)}</b>\n\n"
                       "Скопируйте и сохраните ключ.")
            await update.effective_message.reply_text(caption, parse_mode="HTML")
        except Exception as exc:
            log.exception("Could not issue purchased key: %s", type(exc).__name__)
            await update.effective_message.reply_text(
                "Оплата получена, но автоматическая выдача ключа не завершилась. Напишите администратору и укажите ID платежа: "
                + html.escape(getattr(payment, "telegram_payment_charge_id", "unknown")),
                parse_mode="HTML",
            )

    tg_app.add_handler(CommandHandler("start", start_command))
    tg_app.add_handler(CallbackQueryHandler(license_callback, pattern=r"^license:"))
    tg_app.add_handler(PreCheckoutQueryHandler(pre_checkout))
    tg_app.add_handler(MessageHandler(filters.SUCCESSFUL_PAYMENT, successful_payment))
    await tg_app.initialize()
    await tg_app.start()
    TG_APP, TG_BOT = tg_app, tg_app.bot
    app_.state.telegram_app = tg_app
    if RENDER_EXTERNAL_URL.startswith("https://"):
        await tg_app.bot.set_webhook(url=f"{RENDER_EXTERNAL_URL}/telegram/webhook", secret_token=WEBHOOK_SECRET,
                                     allowed_updates=Update.ALL_TYPES, drop_pending_updates=False)
        try:
            await tg_app.bot.set_chat_menu_button(
                menu_button=MenuButtonWebApp(text="NEZZX AI", web_app=WebAppInfo(url=RENDER_EXTERNAL_URL)))
        except Exception:
            pass
        log.info("Telegram webhook configured")
    else:
        await tg_app.bot.delete_webhook(drop_pending_updates=True)
        await tg_app.updater.start_polling(allowed_updates=Update.ALL_TYPES)
        log.info("Telegram polling started")
    return tg_app


async def _bootstrap_admin_account() -> None:
    try:
        await connect_owner("admin", FUNPAY_GOLDEN_KEY_ENV, FUNPAY_USER_AGENT_DEFAULT)
        log.info("Owner FunPay account connected from FUNPAY_GOLDEN_KEY")
    except Exception as exc:
        log.warning("FUNPAY_GOLDEN_KEY auto-connect failed: %s", type(exc).__name__)


@asynccontextmanager
async def lifespan(app_: FastAPI):
    global TG_APP, TG_BOT
    init_db()
    load_catalog_cache()
    tasks = [asyncio.create_task(expiry_loop(), name="license-expiry")]
    if TELEGRAM_BOT_TOKEN:
        try:
            await _start_telegram(app_)
        except Exception as exc:
            log.exception("Telegram bot initialization failed: %s", type(exc).__name__)
            TG_APP = TG_BOT = None
    else:
        log.warning("TELEGRAM_BOT_TOKEN is not set; the web panel still starts.")
    if not TELEGRAM_API_ID or not TELEGRAM_API_HASH:
        log.warning("TELEGRAM_API_ID / TELEGRAM_API_HASH not set; personal Telegram login is disabled.")
    if not ai_configured():
        log.warning("No AI key set (TOKENHARBOR_API_KEY); AI replies and drafts are disabled.")
    if not DASHBOARD_PASSWORD:
        log.warning("DASHBOARD_PASSWORD is not set; sign-in works with license keys only.")
    if not os.getenv("ADMIN_ACCESS_KEY", "").strip():
        log.warning("ADMIN_ACCESS_KEY is not set: the built-in admin key is active. Set your own key in Render.")
    try:
        yield
    finally:
        for task in tasks:
            task.cancel()
        for task in tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        if TG_APP is not None:
            try:
                if TG_APP.updater and TG_APP.updater.running:
                    await TG_APP.updater.stop()
                await TG_APP.stop()
                await TG_APP.shutdown()
            except Exception as exc:
                log.warning("Telegram shutdown issue: %s", type(exc).__name__)
            TG_APP = TG_BOT = None
        for owner in list(FP_CONNS):
            await close_owner(owner)
        for owner, client in list(TG_CLIENTS.items()):
            try:
                await client.disconnect()
            except Exception:
                pass
        TG_CLIENTS.clear()
        for owner, flow in list(TG_LOGIN_FLOWS.items()):
            try:
                await flow["client"].disconnect()
            except Exception:
                pass
        TG_LOGIN_FLOWS.clear()


app.router.lifespan_context = lifespan


@app.post("/telegram/webhook")
async def telegram_webhook(request: Request) -> dict[str, bool]:
    if not TELEGRAM_BOT_TOKEN:
        raise HTTPException(status_code=404, detail="Telegram bot is disabled")
    if WEBHOOK_SECRET and request.headers.get("X-Telegram-Bot-Api-Secret-Token") != WEBHOOK_SECRET:
        raise HTTPException(status_code=403, detail="Invalid webhook secret")
    tg_app = getattr(app.state, "telegram_app", None)
    if tg_app is None:
        raise HTTPException(status_code=503, detail="Telegram bot is not ready")
    from telegram import Update

    update = Update.de_json(await request.json(), tg_app.bot)
    await tg_app.process_update(update)
    return {"ok": True}


CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://telegram.org https://open.spotify.com https://w.soundcloud.com; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; "
    "img-src 'self' data: blob: https:; connect-src 'self'; frame-src https://open.spotify.com https://w.soundcloud.com; object-src 'none'; base-uri 'none'; "
    "form-action 'self'; frame-ancestors 'none'"
)


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse(HTML_PAGE, headers={
        "Cache-Control": "no-store",
        "Content-Security-Policy": CONTENT_SECURITY_POLICY,
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    })


# The interface is embedded so the project stays a single deployable file.
HTML_PAGE = r'''<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="dark">
<meta name="theme-color" content="#07100a">
<meta name="robots" content="noindex,nofollow">
<title>NEZZX AI Telegram Conv</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Onest:wght@400;500;600;700&family=Unbounded:wght@600;700;800&display=swap" rel="stylesheet">
<script src="https://telegram.org/js/telegram-web-app.js"></script>
<style>
/* ---------- tokens: one dark glass world, apricot accent ---------- */
:root{
  color-scheme:dark;
  --bg:#07100a;
  --ink:#f6f3ee;
  --muted:rgba(246,243,238,.68);
  --faint:rgba(246,243,238,.44);
  --accent:#ffb36b;
  --accent-hi:#ffc98f;
  --accent-ink:#21120a;
  --ai:#a9d2ff;
  --ok:#8fe9bd;
  --bad:#ff9dab;
  --glass:rgba(12,16,14,.56);
  --glass-strong:rgba(12,16,14,.82);
  --glass-soft:rgba(255,255,255,.06);
  --line:rgba(255,255,255,.13);
  --line-soft:rgba(255,255,255,.07);
  --field:rgba(4,8,6,.5);
  --r-xl:28px;
  --r-lg:20px;
  --r-md:15px;
  --f-display:"Unbounded",ui-rounded,"Arial Rounded MT Bold",system-ui,sans-serif;
  --f-body:"Onest",system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  --ease:cubic-bezier(.22,.8,.24,1);
  --spring:cubic-bezier(.34,1.5,.64,1);
}

/* ---------- reset ---------- */
*,*::before,*::after{box-sizing:border-box}
[hidden]{display:none!important}
html,body{height:100%;margin:0}
body{
  background:var(--bg);color:var(--ink);overflow:hidden;
  font:400 14px/1.5 var(--f-body);
  -webkit-font-smoothing:antialiased;-webkit-tap-highlight-color:transparent;
  user-select:none;-webkit-user-select:none;
}
input,textarea{user-select:text;-webkit-user-select:text}
button,input,textarea,select{font:inherit;color:inherit}
button{cursor:pointer;border:0;background:none;padding:0}
button:disabled{opacity:.45;cursor:not-allowed}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.muted{color:var(--muted)}
.hidden{display:none!important}
svg.i{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;flex:none;display:block}

/* ---------- background photo ---------- */
#bg{
  position:fixed;inset:0;z-index:0;
  background:var(--bg) url("data:image/jpeg;base64,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") 50% 28%/cover no-repeat;
  animation:bgIn 1.6s var(--ease) both;
}
#bg::after{
  content:"";position:absolute;inset:0;
  background:linear-gradient(180deg,rgba(4,9,6,.42) 0%,rgba(4,9,6,.66) 55%,rgba(4,9,6,.9) 100%);
}
@keyframes bgIn{from{transform:scale(1.12);opacity:.25}to{transform:none;opacity:1}}

/* ---------- app frame (edge to edge, safe areas respected) ---------- */
#app{
  position:fixed;inset:0;z-index:1;
  padding-top:calc(env(safe-area-inset-top,0px) + var(--tg-content-safe-area-inset-top,0px));
  padding-left:env(safe-area-inset-left,0px);
  padding-right:env(safe-area-inset-right,0px);
}
.shell{position:absolute;inset:0;display:flex;min-width:0}
.stage{position:relative;flex:1;min-width:0;min-height:0;display:flex;flex-direction:column}

/* ---------- top bar ---------- */
.topbar{
  display:flex;align-items:center;gap:10px;
  margin:10px 12px 0;padding:8px 10px 8px 8px;
  border-radius:var(--r-lg);min-height:62px;flex:none;
}
.title-wrap{flex:1;min-width:0}
.title-wrap h1{
  margin:0;font:700 17px/1.2 var(--f-display);letter-spacing:-.01em;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
}
.title-wrap p{margin:3px 0 0;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.top-actions{display:flex;gap:4px;flex:none}
#backBtn{display:grid}
@media (min-width:900px){#backBtn{display:none!important}}

/* ---------- views ---------- */
.views{position:relative;flex:1;min-height:0;margin:10px 12px 0}
.view{position:absolute;inset:0;display:none;flex-direction:column;min-height:0}
.view.active{display:flex;animation:fadeIn .35s var(--ease) both}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}

.page{
  flex:1;min-height:0;overflow:auto;overscroll-behavior:contain;
  display:flex;flex-direction:column;gap:12px;
  padding:2px 2px calc(104px + env(safe-area-inset-bottom,0px));
}
.view.active .page > *{animation:rise .55s var(--ease) both;animation-delay:calc(var(--i,0) * 60ms)}

/* ---------- chats: list + conversation ---------- */
.chats-layout{position:relative;flex:1;min-height:0;display:flex;overflow:hidden;border-radius:var(--r-xl)}
.list-pane{
  flex:1;min-width:0;min-height:0;display:flex;flex-direction:column;
  border-radius:var(--r-xl);
  transition:transform .5s var(--ease),opacity .4s var(--ease);
}
.chat-pane{
  position:absolute;inset:0;z-index:2;display:flex;flex-direction:column;min-width:0;min-height:0;
  border-radius:var(--r-xl);
  transform:translateX(104%);
  transition:transform .55s var(--ease);
}
.shell[data-mode="chat"] .chat-pane{transform:none}
.shell[data-mode="chat"] .list-pane{transform:translateX(-14%);opacity:0;pointer-events:none}

/* ---------- bottom tab bar (phones) ---------- */
.sidebar{display:none}
.tabbar{
  position:absolute;left:14px;right:14px;z-index:6;
  bottom:calc(env(safe-area-inset-bottom,0px) + 12px);
  height:66px;padding:6px;border-radius:26px;
  display:grid;grid-auto-flow:column;grid-auto-columns:1fr;align-items:stretch;
  transition:transform .5s var(--ease),opacity .35s var(--ease);
}
.shell[data-mode="chat"] .tabbar{transform:translateY(140%);opacity:0;pointer-events:none}
.indicator{
  position:absolute;top:6px;bottom:6px;left:0;width:0;border-radius:20px;
  background:rgba(255,255,255,.1);
  box-shadow:inset 0 0 0 1px rgba(255,255,255,.14),0 8px 24px rgba(255,179,107,.14);
  transition:transform .55s var(--spring),width .45s var(--ease);
}
.tab{
  position:relative;z-index:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;
  color:var(--faint);font-size:11px;font-weight:600;letter-spacing:.01em;
  transition:color .3s var(--ease),transform .25s var(--ease);
}
.tab:active{transform:scale(.92)}
.tab svg.i{transition:transform .45s var(--spring)}
.tab.active{color:var(--ink)}
.tab.active svg.i{color:var(--accent);transform:translateY(-1px) scale(1.06)}

/* ---------- desktop: left rail, no tab bar ---------- */
@media (min-width:900px){
  .sidebar{
    display:flex;flex-direction:column;align-items:center;gap:8px;
    width:96px;flex:none;margin:12px 0 12px 12px;padding:14px 10px;border-radius:var(--r-xl);
  }
  .tabbar{display:none}
  .views{margin:10px 12px 12px 12px}
  .page{padding-bottom:24px}
  .list-pane{flex:0 0 340px}
  .chat-pane{position:relative;inset:auto;flex:1;transform:none}
  .shell[data-mode="chat"] .list-pane{transform:none;opacity:1;pointer-events:auto}
  .chat-list{padding-bottom:14px!important}
  .toast{bottom:28px!important}
}
.rail-brand{margin-bottom:10px}
.rail{display:flex;flex-direction:column;gap:6px;width:100%;flex:1}
.rail-btn{
  width:100%;display:flex;flex-direction:column;align-items:center;gap:5px;padding:12px 4px;border-radius:17px;
  color:var(--faint);font-size:11px;font-weight:600;
  transition:background .3s var(--ease),color .3s var(--ease),transform .2s var(--ease);
}
.rail-btn:hover{background:var(--glass-soft);color:var(--ink)}
.rail-btn:active{transform:scale(.94)}
.rail-btn.active{color:var(--accent);background:rgba(255,179,107,.14)}

/* ---------- glass surfaces ---------- */
.glass{
  background:var(--glass);
  -webkit-backdrop-filter:blur(20px) saturate(1.4);backdrop-filter:blur(20px) saturate(1.4);
  border:1px solid var(--line);
  box-shadow:inset 0 1px 0 rgba(255,255,255,.09),0 22px 60px rgba(0,0,0,.34);
}
@supports not ((backdrop-filter:blur(1px)) or (-webkit-backdrop-filter:blur(1px))){
  .glass{background:var(--glass-strong)}
}
.card{
  padding:18px;border-radius:var(--r-lg);min-width:0;
  background:var(--glass);
  -webkit-backdrop-filter:blur(22px) saturate(1.4);backdrop-filter:blur(22px) saturate(1.4);
  border:1px solid var(--line);
  box-shadow:inset 0 1px 0 rgba(255,255,255,.07),0 16px 44px rgba(0,0,0,.3);
}
.card h2{margin:0 0 12px;font:600 15px/1.3 var(--f-body);letter-spacing:-.005em}
.card .lead{margin:0 0 12px;font-size:13px;color:var(--muted);line-height:1.6}

/* the conversation pane scrolls over the photo: a solid, slightly darker glass is much cheaper than blur */
.chat-pane.glass{background:rgba(10,14,12,.88);-webkit-backdrop-filter:none;backdrop-filter:none}

/* ---------- headings ---------- */
.h-display{margin:0;font:700 22px/1.15 var(--f-display);letter-spacing:-.02em}
.eyebrow{margin:0 0 6px;font-size:12.5px;color:var(--muted)}

/* ---------- buttons ---------- */
.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:8px;
  padding:11px 16px;border-radius:15px;font-weight:600;white-space:nowrap;
  background:rgba(255,255,255,.09);border:1px solid var(--line);
  transition:transform .2s var(--ease),background .25s,border-color .25s,box-shadow .25s;
}
.btn svg.i{width:18px;height:18px}
.btn:hover{background:rgba(255,255,255,.16)}
.btn:active{transform:scale(.96)}
.btn.primary{
  background:linear-gradient(160deg,var(--accent-hi),var(--accent));color:var(--accent-ink);
  border-color:transparent;box-shadow:0 12px 30px rgba(255,179,107,.26);
}
.btn.primary:hover{background:linear-gradient(160deg,#ffd9ad,#ffbd80)}
.btn.ghost{background:transparent}
.btn.danger{color:var(--bad);border-color:rgba(255,157,171,.36);background:rgba(255,157,171,.08)}
.btn.block{width:100%}
.btn.sm{padding:8px 12px;border-radius:12px;font-size:13px}
.btn-row{display:flex;flex-wrap:wrap;gap:8px}
.icon-btn{
  width:42px;height:42px;border-radius:14px;display:grid;place-items:center;flex:none;
  color:var(--muted);transition:background .25s,color .25s,transform .2s var(--ease);
}
.icon-btn:hover{background:rgba(255,255,255,.1);color:var(--ink)}
.icon-btn:active{transform:scale(.9)}
.link{color:var(--accent);text-decoration:none;font-weight:600}

/* ---------- inputs ---------- */
.field{display:flex;flex-direction:column;gap:7px;min-width:0}
.field > span{font-size:12.5px;color:var(--muted);font-weight:600}
.field > span em{font-style:normal;font-weight:500;color:var(--faint)}
.input,.select,textarea{
  width:100%;min-width:0;background:var(--field);border:1px solid var(--line);
  border-radius:15px;padding:12px 14px;outline:none;
  transition:border-color .25s,box-shadow .25s,background .25s;
}
.input:focus,.select:focus,textarea:focus{
  border-color:rgba(255,179,107,.62);box-shadow:0 0 0 4px rgba(255,179,107,.14);
}
.input::placeholder,textarea::placeholder{color:var(--faint)}
.select{width:auto;padding:9px 12px;border-radius:13px;font-size:13px;cursor:pointer}
.select option{background:#101512;color:var(--ink)}
textarea{resize:none}
.search{position:relative;display:block}
.search svg.i{position:absolute;left:13px;top:50%;transform:translateY(-50%);color:var(--faint);width:18px;height:18px}
.search .input{padding-left:40px;border-radius:16px}
.error{color:var(--bad);font-size:13px}
.error:empty{display:none}

/* ---------- switch ---------- */
.switch{position:relative;width:46px;height:27px;border-radius:999px;background:rgba(255,255,255,.2);flex:none;transition:background .35s var(--ease)}
.switch span{
  position:absolute;top:3px;left:3px;width:21px;height:21px;border-radius:50%;background:#fff;
  box-shadow:0 2px 7px rgba(0,0,0,.35);transition:transform .5s var(--spring);
}
.switch.on{background:var(--accent)}
.switch.on span{transform:translateX(19px)}

/* ---------- avatars ---------- */
.avatar{
  --h:30;
  width:44px;height:44px;border-radius:50%;flex:none;display:grid;place-items:center;
  font:700 13px/1 var(--f-display);color:#16100a;
  background:linear-gradient(145deg,hsl(var(--h) 88% 74%),hsl(calc(var(--h) + 38) 78% 58%));
  box-shadow:inset 0 0 0 1px rgba(255,255,255,.22);
}
.avatar.sm{width:38px;height:38px;font-size:12px}
.avatar.xs{width:28px;height:28px;font-size:10px}
.avatar{position:relative;overflow:hidden}
.avatar img{position:absolute;inset:0;width:100%;height:100%;max-width:100%;object-fit:cover;border-radius:inherit;opacity:0;transition:opacity .35s var(--ease)}
.avatar img.loaded{opacity:1}
.mark{
  width:42px;height:42px;border-radius:15px;display:grid;place-items:center;flex:none;
  font:800 17px/1 var(--f-display);color:#21120a;
  background:linear-gradient(145deg,#ffdcb4,#ff9f6a);
  box-shadow:0 10px 30px rgba(255,159,106,.34);
}

/* ---------- chat list ---------- */
.list-head{padding:16px 14px 10px;display:flex;flex-direction:column;gap:12px;flex:none}
.list-meta{display:flex;align-items:center;justify-content:space-between;gap:10px}
.list-meta .muted{font-size:12px}
.chat-list{flex:1;min-height:0;overflow:auto;overscroll-behavior:contain;padding:2px 8px 96px;display:flex;flex-direction:column;gap:3px}
.chat-list.list-rise .chat-row{animation:rise .5s var(--ease) both;animation-delay:calc(var(--i,0) * 38ms)}
.chat-row{
  display:flex;align-items:center;gap:12px;width:100%;text-align:left;
  padding:10px;border-radius:17px;border:1px solid transparent;
  transition:background .25s var(--ease),border-color .25s,transform .2s var(--ease);
}
.chat-row:hover{background:rgba(255,255,255,.06)}
.chat-row:active{transform:scale(.985)}
.chat-row.selected{background:rgba(255,179,107,.14);border-color:rgba(255,179,107,.3)}
.chat-main{flex:1;min-width:0;display:flex;flex-direction:column;gap:4px}
.chat-top,.chat-bottom{display:flex;align-items:center;gap:8px;min-width:0}
.chat-top .name{flex:1;min-width:0;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.chat-top time{font-size:11.5px;color:var(--faint);flex:none}
.preview{flex:1;min-width:0;font-size:12.5px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ai-badge{font-size:10px;font-weight:700;letter-spacing:.04em;padding:2px 7px;border-radius:999px;background:rgba(169,210,255,.16);color:var(--ai);flex:none}
.unread{min-width:21px;height:21px;padding:0 6px;border-radius:999px;background:var(--accent);color:var(--accent-ink);font:700 11px/1 var(--f-body);display:grid;place-items:center;flex:none}

/* ---------- conversation ---------- */
.chat-tools{
  display:flex;align-items:center;gap:10px;flex-wrap:wrap;flex:none;
  padding:12px 14px;border-bottom:1px solid var(--line-soft);
}
.chat-tools .tools-text{display:flex;flex-direction:column;min-width:0;flex:1 1 120px}
.chat-tools .tools-text b{font-size:13px;font-weight:600}
.chat-tools .tools-text span{font-size:12px;color:var(--muted)}
.messages{flex:1;min-height:0;overflow:auto;overscroll-behavior:contain;padding:14px 14px 10px;display:flex;flex-direction:column;gap:7px}
.day{align-self:center;margin:6px 0 4px;font-size:11.5px;color:var(--muted);padding:5px 12px;border-radius:999px;background:rgba(0,0,0,.3);border:1px solid var(--line-soft)}
.msg{display:flex;align-items:flex-end;gap:8px;max-width:86%}
.msg.in{align-self:flex-start}
.msg.out{align-self:flex-end;flex-direction:row-reverse}
.msg.anim{animation:rise .42s var(--ease) both;animation-delay:calc(var(--i,0) * 40ms)}
.bubble-wrap{display:flex;flex-direction:column;gap:4px;min-width:0}
.msg.out .bubble-wrap{align-items:flex-end}
.bubble{
  padding:9px 13px;border-radius:19px 19px 19px 6px;line-height:1.5;
  background:rgba(14,18,16,.7);border:1px solid var(--line-soft);
  white-space:pre-wrap;overflow-wrap:anywhere;user-select:text;-webkit-user-select:text;
}
.msg.out .bubble{background:linear-gradient(160deg,#ffc58f,#ff9f6a);color:#24130a;border-color:transparent;border-radius:19px 19px 6px 19px}

/* links in messages */
.bubble a{color:inherit;text-decoration:underline;text-underline-offset:3px;text-decoration-thickness:1px;overflow-wrap:anywhere;user-select:text;-webkit-user-select:text}

/* photos, videos and files inside a bubble */
.bubble.has-media{display:flex;flex-direction:column;gap:6px;padding:5px}
.bubble.has-media .msg-text{padding:4px 8px 3px}
.media{display:block;position:relative;max-width:min(270px,64vw);border-radius:15px;overflow:hidden;background:rgba(0,0,0,.22)}
button.media{padding:0;border:0;font:inherit;color:inherit;cursor:zoom-in}
.media img,.media video{display:block;width:100%;height:auto;max-height:360px;object-fit:contain;border-radius:15px}
.media-sticker{background:none;max-width:170px}
.media-sticker img{width:auto;max-width:100%;max-height:170px}
.media-audio{background:none;max-width:none}
.media-audio audio{display:block;width:min(250px,62vw);height:40px}
.media-note{max-width:250px;padding:12px 13px;font-size:12.5px;line-height:1.45;color:var(--muted)}
.media.broken img,.media.broken video,.media.broken audio{display:none}
.media.broken::after{content:"Медиа не открылось. Откройте его в Telegram";display:block;padding:12px 13px;font-size:12.5px;line-height:1.45;color:var(--muted)}
.file-chip{display:flex;flex-direction:column;gap:2px;max-width:250px;padding:9px 12px;border-radius:14px;background:rgba(255,255,255,.06);color:inherit;text-decoration:none;font-size:13px;font-weight:600;overflow-wrap:anywhere}
.file-chip small{font-size:11.5px;font-weight:500;color:var(--muted)}
.msg.out .file-chip{background:rgba(36,19,10,.08)}
.msg.out .file-chip small{color:rgba(36,19,10,.7)}

/* full-size photo */
.lightbox{
  position:fixed;inset:0;z-index:60;display:grid;place-items:center;cursor:zoom-out;
  padding:calc(16px + env(safe-area-inset-top,0px)) 16px calc(16px + env(safe-area-inset-bottom,0px));
  background:rgba(4,8,6,.9);
}
.lightbox img{max-width:100%;max-height:88vh;width:auto;height:auto;object-fit:contain;border-radius:14px;box-shadow:0 22px 60px rgba(0,0,0,.5)}

/* two reply variants above the composer */
.variants{
  display:flex;flex-direction:column;gap:7px;flex:none;max-height:42vh;overflow:auto;overscroll-behavior:contain;
  margin:0 10px 8px;padding:10px;border-radius:20px;border:1px solid var(--line);background:rgba(10,14,12,.94);
  animation:rise .35s var(--ease) both;
}
.variants-head{display:flex;align-items:center;gap:8px;padding:0 2px 0 6px;font-size:12px;color:var(--muted)}
.variants-head span{flex:1;min-width:0}
.variants-x{width:30px;height:30px;border-radius:50%;display:grid;place-items:center;font-size:19px;line-height:1;color:var(--muted);flex:none}
.variants-x:hover{background:rgba(255,255,255,.1);color:var(--ink)}
.variant{
  text-align:left;padding:10px 13px;border-radius:16px;border:1px solid var(--line-soft);background:rgba(255,255,255,.04);
  color:var(--ink);line-height:1.5;white-space:pre-wrap;overflow-wrap:anywhere;
  transition:background .2s var(--ease),border-color .2s var(--ease),transform .2s var(--spring);
}
.variant:hover,.variant:focus-visible{background:rgba(255,179,107,.12);border-color:rgba(255,179,107,.36)}
.variant:active{transform:scale(.985)}
.meta{font-size:11px;color:var(--faint);padding:0 4px}
.composer{position:relative;display:flex;align-items:flex-end;gap:8px;margin:0 10px calc(10px + env(safe-area-inset-bottom,0px));padding:7px 7px 7px 16px;border-radius:26px;flex:none}
.composer textarea{background:transparent;border:0;padding:9px 0;min-height:24px;max-height:140px;box-shadow:none}
.composer textarea:focus{box-shadow:none}
.send{
  width:44px;height:44px;border-radius:50%;flex:none;display:grid;place-items:center;
  background:linear-gradient(160deg,var(--accent-hi),var(--accent));color:var(--accent-ink);
  box-shadow:0 8px 22px rgba(255,179,107,.3);transition:transform .2s var(--spring);
}
.send:active{transform:scale(.88)}
.send:disabled{opacity:.5}
/* ---------- voice: record, pick the voice, send ---------- */
.voice-btn,.voice-pick{width:40px;height:40px;border-radius:50%;flex:none;display:grid;place-items:center;color:var(--ink);background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);transition:transform .2s var(--spring),background .2s var(--ease),color .2s var(--ease)}
.voice-btn:active,.voice-pick:active{transform:scale(.9)}
.voice-btn.rec{background:rgba(255,80,80,.18);color:#ff8b8b;border-color:rgba(255,80,80,.42);animation:voicePulse 1.1s ease-in-out infinite}
.voice-btn.busy{opacity:.55;pointer-events:none}
.voice-pick.on{color:var(--accent);background:rgba(255,179,107,.12);border-color:rgba(255,179,107,.3)}
@keyframes voicePulse{0%,100%{box-shadow:0 0 0 0 rgba(255,80,80,.35)}50%{box-shadow:0 0 0 8px rgba(255,80,80,0)}}
.voice-timer{font-size:12px;color:var(--faint);align-self:center;padding:0 2px;min-width:36px;font-variant-numeric:tabular-nums}
.voice-pop{position:absolute;bottom:calc(100% + 10px);right:6px;width:236px;padding:12px;border-radius:18px;z-index:30;display:none}
.voice-pop.open{display:block}
.voice-opt{display:flex;align-items:center;justify-content:space-between;gap:10px;width:100%;padding:9px 10px;border-radius:12px;background:transparent;border:1px solid transparent;color:var(--ink);font-size:14px;text-align:left}
.voice-opt.on{background:rgba(255,179,107,.12);border-color:rgba(255,179,107,.3)}
.voice-opt small{color:var(--faint);font-size:11px}
.voice-range{width:100%;margin-top:10px}
.voice-range-row{display:flex;justify-content:space-between;font-size:11px;color:var(--faint);margin-top:4px}

/* ---------- empty + loading states ---------- */
.empty{margin:auto;max-width:320px;padding:28px 18px;text-align:center;display:flex;flex-direction:column;align-items:center;gap:10px}
.empty .sigil{width:54px;height:54px;border-radius:19px;display:grid;place-items:center;color:var(--accent);background:rgba(255,179,107,.12);border:1px solid rgba(255,179,107,.25)}
.empty .sigil svg.i{width:24px;height:24px}
.empty b{font:600 15px/1.35 var(--f-body)}
.empty p{margin:0;font-size:13px;color:var(--muted);line-height:1.6}
.empty-inline{margin:auto;padding:20px;text-align:center;color:var(--muted);font-size:13px}
.skel{
  height:58px;border-radius:16px;
  background:linear-gradient(90deg,rgba(255,255,255,.05),rgba(255,255,255,.13),rgba(255,255,255,.05));
  background-size:200% 100%;animation:shimmer 1.4s linear infinite;
}
@keyframes shimmer{to{background-position:-200% 0}}

/* ---------- overview / AI / settings / admin ---------- */
.stats{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
.stat{padding:16px;border-radius:var(--r-md);background:rgba(4,8,6,.38);border:1px solid var(--line-soft);min-width:0}
.stat .k{font:700 23px/1 var(--f-display);letter-spacing:-.03em;font-variant-numeric:tabular-nums}
.stat .l{margin-top:9px;font-size:12px;color:var(--muted)}
.kv{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:11px 0;border-bottom:1px solid var(--line-soft)}
.kv:last-child{border-bottom:0;padding-bottom:0}
.kv:first-child{padding-top:0}
.kv > span:first-child{color:var(--muted);min-width:0}
.kv b{text-align:right;min-width:0;overflow-wrap:anywhere}
.pill{display:inline-flex;align-items:center;gap:7px;padding:5px 11px;border-radius:999px;font-size:12px;font-weight:600;border:1px solid var(--line);color:var(--muted);white-space:nowrap}
.pill.ok{color:var(--ok);border-color:rgba(143,233,189,.36);background:rgba(143,233,189,.1)}
.pill .dot{width:7px;height:7px;border-radius:50%;background:currentColor}
.mode-list{display:flex;flex-direction:column;gap:10px}
.mode{display:grid;grid-template-columns:auto minmax(0,1fr);gap:14px;align-items:start;padding:14px;border-radius:var(--r-md);background:rgba(4,8,6,.38);border:1px solid var(--line-soft)}
.mode .tag{min-width:52px;height:52px;border-radius:16px;display:grid;place-items:center;font:700 11px/1 var(--f-display);color:var(--accent);background:rgba(255,179,107,.12);border:1px solid rgba(255,179,107,.24)}
.mode h3{margin:0 0 4px;font:600 14px/1.3 var(--f-body)}
.mode p{margin:0;font-size:12.5px;color:var(--muted);line-height:1.55}
.key-row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px;border-radius:14px;background:rgba(4,8,6,.38);border:1px solid var(--line-soft)}
.key-row code{font:500 12.5px/1.3 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}
.key-row small{display:block;margin-top:4px;color:var(--muted);font-size:11.5px}
.row{display:flex;gap:10px;align-items:center;min-width:0}
.row > .grow{flex:1;min-width:0}
.keygen{display:flex;flex-direction:column;gap:10px}
.keygen-out{font-size:13px;color:var(--muted);min-height:0;overflow-wrap:anywhere}
.keygen-out code{color:var(--ink);font:600 13px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.hint{font-size:12.5px;color:var(--muted);line-height:1.6}
.stack{display:flex;flex-direction:column;gap:12px;min-width:0}

/* ---------- login ---------- */
.login{position:absolute;inset:0;z-index:4;display:grid;place-items:center;padding:20px 16px}
.login-card{
  width:min(420px,100%);padding:26px;border-radius:var(--r-xl);
  display:flex;flex-direction:column;gap:14px;animation:pop .65s var(--spring) both;
}
.login-card h1{margin:10px 0 0;font:700 22px/1.2 var(--f-display);letter-spacing:-.02em}
.login-card > p{margin:0;font-size:13.5px;color:var(--muted);line-height:1.6}
.brand{display:flex;align-items:center;gap:12px;min-width:0}
.brand-name{font:700 14px/1.2 var(--f-display);letter-spacing:-.01em}
.brand-sub{font-size:12px;color:var(--muted)}
.rail-brand .mark{margin:0 auto}

/* ---------- toast ---------- */
.toast{
  position:fixed;left:50%;bottom:calc(env(safe-area-inset-bottom,0px) + 94px);z-index:60;
  max-width:min(440px,calc(100vw - 32px));padding:12px 16px;border-radius:17px;font-size:13px;line-height:1.45;
  background:var(--glass-strong);border:1px solid var(--line);box-shadow:0 18px 50px rgba(0,0,0,.45);
  transform:translate(-50%,26px) scale(.98);opacity:0;pointer-events:none;
  transition:transform .5s var(--spring),opacity .3s var(--ease);
}
.toast.show{transform:translate(-50%,0) scale(1);opacity:1}

/* ---------- live state, background preview, lists ---------- */
.count-wrap{display:inline-flex;align-items:center;gap:8px;min-width:0}
.live-dot{width:7px;height:7px;border-radius:50%;background:var(--faint);flex:none;transition:background .3s var(--ease),box-shadow .3s var(--ease)}
.live-dot.on{background:var(--ok);box-shadow:0 0 0 3px rgba(143,233,189,.2)}
.sr-only{position:absolute!important;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap;opacity:0;pointer-events:none}
.bg-preview{
  width:100%;max-width:100%;aspect-ratio:16/9;border-radius:var(--r-md);
  border:1px solid var(--line);background:#0b150f;background-size:cover;background-position:50% 28%;
}
.chat-list,.messages{contain:layout}

/* ---------- motion ---------- */
@keyframes rise{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
@keyframes pop{from{opacity:0;transform:scale(.94) translateY(12px)}to{opacity:1;transform:none}}
@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{animation-duration:.01ms!important;animation-delay:0ms!important;transition-duration:.01ms!important}
}

/* ---------- music: covers, tracks, chips ---------- */
.music-stage{
  position:fixed;right:0;bottom:0;width:320px;height:160px;z-index:7;
  opacity:.01;pointer-events:none;overflow:hidden;
}
.music-stage iframe,.music-stage > div{width:300px;height:152px;border:0;display:block}

/* the official Spotify embed, shown on the music page while a Spotify track is current */
.sp-slot{margin:0 0 16px;border-radius:20px;overflow:hidden;border:1px solid var(--line-soft);background:rgba(10,14,12,.6);min-height:152px}
.sp-slot iframe{display:block;width:100%!important;height:152px!important;border:0}

.cover{
  --c:var(--accent);
  position:relative;overflow:hidden;flex:none;display:grid;place-items:center;
  width:46px;height:46px;border-radius:14px;
  background:linear-gradient(145deg,rgba(255,255,255,.1),rgba(255,255,255,.03));
  border:1px solid var(--line-soft);
}
.cover.sp{--c:#1db954}
.cover.sc{--c:#ff7a33}
.cover > svg.i{position:relative;width:20px;height:20px;color:var(--c);opacity:.9}
.cover img{
  position:absolute;inset:0;width:100%;height:100%;max-width:100%;
  object-fit:cover;opacity:0;transition:opacity .35s var(--ease);
}
.cover img.loaded{opacity:1}
.cover-ico{
  position:absolute;inset:0;display:grid;place-items:center;
  background:rgba(6,10,8,.5);color:#fff;opacity:0;transition:opacity .25s var(--ease);
}
.cover-ico svg.i{width:20px;height:20px;fill:currentColor;stroke:none}
.track-main:hover .cover-ico,.track-main:focus-visible .cover-ico{opacity:1}
.cover .eq{
  position:absolute;inset:0;display:flex;align-items:flex-end;justify-content:center;gap:3px;padding:0 0 10px;
  background:rgba(6,10,8,.5);opacity:0;transition:opacity .25s var(--ease);
}
.cover .eq i{width:3px;height:14px;border-radius:2px;background:var(--c);transform-origin:bottom;animation:eqBar 0.9s ease-in-out infinite}
.cover .eq i:nth-child(2){animation-delay:.18s}
.cover .eq i:nth-child(3){animation-delay:.36s}

/* ---------- track rows ---------- */
.tracks{display:flex;flex-direction:column;gap:3px}
.track{
  display:flex;align-items:center;gap:6px;padding:7px 8px 7px 7px;border-radius:18px;
  border:1px solid transparent;transition:background .25s var(--ease),border-color .25s var(--ease);
  animation:rise .45s var(--ease) both;animation-delay:calc(var(--i,0) * 32ms);
}
.track:hover{background:rgba(255,255,255,.05)}
.track.current{background:rgba(255,179,107,.12);border-color:rgba(255,179,107,.28)}
.track.playing .cover .eq{opacity:1}
.track.playing .cover-ico{opacity:0}
.track-main{flex:1;min-width:0;display:flex;align-items:center;gap:12px;text-align:left;padding:2px 4px 2px 0;border-radius:14px}
.t-text{flex:1;min-width:0;display:flex;flex-direction:column;gap:5px}
.t-title{font:600 14px/1.3 var(--f-body);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.t-sub{display:flex;align-items:center;gap:7px;min-width:0;font-size:12px;color:var(--muted);white-space:nowrap;overflow:hidden}
.t-meta{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.track-actions{display:flex;gap:2px;flex:none}
a.icon-btn{text-decoration:none;color:var(--muted)}
a.icon-btn:hover{color:var(--ink)}

.chip{
  display:inline-flex;align-items:center;gap:6px;flex:none;
  padding:2px 8px;border-radius:999px;border:1px solid var(--line);
  font-size:11px;font-weight:600;color:var(--ink);
}
.chip::before{content:"";width:6px;height:6px;border-radius:50%;background:var(--c,var(--accent))}
.chip.sp{--c:#1db954}
.chip.sc{--c:#ff7a33}

@keyframes eqBar{0%,100%{transform:scaleY(.35)}50%{transform:scaleY(1)}}

/* ---------- mini player (above the tab bar on phones, bottom-left on desktop) ---------- */
.mini{
  position:absolute;z-index:6;left:14px;right:14px;
  bottom:calc(env(safe-area-inset-bottom,0px) + 88px);
  display:flex;align-items:center;gap:10px;padding:9px 9px 11px 9px;border-radius:22px;
  transition:transform .5s var(--ease),opacity .35s var(--ease);
  animation:miniIn .5s var(--spring) backwards;
}
.mini-info{flex:1;min-width:0;display:flex;align-items:center;gap:11px;text-align:left;border-radius:16px}
.mini-text{flex:1;min-width:0;display:flex;flex-direction:column;gap:2px}
.mini-text b{font:600 13.5px/1.3 var(--f-body);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.mini-text span{font-size:11.5px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.mini-ctrl{display:flex;align-items:center;gap:2px;flex:none}
.play-btn{
  width:42px;height:42px;border-radius:50%;display:grid;place-items:center;flex:none;
  background:linear-gradient(160deg,var(--accent-hi),var(--accent));color:var(--accent-ink);
  box-shadow:0 8px 20px rgba(255,179,107,.28);transition:transform .2s var(--spring);
}
.play-btn:active{transform:scale(.9)}
.play-btn svg.i{width:20px;height:20px;fill:currentColor;stroke:none}
.mini .icon-btn svg.i{fill:currentColor;stroke:none;width:18px;height:18px}
.mini .icon-btn{width:36px;height:36px;border-radius:12px}
.mini.pending .mini-text b{animation:pulse 1.2s ease-in-out infinite}
.mini.pending .play-btn{opacity:.6}
.mini-bar{position:absolute;left:16px;right:16px;bottom:4px;height:2px;border-radius:2px;background:rgba(255,255,255,.1);overflow:hidden}
.mini-bar i{display:block;height:100%;width:100%;background:var(--accent);transform-origin:left center;transform:scaleX(0);transition:transform .9s linear}
@keyframes miniIn{from{opacity:0;transform:translateY(24px) scale(.96)}to{opacity:1;transform:none}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.45}}

/* the content keeps clear of the mini player */
html[data-player="on"] .page{padding-bottom:calc(184px + env(safe-area-inset-bottom,0px))}
html[data-player="on"] .chat-list{padding-bottom:184px}
html[data-player="on"] .toast{bottom:calc(env(safe-area-inset-bottom,0px) + 180px)}
@media (max-width:899px){
  .shell[data-mode="chat"] .mini{transform:translateY(170%);opacity:0;pointer-events:none}
}
@media (min-width:900px){
  .mini{left:120px;right:auto;width:340px;bottom:24px}
  html[data-player="on"] .page{padding-bottom:116px}
  html[data-player="on"] .chat-list{padding-bottom:116px!important}
  html[data-player="on"] .toast{bottom:104px!important}
}

/* toast tones */
.toast.ok{border-color:rgba(143,233,189,.42)}
.toast.bad{border-color:rgba(255,157,171,.5)}

/* ---------- own files: upload card and the media slot ---------- */
.cover.fl{--c:#8fb8ff}
.chip.fl{--c:#8fb8ff}
.file-pick{position:relative;cursor:pointer}
.file-pick:focus-within{outline:2px solid var(--accent);outline-offset:3px}
.file-pick.busy{opacity:.55;pointer-events:none}
.upload{margin-top:12px;display:flex;flex-direction:column;gap:8px;min-width:0}
.upload .hint{overflow-wrap:anywhere;min-width:0}
.upload-bar{height:6px;border-radius:6px;background:rgba(255,255,255,.08);overflow:hidden}
.upload-bar i{display:block;height:100%;width:0;border-radius:6px;background:linear-gradient(90deg,var(--accent),var(--accent-hi));transition:width .2s linear}
/* the file's player card. flex:none keeps it at its own height inside the flex column of the page */
.file-slot{
  flex:none;margin:0 0 16px;padding:14px;border-radius:24px;min-width:0;
  border:1px solid var(--line);
  background:linear-gradient(160deg,rgba(255,255,255,.08),rgba(255,255,255,.02)),rgba(8,12,10,.62);
  box-shadow:0 18px 40px rgba(0,0,0,.22);
}
.fp-head{display:flex;align-items:center;gap:12px;min-width:0;margin-bottom:12px}
.fp-info{flex:1;min-width:0;display:flex;flex-direction:column;gap:3px}
.fp-info b{font:600 15px/1.3 var(--f-body);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.fp-info span{font-size:12px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.fp-screen{display:none;position:relative;margin:0 0 12px;border-radius:18px;overflow:hidden;background:#000;aspect-ratio:16/9;max-height:min(52vh,380px);cursor:pointer}
.file-slot[data-kind="video"] .fp-screen{display:block}
.fp-screen video{display:block;width:100%;height:100%;object-fit:contain}
.fp-screen audio{display:none}
.fp-bar{display:flex;align-items:center;gap:12px;min-width:0}
.fp-bar .play-btn{flex:none}
.fp-seek{flex:1;min-width:0;display:flex;flex-direction:column;gap:7px}
.fp-seek input{
  -webkit-appearance:none;appearance:none;width:100%;height:22px;margin:0;background:transparent;cursor:pointer;--p:0%;
}
.fp-seek input::-webkit-slider-runnable-track{
  height:6px;border-radius:6px;background:linear-gradient(90deg,var(--accent) var(--p),rgba(255,255,255,.14) var(--p));
}
.fp-seek input::-webkit-slider-thumb{
  -webkit-appearance:none;width:16px;height:16px;margin-top:-5px;border-radius:50%;background:#fff;
  box-shadow:0 2px 8px rgba(0,0,0,.45);transition:transform .2s var(--spring);
}
.fp-seek input:active::-webkit-slider-thumb{transform:scale(1.25)}
.fp-seek input::-moz-range-track{height:6px;border-radius:6px;background:rgba(255,255,255,.14)}
.fp-seek input::-moz-range-progress{height:6px;border-radius:6px;background:var(--accent)}
.fp-seek input::-moz-range-thumb{width:16px;height:16px;border:0;border-radius:50%;background:#fff;box-shadow:0 2px 8px rgba(0,0,0,.45)}
.fp-seek input:focus-visible{outline:2px solid var(--accent);outline-offset:4px;border-radius:8px}
.fp-times{display:flex;justify-content:space-between;font-size:11.5px;color:var(--muted);font-variant-numeric:tabular-nums}

/* ---------- motion: answers to what the person did (tabs, sends, replies, playback) ---------- */

/* tabs slide in from the side they are coming from */
.view.active{animation:viewFwd .5s var(--ease) both}
.shell[data-dir="back"] .view.active{animation-name:viewBack}
@keyframes viewFwd{from{opacity:0;transform:translateX(16px)}to{opacity:1;transform:none}}
@keyframes viewBack{from{opacity:0;transform:translateX(-16px)}to{opacity:1;transform:none}}

/* a new message in a chat: the row glows once and its badge pops */
.chat-row.fresh{animation:freshGlow 1.6s var(--ease) both}
.chat-row.fresh .unread{animation:badgePop .5s var(--spring) both}
@keyframes freshGlow{
  0%{box-shadow:inset 0 0 0 1px rgba(255,179,107,.55),0 0 0 0 rgba(255,179,107,.3)}
  100%{box-shadow:inset 0 0 0 1px rgba(255,179,107,0),0 0 0 9px rgba(255,179,107,0)}
}
@keyframes badgePop{0%{transform:scale(.55)}60%{transform:scale(1.2)}100%{transform:none}}

/* my own reply slides out from the right */
.msg.out.anim .bubble{animation:bubbleOut .45s var(--spring) both}
@keyframes bubbleOut{from{opacity:0;transform:translateX(22px) scale(.92)}to{opacity:1;transform:none}}

/* the send button launches the message */
.send.launch svg.i{animation:sendFly .5s var(--ease)}
@keyframes sendFly{
  0%{transform:none}
  38%{transform:translate(9px,-9px) scale(1.12)}
  58%{transform:translate(-18px,18px) scale(.5);opacity:0}
  100%{transform:none;opacity:1}
}

/* "thinking" dots while the AI writes a draft */
.dots{display:inline-flex;align-items:center;gap:4px;height:14px}
.dots i{width:6px;height:6px;border-radius:50%;background:currentColor;animation:dotBeat 1.1s ease-in-out infinite}
.dots i:nth-child(2){animation-delay:.15s}
.dots i:nth-child(3){animation-delay:.3s}
@keyframes dotBeat{0%,80%,100%{transform:scale(.6);opacity:.4}40%{transform:scale(1);opacity:1}}

/* background photo: the old picture fades out over the new one */
.bg-ghost{
  position:absolute;inset:0;z-index:-1;pointer-events:none;
  background-size:cover;background-position:50% 28%;background-repeat:no-repeat;
}

/* the tab bar icon bump is driven from JS (Web Animations) */
.tab svg.i{will-change:transform}

/* calm mode (Settings): no movement beyond the instant state change */
html.calm *,html.calm *::before,html.calm *::after{
  animation-duration:.01ms!important;animation-delay:0ms!important;
  animation-iteration-count:1!important;transition-duration:.01ms!important;
}

</style>
</head>
<body>
<div id="bg" aria-hidden="true"></div>

<div id="app">
  <section id="login" class="login hidden" aria-labelledby="loginTitle">
    <form id="loginForm" class="glass login-card" autocomplete="off">
      <div class="brand">
        <div class="mark" aria-hidden="true">N</div>
        <div>
          <div class="brand-name">NEZZX AI</div>
          <div class="brand-sub">Telegram Conv</div>
        </div>
      </div>
      <h1 id="loginTitle">Войдите в панель</h1>
      <p>Введите ключ доступа. Ключ выдаёт Telegram-бот: там же можно получить бесплатный доступ или продлить подписку.</p>
      <label class="field">
        <span>Ключ доступа</span>
        <input id="licenseKey" class="input" spellcheck="false" placeholder="FP-XXXXXX-XXXXXX-XXXXXX" required>
      </label>
      <label class="field">
        <span>Пароль администратора <em>необязательно</em></span>
        <input id="adminPassword" class="input" type="password" autocomplete="current-password" placeholder="Если задан на сервере">
      </label>
      <div id="loginError" class="error" role="alert"></div>
      <button class="btn primary block" type="submit" id="loginSubmit">Войти</button>
      <a class="link" id="loginBotLink" href="#" target="_blank" rel="noopener" hidden>Нет ключа? Откройте бота и отправьте /start</a>
    </form>
  </section>

  <div id="shell" class="shell hidden" data-tab="chats" data-mode="list" data-dir="fwd">
    <aside class="sidebar glass" aria-label="Разделы">
      <div class="rail-brand"><div class="mark" aria-hidden="true">N</div></div>
      <nav class="rail" id="rail" aria-label="Разделы"></nav>
      <button class="rail-btn" data-action="logout" title="Выйти">
        <span data-icon="logout"></span><span>Выход</span>
      </button>
    </aside>

    <main class="stage">
      <header class="topbar glass">
        <button class="icon-btn" id="backBtn" data-action="back" aria-label="Назад к списку" hidden><span data-icon="back"></span></button>
        <div class="avatar sm" id="headAvatar" hidden>N</div>
        <div class="title-wrap">
          <h1 id="pageTitle">Чаты</h1>
          <p id="pageSub" class="muted">NEZZX AI Telegram Conv</p>
        </div>
        <div class="top-actions" id="topActions"></div>
      </header>

      <div class="views">
        <section class="view active" data-view="chats">
          <div class="chats-layout" id="chatsLayout">
            <div class="list-pane glass">
              <div class="list-head">
                <label class="search">
                  <span data-icon="search"></span>
                  <input id="chatSearch" class="input" placeholder="Поиск по личным чатам" autocomplete="off">
                </label>
                <div class="list-meta">
                  <span class="count-wrap"><span id="chatCount" class="muted">Личные чаты</span><i class="live-dot" id="liveDot" title="Подключаемся…"></i></span>
                  <select id="chatSort" class="select" aria-label="Сортировка">
                    <option value="recent">Недавние</option>
                    <option value="unread">Непрочитанные</option>
                    <option value="ai">С AI</option>
                  </select>
                </div>
              </div>
              <div id="chatList" class="chat-list"></div>
            </div>
            <div class="chat-pane glass" id="chatPane"></div>
          </div>
        </section>

        <section class="view" data-view="music"><div class="page" id="musicPage"></div></section>
        <section class="view" data-view="ai"><div class="page" id="aiPage"></div></section>
        <section class="view" data-view="prompt"><div class="page" id="promptPage"></div></section>
        <section class="view" data-view="overview"><div class="page" id="overviewPage"></div></section>
        <section class="view" data-view="settings"><div class="page" id="settingsPage"></div></section>
        <section class="view" data-view="admin"><div class="page" id="adminPage"></div></section>
      </div>
    </main>

    <div class="mini glass" id="miniPlayer" hidden>
      <button class="mini-info" type="button" data-goto="music" aria-label="Открыть плейлист">
        <span class="cover" id="miniCover"></span>
        <span class="mini-text"><b id="miniTitle">Трек</b><span id="miniSub"></span></span>
      </button>
      <div class="mini-ctrl">
        <button class="icon-btn" type="button" data-music="prev" aria-label="Предыдущий трек"><span data-icon="prev"></span></button>
        <button class="play-btn" type="button" id="miniToggle" data-music="toggle" aria-label="Играть"></button>
        <button class="icon-btn" type="button" data-music="next" aria-label="Следующий трек"><span data-icon="next"></span></button>
      </div>
      <span class="mini-bar" aria-hidden="true"><i id="miniBar"></i></span>
    </div>

    <nav class="tabbar glass" id="tabbar" aria-label="Разделы">
      <span class="indicator" id="indicator"></span>
    </nav>
  </div>
</div>

<div id="musicStage" class="music-stage" aria-hidden="true"></div>
<div id="lightbox" class="lightbox" role="dialog" aria-label="Фото на весь экран" hidden><img id="lightboxImg" alt=""></div>
<div id="toast" class="toast" role="status" aria-live="polite"></div>

<script>
'use strict';
/* ================================================================
   CORE: state, helpers, API, Telegram WebApp, login, navigation
   ================================================================ */
const TG = window.Telegram?.WebApp || null;
const $  = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

const ICON = {
  chat:    '<path d="M7.9 20A9 9 0 1 0 4 16.1L2 22z"/>',
  spark:   '<path d="M12 3.5l1.9 5.1 5.1 1.9-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9z"/>',
  grid:    '<rect x="3.5" y="3.5" width="7" height="7" rx="2"/><rect x="13.5" y="3.5" width="7" height="7" rx="2"/><rect x="3.5" y="13.5" width="7" height="7" rx="2"/><rect x="13.5" y="13.5" width="7" height="7" rx="2"/>',
  sliders: '<line x1="4" y1="7" x2="20" y2="7"/><circle cx="9" cy="7" r="2.2"/><line x1="4" y1="17" x2="20" y2="17"/><circle cx="15" cy="17" r="2.2"/>',
  shield:  '<path d="M12 3l7.5 3v5.5c0 4.6-3.2 8.3-7.5 9.5-4.3-1.2-7.5-4.9-7.5-9.5V6z"/><path d="M9 12l2.2 2.2L15.5 10"/>',
  search:  '<circle cx="11" cy="11" r="6.5"/><path d="M20 20l-4.2-4.2"/>',
  back:    '<path d="M14.5 5.5L8 12l6.5 6.5"/>',
  send:    '<path d="M4 12h15"/><path d="M13 6l6 6-6 6"/>',
  refresh: '<path d="M19.5 12a7.5 7.5 0 1 1-2.2-5.3"/><path d="M19.5 4.5v4h-4"/>',
  logout:  '<path d="M14 4h4a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-4"/><path d="M10 8l-4 4 4 4"/><path d="M6 12h10"/>',
  expand:  '<path d="M4 9V4h5"/><path d="M20 9V4h-5"/><path d="M4 15v5h5"/><path d="M20 15v5h-5"/>',
  image:   '<rect x="3.5" y="4.5" width="17" height="15" rx="3.5"/><circle cx="9" cy="10" r="1.8"/><path d="M4 17.5l4.6-4.4 3.4 3.1 2.6-2.4 5.4 4.7"/>',
  music:   '<path d="M9 18V6l10-2v12"/><circle cx="6.5" cy="18" r="2.5"/><circle cx="16.5" cy="16" r="2.5"/>',
  play:    '<path d="M8 5.6v12.8a1 1 0 0 0 1.5.86l10.6-6.4a1 1 0 0 0 0-1.72L9.5 4.74A1 1 0 0 0 8 5.6z" fill="currentColor" stroke="none"/>',
  pause:   '<rect x="6.5" y="5" width="4" height="14" rx="1.2" fill="currentColor" stroke="none"/><rect x="13.5" y="5" width="4" height="14" rx="1.2" fill="currentColor" stroke="none"/>',
  next:    '<path d="M5.5 6.6v10.8c0 .6.7 1 1.2.7l7.8-5.4a.85.85 0 0 0 0-1.4L6.7 5.9c-.5-.3-1.2 0-1.2.7z" fill="currentColor" stroke="none"/><rect x="16" y="6" width="2.5" height="12" rx="1.1" fill="currentColor" stroke="none"/>',
  prev:    '<path d="M18.5 6.6v10.8c0 .6-.7 1-1.2.7l-7.8-5.4a.85.85 0 0 1 0-1.4l7.8-5.4c.5-.3 1.2 0 1.2.7z" fill="currentColor" stroke="none"/><rect x="5.5" y="6" width="2.5" height="12" rx="1.1" fill="currentColor" stroke="none"/>',
  trash:   '<path d="M4.5 7h15"/><path d="M9.5 7V5.2c0-.7.5-1.2 1.2-1.2h2.6c.7 0 1.2.5 1.2 1.2V7"/><path d="M6.5 7l.9 11.2c.1 1 .9 1.8 1.9 1.8h5.4c1 0 1.8-.8 1.9-1.8L17.5 7"/><path d="M10 11v5.5M14 11v5.5"/>',
  plus:    '<path d="M12 5v14M5 12h14"/>',
  link:    '<path d="M10 14a4 4 0 0 0 5.66 0l3-3a4 4 0 0 0-5.66-5.66l-1 1"/><path d="M14 10a4 4 0 0 0-5.66 0l-3 3a4 4 0 0 0 5.66 5.66l1-1"/>',
  mic:     '<rect x="9" y="3.5" width="6" height="11" rx="3"/><path d="M5.5 11.5a6.5 6.5 0 0 0 13 0M12 18v3"/>',
  stop:    '<rect x="6.5" y="6.5" width="11" height="11" rx="2.5" fill="currentColor" stroke="none"/>',
  wave:    '<path d="M3.5 12h2M7.5 8.5v7M11.5 5v14M15.5 8.5v7M19.5 10.5v3"/>',
};
const icon = name => `<svg class="i" viewBox="0 0 24 24" aria-hidden="true">${ICON[name] || ''}</svg>`;
const hydrateIcons = () => $$('[data-icon]').forEach(el => { el.innerHTML = icon(el.dataset.icon); });

const TABS = [
  {id: 'chats',    label: 'Чаты',      icon: 'chat'},
  {id: 'music',    label: 'Музыка',    icon: 'music'},
  {id: 'ai',       label: 'AI',        icon: 'spark'},
  {id: 'prompt',   label: 'Промпт',    icon: 'sliders'},
  {id: 'overview', label: 'Обзор',     icon: 'grid'},
  {id: 'settings', label: 'Настройки', icon: 'sliders'},
  {id: 'admin',    label: 'Админ',     icon: 'shield', admin: true},
];
const TAB_TITLE = {chats: 'Чаты', music: 'Музыка', ai: 'AI Conv', prompt: 'Системный промпт', overview: 'Обзор', settings: 'Настройки', admin: 'Админка'};
const TAB_SUB = {
  music: 'Плейлист: Spotify, SoundCloud и свои файлы',
  ai: 'Четыре стиля общения · tokenharbor',
  prompt: 'Ваши указания для ИИ',
  overview: 'Статистика вашего Inbox',
  settings: 'Подключения и доступ',
  admin: 'Ключи доступа',
};
const MODE_NAMES = {friendly: 'Дружелюбный', mm2_trade: 'MM2 Trade', looking_for_players: 'Поиск игроков', careful_trade: 'Безопасный трейд'};
const MODE_TAG   = {friendly: 'Chat', mm2_trade: 'MM2', looking_for_players: 'Play', careful_trade: 'Safe'};
const MODE_DESC  = {
  friendly: 'Неформально и спокойно общается об игре. Подходит для обычной переписки.',
  mm2_trade: 'Обсуждает Murder Mystery 2 и предметы только на основе подтверждённых условий.',
  looking_for_players: 'Помогает найти людей для совместной игры и договориться о времени.',
  careful_trade: 'Помогает согласовать справедливые условия обмена и избегать сомнительных схем.',
};

const state = {
  session: null, config: null, status: null, aiStats: null,
  chats: [], chatStats: {count: 0, unread_count: 0, ai_active_count: 0},
  selected: null, chatAI: {enabled: false, mode: 'friendly'}, messages: [],
  tab: 'chats', listAnimated: false, fsTries: 0, toastTimer: 0, pollTimer: 0, bg: null,
};

/* ---------- helpers ---------- */
function initials(name) {
  return (String(name || '?').trim().split(/\s+/).slice(0, 2).map(x => x[0] || '').join('') || '?').toUpperCase();
}
function hueOf(text) {
  let h = 7;
  for (const ch of String(text || '')) h = (h * 31 + ch.codePointAt(0)) >>> 0;
  return h % 360;
}
function fmtTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d) ? '' : d.toLocaleTimeString('ru-RU', {hour: '2-digit', minute: '2-digit'});
}
function dayKey(iso) { const d = new Date(iso); return isNaN(d) ? '' : d.toDateString(); }
function dayLabel(iso) {
  const d = new Date(iso); if (isNaN(d)) return '';
  const today = new Date(); const yest = new Date(); yest.setDate(today.getDate() - 1);
  if (d.toDateString() === today.toDateString()) return 'Сегодня';
  if (d.toDateString() === yest.toDateString()) return 'Вчера';
  return d.toLocaleDateString('ru-RU', {day: 'numeric', month: 'long'});
}
function emptyBox(title, text = '', action = '') {
  return `<div class="empty"><div class="sigil">${icon('spark')}</div><b>${esc(title)}</b>${text ? `<p>${esc(text)}</p>` : ''}${action}</div>`;
}

/* ---------- API ---------- */
async function api(path, opts = {}) {
  const init = {method: opts.method || 'GET', credentials: 'same-origin', headers: {Accept: 'application/json'}};
  if (opts.body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(opts.body);
  }
  const res = await fetch('/api' + path, init);
  let data = {};
  try { data = await res.json(); } catch {}
  if (!res.ok) {
    const msg = typeof data.detail === 'string' ? data.detail : (data.detail?.message || 'Не удалось выполнить запрос');
    const err = new Error(msg);
    err.status = res.status;
    throw err;
  }
  return data;
}

function toast(msg, kind = '') {
  const el = $('#toast');
  el.textContent = msg;
  el.classList.remove('ok', 'bad');
  if (kind) el.classList.add(kind);
  el.classList.add('show');
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => el.classList.remove('show'), 3400);
}

/* ---------- Telegram WebApp: open full screen, no accidental close ---------- */
function callTG(fn) { try { return fn(); } catch { return undefined; } }

function requestFullscreen() {
  if (!TG || TG.isFullscreen) return;
  state.fsTries += 1;
  callTG(() => TG.requestFullscreen());
}

function setupTelegram() {
  if (!TG) return;
  callTG(() => TG.ready());
  callTG(() => TG.expand());
  callTG(() => TG.disableVerticalSwipes());
  callTG(() => TG.setHeaderColor('#07100a'));
  callTG(() => TG.setBackgroundColor('#07100a'));
  callTG(() => TG.BackButton.onClick(() => { if (state.selected) closeChat(); }));
  requestFullscreen();
  // some clients only allow fullscreen after a tap, so try again on the first two taps
  document.addEventListener('pointerdown', () => { if (state.fsTries < 3) requestFullscreen(); }, {passive: true});
}

function toggleFullscreen() {
  if (TG) {
    if (TG.isFullscreen) callTG(() => TG.exitFullscreen());
    else callTG(() => TG.requestFullscreen());
    return;
  }
  if (document.fullscreenElement) document.exitFullscreen?.();
  else Promise.resolve(document.documentElement.requestFullscreen?.()).catch(() => toast('Браузер не разрешил полноэкранный режим'));
}

/* ---------- login / logout ---------- */
function showLogin() {
  $('#shell').classList.add('hidden');
  $('#login').classList.remove('hidden');
  if (state.config?.telegram_bot_url) {
    const link = $('#loginBotLink');
    link.href = state.config.telegram_bot_url;
    link.hidden = false;
  }
  setTimeout(() => $('#licenseKey')?.focus({preventScroll: true}), 350);
}

$('#loginForm').addEventListener('submit', async ev => {
  ev.preventDefault();
  const btn = $('#loginSubmit');
  const key = $('#licenseKey').value.trim();
  const pass = $('#adminPassword').value.trim();
  btn.disabled = true;
  btn.textContent = 'Проверяем…';
  $('#loginError').textContent = '';
  try {
    await api('/login', {method: 'POST', body: {key: pass ? '' : key, password: pass || key, init_data: TG?.initData || ''}});
    state.session = await api('/session');
    showShell();
  } catch (e) {
    $('#loginError').textContent = e.message;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Войти';
  }
});

async function logout() {
  try { await api('/logout', {method: 'POST'}); } catch {}
  clearInterval(state.pollTimer);
  disconnectStream();
  stopPlayback();
  MUSIC.items = [];
  MUSIC.loaded = false;
  applyBackground(null);
  state.session = null;
  state.chats = [];
  state.selected = null;
  state.messages = [];
  state.listAnimated = false;
  showLogin();
}

/* ---------- navigation ---------- */
function buildNav() {
  const isAdmin = !!state.session?.is_admin;
  const items = TABS.filter(t => !t.admin || isAdmin);
  const btn = (t, cls) => `<button class="${cls}" data-nav="${t.id}" aria-label="${esc(t.label)}"><span data-icon="${t.icon}"></span><span>${esc(t.label)}</span></button>`;
  $('#rail').innerHTML = items.map(t => btn(t, 'rail-btn')).join('');
  const bar = $('#tabbar');
  bar.querySelectorAll('.tab').forEach(n => n.remove());
  bar.insertAdjacentHTML('afterbegin', items.map(t => btn(t, 'tab')).join(''));
  hydrateIcons();
}

function moveIndicator() {
  const ind = $('#indicator');
  const active = $('#tabbar .tab.active');
  if (!active) return;
  ind.style.width = active.offsetWidth + 'px';
  ind.style.transform = `translateX(${active.offsetLeft}px)`;
}

function subtitle() {
  if (state.tab === 'chats') {
    if (!state.status?.connected) return 'Telegram не подключён';
    return state.status.username ? '@' + state.status.username : 'Telegram подключён';
  }
  return TAB_SUB[state.tab] || '';
}

function renderTitle() {
  const sel = state.tab === 'chats' ? state.selected : null;
  const av = $('#headAvatar');
  if (sel) {
    $('#pageTitle').textContent = sel.name;
    $('#pageSub').textContent = sel.username ? '@' + sel.username : 'Личный чат';
    av.hidden = false;
    setAvatar(av, sel);
  } else {
    av.hidden = true;
    $('#pageTitle').textContent = TAB_TITLE[state.tab] || 'NEZZX AI';
    $('#pageSub').textContent = subtitle();
  }
  $('#backBtn').hidden = !sel;
  $('#shell').dataset.mode = sel ? 'chat' : 'list';
  if (TG?.BackButton) callTG(() => (sel ? TG.BackButton.show() : TG.BackButton.hide()));
}

function renderTopActions() {
  $('#topActions').innerHTML = (state.tab === 'chats' || state.tab === 'overview')
    ? `<button class="icon-btn" data-action="refresh" aria-label="Обновить" title="Обновить">${icon('refresh')}</button>`
    : '';
}

function go(tab) {
  const isAdmin = !!state.session?.is_admin;
  if (tab === 'admin' && !isAdmin) tab = 'chats';
  // the new view slides in from the side it comes from
  const order = TABS.map(t => t.id);
  $('#shell').dataset.dir = order.indexOf(tab) < order.indexOf(state.tab) ? 'back' : 'fwd';
  state.tab = tab;
  $('#shell').dataset.tab = tab;
  $$('[data-nav]').forEach(b => {
    const on = b.dataset.nav === tab;
    b.classList.toggle('active', on);
    if (on) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
  });
  $$('.view').forEach(v => v.classList.toggle('active', v.dataset.view === tab));
  moveIndicator();
  renderTitle();
  renderTopActions();
  if (tab === 'chats') { renderChatList(); renderChatPane(); }
  else if (tab === 'ai') renderAI();
  else if (tab === 'prompt') renderPrompt();
  else if (tab === 'overview') renderOverview();
  else if (tab === 'settings') renderSettings();
  else if (tab === 'music') { renderMusic(); loadPlaylist(true); }
  else if (tab === 'admin') renderAdmin();
}

function showShell() {
  $('#login').classList.add('hidden');
  $('#shell').classList.remove('hidden');
  buildNav();
  go(state.tab);
  loadStatus().then(loadChats);
  loadAIStats();
  startPolling();
  connectStream();
  loadBackground();
}

/* one delegated handler for every [data-nav], [data-goto] and [data-action] */
document.addEventListener('click', ev => {
  const nav = ev.target.closest('[data-nav]');
  if (nav) {
    if (nav.dataset.nav !== state.tab) { SFX.tab(); haptic('selection'); bumpIcon(nav); }
    return go(nav.dataset.nav);
  }
  const goto = ev.target.closest('[data-goto]');
  if (goto) return go(goto.dataset.goto);
  const act = ev.target.closest('[data-action]');
  if (!act) return;
  const a = act.dataset.action;
  if (a === 'logout') logout();
  else if (a === 'back') { SFX.close(); haptic('light'); closeChat(); }
  else if (a === 'refresh') refreshCurrent();
  else if (a === 'fullscreen') toggleFullscreen();
  else if (a === 'pick-bg') $('#bgFile')?.click();
  else if (a === 'reset-bg') resetBackground();
  else if (a === 'save-prompt') savePrompt();
});

// links open in Telegram's own browser when the app runs inside Telegram; in a normal browser they open as usual
document.addEventListener('click', ev => {
  const link = ev.target.closest && ev.target.closest('a[data-ext]');
  if (!link || !TG || typeof TG.openLink !== 'function') return;
  ev.preventDefault();
  callTG(() => TG.openLink(link.href));
});

async function refreshCurrent() {
  await loadStatus();
  await loadChats();
  if (state.tab === 'overview') renderOverview();
}

async function loadStatus() {
  try { state.status = await api('/telegram/status'); }
  catch (e) { state.status = {connected: false, api_configured: false, ai_configured: false, error: e.message}; }
  return state.status;
}

async function loadAIStats() {
  try { state.aiStats = await api('/ai/status'); } catch { state.aiStats = {}; }
}

function startPolling() {
  clearInterval(state.pollTimer);
  // live push delivers changes; this timer only repairs gaps:
  // every 30 s while the stream is connected, every 5 s when it is not
  state.pollTimer = setInterval(() => {
    if (!state.session || document.hidden) return;
    if (!LIVE.connected) { loadChats(); if (state.selected) loadMessages(true); return; }
    if (Date.now() - state.lastSync > 30000) loadChats();
  }, 5000);
}
document.addEventListener('visibilitychange', () => {
  if (document.hidden) { disconnectStream(); return; }
  if (state.session) { connectStream(); loadChats(); }
});
window.addEventListener('resize', moveIndicator);

/* ---------- boot ---------- */
async function boot() {
  setupTelegram();
  hydrateIcons();
  try { state.config = await api('/public/config'); } catch {}
  try {
    state.session = await api('/session');
  } catch {
    // opened from Telegram: try the signed WebApp data (works for the admin account)
    if (TG?.initData) {
      try {
        await api('/login', {method: 'POST', body: {key: '', password: '', init_data: TG.initData}});
        state.session = await api('/session');
      } catch {}
    }
  }
  if (state.session) showShell(); else showLogin();
}

/* ================================================================
   SOUND + FEEL: synthesized tones (no audio files), Telegram haptics,
   calm mode. Preferences live on this device only.
   ================================================================ */
const FX = {ctx: null, master: null, on: true, calm: false, last: {}};

function fxLoad() {
  try {
    FX.on = localStorage.getItem('nezzx.sound') !== '0';
    FX.calm = localStorage.getItem('nezzx.calm') === '1';
  } catch {}
  document.documentElement.classList.toggle('calm', FX.calm);
}
function fxSave(key, value) { try { localStorage.setItem(key, value); } catch {} }

// the first tap on the page unlocks audio (browsers require a gesture)
function fxContext() {
  if (!FX.on) return null;
  if (!FX.ctx) {
    const Ctx = window.AudioContext || window.webkitAudioContext;
    if (!Ctx) return null;
    try {
      FX.ctx = new Ctx();
      FX.master = FX.ctx.createGain();
      FX.master.gain.value = 0.9;
      FX.master.connect(FX.ctx.destination);
    } catch {
      FX.ctx = null;
      return null;
    }
  }
  if (FX.ctx.state === 'suspended') FX.ctx.resume().catch(() => {});
  return FX.ctx;
}

function fxTone(freq, dur, o = {}) {
  const ctx = fxContext();
  if (!ctx) return;
  const t0 = ctx.currentTime + (o.when || 0);
  const osc = ctx.createOscillator();
  const gain = ctx.createGain();
  const vol = o.vol ?? 0.08;
  osc.type = o.type || 'sine';
  osc.frequency.setValueAtTime(freq, t0);
  if (o.slide) osc.frequency.exponentialRampToValueAtTime(Math.max(40, freq + o.slide), t0 + dur);
  gain.gain.setValueAtTime(0.0001, t0);
  gain.gain.exponentialRampToValueAtTime(vol, t0 + Math.min(0.012, dur / 3));
  gain.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);
  osc.connect(gain).connect(FX.master);
  osc.start(t0);
  osc.stop(t0 + dur + 0.03);
}

// rate limit per sound, so bursts of events do not stack into noise
function fxThrottle(key, ms) {
  const now = performance.now();
  if (now - (FX.last[key] || 0) < ms) return true;
  FX.last[key] = now;
  return false;
}

const SFX = {
  tap()     { if (!fxThrottle('tap', 45)) fxTone(1040, 0.035, {vol: 0.03}); },
  tab()     { if (!fxThrottle('tab', 60)) { fxTone(660, 0.07, {vol: 0.05}); fxTone(990, 0.09, {when: 0.05, vol: 0.04}); } },
  open()    { fxTone(520, 0.12, {vol: 0.05, slide: 260}); },
  close()   { fxTone(620, 0.1, {vol: 0.045, slide: -220}); },
  sent()    { fxTone(480, 0.14, {vol: 0.06, slide: 340, type: 'triangle'}); },
  receive() { if (!fxThrottle('receive', 350)) { fxTone(988, 0.1, {vol: 0.07}); fxTone(1319, 0.16, {when: 0.09, vol: 0.06}); } },
  ai()      { [523, 659, 784, 1047].forEach((f, i) => fxTone(f, 0.16, {when: i * 0.075, vol: 0.05, type: 'triangle'})); },
  success() { fxTone(784, 0.12, {vol: 0.05}); fxTone(1175, 0.2, {when: 0.1, vol: 0.05}); },
  error()   { fxTone(190, 0.22, {vol: 0.06, type: 'sawtooth'}); },
  toggle()  { fxTone(1200, 0.05, {vol: 0.04}); },
};

// Telegram haptics: selection on tabs, impact on taps, notification for results
function haptic(kind = 'light') {
  try {
    const H = window.Telegram?.WebApp?.HapticFeedback;
    if (!H) return;
    if (kind === 'selection') H.selectionChanged();
    else if (kind === 'success' || kind === 'error' || kind === 'warning') H.notificationOccurred(kind);
    else H.impactOccurred(kind);
  } catch {}
}

// motion that CSS cannot time from JS: off in calm mode and when the system asks for less motion
function motionOK() {
  return !FX.calm && !(window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches);
}
function bumpIcon(el) {
  const svg = el && el.querySelector ? el.querySelector('svg') : null;
  if (!svg || !svg.animate || !motionOK()) return;
  svg.animate([{transform: 'scale(.72)'}, {transform: 'scale(1.16)'}, {transform: 'scale(1)'}],
    {duration: 460, easing: 'cubic-bezier(.34,1.5,.64,1)'});
}

// every button press gets a very soft tick (tabs and rail have their own sound)
document.addEventListener('pointerdown', () => fxContext(), {once: true, passive: true});
document.addEventListener('pointerdown', ev => {
  if (ev.target.closest && ev.target.closest('button:not(.tab):not(.rail-btn), .chat-row, .switch')) SFX.tap();
}, {passive: true});

function renderFxCard() {
  const card = $('#fxCard');
  if (!card) return;
  card.innerHTML = `
    <h2>Звуки и анимации</h2>
    <div class="kv"><span>Звуки вкладок, сообщений и ИИ</span>
      <button class="switch${FX.on ? ' on' : ''}" id="fxSound" type="button" role="switch" aria-checked="${FX.on}" aria-label="Звуки"><span></span></button></div>
    <div class="kv"><span>Спокойный режим без анимаций</span>
      <button class="switch${FX.calm ? ' on' : ''}" id="fxCalm" type="button" role="switch" aria-checked="${FX.calm}" aria-label="Спокойный режим"><span></span></button></div>
    <p class="hint" style="margin:12px 0 0">Настройка сохраняется на этом устройстве.</p>`;
  $('#fxSound').addEventListener('click', () => {
    FX.on = !FX.on;
    fxSave('nezzx.sound', FX.on ? '1' : '0');
    if (FX.on) { fxContext(); SFX.toggle(); }
    renderFxCard();
  });
  $('#fxCalm').addEventListener('click', () => {
    FX.calm = !FX.calm;
    fxSave('nezzx.calm', FX.calm ? '1' : '0');
    document.documentElement.classList.toggle('calm', FX.calm);
    haptic('selection');
    renderFxCard();
  });
}

fxLoad();

/* ================================================================
   LIVE: server push (SSE), instant list and chat updates, avatars,
   personal background photo
   ================================================================ */
const LIVE = {es: null, connected: false, retryTimer: 0, backoff: 1000, avatarMiss: new Set(), fresh: new Map()};
state.lastSync = 0;
let chatsTimer = 0;

function setLiveDot(on) {
  const dot = $('#liveDot');
  if (!dot) return;
  dot.classList.toggle('on', on);
  dot.title = on ? 'Новые сообщения приходят сразу' : 'Переподключаемся…';
}

function connectStream() {
  if (!state.session || LIVE.es || typeof EventSource === 'undefined') return;
  let es;
  try { es = new EventSource('/api/stream'); } catch { return; }
  LIVE.es = es;
  es.onopen = () => { LIVE.connected = true; LIVE.backoff = 1000; setLiveDot(true); };
  es.onmessage = ev => {
    let data;
    try { data = JSON.parse(ev.data); } catch { return; }
    handleLive(data);
  };
  es.onerror = () => {
    LIVE.connected = false;
    setLiveDot(false);
    if (es.readyState !== EventSource.CLOSED) return; // the browser retries on its own
    disconnectStream(true);
    LIVE.retryTimer = setTimeout(connectStream, LIVE.backoff);
    LIVE.backoff = Math.min(LIVE.backoff * 2, 30000);
  };
}

function disconnectStream(keepBackoff = false) {
  clearTimeout(LIVE.retryTimer);
  if (LIVE.es) { LIVE.es.close(); LIVE.es = null; }
  LIVE.connected = false;
  setLiveDot(false);
  if (!keepBackoff) LIVE.backoff = 1000;
}

function handleLive(evt) {
  if (evt.type === 'message') return onLiveMessage(evt);
  if (evt.type === 'ai_sent') return onAISent(evt);
  if (evt.type === 'ready') {
    // after every (re)connect: resync the list and the open chat once, in case events were missed
    scheduleChatsRefresh(0);
    if (state.selected) loadMessages(true);
  }
}

function onLiveMessage(evt) {
  const m = evt.message;
  if (!m) return;
  const chatId = String(evt.chat_id);
  const chat = state.chats.find(c => c.id === chatId);
  const open = !!state.selected && state.selected.id === chatId;
  if (!m.is_out) {
    markFresh(chatId);
    SFX.receive();
    haptic('light');
    if (!open) toast('Новое сообщение' + (chat ? ' от ' + chat.name : ''));
  }
  if (chat) {
    chat.last_message_text = String(m.text || (m.media ? '[Медиа]' : '')).slice(0, 300);
    chat.last_message_date = m.timestamp || chat.last_message_date;
    if (!m.is_out && !open) {
      chat.unread_count = (chat.unread_count || 0) + 1;
      delete READ_HOLD[chatId]; // a fresh unread message must show, even right after a read
    }
    renderChatList();
  }
  if (open) appendLiveMessage(m);
  // the open chat is in front of the person, so a new incoming message is read at once
  if (open && !m.is_out && !document.hidden) markChatRead(state.selected, true);
  scheduleChatsRefresh();
}

// the row of a chat with a new message glows for a moment (its badge pops in the same pass)
function markFresh(id) {
  clearTimeout(LIVE.fresh.get(id));
  LIVE.fresh.set(id, setTimeout(() => {
    LIVE.fresh.delete(id);
    $$('#chatList .chat-row.fresh').forEach(row => { if (row.dataset.chat === id) row.classList.remove('fresh'); });
  }, 1800));
  $$('#chatList .chat-row').forEach(row => { if (row.dataset.chat === id) row.classList.add('fresh'); });
}

// the AI sent a reply on its own: the reply itself arrives as a normal message; this adds the sound and the language
function onAISent(evt) {
  const chat = state.chats.find(c => c.id === String(evt.chat_id));
  SFX.ai();
  haptic('success');
  const lang = evt.language ? ' · ' + evt.language : '';
  toast('ИИ ответил' + (chat ? ' в чате «' + chat.name + '»' : '') + lang, 'ok');
  if (state.selected && state.selected.id === String(evt.chat_id)) loadMessages(true);
  scheduleChatsRefresh(0);
}

function appendLiveMessage(m) {
  if (state.messages.some(x => x.id === m.id)) return; // the same message can arrive twice (push + send reply)
  state.messages.push(m);
  appendMessageNodes([m], true, true);
}

function scheduleChatsRefresh(delay = 2500) {
  clearTimeout(chatsTimer);
  chatsTimer = setTimeout(() => { if (state.session) loadChats(); }, delay);
}

/* ---------- avatars: real Telegram photo over initials, initials when there is none ---------- */
function avatarInner(chat) {
  const name = chat?.name || '?';
  const id = chat?.id ? String(chat.id) : '';
  const withImg = id && !LIVE.avatarMiss.has(id);
  return `${esc(initials(name))}${withImg ? `<img alt="" loading="lazy" decoding="async" src="/api/telegram/avatar/${encodeURIComponent(id)}">` : ''}`;
}

function avatarHTML(chat, size = '') {
  const id = chat?.id ? String(chat.id) : '';
  const withImg = id && !LIVE.avatarMiss.has(id);
  return `<span class="avatar${size ? ' ' + size : ''}" style="--h:${hueOf(chat?.name)}"${withImg ? ` data-av="${esc(id)}"` : ''}>${avatarInner(chat)}</span>`;
}

function setAvatar(el, chat) {
  el.style.setProperty('--h', hueOf(chat?.name));
  el.dataset.av = chat?.id && !LIVE.avatarMiss.has(String(chat.id)) ? String(chat.id) : '';
  el.innerHTML = avatarInner(chat);
}

document.addEventListener('load', ev => {
  const img = ev.target;
  if (img instanceof HTMLImageElement && img.closest('.avatar')) img.classList.add('loaded');
}, true);
document.addEventListener('error', ev => {
  const img = ev.target;
  if (!(img instanceof HTMLImageElement)) return;
  const holder = img.closest('.avatar');
  if (!holder) return;
  if (holder.dataset.av) LIVE.avatarMiss.add(holder.dataset.av);
  img.remove();
}, true);

/* ---------- personal background photo ---------- */
function applyBackground(meta, instant = false) {
  state.bg = meta && meta.custom ? meta : null;
  const el = $('#bg');
  if (!el) return;
  const before = el.style.backgroundImage || getComputedStyle(el).backgroundImage;
  el.style.backgroundImage = state.bg ? `url("/api/ui/background?v=${state.bg.version}")` : '';
  const after = el.style.backgroundImage || getComputedStyle(el).backgroundImage;
  if (instant || before === after || !motionOK() || !el.animate) return;
  // the old picture stays on top and fades out: a crossfade instead of a cut
  const ghost = document.createElement('div');
  ghost.className = 'bg-ghost';
  ghost.style.backgroundImage = before;
  el.appendChild(ghost);
  ghost.animate([{opacity: 1}, {opacity: 0}], {duration: 900, easing: 'ease-out', fill: 'forwards'}).onfinish = () => ghost.remove();
}

async function loadBackground() {
  try { applyBackground(await api('/ui/background/meta'), true); } catch {}
}

function resizeImage(file, maxSide, quality) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.decoding = 'async';
    img.onload = () => {
      const scale = Math.min(1, maxSide / Math.max(img.naturalWidth, img.naturalHeight));
      const canvas = document.createElement('canvas');
      canvas.width = Math.max(1, Math.round(img.naturalWidth * scale));
      canvas.height = Math.max(1, Math.round(img.naturalHeight * scale));
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      URL.revokeObjectURL(url);
      canvas.toBlob(b => (b ? resolve(b) : reject(new Error('Не удалось подготовить фото'))), 'image/jpeg', quality);
    };
    img.onerror = () => { URL.revokeObjectURL(url); reject(new Error('Не удалось открыть это фото')); };
    img.src = url;
  });
}

async function uploadBackground(file) {
  if (!file) return;
  if (!/^image\//.test(file.type || '')) { toast('Выберите изображение'); return; }
  toast('Готовим фон…');
  try {
    const blob = await resizeImage(file, 1600, 0.86);
    const res = await fetch('/api/ui/background', {method: 'PUT', credentials: 'same-origin',
      headers: {'Content-Type': 'image/jpeg'}, body: blob});
    let data = {};
    try { data = await res.json(); } catch {}
    if (!res.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Не удалось сохранить фон');
    applyBackground({custom: true, version: data.version});
    renderBackgroundCard();
    toast('Фон обновлён');
  } catch (e) {
    toast(e.message);
  }
}

async function resetBackground() {
  try {
    await api('/ui/background', {method: 'DELETE'});
    applyBackground({custom: false});
    renderBackgroundCard();
    toast('Вернули стандартный фон');
  } catch (e) {
    toast(e.message);
  }
}

function renderBackgroundCard() {
  const card = $('#bgCard');
  if (!card) return;
  const custom = !!state.bg;
  card.innerHTML = `
    <h2>Фон сайта</h2>
    <div class="bg-preview" id="bgPreview" aria-hidden="true"></div>
    <p class="hint" style="margin:12px 0">Фото показывается за стеклом во всём приложении. Хранится на сервере и видно только вам.</p>
    <div class="btn-row">
      <button class="btn primary" type="button" data-action="pick-bg">${icon('image')}Сменить фон</button>
      ${custom ? '<button class="btn" type="button" data-action="reset-bg">Стандартный</button>' : ''}
    </div>
    <input type="file" id="bgFile" class="sr-only" accept="image/*" tabindex="-1">`;
  $('#bgPreview').style.backgroundImage = custom
    ? `url("/api/ui/background?v=${state.bg.version}")`
    : getComputedStyle($('#bg')).backgroundImage;
  $('#bgFile').addEventListener('change', ev => {
    const file = ev.target.files && ev.target.files[0];
    ev.target.value = '';
    uploadBackground(file);
  });
}

/* ================================================================
   PLAYER: official Spotify and SoundCloud embeds, and the owner's own uploaded files.
   One track plays at a time. Spotify and SoundCloud audio comes from their embeds;
   the server keeps links for those and the uploaded bytes for files.
   ================================================================ */
const PLAYER = {
  item: null, playing: false, pending: false, progress: 0,
  sc: null, scPromise: null, scEl: null, scUrl: '',
  sp: null, spPromise: null, spEl: null, spUri: '', spAPI: null, spAPIPromise: null,
  spNearEnd: false, spWasPlaying: false, scripts: {},
  fileEls: {video: null, audio: null}, // one <video> for MP4 and one <audio> for the rest, made on first use
};

function loadScript(src) {
  if (!PLAYER.scripts[src]) {
    PLAYER.scripts[src] = new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = src;
      s.async = true;
      s.onload = () => resolve();
      s.onerror = () => { delete PLAYER.scripts[src]; s.remove(); reject(new Error('Плеер не загрузился. Проверьте сеть')); };
      document.head.appendChild(s);
    });
  }
  return PLAYER.scripts[src];
}

function withTimeout(promise, ms, text) {
  let timer = 0;
  const guard = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(text)), ms); });
  return Promise.race([promise, guard]).finally(() => clearTimeout(timer));
}

function stageEl() { return $('#musicStage'); }

/* ---------- SoundCloud ---------- */
function scSrc(url) {
  return 'https://w.soundcloud.com/player/?url=' + encodeURIComponent(url) +
    '&auto_play=true&visual=false&hide_related=true&show_comments=false&show_user=false&show_teaser=false&buying=false&sharing=false&download=false';
}

function scEnsure(url) {
  if (!PLAYER.scPromise) {
    PLAYER.scPromise = (async () => {
      await loadScript('https://w.soundcloud.com/player/api.js');
      if (!window.SC || !window.SC.Widget) throw new Error('SoundCloud не отвечает');
      const iframe = document.createElement('iframe');
      iframe.title = 'Плеер SoundCloud';
      iframe.allow = 'autoplay';
      iframe.src = scSrc(url);
      stageEl().appendChild(iframe);
      const widget = window.SC.Widget(iframe);
      const E = window.SC.Widget.Events;
      await withTimeout(new Promise(resolve => widget.bind(E.READY, resolve)), 10000, 'SoundCloud не запустился');
      widget.bind(E.PLAY, () => scEvent(() => { PLAYER.pending = false; setPlaying(true); }));
      widget.bind(E.PAUSE, () => scEvent(() => setPlaying(false)));
      widget.bind(E.FINISH, () => scEvent(() => handleEnded()));
      widget.bind(E.PLAY_PROGRESS, e => scEvent(() => { PLAYER.progress = Number(e.relativePosition) || 0; updateMiniBar(); }));
      PLAYER.sc = widget;
      PLAYER.scEl = iframe;
      PLAYER.scUrl = url;
      return widget;
    })().catch(err => { PLAYER.scPromise = null; throw err; });
  }
  return PLAYER.scPromise;
}

// SoundCloud events only count while a SoundCloud track is the current one
function scEvent(fn) {
  if (PLAYER.item && PLAYER.item.provider === 'soundcloud') fn();
}

/* ---------- Spotify ---------- */
function spLoadAPI() {
  if (PLAYER.spAPI) return Promise.resolve(PLAYER.spAPI);
  if (!PLAYER.spAPIPromise) {
    PLAYER.spAPIPromise = withTimeout(new Promise((resolve, reject) => {
      window.onSpotifyIframeApiReady = api => { PLAYER.spAPI = api; resolve(api); };
      loadScript('https://open.spotify.com/embed/iframe-api/v1').catch(reject);
    }), 12000, 'Spotify не запустился').catch(err => { PLAYER.spAPIPromise = null; throw err; });
  }
  return PLAYER.spAPIPromise;
}

// the Spotify embed lives in the music page's slot, which is shown while a Spotify track is current:
// its own play button is then always in reach, even where the browser holds back audio that was not asked for by a tap
function spEnsure(uri) {
  if (!PLAYER.spPromise) {
    PLAYER.spPromise = (async () => {
      const api = await spLoadAPI();
      const el = document.createElement('div');
      ($('#spSlot') || stageEl()).appendChild(el);
      try {
        const controller = await withTimeout(new Promise(resolve => {
          api.createController(el, {uri, width: 300, height: 152}, c => {
            // the callback can arrive before the embed is ready, so also wait for its ready event
            c.addListener('ready', () => resolve(c));
            setTimeout(() => resolve(c), 4000);
          });
        }), 12000, 'Spotify не запустился');
        controller.addListener('playback_started', () => spEvent(() => {
          PLAYER.spNearEnd = false;
          PLAYER.spWasPlaying = true;
          PLAYER.pending = false;
          setPlaying(true);
        }));
        controller.addListener('playback_update', e => spEvent(() => spUpdate(e && e.data ? e.data : {})));
        PLAYER.sp = controller;
        PLAYER.spEl = el;
        PLAYER.spUri = uri;
        return controller;
      } catch (err) {
        el.remove();
        throw err;
      }
    })().catch(err => { PLAYER.spPromise = null; throw err; });
  }
  return PLAYER.spPromise;
}

function showSpSlot(on) {
  const slot = $('#spSlot');
  if (slot) slot.hidden = !on;
}

function spEvent(fn) {
  if (PLAYER.item && PLAYER.item.provider === 'spotify') fn();
}

// Spotify has no "finished" event: a track counts as finished when playback stops within 1.5 s of its end
function spUpdate(d) {
  const paused = !!d.isPaused;
  const dur = Number(d.duration) || 0;
  const pos = Number(d.position) || 0;
  PLAYER.progress = dur ? Math.min(1, pos / dur) : 0;
  if (!paused) PLAYER.spNearEnd = dur > 0 && pos >= dur - 1500;
  const ended = paused && PLAYER.spWasPlaying && PLAYER.spNearEnd;
  PLAYER.spWasPlaying = !paused;
  if (ended) { handleEnded(); return; }
  setPlaying(!paused);
  updateMiniBar();
}

/* ---------- own files: MP4 plays in a <video>, M4A, MP3 and WAV in an <audio> ---------- */
function fileKey(kind) { return kind === 'video' ? 'video' : 'audio'; }

function showFileSlot(on) {
  const slot = $('#fileSlot');
  if (slot) slot.hidden = !on;
}

// events only count while a file is the current track
function fileEvent(fn) {
  if (PLAYER.item && PLAYER.item.provider === 'file') fn();
}

// made on first use and kept; only the element for this kind is shown
function fileMedia(kind) {
  const key = fileKey(kind);
  if (!PLAYER.fileEls[key]) {
    const el = document.createElement(key);
    el.preload = 'metadata';
    el.playsInline = true;
    el.addEventListener('play', () => fileEvent(() => { PLAYER.pending = false; setPlaying(true); }));
    el.addEventListener('pause', () => fileEvent(() => setPlaying(false)));
    el.addEventListener('loadedmetadata', () => fileEvent(() => renderFileBar()));
    el.addEventListener('timeupdate', () => fileEvent(() => {
      const d = el.duration;
      PLAYER.progress = Number.isFinite(d) && d > 0 ? Math.min(1, el.currentTime / d) : 0;
      updateMiniBar();
      renderFileBar();
    }));
    el.addEventListener('ended', () => fileEvent(() => handleEnded()));
    el.addEventListener('error', () => fileEvent(() => fileFailed()));
    $('#fpScreen').appendChild(el);
    PLAYER.fileEls[key] = el;
  }
  for (const k of Object.keys(PLAYER.fileEls)) {
    if (PLAYER.fileEls[k]) PLAYER.fileEls[k].hidden = k !== key;
  }
  return PLAYER.fileEls[key];
}

function fileFailed() {
  PLAYER.pending = false;
  PLAYER.playing = false;
  renderMini();
  updateTrackStates();
  SFX.error();
  toast('Браузер не смог открыть файл. Для видео нужен MP4 с кодеком H.264, для звука MP3 или WAV', 'bad');
}

async function playFile(item) {
  pauseSoundCloud();
  pauseSpotify();
  const el = fileMedia(item.kind);
  showFileSlot(true);
  if (el.getAttribute('src') !== item.file_url) el.src = item.file_url;
  try {
    await el.play();
  } catch (err) {
    if (PLAYER.item !== item) return; // the user already picked something else
    if (err.name === 'NotAllowedError') {
      // the browser wants a tap before it plays sound: the mini player's button does that
      PLAYER.pending = false;
      renderMini();
      toast('Нажмите ▶ внизу, чтобы включить звук');
    }
    // other errors reach the element's error event, which reports them once
  }
}

function pauseFile() {
  for (const el of Object.values(PLAYER.fileEls)) {
    try { if (el) el.pause(); } catch {}
  }
}

function toggleFile() {
  const item = PLAYER.item;
  const el = PLAYER.fileEls[fileKey(item.kind)];
  if (!el) return startItem(item);
  if (el.paused) {
    el.play().catch(err => {
      if (err.name === 'NotAllowedError') toast('Браузер ждёт нажатия. Нажмите ▶ ещё раз', 'bad');
    });
  } else {
    el.pause();
  }
}

// stop releases the media, so a stopped file is no longer streamed or kept in memory
function unloadFile() {
  for (const el of Object.values(PLAYER.fileEls)) {
    if (!el) continue;
    try { el.pause(); } catch {}
    if (el.getAttribute('src')) { el.removeAttribute('src'); el.load(); }
  }
  showFileSlot(false);
}

/* ---------- playback control ---------- */
async function playItem(item) {
  if (!item) return;
  if (PLAYER.item && PLAYER.item.id === item.id) return togglePlayback();
  startItem(item);
}

// starts a track, even when it is already the current one (used when the embed is not ready yet)
async function startItem(item) {
  PLAYER.item = item;
  PLAYER.playing = false;
  PLAYER.pending = true;
  PLAYER.progress = 0;
  PLAYER.spNearEnd = false;
  PLAYER.spWasPlaying = false;
  showSpSlot(item.provider === 'spotify');
  showFileSlot(item.provider === 'file');
  renderMini();
  updateTrackStates();
  try {
    if (item.provider === 'soundcloud') await playSoundCloud(item);
    else if (item.provider === 'file') await playFile(item);
    else await playSpotify(item);
  } catch (err) {
    PLAYER.pending = false;
    PLAYER.playing = false;
    renderMini();
    updateTrackStates();
    toast(err.message || 'Не удалось запустить плеер', 'bad');
    SFX.error();
  }
}

async function playSoundCloud(item) {
  pauseSpotify();
  const widget = await scEnsure(item.source_url);
  if (PLAYER.item !== item) return; // the user already picked something else
  if (PLAYER.scUrl !== item.source_url) {
    PLAYER.scUrl = item.source_url;
    widget.load(item.source_url, {auto_play: true});
  } else {
    widget.play();
  }
  // no PLAY event within a few seconds usually means the browser blocked autoplay: the mini button starts it
  setTimeout(() => { if (PLAYER.item === item && PLAYER.pending) { PLAYER.pending = false; renderMini(); } }, 3500);
}

async function playSpotify(item) {
  pauseSoundCloud();
  const uri = 'spotify:' + item.embed_id;
  PLAYER.spNearEnd = false;
  PLAYER.spWasPlaying = false;
  const controller = await spEnsure(uri);
  if (PLAYER.item !== item) return;
  if (PLAYER.spUri !== uri) {
    PLAYER.spUri = uri;
    if (controller.loadEntity) controller.loadEntity(uri);
    else controller.loadUri(uri);
  }
  controller.play();
  // no playback event within a few seconds: the browser held the audio back, so the embed's own play button is the way on
  setTimeout(() => {
    if (PLAYER.item !== item || !PLAYER.pending) return;
    PLAYER.pending = false;
    renderMini();
    if (state.tab === 'music') toast('Звука нет? Нажмите ▶ во встроенном плеере Spotify');
  }, 3500);
}

// each provider pauses the others, so only one track plays at a time
function pauseSoundCloud() {
  try { if (PLAYER.sc) PLAYER.sc.pause(); } catch {}
  pauseFile();
}

function pauseSpotify() {
  try { if (PLAYER.sp) PLAYER.sp.pause(); } catch {}
  pauseFile();
}

function togglePlayback() {
  const item = PLAYER.item;
  if (!item) return;
  try {
    if (item.provider === 'file') {
      toggleFile();
    } else if (item.provider === 'soundcloud') {
      if (PLAYER.sc) PLAYER.sc.toggle(); else startItem(item);
    } else if (PLAYER.sp) {
      PLAYER.sp.togglePlay();
    } else {
      startItem(item);
    }
  } catch {
    toast('Плеер ещё не готов. Попробуйте ещё раз', 'bad');
  }
  haptic('light');
  SFX.toggle();
}

function stepPlayback(dir) {
  const list = MUSIC.items;
  if (!list.length) return;
  const cur = PLAYER.item ? list.findIndex(x => x.id === PLAYER.item.id) : -1;
  const next = cur < 0 ? (dir > 0 ? 0 : list.length - 1) : (cur + dir + list.length) % list.length;
  haptic('selection');
  SFX.tab();
  playItem(list[next]);
}

// repeat-all: when a track ends, the next one plays; a single track simply stops
function handleEnded() {
  PLAYER.spNearEnd = false;
  PLAYER.spWasPlaying = false;
  if (MUSIC.items.length > 1) stepPlayback(1);
  else setPlaying(false);
}

function stopPlayback() {
  pauseSoundCloud();
  pauseSpotify();
  PLAYER.item = null;
  PLAYER.playing = false;
  PLAYER.pending = false;
  PLAYER.progress = 0;
  showSpSlot(false);
  unloadFile();
  renderMini();
  updateTrackStates();
}

/* ---------- the file's own player card: title, seek bar, time, play button ---------- */
function fmtDur(sec) {
  const s = Math.max(0, Math.floor(Number(sec) || 0));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), r = String(s % 60).padStart(2, '0');
  return h ? `${h}:${String(m).padStart(2, '0')}:${r}` : `${m}:${r}`;
}

function renderFileBar() {
  const slot = $('#fileSlot');
  const item = PLAYER.item;
  if (!slot || !item || item.provider !== 'file') return;
  const el = PLAYER.fileEls[fileKey(item.kind)];
  const d = el && Number.isFinite(el.duration) ? el.duration : 0;
  const t = el ? el.currentTime : 0;
  slot.dataset.kind = fileKey(item.kind);
  if (slot.dataset.tid !== String(item.id)) {
    slot.dataset.tid = String(item.id);
    $('#fpCover').innerHTML = icon('music');
    $('#fpTitle').textContent = item.title || 'Без названия';
    $('#fpSub').textContent = [item.kind_label, 'Файл'].filter(Boolean).join(' · ');
  }
  const seek = $('#fpSeek');
  const pct = d ? Math.min(100, t / d * 100) : 0;
  if (document.activeElement !== seek) seek.value = String(Math.round(pct * 10));
  seek.style.setProperty('--p', pct.toFixed(2) + '%');
  $('#fpNow').textContent = fmtDur(t);
  $('#fpLeft').textContent = d ? '-' + fmtDur(d - t) : '0:00';
  const btn = $('#fpToggle');
  btn.innerHTML = icon(PLAYER.playing ? 'pause' : 'play');
  btn.setAttribute('aria-label', PLAYER.playing ? 'Пауза' : 'Играть');
}

// fraction 0..1 of the file's length
function seekFile(fraction) {
  const item = PLAYER.item;
  const el = item && item.provider === 'file' ? PLAYER.fileEls[fileKey(item.kind)] : null;
  if (!el || !Number.isFinite(el.duration)) return;
  el.currentTime = Math.min(1, Math.max(0, fraction)) * el.duration;
  renderFileBar();
}

/* ---------- state and mini player ---------- */
function setPlaying(on) {
  if (PLAYER.playing === on && !(on && PLAYER.pending)) return;
  PLAYER.playing = on;
  if (on) PLAYER.pending = false;
  renderMini();
  updateTrackStates();
}

function updateMiniBar() {
  const bar = $('#miniBar');
  if (bar) bar.style.transform = 'scaleX(' + PLAYER.progress.toFixed(4) + ')';
}

// the colour of a track: Spotify green, SoundCloud orange, the owner's own files blue
function providerClass(item) {
  if (item.provider === 'soundcloud') return 'sc';
  if (item.provider === 'file') return 'fl';
  return 'sp';
}

function renderMini() {
  const mini = $('#miniPlayer');
  if (!mini) return;
  const item = PLAYER.item;
  document.documentElement.dataset.player = item ? 'on' : 'off';
  if (!item) { mini.hidden = true; mini.classList.remove('playing'); return; }
  mini.hidden = false;
  mini.classList.toggle('playing', PLAYER.playing);
  mini.classList.toggle('pending', PLAYER.pending && !PLAYER.playing);
  $('#miniCover').className = 'cover ' + providerClass(item);
  $('#miniCover').innerHTML = coverInner(item);
  $('#miniTitle').textContent = item.title || 'Без названия';
  $('#miniSub').textContent = [item.provider_label, item.artist].filter(Boolean).join(' · ');
  const btn = $('#miniToggle');
  btn.innerHTML = icon(PLAYER.playing ? 'pause' : 'play');
  btn.setAttribute('aria-label', PLAYER.playing ? 'Пауза' : 'Играть');
  updateMiniBar();
  renderFileBar();
}

/* ================================================================
   MUSIC: playlist of Spotify and SoundCloud links (add, play, remove)
   ================================================================ */
const MUSIC = {items: [], loaded: false, busy: false, uploading: false};

function ruPlural(n, forms) {
  const m10 = n % 10, m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return forms[0];
  if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return forms[1];
  return forms[2];
}

// the icon sits under the cover photo, so a broken photo leaves something to look at
function coverInner(item) {
  const photo = item.thumb_url ? `<img alt="" loading="lazy" decoding="async" referrerpolicy="no-referrer" src="${esc(item.thumb_url)}">` : '';
  return icon('music') + photo;
}

document.addEventListener('load', ev => {
  const img = ev.target;
  if (img instanceof HTMLImageElement && img.closest('.cover')) img.classList.add('loaded');
}, true);
document.addEventListener('error', ev => {
  const img = ev.target;
  if (img instanceof HTMLImageElement && img.closest('.cover')) img.remove();
}, true);

function trackHTML(item, i) {
  const cur = !!PLAYER.item && PLAYER.item.id === item.id;
  const sp = providerClass(item);
  return `
    <div class="track${cur ? ' current' : ''}${cur && PLAYER.playing ? ' playing' : ''}" data-tid="${esc(item.id)}" style="--i:${Math.min(i, 14)}">
      <button class="track-main" type="button" data-play="${esc(item.id)}" aria-label="Играть: ${esc(item.title)}">
        <span class="cover ${sp}">${coverInner(item)}<span class="cover-ico">${icon('play')}</span><span class="eq" aria-hidden="true"><i></i><i></i><i></i></span></span>
        <span class="t-text">
          <b class="t-title">${esc(item.title)}</b>
          <span class="t-sub"><span class="chip ${sp}">${esc(item.provider_label)}</span><span class="t-meta">${esc(item.kind_label)}${item.artist ? ' · ' + esc(item.artist) : ''}</span></span>
        </span>
      </button>
      <div class="track-actions">
        ${item.source_url ? `<a class="icon-btn" href="${esc(item.source_url)}" data-ext target="_blank" rel="noopener noreferrer" aria-label="Открыть ссылку" title="Открыть ссылку">${icon('link')}</a>` : ''}
        <button class="icon-btn" type="button" data-remove="${esc(item.id)}" aria-label="Убрать из плейлиста" title="Убрать">${icon('trash')}</button>
      </div>
    </div>`;
}

function ensureMusicPage() {
  const page = $('#musicPage');
  if (!page || page.dataset.ready) return;
  page.dataset.ready = '1';
  page.innerHTML = `
    <section class="card">
      <h2>Добавить трек</h2>
      <p class="hint" style="margin:0 0 12px">Вставьте ссылку на трек, альбом или плейлист Spotify или SoundCloud. Сервер хранит только ссылку и название, а звук играет официальный плеер.</p>
      <form id="musicForm" class="stack" autocomplete="off">
        <label class="field"><span>Ссылка</span>
          <input class="input" id="musicUrl" inputmode="url" spellcheck="false" autocapitalize="off" placeholder="https://open.spotify.com/track/…"></label>
        <div class="btn-row">
          <button class="btn primary" type="submit" data-add="play">${icon('play')}Добавить и играть</button>
          <button class="btn" type="button" data-add="list">${icon('plus')}В плейлист</button>
        </div>
      </form>
      <p class="hint" style="margin:12px 0 0">Полная песня в Spotify требует входа в аккаунт Spotify в этом браузере, без него звучит отрывок. У SoundCloud некоторые треки запрещают встраивание.</p>
    </section>
    <section class="card">
      <h2>Свой файл</h2>
      <p class="hint" style="margin:0 0 12px">MP4, M4A, MP3 или WAV, до 50 МБ. Файл хранится на сервере и виден только вам.</p>
      <label class="btn primary file-pick" id="filePick">
        <input type="file" id="musicFile" class="sr-only" accept=".mp4,.m4a,.mp3,.wav,video/mp4,audio/mp4,audio/mpeg,audio/wav,audio/x-wav">
        ${icon('plus')}Выбрать файл
      </label>
      <div class="upload" id="uploadBox" hidden>
        <div class="upload-bar"><i id="uploadBar"></i></div>
        <span class="hint" id="uploadText"></span>
      </div>
    </section>
    <div class="sp-slot" id="spSlot" hidden></div>
    <section class="file-slot" id="fileSlot" hidden aria-label="Плеер файла">
      <div class="fp-head">
        <span class="cover fl" id="fpCover"></span>
        <div class="fp-info"><b id="fpTitle"></b><span id="fpSub"></span></div>
      </div>
      <div class="fp-screen" id="fpScreen" title="Нажмите, чтобы остановить или продолжить"></div>
      <div class="fp-bar">
        <button class="play-btn" type="button" id="fpToggle" aria-label="Играть"></button>
        <div class="fp-seek">
          <input type="range" id="fpSeek" min="0" max="1000" step="1" value="0" aria-label="Перемотка">
          <div class="fp-times"><span id="fpNow">0:00</span><span id="fpLeft">0:00</span></div>
        </div>
      </div>
    </section>
    <section class="card">
      <div class="row" style="justify-content:space-between;margin-bottom:10px">
        <h2 style="margin:0">Плейлист</h2>
        <span class="muted" id="musicCount"></span>
      </div>
      <div id="trackList" class="tracks"></div>
    </section>`;
  stagger(page);
}

function renderMusic() {
  ensureMusicPage();
  const list = $('#trackList');
  if (!list) return;
  const n = MUSIC.items.length;
  const count = $('#musicCount');
  if (count) count.textContent = n ? `${n} ${ruPlural(n, ['трек', 'трека', 'треков'])}` : '';
  if (!MUSIC.loaded && !n) {
    list.dataset.sig = '';
    list.innerHTML = '<div class="skel"></div><div class="skel"></div>';
    return;
  }
  // the Spotify embed loads ahead of time, so the first press of play does not wait for it
  const spotify = MUSIC.items.find(x => x.provider === 'spotify');
  if (spotify && !PLAYER.spPromise) spEnsure('spotify:' + spotify.embed_id).catch(() => {});
  const sig = JSON.stringify(MUSIC.items.map(x => [x.id, x.title, x.artist, x.thumb_url, x.provider]));
  if (list.dataset.sig === sig) return updateTrackStates();
  list.dataset.sig = sig;
  list.innerHTML = n
    ? MUSIC.items.map((item, i) => trackHTML(item, i)).join('')
    : emptyBox('Плейлист пуст', 'Вставьте ссылку Spotify или SoundCloud, либо загрузите свой MP4 или MP3. Всё сохранится здесь.');
  updateTrackStates();
}

// marks the current row and shows the equalizer only while it really plays
function updateTrackStates() {
  const cur = PLAYER.item ? PLAYER.item.id : null;
  $$('#trackList .track').forEach(row => {
    const on = cur !== null && String(cur) === row.dataset.tid;
    row.classList.toggle('current', on);
    row.classList.toggle('playing', on && PLAYER.playing);
  });
}

async function loadPlaylist(silent) {
  try {
    const d = await api('/music/playlist');
    MUSIC.items = d.items || [];
    MUSIC.loaded = true;
    if (state.tab === 'music') renderMusic();
  } catch (e) {
    if (!silent) toast(e.message, 'bad');
  }
}

function setMusicBusy(on) {
  $$('#musicPage [data-add]').forEach(b => { b.disabled = on; });
  const form = $('#musicForm');
  if (form) form.setAttribute('aria-busy', String(on));
}

async function addTrack(playNow) {
  const input = $('#musicUrl');
  const url = input ? input.value.trim() : '';
  if (!url) {
    SFX.error();
    toast('Вставьте ссылку на Spotify или SoundCloud', 'bad');
    input?.focus();
    return;
  }
  if (MUSIC.busy) return;
  MUSIC.busy = true;
  setMusicBusy(true);
  try {
    const d = await api('/music/playlist', {method: 'POST', body: {url}});
    const item = d.item;
    if (!MUSIC.items.some(x => x.id === item.id)) MUSIC.items.push(item);
    input.value = '';
    SFX.success();
    haptic('success');
    toast(d.created ? `Добавлено: ${item.title}` : 'Этот трек уже есть в плейлисте', 'ok');
    renderMusic();
    if (playNow) playItem(item);
  } catch (e) {
    SFX.error();
    haptic('error');
    toast(e.message, 'bad');
  } finally {
    MUSIC.busy = false;
    setMusicBusy(false);
  }
}

async function removeTrack(id) {
  if (!MUSIC.items.some(x => x.id === id)) return;
  try {
    await api(`/music/playlist/${encodeURIComponent(id)}`, {method: 'DELETE'});
    MUSIC.items = MUSIC.items.filter(x => x.id !== id);
    if (PLAYER.item && PLAYER.item.id === id) stopPlayback();
    renderMusic();
    haptic('medium');
    toast('Трек убран из плейлиста', 'ok');
  } catch (e) {
    SFX.error();
    haptic('error');
    toast(e.message, 'bad');
  }
}

/* ---------- own files: MP4, M4A, MP3 or WAV, uploaded to this owner's space ---------- */
const UPLOAD_MAX = 50 * 1024 * 1024;
const UPLOAD_RE = /\.(mp4|m4a|mp3|wav)$/i;

function showUpload(p, text) {
  const box = $('#uploadBox');
  if (!box) return;
  box.hidden = false;
  $('#uploadBar').style.width = (Math.min(1, Math.max(0, p)) * 100).toFixed(1) + '%';
  $('#uploadText').textContent = text;
}

function setUploading(on) {
  MUSIC.uploading = on;
  const pick = $('#filePick');
  if (pick) pick.classList.toggle('busy', on);
  if (!on) {
    const box = $('#uploadBox');
    if (box) box.hidden = true;
  }
}

function uploadFile(file) {
  const name = String(file.name || '').trim();
  if (MUSIC.uploading) return toast('Дождитесь окончания загрузки', 'bad');
  if (!UPLOAD_RE.test(name)) {
    SFX.error();
    haptic('error');
    return toast('Выберите файл MP4, M4A, MP3 или WAV', 'bad');
  }
  if (!file.size) {
    SFX.error();
    return toast('Этот файл пустой', 'bad');
  }
  if (file.size > UPLOAD_MAX) {
    SFX.error();
    haptic('error');
    return toast('Файл больше 50 МБ. Возьмите файл поменьше', 'bad');
  }
  setUploading(true);
  showUpload(0, `Загружаем: ${name}`);
  const xhr = new XMLHttpRequest();
  xhr.open('POST', '/api/music/upload');
  xhr.setRequestHeader('Content-Type', 'application/octet-stream');
  xhr.setRequestHeader('X-File-Name', encodeURIComponent(name));
  xhr.upload.onprogress = ev => {
    if (ev.lengthComputable) showUpload(ev.loaded / ev.total, `Загружаем: ${name}`);
  };
  xhr.onerror = () => {
    setUploading(false);
    SFX.error();
    haptic('error');
    toast('Нет связи с сервером. Попробуйте ещё раз', 'bad');
  };
  xhr.onload = () => {
    setUploading(false);
    let data = {};
    try { data = JSON.parse(xhr.responseText || '{}'); } catch {}
    if (xhr.status < 200 || xhr.status >= 300) {
      SFX.error();
      haptic('error');
      const msg = typeof data.detail === 'string' ? data.detail : (data.detail?.message || 'Не удалось загрузить файл');
      return toast(msg, 'bad');
    }
    const item = data.item;
    if (!MUSIC.items.some(x => x.id === item.id)) MUSIC.items.push(item);
    SFX.success();
    haptic('success');
    toast(`Файл добавлен: ${item.title}`, 'ok');
    renderMusic();
    playItem(item);
  };
  xhr.send(file);
}

$('#musicPage').addEventListener('change', ev => {
  if (!ev.target || ev.target.id !== 'musicFile') return;
  const file = ev.target.files && ev.target.files[0];
  ev.target.value = ''; // so picking the same file again still fires a change
  if (file) uploadFile(file);
});

// dragging the seek bar moves the file
$('#musicPage').addEventListener('input', ev => {
  if (ev.target && ev.target.id === 'fpSeek') seekFile(Number(ev.target.value) / 1000);
});

$('#musicPage').addEventListener('submit', ev => {
  if (ev.target && ev.target.id === 'musicForm') {
    ev.preventDefault();
    addTrack(true);
  }
});

$('#musicPage').addEventListener('click', ev => {
  if (ev.target.closest('#fpToggle') || ev.target.closest('#fpScreen')) return togglePlayback();
  const add = ev.target.closest('[data-add="list"]');
  if (add) return addTrack(false);
  const play = ev.target.closest('[data-play]');
  if (play) {
    const item = MUSIC.items.find(x => String(x.id) === play.dataset.play);
    if (item) playItem(item);
    return;
  }
  const rm = ev.target.closest('[data-remove]');
  if (rm) removeTrack(Number(rm.dataset.remove));
});

// the mini player buttons (play, pause, next, previous)
document.addEventListener('click', ev => {
  const btn = ev.target.closest && ev.target.closest('[data-music]');
  if (!btn) return;
  const action = btn.dataset.music;
  if (action === 'toggle') togglePlayback();
  else if (action === 'next') stepPlayback(1);
  else if (action === 'prev') stepPlayback(-1);
});

/* ================================================================
   VIEWS: chats, conversation, AI, overview, settings, admin
   ================================================================ */
const AI_NAMES = {tokenharbor: 'tokenharbor'};
const pill = (ok, text) => `<span class="pill${ok ? ' ok' : ''}"><span class="dot"></span>${esc(text)}</span>`;
const stagger = root => Array.from(root.children).forEach((el, i) => el.style.setProperty('--i', Math.min(i, 12)));
const modeOptions = sel => Object.keys(MODE_NAMES)
  .map(k => `<option value="${k}"${k === sel ? ' selected' : ''}>${esc(MODE_NAMES[k])}</option>`).join('');

/* ---------- chat list (personal chats only: the server already drops groups) ---------- */
// chat id -> time until which the server's unread count is ignored, so a chat read a moment ago stays read
// while the server catches up with the read receipt
const READ_HOLD = {};

// reading a chat (or a new message while it is open and visible) tells Telegram too, so the badge stays gone
async function markChatRead(chat, force = false) {
  if (!chat || (!force && !chat.unread_count)) return;
  chat.unread_count = 0;
  READ_HOLD[chat.id] = Date.now() + 15000;
  state.chatStats.unread_count = state.chats.reduce((n, c) => n + (c.unread_count || 0), 0);
  renderChatList();
  if (state.tab === 'overview') renderOverview();
  try {
    await api(`/telegram/chats/${encodeURIComponent(chat.id)}/read`, {method: 'POST'});
  } catch {
    // the next refresh shows whatever Telegram still counts as unread
  }
}

async function loadChats() {
  try {
    const d = await api('/telegram/chats');
    state.lastSync = Date.now();
    state.chats = (d.items || []).filter(c => c.is_user !== false);
    const now = Date.now();
    state.chats.forEach(c => { if ((READ_HOLD[c.id] || 0) > now) c.unread_count = 0; });
    state.chatStats = {
      count: d.count ?? state.chats.length,
      unread_count: state.chats.reduce((n, c) => n + (c.unread_count || 0), 0),
      ai_active_count: d.ai_active_count ?? 0,
    };
    if (state.selected) {
      const fresh = state.chats.find(c => c.id === state.selected.id);
      if (fresh) state.selected = fresh;
      else { state.selected = null; state.messages = []; renderTitle(); renderChatPane(); }
    }
    renderChatList();
    renderTitle();
    if (state.selected) {
      // an open chat with new messages, seen while the app is in front, counts as read
      if (state.selected.unread_count && !document.hidden) markChatRead(state.selected, true);
      await loadMessages(true);
    }
  } catch (e) {
    state.chats = [];
    renderChatList(e.message);
    if (state.status?.connected) toast(e.message);
  }
}

function renderChatList(errorMsg = '') {
  const list = $('#chatList');
  const hasTg = !!state.status?.connected;
  if (errorMsg) {
    list.dataset.sig = '';
    list.innerHTML = emptyBox('Чаты не загрузились', errorMsg,
      hasTg ? '' : '<button class="btn primary sm" data-goto="settings">Подключить Telegram</button>');
    return;
  }
  const q = $('#chatSearch').value.trim().toLowerCase();
  const sort = $('#chatSort').value;
  let items = state.chats.filter(c =>
    `${c.name} ${c.username || ''} ${c.last_message_text || ''}`.toLowerCase().includes(q));
  if (sort === 'unread') items.sort((a, b) => b.unread_count - a.unread_count);
  else if (sort === 'ai') items = items.filter(c => c.ai_enabled);
  else items.sort((a, b) => (b.last_message_date || '').localeCompare(a.last_message_date || ''));

  $('#chatCount').textContent = state.chats.length ? `${state.chats.length} личных` : 'Личные чаты';

  if (!items.length) {
    list.dataset.sig = '';
    list.innerHTML = state.chats.length
      ? emptyBox('Ничего не найдено', 'Попробуйте другое имя или смените фильтр.')
      : hasTg
        ? emptyBox('Личных чатов пока нет', 'Здесь появятся диалоги с людьми. Группы сюда не попадают.')
        : emptyBox('Telegram не подключён', 'Подключите аккаунт в настройках, и личные чаты появятся здесь.',
            '<button class="btn primary sm" data-goto="settings">Подключить Telegram</button>');
    return;
  }

  // unchanged list: no DOM work at all (the live stream and the polling both call this often)
  const sig = JSON.stringify([q, sort, state.selected?.id || '',
    items.map(c => [c.id, c.name, c.last_message_text, c.last_message_date, c.unread_count, c.ai_enabled])]);
  if (list.dataset.sig === sig) return;
  list.dataset.sig = sig;

  const first = !state.listAnimated;
  list.classList.toggle('list-rise', first);
  if (first) {
    state.listAnimated = true;
    setTimeout(() => list.classList.remove('list-rise'), 1300);
  }
  list.innerHTML = items.map((c, i) => `
    <button class="chat-row${state.selected?.id === c.id ? ' selected' : ''}${LIVE.fresh.has(c.id) ? ' fresh' : ''}" data-chat="${esc(c.id)}" style="--i:${Math.min(i, 14)}">
      ${avatarHTML(c)}
      <span class="chat-main">
        <span class="chat-top"><span class="name">${esc(c.name)}</span><time>${esc(fmtTime(c.last_message_date))}</time></span>
        <span class="chat-bottom">
          <span class="preview">${esc(c.last_message_text || 'Нет сообщений')}</span>
          ${c.ai_enabled ? '<span class="ai-badge" title="AI включён в этом чате">AI</span>' : ''}
          ${c.unread_count ? `<span class="unread">${c.unread_count}</span>` : ''}
        </span>
      </span>
    </button>`).join('');
}

$('#chatList').addEventListener('click', ev => {
  const row = ev.target.closest('[data-chat]');
  if (row) {
    SFX.open();
    haptic('light');
    openChat(row.dataset.chat);
  }
});
$('#chatSearch').addEventListener('input', () => renderChatList());
$('#chatSort').addEventListener('change', () => renderChatList());

/* ---------- conversation ---------- */
async function openChat(id) {
  const chat = state.chats.find(c => c.id === String(id));
  if (!chat) return;
  state.selected = chat;
  state.chatAI = {enabled: !!chat.ai_enabled, mode: chat.ai_mode || 'friendly'};
  state.messages = [];
  renderChatList();
  renderTitle();
  renderChatPane();
  markChatRead(chat);
  await loadMessages(false);
}

function closeChat() {
  state.selected = null;
  state.messages = [];
  renderChatList();
  renderTitle();
  renderChatPane();
}

function renderChatPane() {
  const pane = $('#chatPane');
  const c = state.selected;
  if (!c) {
    pane.innerHTML = emptyBox('Выберите чат',
      'Откройте диалог слева, чтобы читать переписку, отвечать и включать AI.',
      state.status?.connected ? '' : '<button class="btn primary sm" data-goto="settings">Подключить Telegram</button>');
    return;
  }
  pane.innerHTML = `
    <div class="chat-tools">
      <button class="switch" id="aiToggle" role="switch" aria-checked="false" aria-label="AI-ответы в этом чате"><span></span></button>
      <div class="tools-text"><b>AI-ответы</b><span id="aiState"></span></div>
      <select id="chatMode" class="select" aria-label="Режим ИИ">${modeOptions(state.chatAI.mode)}</select>
      <button class="btn sm" id="draftBtn" type="button">${icon('spark')}Предложить ответ</button>
    </div>
    <div id="messages" class="messages">
      <div class="skel"></div>
      <div class="skel" style="width:70%;margin-left:auto"></div>
    </div>
    <div class="attach-chip" id="attachChip" hidden></div>
    <form class="composer glass" id="sendForm">
      <button class="icon-btn" type="button" id="attachBtn" aria-label="Прикрепить фото" title="Прикрепить фото">${icon('image')}</button>
      <input type="file" id="attachFile" accept="image/*" hidden>
      <textarea id="messageText" rows="1" maxlength="4000" placeholder="Написать сообщение" aria-label="Текст сообщения"></textarea>
      <span class="voice-timer" id="voiceTimer" hidden>0:00</span>
      <button class="voice-btn" type="button" id="voiceBtn" aria-label="Записать голосовое" title="Голосовое">${icon('mic')}</button>
      <button class="voice-pick" type="button" id="voicePick" aria-label="Выбор голоса" title="Выбор голоса">${icon('wave')}</button>
      <div class="glass voice-pop" id="voicePop" role="dialog" aria-label="Выбор голоса">
        <button type="button" class="voice-opt" data-voice="normal"><span>Нормальный</span><small>как есть</small></button>
        <button type="button" class="voice-opt" data-voice="rough"><span>Грубый</span><small>анонимный</small></button>
        <input type="range" class="voice-range" id="voiceRange" min="0.1" max="1" step="0.1" aria-label="Сила грубого голоса">
        <div class="voice-range-row"><span>0.1</span><span id="voiceLevel">0.5</span><span>1</span></div>
      </div>
      <button class="send" type="submit" aria-label="Отправить">${icon('send')}</button>
    </form>`;
  const form = $('#sendForm');
  const ta = $('#messageText');
  $('#aiToggle').addEventListener('click', () => saveAI(!state.chatAI.enabled, $('#chatMode').value));
  $('#chatMode').addEventListener('change', e => saveAI(state.chatAI.enabled, e.target.value));
  $('#draftBtn').addEventListener('click', makeDraft);
  form.addEventListener('submit', sendMessage);
  wireVoice();
  $('#attachBtn').addEventListener('click', () => $('#attachFile').click());
  $('#attachFile').addEventListener('change', e => setAttachment(e.target.files?.[0]));
  if (state.attachmentChat !== c.id) { state.attachment = null; state.attachmentChat = c.id; }
  ta.addEventListener('input', autoGrow);
  ta.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing && matchMedia('(min-width:900px)').matches) {
      e.preventDefault();
      form.requestSubmit();
    }
  });
  renderChatTools();
  renderAttachChip();
}

function renderChatTools() {
  const sw = $('#aiToggle');
  if (!sw) return;
  const on = !!state.chatAI.enabled;
  sw.classList.toggle('on', on);
  sw.setAttribute('aria-checked', String(on));
  $('#aiState').textContent = on ? 'Включены · язык определяет сам' : 'Выключены';
  const sel = $('#chatMode');
  if (sel && sel.value !== state.chatAI.mode) sel.value = state.chatAI.mode;
}

function autoGrow(ev) {
  const t = ev.target;
  t.style.height = 'auto';
  t.style.height = Math.min(t.scrollHeight, 140) + 'px';
}

async function loadMessages(silent) {
  const chat = state.selected;
  if (!chat) return;
  try {
    const d = await api(`/telegram/chats/${encodeURIComponent(chat.id)}/messages?limit=80`);
    if (!state.selected || state.selected.id !== chat.id) return;
    state.chatAI = d.ai || state.chatAI;
    renderChatTools();
    syncMessages(d.items || [], silent);
  } catch (e) {
    if (!silent) toast(e.message);
    const box = $('#messages');
    if (box && !silent && !state.messages.length) box.innerHTML = emptyBox('Переписка не открылась', e.message);
  }
}

/* only the difference reaches the DOM: nothing when unchanged, appended nodes when new messages arrived */
function syncMessages(items, silent) {
  const box = $('#messages');
  if (!box || !state.selected) return;
  const prev = state.messages;
  const sameChat = box.dataset.chat === state.selected.id;
  if (sameChat && prev.length === items.length && prev.every((m, i) => m.id === items[i].id && m.text === items[i].text)) return;
  const lastId = prev.length ? prev[prev.length - 1].id : null;
  const k = sameChat && lastId !== null ? items.findIndex(m => m.id === lastId) : -1;
  const aligned = k >= 0 && k + 1 <= prev.length && prev.slice(prev.length - (k + 1)).every((m, i) => m.id === items[i].id);
  state.messages = items;
  if (aligned && items.length > k + 1) appendMessageNodes(items.slice(k + 1), !silent, !silent);
  else renderMessages(silent);
}

function renderMessages(silent) {
  const box = $('#messages');
  if (!box || !state.selected) return;
  const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 140;
  const keep = box.scrollTop;
  box.dataset.chat = state.selected.id;
  if (!state.messages.length) {
    box.innerHTML = '<div class="empty-inline">В этой переписке пока нет сообщений.</div>';
    return;
  }
  box.innerHTML = '';
  appendMessageNodes(state.messages, false, false);
  box.scrollTop = (!silent || nearBottom) ? box.scrollHeight : keep;
}

// links in a message become clickable; the rest of the text is escaped as before
const URL_RE = /\b(?:https?:\/\/|www\.)[^\s<>"']+/gi;
function linkify(text) {
  const src = String(text ?? '');
  let out = '';
  let last = 0;
  for (const m of src.matchAll(URL_RE)) {
    const raw = m[0];
    const url = raw.replace(/[.,!?;:)\]]+$/, '');
    if (!url) continue;
    const href = /^www\./i.test(url) ? 'https://' + url : url;
    out += esc(src.slice(last, m.index)) +
      `<a href="${esc(href)}" data-ext target="_blank" rel="noopener noreferrer">${esc(url)}</a>${esc(raw.slice(url.length))}`;
    last = m.index + raw.length;
  }
  return out + esc(src.slice(last));
}

const MEDIA_LABEL = {photo: 'Фото', video: 'Видео', gif: 'Анимация', sticker: 'Стикер', voice: 'Голосовое', audio: 'Аудио', file: 'Файл', other: 'Вложение'};
function fmtSize(bytes) {
  const n = Number(bytes) || 0;
  if (n >= 1048576) return (n / 1048576).toFixed(1).replace('.', ',') + ' МБ';
  return Math.max(1, Math.round(n / 1024)) + ' КБ';
}

// photos and videos load from the server's media endpoint; a file that is too big or unknown gets a short note
function mediaHTML(m) {
  if (!m.media) return '';
  const label = MEDIA_LABEL[m.media] || 'Вложение';
  const sizeText = m.media_size ? fmtSize(m.media_size) : '';
  if (!m.media_url) return `<div class="media media-note">${esc(label)}${sizeText ? ' · ' + esc(sizeText) : ''}. Откройте в Telegram</div>`;
  const src = esc(m.media_url);
  if (m.media === 'photo') return `<button class="media" type="button" data-zoom="${src}" aria-label="Открыть фото"><img src="${src}" alt="Фото" loading="lazy" decoding="async"></button>`;
  if (m.media === 'sticker' && /tgsticker/.test(m.media_mime || '')) return '<div class="media media-note">Анимированный стикер</div>';
  if (m.media === 'sticker') return `<div class="media media-sticker"><img src="${src}" alt="Стикер" loading="lazy" decoding="async"></div>`;
  if (m.media === 'gif') return `<div class="media"><video src="${src}" autoplay muted loop playsinline preload="auto" aria-label="Анимация"></video></div>`;
  if (m.media === 'video') return `<div class="media"><video src="${src}" controls playsinline preload="metadata" aria-label="Видео"></video></div>`;
  if (m.media === 'voice' || m.media === 'audio') return `<div class="media media-audio"><audio src="${src}" controls preload="none"></audio></div>`;
  if (m.media === 'file') {
    return `<a class="file-chip" href="${src}" download="${esc(m.media_name || 'file')}">${esc(m.media_name || 'Файл')}${sizeText ? `<small>${esc(sizeText)}</small>` : ''}</a>`;
  }
  return `<div class="media media-note">${esc(label)}</div>`;
}

function messageHTML(m, other, animate) {
  const who = m.author || (m.is_out ? 'Вы' : other);
  const media = mediaHTML(m);
  const text = m.text ? `<div class="msg-text">${linkify(m.text)}</div>` : '';
  return `
    <div class="msg ${m.is_out ? 'out' : 'in'}${animate ? ' anim' : ''}" data-mid="${esc(m.id)}">
      ${m.is_out ? '' : avatarHTML(state.selected, 'xs')}
      <div class="bubble-wrap">
        <div class="bubble${media ? ' has-media' : ''}">${media}${text}</div>
        <div class="meta">${esc(who)} · ${esc(fmtTime(m.timestamp))}</div>
      </div>
    </div>`;
}

// a picture or video that fails to load shows a short message instead of a broken icon
document.addEventListener('error', ev => {
  const el = ev.target;
  if (!(el instanceof HTMLImageElement || el instanceof HTMLVideoElement)) return;
  const holder = el.closest('.media');
  if (holder) holder.classList.add('broken');
}, true);

function openLightbox(src) {
  const box = $('#lightbox');
  $('#lightboxImg').src = src;
  box.hidden = false;
}

function closeLightbox() {
  const box = $('#lightbox');
  if (!box || box.hidden) return;
  box.hidden = true;
  $('#lightboxImg').removeAttribute('src');
}

$('#lightbox').addEventListener('click', closeLightbox);
document.addEventListener('keydown', ev => { if (ev.key === 'Escape') closeLightbox(); });
$('#chatPane').addEventListener('click', ev => {
  const zoom = ev.target.closest && ev.target.closest('[data-zoom]');
  if (zoom) openLightbox(zoom.dataset.zoom);
});

function appendMessageNodes(list, animate, forceBottom) {
  const box = $('#messages');
  if (!box || !state.selected || !list.length) return;
  const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 140;
  const other = state.selected.name || 'Собеседник';
  box.querySelector('.empty-inline')?.remove();
  let html = '';
  for (const m of list) {
    const idx = state.messages.indexOf(m);
    const prev = idx > 0 ? state.messages[idx - 1] : null;
    if (!prev || dayKey(prev.timestamp) !== dayKey(m.timestamp)) {
      html += `<div class="day">${esc(dayLabel(m.timestamp))}</div>`;
    }
    html += messageHTML(m, other, animate);
  }
  box.insertAdjacentHTML('beforeend', html);
  if (forceBottom || nearBottom) box.scrollTop = box.scrollHeight;
}

async function saveAI(enabled, mode) {
  const chat = state.selected;
  if (!chat) return;
  try {
    const d = await api(`/telegram/chats/${encodeURIComponent(chat.id)}/ai`, {method: 'PUT', body: {enabled, mode}});
    state.chatAI = {enabled: !!d.enabled, mode: d.mode || mode};
    chat.ai_enabled = state.chatAI.enabled;
    chat.ai_mode = state.chatAI.mode;
    renderChatTools();
    renderChatList();
    toast(state.chatAI.enabled ? 'AI-ответы включены для этого чата' : 'AI-ответы выключены');
  } catch (e) {
    toast(e.message);
    renderChatTools();
  }
}

async function makeDraft() {
  const chat = state.selected;
  if (!chat) return;
  const btn = $('#draftBtn');
  btn.disabled = true;
  btn.innerHTML = '<span class="dots" aria-label="ИИ пишет черновик"><i></i><i></i><i></i></span>';
  try {
    const d = await api('/ai/draft', {method: 'POST', body: {chat_id: chat.id, mode: $('#chatMode').value}});
    const list = (Array.isArray(d.variants) && d.variants.length ? d.variants : [d.draft]).filter(Boolean);
    showVariants(list, d.language);
    SFX.ai();
    haptic('success');
    toast('Ответы готовы' + (d.language ? ' · ' + d.language : '') + '. Выберите один и отправьте его сами', 'ok');
  } catch (e) {
    SFX.error();
    haptic('error');
    toast(e.message, 'bad');
  } finally {
    btn.disabled = false;
    btn.innerHTML = icon('spark') + 'Предложить ответ';
  }
}

/* ---------- reply variants: the AI offers two replies; the person picks one, then sends it */
function hideVariants() {
  $('#variants')?.remove();
}

function showVariants(list, language) {
  hideVariants();
  const form = $('#sendForm');
  if (!form || !list.length) return;
  const box = document.createElement('div');
  box.id = 'variants';
  box.className = 'variants';
  box.setAttribute('role', 'group');
  box.setAttribute('aria-label', 'Варианты ответа');
  box.innerHTML = `
    <div class="variants-head">
      <span>${list.length > 1 ? 'Два варианта ответа' : 'Вариант ответа'}${language ? ' · ' + esc(language) : ''}</span>
      <button class="variants-x" type="button" data-variants-close aria-label="Скрыть варианты">×</button>
    </div>
    ${list.map((text, i) => `<button class="variant" type="button" data-variant="${i}">${esc(text)}</button>`).join('')}`;
  box.addEventListener('click', ev => {
    if (ev.target.closest('[data-variants-close]')) return hideVariants();
    const pick = ev.target.closest('[data-variant]');
    if (!pick) return;
    const ta = $('#messageText');
    if (ta) {
      ta.value = list[Number(pick.dataset.variant)] || '';
      autoGrow({target: ta});
      ta.focus();
    }
    hideVariants();
  });
  form.before(box);
}

/* ---------- voice messages: record, change the voice, send ---------- */
const VOICE = {
  mode: localStorage.getItem('nezzx_voice_mode') || 'normal',
  level: Number(localStorage.getItem('nezzx_voice_level')) || 0.5,
  rec: null, stream: null, chunks: [], timer: null, startedAt: 0, chatId: null, sendAfter: true,
};

function paintVoicePick() {
  const pick = $('#voicePick');
  if (!pick) return;
  pick.classList.toggle('on', VOICE.mode === 'rough');
  $$('.voice-opt').forEach(b => b.classList.toggle('on', b.dataset.voice === VOICE.mode));
  const range = $('#voiceRange');
  range.value = VOICE.level;
  range.disabled = VOICE.mode !== 'rough';
  $('#voiceLevel').textContent = VOICE.level.toFixed(1);
}

function setVoiceMode(mode) {
  VOICE.mode = mode;
  localStorage.setItem('nezzx_voice_mode', mode);
  paintVoicePick();
}

function setVoiceLevel(v) {
  const n = Math.min(1, Math.max(0.1, Math.round(Number(v) * 10) / 10));
  VOICE.level = n;
  localStorage.setItem('nezzx_voice_level', String(n));
  paintVoicePick();
}

function wireVoice() {
  const btn = $('#voiceBtn');
  const pick = $('#voicePick');
  const pop = $('#voicePop');
  if (!btn || !pick || !pop) return;
  paintVoicePick();
  btn.addEventListener('click', toggleVoiceRec);
  pick.addEventListener('click', e => { e.stopPropagation(); pop.classList.toggle('open'); });
  pop.addEventListener('click', e => e.stopPropagation());
  $$('.voice-opt').forEach(b => b.addEventListener('click', () => {
    setVoiceMode(b.dataset.voice);
    if (VOICE.mode === 'rough') pop.classList.add('open');
  }));
  $('#voiceRange').addEventListener('input', e => setVoiceLevel(e.target.value));
  if (!window.__voicePopBound) {
    window.__voicePopBound = true;
    document.addEventListener('click', () => { const p = $('#voicePop'); if (p) p.classList.remove('open'); });
  }
}

function tickVoiceTimer() {
  const s = Math.floor((Date.now() - VOICE.startedAt) / 1000);
  const t = $('#voiceTimer');
  if (t) t.textContent = Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');
}

async function toggleVoiceRec() {
  if (VOICE.rec) { stopVoiceRec(true); return; }
  const chat = state.selected;
  if (!chat) return;
  if (!navigator.mediaDevices || !window.MediaRecorder) {
    toast('Этот браузер не умеет записывать звук', 'bad');
    return;
  }
  try {
    VOICE.stream = await navigator.mediaDevices.getUserMedia({audio: true});
  } catch {
    toast('Нет доступа к микрофону. Разрешите его в браузере', 'bad');
    return;
  }
  VOICE.chatId = chat.id;
  VOICE.chunks = [];
  VOICE.sendAfter = true;
  const rec = new MediaRecorder(VOICE.stream);
  rec.ondataavailable = e => { if (e.data && e.data.size) VOICE.chunks.push(e.data); };
  rec.onstop = () => finishVoiceRec();
  rec.start(250);
  VOICE.rec = rec;
  VOICE.startedAt = Date.now();
  const btn = $('#voiceBtn');
  btn.classList.add('rec');
  btn.innerHTML = icon('stop');
  $('#voiceTimer').hidden = false;
  tickVoiceTimer();
  VOICE.timer = setInterval(tickVoiceTimer, 250);
  haptic('soft');
}

function stopVoiceRec(send) {
  if (!VOICE.rec) return;
  VOICE.sendAfter = send;
  VOICE.rec.stop();
}

async function finishVoiceRec() {
  const send = VOICE.sendAfter !== false;
  clearInterval(VOICE.timer);
  VOICE.timer = null;
  const chunks = VOICE.chunks;
  const chatId = VOICE.chatId;
  const seconds = Math.max(1, Math.round((Date.now() - VOICE.startedAt) / 1000));
  if (VOICE.stream) VOICE.stream.getTracks().forEach(t => t.stop());
  VOICE.rec = null; VOICE.stream = null; VOICE.chunks = []; VOICE.sendAfter = true;
  const btn = $('#voiceBtn');
  if (btn) { btn.classList.remove('rec'); btn.innerHTML = icon('mic'); }
  const t = $('#voiceTimer');
  if (t) t.hidden = true;
  if (!send || !chunks.length) return;
  if (btn) btn.classList.add('busy');
  try {
    const raw = new Blob(chunks, {type: chunks[0].type || 'audio/webm'});
    const wav = await voiceToWav(raw, VOICE.mode, VOICE.level);
    await uploadVoice(chatId, wav);
    SFX.sent();
    haptic('soft');
    await loadMessages(false);
    await loadChats();
  } catch (e) {
    SFX.error();
    haptic('error');
    toast(e.message || 'Не удалось отправить голосовое', 'bad');
  } finally {
    if (btn) btn.classList.remove('busy');
  }
}

async function voiceToWav(blob, mode, level) {
  const Ctx = window.AudioContext || window.webkitAudioContext;
  const ctx = new Ctx();
  const decoded = await ctx.decodeAudioData(await blob.arrayBuffer());
  if (ctx.close) ctx.close();
  const rendered = mode === 'rough' ? await roughRender(decoded, level) : decoded;
  return encodeWav(rendered);
}

function driveCurve(amount) {
  const n = 1024;
  const curve = new Float32Array(n);
  for (let i = 0; i < n; i++) {
    const x = (i * 2) / n - 1;
    curve[i] = Math.tanh(amount * x) / Math.tanh(amount);
  }
  return curve;
}

// the rough voice: lower pitch, grit, a tremolo wobble and a darker top end; k = strength 0.1..1
async function roughRender(src, level) {
  const k = Math.min(1, Math.max(0.1, level));
  const rate = 1 - 0.32 * k;
  const len = Math.ceil(src.length / rate);
  const off = new OfflineAudioContext(1, len, src.sampleRate);
  const node = off.createBufferSource();
  node.buffer = src;
  node.playbackRate.value = rate;
  const hp = off.createBiquadFilter();
  hp.type = 'highpass';
  hp.frequency.value = 140;
  const shaper = off.createWaveShaper();
  shaper.curve = driveCurve(1 + 22 * k);
  shaper.oversample = '4x';
  const lp = off.createBiquadFilter();
  lp.type = 'lowpass';
  lp.frequency.value = 4200 - 2600 * k;
  const trem = off.createGain();
  trem.gain.value = 1 - 0.35 * k;
  const lfo = off.createOscillator();
  lfo.frequency.value = 28 + 40 * k;
  const lfoDepth = off.createGain();
  lfoDepth.gain.value = 0.35 * k;
  lfo.connect(lfoDepth);
  lfoDepth.connect(trem.gain);
  const out = off.createGain();
  out.gain.value = 0.9;
  node.connect(hp); hp.connect(shaper); shaper.connect(lp); lp.connect(trem); trem.connect(out); out.connect(off.destination);
  lfo.start(0);
  node.start(0);
  const rendered = await off.startRendering();
  return normalizeBuffer(rendered, 0.92);
}

function normalizeBuffer(buf, peak) {
  const data = buf.getChannelData(0);
  let max = 0;
  for (let i = 0; i < data.length; i++) { const a = Math.abs(data[i]); if (a > max) max = a; }
  if (max > 0) {
    const g = peak / max;
    for (let i = 0; i < data.length; i++) data[i] *= g;
  }
  return buf;
}

// 16-bit mono WAV: the browser sends this, the server turns it into OGG/Opus
function encodeWav(buf) {
  const ch = buf.numberOfChannels;
  const n = buf.length;
  const rate = buf.sampleRate;
  const mono = new Float32Array(n);
  for (let c = 0; c < ch; c++) {
    const d = buf.getChannelData(c);
    for (let i = 0; i < n; i++) mono[i] += d[i] / ch;
  }
  const bytes = new ArrayBuffer(44 + n * 2);
  const view = new DataView(bytes);
  const put = (off, str) => { for (let i = 0; i < str.length; i++) view.setUint8(off + i, str.charCodeAt(i)); };
  put(0, 'RIFF'); view.setUint32(4, 36 + n * 2, true); put(8, 'WAVE');
  put(12, 'fmt '); view.setUint32(16, 16, true); view.setUint16(20, 1, true); view.setUint16(22, 1, true);
  view.setUint32(24, rate, true); view.setUint32(28, rate * 2, true); view.setUint16(32, 2, true); view.setUint16(34, 16, true);
  put(36, 'data'); view.setUint32(40, n * 2, true);
  let off = 44;
  for (let i = 0; i < n; i++) {
    const s = Math.max(-1, Math.min(1, mono[i]));
    view.setInt16(off, s < 0 ? s * 0x8000 : s * 0x7fff, true);
    off += 2;
  }
  return new Blob([bytes], {type: 'audio/wav'});
}

async function uploadVoice(chatId, wav) {
  if (!chatId) throw new Error('Чат не выбран');
  const res = await fetch(`/api/telegram/chats/${encodeURIComponent(chatId)}/voice`, {
    method: 'POST', credentials: 'same-origin', headers: {'Content-Type': 'audio/wav'}, body: wav,
  });
  let data = {};
  try { data = await res.json(); } catch {}
  if (!res.ok) {
    throw new Error(typeof data.detail === 'string' ? data.detail : 'Не удалось отправить голосовое');
  }
  return data;
}

// the send button flies off once, so the message visibly leaves the composer
function launchSend(btn) {
  if (!btn || !motionOK()) return;
  btn.classList.remove('launch');
  void btn.offsetWidth;
  btn.classList.add('launch');
  setTimeout(() => btn.classList.remove('launch'), 520);
}

async function sendMessage(ev) {
  ev.preventDefault();
  const chat = state.selected;
  const input = $('#messageText');
  const text = input.value.trim();
  const att = state.attachment;
  if (!chat || (!text && !att)) return;
  const btn = ev.submitter || ev.target.querySelector('button[type="submit"]');
  if (btn) btn.disabled = true;
  try {
    const body = {text};
    if (att) {
      body.image = att.dataUrl.slice(att.dataUrl.indexOf(',') + 1);
      body.mime_type = 'image/jpeg';
      body.filename = 'photo.jpg';
    }
    await api(`/telegram/chats/${encodeURIComponent(chat.id)}/send`, {method: 'POST', body});
    input.value = '';
    state.attachment = null;
    renderAttachChip();
    autoGrow({target: input});
    SFX.sent();
    haptic('soft');
    launchSend(btn);
    await loadMessages(false);
    await loadChats();
  } catch (e) {
    SFX.error();
    haptic('error');
    toast(e.message, 'bad');
  } finally {
    if (btn) btn.disabled = false;
    input.focus();
  }
}

function blobToDataURL(blob) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(r.result);
    r.onerror = () => reject(new Error('Не удалось прочитать фото'));
    r.readAsDataURL(blob);
  });
}

async function setAttachment(file) {
  if (!file) return;
  if (!/^image\//.test(file.type || '')) { toast('Выберите изображение'); return; }
  try {
    const blob = await resizeImage(file, 1600, 0.86);
    state.attachment = {dataUrl: await blobToDataURL(blob)};
    renderAttachChip();
  } catch (e) {
    toast(e.message, 'bad');
  } finally {
    const input = $('#attachFile');
    if (input) input.value = '';
  }
}

function renderAttachChip() {
  const chip = $('#attachChip');
  if (!chip) return;
  if (!state.attachment) { chip.style.display = 'none'; chip.innerHTML = ''; return; }
  chip.style.cssText = 'display:flex;align-items:center;gap:10px;margin:0 12px 8px;padding:6px 8px;border-radius:14px;background:rgba(0,0,0,.3)';
  chip.innerHTML = `<img alt="" src="${state.attachment.dataUrl}" style="width:44px;height:44px;object-fit:cover;border-radius:10px"><span style="flex:1;font-size:12.5px">Фото прикреплено</span><button type="button" class="variants-x" id="attachRemove" aria-label="Убрать фото">×</button>`;
  $('#attachRemove').addEventListener('click', () => { state.attachment = null; renderAttachChip(); });
}

/* ---------- system prompt tab ---------- */
async function renderPrompt() {
  const page = $('#promptPage');
  if (!state.promptLoaded) {
    try {
      const d = await api('/ai/prompt');
      state.promptText = d.prompt || '';
    } catch (e) {
      toast(e.message, 'bad');
    }
    state.promptLoaded = true;
  }
  const value = state.promptText || '';
  page.innerHTML = `
    <section class="card">
      <h2>Системный промпт</h2>
      <p class="lead">Ваши указания для ИИ: тон, стиль, что можно и нельзя говорить, как представляться. Они добавляются к правилам безопасности, которые ИИ не отменяет.</p>
      <textarea id="promptText" maxlength="4000" placeholder="Например: отвечай коротко, без эмодзи, не называй цены, предлагай созвониться" style="width:100%;min-height:240px;padding:12px;border-radius:14px;border:1px solid var(--line);background:transparent;color:inherit;font:inherit;resize:vertical;box-sizing:border-box">${esc(value)}</textarea>
      <div class="btn-row" style="margin-top:12px">
        <span class="muted" id="promptCount">${value.length}/4000</span>
        <button class="btn primary" data-action="save-prompt" type="button">Сохранить</button>
      </div>
    </section>`;
  stagger(page);
  $('#promptText').addEventListener('input', e => {
    state.promptText = e.target.value;
    $('#promptCount').textContent = e.target.value.length + '/4000';
  });
}

async function savePrompt() {
  const text = (state.promptText || '').trim();
  try {
    await api('/ai/prompt', {method: 'PUT', body: {prompt: text}});
    state.promptText = text;
    SFX.ai();
    haptic('success');
    toast('Промпт сохранён', 'ok');
  } catch (e) {
    SFX.error();
    toast(e.message, 'bad');
  }
}

/* ---------- AI ---------- */
function renderAI(fromRefresh) {
  const page = $('#aiPage');
  const d = state.aiStats || {};
  page.innerHTML = `
    <div class="stats">
      <div class="stat">
        <div class="k" style="font:600 15px/1.3 var(--f-body);letter-spacing:0;overflow-wrap:anywhere">${esc(d.model || 'claude-opus-4.8')}</div>
        <div class="l">${d.configured ? `${esc(AI_NAMES[d.provider] || 'tokenharbor')} API подключён` : 'Добавьте TOKENHARBOR_API_KEY'}</div>
      </div>
      <div class="stat"><div class="k">${d.today?.auto_sent || 0}</div><div class="l">Автоответов за 24 ч</div></div>
      <div class="stat"><div class="k">${d.today?.drafts || 0}</div><div class="l">Черновиков за 24 ч</div></div>
      <div class="stat"><div class="k">${d.today?.total || 0}</div><div class="l">Операций всего</div></div>
    </div>
    <div class="mode-list">
      ${Object.keys(MODE_NAMES).map(k => `
        <article class="mode">
          <span class="tag">${esc(MODE_TAG[k])}</span>
          <div><h3>${esc(MODE_NAMES[k])}</h3><p>${esc(MODE_DESC[k])}</p></div>
        </article>`).join('')}
    </div>
    <section class="card">
      <h2>Как это работает</h2>
      <p class="lead">Автоответ включается отдельно в каждом чате и срабатывает только после входящего сообщения. ИИ не пишет первым и не делает рассылок. Черновик можно проверить и поправить перед отправкой.</p>
      <p class="lead">Язык ИИ определяет сам по собеседнику и отвечает на том же языке.</p>
      <p class="lead">«Предложить ответ» даёт два варианта: выбранный попадает в поле ввода, а отправляете его вы. Автоответ отправляет первый вариант.</p>
      <p class="lead" style="margin:0">ИИ не выдумывает цены и гарантии и не просит пароли или коды входа.</p>
      <div class="btn-row" style="margin-top:14px">
        <button class="btn primary" data-nav="chats">Выбрать чат</button>
        <button class="btn" data-nav="settings">Проверить API</button>
      </div>
    </section>`;
  stagger(page);
  if (!fromRefresh) {
    const before = JSON.stringify(state.aiStats);
    loadAIStats().then(() => {
      if (state.tab === 'ai' && JSON.stringify(state.aiStats) !== before) renderAI(true);
    });
  }
}

/* ---------- overview ---------- */
function renderOverview() {
  const page = $('#overviewPage');
  const st = state.status || {};
  const ai = state.aiStats || {};
  const s = state.chatStats || {};
  page.innerHTML = `
    <div class="stats">
      <div class="stat"><div class="k">${s.count || 0}</div><div class="l">Личных чатов</div></div>
      <div class="stat"><div class="k">${s.unread_count || 0}</div><div class="l">Непрочитанных</div></div>
      <div class="stat"><div class="k">${s.ai_active_count || 0}</div><div class="l">С включённым AI</div></div>
      <div class="stat"><div class="k">${ai.today?.auto_sent || 0}</div><div class="l">Автоответов за 24 ч</div></div>
    </div>
    <section class="card">
      <h2>Подключения</h2>
      <div class="kv"><span>Telegram-аккаунт</span>${pill(st.connected, st.connected ? 'Подключён' : 'Не подключён')}</div>
      <div class="kv"><span>tokenharbor API</span>${pill(st.ai_configured, st.ai_configured ? 'Готов' : 'Нужен ключ')}</div>
      <div class="kv"><span>Модель</span><b>${esc(ai.model || 'claude-opus-4.8')}</b></div>
    </section>
    <section class="card">
      <h2>Быстрый старт</h2>
      <p class="lead">Подключите Telegram по номеру, откройте диалог и отметьте, где AI может отвечать. Первое сообщение всегда отправляете вы.</p>
      <div class="btn-row">
        <button class="btn primary" data-nav="chats">Открыть чаты</button>
        <button class="btn" data-nav="settings">Настройки</button>
      </div>
    </section>`;
  stagger(page);
}

/* ---------- settings ---------- */
function renderSettings() {
  const page = $('#settingsPage');
  const s = state.session || {};
  const expires = s.forever ? 'Без срока'
    : s.expires_at ? new Date(s.expires_at * 1000).toLocaleString('ru-RU', {day: 'numeric', month: 'long', hour: '2-digit', minute: '2-digit'})
    : '—';
  page.innerHTML = `
    <section class="card" id="tgCard"><h2>Telegram-аккаунт</h2><div class="skel"></div></section>
    <section class="card" id="aiCard"><h2>tokenharbor API</h2><div class="skel"></div></section>
    <section class="card" id="bgCard"><h2>Фон сайта</h2><div class="skel"></div></section>
    <section class="card" id="fxCard"></section>
    <section class="card">
      <h2>Доступ</h2>
      <div class="kv"><span>Тариф</span><b>${esc(s.plan_title || 'Ключ доступа')}</b></div>
      <div class="kv"><span>Действует до</span><b>${esc(expires)}</b></div>
      <div class="kv"><span>Версия</span><b>${esc(s.version || '6.0.0')}</b></div>
      <div class="btn-row" style="margin-top:14px">
        ${state.config?.telegram_bot_url ? `<a class="btn" href="${esc(state.config.telegram_bot_url)}" target="_blank" rel="noopener">Открыть бота</a>` : ''}
        <button class="btn" data-action="fullscreen">${icon('expand')}Во весь экран</button>
        <button class="btn danger" data-action="logout">Выйти</button>
      </div>
    </section>`;
  stagger(page);
  renderBackgroundCard();
  renderFxCard();
  loadStatus().then(st => {
    if (state.tab !== 'settings') return;
    renderTelegramCard(st);
    renderAICard(st);
  });
}

function renderTelegramCard(st) {
  const card = $('#tgCard');
  const on = !!st.connected;
  const who = st.username ? '@' + st.username : (st.phone || 'Аккаунт');
  card.innerHTML = `
    <h2>Telegram-аккаунт</h2>
    <div class="kv"><span>${on ? esc(who) : 'Аккаунт не подключён'}</span>${pill(on, on ? 'Подключён' : 'Отключён')}</div>
    ${on ? `
      <p class="hint" style="margin:12px 0">Сессия хранится на сервере в зашифрованном виде. Код и пароль 2FA не сохраняются.</p>
      <button class="btn danger block" id="tgDisconnect" type="button">Отключить аккаунт</button>`
    : `
      <p class="lead" style="margin:12px 0">Вход по номеру через официальный Telegram MTProto. Код придёт в приложение Telegram.</p>
      ${st.api_configured ? '' : '<p class="error" style="margin:0 0 12px">Не заданы TELEGRAM_API_ID и TELEGRAM_API_HASH в Render → Environment.</p>'}
      <form id="phoneForm" class="stack">
        <label class="field"><span>Номер с кодом страны</span>
          <input class="input" id="phone" inputmode="tel" autocomplete="tel" placeholder="+374…" required></label>
        <div class="error" id="tgError"></div>
        <button class="btn primary block" id="phoneSubmit" type="submit">Отправить код</button>
      </form>
      <form id="codeForm" class="stack" hidden>
        <label class="field"><span>Код из Telegram</span>
          <input class="input" id="tgCode" autocomplete="one-time-code" inputmode="numeric" placeholder="Код из Telegram" required></label>
        <div class="error" id="codeError"></div>
        <button class="btn primary block" type="submit" id="codeSubmit">Подтвердить код</button>
      </form>
      <form id="passwordForm" class="stack" hidden>
        <label class="field"><span>Пароль двухэтапной проверки</span>
          <input class="input" type="password" id="tgPassword" autocomplete="current-password" required></label>
        <p class="hint" style="margin:0">Пароль нужен только для входа и нигде не сохраняется.</p>
        <div class="error" id="passwordError"></div>
        <button class="btn primary block" type="submit" id="passwordSubmit">Войти в Telegram</button>
      </form>`}`;
  bindTelegramForms();
}

function renderAICard(st) {
  $('#aiCard').innerHTML = `
    <h2>tokenharbor API</h2>
    <div class="kv"><span>Подключение</span>${pill(st.ai_configured, st.ai_configured ? 'Подключено' : 'Не настроено')}</div>
    <p class="hint" style="margin:12px 0 0">Адрес cleanapis.com/v1, модель claude-opus-4.8. Ключ встроен в сервер и может быть переопределён через TOKENHARBOR_API_KEY в Render → Environment, модель через TOKENHARBOR_MODEL. Лимиты тарифа смотрите на tokenharbor.ai/pricing. Ключ хранится на сервере и в браузер не попадает.</p>`;
}

function bindTelegramForms() {
  const pf = $('#phoneForm');
  if (pf) pf.addEventListener('submit', async e => {
    e.preventDefault();
    const b = $('#phoneSubmit');
    b.disabled = true;
    $('#tgError').textContent = '';
    try {
      await api('/telegram/login/start', {method: 'POST', body: {phone: $('#phone').value.trim()}});
      $('#codeForm').hidden = false;
      $('#tgCode').focus();
      toast('Код отправлен в Telegram');
    } catch (err) {
      $('#tgError').textContent = err.message;
    } finally {
      b.disabled = false;
    }
  });

  const cf = $('#codeForm');
  if (cf) cf.addEventListener('submit', async e => {
    e.preventDefault();
    const b = $('#codeSubmit');
    b.disabled = true;
    $('#codeError').textContent = '';
    try {
      const d = await api('/telegram/login/complete', {method: 'POST', body: {code: $('#tgCode').value.trim()}});
      if (d.needs_password) {
        $('#passwordForm').hidden = false;
        $('#tgPassword').focus();
      } else {
        await afterTelegramConnect();
      }
    } catch (err) {
      $('#codeError').textContent = err.message;
    } finally {
      b.disabled = false;
    }
  });

  const pw = $('#passwordForm');
  if (pw) pw.addEventListener('submit', async e => {
    e.preventDefault();
    const b = $('#passwordSubmit');
    b.disabled = true;
    $('#passwordError').textContent = '';
    try {
      await api('/telegram/login/password', {method: 'POST', body: {password: $('#tgPassword').value}});
      $('#tgPassword').value = '';
      await afterTelegramConnect();
    } catch (err) {
      $('#passwordError').textContent = err.message;
    } finally {
      b.disabled = false;
    }
  });

  const disc = $('#tgDisconnect');
  if (disc) disc.addEventListener('click', async () => {
    if (!confirm('Отключить Telegram и удалить сохранённую серверную сессию?')) return;
    try {
      await api('/telegram/logout', {method: 'POST'});
      state.selected = null;
      state.messages = [];
      await loadStatus();
      toast('Telegram отключён');
      renderSettings();
      loadChats();
    } catch (err) {
      toast(err.message);
    }
  });
}

async function afterTelegramConnect() {
  await loadStatus();
  await loadChats();
  toast('Telegram подключён');
  go('chats');
}

/* ---------- admin ---------- */
function renderAdmin() {
  if (!state.session?.is_admin) { go('chats'); return; }
  const page = $('#adminPage');
  page.innerHTML = `
    <section class="card keygen">
      <h2 style="margin:0">Создать ключ</h2>
      <select id="admDuration" class="select" aria-label="Срок действия" style="width:100%">
        <option value="1h">1 час</option><option value="6h">6 часов</option><option value="12h">12 часов</option>
        <option value="24h" selected>1 день</option><option value="36h">1,5 дня</option><option value="3d">3 дня</option>
        <option value="7d">7 дней</option><option value="30d">30 дней</option><option value="forever">Навсегда</option>
      </select>
      <div class="row">
        <input id="admTg" class="input grow" inputmode="numeric" placeholder="Telegram ID (необязательно)">
        <button id="admCreate" class="btn primary" type="button">Создать</button>
      </div>
      <div id="admOut" class="keygen-out"></div>
    </section>
    <section class="card">
      <div class="row" style="justify-content:space-between;margin-bottom:12px">
        <h2 style="margin:0">Последние ключи</h2>
        <button class="btn sm" id="admRefresh" type="button">${icon('refresh')}Обновить</button>
      </div>
      <div id="adminKeys" class="stack"><div class="skel"></div><div class="skel"></div></div>
    </section>`;
  stagger(page);
  $('#admCreate').addEventListener('click', createKey);
  $('#admRefresh').addEventListener('click', loadAdminKeys);
  loadAdminKeys();
}

async function createKey() {
  const btn = $('#admCreate');
  btn.disabled = true;
  try {
    const d = await api('/admin/licenses', {method: 'POST', body: {
      duration: $('#admDuration').value,
      telegram_user_id: Number($('#admTg').value || 0),
    }});
    $('#admOut').innerHTML = `Новый ключ: <code>${esc(d.key)}</code> <button class="btn sm" id="admCopy" type="button">Копировать</button>`;
    $('#admCopy').addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(d.key); toast('Ключ скопирован'); }
      catch { toast('Не удалось скопировать. Выделите ключ вручную'); }
    });
    loadAdminKeys();
  } catch (e) {
    toast(e.message);
  } finally {
    btn.disabled = false;
  }
}

async function loadAdminKeys() {
  const box = $('#adminKeys');
  if (!box) return;
  try {
    const d = await api('/admin/licenses');
    const items = (d.items || []).slice(0, 50);
    box.innerHTML = items.length
      ? items.map(k => `
          <div class="key-row">
            <div style="min-width:0"><code>${esc(k.key)}</code>
              <small>${esc(k.plan_id)} · ${k.active ? 'активен' : k.revoked ? 'отозван' : 'истёк'}</small></div>
            ${k.active ? `<button class="btn danger sm" data-revoke="${esc(k.key)}" type="button">Отозвать</button>` : ''}
          </div>`).join('')
      : emptyBox('Ключей пока нет', 'Создайте первый ключ выше.');
    box.querySelectorAll('[data-revoke]').forEach(b => b.addEventListener('click', async () => {
      if (!confirm('Отозвать этот ключ?')) return;
      try {
        await api('/admin/licenses/revoke', {method: 'POST', body: {key: b.dataset.revoke}});
        loadAdminKeys();
      } catch (e) { toast(e.message); }
    }));
  } catch (e) {
    box.innerHTML = `<p class="error">${esc(e.message)}</p>`;
  }
}

boot();

</script>
</body>
</html>
'''


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=PORT)
