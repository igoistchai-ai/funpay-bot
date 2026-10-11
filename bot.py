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
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, parse_qsl, urljoin, urlparse

from bs4 import BeautifulSoup
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
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
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash").strip() or "gemini-2.5-flash"
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
APP_VERSION = "6.0.0"
ADMIN_TELEGRAM_ID = int(os.getenv("ADMIN_TELEGRAM_ID", "8357023784"))
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
        conn.execute("""CREATE TABLE IF NOT EXISTS ai_message_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            chat_id TEXT NOT NULL,
            direction TEXT NOT NULL,
            mode TEXT NOT NULL DEFAULT 'friendly',
            created_at INTEGER NOT NULL
        )""")
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
    if plan_id == "admin":
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
        forever = self.plan_id in ("forever", "admin_forever")
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
        "forever": plan_id in ("forever", "admin_forever"),
        "license_hint": (license_key or "")[-4:],
        "expires_at": expires_at,
        "remaining_seconds": max(0, expires_at - now),
        "server_time": now,
        "version": APP_VERSION,
    }


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
    password_ok = bool(DASHBOARD_PASSWORD and supplied and hmac.compare_digest(supplied, DASHBOARD_PASSWORD))

    if is_tg_admin or password_ok:
        expires = now + ADMIN_SESSION_SECONDS
        token = create_web_session("admin", "admin", True, None, expires, user_agent)
        plan_id, is_admin, license_key = "admin", True, None
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
            "telegram_enabled": bool(TELEGRAM_BOT_TOKEN), "telegram_user_login_configured": bool(TELEGRAM_API_ID.isdigit() and TELEGRAM_API_HASH), "ai_configured": bool(GEMINI_API_KEY), "server_time": now_ts()}


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
    text: str = Field(min_length=1, max_length=4000)

class ChatAISettingsBody(BaseModel):
    enabled: bool = False
    mode: str = Field(default="friendly", min_length=1, max_length=40)

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
Если человек отказался или просит прекратить общение, ответь вежливо один раз и рекомендуй выключить автоматические ответы для этого чата. Никаких массовых первых сообщений: генерируй только ответ на полученное входящее сообщение в чате, который пользователь явно включил для AI.
Возвращай только текст предполагаемого ответа — без кавычек, пояснений и markdown."""


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


def _log_ai(owner: str, chat_id: str, direction: str, mode: str) -> None:
    with db() as conn:
        conn.execute("INSERT INTO ai_message_log(owner,chat_id,direction,mode,created_at) VALUES(?,?,?,?,?)",
                     (owner, str(chat_id), direction, mode, now_ts()))


def _telethon_client(session_string: str = ""):
    TelegramClient, events, StringSession, _ = _telethon_imports()
    return TelegramClient(StringSession(session_string), int(TELEGRAM_API_ID), TELEGRAM_API_HASH,
                          **_tg_device_kwargs())


async def _install_ai_listener(owner: str, client: Any) -> None:
    marker = f"{owner}:{id(client)}"
    if marker in TG_LISTENERS:
        return
    _, events, _, _ = _telethon_imports()

    async def on_incoming(event: Any) -> None:
        if not event.is_private or not event.message or not (event.raw_text or "").strip():
            return
        chat_id = str(event.chat_id)
        settings = _ai_settings(owner, chat_id)
        if not settings["enabled"]:
            return
        key = f"{owner}:{chat_id}"
        current = time.time()
        if current - TG_SEND_GUARD.get(key, 0) < 20:
            return
        # Safety brake: at most 30 automated replies per owner per rolling process-day.
        day_key = f"{owner}:day:{datetime.now(timezone.utc).date().isoformat()}"
        sent_today = TG_SEND_GUARD.get(day_key, 0)
        if sent_today >= 30:
            return
        TG_SEND_GUARD[key] = current
        try:
            history = await _load_tg_messages(client, chat_id, 12)
            reply = await _generate_ai_reply(history, settings["mode"])
            if not reply:
                return
            await client.send_message(event.chat_id, reply, reply_to=event.message.id)
            TG_SEND_GUARD[day_key] = sent_today + 1
            _log_ai(owner, chat_id, "auto_sent", settings["mode"])
        except Exception as exc:
            log.warning("AI reply failed (%s)", type(exc).__name__)

    client.add_event_handler(on_incoming, events.NewMessage(incoming=True))
    TG_LISTENERS.add(marker)


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
    out = []
    async for message in client.iter_messages(entity, limit=max(1, min(limit, 100))):
        sender = None
        try:
            sender = await message.get_sender()
        except Exception:
            pass
        name = "Вы" if message.out else (getattr(sender, "first_name", None) or getattr(sender, "title", None) or "Собеседник")
        if message.out and getattr(sender, "last_name", None):
            name += " " + sender.last_name
        out.append({"id": int(message.id), "text": message.message or ("[Медиа]" if message.media else "[Сообщение]"),
                    "author": name, "is_out": bool(message.out),
                    "timestamp": message.date.isoformat() if message.date else "", "media": bool(message.media)})
    return list(reversed(out))


async def _generate_ai_reply(messages: list[dict[str, Any]], mode: str) -> str:
    if not GEMINI_API_KEY:
        raise HTTPException(status_code=503, detail="Добавьте GEMINI_API_KEY в переменные окружения Render.")
    mode = mode if mode in AI_MODES else "friendly"
    transcript = [{"role": "assistant" if m.get("is_out") else "user", "content": str(m.get("text", ""))[:2500]}
                  for m in messages[-16:] if str(m.get("text", "")).strip()]
    if not transcript:
        raise HTTPException(status_code=422, detail="В чате пока нет текстовых сообщений для ответа.")
    contents = []
    for item in transcript:
        role = "model" if item["role"] == "assistant" else "user"
        contents.append({"role": role, "parts": [{"text": item["content"]}]})
    body = {
        "systemInstruction": {"parts": [{"text": AI_SYSTEM_PROMPT + "\n\nСтиль выбранного режима: " + AI_MODES[mode]}]},
        "contents": contents,
        "generationConfig": {"temperature": 0.75, "maxOutputTokens": 220},
    }
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
    request = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    def do_request() -> dict[str, Any]:
        with urllib.request.urlopen(request, timeout=35) as response:
            return json.loads(response.read().decode("utf-8"))
    try:
        data = await asyncio.to_thread(do_request)
    except Exception as exc:
        log.warning("Gemini request failed (%s)", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Gemini не ответил. Проверьте GEMINI_API_KEY и доступность модели.") from exc
    try:
        text = "".join(part.get("text", "") for part in data["candidates"][0]["content"]["parts"]).strip()
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Gemini вернул пустой или неизвестный ответ.") from exc
    if not text:
        raise HTTPException(status_code=502, detail="ИИ вернул пустой ответ.")
    return text[:4000]


@app.get("/api/telegram/status")
async def telegram_status(session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    init_db()
    with db() as conn:
        row = conn.execute("SELECT phone,username,updated_at FROM telegram_accounts WHERE owner=?", (session.owner,)).fetchone()
    if not row:
        return {"connected": False, "api_configured": bool(TELEGRAM_API_ID.isdigit() and TELEGRAM_API_HASH),
                "ai_configured": bool(GEMINI_API_KEY)}
    connected = False
    try:
        client = await _tg_client_for(session.owner)
        connected = bool(await client.is_user_authorized())
    except Exception:
        connected = False
    return {"connected": connected, "phone": row["phone"], "username": row["username"],
            "updated_at": row["updated_at"], "api_configured": bool(TELEGRAM_API_ID.isdigit() and TELEGRAM_API_HASH),
            "ai_configured": bool(GEMINI_API_KEY)}


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


@app.get("/api/telegram/chats")
async def telegram_chats(session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    client = await _tg_client_for(session.owner)
    rows = []
    async for dialog in client.iter_dialogs(limit=300):
        if not dialog.is_user:  # personal chats only: groups, channels and supergroups are skipped
            continue
        entity = dialog.entity
        title = dialog.name or getattr(entity, "username", None) or str(dialog.id)
        last = dialog.message
        settings = _ai_settings(session.owner, str(dialog.id))
        rows.append({"id": str(dialog.id), "name": title, "username": getattr(entity, "username", None),
                     "unread_count": int(dialog.unread_count or 0),
                     "last_message_text": (getattr(last, "message", "") or ("[Медиа]" if getattr(last, "media", None) else ""))[:300] if last else "",
                     "last_message_date": last.date.isoformat() if last and last.date else "",
                     "is_user": bool(getattr(entity, "bot", None) is not None or hasattr(entity, "first_name")),
                     "ai_enabled": settings["enabled"], "ai_mode": settings["mode"]})
    return {"items": rows, "count": len(rows), "unread_count": sum(x["unread_count"] for x in rows),
            "ai_active_count": sum(1 for x in rows if x["ai_enabled"])}


@app.get("/api/telegram/chats/{chat_id}/messages")
async def telegram_messages(chat_id: str, limit: int = 80, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    client = await _tg_client_for(session.owner)
    items = await _load_tg_messages(client, chat_id, limit)
    return {"items": items, "count": len(items), "ai": _ai_settings(session.owner, chat_id)}


@app.post("/api/telegram/chats/{chat_id}/send")
async def telegram_send_message(chat_id: str, payload: TelegramSendBody, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    text = payload.text.strip()
    if not text:
        raise HTTPException(status_code=422, detail="Сообщение пустое.")
    client = await _tg_client_for(session.owner)
    try:
        entity = await client.get_entity(int(chat_id))
        message = await client.send_message(entity, text)
    except Exception as exc:
        log.warning("Telegram send failed (%s)", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Не удалось отправить сообщение в Telegram.") from exc
    return {"ok": True, "id": message.id, "text": message.message or text}


@app.put("/api/telegram/chats/{chat_id}/ai")
async def telegram_chat_ai(chat_id: str, payload: ChatAISettingsBody, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    if payload.mode not in AI_MODES:
        raise HTTPException(status_code=422, detail="Неизвестный режим ИИ.")
    if payload.enabled and not GEMINI_API_KEY:
        raise HTTPException(status_code=503, detail="Добавьте GEMINI_API_KEY в переменные окружения Render.")
    with db() as conn:
        conn.execute("""INSERT INTO ai_chat_settings(owner,chat_id,enabled,mode,updated_at) VALUES(?,?,?,?,?)
            ON CONFLICT(owner,chat_id) DO UPDATE SET enabled=excluded.enabled, mode=excluded.mode, updated_at=excluded.updated_at""",
            (session.owner, str(chat_id), 1 if payload.enabled else 0, payload.mode, now_ts()))
    return {"ok": True, **_ai_settings(session.owner, chat_id)}


@app.post("/api/ai/draft")
async def ai_draft(payload: AIDraftBody, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    if payload.mode not in AI_MODES:
        raise HTTPException(status_code=422, detail="Неизвестный режим ИИ.")
    client = await _tg_client_for(session.owner)
    history = await _load_tg_messages(client, payload.chat_id, 20)
    draft = await _generate_ai_reply(history, payload.mode)
    _log_ai(session.owner, payload.chat_id, "draft", payload.mode)
    return {"draft": draft, "mode": payload.mode}


@app.get("/api/ai/status")
async def ai_status(session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    with db() as conn:
        row = conn.execute("""SELECT COUNT(*) AS total, SUM(CASE WHEN direction='auto_sent' THEN 1 ELSE 0 END) AS auto_sent,
            SUM(CASE WHEN direction='draft' THEN 1 ELSE 0 END) AS drafts FROM ai_message_log WHERE owner=? AND created_at>=?""",
            (session.owner, now_ts()-86400)).fetchone()
    return {"configured": bool(GEMINI_API_KEY), "model": GEMINI_MODEL, "modes": AI_MODE_LABELS,
            "today": {"total": int(row["total"] or 0), "auto_sent": int(row["auto_sent"] or 0), "drafts": int(row["drafts"] or 0)}}


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
    if not GEMINI_API_KEY:
        log.warning("GEMINI_API_KEY not set; AI replies and drafts are disabled.")
    if not DASHBOARD_PASSWORD:
        log.warning("DASHBOARD_PASSWORD is not set; sign-in works with license keys only.")
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
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://telegram.org; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; "
    "img-src 'self' data: blob: https:; connect-src 'self'; object-src 'none'; base-uri 'none'; "
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
  background:var(--bg) url("data:image/jpeg;base64,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") center/cover no-repeat;
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
  -webkit-backdrop-filter:blur(26px) saturate(1.5);backdrop-filter:blur(26px) saturate(1.5);
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

.chat-pane.glass{background:rgba(10,14,12,.8)}

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
  -webkit-backdrop-filter:blur(10px);backdrop-filter:blur(10px);
}
.msg.out .bubble{background:linear-gradient(160deg,#ffc58f,#ff9f6a);color:#24130a;border-color:transparent;border-radius:19px 19px 6px 19px}
.meta{font-size:11px;color:var(--faint);padding:0 4px}
.composer{display:flex;align-items:flex-end;gap:8px;margin:0 10px calc(10px + env(safe-area-inset-bottom,0px));padding:7px 7px 7px 16px;border-radius:26px;flex:none}
.composer textarea{background:transparent;border:0;padding:9px 0;min-height:24px;max-height:140px;box-shadow:none}
.composer textarea:focus{box-shadow:none}
.send{
  width:44px;height:44px;border-radius:50%;flex:none;display:grid;place-items:center;
  background:linear-gradient(160deg,var(--accent-hi),var(--accent));color:var(--accent-ink);
  box-shadow:0 8px 22px rgba(255,179,107,.3);transition:transform .2s var(--spring);
}
.send:active{transform:scale(.88)}
.send:disabled{opacity:.5}

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

/* ---------- motion ---------- */
@keyframes rise{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
@keyframes pop{from{opacity:0;transform:scale(.94) translateY(12px)}to{opacity:1;transform:none}}
@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{animation-duration:.01ms!important;animation-delay:0ms!important;transition-duration:.01ms!important}
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

  <div id="shell" class="shell hidden" data-tab="chats" data-mode="list">
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
                  <span id="chatCount" class="muted">Личные чаты</span>
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

        <section class="view" data-view="ai"><div class="page" id="aiPage"></div></section>
        <section class="view" data-view="overview"><div class="page" id="overviewPage"></div></section>
        <section class="view" data-view="settings"><div class="page" id="settingsPage"></div></section>
        <section class="view" data-view="admin"><div class="page" id="adminPage"></div></section>
      </div>
    </main>

    <nav class="tabbar glass" id="tabbar" aria-label="Разделы">
      <span class="indicator" id="indicator"></span>
    </nav>
  </div>
</div>

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
};
const icon = name => `<svg class="i" viewBox="0 0 24 24" aria-hidden="true">${ICON[name] || ''}</svg>`;
const hydrateIcons = () => $$('[data-icon]').forEach(el => { el.innerHTML = icon(el.dataset.icon); });

const TABS = [
  {id: 'chats',    label: 'Чаты',      icon: 'chat'},
  {id: 'ai',       label: 'AI',        icon: 'spark'},
  {id: 'overview', label: 'Обзор',     icon: 'grid'},
  {id: 'settings', label: 'Настройки', icon: 'sliders'},
  {id: 'admin',    label: 'Админ',     icon: 'shield', admin: true},
];
const TAB_TITLE = {chats: 'Чаты', ai: 'AI Conv', overview: 'Обзор', settings: 'Настройки', admin: 'Админка'};
const TAB_SUB = {
  ai: 'Четыре стиля общения на Gemini',
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
  tab: 'chats', listAnimated: false, fsTries: 0, toastTimer: 0, pollTimer: 0,
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

function toast(msg) {
  const el = $('#toast');
  el.textContent = msg;
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
    av.textContent = initials(sel.name);
    av.style.setProperty('--h', hueOf(sel.name));
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
  else if (tab === 'overview') renderOverview();
  else if (tab === 'settings') renderSettings();
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
}

/* one delegated handler for every [data-nav], [data-goto] and [data-action] */
document.addEventListener('click', ev => {
  const nav = ev.target.closest('[data-nav]');
  if (nav) return go(nav.dataset.nav);
  const goto = ev.target.closest('[data-goto]');
  if (goto) return go(goto.dataset.goto);
  const act = ev.target.closest('[data-action]');
  if (!act) return;
  const a = act.dataset.action;
  if (a === 'logout') logout();
  else if (a === 'back') closeChat();
  else if (a === 'refresh') refreshCurrent();
  else if (a === 'fullscreen') toggleFullscreen();
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
  state.pollTimer = setInterval(() => { if (state.session && !document.hidden) loadChats(); }, 15000);
}
document.addEventListener('visibilitychange', () => { if (!document.hidden && state.session) loadChats(); });
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
   VIEWS: chats, conversation, AI, overview, settings, admin
   ================================================================ */
const pill = (ok, text) => `<span class="pill${ok ? ' ok' : ''}"><span class="dot"></span>${esc(text)}</span>`;
const stagger = root => Array.from(root.children).forEach((el, i) => el.style.setProperty('--i', Math.min(i, 12)));
const modeOptions = sel => Object.keys(MODE_NAMES)
  .map(k => `<option value="${k}"${k === sel ? ' selected' : ''}>${esc(MODE_NAMES[k])}</option>`).join('');

/* ---------- chat list (personal chats only: the server already drops groups) ---------- */
async function loadChats() {
  try {
    const d = await api('/telegram/chats');
    state.chats = (d.items || []).filter(c => c.is_user !== false);
    state.chatStats = {
      count: d.count ?? state.chats.length,
      unread_count: d.unread_count ?? 0,
      ai_active_count: d.ai_active_count ?? 0,
    };
    if (state.selected) {
      const fresh = state.chats.find(c => c.id === state.selected.id);
      if (fresh) state.selected = fresh;
      else { state.selected = null; state.messages = []; renderTitle(); renderChatPane(); }
    }
    renderChatList();
    renderTitle();
    if (state.selected) await loadMessages(true);
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
    list.innerHTML = state.chats.length
      ? emptyBox('Ничего не найдено', 'Попробуйте другое имя или смените фильтр.')
      : hasTg
        ? emptyBox('Личных чатов пока нет', 'Здесь появятся диалоги с людьми. Группы сюда не попадают.')
        : emptyBox('Telegram не подключён', 'Подключите аккаунт в настройках, и личные чаты появятся здесь.',
            '<button class="btn primary sm" data-goto="settings">Подключить Telegram</button>');
    return;
  }

  const first = !state.listAnimated;
  list.classList.toggle('list-rise', first);
  if (first) {
    state.listAnimated = true;
    setTimeout(() => list.classList.remove('list-rise'), 1300);
  }
  list.innerHTML = items.map((c, i) => `
    <button class="chat-row${state.selected?.id === c.id ? ' selected' : ''}" data-chat="${esc(c.id)}" style="--i:${Math.min(i, 14)}">
      <span class="avatar" style="--h:${hueOf(c.name)}">${esc(initials(c.name))}</span>
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
  if (row) openChat(row.dataset.chat);
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
    <form class="composer glass" id="sendForm">
      <textarea id="messageText" rows="1" maxlength="4000" placeholder="Написать сообщение" aria-label="Текст сообщения"></textarea>
      <button class="send" type="submit" aria-label="Отправить">${icon('send')}</button>
    </form>`;
  const form = $('#sendForm');
  const ta = $('#messageText');
  $('#aiToggle').addEventListener('click', () => saveAI(!state.chatAI.enabled, $('#chatMode').value));
  $('#chatMode').addEventListener('change', e => saveAI(state.chatAI.enabled, e.target.value));
  $('#draftBtn').addEventListener('click', makeDraft);
  form.addEventListener('submit', sendMessage);
  ta.addEventListener('input', autoGrow);
  ta.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing && matchMedia('(min-width:900px)').matches) {
      e.preventDefault();
      form.requestSubmit();
    }
  });
  renderChatTools();
}

function renderChatTools() {
  const sw = $('#aiToggle');
  if (!sw) return;
  const on = !!state.chatAI.enabled;
  sw.classList.toggle('on', on);
  sw.setAttribute('aria-checked', String(on));
  $('#aiState').textContent = on ? 'Включены в этом чате' : 'Выключены';
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
    state.messages = d.items || [];
    state.chatAI = d.ai || state.chatAI;
    renderChatTools();
    renderMessages(silent);
  } catch (e) {
    if (!silent) toast(e.message);
    const box = $('#messages');
    if (box && !silent && !state.messages.length) box.innerHTML = emptyBox('Переписка не открылась', e.message);
  }
}

function renderMessages(silent) {
  const box = $('#messages');
  if (!box) return;
  const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 140;
  if (!state.messages.length) {
    box.innerHTML = '<div class="empty-inline">В этой переписке пока нет сообщений.</div>';
    return;
  }
  const other = state.selected?.name || 'Собеседник';
  let lastDay = '';
  let html = '';
  state.messages.forEach((m, i) => {
    const key = dayKey(m.timestamp);
    if (key && key !== lastDay) {
      html += `<div class="day">${esc(dayLabel(m.timestamp))}</div>`;
      lastDay = key;
    }
    const who = m.author || (m.is_out ? 'Вы' : other);
    html += `
      <div class="msg ${m.is_out ? 'out' : 'in'}${silent ? '' : ' anim'}" style="--i:${Math.min(i, 10)}">
        ${m.is_out ? '' : `<span class="avatar xs" style="--h:${hueOf(who)}">${esc(initials(who))}</span>`}
        <div class="bubble-wrap">
          <div class="bubble">${esc(m.text)}</div>
          <div class="meta">${esc(who)} · ${esc(fmtTime(m.timestamp))}</div>
        </div>
      </div>`;
  });
  box.innerHTML = html;
  if (!silent || nearBottom) box.scrollTop = box.scrollHeight;
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
  btn.textContent = 'Думаю…';
  try {
    const d = await api('/ai/draft', {method: 'POST', body: {chat_id: chat.id, mode: $('#chatMode').value}});
    const ta = $('#messageText');
    ta.value = d.draft;
    autoGrow({target: ta});
    ta.focus();
    toast('Черновик готов. Проверьте текст и отправьте его сами');
  } catch (e) {
    toast(e.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = icon('spark') + 'Предложить ответ';
  }
}

async function sendMessage(ev) {
  ev.preventDefault();
  const chat = state.selected;
  const input = $('#messageText');
  const text = input.value.trim();
  if (!chat || !text) return;
  const btn = ev.submitter || ev.target.querySelector('button[type="submit"]');
  if (btn) btn.disabled = true;
  try {
    await api(`/telegram/chats/${encodeURIComponent(chat.id)}/send`, {method: 'POST', body: {text}});
    input.value = '';
    autoGrow({target: input});
    await loadMessages(false);
    await loadChats();
  } catch (e) {
    toast(e.message);
  } finally {
    if (btn) btn.disabled = false;
    input.focus();
  }
}

/* ---------- AI ---------- */
function renderAI(fromRefresh) {
  const page = $('#aiPage');
  const d = state.aiStats || {};
  page.innerHTML = `
    <div class="stats">
      <div class="stat">
        <div class="k" style="font:600 15px/1.3 var(--f-body);letter-spacing:0;overflow-wrap:anywhere">${esc(d.model || 'gemini-2.5-flash')}</div>
        <div class="l">${d.configured ? 'API подключён' : 'Добавьте GEMINI_API_KEY'}</div>
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
      <div class="kv"><span>Gemini API</span>${pill(st.ai_configured, st.ai_configured ? 'Готов' : 'Нужен ключ')}</div>
      <div class="kv"><span>Модель</span><b>${esc(ai.model || 'gemini-2.5-flash')}</b></div>
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
    <section class="card" id="aiCard"><h2>Google Gemini</h2><div class="skel"></div></section>
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
    <h2>Google Gemini</h2>
    <div class="kv"><span>Подключение</span>${pill(st.ai_configured, st.ai_configured ? 'Подключено' : 'Не настроено')}</div>
    <p class="hint" style="margin:12px 0 0">Ключ GEMINI_API_KEY задаётся в Render → Environment, модель меняется через GEMINI_MODEL. Ключ никогда не попадает в браузер.</p>`;
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
