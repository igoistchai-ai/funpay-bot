"""FunPay Lister v5 — single-file FastAPI service + Telegram bot.

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
APP_VERSION = "5.0.0"
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
log = logging.getLogger("funpay_lister")


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
            detail="Библиотека FunPay не установлена. Добавьте funpay-api-python в requirements.txt.",
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


app = FastAPI(title="FunPay Lister", version=APP_VERSION, docs_url=None, redoc_url=None, openapi_url=None)


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


@app.get("/api/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "version": APP_VERSION, "uptime_seconds": int(time.monotonic() - START_TIME),
            "telegram_enabled": bool(TELEGRAM_BOT_TOKEN), "server_time": now_ts()}


@app.get("/api/session")
async def session_info(session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    return session.payload()


@app.get("/api/notifications")
async def notifications(after: int = 0, session: SessionInfo = Depends(get_session)) -> dict[str, Any]:
    items, last_seq = notifications_after(session.owner, max(0, int(after)))
    return {"items": items, "last_seq": last_seq, "session": session.payload()}


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
            "<b>FunPay Lister</b>\n"
            "Офферы, поиск по каталогу, чаты и заказы в одной панели.\n\n"
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
                menu_button=MenuButtonWebApp(text="Lister", web_app=WebAppInfo(url=RENDER_EXTERNAL_URL)))
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
    tasks = [
        asyncio.create_task(poll_loop(), name="fp-poll"),
        asyncio.create_task(expiry_loop(), name="fp-expiry"),
        asyncio.create_task(keepalive_loop(), name="fp-keepalive"),
    ]
    if TELEGRAM_BOT_TOKEN:
        try:
            await _start_telegram(app_)
        except Exception as exc:
            log.exception("Telegram bot initialization failed: %s", type(exc).__name__)
            TG_APP = TG_BOT = None
    else:
        log.warning("TELEGRAM_BOT_TOKEN is not set; the web panel still starts.")
    if FUNPAY_GOLDEN_KEY_ENV and not FP_CONNS.get("admin") and not load_fp_account("admin"):
        tasks.append(asyncio.create_task(_bootstrap_admin_account(), name="fp-bootstrap"))
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
<meta name="theme-color" content="#070708">
<meta name="robots" content="noindex,nofollow">
<title>FunPay Lister</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap">
<style>
:root{
  --bg:#070708;--panel:#0f0f11;--panel2:#15151a;--panel3:#1c1c22;--field:#0b0b0d;
  --text:#ededf0;--muted:#8e8e97;--faint:#5b5b64;
  --line:rgba(255,255,255,.12);--line2:rgba(255,255,255,.2);--line3:rgba(255,255,255,.34);
  --white:#fff;--danger:#ff8f8f;
  --r:14px;--r2:11px;--kb:0px;--vh:100dvh;--bg-opacity:.2;--bg-image:none;
  --shadow:0 22px 70px rgba(0,0,0,.6);
  --font:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;
  color-scheme:dark;
}
*{box-sizing:border-box}
html,body{height:100%;margin:0}
html{-webkit-text-size-adjust:100%;touch-action:manipulation}
body{background:var(--bg);color:var(--text);font:400 15px/1.45 var(--font);-webkit-font-smoothing:antialiased;overflow:hidden;overscroll-behavior:none}
body::before{content:"";position:fixed;inset:0;z-index:-2;background:var(--bg-image) center/cover no-repeat;opacity:var(--bg-opacity);filter:grayscale(.55) brightness(.8);pointer-events:none}
body::after{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;background:radial-gradient(1100px 620px at 18% -12%,rgba(255,255,255,.07),transparent 62%),linear-gradient(180deg,rgba(7,7,8,.25),rgba(7,7,8,.93) 72%)}
button,input,textarea,select{font:inherit;color:inherit}
button{cursor:pointer;-webkit-tap-highlight-color:transparent}
a{color:inherit}
[hidden]{display:none!important}
:focus-visible{outline:2px solid var(--white);outline-offset:2px}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.mono{font-variant-numeric:tabular-nums}
.muted{color:var(--muted)}.faint{color:var(--faint)}.small{font-size:13px}.tiny{font-size:12px}
.row{display:flex;align-items:center;gap:10px;min-width:0}
.between{justify-content:space-between}.grow{flex:1 1 auto;min-width:0}.wrap-row{flex-wrap:wrap}
.stack{display:flex;flex-direction:column;gap:12px;min-width:0}
.grid{display:grid;gap:12px;min-width:0}
.g2{grid-template-columns:repeat(2,minmax(0,1fr))}
.g3{grid-template-columns:repeat(3,minmax(0,1fr))}
@media(max-width:640px){.g3{grid-template-columns:repeat(2,minmax(0,1fr))}.g3>:last-child:nth-child(odd){grid-column:1/-1}}
@media(max-width:380px){.g2{grid-template-columns:minmax(0,1fr)}}
.ellipsis{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}

/* ---- shell ---- */
#app{height:var(--vh);display:grid;grid-template-columns:248px minmax(0,1fr);overflow:hidden}
.side{display:flex;flex-direction:column;gap:18px;padding:18px 12px;min-height:0;overflow:auto;border-right:1px solid var(--line);background:rgba(9,9,11,.93)}
.brand{display:flex;align-items:center;gap:11px;padding:4px 8px}
.brand-name{font-weight:800;letter-spacing:.01em}
.mark{width:36px;height:36px;flex:none;border-radius:11px;border:1px solid var(--line3);display:grid;place-items:center;background:linear-gradient(145deg,#25252c,#0b0b0d);box-shadow:inset 0 1px 0 rgba(255,255,255,.12)}
.mark svg{width:19px;height:19px}
.nav{display:flex;flex-direction:column;gap:4px}
.nav button{display:flex;align-items:center;gap:11px;width:100%;padding:10px 11px;border-radius:var(--r2);border:1px solid transparent;background:none;color:var(--muted);text-align:left;font-weight:600}
.nav button:hover{color:var(--text);border-color:var(--line)}
.nav button[aria-current="page"]{color:#fff;border-color:var(--line3);background:rgba(255,255,255,.07)}
.side-foot{display:flex;flex-direction:column;gap:10px}
.main{display:flex;flex-direction:column;min-width:0;min-height:0}
.topbar{display:flex;align-items:center;gap:8px;padding:12px 22px;min-height:66px;border-bottom:1px solid var(--line);background:rgba(7,7,8,.72);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px)}
.title{font-weight:800;font-size:17px;letter-spacing:.01em;margin-right:auto;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.view{flex:1 1 auto;min-height:0;overflow:auto;padding:22px;display:flex;flex-direction:column;min-width:0;overscroll-behavior:contain}
.view-inner{width:100%;max-width:1120px;margin:0 auto;display:flex;flex-direction:column;gap:16px;min-width:0}
.iconbtn{position:relative;width:42px;height:42px;flex:none;display:grid;place-items:center;border-radius:12px;border:1px solid var(--line2);background:rgba(255,255,255,.025);color:var(--text)}
.iconbtn:hover{border-color:var(--line3);background:rgba(255,255,255,.07)}
.iconbtn svg,.btn svg,.chip svg{width:20px;height:20px}
svg{flex:none}
.li>svg,.nav button svg,.row>svg{width:20px;height:20px}
.badge{position:absolute;top:-6px;right:-6px;min-width:20px;height:20px;padding:0 5px;border-radius:999px;background:#fff;color:#000;font-size:11px;font-weight:800;display:grid;place-items:center;border:2px solid var(--bg)}
.chip{display:inline-flex;align-items:center;gap:8px;height:42px;padding:0 13px;border-radius:12px;border:1px solid var(--line2);background:rgba(255,255,255,.025);color:var(--text);font-weight:700;font-variant-numeric:tabular-nums;white-space:nowrap}
.chip svg{width:17px;height:17px;color:var(--muted)}
.chip.low{border-color:#fff;animation:pulse 1.4s ease-in-out infinite}
@keyframes pulse{50%{box-shadow:0 0 0 4px rgba(255,255,255,.12)}}

/* ---- bottom nav (mobile) ---- */
.bottomnav{display:none}

/* ---- cards and text ---- */
.card{background:linear-gradient(180deg,rgba(255,255,255,.04),rgba(255,255,255,.01)),var(--panel);border:1px solid var(--line2);border-radius:var(--r);padding:16px;box-shadow:inset 0 1px 0 rgba(255,255,255,.05);min-width:0}
.card-h{font-size:12px;letter-spacing:.09em;text-transform:uppercase;color:var(--muted);font-weight:700;margin:0 0 10px}
.kpi{font-size:28px;font-weight:800;letter-spacing:-.02em;font-variant-numeric:tabular-nums;line-height:1.1}
.h1{font-size:22px;font-weight:800;letter-spacing:-.01em;margin:0}
.h2{font-size:17px;font-weight:800;margin:0}
.notice{padding:12px 14px;border-radius:var(--r2);border:1px dashed var(--line3);color:var(--muted);font-size:14px}
.empty{text-align:center;padding:34px 18px;border:1px dashed var(--line2);border-radius:var(--r);color:var(--muted)}
.empty b{display:block;color:var(--text);font-size:16px;margin-bottom:6px}
.error{color:var(--danger);font-size:13px;min-height:18px}
.loading{display:flex;align-items:center;gap:10px;color:var(--muted);padding:14px 2px}
.spin{width:17px;height:17px;flex:none;border-radius:50%;border:2px solid rgba(255,255,255,.2);border-top-color:#fff;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.hr{height:1px;background:var(--line);border:0;margin:4px 0}

/* ---- controls ---- */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;min-height:44px;padding:0 16px;border-radius:12px;border:1px solid var(--line3);background:transparent;color:var(--text);font-weight:700;white-space:nowrap;transition:background .15s,border-color .15s,transform .05s}
.btn:hover{background:rgba(255,255,255,.07);border-color:#fff}
.btn:active{transform:translateY(1px)}
.btn[disabled]{opacity:.45;cursor:not-allowed;transform:none}
.btn-solid{background:#fff;color:#000;border-color:#fff}
.btn-solid:hover{background:#e7e7ec;color:#000}
.btn-ghost{border-color:var(--line2)}
.btn-danger{border-color:rgba(255,143,143,.55);color:#ffb7b7}
.btn-danger:hover{background:rgba(255,143,143,.09);border-color:#ff8f8f}
.btn-sm{min-height:36px;padding:0 12px;font-size:13px;border-radius:10px}
.btn-block{width:100%}
.input,.textarea,.select{width:100%;min-width:0;min-height:44px;padding:10px 13px;border-radius:12px;border:1px solid var(--line2);background:var(--field);color:var(--text);outline:none;transition:border-color .15s,box-shadow .15s}
.textarea{min-height:96px;resize:vertical;line-height:1.45}
.input:focus,.textarea:focus,.select:focus{border-color:#fff;box-shadow:0 0 0 3px rgba(255,255,255,.12)}
.input::placeholder,.textarea::placeholder{color:var(--faint)}
.field{display:flex;flex-direction:column;gap:7px;min-width:0}
.field>label,.label{font-size:12px;letter-spacing:.07em;text-transform:uppercase;color:var(--muted);font-weight:700}
.hint{font-size:12px;color:var(--faint);line-height:1.45}
.pill{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;border:1px solid var(--line2);font-size:12px;font-weight:700;color:var(--muted);white-space:nowrap}
.pill.on{color:#fff;border-color:var(--line3)}
.switch{position:relative;width:46px;height:27px;flex:none}
.switch input{position:absolute;inset:0;width:100%;height:100%;margin:0;opacity:0;cursor:pointer;z-index:1}
.switch .track{position:absolute;inset:0;border-radius:999px;border:1px solid var(--line3);background:#0b0b0d;transition:background .2s,border-color .2s}
.switch .track::after{content:"";position:absolute;top:3px;left:3px;width:19px;height:19px;border-radius:50%;background:#9a9aa3;transition:transform .2s,background .2s}
.switch input:checked+.track{background:#fff;border-color:#fff}
.switch input:checked+.track::after{transform:translateX(19px);background:#000}
.switch input:focus-visible+.track{outline:2px solid #fff;outline-offset:2px}
.check{width:20px;height:20px;accent-color:#fff;margin:0;flex:none}
.tabs{display:flex;gap:6px;padding:4px;border:1px solid var(--line2);border-radius:14px;background:rgba(255,255,255,.02);overflow-x:auto;scrollbar-width:none}
.tabs::-webkit-scrollbar{display:none}
.tabs button{flex:1 0 auto;min-height:38px;padding:0 12px;border-radius:10px;border:1px solid transparent;background:none;color:var(--muted);font-weight:700;white-space:nowrap}
.tabs button[aria-selected="true"]{background:#fff;color:#000}

/* ---- tiles and lists ---- */
.tile{position:relative;width:46px;height:46px;flex:none;border-radius:13px;border:1px solid var(--line2);background:linear-gradient(145deg,#2b2b33,#0f0f12);display:grid;place-items:center;overflow:hidden;font-weight:800;font-size:15px;letter-spacing:.03em;color:#e9e9ef}
.tile img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;background:#0b0b0d;opacity:0;transition:opacity .2s}
.tile img.ok{opacity:1}
.tile.lg{width:64px;height:64px;border-radius:17px;font-size:20px}
.game-grid{display:grid;grid-template-columns:repeat(auto-fill,minm
