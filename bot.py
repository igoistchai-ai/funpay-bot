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
APP_VERSION = "5.1.0"
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
CATALOG_WAIT_SECONDS = 2.5
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
            items = data["items"]
            # Ignore an old cache that contains category cards but no usable sections.
            has_sections = any(
                isinstance(category, dict) and isinstance(category.get("subcategories"), list)
                and bool(category.get("subcategories"))
                for category in items
            )
            if has_sections:
                CATALOG["items"] = items
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


def fallback_catalog_from_html(page_html: str) -> list[dict[str, Any]]:
    """Fallback catalogue parser for changes to FunPay's homepage CSS classes."""
    soup = BeautifulSoup(page_html, "html.parser")
    found: dict[str, dict[str, Any]] = {}
    for link in soup.select("a[href]"):
        href = str(link.get("href") or "").strip()
        path = urlparse(href).path
        match = re.fullmatch(r"/lots/(\d+)/?", path)
        if not match:
            continue
        name = link.get_text(" ", strip=True)
        if not name:
            image = link.find("img")
            name = str(image.get("alt") or "").strip() if image else ""
        sub_id = match.group(1)
        if name and sub_id not in found:
            found[sub_id] = {"id": int(sub_id), "name": name, "icon": None}
    if not found:
        return []
    # If the site's category-card markup changed, still expose every found section
    # so users can open lots instead of getting an entirely empty catalogue.
    return [{"id": "all", "name": "Все разделы FunPay", "icon": None,
             "subcategories": sorted(found.values(), key=lambda row: row["name"].casefold())}]


async def refresh_catalog(conn: FPConn) -> None:
    values = await fp_call(conn, lambda: conn.account.get_categories(), "Не удалось получить каталог FunPay",
                           timeout=min(max(FP_READ_TIMEOUT, 10), 18), retries=0)
    categories = normalize_catalog(values)
    if not categories or not any(category.get("subcategories") for category in categories):
        # get_categories currently relies on FunPay's CSS markup; try a tolerant
        # link-based parser if the homepage was redesigned.
        response = await fp_call(conn, lambda: conn.client.get("", raise_not_200=True), None,
                                 timeout=min(max(FP_READ_TIMEOUT, 10), 18), retries=0)
        categories = fallback_catalog_from_html(response.text)
    if not categories:
        raise HTTPException(status_code=502, detail="FunPay не вернул разделы каталога. Повторите загрузку позже.")
    # Don't fetch a second homepage just to decorate icons; the extra request delayed
    # the actual catalogue and could make it appear to be stuck on mobile.
    for category in categories:
        category.setdefault("icon", None)
        for sub in category.get("subcategories", []):
            sub.setdefault("icon", None)
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
    """Return cached data immediately; on a cold start wait briefly while refreshing in background."""
    global CATALOG_TASK
    fresh = bool(CATALOG["items"]) and time.time() - CATALOG["fetched_at"] < CATALOG_MAX_AGE_SECONDS
    if fresh:
        return
    started = False
    if CATALOG_TASK is None or CATALOG_TASK.done():
        CATALOG_TASK = asyncio.create_task(_catalog_job(owner), name="funpay-catalog")
        started = True
    # Keep stale cached data usable and don't make every frontend poll wait for the same task.
    if CATALOG["items"] or not started:
        return
    try:
        await asyncio.wait_for(asyncio.shield(CATALOG_TASK), timeout=CATALOG_WAIT_SECONDS)
    except asyncio.TimeoutError:
        return
    except Exception:
        return


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
    """Send without retries, then verify the new message in FunPay history when possible.

    Text messages use the library's maintained account.send_message() implementation.
    Image messages use the same library runner transport with FunPay's image_id field.
    """
    node_id = _as_id(chat_id)
    client = conn.client
    message_id: str | None = None
    image_link: str | None = None

    try:
        if image_mode:
            if image_id is None:
                raise HTTPException(status_code=422, detail="Не выбрано изображение для отправки.")
            objects = [{
                "type": "chat_node", "id": node_id, "tag": "00000000",
                "data": {"node": node_id, "last_message": "", "content": ""},
            }]
            request_payload = {"action": "message_send", "data": {
                "node": node_id, "content": "", "image_id": int(image_id),
            }}
            runner_objects = await fp_call(
                conn,
                lambda: client.runner(objects, request=request_payload),
                None, write=True, retries=0,
            )
            for obj in runner_objects or []:
                data = obj.get("data") if isinstance(obj, dict) else None
                msgs = data.get("messages") if isinstance(data, dict) else None
                if isinstance(msgs, list) and msgs and isinstance(msgs[-1], dict):
                    raw_id = msgs[-1].get("id")
                    if raw_id is not None:
                        message_id = str(raw_id)
                    raw_html = msgs[-1].get("html") or ""
                    if raw_html:
                        try:
                            image = BeautifulSoup(str(raw_html), "html.parser").select_one("a.chat-img-link")
                            if image and image.get("href"):
                                image_link = urljoin("https://funpay.com", image["href"])
                        except Exception:
                            pass
        else:
            result = await fp_call(
                conn,
                lambda: conn.account.send_message(node_id, text),
                None, write=True, retries=0,
            )
            data = clean_model(result)
            if isinstance(data, dict) and data.get("message_id") is not None:
                message_id = str(data["message_id"])
    except Exception as exc:
        # A timeout can happen after FunPay received a request. Verify history before
        # telling the user it failed, and never auto-send again (which could duplicate it).
        log.warning("FunPay message send failed: %s", type(exc).__name__)
        for delay in (1.0, 2.0, 3.0):
            await asyncio.sleep(delay)
            found = await _find_sent(conn, chat_id, text, image_mode, known_ids)
            if found:
                return {"message_id": found["id"], "verified": True, "image_link": found.get("image_link")}
        if isinstance(exc, HTTPException):
            raise exc
        raise HTTPException(
            status_code=502,
            detail="FunPay не подтвердил отправку. Проверьте чат в FunPay перед повторной отправкой, чтобы не получить дубль.",
        ) from exc

    if message_id and (known_ids is None or message_id not in known_ids):
        return {"message_id": message_id, "verified": True, "image_link": image_link}
    for delay in (1.0, 2.0, 3.0):
        await asyncio.sleep(delay)
        found = await _find_sent(conn, chat_id, text, image_mode, known_ids)
        if found:
            return {"message_id": found["id"], "verified": True, "image_link": found.get("image_link")}
    # Preserve an explicit unconfirmed state; callers must not report success here.
    return {"message_id": None, "verified": False, "image_link": image_link}


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
@app.get("/api/funpay/orders/counters")
async def orders_counters(session: SessionInfo = Depends(get_session)) -> dict[str, int | None]:
    conn = await conn_for(session.owner)
    values = await fp_call(conn, lambda: conn.account.get_orders_counters(),
                           "Не удалось загрузить счётчики продаж и покупок", timeout=12, retries=0)
    data = clean_model(values)
    if not isinstance(data, dict):
        data = {}
    def counter(value: Any) -> int | None:
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None
    return {"sales": counter(data.get("seller")), "purchases": counter(data.get("buyer"))}


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
    try:
        _library()
    except HTTPException:
        log.warning("FunPay client library is not installed; FunPay features are disabled, the rest of the app runs.")
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
.game-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(148px,1fr));gap:12px}
.game{display:flex;flex-direction:column;align-items:flex-start;gap:12px;min-height:138px;padding:14px;border-radius:var(--r);border:1px solid var(--line2);background:var(--panel);color:var(--text);text-align:left;min-width:0}
.game:hover{border-color:#fff;background:var(--panel2)}
.game .name{font-weight:800;font-size:14px;line-height:1.2;text-transform:uppercase;letter-spacing:.03em;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;width:100%}
.game .sub{color:var(--muted);font-size:12px;margin-top:auto}
.list{display:flex;flex-direction:column;border:1px solid var(--line2);border-radius:var(--r);overflow:hidden;background:var(--panel);min-width:0}
.li{display:flex;align-items:center;gap:12px;width:100%;min-width:0;padding:13px 14px;border:0;border-bottom:1px solid var(--line);background:none;color:var(--text);text-align:left}
.li:last-child{border-bottom:0}
button.li:hover{background:rgba(255,255,255,.04)}
.li .meta{min-width:0;flex:1 1 auto}
.li .t{display:block;font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.li .s{display:block;color:var(--muted);font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.li.active{background:rgba(255,255,255,.07)}
.price{font-weight:800;font-variant-numeric:tabular-nums;white-space:nowrap}
.unread{min-width:22px;height:22px;padding:0 7px;border-radius:999px;background:#fff;color:#000;font-size:12px;font-weight:800;display:grid;place-items:center}

/* ---- chat ---- */
.chat{display:flex;flex-direction:column;flex:1 1 auto;min-height:0}
.chat-head{position:sticky;top:0;z-index:3;display:flex;align-items:center;gap:10px;min-height:62px;padding:10px 14px;border-bottom:1px solid var(--line);background:rgba(7,7,8,.94);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px)}
.msgs{flex:1 1 auto;min-height:0;overflow:auto;padding:14px 14px 8px;display:flex;flex-direction:column;gap:8px;overscroll-behavior:contain}
.bubble{align-self:flex-start;max-width:min(80%,540px);padding:9px 12px;border-radius:15px;border:1px solid var(--line2);background:var(--panel2);white-space:pre-wrap;word-break:break-word}
.bubble.out{align-self:flex-end;background:rgba(255,255,255,.09);border-color:var(--line3)}
.bubble .ts{display:block;margin-top:4px;font-size:11px;color:var(--faint)}
.bubble .st{color:var(--muted)}
.bubble.warn{border-style:dashed;border-color:var(--line3)}
.bubble img{display:block;max-width:100%;max-height:260px;border-radius:10px;margin-top:6px}
.composer{display:flex;align-items:flex-end;gap:8px;padding:10px 12px calc(10px + env(safe-area-inset-bottom));border-top:1px solid var(--line);background:rgba(7,7,8,.95)}
.composer .input{flex:1 1 auto;min-height:44px;max-height:140px;resize:none;border-radius:15px;padding:11px 13px;line-height:1.4}
.composer .iconbtn{width:44px;height:44px}
.send-btn{width:46px;height:46px;flex:none;border-radius:14px;background:#fff;color:#000;border:1px solid #fff;display:grid;place-items:center}
.send-btn[disabled]{opacity:.4}

/* ---- overlays ---- */
.toasts{position:fixed;right:18px;bottom:18px;z-index:90;display:flex;flex-direction:column;gap:10px;width:min(380px,calc(100vw - 36px))}
.toast{display:flex;gap:12px;align-items:flex-start;padding:13px 14px;border-radius:14px;border:1px solid var(--line3);background:rgba(16,16,19,.97);box-shadow:var(--shadow);animation:rise .25s ease both}
.toast .t{font-weight:700}
.toast .s{color:var(--muted);font-size:13px;white-space:pre-wrap;word-break:break-word}
.toast .x{margin-left:auto;flex:none}
@keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
.overlay{position:fixed;inset:0;z-index:80;display:grid;place-items:center;padding:16px;background:rgba(0,0,0,.62);backdrop-filter:blur(5px);-webkit-backdrop-filter:blur(5px)}
.dialog{width:min(500px,100%);max-height:calc(100dvh - 32px);overflow:auto;display:flex;flex-direction:column;gap:14px;padding:20px;border-radius:18px;border:1px solid var(--line3);background:#0d0d10;box-shadow:var(--shadow)}
.dialog .x{align-self:flex-end}
.dialog.wide{width:min(640px,100%)}
.sheet-overlay{align-items:end;padding:0}
.sheet{width:100%;max-height:84dvh;border-radius:22px 22px 0 0;padding:18px 16px calc(18px + env(safe-area-inset-bottom))}
.handle{width:44px;height:5px;border-radius:9px;background:var(--line3);margin:-6px auto 4px}
.auth{min-height:100%;display:grid;place-items:center;padding:24px 16px}
.auth-card{width:min(430px,100%);display:flex;flex-direction:column;gap:16px;padding:26px 22px;border-radius:22px;border:1px solid var(--line3);background:rgba(10,10,12,.9);box-shadow:var(--shadow)}
.auth-title{font-size:24px;font-weight:800;letter-spacing:-.01em;margin:0}
.boot{position:fixed;inset:0;display:grid;place-items:center;color:var(--muted)}

/* ---- mobile ---- */
@media (max-width:959px){
  #app{grid-template-columns:minmax(0,1fr)}
  .side{display:none}
  .topbar{padding:10px 14px;min-height:58px}
  .view{padding:14px 14px calc(96px + env(safe-area-inset-bottom))}
  .bottomnav{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:4px;position:fixed;left:10px;right:10px;bottom:calc(var(--kb) + 10px + env(safe-area-inset-bottom));z-index:60;padding:6px;border-radius:20px;border:1px solid var(--line3);background:rgba(10,10,12,.95);box-shadow:var(--shadow)}
  .bottomnav button{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;min-height:52px;border:0;border-radius:14px;background:none;color:var(--muted);font-size:11px;font-weight:700}
  .bottomnav button svg{width:21px;height:21px}
  .bottomnav button[aria-current="page"]{background:#fff;color:#000}
  .kb-open .bottomnav,.in-chat .bottomnav{display:none}
  .view.chat-view{padding:0}
  .game-grid{grid-template-columns:repeat(2,minmax(0,1fr))}
  .qa{grid-template-columns:minmax(0,1fr)}
  .toasts{left:12px;right:12px;bottom:auto;top:calc(env(safe-area-inset-top) + 10px);width:auto}
  .bubble{max-width:88%}
  .hide-m{display:none!important}
  .in-chat .topbar{display:none}
}
@media (min-width:960px){.show-m{display:none!important}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<div class="boot" id="boot"><div class="spin" aria-hidden="true"></div><span class="sr">Загрузка</span></div>

<section class="auth" id="auth" hidden>
  <form class="auth-card" id="authForm" autocomplete="off" novalidate>
    <div class="row">
      <div class="mark" aria-hidden="true"><i data-icon="box"></i></div>
      <div class="grow">
        <div class="brand-name">FunPay Lister</div>
        <div class="hint">Панель для FunPay · v5</div>
      </div>
    </div>
    <h1 class="auth-title">Вход по ключу</h1>
    <div class="field">
      <label for="keyInput">Ключ доступа</label>
      <div class="row">
        <input class="input grow" id="keyInput" name="key" type="password" autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder="FP-XXXXXX-XXXXXX-…" maxlength="300" required>
        <button class="iconbtn" type="button" id="toggleKey" aria-label="Показать ключ" aria-pressed="false"><i data-icon="eye"></i></button>
      </div>
    </div>
    <button class="btn btn-solid btn-block" id="loginBtn" type="submit">Войти</button>
    <div class="error" id="authError" role="alert"></div>
    <div class="notice" id="coldNotice" hidden>Сервер просыпается после простоя. Обычно это занимает до минуты, подождите…</div>
    <p class="hint">Ключ выдаёт Telegram-бот: FREE PLAN на 30 минут или платный ключ за Stars. Отсчёт FREE PLAN начинается при первом входе.</p>
  </form>
</section>

<div id="app" hidden>
  <aside class="side" aria-label="Навигация">
    <div class="brand">
      <div class="mark" aria-hidden="true"><i data-icon="box"></i></div>
      <div><div class="brand-name">FunPay Lister</div><div class="hint">панель продавца</div></div>
    </div>
    <nav class="nav" id="sideNav"></nav>
    <div class="grow"></div>
    <div class="side-foot">
      <div class="card" id="sideAccount" style="padding:12px"></div>
      <button class="btn btn-block" id="sideLogout" type="button"><i data-icon="logout"></i>Выйти</button>
    </div>
  </aside>

  <div class="main">
    <header class="topbar">
      <button class="iconbtn" id="backBtn" type="button" aria-label="Назад" hidden><i data-icon="back"></i></button>
      <h1 class="title" id="pageTitle">Главная</h1>
      <button class="chip" id="timerChip" type="button" aria-label="Срок действия сессии" title="Срок действия сессии"><i data-icon="clock"></i><span id="timerText">—</span></button>
      <button class="iconbtn" id="bellBtn" type="button" aria-label="Уведомления"><i data-icon="bell"></i><span class="badge" id="bellBadge" hidden>0</span></button>
      <button class="iconbtn hide-m" id="fsBtn" type="button" aria-label="Полноэкранный режим (F)" title="Полноэкранный режим (F)" hidden><i data-icon="expand"></i></button>
    </header>
    <main class="view" id="view" tabindex="-1"></main>
  </div>
</div>

<nav class="bottomnav" id="bottomNav" aria-label="Нижнее меню" hidden>
  <button type="button" data-route="home"><i data-icon="home"></i>Главная</button>
  <button type="button" data-route="search"><i data-icon="search"></i>Поиск</button>
  <button type="button" data-route="chats"><i data-icon="chat"></i>Чаты</button>
  <button type="button" data-route="orders"><i data-icon="cart"></i>Заказы</button>
  <button type="button" id="moreBtn"><i data-icon="dots"></i>Ещё</button>
</nav>

<div class="toasts" id="toasts" aria-live="polite"></div>
<div class="overlay" id="overlay" hidden>
  <div class="dialog" id="dialog" role="dialog" aria-modal="true" aria-labelledby="dialogTitle"></div>
</div>
<input type="file" id="pickImage" accept="image/*" hidden>
<input type="file" id="pickBackground" accept="image/*" hidden>
<script src="https://telegram.org/js/telegram-web-app.js"></script>
<script>
/* ===== FunPay Lister v5 — core ===== */
(function () {
'use strict';

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const isMobile = () => window.matchMedia('(max-width: 959px)').matches;
const safeUrl = (u) => (/^https:\/\//i.test(u || '') || /^data:image\//i.test(u || '') ? u : '');

function money(value, currency) {
  if (value === null || value === undefined || value === '' || Number.isNaN(Number(value))) return '—';
  return Number(value).toLocaleString('ru-RU', { maximumFractionDigits: 2 }) + ' ' + (currency || 'RUB');
}
function fmtClock(ts) {
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
}
function fmtUnix(sec) {
  return new Date(sec * 1000).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
}
function mono(name) {
  const parts = String(name || '?').replace(/[^\p{L}\p{N}\s]/gu, ' ').trim().split(/\s+/).filter(Boolean);
  const text = parts.length > 1 ? parts[0][0] + parts[1][0] : (parts[0] || '?').slice(0, 2);
  return text.toUpperCase();
}
function tileHtml(name, image, big) {
  const src = safeUrl(image);
  return `<span class="tile${big ? ' lg' : ''}" aria-hidden="true">${esc(mono(name))}` +
    (src ? `<img src="${esc(src)}" alt="" loading="lazy" referrerpolicy="no-referrer" onload="this.classList.add('ok')" onerror="this.remove()">` : '') + '</span>';
}

const ICONS = {
  home: '<path d="M3 11.5 12 4l9 7.5"/><path d="M5 10.5V20h14v-9.5"/>',
  search: '<circle cx="11" cy="11" r="6.5"/><path d="m16 16 4.5 4.5"/>',
  box: '<path d="M12 3 20 7.5v9L12 21l-8-4.5v-9z"/><path d="M12 12 20 7.5M12 12v9M12 12 4 7.5"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  chat: '<path d="M4 5h16v11H9l-5 4z"/>',
  cart: '<path d="M3 4h2l2.2 10.2a1 1 0 0 0 1 .8h9.6a1 1 0 0 0 1-.8L20.5 8H7"/><circle cx="9.5" cy="19" r="1.4"/><circle cx="17" cy="19" r="1.4"/>',
  cog: '<circle cx="12" cy="12" r="3"/><path d="M12 2.8v2.4M12 18.8v2.4M4.9 4.9l1.7 1.7M17.4 17.4l1.7 1.7M2.8 12h2.4M18.8 12h2.4M4.9 19.1l1.7-1.7M17.4 6.6l1.7-1.7"/>',
  bell: '<path d="M6 16V11a6 6 0 1 1 12 0v5l1.5 2h-15z"/><path d="M10 20.5a2 2 0 0 0 4 0"/>',
  expand: '<path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/>',
  shrink: '<path d="M9 4v5H4M15 4v5h5M9 20v-5H4M15 20v-5h5"/>',
  logout: '<path d="M9 4H5v16h4"/><path d="M14 8l4 4-4 4M18 12H9"/>',
  back: '<path d="M15 5l-7 7 7 7"/>',
  send: '<path d="M4 12 20 4l-5 16-3.5-6.5z"/><path d="m11.5 13.5 3-3"/>',
  image: '<rect x="3.5" y="4.5" width="17" height="15" rx="2.5"/><circle cx="9" cy="10" r="1.6"/><path d="m20 16-4.5-4.5L7 19"/>',
  refresh: '<path d="M20 11a8 8 0 1 0-2.3 5.7"/><path d="M20 4v7h-7"/>',
  trash: '<path d="M4 7h16M9 7V4.5h6V7M6.5 7l1 13h9l1-13"/>',
  check: '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
  copy: '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5.5A1.5 1.5 0 0 0 14.5 4h-9A1.5 1.5 0 0 0 4 5.5v9A1.5 1.5 0 0 0 5.5 16H8"/>',
  close: '<path d="M6 6l12 12M18 6 6 18"/>',
  dots: '<circle cx="5.5" cy="12" r="1.3"/><circle cx="12" cy="12" r="1.3"/><circle cx="18.5" cy="12" r="1.3"/>',
  eye: '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="3"/>',
  eyeOff: '<path d="M3 3l18 18M10.6 6.2A9.6 9.6 0 0 1 12 6c6 0 9.5 6 9.5 6a16 16 0 0 1-3 3.6M6.4 7.4A16 16 0 0 0 2.5 12S6 18 12 18a9.7 9.7 0 0 0 4.3-1"/>',
  clock: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
  tag: '<path d="M3.5 12.5V4.5h8l9 9-8 8z"/><circle cx="8" cy="9" r="1.3"/>',
  sound: '<path d="M4 9.5h3.5L12 6v12l-4.5-3.5H4z"/><path d="M16 9a4 4 0 0 1 0 6M18.5 6.5a7.5 7.5 0 0 1 0 11"/>',
  soundOff: '<path d="M4 9.5h3.5L12 6v12l-4.5-3.5H4z"/><path d="M16 9.5l5 5M21 9.5l-5 5"/>',
  external: '<path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>',
  shield: '<path d="M12 3.5 19 6v5.5c0 4.2-3 7.4-7 9-4-1.6-7-4.8-7-9V6z"/>',
  layers: '<path d="M12 3 21 8l-9 5-9-5z"/><path d="m3 13 9 5 9-5"/>',
  pen: '<path d="M4 20h4L19 9l-4-4L4 16z"/>',
};
function icon(name, cls) {
  return `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"${cls ? ` class="${cls}"` : ''}>${ICONS[name] || ICONS.box}</svg>`;
}
function hydrateIcons(root) {
  $$('i[data-icon]', root || document).forEach((el) => { el.outerHTML = icon(el.dataset.icon); });
}

/* ---- state ---- */
const S = {
  session: null, skew: 0, lastSeq: 0, notifs: [], readSeq: 0, notifTimer: null, notifFirst: true,
  renderToken: 0, viewTimer: null, sound: true, bgOpacity: 0.2, ending: false, sticky: false,
  autoFsDone: false, nodes: {}, catalog: null, catalogAt: 0, lastNode: null,
};
const store = {
  get(key, fallback) { try { const v = localStorage.getItem(key); return v === null ? fallback : v; } catch (e) { return fallback; } },
  set(key, value) { try { localStorage.setItem(key, String(value)); } catch (e) { /* private mode */ } },
  del(key) { try { localStorage.removeItem(key); } catch (e) { /* private mode */ } },
};

/* ---- API client ---- */
class ApiError extends Error {
  constructor(status, message, code) { super(message); this.status = status; this.code = code || ''; }
}
async function api(path, opt) {
  const options = opt || {};
  const method = options.method || (options.body !== undefined ? 'POST' : 'GET');
  const timeout = options.timeout || (method === 'GET' ? 30000 : 60000);
  const headers = { Accept: 'application/json' };
  let body;
  if (options.body !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(options.body); }
  const attempts = method === 'GET' ? 3 : 1;
  for (let attempt = 1; ; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    let res;
    try {
      res = await fetch('/api' + path, { method, headers, body, credentials: 'same-origin', cache: 'no-store', signal: controller.signal });
    } catch (e) {
      clearTimeout(timer);
      if (attempt < attempts) { await sleep(1500 * attempt); continue; }
      throw new ApiError(0, e.name === 'AbortError' ? 'Сервер не ответил вовремя. Попробуйте ещё раз.' : 'Нет связи с сервером. Проверьте интернет.');
    }
    clearTimeout(timer);
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch (e) { data = text; }
    if (res.ok) return data;
    if ((res.status === 502 || res.status === 503 || res.status === 504) && attempt < attempts && method === 'GET') {
      await sleep(1500 * attempt);
      continue;
    }
    const detail = data && data.detail;
    const code = detail && typeof detail === 'object' ? detail.code : '';
    let message = 'Ошибка запроса';
    if (typeof detail === 'string') message = detail;
    else if (detail && detail.message) message = detail.message;
    else if (Array.isArray(detail)) message = 'Проверьте заполнение полей';
    const error = new ApiError(res.status, message, code);
    if (res.status === 401 && S.session && path !== '/login') sessionEnded(message, code);
    throw error;
  }
}

/* ---- toasts, dialogs ---- */
function toast(opts) {
  const { title, text = '', type = 'info', go = '' } = opts;
  const el = document.createElement('div');
  el.className = 'toast';
  if (go) el.dataset.go = go;
  const glyph = type === 'order' ? 'cart' : type === 'error' ? 'close' : 'chat';
  el.innerHTML = `<span style="flex:none;margin-top:1px">${icon(glyph)}</span>` +
    `<div class="grow" style="min-width:0"><div class="t">${esc(title)}</div>${text ? `<div class="s">${esc(text)}</div>` : ''}</div>` +
    `<button class="iconbtn x" type="button" aria-label="Закрыть" style="width:32px;height:32px;border-radius:10px">${icon('close')}</button>`;
  el.querySelector('.x').addEventListener('click', (ev) => { ev.stopPropagation(); el.remove(); });
  const box = $('#toasts');
  box.appendChild(el);
  while (box.children.length > 4) box.firstElementChild.remove();
  setTimeout(() => el.remove(), 6500);
}

function openDialog(html, opts) {
  const options = opts || {};
  const overlay = $('#overlay');
  const dialog = $('#dialog');
  S.sticky = !!options.sticky;
  overlay.classList.toggle('sheet-overlay', !!options.sheet);
  dialog.className = 'dialog' + (options.sheet ? ' sheet' : '') + (options.wide ? ' wide' : '');
  dialog.innerHTML = html;
  overlay.hidden = false;
  hydrateIcons(dialog);
  if (options.onOpen) options.onOpen(dialog);
  return dialog;
}
function closeDialog() {
  if (S.sticky) return;
  $('#overlay').hidden = true;
  $('#dialog').innerHTML = '';
}
function confirmBox(title, text, okText, danger) {
  return new Promise((resolve) => {
    const dialog = openDialog(
      `<h2 class="h2" id="dialogTitle">${esc(title)}</h2><p class="muted" style="margin:0">${esc(text)}</p>` +
      `<div class="row wrap-row" style="justify-content:flex-end"><button class="btn" type="button" data-no>Отмена</button>` +
      `<button class="btn ${danger ? 'btn-danger' : 'btn-solid'}" type="button" data-yes>${esc(okText || 'Подтвердить')}</button></div>`);
    dialog.querySelector('[data-no]').onclick = () => { closeDialog(); resolve(false); };
    dialog.querySelector('[data-yes]').onclick = () => { closeDialog(); resolve(true); };
  });
}
function busy(btn, on, label) {
  if (!btn) return;
  if (on) {
    if (btn.dataset.label === undefined) btn.dataset.label = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `<span class="spin" aria-hidden="true"></span>${esc(label || 'Подождите…')}`;
  } else {
    btn.disabled = false;
    if (btn.dataset.label !== undefined) btn.innerHTML = btn.dataset.label;
    delete btn.dataset.label;
  }
}

/* ---- session, timer and sign-in ---- */
function applySession(sess) {
  if (!sess) return;
  S.session = sess;
  S.skew = (sess.server_time || Date.now() / 1000) - Date.now() / 1000;
  renderSideAccount();
}
function remainingSeconds() {
  if (!S.session || S.session.forever) return null;
  return Math.max(0, S.session.expires_at - (Date.now() / 1000 + S.skew));
}
function fmtRemain(sec) {
  if (sec >= 86400) return `${Math.floor(sec / 86400)} д ${Math.floor((sec % 86400) / 3600)} ч`;
  if (sec >= 3600) return `${Math.floor(sec / 3600)} ч ${Math.floor((sec % 3600) / 60)} м`;
  const m = Math.floor(sec / 60);
  const s = Math.floor(sec % 60);
  return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}
function tickTimer() {
  if (!S.session) return;
  const chip = $('#timerChip');
  const text = $('#timerText');
  if (S.session.forever) { text.textContent = 'Бессрочно'; chip.classList.remove('low'); return; }
  const left = remainingSeconds();
  if (left <= 0) {
    sessionEnded(S.session.free ? 'FREE PLAN закончился: 30 минут истекли.' : 'Срок действия ключа истёк.', 'session_expired');
    return;
  }
  text.textContent = (S.session.free ? 'FREE ' : '') + fmtRemain(left);
  chip.classList.toggle('low', left < 300);
}
function renderSideAccount() {
  const box = $('#sideAccount');
  if (!box || !S.session) return;
  const until = S.session.forever ? 'без срока' : `до ${fmtUnix(S.session.expires_at)}`;
  box.innerHTML = `<div class="label" style="margin-bottom:6px">Доступ</div><div class="ellipsis" style="font-weight:700">${esc(S.session.plan_title)}</div><div class="tiny muted">${esc(until)}</div>`;
  const adminBtn = $('#navAdmin');
  if (adminBtn) adminBtn.hidden = !S.session.is_admin;
}
function startTimers() {
  stopTimers();
  S.clock = setInterval(tickTimer, 1000);
  tickTimer();
  scheduleNotifications(0);
}
function stopTimers() {
  if (S.clock) clearInterval(S.clock);
  S.clock = null;
  clearTimeout(S.notifTimer);
  clearViewTimer();
}
function clearViewTimer() {
  if (S.viewTimer) clearInterval(S.viewTimer);
  S.viewTimer = null;
  S.onNotify = null;
}
function sessionEnded(message, code) {
  if (S.ending || !S.session) return;
  S.ending = true;
  stopTimers();
  S.session = null;
  const title = code === 'session_revoked' ? 'Доступ отозван' : 'Сессия завершена';
  openDialog(
    `<h2 class="h2" id="dialogTitle">${esc(title)}</h2><p class="muted" style="margin:0">${esc(message || 'Срок действия ключа истёк.')}</p>` +
    `<button class="btn btn-solid btn-block" type="button" id="endNew">Ввести новый ключ</button>` +
    '<p class="hint" style="margin:0">Новый FREE PLAN или платный ключ выдаёт бот в Telegram.</p>',
    { sticky: true });
  $('#endNew').onclick = async () => {
    S.sticky = false;
    S.ending = false;
    await logout({ silent: true });
    closeDialog();
  };
}
function showAuth(message) {
  stopTimers();
  S.session = null;
  $('#boot').hidden = true;
  $('#app').hidden = true;
  $('#bottomNav').hidden = true;
  $('#auth').hidden = false;
  $('#authError').textContent = message || '';
  setTimeout(() => $('#keyInput').focus(), 50);
}
async function enterApp() {
  $('#boot').hidden = true;
  $('#auth').hidden = true;
  $('#app').hidden = false;
  $('#bottomNav').hidden = false;
  S.ending = false;
  buildNav();
  startTimers();
  if (!location.hash || location.hash === '#') location.hash = '#home';
  else render();
}
async function login(key) {
  const button = $('#loginBtn');
  const cold = setTimeout(() => { $('#coldNotice').hidden = false; }, 3500);
  busy(button, true, 'Проверяем…');
  $('#authError').textContent = '';
  try {
    const body = key ? { key } : { init_data: (window.Telegram && window.Telegram.WebApp && window.Telegram.WebApp.initData) || '' };
    const data = await api('/login', { body, timeout: 90000 });
    applySession(data.session);
    store.del('fpl.readSeq.pending');
    await enterApp();
    return true;
  } catch (err) {
    $('#authError').textContent = err.message;
    return false;
  } finally {
    clearTimeout(cold);
    $('#coldNotice').hidden = true;
    busy(button, false);
  }
}
async function logout(opts) {
  const options = opts || {};
  try { await api('/logout', { method: 'POST' }); } catch (e) { /* session may already be gone */ }
  S.notifs = [];
  S.lastSeq = 0;
  S.notifFirst = true;
  S.nodes = {};
  stopTimers();
  showAuth(options.silent ? '' : 'Вы вышли из панели.');
}

/* ---- in-app notifications ---- */
function unreadCount() { return S.notifs.filter((n) => n.seq > S.readSeq).length; }
function updateBadge() {
  const count = unreadCount();
  const badge = $('#bellBadge');
  badge.hidden = count === 0;
  badge.textContent = count > 99 ? '99+' : String(count);
}
function scheduleNotifications(delay) {
  clearTimeout(S.notifTimer);
  const wait = delay !== undefined ? delay : (document.hidden ? 20000 : 6000);
  S.notifTimer = setTimeout(pollNotifications, wait);
}
async function pollNotifications() {
  if (!S.session) return;
  try {
    const data = await api(`/notifications?after=${S.lastSeq}`);
    if (data.session) applySession(data.session);
    const fresh = data.items || [];
    if (S.notifFirst) {
      S.notifFirst = false;
      if (!store.get('fpl.readSeq', '')) store.set('fpl.readSeq', data.last_seq || 0);
      S.readSeq = Number(store.get('fpl.readSeq', 0)) || 0;
    }
    if (fresh.length) {
      S.notifs = S.notifs.concat(fresh).slice(-120);
      for (const n of fresh) {
        const go = n.chat_id ? `#chat/${n.chat_id}` : (n.type === 'order' ? '#orders' : '#home');
        if (S.lastSeq > 0) toast({ title: n.title, text: n.text, type: n.type, go });
      }
      if (S.lastSeq > 0) playSound();
      if (document.hidden && S.lastSeq > 0) document.title = `(${unreadCount()}) FunPay Lister`;
    }
    S.lastSeq = Math.max(S.lastSeq, data.last_seq || 0);
    updateBadge();
    if (fresh.length && S.onNotify) S.onNotify(fresh);
  } catch (err) {
    if (err.status === 401) return;
  } finally {
    if (S.session) scheduleNotifications();
  }
}
function markRead() {
  S.readSeq = S.lastSeq;
  store.set('fpl.readSeq', S.readSeq);
  document.title = 'FunPay Lister';
}
let audioCtx = null;
function playSound() {
  if (!S.sound) return;
  try {
    if (!audioCtx) return;
    const now = audioCtx.currentTime;
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.type = 'sine';
    osc.frequency.value = 880;
    gain.gain.setValueAtTime(0.0001, now);
    gain.gain.exponentialRampToValueAtTime(0.12, now + 0.01);
    gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.25);
    osc.connect(gain).connect(audioCtx.destination);
    osc.start(now);
    osc.stop(now + 0.27);
  } catch (e) { /* audio is optional */ }
}
function openNotifications() {
  const items = S.notifs.slice().reverse();
  markRead();
  updateBadge();
  const rows = items.map((n) => {
    const go = n.chat_id ? `#chat/${n.chat_id}` : (n.type === 'order' ? '#orders' : '#home');
    return `<button class="li" type="button" data-go="${esc(go)}">${tileHtml(n.type === 'chat' ? n.title : (n.type === 'order' ? 'FP' : '!'), '', false)}` +
      `<span class="meta"><span class="t" style="white-space:normal">${esc(n.title)}</span><span class="s" style="white-space:normal">${esc(n.text)}</span></span>` +
      `<span class="tiny faint" style="align-self:flex-start">${esc(fmtClock(n.created_at * 1000))}</span></button>`;
  }).join('');
  const dialog = openDialog(
    (isMobile() ? '<div class="handle"></div>' : '') +
    `<div class="row between"><h2 class="h2" id="dialogTitle">Уведомления</h2><button class="btn btn-sm" type="button" data-clear>Очистить</button></div>` +
    `<div class="list">${rows || '<div class="empty"><b>Пока пусто</b>Здесь появятся сообщения, заказы и ошибки FunPay.</div>'}</div>`,
    { sheet: isMobile() });
  dialog.addEventListener('click', (ev) => {
    const target = ev.target.closest('[data-go]');
    if (target) { closeDialog(); navigate(target.dataset.go); }
    if (ev.target.closest('[data-clear]')) { S.notifs = []; closeDialog(); updateBadge(); }
  });
}
function openMoreSheet() {
  const last = S.lastNode;
  const dialog = openDialog(
    '<div class="handle"></div><h2 class="h2" id="dialogTitle">Разделы</h2>' +
    `<div class="list">` +
    (last ? `<button class="li" type="button" data-go="#node/${esc(last.id)}/lots">${icon('box')}<span class="meta"><span class="t">Мои офферы</span><span class="s">${esc(last.name)} · выбранный раздел</span></span></button>` : '') +
    `<button class="li" type="button" data-go="#settings">${icon('cog')}<span class="meta"><span class="t">Настройки</span><span class="s">FunPay, фон, звук</span></span></button>` +
    (S.session && S.session.is_admin ? `<button class="li" type="button" data-go="#admin">${icon('shield')}<span class="meta"><span class="t">Администрирование</span><span class="s">Ключи и доступы</span></span></button>` : '') +
    `<button class="li" type="button" data-logout>${icon('logout')}<span class="meta"><span class="t">Выйти</span><span class="s">Завершить сессию на этом устройстве</span></span></button>` +
    '</div>',
    { sheet: true });
  dialog.addEventListener('click', (ev) => {
    if (ev.target.closest('[data-logout]')) { closeDialog(); logout(); return; }
    const target = ev.target.closest('[data-go]');
    if (target) { closeDialog(); navigate(target.dataset.go); }
  });
}

/* ---- navigation and routing ---- */
const NAV = [
  { key: 'home', route: 'home', label: 'Главная', icon: 'home' },
  { key: 'search', route: 'search', label: 'Поиск игр', icon: 'search' },
  { key: 'chats', route: 'chats', label: 'Чаты', icon: 'chat' },
  { key: 'orders', route: 'orders', label: 'Заказы', icon: 'cart' },
  { key: 'settings', route: 'settings', label: 'Настройки', icon: 'cog' },
  { key: 'admin', route: 'admin', label: 'Администрирование', icon: 'shield', admin: true },
];
const NAV_KEY = { home: 'home', search: 'search', game: 'search', node: 'search', chats: 'chats', chat: 'chats', orders: 'orders', settings: 'settings', admin: 'admin' };
const TITLES = { home: 'Главная', search: 'Поиск игр', game: 'Игра', node: 'Раздел', chats: 'Чаты', chat: 'Чат', orders: 'Заказы', settings: 'Настройки', admin: 'Администрирование' };
const TOP_LEVEL = { home: 1, search: 1, chats: 1, orders: 1, settings: 1, admin: 1 };

function buildNav() {
  $('#sideNav').innerHTML = NAV.map((item) =>
    `<button type="button" data-nav="${item.key}" data-go="#${item.key === 'lots' ? 'search' : item.route}"${item.admin ? ' id="navAdmin" hidden' : ''}>${icon(item.icon)}<span>${esc(item.label)}</span></button>`
  ).join('');
  $$('#sideNav button').forEach((btn) => btn.addEventListener('click', () => {
    if (btn.dataset.nav === 'lots' && S.lastNode) navigate(`#node/${S.lastNode.id}/lots`);
    else navigate(btn.dataset.go);
  }));
  renderSideAccount();
}
function setNavCurrent(name) {
  const key = NAV_KEY[name] || '';
  $$('#sideNav button').forEach((btn) => { if (btn.dataset.nav === key) btn.setAttribute('aria-current', 'page'); else btn.removeAttribute('aria-current'); });
  $$('#bottomNav button[data-route]').forEach((btn) => {
    const match = btn.dataset.route === key;
    if (match) btn.setAttribute('aria-current', 'page'); else btn.removeAttribute('aria-current');
  });
}
function parseRoute() {
  const raw = location.hash.replace(/^#\/?/, '');
  const parts = raw.split('/').map((p) => { try { return decodeURIComponent(p); } catch (e) { return p; } });
  const name = parts[0] || 'home';
  return { name: TITLES[name] ? name : 'home', args: parts.slice(1) };
}
function navigate(hash) {
  if (location.hash === hash) render();
  else location.hash = hash;
}
async function render() {
  if (!S.session) return;
  const route = parseRoute();
  if (route.name === 'admin' && !S.session.is_admin) { navigate('#settings'); return; }
  const token = ++S.renderToken;
  clearViewTimer();
  const ctx = { token, name: route.name, args: route.args, alive: () => token === S.renderToken };
  const app = $('#app');
  document.documentElement.classList.toggle('in-chat', route.name === 'chat');
  const view = $('#view');
  view.classList.toggle('chat-view', route.name === 'chat');
  $('#pageTitle').textContent = TITLES[route.name] || '';
  document.title = `${TITLES[route.name] || ''} · FunPay Lister`;
  $('#backBtn').hidden = !!TOP_LEVEL[route.name];
  setNavCurrent(route.name);
  if (route.name !== 'chat') view.scrollTop = 0;
  view.innerHTML = '<div class="loading"><span class="spin"></span>Загрузка…</div>';
  try {
    const handler = window.FPL_VIEWS[route.name] || window.FPL_VIEWS.home;
    await handler(ctx, view);
  } catch (err) {
    if (ctx.alive()) view.innerHTML = errorBlock(err.message);
  }
}
function errorBlock(message) {
  return `<div class="view-inner"><div class="notice">${esc(message)}</div>` +
    '<div><button class="btn" type="button" data-retry>Повторить</button></div></div>';
}
function goBack() {
  if (history.length > 1) history.back();
  else navigate('#home');
}

/* ---- viewport, keyboard, fullscreen, background, sound ---- */
function bindViewport() {
  const vv = window.visualViewport;
  const apply = () => {
    const height = vv ? vv.height : window.innerHeight;
    const keyboard = vv ? Math.max(0, window.innerHeight - vv.height - vv.offsetTop) : 0;
    const root = document.documentElement;
    root.style.setProperty('--vh', `${Math.round(height)}px`);
    root.style.setProperty('--kb', `${Math.round(keyboard)}px`);
    const typing = /INPUT|TEXTAREA/.test((document.activeElement || {}).tagName || '');
    root.classList.toggle('kb-open', keyboard > 120 || (typing && keyboard > 60));
  };
  if (vv) { vv.addEventListener('resize', apply); vv.addEventListener('scroll', apply); }
  window.addEventListener('resize', apply);
  document.addEventListener('focusin', apply);
  document.addEventListener('focusout', () => setTimeout(apply, 150));
  apply();
}
function isFullscreen() { return !!document.fullscreenElement; }
async function toggleFullscreen() {
  try {
    if (isFullscreen()) await document.exitFullscreen();
    else await document.documentElement.requestFullscreen({ navigationUI: 'hide' });
  } catch (e) { /* the browser refused: nothing to do */ }
  updateFsButton();
}
function updateFsButton() {
  const button = $('#fsBtn');
  button.innerHTML = icon(isFullscreen() ? 'shrink' : 'expand');
  button.setAttribute('aria-label', isFullscreen() ? 'Выйти из полноэкранного режима' : 'Полноэкранный режим (F)');
}
function applyBackground(url) {
  const root = document.documentElement;
  if (!url) root.style.removeProperty('--bg-image');
  else root.style.setProperty('--bg-image', `url(${JSON.stringify(url)})`);
}
function applyOpacity(value) {
  S.bgOpacity = Math.min(0.6, Math.max(0.05, Number(value) || 0.2));
  document.documentElement.style.setProperty('--bg-opacity', String(S.bgOpacity));
}
function loadPreferences() {
  S.sound = store.get('fpl.sound', '1') !== '0';
  applyOpacity(store.get('fpl.bgOpacity', '0.2'));
  applyBackground(safeUrl(store.get('fpl.bg', '')) || '');
  S.readSeq = Number(store.get('fpl.readSeq', 0)) || 0;
  try { S.lastNode = JSON.parse(store.get('fpl.lastNode', 'null')); } catch (e) { S.lastNode = null; }
}
function rememberNode(node) {
  S.lastNode = node;
  store.set('fpl.lastNode', JSON.stringify(node));
}

window.FPL = { S, $, $$, esc, api, ApiError, icon, hydrateIcons, toast, openDialog, closeDialog, confirmBox, busy,
  money, fmtClock, fmtUnix, mono, tileHtml, safeUrl, navigate, render, errorBlock, store, sleep, isMobile,
  rememberNode, applyBackground, applyOpacity, goBack, logout, sessionEnded, applySession, toggleFullscreen,
  updateFsButton, openNotifications, openMoreSheet, playSound, isFullscreen, parseRoute, clearViewTimer,
  unreadCount, updateBadge };
window.FPL_VIEWS = {};

/* ---- boot ---- */
function bindUi() {
  $('#authForm').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const key = $('#keyInput').value.trim();
    if (!key) { $('#authError').textContent = 'Введите ключ доступа.'; return; }
    login(key);
  });
  $('#toggleKey').addEventListener('click', (ev) => {
    const input = $('#keyInput');
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    ev.currentTarget.setAttribute('aria-pressed', String(show));
    ev.currentTarget.innerHTML = icon(show ? 'eyeOff' : 'eye');
  });
  $('#sideLogout').addEventListener('click', () => logout());
  $('#bellBtn').addEventListener('click', openNotifications);
  $('#fsBtn').addEventListener('click', toggleFullscreen);
  $('#timerChip').addEventListener('click', () => navigate('#settings'));
  $('#backBtn').addEventListener('click', goBack);
  $('#moreBtn').addEventListener('click', openMoreSheet);
  $$('#bottomNav button[data-route]').forEach((btn) => btn.addEventListener('click', () => navigate(`#${btn.dataset.route}`)));
  $('#overlay').addEventListener('click', (ev) => { if (ev.target.id === 'overlay') closeDialog(); });
  $('#toasts').addEventListener('click', (ev) => {
    const card = ev.target.closest('.toast');
    if (card && card.dataset.go && !ev.target.closest('.x')) navigate(card.dataset.go);
  });
  $('#view').addEventListener('click', (ev) => {
    if (ev.target.closest('[data-retry]')) { render(); return; }
    const go = ev.target.closest('[data-go]');
    if (go) navigate(go.dataset.go);
  });
  window.addEventListener('hashchange', () => { if (S.session) render(); });
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') closeDialog();
    const typing = /INPUT|TEXTAREA|SELECT/.test(ev.target.tagName) || ev.target.isContentEditable;
    if (!typing && (ev.key === 'f' || ev.key === 'F') && !ev.ctrlKey && !ev.metaKey && !ev.altKey && $('#app').hidden === false) {
      toggleFullscreen();
    }
    if (!S.autoFsDone && (ev.key === 'Enter' || ev.key === ' ')) autoFullscreen();
  });
  document.addEventListener('pointerdown', () => {
    if (!audioCtx) {
      try { audioCtx = new (window.AudioContext || window.webkitAudioContext)(); } catch (e) { audioCtx = null; }
    }
    if (audioCtx && audioCtx.state === 'suspended') audioCtx.resume();
    if (!S.autoFsDone) autoFullscreen();
  }, { passive: true });
  document.addEventListener('visibilitychange', () => { if (!document.hidden && S.session) scheduleNotifications(0); });
  document.addEventListener('fullscreenchange', updateFsButton);
  if (!document.fullscreenEnabled) $('#fsBtn').hidden = true;
  updateFsButton();
}
function autoFullscreen() {
  S.autoFsDone = true;
  if (!S.session || store.get('fpl.autofs', '1') === '0' || !document.fullscreenEnabled || isFullscreen()) return;
  document.documentElement.requestFullscreen({ navigationUI: 'hide' }).catch(() => {});
  setTimeout(updateFsButton, 300);
}

async function init() {
  hydrateIcons(document);
  loadPreferences();
  bindUi();
  bindViewport();
  const slow = setTimeout(() => {
    const note = $('#boot .sr');
    if (note) note.textContent = 'Сервер просыпается, подождите…';
  }, 4000);
  try {
    let attempt = 0;
    for (;;) {
      try {
        const data = await api('/session');
        applySession(data);
        break;
      } catch (err) {
        attempt += 1;
        if (err.status === 0 && attempt < 4) { await sleep(3000); continue; }
        throw err;
      }
    }
    await enterApp();
  } catch (err) {
    const hasTelegram = !!(window.Telegram && window.Telegram.WebApp && window.Telegram.WebApp.initData);
    if (hasTelegram && await login('')) return;
    showAuth(err.code === 'no_session' || err.status === 401 ? '' : err.message);
  } finally {
    clearTimeout(slow);
  }
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();

})();

/* ===== FunPay Lister v5 — views: home, catalogue, game, node workspace ===== */
(function () {
'use strict';
const { $, $$, esc, api, icon, toast, openDialog, closeDialog, confirmBox, busy, money, fmtClock, tileHtml,
  safeUrl, navigate, errorBlock, S, rememberNode, sleep } = window.FPL;
const V = window.FPL_VIEWS;
const ROW_BTN = 'background:none;border:0;color:inherit;text-align:left;padding:0;min-width:0;flex:1 1 auto;cursor:pointer;font:inherit';

async function safe(fn, fallback) {
  try { return await fn(); } catch (err) { return fallback === undefined ? null : fallback; }
}

/* Full catalogue, served from the backend cache; waits briefly while it refreshes. */
async function loadCatalog(ctx) {
  if (S.catalog && S.catalog.items.length && Date.now() - S.catalogAt < 60000) return S.catalog;
  let data = await api('/funpay/catalog', { timeout: 15000 });
  // Poll the background refresh quickly, without blocking every request on the server.
  for (let i = 0; i < 18 && data.refreshing && !data.items.length && ctx.alive(); i++) {
    await sleep(1000);
    data = await api('/funpay/catalog', { timeout: 15000 });
  }
  if (data.items.length) { S.catalog = data; S.catalogAt = Date.now(); }
  return data;
}
function findNode(catalog, subId) {
  for (const category of catalog.items) {
    for (const sub of category.subcategories || []) {
      if (String(sub.id) === String(subId)) return { id: sub.id, name: sub.name, category: category.name, categoryId: category.id, icon: sub.icon || category.icon };
    }
  }
  return null;
}
function catalogNotice(catalog) {
  if (catalog.items.length) return '';
  if (catalog.refreshing) return '<div class="loading"><span class="spin"></span>Загружаем каталог FunPay. Это занимает несколько секунд…</div>';
  return `<div class="notice">${esc(catalog.error || 'Каталог пока пуст. Подключите аккаунт FunPay в «Настройках».')}</div>` +
    '<div class="row wrap-row"><button class="btn" type="button" data-retry>Повторить</button><button class="btn btn-ghost" type="button" data-go="#settings">Настройки</button></div>';
}

/* ---- home ---- */
V.home = async (ctx, view) => {
  const status = await safe(() => api('/funpay/status'), { connected: false });
  const connected = !!(status && status.connected);
  const [chats, orders] = connected
    ? await Promise.all([safe(() => api('/funpay/chats', { timeout: 12000 }), []), safe(() => api('/funpay/orders?limit=50', { timeout: 12000 }), [])])
    : [[], []];
  if (!ctx.alive()) return;
  const unread = chats.reduce((sum, c) => sum + (c.unread_count || 0), 0);
  const recent = S.notifs.slice(-5).reverse();
  const account = connected
    ? `<div class="row between wrap-row"><div><div class="label">Аккаунт FunPay</div><div class="h2" style="margin-top:4px">${esc(status.username || 'Продавец')}</div></div>` +
      `<div style="text-align:right"><div class="label">Баланс</div><div class="kpi" style="font-size:22px">${esc(money(status.balance, 'RUB'))}</div></div></div>`
    : `<div class="row between wrap-row"><div><div class="label">Аккаунт FunPay</div><div class="h2" style="margin-top:4px">Не подключён</div>` +
      `<div class="hint" style="margin-top:4px">${esc((status && status.message) || 'Подключите golden_key аккаунта, чтобы видеть чаты, заказы и офферы.')}</div></div>` +
      '<button class="btn btn-solid" type="button" data-go="#settings">Подключить</button></div>';
  view.innerHTML = `<div class="view-inner">
    <section class="card">${account}</section>
    <div class="grid g3">
      <div class="card"><div class="label">Непрочитанные</div><div class="kpi">${connected ? unread : '—'}</div><div class="tiny muted">сообщения в чатах</div></div>
      <div class="card"><div class="label">Чаты</div><div class="kpi">${connected ? chats.length : '—'}</div><div class="tiny muted">активные диалоги</div></div>
      <div class="card"><div class="label">Заказы</div><div class="kpi">${connected ? orders.length : '—'}</div><div class="tiny muted">последние 50</div></div>
    </div>
    <div class="grid g2 qa">
      <button class="card" type="button" data-go="#search" style="text-align:left;color:inherit;cursor:pointer"><div class="row">${icon('search')}<div><div class="h2">Найти игру</div><div class="tiny muted">каталог FunPay, разделы и офферы</div></div></div></button>
      <button class="card" type="button" data-go="#chats" style="text-align:left;color:inherit;cursor:pointer"><div class="row">${icon('chat')}<div><div class="h2">Открыть чаты</div><div class="tiny muted">ответы покупателям с фото</div></div></div></button>
    </div>
    <section class="card"><h3 class="card-h">Последние события</h3>
      ${recent.length ? `<div class="list">${recent.map((n) => `<button class="li" type="button" data-go="${esc(n.chat_id ? '#chat/' + n.chat_id : '#orders')}"><span class="meta"><span class="t">${esc(n.title)}</span><span class="s">${esc(n.text)}</span></span><span class="tiny faint">${esc(fmtClock(n.created_at * 1000))}</span></button>`).join('')}</div>`
        : '<div class="hint">Пока тихо. Новые сообщения, заказы и ошибки FunPay появятся здесь и в колокольчике.</div>'}
    </section>
  </div>`;
};

/* ---- catalogue search ---- */
V.search = async (ctx, view) => {
  view.innerHTML = `<div class="view-inner">
    <div class="row"><input class="input grow" id="gameQ" type="search" placeholder="Игра или категория: Roblox, Steam, Minecraft…" aria-label="Поиск по каталогу FunPay" value="${esc(S.searchQ || '')}" autocomplete="off" enterkeyhint="search">
    <button class="btn btn-ghost" type="button" data-refresh-catalog aria-label="Обновить каталог">${icon('refresh')}</button></div>
    <div id="catBody"></div></div>`;
  const body = $('#catBody');
  const input = $('#gameQ');
  let catalog = null;
  const draw = () => {
    if (!ctx.alive() || !catalog) return;
    const q = input.value.trim();
    S.searchQ = q;
    if (!catalog.items.length) { body.innerHTML = catalogNotice(catalog); return; }
    if (!q) {
      body.innerHTML = `<div class="hint" style="margin:4px 0 10px">Выберите игру. Всего разделов: ${catalog.items.length}</div>` +
        `<div class="game-grid">${catalog.items.map((c) => `<button class="game" type="button" data-cat="${esc(c.id)}">${tileHtml(c.name, c.icon, true)}<span class="name">${esc(c.name)}</span><span class="sub">${(c.subcategories || []).length} разд.</span></button>`).join('')}</div>`;
      return;
    }
    body.innerHTML = '<div class="loading"><span class="spin"></span>Ищем…</div>';
    api(`/funpay/catalog?q=${encodeURIComponent(q)}`).then((res) => {
      if (!ctx.alive() || input.value.trim() !== q) return;
      if (!res.items.length) { body.innerHTML = `<div class="empty"><b>Ничего не нашли</b>Попробуйте часть названия или другое слово.</div>`; return; }
      body.innerHTML = `<div class="list">${res.items.map((it) => {
        const isCat = it.type === 'category';
        const attrs = isCat ? `data-cat="${esc(it.id)}"` : `data-node="${esc(it.id)}" data-node-cat="${esc(it.category_id)}" data-node-name="${esc(it.name)}" data-node-catname="${esc(it.category_name)}"`;
        return `<button class="li" type="button" ${attrs}>${tileHtml(isCat ? it.name : it.category_name, it.icon, false)}` +
          `<span class="meta"><span class="t">${esc(it.name)}</span><span class="s">${isCat ? 'Игра' : 'Раздел · ' + esc(it.category_name)}</span></span>${icon('tag')}</button>`;
      }).join('')}</div>`;
    }).catch((err) => { if (ctx.alive()) body.innerHTML = errorBlock(err.message); });
  };
  let timer = null;
  input.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(draw, 200); });
  $('[data-refresh-catalog]').addEventListener('click', async () => {
    S.catalog = null;
    body.innerHTML = '<div class="loading"><span class="spin"></span>Обновляем каталог…</div>';
    try { catalog = await loadCatalog(ctx); draw(); } catch (err) { body.innerHTML = errorBlock(err.message); }
  });
  body.addEventListener('click', (ev) => {
    const cat = ev.target.closest('[data-cat]');
    const node = ev.target.closest('[data-node]');
    if (node) {
      rememberNode({ id: node.dataset.node, name: node.dataset.nodeName, category: node.dataset.nodeCatname, categoryId: node.dataset.nodeCat });
      navigate(`#node/${node.dataset.node}/lots`);
    } else if (cat) navigate(`#game/${cat.dataset.cat}`);
  });
  try {
    catalog = await loadCatalog(ctx);
    if (!ctx.alive()) return;
    if (!catalog.items.length && catalog.refreshing) { body.innerHTML = catalogNotice(catalog); const again = await loadCatalog(ctx); catalog = again; }
    draw();
    if (!window.FPL.isMobile()) input.focus({ preventScroll: true });
  } catch (err) {
    if (ctx.alive()) body.innerHTML = errorBlock(err.message);
  }
};

/* ---- game: its subcategories ---- */
V.game = async (ctx, view) => {
  const catalog = await loadCatalog(ctx);
  if (!ctx.alive()) return;
  const category = catalog.items.find((c) => String(c.id) === String(ctx.args[0]));
  if (!category) { view.innerHTML = `<div class="view-inner">${errorBlock('Игра не найдена в каталоге. Обновите каталог на странице поиска.')}</div>`; return; }
  const subs = category.subcategories || [];
  view.innerHTML = `<div class="view-inner">
    <section class="card row">${tileHtml(category.name, category.icon, true)}<div class="grow" style="min-width:0"><div class="h1 ellipsis">${esc(category.name)}</div><div class="tiny muted">Разделов: ${subs.length}. Выберите раздел, чтобы открыть офферы.</div></div></section>
    ${subs.length ? `<div class="list">${subs.map((s) => `<button class="li" type="button" data-node="${esc(s.id)}">${tileHtml(s.name, s.icon || category.icon, false)}<span class="meta"><span class="t">${esc(s.name)}</span><span class="s">Офферы, рынок FunPay и создание</span></span>${icon('tag')}</button>`).join('')}</div>`
      : '<div class="empty"><b>Разделов нет</b>У этой игры нет подкатегорий в каталоге FunPay.</div>'}
  </div>`;
  view.querySelector('.view-inner').addEventListener('click', (ev) => {
    const btn = ev.target.closest('[data-node]');
    if (!btn) return;
    const sub = subs.find((s) => String(s.id) === btn.dataset.node);
    rememberNode({ id: btn.dataset.node, name: sub ? sub.name : '', category: category.name, categoryId: category.id });
    navigate(`#node/${btn.dataset.node}/lots`);
  });
};

/* ---- node workspace: lots, market, create ---- */
V.node = async (ctx, view) => {
  const subId = ctx.args[0];
  const tab = ctx.args[1] || 'lots';
  let node = S.lastNode && String(S.lastNode.id) === String(subId) ? S.lastNode : null;
  if (!node) {
    const catalog = await loadCatalog(ctx);
    if (!ctx.alive()) return;
    node = findNode(catalog, subId);
    if (node) rememberNode(node);
  }
  if (!ctx.alive()) return;
  if (!node) { view.innerHTML = `<div class="view-inner">${errorBlock('Раздел не найден. Откройте его через поиск игр.')}</div>`; return; }
  const tabs = [['lots', 'Мои офферы'], ['market', 'Рынок FunPay'], ['create', 'Создать оффер']];
  view.innerHTML = `<div class="view-inner">
    <section class="card"><div class="tiny muted ellipsis">${esc(node.category || '')}</div><div class="h2 ellipsis" style="margin-top:2px">${esc(node.name || 'Раздел')}</div><div class="tiny faint">раздел FunPay #${esc(subId)}</div></section>
    <div class="tabs" role="tablist">${tabs.map(([key, label]) => `<button type="button" role="tab" aria-selected="${tab === key}" data-tab="${key}">${label}</button>`).join('')}</div>
    <div id="nodeBody" class="stack"></div></div>`;
  $$('[data-tab]', view).forEach((btn) => btn.addEventListener('click', () => navigate(`#node/${subId}/${btn.dataset.tab}`)));
  const body = $('#nodeBody', view);
  if (tab === 'market') renderMarket(ctx, body, subId);
  else if (tab === 'create') renderCreate(ctx, body, subId);
  else await renderLots(ctx, body, subId);
};

async function renderLots(ctx, body, subId) {
  body.innerHTML = '<div class="loading"><span class="spin"></span>Загружаем офферы…</div>';
  let lots;
  try { lots = await api(`/funpay/lots?subcategory_id=${encodeURIComponent(subId)}`); }
  catch (err) { if (ctx.alive()) body.innerHTML = errorBlock(err.message); return; }
  if (!ctx.alive()) return;
  body._ctx = ctx;
  body._subId = subId;
  body._sel = new Set();
  body.innerHTML = `<div class="row wrap-row between"><span class="pill">${lots.length} офферов</span>` +
    `<div class="row wrap-row"><button class="btn btn-sm" type="button" data-refresh>${icon('refresh')}Обновить</button>` +
    `<button class="btn btn-sm btn-solid" type="button" data-raise disabled>${icon('check')}Поднять выбранные</button></div></div>` +
    (lots.length
      ? `<div class="list">${lots.map((l) => `<div class="li"><input class="check" type="checkbox" data-check="${esc(l.id)}" aria-label="Выбрать оффер ${esc(l.id)}">` +
        `<button type="button" data-edit="${esc(l.id)}" style="${ROW_BTN}"><span class="t" style="display:block">${esc(l.title)}</span>` +
        `<span class="s" style="display:block">#${esc(l.id)} · ${esc(l.amount ?? '—')} шт. · ${l.active ? 'активен' : 'скрыт'}</span></button>` +
        `<span class="price">${esc(money(l.price, l.currency))}</span></div>`).join('')}</div>`
      : '<div class="empty"><b>Офферов в разделе нет</b>Создайте первое предложение во вкладке «Создать оффер».</div>');
  if (!body._bound) {
    body._bound = true;
    body.addEventListener('change', (ev) => {
      const box = ev.target.closest('[data-check]');
      if (!box) return;
      const id = Number(box.dataset.check);
      if (box.checked) body._sel.add(id); else body._sel.delete(id);
      syncRaise(body);
    });
    body.addEventListener('click', onLotsClick);
  }
  syncRaise(body);
}
function syncRaise(body) {
  const btn = body.querySelector('[data-raise]');
  if (!btn) return;
  const n = body._sel ? body._sel.size : 0;
  btn.disabled = n === 0;
  btn.textContent = n ? `Поднять (${n})` : 'Поднять выбранные';
}
async function onLotsClick(ev) {
  const body = ev.currentTarget;
  if (ev.target.closest('[data-refresh]')) { renderLots(body._ctx, body, body._subId); return; }
  const edit = ev.target.closest('[data-edit]');
  if (edit) { openLotEditor(Number(edit.dataset.edit), () => renderLots(body._ctx, body, body._subId)); return; }
  const raiseBtn = ev.target.closest('[data-raise]');
  if (raiseBtn && body._sel && body._sel.size) {
    const ids = Array.from(body._sel);
    busy(raiseBtn, true, 'Поднимаем…');
    try {
      await api('/funpay/lots/raise', { body: { ids } });
      toast({ title: 'Офферы подняты', text: `Поднято: ${ids.length}` });
      renderLots(body._ctx, body, body._subId);
    } catch (err) {
      toast({ title: 'Не удалось поднять', text: err.message, type: 'error' });
      busy(raiseBtn, false);
      syncRaise(body);
    }
  }
}

async function openLotEditor(lotId, onSaved) {
  openDialog('<div class="loading"><span class="spin"></span>Открываем оффер…</div>', { sheet: window.FPL.isMobile() });
  let fields;
  try { fields = await api(`/funpay/lots/${lotId}/fields`); }
  catch (err) { openDialog(`<h2 class="h2" id="dialogTitle">Оффер #${esc(lotId)}</h2>${errorBlock(err.message)}`); return; }
  const dialog = openDialog(`<div class="handle"></div><div class="row between"><h2 class="h2" id="dialogTitle">Оффер #${esc(lotId)}</h2><button class="iconbtn" type="button" data-close aria-label="Закрыть">${icon('close')}</button></div>
    <form class="stack" id="lotForm" novalidate>
      <div class="field"><label for="lotTitle">Название</label><input class="input" id="lotTitle" maxlength="200" value="${esc(fields.title)}" required></div>
      <div class="field"><label for="lotDesc">Описание</label><textarea class="textarea" id="lotDesc" maxlength="5000">${esc(fields.description)}</textarea></div>
      <div class="grid g2"><div class="field"><label for="lotPrice">Цена</label><input class="input" id="lotPrice" type="number" inputmode="decimal" min="0.01" step="0.01" value="${esc(fields.price)}" required></div>
      <div class="field"><label for="lotAmount">Количество</label><input class="input" id="lotAmount" type="number" inputmode="numeric" min="0" step="1" value="${esc(fields.amount)}"></div></div>
      <label class="row between" style="cursor:pointer"><span>Оффер активен</span><span class="switch"><input type="checkbox" id="lotActive" ${fields.active ? 'checked' : ''}><span class="track"></span></span></label>
      <div class="error" id="lotError" role="alert"></div>
      <div class="row wrap-row" style="justify-content:space-between"><button class="btn btn-danger" type="button" data-delete>${icon('trash')}Удалить</button>
      <button class="btn btn-solid" type="submit" id="lotSave">Сохранить</button></div>
    </form>`, { sheet: window.FPL.isMobile() });
  dialog.querySelector('[data-close]').onclick = closeDialog;
  dialog.querySelector('[data-delete]').onclick = async () => {
    const ok = await confirmBox('Удалить оффер?', `Оффер #${lotId} будет удалён на FunPay.`, 'Удалить', true);
    if (!ok) return;
    try {
      await api(`/funpay/lots/${lotId}`, { method: 'DELETE' });
      toast({ title: 'Оффер удалён', text: `#${lotId}` });
      closeDialog();
      if (onSaved) onSaved();
    } catch (err) { toast({ title: 'Не удалось удалить', text: err.message, type: 'error' }); }
  };
  dialog.querySelector('#lotForm').onsubmit = async (ev) => {
    ev.preventDefault();
    const price = Number($('#lotPrice').value);
    const title = $('#lotTitle').value.trim();
    if (!title) { $('#lotError').textContent = 'Введите название оффера.'; return; }
    if (!(price > 0)) { $('#lotError').textContent = 'Цена должна быть больше нуля.'; return; }
    const button = $('#lotSave');
    busy(button, true, 'Сохраняем…');
    try {
      await api(`/funpay/lots/${lotId}`, { method: 'PUT', body: {
        title, description: $('#lotDesc').value, price, amount: Number($('#lotAmount').value || 1), active: $('#lotActive').checked } });
      toast({ title: 'Оффер сохранён', text: `#${lotId}` });
      closeDialog();
      if (onSaved) onSaved();
    } catch (err) {
      $('#lotError').textContent = err.message;
      busy(button, false);
    }
  };
}

function renderMarket(ctx, body, subId) {
  body.innerHTML = `<div class="row"><input class="input grow" id="mktQ" type="search" maxlength="180" placeholder="Например: pets 1b или аккаунт" aria-label="Поиск офферов на FunPay" enterkeyhint="search">` +
    '<button class="btn btn-solid" type="button" data-mkt>Искать</button></div><p class="hint" style="margin:0">Публичные офферы FunPay в этом разделе. Ссылка откроет страницу FunPay.</p><div id="mktRes" class="stack"></div>';
  const run = async () => {
    const q = $('#mktQ').value.trim();
    const res = $('#mktRes');
    res.innerHTML = '<div class="loading"><span class="spin"></span>Ищем офферы…</div>';
    try {
      const offers = await api(`/funpay/offers?subcategory_id=${encodeURIComponent(subId)}&q=${encodeURIComponent(q)}`);
      if (!ctx.alive()) return;
      if (!offers.length) { res.innerHTML = '<div class="empty"><b>Офферов не найдено</b>Попробуйте другой запрос или раздел.</div>'; return; }
      res.innerHTML = `<div class="list">${offers.map((o) => {
        const href = safeUrl(o.url) || 'https://funpay.com/';
        return `<a class="li" href="${esc(href)}" target="_blank" rel="noopener noreferrer"><span class="meta"><span class="t">${esc(o.title)}</span>` +
          `<span class="s">${esc(o.seller)}${o.server ? ' · ' + esc(o.server) : ''}${o.amount ? ' · ' + esc(o.amount) : ''}</span></span>` +
          `<span class="price">${esc(o.price !== null && o.price !== undefined ? money(o.price, 'RUB') : (o.price_text || '—'))}</span></a>`;
      }).join('')}</div>`;
    } catch (err) { if (ctx.alive()) res.innerHTML = errorBlock(err.message); }
  };
  $('[data-mkt]', body).addEventListener('click', run);
  $('#mktQ', body).addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); run(); } });
  run();
}

function renderCreate(ctx, body, subId) {
  body.innerHTML = `<form class="card stack" id="createForm" novalidate>
    <div class="field"><label for="crTitle">Название оффера</label><input class="input" id="crTitle" maxlength="200" placeholder="Например: Pets 1B · быстрая выдача" required></div>
    <div class="field"><label for="crDesc">Описание</label><textarea class="textarea" id="crDesc" maxlength="5000" placeholder="Условия, сроки выдачи, гарантии"></textarea></div>
    <div class="grid g2"><div class="field"><label for="crPrice">Цена, ₽</label><input class="input" id="crPrice" type="number" inputmode="decimal" min="0.01" step="0.01" required></div>
    <div class="field"><label for="crAmount">Количество</label><input class="input" id="crAmount" type="number" inputmode="numeric" min="1" step="1" value="1"></div></div>
    <label class="row between" style="cursor:pointer"><span>Сразу активен</span><span class="switch"><input type="checkbox" id="crActive" checked><span class="track"></span></span></label>
    <div class="error" id="crError" role="alert"></div>
    <button class="btn btn-solid btn-block" type="submit" id="crSubmit">${icon('plus')}Создать оффер</button>
    <p class="hint" style="margin:0">Форма использует поля категории FunPay. Если FunPay потребует дополнительные поля, заполните их на сайте.</p></form>`;
  $('#createForm', body).addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const title = $('#crTitle').value.trim();
    const price = Number($('#crPrice').value);
    if (!title) { $('#crError').textContent = 'Введите название оффера.'; return; }
    if (!(price > 0)) { $('#crError').textContent = 'Укажите цену больше нуля.'; return; }
    const button = $('#crSubmit');
    busy(button, true, 'Создаём…');
    $('#crError').textContent = '';
    try {
      await api('/funpay/lots/create', { body: {
        subcategory_id: Number(subId), title, description: $('#crDesc').value, price,
        amount: Number($('#crAmount').value || 1), active: $('#crActive').checked } });
      toast({ title: 'Оффер создан', text: title });
      navigate(`#node/${subId}/lots`);
    } catch (err) {
      $('#crError').textContent = err.message;
      busy(button, false);
    }
  });
}

})();

/* ===== FunPay Lister v5 — views: chats, chat, orders, settings, admin ===== */
(function () {
'use strict';
const { $, $$, esc, api, icon, toast, openDialog, closeDialog, confirmBox, busy, money, fmtClock, fmtUnix, tileHtml,
  safeUrl, navigate, errorBlock, S, store, applyBackground, applyOpacity, logout, isMobile, render } = window.FPL;
const V = window.FPL_VIEWS;
const LOADING = '<div class="loading"><span class="spin"></span>Загружаем…</div>';

async function safe(fn, fallback) {
  try { return await fn(); } catch (err) { return fallback; }
}

/* ---- chats list ---- */
V.chats = async (ctx, view) => {
  view.innerHTML = `<div class="view-inner">
    <div class="row"><input class="input grow" id="chatQ" type="search" placeholder="Поиск по чатам" aria-label="Поиск по чатам" autocomplete="off">
    <button class="btn btn-ghost" type="button" data-refresh aria-label="Обновить">${icon('refresh')}</button></div>
    <div id="chatList" class="stack">${LOADING}</div></div>`;
  let chats = [];
  const draw = () => {
    const box = $('#chatList');
    if (!box) return;
    const q = ($('#chatQ').value || '').trim().toLowerCase();
    if (!chats.length) { box.innerHTML = '<div class="empty"><b>Чатов пока нет</b>Диалоги с покупателями появятся здесь.</div>'; return; }
    const list = chats.filter((c) => !q || `${c.name} ${c.last_message_text}`.toLowerCase().includes(q));
    if (!list.length) { box.innerHTML = '<div class="empty"><b>Ничего не найдено</b>Измените запрос.</div>'; return; }
    box.innerHTML = `<div class="list">${list.map((c) => `<button class="li" type="button" data-chat="${esc(c.id)}">${tileHtml(c.name, '', false)}` +
      `<span class="meta"><span class="t">${esc(c.name)}</span><span class="s">${esc(c.last_message_text || 'Нет сообщений')}</span></span>` +
      `${c.unread_count ? `<span class="unread" aria-label="Непрочитано: ${c.unread_count}">${esc(c.unread_count)}</span>` : ''}</button>`).join('')}</div>`;
  };
  const load = async (silent) => {
    if (!ctx.alive()) return;
    try {
      chats = await api('/funpay/chats');
      S.chatsCache = chats;
      if (ctx.alive()) draw();
    } catch (err) {
      if (ctx.alive() && !silent) $('#chatList').innerHTML = errorBlock(err.message);
    }
  };
  $('#chatQ').addEventListener('input', draw);
  const inner = view.querySelector('.view-inner');
  inner.addEventListener('click', (ev) => {
    if (ev.target.closest('[data-refresh]')) { load(false); return; }
    const row = ev.target.closest('[data-chat]');
    if (row) navigate(`#chat/${row.dataset.chat}`);
  });
  await load(false);
  S.onNotify = () => load(true);
  S.viewTimer = setInterval(() => load(true), 20000);
};

/* ---- single chat ---- */
function bubbleHtml(m) {
  const out = !m.is_incoming;
  const labels = { pending: 'отправляется…', unconfirmed: 'не найдено на FunPay', failed: m.error || 'не отправлено' };
  const label = out ? (labels[m.status] || '') : '';
  const warn = m.status === 'unconfirmed' || m.status === 'failed';
  const image = m.image_link && safeUrl(m.image_link)
    ? `<img src="${esc(safeUrl(m.image_link))}" alt="Фото из чата" loading="lazy" referrerpolicy="no-referrer">` : '';
  return `<div class="bubble${out ? ' out' : ''}${warn ? ' warn' : ''}">${esc(m.text || '')}${image}` +
    `<span class="ts">${out ? 'Вы' : esc(m.author || 'Покупатель')} · ${esc(fmtClock(m.timestamp))}` +
    `${label ? ` · <span class="st">${esc(label)}</span>` : ''}</span></div>`;
}
function readAsBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(',')[1] || '');
    reader.onerror = () => reject(new Error('Не удалось прочитать файл.'));
    reader.readAsDataURL(file);
  });
}

V.chat = async (ctx, view) => {
  const chatId = ctx.args[0];
  const known = (S.chatsCache || []).find((c) => String(c.id) === String(chatId));
  const name = known ? known.name : `Чат ${chatId}`;
  view.innerHTML = `<div class="chat">
    <header class="chat-head"><button class="iconbtn" type="button" data-back aria-label="Назад">${icon('back')}</button>
      ${tileHtml(name, '', false)}
      <div class="grow" style="min-width:0"><div class="t ellipsis" style="font-weight:800">${esc(name)}</div><div class="tiny muted">FunPay · чат ${esc(chatId)}</div></div>
      <button class="iconbtn" type="button" data-refresh aria-label="Обновить переписку">${icon('refresh')}</button></header>
    <div class="msgs" id="msgs">${LOADING}</div>
    <form class="composer" id="composer" autocomplete="off">
      <button class="iconbtn" type="button" data-attach aria-label="Отправить фото">${icon('image')}</button>
      <textarea class="input" id="msgText" rows="1" maxlength="4000" placeholder="Сообщение покупателю" aria-label="Текст сообщения"></textarea>
      <button class="send-btn" type="submit" id="sendBtn" aria-label="Отправить">${icon('send')}</button>
    </form></div>`;
  const msgs = $('#msgs');
  const input = $('#msgText');
  const sendBtn = $('#sendBtn');
  let pending = [];
  let items = [];
  let signature = '';
  let busyLoad = false;

  const draw = (forceScroll) => {
    const nearBottom = msgs.scrollHeight - msgs.scrollTop - msgs.clientHeight < 90;
    const all = items.concat(pending);
    msgs.innerHTML = all.length ? all.map(bubbleHtml).join('') : '<div class="empty" style="margin:auto"><b>Сообщений пока нет</b>Напишите покупателю первым.</div>';
    if (forceScroll || nearBottom) msgs.scrollTop = msgs.scrollHeight;
  };
  const load = async (silent) => {
    if (busyLoad || !ctx.alive()) return;
    busyLoad = true;
    try {
      const fresh = await api(`/funpay/chats/${encodeURIComponent(chatId)}`);
      if (!ctx.alive()) return;
      const next = fresh.map((m) => `${m.id}:${m.status}`).join('|');
      if (next !== signature || !silent) {
        signature = next;
        items = fresh;
        draw(!silent);
      }
    } catch (err) {
      if (ctx.alive() && !silent) msgs.innerHTML = errorBlock(err.message);
    } finally {
      busyLoad = false;
    }
  };

  input.addEventListener('input', () => {
    input.style.height = 'auto';
    input.style.height = `${Math.min(140, input.scrollHeight)}px`;
  });
  input.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter' && !ev.shiftKey && !ev.isComposing && !isMobile()) {
      ev.preventDefault();
      $('#composer').requestSubmit();
    }
  });
  $('#composer').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const text = input.value.trim();
    if (!text) return;
    const temp = { id: `tmp-${Date.now()}`, text, is_incoming: false, status: 'pending', timestamp: new Date().toISOString(), author: 'Вы' };
    pending.push(temp);
    input.value = '';
    input.style.height = 'auto';
    sendBtn.disabled = true;
    draw(true);
    try {
      const res = await api(`/funpay/chats/${encodeURIComponent(chatId)}/send`, { body: { text }, timeout: 90000 });
      pending = pending.filter((p) => p !== temp);
      if (!res.verified) toast({ title: 'Отправка не подтверждена', text: 'FunPay не показал сообщение в истории. Проверьте чат на FunPay перед повторной отправкой.', type: 'error' });
      await load(true);
    } catch (err) {
      temp.status = 'failed';
      temp.error = err.message;
      if (!input.value) input.value = text;
      toast({ title: 'Сообщение не отправлено', text: err.message, type: 'error' });
      draw(true);
    } finally {
      sendBtn.disabled = false;
    }
  });

  $('[data-attach]').addEventListener('click', () => $('#pickImage').click());
  $('#pickImage').onchange = async (ev) => {
    const file = ev.target.files && ev.target.files[0];
    ev.target.value = '';
    if (!file) return;
    if (file.size > 8 * 1024 * 1024) { toast({ title: 'Файл слишком большой', text: 'Максимум 8 МБ.', type: 'error' }); return; }
    const temp = { id: `tmp-${Date.now()}`, text: '', is_incoming: false, status: 'pending', timestamp: new Date().toISOString(), author: 'Вы' };
    pending.push(temp);
    draw(true);
    try {
      const data = await readAsBase64(file);
      const res = await api(`/funpay/chats/${encodeURIComponent(chatId)}/send-image`, {
        body: { filename: file.name.slice(0, 120), mime_type: file.type || 'image/jpeg', data }, timeout: 90000 });
      pending = pending.filter((p) => p !== temp);
      if (!res.verified) toast({ title: 'Отправка фото не подтверждена', text: 'Проверьте чат на FunPay перед повторной отправкой.', type: 'error' });
      await load(true);
    } catch (err) {
      temp.status = 'failed';
      temp.error = err.message;
      draw(true);
      toast({ title: 'Фото не отправлено', text: err.message, type: 'error' });
    }
  };

  view.querySelector('.chat').addEventListener('click', (ev) => {
    if (ev.target.closest('[data-back]')) { window.FPL.goBack(); return; }
    if (ev.target.closest('[data-refresh]')) load(false);
  });
  await load(false);
  S.onNotify = () => load(true);
  S.viewTimer = setInterval(() => load(true), 8000);
  if (!isMobile()) input.focus({ preventScroll: true });
};

/* ---- orders ---- */
function orderCard(o) {
  return `<div class="card"><div class="row between"><div class="grow" style="min-width:0">` +
    `<div class="t ellipsis" style="font-weight:800">#${esc(o.id)} · ${esc(o.title)}</div>` +
    `<div class="tiny muted ellipsis">${esc([o.game, o.server].filter(Boolean).join(' · '))}</div></div>` +
    `<span class="pill${o.status === 'paid' ? ' on' : ''}">${esc(o.status || '—')}</span></div>` +
    `<div class="row between wrap-row" style="margin-top:10px"><span class="small muted">${esc(o.buyer_username || 'покупатель')}${o.date ? ' · ' + esc(o.date) : ''}</span>` +
    `<span class="price">${esc(money(o.price, o.currency))}</span></div></div>`;
}
V.orders = async (ctx, view) => {
  view.innerHTML = `<div class="view-inner">
    <div class="row between wrap-row"><span class="pill" id="ordCount">Заказы</span>
      <button class="btn btn-sm" type="button" data-refresh>${icon('refresh')}Обновить</button></div>
    <div class="grid g2" id="orderStats">
      <section class="card"><div class="label">Активные продажи</div><div class="kpi">—</div><div class="tiny muted">сделки как продавец</div></section>
      <section class="card"><div class="label">Активные покупки</div><div class="kpi">—</div><div class="tiny muted">сделки как покупатель</div></section>
    </div>
    <section class="card"><h3 class="card-h">Последние продажи</h3><div id="ordList" class="stack">${LOADING}</div></section>
  </div>`;
  const load = async () => {
    const statsEl = $('#orderStats');
    const listEl = $('#ordList');
    const [counterResult, salesResult] = await Promise.allSettled([
      api('/funpay/orders/counters', { timeout: 15000 }),
      api('/funpay/orders?limit=100', { timeout: 20000 }),
    ]);
    if (!ctx.alive()) return;
    if (counterResult.status === 'fulfilled') {
      const counts = counterResult.value || {};
      statsEl.innerHTML = `<section class="card"><div class="label">Активные продажи</div><div class="kpi">${counts.sales === null || counts.sales === undefined ? '—' : esc(counts.sales)}</div><div class="tiny muted">сделки как продавец</div></section>` +
        `<section class="card"><div class="label">Активные покупки</div><div class="kpi">${counts.purchases === null || counts.purchases === undefined ? '—' : esc(counts.purchases)}</div><div class="tiny muted">сделки как покупатель</div></section>`;
    } else {
      statsEl.innerHTML = `<section class="card"><div class="label">Продажи и покупки</div><div class="hint">${esc(counterResult.reason?.message || 'Не удалось загрузить счётчики.')}</div></section>`;
    }
    if (salesResult.status === 'fulfilled') {
      const items = salesResult.value || [];
      $('#ordCount').textContent = `${items.length} продаж`;
      listEl.innerHTML = items.length ? items.map(orderCard).join('')
        : '<div class="empty"><b>Продаж пока нет</b>Когда появятся продажи, они отобразятся здесь.</div>';
    } else {
      listEl.innerHTML = errorBlock(salesResult.reason?.message || 'Не удалось загрузить продажи.');
    }
  };
  view.querySelector('.view-inner').addEventListener('click', (ev) => { if (ev.target.closest('[data-refresh]')) load(); });
  await load();
};

/* ---- settings ---- */
V.settings = async (ctx, view) => {
  const status = await safe(() => api('/funpay/status'), { connected: false, message: '' });
  if (!ctx.alive()) return;
  const session = S.session || {};
  const hasBg = !!store.get('fpl.bg', '');
  view.innerHTML = `<div class="view-inner">
  <section class="card stack">
    <h3 class="card-h">Аккаунт FunPay</h3>
    <div class="row between wrap-row"><div style="min-width:0"><div class="h2 ellipsis">${status.connected ? esc(status.username || 'Подключён') : 'Не подключён'}</div>` +
    `<div class="tiny muted">${status.connected ? 'Сессия активна' : esc(status.message || 'Вставьте golden_key из браузера, где вы вошли в FunPay')}</div></div>` +
    `<span class="pill${status.connected ? ' on' : ''}">${status.connected ? 'подключён' : 'нет'}</span></div>
    ${status.connected && status.balance !== null && status.balance !== undefined ? `<div class="small muted">Баланс: <span class="mono" style="color:var(--text)">${esc(money(status.balance, 'RUB'))}</span></div>` : ''}
    <form id="fpForm" class="stack" novalidate>
      <div class="field"><label for="fpKey">golden_key</label><div class="row">
        <input class="input grow" id="fpKey" type="password" autocomplete="off" spellcheck="false" maxlength="1000" placeholder="${status.connected ? 'Новый ключ, чтобы переподключить' : 'Вставьте golden_key'}">
        <button class="iconbtn" type="button" data-showkey aria-label="Показать ключ">${icon('eye')}</button></div></div>
      <details><summary class="small muted" style="cursor:pointer">Дополнительно: User-Agent</summary>
        <div class="field" style="margin-top:10px"><label for="fpUa">User-Agent</label><input class="input" id="fpUa" maxlength="1000" placeholder="Оставьте пустым, если не знаете"></div></details>
      <div class="error" id="fpError" role="alert"></div>
      <div class="row wrap-row"><button class="btn btn-solid" type="submit" id="fpSave">${status.connected ? 'Переподключить' : 'Подключить'}</button>
      ${status.connected ? '<button class="btn btn-danger" type="button" id="fpOff">Отключить</button>' : ''}</div>
      <p class="hint" style="margin:0">Ключ хранится на сервере в зашифрованном виде и не показывается обратно. «Отключить» удаляет его.</p>
    </form>
  </section>
  <section class="card stack">
    <h3 class="card-h">Внешний вид и уведомления</h3>
    <div class="field"><label for="bgUrl">Фон: ссылка на изображение (https)</label>
      <div class="row"><input class="input grow" id="bgUrl" type="url" placeholder="https://…" value="${esc(store.get('fpl.bg', '').startsWith('data:') ? '' : store.get('fpl.bg', ''))}">
      <button class="btn btn-sm" type="button" id="bgApply">Применить</button></div></div>
    <div class="row wrap-row"><button class="btn btn-sm" type="button" id="bgFile">Загрузить фото с устройства</button>
      <button class="btn btn-sm btn-ghost" type="button" id="bgReset"${hasBg ? '' : ' disabled'}>Сбросить фон</button></div>
    <div class="field"><label for="bgOp">Яркость фона: <span class="mono" id="bgOpVal">${Math.round(S.bgOpacity * 100)}%</span></label>
      <input id="bgOp" type="range" min="5" max="60" step="1" value="${Math.round(S.bgOpacity * 100)}" style="width:100%;accent-color:#fff"></div>
    <label class="row between" style="cursor:pointer"><span>Звук уведомлений</span><span class="switch"><input type="checkbox" id="sndSw"${S.sound ? ' checked' : ''}><span class="track"></span></span></label>
    <label class="row between" style="cursor:pointer"><span>Полноэкранный режим при первом касании</span><span class="switch"><input type="checkbox" id="fsSw"${store.get('fpl.autofs', '1') !== '0' ? ' checked' : ''}><span class="track"></span></span></label>
    <div class="error" id="bgError" role="alert"></div>
  </section>
  <section class="card stack">
    <h3 class="card-h">Сессия</h3>
    <div class="row between wrap-row"><div style="min-width:0"><div class="h2">${esc(session.plan_title || '—')}</div>
      <div class="tiny muted">${session.forever ? 'Без срока действия' : session.expires_at ? 'Действует до ' + esc(fmtUnix(session.expires_at)) : ''}</div></div>
      <button class="btn btn-ghost" type="button" id="logoutBtn">${icon('logout')}Выйти</button></div>
    <p class="hint" style="margin:0">Выход завершает сессию только на этом устройстве. Ключ и подключение FunPay сохраняются.</p>
  </section></div>`;

  const root = view.querySelector('.view-inner');
  $('#fpForm').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const key = $('#fpKey').value.trim();
    if (key.length < 8) { $('#fpError').textContent = 'Проверьте golden_key: он длиннее 8 символов.'; return; }
    const button = $('#fpSave');
    busy(button, true, 'Проверяем…');
    $('#fpError').textContent = '';
    try {
      const res = await api('/funpay/connect', { body: { golden_key: key, user_agent: $('#fpUa').value.trim() }, timeout: 90000 });
      $('#fpKey').value = '';
      toast({ title: 'FunPay подключён', text: res.username || '' });
      render();
    } catch (err) {
      $('#fpError').textContent = err.message;
      busy(button, false);
    }
  });
  root.addEventListener('click', async (ev) => {
    if (ev.target.closest('[data-showkey]')) {
      const input = $('#fpKey');
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      ev.target.closest('[data-showkey]').innerHTML = icon(show ? 'eyeOff' : 'eye');
      return;
    }
    if (ev.target.closest('#fpOff')) {
      const ok = await confirmBox('Отключить FunPay?', 'Сохранённый ключ будет удалён с сервера. Чаты и офферы станут недоступны.', 'Отключить', true);
      if (!ok) return;
      try { await api('/funpay/disconnect', { method: 'POST' }); toast({ title: 'FunPay отключён' }); render(); }
      catch (err) { toast({ title: 'Не удалось отключить', text: err.message, type: 'error' }); }
      return;
    }
    if (ev.target.closest('#bgApply')) {
      const url = $('#bgUrl').value.trim();
      $('#bgError').textContent = '';
      if (!url) { store.del('fpl.bg'); applyBackground(''); return; }
      if (!/^https:\/\//i.test(url)) { $('#bgError').textContent = 'Нужна ссылка, которая начинается с https://'; return; }
      store.set('fpl.bg', url);
      applyBackground(url);
      toast({ title: 'Фон применён' });
      return;
    }
    if (ev.target.closest('#bgReset')) {
      store.del('fpl.bg');
      applyBackground('');
      $('#bgUrl').value = '';
      render();
      return;
    }
    if (ev.target.closest('#bgFile')) { $('#pickBackground').click(); return; }
    if (ev.target.closest('#logoutBtn')) { logout(); }
  });
  $('#bgOp').addEventListener('input', (ev) => {
    applyOpacity(Number(ev.target.value) / 100);
    $('#bgOpVal').textContent = `${Math.round(S.bgOpacity * 100)}%`;
    store.set('fpl.bgOpacity', S.bgOpacity);
  });
  $('#sndSw').addEventListener('change', (ev) => { S.sound = ev.target.checked; store.set('fpl.sound', ev.target.checked ? '1' : '0'); });
  $('#fsSw').addEventListener('change', (ev) => store.set('fpl.autofs', ev.target.checked ? '1' : '0'));
  $('#pickBackground').onchange = (ev) => {
    const file = ev.target.files && ev.target.files[0];
    ev.target.value = '';
    if (!file) return;
    if (file.size > 1.5 * 1024 * 1024) { $('#bgError').textContent = 'Изображение больше 1,5 МБ. Выберите файл меньше или используйте ссылку.'; return; }
    const reader = new FileReader();
    reader.onload = () => {
      try {
        store.set('fpl.bg', String(reader.result));
        applyBackground(String(reader.result));
        toast({ title: 'Фон загружен' });
        render();
      } catch (err) { $('#bgError').textContent = 'Не хватает места в браузере для этого фона.'; }
    };
    reader.readAsDataURL(file);
  };
};

/* ---- administration (Telegram admin or dashboard owner) ---- */
const DURATIONS = [['1h', '1 час'], ['6h', '6 часов'], ['12h', '12 часов'], ['24h', '1 день'], ['36h', '1,5 дня'],
  ['3d', '3 дня'], ['7d', '7 дней'], ['30d', '30 дней'], ['forever', 'Навсегда']];

V.admin = async (ctx, view) => {
  if (!S.session || !S.session.is_admin) { view.innerHTML = `<div class="view-inner">${errorBlock('Раздел доступен только администратору.')}</div>`; return; }
  view.innerHTML = `<div class="view-inner">
    <section class="card stack"><h3 class="card-h">Новый ключ</h3>
      <form id="admForm" class="stack" novalidate>
        <div class="grid g2">
          <div class="field"><label for="admDur">Срок</label><select class="select" id="admDur">${DURATIONS.map(([v, l]) => `<option value="${v}">${l}</option>`).join('')}</select></div>
          <div class="field"><label for="admTg">Telegram ID (необязательно)</label><input class="input" id="admTg" inputmode="numeric" maxlength="15" placeholder="например, 123456789"></div>
        </div>
        <div class="error" id="admError" role="alert"></div>
        <button class="btn btn-solid" type="submit" id="admSubmit">Выдать ключ</button>
      </form>
      <div id="admResult"></div>
    </section>
    <section class="card stack">
      <div class="row between"><h3 class="card-h" style="margin:0">Ключи</h3><button class="btn btn-sm" type="button" data-refresh>${icon('refresh')}Обновить</button></div>
      <div id="admList" class="stack">${LOADING}</div>
    </section></div>`;
  const loadList = async () => {
    try {
      const data = await api('/admin/licenses');
      if (!ctx.alive()) return;
      const rows = data.items.slice(0, 60).map((k) => {
        const until = k.expires_at === null ? 'бессрочно' : fmtUnix(k.expires_at);
        const action = k.active
          ? `<button class="btn btn-sm btn-danger" type="button" data-revoke="${esc(k.key)}">Отозвать</button>`
          : `<span class="pill">${k.revoked ? 'отозван' : 'истёк'}</span>`;
        return `<div class="li"><span class="meta"><span class="t mono ellipsis" style="display:block">${esc(k.key)}</span>` +
          `<span class="s" style="display:block">${esc(k.plan_id)} · до ${esc(until)}</span></span>${action}</div>`;
      }).join('');
      $('#admList').innerHTML = rows ? `<div class="list">${rows}</div>` : '<div class="empty"><b>Ключей пока нет</b></div>';
    } catch (err) {
      if (ctx.alive()) $('#admList').innerHTML = errorBlock(err.message);
    }
  };
  $('#admForm').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const tg = $('#admTg').value.trim();
    if (tg && !/^\d{1,15}$/.test(tg)) { $('#admError').textContent = 'Telegram ID — только цифры.'; return; }
    const button = $('#admSubmit');
    busy(button, true, 'Создаём…');
    $('#admError').textContent = '';
    try {
      const key = await api('/admin/licenses', { body: { duration: $('#admDur').value, telegram_user_id: tg ? Number(tg) : 0 } });
      $('#admResult').innerHTML = `<div class="notice mono" style="color:var(--text);word-break:break-all">${esc(key.key)}</div>` +
        `<button class="btn btn-sm" type="button" data-copy="${esc(key.key)}" style="margin-top:8px">${icon('copy')}Скопировать</button>`;
      loadList();
    } catch (err) {
      $('#admError').textContent = err.message;
    } finally {
      busy(button, false);
    }
  });
  view.querySelector('.view-inner').addEventListener('click', async (ev) => {
    if (ev.target.closest('[data-refresh]')) { loadList(); return; }
    const copy = ev.target.closest('[data-copy]');
    if (copy) {
      try { await navigator.clipboard.writeText(copy.dataset.copy); toast({ title: 'Ключ скопирован' }); }
      catch (err) { toast({ title: 'Не удалось скопировать', text: 'Выделите ключ вручную.', type: 'error' }); }
      return;
    }
    const revoke = ev.target.closest('[data-revoke]');
    if (revoke) {
      const ok = await confirmBox('Отозвать ключ?', 'Все сессии этого ключа завершатся сразу.', 'Отозвать', true);
      if (!ok) return;
      try { await api('/admin/licenses/revoke', { body: { key: revoke.dataset.revoke } }); toast({ title: 'Ключ отозван' }); loadList(); }
      catch (err) { toast({ title: 'Не удалось отозвать', text: err.message, type: 'error' }); }
    }
  });
  await loadList();
};

})();

</script>
</body>
</html>
'''


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=PORT)
