"""FunPay Auto Lister Bot — single-file FastAPI + Telegram Web App.

Environment:
  TELEGRAM_BOT_TOKEN  optional; enables the Telegram bot
  DASHBOARD_PASSWORD  optional fallback password for the web dashboard
  RENDER_EXTERNAL_URL Render public URL; enables Telegram webhook + WebApp button
  PORT                HTTP port (Render sets this automatically)

FunPay access is connected from Settings using the account's golden_key cookie and
browser User-Agent. The values stay in process memory only and are never logged.
"""
from __future__ import annotations

import asyncio
import difflib
import hashlib
import html
import hmac
import json
import logging
import os
import secrets
import sqlite3
import time
from pathlib import Path
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import parse_qs, urljoin, urlparse

from bs4 import BeautifulSoup
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "")
PORT = int(os.getenv("PORT", "8000"))
RENDER_EXTERNAL_URL = os.getenv("RENDER_EXTERNAL_URL", "").strip().rstrip("/")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "").strip() or None
APP_VERSION = "3.2.0"
ADMIN_TELEGRAM_ID = 8357023784
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
START_TIME = time.monotonic()
SESSION_TTL_SECONDS = 12 * 60 * 60
LICENSE_DB_PATH = os.getenv("LICENSE_DB_PATH", str(Path(__file__).with_name("licenses.sqlite3")))
STAR_PLANS: dict[str, dict[str, Any]] = {
    "day": {"title": "1 день", "stars": 15, "seconds": 24 * 60 * 60},
    "day_half": {"title": "1,5 дня", "stars": 25, "seconds": 36 * 60 * 60},
    "three_days": {"title": "3 дня", "stars": 50, "seconds": 3 * 24 * 60 * 60},
    "week": {"title": "1 неделя", "stars": 100, "seconds": 7 * 24 * 60 * 60},
    "month": {"title": "1 месяц", "stars": 400, "seconds": 30 * 24 * 60 * 60},
    "forever": {"title": "Навсегда", "stars": 1000, "seconds": None},
}

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger("funpay_lister")

# Dashboard sessions are intentionally ephemeral. Restarting the process invalidates them.
SESSIONS: dict[str, float] = {}
SESSION_META: dict[str, dict[str, Any]] = {}
LOGIN_ATTEMPTS: dict[str, list[float]] = {}
FP_CLIENT: Any = None
FP_ACCOUNT: Any = None
FP_PROFILE: dict[str, Any] | None = None
FP_LOCK = asyncio.Lock()
FP_CATEGORIES_CACHE: list[dict[str, Any]] = []
FP_CATEGORIES_CACHE_AT = 0.0


def init_license_db() -> None:
    """Persistent storage for free claims and Telegram Stars purchases."""
    Path(LICENSE_DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(LICENSE_DB_PATH) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS license_keys (
            license_key TEXT PRIMARY KEY,
            telegram_user_id INTEGER NOT NULL,
            plan_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER,
            telegram_payment_charge_id TEXT UNIQUE
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS free_claims (
            telegram_user_id INTEGER PRIMARY KEY,
            license_key TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS sent_chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id TEXT NOT NULL,
            message_id TEXT NOT NULL,
            text TEXT NOT NULL,
            author TEXT NOT NULL DEFAULT 'Вы',
            timestamp TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            UNIQUE(chat_id, message_id)
        )""")
        db.commit()


def create_license_key() -> str:
    token = secrets.token_hex(12).upper()
    return "FP-" + "-".join(token[i:i + 6] for i in range(0, len(token), 6))


def claim_free_license(user_id: int) -> tuple[str | None, int | None, bool]:
    """Return (key, expiry, was_created). Free plan is one 24-hour key per Telegram account."""
    init_license_db()
    now = int(time.time())
    with sqlite3.connect(LICENSE_DB_PATH) as db:
        row = db.execute("SELECT license_key FROM free_claims WHERE telegram_user_id=?", (user_id,)).fetchone()
        if row:
            key_row = db.execute("SELECT expires_at FROM license_keys WHERE license_key=?", (row[0],)).fetchone()
            return row[0], (key_row[0] if key_row else now + 86400), False
        key = create_license_key()
        expires = now + 86400
        db.execute(
            "INSERT INTO license_keys(license_key,telegram_user_id,plan_id,created_at,expires_at) VALUES(?,?,?,?,?)",
            (key, user_id, "free", now, expires),
        )
        db.execute("INSERT INTO free_claims(telegram_user_id,license_key,created_at) VALUES(?,?,?)", (user_id, key, now))
        db.commit()
        return key, expires, True


def issue_paid_license(user_id: int, plan_id: str, charge_id: str) -> tuple[str, int | None, bool]:
    init_license_db()
    if plan_id not in STAR_PLANS:
        raise ValueError("Unknown license plan")
    now = int(time.time())
    plan = STAR_PLANS[plan_id]
    expires = now + int(plan["seconds"]) if plan["seconds"] is not None else None
    with sqlite3.connect(LICENSE_DB_PATH) as db:
        existing = db.execute(
            "SELECT license_key,expires_at FROM license_keys WHERE telegram_payment_charge_id=?", (charge_id,)
        ).fetchone()
        if existing:
            return existing[0], existing[1], False
        key = create_license_key()
        db.execute(
            "INSERT INTO license_keys(license_key,telegram_user_id,plan_id,created_at,expires_at,telegram_payment_charge_id) VALUES(?,?,?,?,?,?)",
            (key, user_id, plan_id, now, expires, charge_id),
        )
        db.commit()
        return key, expires, True


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


def create_admin_license(duration: str, telegram_user_id: int | None = None) -> dict[str, Any]:
    """Issue a manually-created key; old keys remain in the ledger after expiry."""
    if duration not in ADMIN_LICENSE_DURATIONS:
        raise ValueError("Неизвестный срок ключа.")
    title, seconds = ADMIN_LICENSE_DURATIONS[duration]
    now = int(time.time())
    expires = now + seconds if seconds is not None else None
    key = create_license_key()
    owner_id = int(telegram_user_id or 0)
    init_license_db()
    with sqlite3.connect(LICENSE_DB_PATH) as db:
        db.execute(
            "INSERT INTO license_keys(license_key,telegram_user_id,plan_id,created_at,expires_at) VALUES(?,?,?,?,?)",
            (key, owner_id, f"admin_{duration}", now, expires),
        )
        db.commit()
    return {"key": key, "duration": duration, "duration_title": title, "telegram_user_id": owner_id,
            "created_at": now, "expires_at": expires, "active": expires is None or expires > now}


def save_sent_chat_message(chat_id: int | str, message_id: str | int | None, text: str, author: str = "Вы") -> dict[str, Any]:
    init_license_db()
    now = int(time.time())
    stable_id = str(message_id) if message_id is not None else f"local-{now}-{secrets.token_hex(5)}"
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with sqlite3.connect(LICENSE_DB_PATH) as db:
        db.execute(
            "INSERT OR IGNORE INTO sent_chat_messages(chat_id,message_id,text,author,timestamp,created_at) VALUES(?,?,?,?,?,?)",
            (str(chat_id), stable_id, text, author or "Вы", stamp, now),
        )
        db.commit()
    return {"id": stable_id, "chat_id": str(chat_id), "text": text, "author": author or "Вы",
            "author_id": None, "is_incoming": False, "image_link": None, "timestamp": stamp}


def format_expiry(expires_at: int | None) -> str:
    if expires_at is None:
        return "без срока действия"
    return datetime.fromtimestamp(expires_at, timezone.utc).strftime("%d.%m.%Y в %H:%M UTC")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def public_url() -> str:
    return RENDER_EXTERNAL_URL or f"http://127.0.0.1:{PORT}"


def clean_model(value: Any) -> Any:
    """Convert Pydantic models/enums into JSON-compatible values."""
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {str(k): clean_model(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [clean_model(v) for v in value]
    if hasattr(value, "value"):
        return value.value
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def require_session(x_dashboard_session: str | None = Header(default=None, alias="X-Dashboard-Session")) -> bool:
    """Protect endpoints and enforce license expiration server-side."""
    if not x_dashboard_session:
        raise HTTPException(status_code=401, detail="Сессия закончилась. Войдите снова.")
    expiry = SESSIONS.get(x_dashboard_session)
    meta = SESSION_META.get(x_dashboard_session, {})
    now = time.time()
    license_expiry = meta.get("license_expires_at")
    if expiry is None or expiry < now or (license_expiry is not None and int(license_expiry) <= int(now)):
        SESSIONS.pop(x_dashboard_session, None)
        SESSION_META.pop(x_dashboard_session, None)
        raise HTTPException(status_code=401, detail="Срок ключа закончился или сессия истекла. Получите новый ключ.")
    return True


def require_admin(x_dashboard_session: str | None = Header(default=None, alias="X-Dashboard-Session")) -> bool:
    require_session(x_dashboard_session)
    if not SESSION_META.get(x_dashboard_session or "", {}).get("is_admin", False):
        raise HTTPException(status_code=403, detail="Этот раздел доступен только администратору Telegram.")
    return True


def verify_telegram_init_data(init_data: str) -> dict[str, Any] | None:
    """Validate Telegram WebApp initData using the configured bot token."""
    if not TELEGRAM_BOT_TOKEN or not init_data or len(init_data) > 8192:
        return None
    try:
        from urllib.parse import parse_qsl
        values = dict(parse_qsl(init_data, keep_blank_values=True, strict_parsing=True))
        supplied_hash = values.pop("hash", "")
        auth_date = int(values.get("auth_date", "0"))
        now = int(time.time())
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


def need_funpay() -> tuple[Any, Any]:
    if FP_CLIENT is None or FP_ACCOUNT is None:
        raise HTTPException(status_code=409, detail="Сначала подключите аккаунт FunPay в разделе «Настройки».")
    return FP_CLIENT, FP_ACCOUNT


async def funpay_connect(golden_key: str, user_agent: str | None = None) -> dict[str, Any]:
    """Connect and verify a FunPay session without writing credentials to disk."""
    global FP_CLIENT, FP_ACCOUNT, FP_PROFILE, FP_CATEGORIES_CACHE, FP_CATEGORIES_CACHE_AT
    try:
        from funpay_api_python import FunPayAccount, FunPayClient
    except ImportError as exc:
        raise HTTPException(
            status_code=503,
            detail="Библиотека FunPay не установлена. Добавьте funpay-api-python в requirements.txt.",
        ) from exc

    if len(golden_key.strip()) < 8:
        raise HTTPException(status_code=422, detail="Проверьте значение golden_key.")

    new_client = FunPayClient(
        golden_key=golden_key.strip(),
        user_agent=(user_agent or "").strip() or os.getenv("FUNPAY_USER_AGENT", "").strip() or DEFAULT_USER_AGENT,
        timeout=float(os.getenv("FUNPAY_TIMEOUT", "20")),
        locale="ru",
        min_interval=0.45,
    )
    new_account = FunPayAccount(new_client)
    try:
        async with FP_LOCK:
            profile = await new_account.get_me()
            balance = await new_account.get_balance()
        profile_data = clean_model(profile)
        balance_data = clean_model(balance)
    except Exception as exc:
        await new_client.close()
        # Do not echo request headers/cookies or any submitted secret in the response.
        reason = str(exc)
        if "Unauthorized" in reason or "Profile not detected" in reason or "401" in reason:
            reason = "FunPay не принял сессию. Проверьте golden_key и User-Agent."
        else:
            reason = "Не удалось подключиться к FunPay. Проверьте сессию и попробуйте ещё раз."
        log.warning("FunPay connection failed: %s", type(exc).__name__)
        raise HTTPException(status_code=401, detail=reason) from exc

    old_client = FP_CLIENT
    FP_CLIENT, FP_ACCOUNT = new_client, new_account
    FP_PROFILE = {"profile": profile_data, "balance": balance_data, "connected_at": utc_now()}
    FP_CATEGORIES_CACHE = []
    FP_CATEGORIES_CACHE_AT = 0.0
    if old_client is not None:
        try:
            await old_client.close()
        except Exception:
            pass
    log.info("FunPay connected as account id %s", profile_data.get("id"))
    return {"connected": True, **FP_PROFILE}


def extract_form_fields(form: Any) -> dict[str, str]:
    """Extract the default values from a FunPay offer-editor form."""
    fields: dict[str, str] = {}
    for node in form.find_all(["input", "textarea", "select"]):
        name = node.get("name")
        if not name:
            continue
        tag = node.name
        if tag == "input":
            input_type = (node.get("type") or "text").lower()
            if input_type in ("checkbox", "radio"):
                if node.has_attr("checked"):
                    fields[name] = node.get("value") or "on"
            else:
                fields[name] = node.get("value") or ""
        elif tag == "textarea":
            fields[name] = node.get_text() or ""
        elif tag == "select":
            selected = node.find("option", selected=True) or node.find("option")
            if selected is not None:
                fields[name] = selected.get("value") or selected.get_text(strip=True)
    return fields


async def create_funpay_lot(
    subcategory_id: int,
    title: str,
    description: str,
    price: float,
    amount: int,
    active: bool = True,
) -> dict[str, Any]:
    """Create a new regular offer by using the editor form returned by FunPay."""
    client, _account = need_funpay()
    async with FP_LOCK:
        response = await client.get("lots/offerEdit", node=subcategory_id, raise_not_200=True)
        soup = BeautifulSoup(response.text, "html.parser")
        form = soup.select_one("form.form-offer-editor") or soup.find("form")
        if not form:
            raise HTTPException(
                status_code=502,
                detail="FunPay не вернул форму создания оффера для этой категории. Попробуйте другую игру или создайте лот на сайте FunPay.",
            )
        fields = extract_form_fields(form)
        # Retain dynamic fields (server/platform/payment options) from the category form.
        fields["offer_id"] = fields.get("offer_id") or "0"
        fields["node_id"] = str(subcategory_id)
        fields["csrf_token"] = getattr(client, "csrf_token", "") or fields.get("csrf_token", "")
        fields["fields[summary][ru]"] = title.strip()
        fields["fields[desc][ru]"] = description.strip()
        fields["price"] = str(price)
        fields["amount"] = str(amount)
        if active:
            fields["active"] = "on"
        else:
            fields.pop("active", None)
        headers = {
            "accept": "*/*",
            "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
            "x-requested-with": "XMLHttpRequest",
        }
        saved = await client.post("lots/offerSave", data=fields, headers=headers, raise_not_200=True)
        try:
            result = saved.json()
        except Exception:
            raise HTTPException(status_code=502, detail="FunPay вернул неожиданный ответ при сохранении оффера.")
        if result.get("error") or result.get("errors"):
            errors = result.get("errors") or result.get("error")
            safe_errors = str(errors)[:700]
            raise HTTPException(status_code=422, detail=f"FunPay не сохранил оффер: {safe_errors}")
        return {"ok": True, "result": result, "subcategory_id": subcategory_id}


@asynccontextmanager
async def lifespan(app: FastAPI):
    global FP_CLIENT, FP_ACCOUNT, FP_PROFILE
    tg_app = None
    notify_task = None
    if TELEGRAM_BOT_TOKEN:
        try:
            from telegram import InlineKeyboardButton, InlineKeyboardMarkup, LabeledPrice, MenuButtonWebApp, WebAppInfo, Update
            from telegram.ext import Application, CallbackQueryHandler, CommandHandler, MessageHandler, PreCheckoutQueryHandler, filters

            tg_app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
            init_license_db()

            async def start_command(update: Any, context: Any) -> None:
                caption = (
                    "<b>FunPay Auto Lister</b>\n"
                    "Управляйте офферами, поиском, чатами и заказами в одной панели.\n\n"
                    "Выберите бесплатный план или оформите ключ за Telegram Stars."
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
                image_path = Path(__file__).with_name("a_sleek_dark_futuristic_cyber_neon_ui_welcome_s.png")
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
                    key, expires, created = claim_free_license(user.id)
                    text = (
                        ("✅ <b>Ваш FREE PLAN ключ создан</b>" if created else "ℹ️ <b>Ваш FREE PLAN ключ уже был выдан</b>")
                        + f"\n\n<code>{html.escape(key or '')}</code>\n\n"
                        + f"Действует до: <b>{format_expiry(expires)}</b>\n"
                        + "Бесплатный ключ выдаётся один раз на Telegram-аккаунт. Сохраните его в безопасном месте."
                    )
                    await query.message.reply_text(text, parse_mode="HTML")
                    return
                if query.data == "license:buy":
                    rows = [[InlineKeyboardButton(f"{p['title']} · {p['stars']} ⭐", callback_data=f"license:plan:{pid}")]
                            for pid, p in STAR_PLANS.items()]
                    await query.message.reply_text(
                        "<b>Выберите срок ключа</b>\nОплата проходит внутри Telegram в Stars.",
                        parse_mode="HTML", reply_markup=InlineKeyboardMarkup(rows),
                    )
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
                    key, expires, created = issue_paid_license(
                        user.id, plan_id, payment.telegram_payment_charge_id
                    )
                    plan = STAR_PLANS[plan_id]
                    caption = (
                        "✅ <b>Оплата прошла успешно!</b>\n\n"
                        f"Тариф: <b>{plan['title']}</b> · <b>{plan['stars']} ⭐</b>\n"
                        f"Ваш ключ: <code>{html.escape(key)}</code>\n"
                        f"Действует: <b>{format_expiry(expires)}</b>\n\n"
                        "Скопируйте и сохраните ключ."
                    )
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
            app.state.telegram_app = tg_app
            await tg_app.initialize()
            await tg_app.start()
            me = await tg_app.bot.get_me()
            if RENDER_EXTERNAL_URL.startswith("https://"):
                await tg_app.bot.set_webhook(
                    url=f"{RENDER_EXTERNAL_URL}/telegram/webhook",
                    secret_token=WEBHOOK_SECRET,
                    allowed_updates=Update.ALL_TYPES,
                    drop_pending_updates=False,
                )
                log.info("Telegram webhook configured for %s", RENDER_EXTERNAL_URL)
                try:
                    await tg_app.bot.set_chat_menu_button(
                        menu_button=MenuButtonWebApp(text="Lister", web_app=WebAppInfo(url=RENDER_EXTERNAL_URL))
                    )
                except Exception:
                    pass
            else:
                await tg_app.bot.delete_webhook(drop_pending_updates=True)
                await tg_app.updater.start_polling(allowed_updates=Update.ALL_TYPES)
            log.info("Telegram bot started: @%s", me.username)
            notify_task = asyncio.create_task(telegram_message_notifier(tg_app.bot), name="funpay-message-notifier")
        except Exception as exc:
            log.exception("Telegram bot initialization failed: %s", type(exc).__name__)
            if tg_app:
                try:
                    await tg_app.shutdown()
                except Exception:
                    pass
            tg_app = None
            app.state.telegram_app = None
    else:
        log.warning("TELEGRAM_BOT_TOKEN is not configured; the web dashboard will still start.")
    startup_golden_key = os.getenv("FUNPAY_GOLDEN_KEY", "").strip()
    if startup_golden_key and FP_ACCOUNT is None:
        try:
            await funpay_connect(startup_golden_key, os.getenv("FUNPAY_USER_AGENT", "").strip() or DEFAULT_USER_AGENT)
            log.info("FunPay auto-connected from environment configuration")
        except Exception as exc:
            log.warning("FunPay auto-connect failed: %s", type(exc).__name__)
    if not DASHBOARD_PASSWORD:
        log.warning("DASHBOARD_PASSWORD is not set; sign-in still works with a valid license key or Telegram admin initData.")
    try:
        yield
    finally:
        if notify_task:
            notify_task.cancel()
            try:
                await notify_task
            except asyncio.CancelledError:
                pass
        if tg_app:
            try:
                if tg_app.updater and tg_app.updater.running:
                    await tg_app.updater.stop()
                await tg_app.stop()
                await tg_app.shutdown()
            except Exception as exc:
                log.warning("Telegram shutdown issue: %s", type(exc).__name__)
        if FP_CLIENT is not None:
            try:
                await FP_CLIENT.close()
            except Exception:
                pass
            FP_CLIENT = None
            FP_ACCOUNT = None
            FP_PROFILE = None


async def telegram_message_notifier(bot: Any) -> None:
    """Poll FunPay chat IDs and notify the configured administrator about new incoming messages."""
    seen: dict[str, tuple[str, str]] = {}
    initialized = False
    while True:
        try:
            account = FP_ACCOUNT
            if account is not None:
                async with FP_LOCK:
                    chat_items = await account.get_chats()
                snapshots = []
                for item in chat_items:
                    data = clean_model(item)
                    if not isinstance(data, dict):
                        continue
                    cid = str(data.get("id", ""))
                    if not cid:
                        continue
                    latest_id = str(data.get("last_message_id") or "")
                    latest_text = str(data.get("last_message_text") or "")
                    snapshots.append((cid, data, latest_id, latest_text))
                if not initialized:
                    for cid, _data, latest_id, latest_text in snapshots:
                        seen[cid] = (latest_id, latest_text)
                    initialized = True
                else:
                    for cid, data, latest_id, latest_text in snapshots:
                        old_id, old_text = seen.get(cid, ("", ""))
                        if latest_id == old_id and latest_text == old_text:
                            continue
                        incoming_messages = []
                        try:
                            previous_id = int(old_id) if old_id.isdigit() else None
                            async with FP_LOCK:
                                history = await account.get_chat_history(int(cid) if cid.isdigit() else cid, last_message_id=previous_id)
                            for msg in history or []:
                                msg_data = clean_model(msg)
                                if not isinstance(msg_data, dict):
                                    continue
                                msg_id = str(msg_data.get("id") or "")
                                if old_id.isdigit() and msg_id.isdigit() and int(msg_id) <= int(old_id):
                                    continue
                                if msg_data.get("is_incoming"):
                                    incoming_messages.append(msg_data)
                        except Exception:
                            log.debug("Notification history lookup failed", exc_info=True)
                        # A newly appearing chat may not have an old ID; only notify on a changed snapshot.
                        if incoming_messages:
                            outgoing = incoming_messages[-3:]
                            for msg in outgoing:
                                content = str(msg.get("text") or "Сообщение без текста").strip()
                                if msg.get("image_link"):
                                    content += " [изображение]"
                                message = ("💬 <b>Новое сообщение в FunPay</b>\n"
                                           f"Чат: <b>{html.escape(str(data.get('name') or cid))}</b>\n"
                                           f"От: <b>{html.escape(str(msg.get('author') or 'Покупатель'))}</b>\n"
                                           f"{html.escape(content[:2500])}\n"
                                           f"<i>Чат ID: {html.escape(cid)}</i>")
                                try:
                                    await bot.send_message(chat_id=ADMIN_TELEGRAM_ID, text=message, parse_mode="HTML", disable_web_page_preview=True)
                                except Exception as send_exc:
                                    log.warning("Telegram message notification could not be delivered: %s", type(send_exc).__name__)
                        elif cid not in seen and latest_text:
                            latest_author = str(data.get("last_message_author") or "")
                            own_name = str((FP_PROFILE or {}).get("profile", {}).get("username") or "")
                            if latest_author and latest_author.casefold() != own_name.casefold():
                                message = ("💬 <b>Новое сообщение в FunPay</b>\n"
                                           f"Чат: <b>{html.escape(str(data.get('name') or cid))}</b>\n"
                                           f"{html.escape(latest_text[:2500])}\n<i>Чат ID: {html.escape(cid)}</i>")
                                try:
                                    await bot.send_message(chat_id=ADMIN_TELEGRAM_ID, text=message, parse_mode="HTML", disable_web_page_preview=True)
                                except Exception as send_exc:
                                    log.warning("Telegram message notification could not be delivered: %s", type(send_exc).__name__)
                        seen[cid] = (latest_id, latest_text)
                known = {cid for cid, *_ in snapshots}
                if len(seen) > 1000:
                    seen = {k: v for k, v in seen.items() if k in known}
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.debug("FunPay notifier loop issue: %s", type(exc).__name__)
        await asyncio.sleep(3)


app = FastAPI(title="FunPay Auto Lister Bot", version=APP_VERSION, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


class LoginBody(BaseModel):
    password: str = Field(default="", max_length=300)
    init_data: str = Field(default="", max_length=8192)


class FunPayConnectBody(BaseModel):
    golden_key: str = Field(min_length=8, max_length=1000)
    user_agent: str = Field(default="", max_length=1000)


class ChatMessageBody(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


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


class MessageBody(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


class AdminLicenseCreateBody(BaseModel):
    duration: str = Field(default="24h", min_length=1, max_length=20)
    telegram_user_id: int | None = Field(default=None, ge=0)


@app.post("/api/login")
async def login(payload: LoginBody, request: Request) -> dict[str, Any]:
    host = request.client.host if request.client else "unknown"
    now = time.time()
    attempts = [t for t in LOGIN_ATTEMPTS.get(host, []) if now - t < 300]
    if len(attempts) >= 8:
        raise HTTPException(status_code=429, detail="Слишком много попыток. Подождите пять минут.")

    supplied = payload.password.strip()
    verified_user = verify_telegram_init_data(payload.init_data)
    is_admin = bool(verified_user and int(verified_user.get("id", 0) or 0) == ADMIN_TELEGRAM_ID)
    password_ok = bool(DASHBOARD_PASSWORD) and bool(supplied) and hmac.compare_digest(supplied, DASHBOARD_PASSWORD)
    license_row = None
    license_ok = False
    if not password_ok and not is_admin and supplied:
        try:
            init_license_db()
            with sqlite3.connect(LICENSE_DB_PATH) as db:
                license_row = db.execute(
                    "SELECT license_key,telegram_user_id,plan_id,expires_at,created_at FROM license_keys WHERE license_key = ? COLLATE NOCASE",
                    (supplied,),
                ).fetchone()
            license_ok = bool(license_row and (license_row[3] is None or int(license_row[3]) > int(now)))
        except sqlite3.Error:
            log.exception("License lookup failed during login")
            license_ok = False

    if not (password_ok or license_ok or is_admin):
        attempts.append(now)
        LOGIN_ATTEMPTS[host] = attempts
        raise HTTPException(status_code=401, detail="Неверный пароль панели или ключ. Проверьте ключ и срок его действия.")
    LOGIN_ATTEMPTS.pop(host, None)
    token = secrets.token_urlsafe(32)
    session_expiry = now + SESSION_TTL_SECONDS
    meta: dict[str, Any] = {"is_admin": is_admin, "plan_id": "admin" if is_admin else "password" if password_ok else "", "license_key": None, "license_expires_at": None}
    if license_ok and license_row:
        meta.update({"plan_id": str(license_row[2]), "license_key": str(license_row[0]), "license_expires_at": license_row[3], "license_created_at": int(license_row[4])})
        if license_row[3] is not None:
            session_expiry = min(session_expiry, float(license_row[3]))
    SESSIONS[token] = session_expiry
    SESSION_META[token] = meta
    for old_token, expiry in list(SESSIONS.items()):
        if expiry < now:
            SESSIONS.pop(old_token, None)
            SESSION_META.pop(old_token, None)
    return {"token": token, "expires_in": max(0, int(session_expiry - now)), "is_admin": is_admin, "plan_id": meta["plan_id"]}


@app.post("/api/logout")
async def logout(_: bool = Depends(require_session), x_dashboard_session: str | None = Header(default=None, alias="X-Dashboard-Session")) -> dict[str, bool]:
    if x_dashboard_session:
        SESSIONS.pop(x_dashboard_session, None)
        SESSION_META.pop(x_dashboard_session, None)
    return {"ok": True}


@app.get("/api/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "version": APP_VERSION, "uptime_seconds": int(time.monotonic() - START_TIME), "telegram_enabled": bool(TELEGRAM_BOT_TOKEN)}


@app.get("/api/session/info")
async def session_info(_: bool = Depends(require_session), x_dashboard_session: str | None = Header(default=None, alias="X-Dashboard-Session")) -> dict[str, Any]:
    meta = SESSION_META.get(x_dashboard_session or "", {})
    expiry = meta.get("license_expires_at")
    return {"is_admin": bool(meta.get("is_admin")), "plan_id": meta.get("plan_id", ""), "created_at": meta.get("license_created_at"), "expires_at": expiry,
            "remaining_seconds": None if expiry is None else max(0, int(expiry - time.time()))}


@app.post("/api/admin/licenses")
async def admin_create_license(payload: AdminLicenseCreateBody, _: bool = Depends(require_admin)) -> dict[str, Any]:
    if payload.duration not in ADMIN_LICENSE_DURATIONS:
        raise HTTPException(status_code=422, detail="Выберите срок из списка.")
    try:
        return create_admin_license(payload.duration, payload.telegram_user_id)
    except sqlite3.Error as exc:
        log.exception("Admin key creation failed")
        raise HTTPException(status_code=500, detail="Не удалось сохранить ключ в журнале.") from exc


@app.get("/api/admin/licenses")
async def admin_licenses(_: bool = Depends(require_admin)) -> dict[str, Any]:
    """Read-only historical license ledger; expired keys remain in the database."""
    init_license_db()
    now = int(time.time())
    with sqlite3.connect(LICENSE_DB_PATH) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute("SELECT license_key,telegram_user_id,plan_id,created_at,expires_at,telegram_payment_charge_id FROM license_keys ORDER BY created_at DESC").fetchall()
    values = []
    for row in rows:
        expires = row["expires_at"]
        values.append({"key": row["license_key"], "telegram_user_id": row["telegram_user_id"] or None, "plan_id": row["plan_id"],
                       "created_at": row["created_at"], "expires_at": expires,
                       "active": expires is None or int(expires) > now,
                       "payment_id": row["telegram_payment_charge_id"]})
    return {"total": len(values), "items": values}


@app.get("/api/funpay/status")
async def funpay_status(_: bool = Depends(require_session)) -> dict[str, Any]:
    return {"connected": bool(FP_CLIENT and FP_ACCOUNT), **(FP_PROFILE or {})}


@app.post("/api/funpay/connect")
async def connect_funpay(payload: FunPayConnectBody, _: bool = Depends(require_session)) -> dict[str, Any]:
    return await funpay_connect(payload.golden_key, payload.user_agent)


@app.post("/api/funpay/disconnect")
async def disconnect_funpay(_: bool = Depends(require_session)) -> dict[str, bool]:
    global FP_CLIENT, FP_ACCOUNT, FP_PROFILE, FP_CATEGORIES_CACHE, FP_CATEGORIES_CACHE_AT
    old_client = FP_CLIENT
    FP_CLIENT = FP_ACCOUNT = FP_PROFILE = None
    FP_CATEGORIES_CACHE = []
    FP_CATEGORIES_CACHE_AT = 0.0
    if old_client is not None:
        await old_client.close()
    return {"ok": True}


@app.get("/api/funpay/categories")
async def categories(_: bool = Depends(require_session)) -> list[dict[str, Any]]:
    global FP_CATEGORIES_CACHE, FP_CATEGORIES_CACHE_AT
    _client, account = need_funpay()
    try:
        async with FP_LOCK:
            values = await account.get_categories()
        FP_CATEGORIES_CACHE = [clean_model(item) for item in values]
        FP_CATEGORIES_CACHE_AT = time.time()
        return FP_CATEGORIES_CACHE
    except HTTPException:
        raise
    except Exception as exc:
        log.warning("Categories read failed: %s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Не удалось загрузить список игр и категорий FunPay.") from exc


@app.get("/api/funpay/catalog/search")
async def search_funpay_catalog(q: str = "", _: bool = Depends(require_session)) -> list[dict[str, Any]]:
    """Fuzzy search actual FunPay categories and subcategories (one-character input works)."""
    global FP_CATEGORIES_CACHE, FP_CATEGORIES_CACHE_AT
    _client, account = need_funpay()
    query = " ".join(q.casefold().split())[:80]
    if time.time() - FP_CATEGORIES_CACHE_AT > 60 or not FP_CATEGORIES_CACHE:
        try:
            async with FP_LOCK:
                raw = await account.get_categories()
            FP_CATEGORIES_CACHE = [clean_model(item) for item in raw]
            FP_CATEGORIES_CACHE_AT = time.time()
        except Exception as exc:
            log.warning("FunPay catalog search failed: %s", type(exc).__name__)
            raise HTTPException(status_code=502, detail="Не удалось запросить каталог FunPay.") from exc

    def rank(name: str) -> float:
        normalized = " ".join(str(name or "").casefold().split())
        if not query:
            return 5.0
        if normalized.startswith(query):
            return 120.0 - min(len(normalized), 80) / 20
        words = normalized.split()
        if any(word.startswith(query) for word in words):
            return 108.0 - min(len(normalized), 80) / 20
        if query in normalized:
            return 95.0 - normalized.index(query) / 100
        ratio = max([difflib.SequenceMatcher(None, query, word).ratio() for word in words] or [0.0])
        if len(query) == 1 and ratio < 1:
            return 0.0
        if len(query) >= 2 and ratio >= 0.35:
            return 45.0 * ratio
        return 0.0

    matches: list[dict[str, Any]] = []
    for category in FP_CATEGORIES_CACHE:
        category_id = category.get("id")
        category_name = str(category.get("name") or "")
        score = rank(category_name)
        if score > 0:
            matches.append({"type": "category", "category_id": category_id, "subcategory_id": None,
                            "category_name": category_name, "name": category_name, "score": score})
        subs = category.get("subcategories") if isinstance(category.get("subcategories"), list) else []
        for sub in subs:
            sub_name = str(sub.get("name") or "")
            sub_score = rank(sub_name)
            if sub_score > 0:
                matches.append({"type": "subcategory", "category_id": category_id, "subcategory_id": sub.get("id"),
                                "category_name": category_name, "name": sub_name, "score": sub_score + 1.0})
    matches.sort(key=lambda item: (-item["score"], str(item["name"]).casefold()))
    return [{k: v for k, v in item.items() if k != "score"} for item in matches[:30]]


@app.get("/api/funpay/subcategories/{category_id}")
async def subcategories(category_id: int, _: bool = Depends(require_session)) -> list[dict[str, Any]]:
    _client, account = need_funpay()
    try:
        async with FP_LOCK:
            values = await account.get_subcategories(category_id)
        return [clean_model(item) for item in values]
    except Exception as exc:
        log.warning("Subcategories read failed: %s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Не удалось загрузить подкатегории этой игры.") from exc


@app.get("/api/funpay/lots")
async def my_lots(subcategory_id: int, _: bool = Depends(require_session)) -> list[dict[str, Any]]:
    _client, account = need_funpay()
    try:
        async with FP_LOCK:
            values = await account.get_my_lots(subcategory_id)
        return [clean_model(item) for item in values]
    except Exception as exc:
        log.warning("My lots read failed: %s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Не удалось загрузить офферы. Проверьте выбранную категорию.") from exc


@app.get("/api/funpay/offers")
async def search_offers(subcategory_id: int, q: str = "", _: bool = Depends(require_session)) -> list[dict[str, Any]]:
    """Search publicly visible offer cards in the selected FunPay subcategory."""
    client, _account = need_funpay()
    if len(q) > 180:
        raise HTTPException(status_code=422, detail="Поисковый запрос слишком длинный.")
    try:
        async with FP_LOCK:
            response = await client.get(f"lots/{subcategory_id}/", query=q.strip() or None, raise_not_200=True)
        soup = BeautifulSoup(response.text, "html.parser")
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
            price_raw = (price_node.get("data-s") if price_node else None)
            if not price_raw and price_node:
                price_raw = price_node.get_text(" ", strip=True).replace("\u00a0", " ").split()[0]
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
    except Exception as exc:
        log.warning("Offer search failed: %s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="FunPay не вернул список офферов. Проверьте категорию и попробуйте ещё раз.") from exc


@app.post("/api/funpay/lots/create")
async def create_lot(payload: LotCreateBody, _: bool = Depends(require_session)) -> dict[str, Any]:
    try:
        return await create_funpay_lot(
            payload.subcategory_id, payload.title, payload.description, payload.price, payload.amount, payload.active
        )
    except HTTPException:
        raise
    except Exception as exc:
        log.warning("Lot create failed: %s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Не удалось создать оффер. Проверьте обязательные поля этой категории на FunPay.") from exc


@app.get("/api/funpay/lots/{lot_id}/fields")
async def lot_fields(lot_id: int, _: bool = Depends(require_session)) -> dict[str, Any]:
    _client, account = need_funpay()
    try:
        async with FP_LOCK:
            lot = await account.get_lot_fields(lot_id)
        fields = getattr(lot, "fields", {}) or {}
        return {
            "lot_id": lot_id,
            "title": fields.get("fields[summary][ru]", ""),
            "description": fields.get("fields[desc][ru]", ""),
            "price": fields.get("price", ""),
            "amount": fields.get("amount", "1"),
            "active": "active" in fields,
        }
    except Exception as exc:
        log.warning("Lot fields read failed: %s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Не удалось открыть редактор этого оффера.") from exc


@app.put("/api/funpay/lots/{lot_id}")
async def save_lot(lot_id: int, payload: LotEditBody, _: bool = Depends(require_session)) -> dict[str, Any]:
    _client, account = need_funpay()
    try:
        async with FP_LOCK:
            lot = await account.get_lot_fields(lot_id)
            fields = dict(getattr(lot, "fields", {}) or {})
            fields["fields[summary][ru]"] = payload.title.strip()
            fields["fields[desc][ru]"] = payload.description.strip()
            fields["price"] = str(payload.price)
            fields["amount"] = str(payload.amount)
            if payload.active:
                fields["active"] = "on"
            else:
                fields.pop("active", None)
            result = await account.save_lot(lot_id, fields)
        return {"ok": bool(getattr(result, "saved", True)), "lot_id": lot_id}
    except Exception as exc:
        log.warning("Lot save failed: %s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Не удалось сохранить изменения оффера.") from exc


@app.delete("/api/funpay/lots/{lot_id}")
async def delete_lot(lot_id: int, _: bool = Depends(require_session)) -> dict[str, Any]:
    _client, account = need_funpay()
    try:
        async with FP_LOCK:
            result = await account.delete_lot(lot_id)
        return {"ok": bool(getattr(result, "saved", True)), "lot_id": lot_id}
    except Exception as exc:
        log.warning("Lot delete failed: %s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Не удалось удалить оффер.") from exc


@app.post("/api/funpay/lots/raise")
async def raise_lots(payload: dict[str, Any], _: bool = Depends(require_session)) -> dict[str, Any]:
    _client, account = need_funpay()
    raw_ids = payload.get("ids", [])
    if not isinstance(raw_ids, list) or not raw_ids or len(raw_ids) > 100:
        raise HTTPException(status_code=422, detail="Выберите от 1 до 100 офферов.")
    try:
        ids = [int(i) for i in raw_ids]
        async with FP_LOCK:
            result = await account.raise_lots(ids)
        return clean_model(result)
    except Exception as exc:
        log.warning("Lot raise failed: %s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Не удалось поднять выбранные офферы. FunPay может ограничивать частоту поднятия.") from exc


@app.get("/api/funpay/chats")
async def chats(_: bool = Depends(require_session)) -> list[dict[str, Any]]:
    _client, account = need_funpay()
    try:
        async with FP_LOCK:
            values = await account.get_chats()
        return [clean_model(v) for v in values]
    except Exception as exc:
        log.warning("Chats read failed: %s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Не удалось загрузить чаты FunPay.") from exc


@app.get("/api/funpay/chats/{chat_id}")
async def chat_history(chat_id: int, _: bool = Depends(require_session)) -> list[dict[str, Any]]:
    _client, account = need_funpay()
    try:
        async with FP_LOCK:
            values = await account.get_chat_history(chat_id)
        remote = [clean_model(v) for v in values or []]
        init_license_db()
        with sqlite3.connect(LICENSE_DB_PATH) as db:
            db.row_factory = sqlite3.Row
            saved = db.execute(
                "SELECT message_id,text,author,timestamp,created_at FROM sent_chat_messages WHERE chat_id=? ORDER BY created_at ASC LIMIT 500",
                (str(chat_id),),
            ).fetchall()
        remote_ids = {str(m.get("id")) for m in remote if isinstance(m, dict) and m.get("id") is not None}
        # Deduplicate only by stable message ID. Matching text is not enough:
        # users can legitimately send the same phrase more than once.
        for row in saved:
            mid = str(row["message_id"])
            if mid in remote_ids:
                continue
            remote.append({"id": mid, "chat_id": str(chat_id), "text": row["text"], "author": row["author"] or "Вы",
                           "author_id": None, "is_incoming": False, "image_link": None, "timestamp": row["timestamp"],
                           "local_confirmed": True})
        return remote
    except Exception as exc:
        log.warning("Chat history read failed: %s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Не удалось открыть историю этого чата.") from exc


@app.post("/api/funpay/chats/{chat_id}/send")
async def send_chat_message(chat_id: int, payload: MessageBody, _: bool = Depends(require_session)) -> dict[str, Any]:
    _client, account = need_funpay()
    message_text = payload.text.strip()
    if not message_text:
        raise HTTPException(status_code=422, detail="Введите текст сообщения.")
    if len(message_text) > 4000:
        raise HTTPException(status_code=422, detail="Сообщение слишком длинное.")
    try:
        async with FP_LOCK:
            chat_items = await account.get_chats()
            target = next((item for item in chat_items if str(getattr(item, "id", None) if not isinstance(item, dict) else item.get("id")) == str(chat_id)), None)
            interlocutor_id = getattr(target, "interlocutor_id", None) if target is not None and not isinstance(target, dict) else (target.get("interlocutor_id") if isinstance(target, dict) else None)
            result = await account.send_message(chat_id, message_text, interlocutor_id=int(interlocutor_id) if interlocutor_id is not None else None)
            result_data = clean_model(result)
            message_id = result_data.get("message_id", result_data.get("id")) if isinstance(result_data, dict) else None
            # A transport response alone is insufficient; the API's parsed message id is the send confirmation.
            if message_id is None:
                try:
                    history = await account.get_chat_history(chat_id)
                    for candidate in reversed(history or []):
                        item = clean_model(candidate)
                        if isinstance(item, dict) and str(item.get("text") or "").strip() == message_text and not item.get("is_incoming", False):
                            message_id = item.get("id")
                            break
                except Exception:
                    pass
        if message_id is None:
            raise HTTPException(status_code=502, detail="FunPay не подтвердил сообщение. Оно не отмечено как отправленное — проверьте чат и попробуйте ещё раз.")
        profile = FP_PROFILE or {}
        author = str((profile.get("profile") or {}).get("username") or "Вы")
        saved_message = save_sent_chat_message(chat_id, message_id, message_text, author)
        return {"ok": True, "message_id": str(message_id), "chat_id": str(chat_id), "text": message_text,
                "author": author, "is_incoming": False, "timestamp": saved_message["timestamp"], "message": saved_message}
    except HTTPException:
        raise
    except Exception as exc:
        log.warning("Message send failed: %s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="FunPay не подтвердил отправку. Проверьте соединение и откройте чат повторно.") from exc

@app.get("/api/funpay/orders")
async def orders(limit: int = 50, _: bool = Depends(require_session)) -> list[dict[str, Any]]:
    _client, account = need_funpay()
    limit = min(max(limit, 1), 100)
    try:
        async with FP_LOCK:
            values = await account.get_sales(include_paid=True, include_closed=False, include_refunded=False, limit=limit)
        return [clean_model(v) for v in values]
    except Exception as exc:
        log.warning("Orders read failed: %s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Не удалось загрузить заказы FunPay.") from exc


@app.post("/telegram/webhook")
async def telegram_webhook(request: Request) -> dict[str, bool]:
    if not TELEGRAM_BOT_TOKEN:
        raise HTTPException(status_code=404, detail="Telegram bot is disabled")
    if WEBHOOK_SECRET and request.headers.get("X-Telegram-Bot-Api-Secret-Token") != WEBHOOK_SECRET:
        raise HTTPException(status_code=403, detail="Invalid webhook secret")
    # The Application object is held by lifespan so imports and startup remain optional.
    tg_app = getattr(app.state, "telegram_app", None)
    if tg_app is None:
        raise HTTPException(status_code=503, detail="Telegram bot is not ready")
    from telegram import Update
    update = Update.de_json(await request.json(), tg_app.bot)
    await tg_app.process_update(update)
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse(HTML_PAGE, headers={"Cache-Control": "no-store"})


# Frontend is embedded to keep the project deployable as one Python service.
HTML_PAGE = r'''<!doctype html>
<html lang="ru" data-theme="dark">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover">
<meta name="theme-color" content="#101018"><meta name="description" content="FunPay Auto Lister Bot — управление офферами, чатами и заказами">
<title>FunPay Auto Lister</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Manrope:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<script src="https://telegram.org/js/telegram-web-app.js"></script>
<style>
:root{color-scheme:dark;--bg:#0c0c13;--panel:#12121d;--panel2:#171724;--panel3:#1d1d2b;--text:#f4f4fb;--muted:#9696ad;--line:rgba(255,255,255,.085);--line2:rgba(255,255,255,.15);--accent:#9672ff;--accent2:#6f9cff;--good:#4cd6a0;--warn:#f6c768;--bad:#ff7188;--r:17px;--shadow:0 24px 70px rgba(0,0,0,.28);--ease:cubic-bezier(.2,.8,.2,1)}
*{box-sizing:border-box}html,body{width:100vw;height:100dvh;margin:0;overflow:hidden}body{font-family:'DM Sans',system-ui,sans-serif;background:var(--bg);color:var(--text);-webkit-font-smoothing:antialiased}button,input,textarea,select{font:inherit;color:inherit}button{cursor:pointer}button:disabled{opacity:.45;cursor:not-allowed}input,textarea,select{outline:none}button:focus-visible,input:focus-visible,textarea:focus-visible,select:focus-visible{outline:2px solid var(--accent);outline-offset:2px}::selection{background:#9672ff55}::-webkit-scrollbar{width:8px;height:8px}::-webkit-scrollbar-thumb{border-radius:20px;background:#ffffff1d;border:2px solid transparent;background-clip:padding-box}::-webkit-scrollbar-thumb:hover{background:#ffffff35;background-clip:padding-box}
body:before{content:'';position:fixed;inset:-22%;z-index:-1;pointer-events:none;background:radial-gradient(45% 36% at 8% 4%,#6540b42b,transparent 75%),radial-gradient(45% 35% at 95% 4%,#246dba1c,transparent 75%),radial-gradient(45% 30% at 62% 105%,#8f42b31a,transparent 80%)}
.hidden{display:none!important}.app{height:100dvh;display:grid;grid-template-columns:248px minmax(0,1fr);grid-template-rows:68px minmax(0,1fr);grid-template-areas:'side top' 'side main';overflow:hidden}.sidebar{grid-area:side;display:flex;flex-direction:column;gap:26px;padding:22px 14px 16px;background:rgba(14,14,23,.94);border-right:1px solid var(--line);min-height:0;overflow:auto;z-index:40}.brand{display:flex;align-items:center;gap:12px;padding:0 10px 22px;border-bottom:1px solid var(--line)}.brand-mark{width:38px;height:38px;display:grid;place-items:center;border-radius:12px;background:linear-gradient(145deg,#a18aff,#5c67ce);box-shadow:0 8px 24px #7d63ff36;color:#fff}.brand-mark svg{width:24px;height:24px}.brand-title{font:800 13px/1.2 Manrope,sans-serif;letter-spacing:.09em}.brand-sub{font-size:11px;color:var(--muted);margin-top:5px;letter-spacing:.11em}.nav-label{padding:0 12px 7px;color:#68687f;font-size:10px;font-weight:700;letter-spacing:.16em;text-transform:uppercase}.nav{display:flex;flex-direction:column;gap:5px}.nav-item{position:relative;display:flex;align-items:center;gap:13px;width:100%;padding:12px 13px;border:1px solid transparent;border-radius:12px;background:transparent;color:#a5a5b9;text-align:left;transition:background .2s,color .2s,transform .2s}.nav-item:hover{background:#ffffff08;color:#fff;transform:translateX(2px)}.nav-item.active{background:linear-gradient(100deg,#8e6dff26,#6964e90b);border-color:#9672ff23;color:#fff}.nav-item.active:before{content:'';position:absolute;left:-14px;top:22%;height:56%;width:3px;border-radius:3px;background:var(--accent);box-shadow:0 0 14px #9672ffb3}.nav-item svg{width:18px;height:18px;stroke:currentColor;stroke-width:1.7;fill:none;flex:none}.nav-item .label{font-size:13px;font-weight:600;flex:1}.badge{min-width:21px;height:21px;padding:0 6px;border-radius:7px;display:inline-grid;place-items:center;background:#ffffff0b;color:#acacc0;font-size:10px}.sidebar-bottom{margin-top:auto;display:grid;gap:12px}.connection-card{padding:13px;border:1px solid var(--line);border-radius:13px;background:linear-gradient(140deg,#ffffff08,#ffffff02)}.connection-top{display:flex;align-items:center;gap:9px;font-size:12px;font-weight:600}.status-dot{width:7px;height:7px;border-radius:50%;background:#77778a;box-shadow:0 0 0 4px #77778a15;flex:none}.status-dot.on{background:var(--good);box-shadow:0 0 0 4px #4cd6a01a}.status-dot.off{background:var(--bad);box-shadow:0 0 0 4px #ff71881a}.connection-sub{font-size:11px;color:var(--muted);margin:8px 0 0 16px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.side-footer{font-size:10px;color:#67677e;padding:0 11px;letter-spacing:.06em}
.topbar{grid-area:top;display:flex;align-items:center;gap:15px;padding:0 25px;border-bottom:1px solid var(--line);background:#0e0e16a8;backdrop-filter:blur(22px);z-index:30}.mobile-menu{display:none}.crumb{display:flex;align-items:center;gap:9px;color:var(--muted);font-size:12px}.crumb strong{color:#eeeef7;font-weight:600}.top-spacer{flex:1}.live-label{display:flex;align-items:center;gap:8px;font-size:11px;color:var(--muted);padding:8px 11px;border:1px solid var(--line);border-radius:10px;background:#ffffff04}.live-label .status-dot{width:6px;height:6px}.top-actions{display:flex;align-items:center;gap:8px}.icon-btn{width:38px;height:38px;display:grid;place-items:center;border-radius:11px;border:1px solid var(--line);background:#ffffff06;color:#c7c7d6;transition:background .2s,transform .15s,border-color .2s}.icon-btn:hover{background:#ffffff10;border-color:var(--line2);transform:translateY(-1px)}.icon-btn svg{width:17px;height:17px;stroke:currentColor;fill:none;stroke-width:1.7}.user-chip{display:flex;align-items:center;gap:9px;margin-left:4px;padding-left:13px;border-left:1px solid var(--line)}.user-avatar{width:32px;height:32px;display:grid;place-items:center;border-radius:10px;background:linear-gradient(140deg,#7d5ee4,#4b75cb);font-size:10px;font-weight:800;letter-spacing:.08em}.user-name{max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;font-weight:600}.user-caption{font-size:10px;color:var(--muted);margin-top:2px}
.main{grid-area:main;min-width:0;min-height:0;overflow:auto;padding:27px clamp(17px,2.5vw,36px) 35px;scroll-behavior:smooth}.page{max-width:1450px;margin:0 auto;animation:page-in .32s var(--ease) both}.page-head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;margin-bottom:25px}.eyebrow{color:#a38aff;font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:.17em;margin-bottom:8px}.h1{font:800 clamp(24px,2.4vw,32px)/1.15 Manrope,sans-serif;letter-spacing:-.045em;margin:0}.page-desc{color:var(--muted);font-size:13px;margin-top:9px}.actions{display:flex;align-items:center;gap:9px;flex-wrap:wrap}.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;min-height:39px;padding:0 14px;border:1px solid var(--line);border-radius:11px;background:#ffffff06;color:#ececf7;font-size:12px;font-weight:700;white-space:nowrap;transition:transform .15s,background .2s,border-color .2s,box-shadow .2s}.btn:hover{transform:translateY(-1px);background:#ffffff0c;border-color:var(--line2)}.btn:active{transform:scale(.98)}.btn svg{width:15px;height:15px;stroke:currentColor;stroke-width:1.8;fill:none}.btn-primary{border-color:#9672ff88;background:linear-gradient(120deg,#936fff,#6e72e8);box-shadow:0 10px 28px #7658ea26;color:white}.btn-primary:hover{background:linear-gradient(120deg,#a085ff,#7d83fa);box-shadow:0 12px 30px #7658ea38}.btn-danger{border-color:#ff718830;background:#ff718812;color:#ff8d9f}.btn-small{min-height:32px;padding:0 10px;font-size:11px;border-radius:9px}.btn-quiet{background:transparent}.grid{display:grid;gap:15px}.stats-grid{grid-template-columns:repeat(4,minmax(0,1fr));margin-bottom:17px}.stat-card{position:relative;min-width:0;overflow:hidden;padding:19px;border-radius:16px;border:1px solid var(--line);background:linear-gradient(145deg,#181824e8,#12121bd9);box-shadow:0 12px 36px #0000000b}.stat-card:after{content:'';position:absolute;right:-30px;top:-40px;width:110px;height:110px;border-radius:50%;background:radial-gradient(circle,#9672ff27,transparent 70%);pointer-events:none}.stat-header{display:flex;align-items:center;gap:9px;color:var(--muted);font-size:11px;font-weight:600}.stat-icon{width:29px;height:29px;display:grid;place-items:center;background:#9672ff16;border:1px solid #9672ff1c;border-radius:9px;color:#ad98ff}.stat-icon svg{width:15px;height:15px;stroke:currentColor;fill:none;stroke-width:1.7}.stat-value{font:800 clamp(24px,2.3vw,32px)/1.1 Manrope,sans-serif;letter-spacing:-.04em;margin-top:18px;overflow:hidden;text-overflow:ellipsis}.stat-foot{margin-top:8px;font-size:11px;color:#85859d}.stat-foot strong{color:var(--good);font-weight:600}.two-col{grid-template-columns:minmax(0,1.25fr) minmax(300px,.75fr)}.panel{min-width:0;border:1px solid var(--line);border-radius:16px;background:#14141ee6;box-shadow:0 15px 45px #0000000b;overflow:hidden}.panel-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:17px 19px;border-bottom:1px solid var(--line)}.panel-title{font:700 13px Manrope,sans-serif}.panel-sub{font-size:11px;color:var(--muted);margin-top:5px}.panel-body{padding:18px}.quick-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.quick-card{display:flex;align-items:center;gap:12px;min-height:76px;text-align:left;padding:14px;border:1px solid var(--line);border-radius:13px;background:#ffffff03;transition:background .2s,border-color .2s,transform .2s}.quick-card:hover{background:#9672ff0d;border-color:#9672ff44;transform:translateY(-2px)}.quick-ico{width:36px;height:36px;display:grid;place-items:center;border-radius:11px;background:#9672ff16;color:#b3a2ff;flex:none}.quick-ico svg{width:18px;height:18px;stroke:currentColor;fill:none;stroke-width:1.7}.quick-title{font-size:12px;font-weight:700}.quick-text{margin-top:5px;color:var(--muted);font-size:10px}.activity{display:grid;gap:0}.activity-row{display:flex;align-items:flex-start;gap:11px;padding:13px 0;border-bottom:1px solid var(--line)}.activity-row:last-child{border-bottom:0}.activity-mark{margin-top:4px;width:7px;height:7px;border-radius:50%;background:var(--accent);box-shadow:0 0 0 4px #9672ff14;flex:none}.activity-title{font-size:12px;font-weight:600}.activity-note{font-size:10px;color:var(--muted);margin-top:4px;line-height:1.5}
.form-layout{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(270px,.7fr);gap:16px}.form-card{padding:21px}.section-label{color:#a9a9bc;font-size:10px;font-weight:800;letter-spacing:.14em;text-transform:uppercase;margin-bottom:15px}.field-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:13px}.field{display:grid;gap:7px;min-width:0}.field.full{grid-column:1/-1}.field label{color:#b8b8ca;font-size:11px;font-weight:600}.field input,.field textarea,.field select{width:100%;min-width:0;border:1px solid #ffffff13;background:#0e0e17;border-radius:10px;padding:11px 12px;font-size:12px;color:#f4f4fb;transition:border-color .2s,box-shadow .2s}.field input,.field select{height:42px}.field textarea{min-height:112px;resize:vertical;line-height:1.55}.field input:focus,.field textarea:focus,.field select:focus{border-color:#9672ff93;box-shadow:0 0 0 3px #9672ff17}.field input::placeholder,.field textarea::placeholder{color:#626278}.field select option{background:#13131e;color:#fff}.field-hint{color:#797990;font-size:10px;line-height:1.5}.mode-switch{display:flex;gap:4px;width:max-content;max-width:100%;padding:4px;background:#0d0d16;border:1px solid var(--line);border-radius:12px;margin-bottom:20px}.mode-switch button{padding:9px 16px;border-radius:8px;border:0;background:transparent;color:var(--muted);font-size:11px;font-weight:700}.mode-switch button.active{background:#28223e;color:#c5b7ff;box-shadow:inset 0 0 0 1px #9672ff29}.preview-box{height:100%;padding:20px;border-radius:15px;border:1px solid #9672ff21;background:radial-gradient(100% 60% at 100% 0%,#9672ff15,transparent 70%),#10101a}.preview-icon{width:45px;height:45px;display:grid;place-items:center;border-radius:13px;background:#9672ff18;color:#b6a2ff;margin-bottom:23px}.preview-icon svg{width:22px;height:22px;stroke:currentColor;fill:none;stroke-width:1.6}.preview-title{font:800 17px/1.3 Manrope,sans-serif;overflow-wrap:anywhere}.preview-desc{font-size:11px;color:var(--muted);margin-top:9px;line-height:1.65;overflow-wrap:anywhere;white-space:pre-wrap}.preview-divider{height:1px;background:var(--line);margin:18px 0}.preview-line{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:7px 0;color:var(--muted);font-size:11px}.preview-line strong{color:#f0f0fa;font-weight:700}.preview-price{font:800 25px Manrope,sans-serif;color:#b8a6ff;margin-top:5px}.notice{padding:12px 14px;border:1px solid #9672ff23;background:#9672ff0b;border-radius:11px;color:#b9b3d4;font-size:11px;line-height:1.6}.toolbar{display:flex;align-items:center;gap:9px;flex-wrap:wrap;padding:13px 15px;border-bottom:1px solid var(--line)}.toolbar .field-inline{display:flex;align-items:center;gap:7px}.toolbar label{font-size:10px;color:var(--muted)}.toolbar select,.toolbar input{height:36px;min-width:130px;border:1px solid var(--line);border-radius:9px;background:#0d0d16;padding:0 10px;font-size:11px}.toolbar input{min-width:200px}.toolbar-spacer{flex:1}.table-wrap{width:100%;overflow:auto}table{width:100%;border-collapse:collapse;min-width:680px}th{padding:12px 15px;text-align:left;color:#7f7f97;text-transform:uppercase;letter-spacing:.1em;font-size:9px;font-weight:800;border-bottom:1px solid var(--line);white-space:nowrap}td{padding:13px 15px;border-bottom:1px solid #ffffff09;font-size:11px;color:#c9c9d9;vertical-align:middle}tbody tr:hover{background:#ffffff04}tbody tr:last-child td{border-bottom:0}.cell-main{font-size:11px;font-weight:700;color:#ededf8;max-width:360px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.cell-sub{font-size:10px;color:var(--muted);margin-top:4px}.price{font-weight:800;color:#c3b2ff;font-variant-numeric:tabular-nums}.pill{display:inline-flex;align-items:center;gap:6px;padding:5px 8px;border-radius:7px;background:#ffffff08;border:1px solid var(--line);font-size:9px;color:#b5b5c9;white-space:nowrap}.pill.good{color:var(--good);background:#4cd6a00b;border-color:#4cd6a022}.pill.warn{color:var(--warn);background:#f6c7680b;border-color:#f6c76822}.pill.bad{color:var(--bad);background:#ff71880b;border-color:#ff718822}.empty-state{display:grid;place-items:center;text-align:center;min-height:220px;padding:30px;color:var(--muted)}.empty-state svg{width:31px;height:31px;stroke:#8a7cba;fill:none;stroke-width:1.5;margin-bottom:13px}.empty-state strong{font:700 13px Manrope,sans-serif;color:#deddec}.empty-state p{max-width:340px;line-height:1.6;font-size:11px}.empty-state .btn{margin-top:6px}
.chat-layout{display:grid;grid-template-columns:minmax(230px,.72fr) minmax(0,1.28fr);min-height:min(650px,calc(100dvh - 220px))}.chat-sidebar{border-right:1px solid var(--line);min-width:0}.chat-list{overflow:auto;max-height:620px}.chat-item{display:flex;width:100%;gap:11px;text-align:left;padding:14px;border:0;border-bottom:1px solid #ffffff09;background:transparent}.chat-item:hover,.chat-item.active{background:#9672ff0e}.chat-item.active{box-shadow:inset 2px 0 var(--accent)}.chat-avatar{width:34px;height:34px;display:grid;place-items:center;flex:none;border-radius:11px;background:#28243b;color:#bdb0ff;font-size:11px;font-weight:800}.chat-meta{min-width:0;flex:1}.chat-name{font-size:11px;font-weight:700;display:flex;justify-content:space-between;gap:5px}.chat-preview{font-size:10px;color:var(--muted);margin-top:5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.unread{border-radius:8px;background:#9672ff30;color:#c6b9ff;padding:2px 5px;font-size:9px}.chat-main{min-width:0;display:flex;flex-direction:column}.chat-main-head{padding:15px 17px;border-bottom:1px solid var(--line)}.chat-messages{flex:1;min-height:280px;max-height:540px;overflow:auto;padding:18px;display:flex;flex-direction:column;gap:10px}.message{max-width:min(80%,490px);padding:10px 12px;border-radius:12px;background:#20202d;border:1px solid #ffffff09;font-size:11px;line-height:1.55;white-space:pre-wrap;overflow-wrap:anywhere}.message.outgoing{align-self:flex-end;background:#30284a;border-color:#9672ff21}.message-meta{font-size:9px;color:#8d8da3;margin-top:5px}.chat-composer{display:flex;gap:8px;padding:13px;border-top:1px solid var(--line)}.chat-composer input{min-width:0;flex:1;height:40px;border-radius:10px;border:1px solid var(--line);background:#0d0d16;padding:0 12px;font-size:11px}.chat-composer input:focus{border-color:#9672ff83}
.settings-grid{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(260px,.8fr);gap:16px}.settings-card{padding:21px}.settings-card h3{font:700 14px Manrope,sans-serif;margin:0 0 6px}.settings-card>p{color:var(--muted);font-size:11px;line-height:1.65;margin:0 0 20px}.settings-field{margin-top:14px}.settings-foot{margin-top:16px;display:flex;gap:9px;align-items:center;flex-wrap:wrap}.security-note{padding:14px;border:1px solid #f6c76823;background:#f6c76808;border-radius:12px;color:#c9b98d;font-size:10px;line-height:1.6}.toggle-row{display:flex;align-items:center;justify-content:space-between;gap:15px;padding:15px 0;border-bottom:1px solid var(--line)}.toggle-row:last-child{border-bottom:0}.toggle-label{font-size:12px;font-weight:700}.toggle-help{font-size:10px;color:var(--muted);margin-top:4px}.switch{position:relative;width:39px;height:23px;flex:none}.switch input{opacity:0;width:0;height:0}.switch span{position:absolute;inset:0;border-radius:20px;background:#444455;transition:background .2s}.switch span:before{content:'';position:absolute;left:3px;top:3px;width:17px;height:17px;border-radius:50%;background:#fff;transition:transform .2s}.switch input:checked+span{background:#8869ed}.switch input:checked+span:before{transform:translateX(16px)}
#login-view{position:fixed;inset:0;display:grid;place-items:center;padding:20px;overflow:auto;background:radial-gradient(55% 45% at 20% 15%,#7653d927,transparent 75%),radial-gradient(55% 45% at 90% 90%,#336bd31d,transparent 75%),#0c0c13;z-index:500} .login-card{width:min(430px,100%);padding:32px;border:1px solid #ffffff17;border-radius:23px;background:#151520eb;box-shadow:0 35px 110px #0008;animation:pop .45s var(--ease) both}.login-brand{display:flex;align-items:center;gap:12px;margin-bottom:28px}.login-symbol{width:47px;height:47px;display:grid;place-items:center;border-radius:15px;background:linear-gradient(140deg,#a18aff,#5f6ed5);box-shadow:0 12px 35px #8768ff36}.login-symbol svg{width:27px;height:27px;stroke:#fff;fill:none;stroke-width:1.6}.login-title{font:800 22px/1.2 Manrope,sans-serif;letter-spacing:-.035em;margin:0}.login-sub{font-size:12px;color:var(--muted);margin-top:7px;line-height:1.6}.login-field{margin-top:23px}.login-field label{display:block;color:#b9b9cd;font-size:11px;font-weight:700;margin-bottom:8px}.login-field input{width:100%;height:46px;padding:0 13px;border-radius:11px;border:1px solid var(--line2);background:#0d0d16;font-size:13px}.login-card .btn{width:100%;height:45px;margin-top:13px}.login-note{font-size:10px;color:#77778f;line-height:1.6;margin-top:16px;text-align:center}.login-error{font-size:11px;color:var(--bad);margin-top:10px;min-height:16px}
.toast-stack{position:fixed;right:17px;top:80px;width:min(350px,calc(100vw - 34px));z-index:1000;display:grid;gap:9px;pointer-events:none}.toast{display:flex;align-items:flex-start;gap:10px;padding:12px 13px;border-radius:13px;background:#1c1c29f2;border:1px solid #ffffff17;border-left:3px solid var(--accent);box-shadow:var(--shadow);font-size:11px;line-height:1.55;animation:toast-in .28s var(--ease) both;pointer-events:auto}.toast.ok{border-left-color:var(--good)}.toast.error{border-left-color:var(--bad)}.toast.warn{border-left-color:var(--warn)}.toast button{border:0;background:none;color:#8f8fa5;font-size:16px;margin-left:auto;padding:0 2px}.scrim{display:none;position:fixed;inset:0;background:#0008;backdrop-filter:blur(3px);z-index:35}.loading{opacity:.65;pointer-events:none}.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:10px;color:var(--muted)}
/* Requested cross-browser fullscreen control. */
#fs{position:fixed;top:12px;right:12px;z-index:9999;width:38px;height:38px;border:1px solid rgba(255,255,255,.15);border-radius:11px;background:rgba(20,20,28,.78);backdrop-filter:blur(12px) saturate(160%);color:#fff;font-size:18px;cursor:pointer;transition:transform .15s,background .15s;display:grid;place-items:center}#fs:hover{background:rgba(40,40,55,.9);transform:scale(1.05)}#fs:active{transform:scale(.95)}body.is-fs{cursor:none}body.is-fs #fs{cursor:pointer}.topbar{padding-right:62px}
@keyframes page-in{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}@keyframes pop{from{opacity:0;transform:translateY(10px) scale(.985)}to{opacity:1;transform:none}}@keyframes toast-in{from{opacity:0;transform:translateX(16px)}to{opacity:1;transform:none}}
@media(max-width:1120px){.stats-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.two-col{grid-template-columns:1fr}.form-layout,.settings-grid{grid-template-columns:1fr}.preview-box{min-height:320px}.app{grid-template-columns:225px minmax(0,1fr)}}
@media(max-width:780px){.app{grid-template-columns:minmax(0,1fr);grid-template-rows:60px minmax(0,1fr);grid-template-areas:'top' 'main'}.sidebar{position:fixed;left:0;top:0;bottom:0;width:min(285px,86vw);transform:translateX(-105%);transition:transform .28s var(--ease);box-shadow:var(--shadow)}.sidebar.open{transform:translateX(0)}.scrim.show{display:block}.mobile-menu{display:grid}.topbar{padding:0 13px 0 13px;padding-right:59px;gap:10px}.crumb{display:none}.live-label{display:none}.user-chip{display:none}.main{padding:21px 13px 28px}.page-head{align-items:flex-start;flex-direction:column;margin-bottom:20px}.page-head>.actions{width:100%}.page-head>.actions .btn{flex:1}.chat-layout{grid-template-columns:minmax(125px,.68fr) minmax(0,1.32fr)}.chat-item{padding:11px 8px;gap:7px}.chat-avatar{width:29px;height:29px}.chat-name{font-size:10px}.chat-preview{font-size:9px}.chat-main-head{padding:12px}.chat-messages{padding:11px;min-height:240px}.message{max-width:92%}.panel-head{padding:14px}.panel-body{padding:14px}.toolbar{padding:11px}.toolbar input{min-width:140px;flex:1}.toolbar .field-inline{flex:1}.toolbar-spacer{display:none}}
@media(max-width:520px){.stats-grid{gap:9px}.stat-card{padding:13px}.stat-value{margin-top:13px;font-size:23px}.stat-header{font-size:10px;gap:7px}.stat-icon{width:25px;height:25px}.stat-foot{font-size:9px}.quick-grid{grid-template-columns:1fr}.quick-card{min-height:65px}.field-grid{grid-template-columns:1fr}.field.full{grid-column:auto}.form-card,.settings-card{padding:15px}.chat-layout{grid-template-columns:1fr;min-height:520px}.chat-sidebar{border-right:0;border-bottom:1px solid var(--line)}.chat-list{display:flex;overflow-x:auto;max-height:none}.chat-item{min-width:165px;border-right:1px solid var(--line);border-bottom:0}.chat-messages{min-height:235px}.mode-switch{width:100%}.mode-switch button{flex:1}.login-card{padding:24px}.h1{font-size:25px}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{animation-duration:.001ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important;transition-duration:.001ms!important}}

/* V3 polish: crisp outlines, subtle motion, stable touch viewport, generated profile portraits */
:root{--line:rgba(190,177,255,.13);--line2:rgba(190,177,255,.25)}
@keyframes glow-breathe{0%,100%{box-shadow:0 0 0 1px #9d83ff12,0 8px 22px #7d63ff0a}50%{box-shadow:0 0 0 1px #9d83ff2d,0 8px 28px #7d63ff1c}}
.panel,.stat-card,.preview-box,.settings-card,.form-card{border-color:rgba(178,157,255,.14);transition:border-color .24s ease,box-shadow .24s ease,transform .24s ease}
.panel:hover,.stat-card:hover{border-color:rgba(178,157,255,.25);box-shadow:0 18px 50px #00000018}
.btn-primary{position:relative;overflow:hidden}
.btn-primary:after{content:'';position:absolute;inset:0;transform:translateX(-130%);background:linear-gradient(105deg,transparent 25%,#ffffff30 48%,transparent 72%);transition:transform .65s ease;pointer-events:none}
.btn-primary:hover:after{transform:translateX(130%)}
.chat-avatar,.user-avatar{position:relative;overflow:hidden;border-radius:14px;border:1px solid #ffffff24;box-shadow:0 5px 18px #0003;isolation:isolate}
.chat-avatar img,.user-avatar img{width:100%;height:100%;display:block;object-fit:cover;border-radius:inherit}
.nav-item.active{box-shadow:inset 0 0 0 1px #a990ff10,0 5px 19px #7d63ff08}
input,textarea,select{touch-action:pan-y}
html,body,#app{overscroll-behavior:none;touch-action:pan-x pan-y}
button,.nav-item,.chat-item,.quick-card{ -webkit-tap-highlight-color:transparent; }
.license-timer{display:flex;align-items:center;gap:7px;padding:8px 10px;border:1px solid #6fceab35;border-radius:10px;background:#4cd6a00a;color:#9ce8cb;font-size:10px;font-weight:800;white-space:nowrap;letter-spacing:.02em}
.license-timer:before{content:'';width:6px;height:6px;border-radius:50%;background:#4cd6a0;box-shadow:0 0 10px #4cd6a080;animation:timer-pulse 1.8s ease infinite}
@keyframes timer-pulse{50%{opacity:.45;box-shadow:0 0 2px #4cd6a040}}
.catalog-search-panel{margin:0 0 17px;padding:18px;border:1px solid #9672ff38;border-radius:17px;background:linear-gradient(115deg,#211b36e8,#13131ee8 58%,#142034cc);box-shadow:0 12px 35px #0002;position:relative;overflow:visible}
.catalog-search-top{display:flex;align-items:center;gap:12px;margin-bottom:12px}.catalog-search-symbol{display:grid;place-items:center;width:38px;height:38px;flex:none;border-radius:13px;background:linear-gradient(145deg,#a18aff,#5c6fe2);box-shadow:0 6px 22px #8c72ff45}.catalog-search-symbol svg{width:18px;height:18px;stroke:white;fill:none;stroke-width:1.8}.catalog-search-title{font:800 14px Manrope,sans-serif}.catalog-search-sub{font-size:10px;color:var(--muted);margin-top:4px}.catalog-search-wrap{position:relative}.catalog-search-input{height:47px;width:100%;padding:0 15px 0 43px;border-radius:13px;border:1px solid #a48cff40;background:#0d0d18cc;font-size:13px;box-shadow:inset 0 1px 0 #ffffff08;transition:border-color .2s,box-shadow .2s}.catalog-search-input:focus{border-color:#a48cff9c;box-shadow:0 0 0 3px #9672ff1d}.catalog-search-wrap:before{content:'⌕';position:absolute;left:15px;top:7px;font-size:25px;line-height:30px;color:#b7a4ff;pointer-events:none}.catalog-results{display:grid;gap:6px;margin-top:10px;max-height:260px;overflow:auto}.catalog-result{display:flex;align-items:center;gap:11px;width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:11px;background:#ffffff05;text-align:left;transition:background .15s,border-color .15s,transform .15s}.catalog-result:hover{background:#9672ff13;border-color:#9672ff55;transform:translateX(2px)}.catalog-result-ico{width:31px;height:31px;display:grid;place-items:center;border-radius:10px;background:#9672ff1c;color:#b7a4ff;font-size:12px;font-weight:800;flex:none}.catalog-result-main{min-width:0;flex:1}.catalog-result-name{font-size:12px;font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.catalog-result-path{font-size:10px;color:var(--muted);margin-top:4px}.catalog-result-arrow{color:#a893ff;font-size:18px}
.admin-key-table code{font-size:10px;white-space:nowrap}.license-status{display:inline-flex;padding:5px 8px;border-radius:8px;font-size:10px;font-weight:800}.license-status.active{color:#85e4bd;background:#4cd6a014;border:1px solid #4cd6a031}.license-status.expired{color:#ff9aaa;background:#ff718812;border:1px solid #ff71882c}
@media(max-width:860px){.license-timer{padding:7px 8px;font-size:9px}.catalog-search-panel{padding:14px}}
@media(max-width:600px){.license-timer{max-width:100px;overflow:hidden;text-overflow:ellipsis}.license-timer:before{display:none}.topbar{gap:7px;padding:0 10px}.live-label{display:none}.user-chip{padding-left:7px}.user-caption{display:none}.user-name{max-width:72px}.top-actions{gap:5px}.icon-btn{width:32px;height:32px}.catalog-search-title{font-size:12px}.catalog-search-sub{font-size:9px}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{animation-duration:.01ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important;transition-duration:.01ms!important}}

/* V4 — neon workspace concept (variant 2): compact spacing, glass edges, animated accent rails. */

/* Compact trend lines echo the selected second concept without introducing fake historical statistics. */
.stat-card{padding-bottom:48px}.stat-card:before{content:'';position:absolute;right:13px;bottom:15px;width:92px;height:28px;opacity:.78;pointer-events:none;background-repeat:no-repeat;background-size:100% 100%;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 30'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0' y1='0' x2='0' y2='1'%3E%3Cstop stop-color='%2379d7ff' stop-opacity='.28'/%3E%3Cstop offset='1' stop-color='%2379d7ff' stop-opacity='0'/%3E%3C/linearGradient%3E%3C/defs%3E%3Cpath d='M0 26 L13 21 L24 23 L35 14 L48 19 L61 8 L71 12 L83 4 L100 2 L100 30 L0 30 Z' fill='url(%23g)'/%3E%3Cpath d='M0 26 L13 21 L24 23 L35 14 L48 19 L61 8 L71 12 L83 4 L100 2' stroke='%2379d7ff' stroke-width='1.8' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E")}
.stat-card:nth-child(2):before{filter:hue-rotate(42deg)}.stat-card:nth-child(3):before{filter:hue-rotate(120deg)}.stat-card:nth-child(4):before{filter:hue-rotate(220deg)}
@media(max-width:520px){.stat-card{padding-bottom:42px}.stat-card:before{width:72px;height:23px;bottom:12px}}

:root{--bg:#090a12;--panel:#111322;--panel2:#171a30;--panel3:#20243c;--text:#f7f7ff;--muted:#a2a7c3;--line:rgba(156,150,255,.17);--line2:rgba(167,156,255,.34);--accent:#8b5cf6;--accent2:#45c8ff;--r:18px;--shadow:0 24px 68px #02030b70}
body:before{background:radial-gradient(42% 38% at 4% 0%,#7845ff30,transparent 76%),radial-gradient(38% 34% at 100% 8%,#1c8dff22,transparent 78%),radial-gradient(34% 30% at 60% 100%,#a12cff1c,transparent 80%);animation:ambient-shift 22s ease-in-out infinite alternate}
@keyframes ambient-shift{from{transform:translate3d(-1%,0,0) scale(1)}to{transform:translate3d(1%,1%,0) scale(1.035)}}
.brand-mark,.login-symbol,.catalog-search-symbol{background:linear-gradient(135deg,#8d5bff,#4c75ff 58%,#28c7ff);box-shadow:0 8px 26px #704fff40}
.nav-item.active{background:linear-gradient(105deg,#7546ff38,#2789ff12);border-color:#906dff48;box-shadow:inset 0 0 0 1px #d5caff09,0 7px 25px #784cff12}
.nav-item.active:before{background:linear-gradient(180deg,#a855f7,#40c6ff);box-shadow:0 0 17px #8b5cf6b0}
.btn-primary{border-color:#9b7aff9c;background:linear-gradient(115deg,#8b5cf6,#6545d8 56%,#4278ef);box-shadow:0 8px 26px #6948e53b}
.btn-primary:hover{background:linear-gradient(115deg,#a074ff,#7354e8 56%,#518bff)}
.panel,.stat-card,.form-card,.settings-card,.preview-box{border-color:rgba(150,145,255,.19);background:linear-gradient(145deg,#16192beF,#101321f5);box-shadow:0 14px 38px #02030b2a}
.panel{position:relative}
.panel:before{content:'';position:absolute;inset:0 18% auto;height:1px;background:linear-gradient(90deg,transparent,#a48bff75,#40c6ff55,transparent);pointer-events:none;opacity:.65}
.stat-card{background:linear-gradient(145deg,#171a30ef,#101321ee)}
.stat-card:after{background:radial-gradient(circle,#7651ff30,transparent 70%)}
.stat-icon,.quick-ico,.catalog-result-ico{background:linear-gradient(145deg,#8e5fff28,#31bfff15);border-color:#9c85ff2a;color:#bbaaff}
.catalog-search-panel{border-color:#9877ff55;background:linear-gradient(115deg,#21183cef,#12172bf2 59%,#112439e8);box-shadow:0 15px 40px #0003,0 0 34px #6b48ff12}
.catalog-search-input{border-color:#8c7cff56;background:#0a0e1cdd}
.catalog-search-input:focus{border-color:#a78bfa;box-shadow:0 0 0 3px #8b5cf626,0 0 22px #7c5cff1b}
.license-timer{max-width:none;border-color:#6e60c45f;background:linear-gradient(100deg,#6c45ee1d,#238ac01a);color:#d6caff;box-shadow:inset 0 0 0 1px #ffffff04}
.license-timer:before{background:#61d9ff;box-shadow:0 0 10px #61d9ffb0}
.chat-item.active{border-color:#9878ff5c;background:linear-gradient(100deg,#784dff24,#258bff10)}
.chat-avatar,.user-avatar{border-radius:50%;border-color:#9b8aff50;box-shadow:0 0 0 2px #8b5cf619,0 6px 18px #0005}
input:focus,textarea:focus,select:focus{border-color:#9878ffb3!important;box-shadow:0 0 0 3px #8b5cf61a}
#fs{background:linear-gradient(135deg,#8b5cf6,#377ff3);box-shadow:0 8px 25px #744dff52}
#page-admin{width:100%}.admin-create-panel{margin-bottom:16px}.admin-create-panel .panel-body{padding:20px}.admin-created{display:flex;align-items:center;gap:10px;flex-wrap:wrap;border:1px solid #4cd6a048;background:#4cd6a00d;padding:12px 14px;border-radius:12px}.admin-created code{font-size:12px;font-weight:800;letter-spacing:.035em;color:#aff5d9;overflow-wrap:anywhere}.admin-create-panel .field-hint{line-height:1.5}
.stat-value{font-size:clamp(23px,2vw,30px)}.page-head{margin-bottom:21px}
@media(min-width:1100px){.main{padding-left:clamp(20px,2vw,31px);padding-right:clamp(20px,2vw,31px)}.two-col{grid-template-columns:minmax(0,1.2fr) minmax(310px,.8fr)}}
@media(max-width:860px){.license-timer{max-width:185px;font-size:9px;white-space:normal;line-height:1.25}.admin-create-panel .field-grid{grid-template-columns:1fr}}
@media(max-width:600px){.license-timer{max-width:145px;padding:6px 7px;font-size:8px;white-space:normal}.license-timer:before{display:block;flex:none}.topbar{gap:6px}.user-chip{gap:5px}.user-avatar{width:29px;height:29px}.admin-create-panel .panel-body{padding:14px}.admin-create-panel .settings-foot{align-items:stretch;flex-direction:column}}
/* Variant 2 dashboard: recent chats, plan rail, and a compact timer progress strip. */
.dashboard-lower{grid-template-columns:minmax(0,1.13fr) minmax(280px,.87fr);margin-top:15px;align-items:stretch}
.dashboard-chat-panel,.dashboard-access-panel{min-width:0}
.dashboard-chat-list{display:grid;gap:0;padding:6px 14px 10px;min-height:180px}
.dashboard-chat-row{width:100%;min-width:0;display:flex;align-items:center;gap:11px;text-align:left;padding:11px 5px;border:0;border-bottom:1px solid var(--line);background:transparent;cursor:pointer;transition:background .18s,transform .18s;border-radius:10px}
.dashboard-chat-row:last-child{border-bottom:0}.dashboard-chat-row:hover{background:#8b5cf612;transform:translateX(2px)}
.dashboard-chat-copy{display:flex;flex-direction:column;min-width:0;flex:1;gap:5px}.dashboard-chat-copy b{font-size:12px;font-weight:800;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.dashboard-chat-copy small{font-size:10px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%}
.dashboard-chat-time{font-size:9px;color:#858ba8;white-space:nowrap}.dashboard-plan-list{display:grid;gap:2px}
.dashboard-plan-row{display:grid;grid-template-columns:8px 74px minmax(0,1fr) auto;gap:8px;align-items:center;padding:9px 9px;border:1px solid transparent;border-radius:10px;font-size:11px;transition:background .18s,border-color .18s}
.dashboard-plan-row:hover{background:#8b5cf60d;border-color:#8b5cf626}.plan-dot{width:7px;height:7px;border-radius:50%;background:linear-gradient(140deg,#b58bff,#46d5ff);box-shadow:0 0 10px #8b5cf650}.dashboard-plan-row b{font-size:11px;color:#e5dfff}.dashboard-plan-row>span:nth-of-type(2){color:var(--muted)}.plan-availability{font-size:9px;color:#8fe5c3;background:#46d6a012;border:1px solid #46d6a01d;border-radius:7px;padding:4px 6px}
.dashboard-access-footer{display:flex;align-items:center;gap:9px;margin-top:11px;padding:12px 10px;border:1px solid #8b5cf625;border-radius:12px;background:linear-gradient(100deg,#8b5cf610,#31bfff08);font-size:10px;line-height:1.45;color:var(--muted)}.access-lock{display:grid;place-items:center;flex:none;width:28px;height:28px;border-radius:9px;background:#8b5cf61b;color:#c4b4ff;font-size:17px}.dashboard-admin-btn{width:100%;margin-top:10px;justify-content:space-between}
.license-timer{position:relative;display:flex;flex-direction:column;align-items:stretch;gap:5px;min-width:155px;padding:7px 10px;border-radius:11px;white-space:normal;font-size:9px;line-height:1.2}
.license-timer:before{position:absolute;left:10px;top:11px;margin:0}.license-timer .license-timer-line{display:block;padding-left:13px;font-weight:800;white-space:nowrap}.license-progress{display:block;overflow:hidden;height:3px;border-radius:99px;background:#b7b2ff18}.license-progress i{display:block;height:100%;width:100%;border-radius:99px;background:linear-gradient(90deg,#a855f7,#477dff,#4bd4ff);box-shadow:0 0 10px #8b5cf666;transition:width .6s linear}
@media(max-width:1100px){.dashboard-lower{grid-template-columns:1fr}.dashboard-chat-list{min-height:0}}
@media(max-width:600px){.dashboard-plan-row{grid-template-columns:7px 65px minmax(0,1fr) auto;gap:6px;padding:8px 6px}.license-timer{min-width:0;max-width:142px;font-size:8px;padding:6px 7px}.license-timer:before{left:7px;top:9px}.license-timer .license-timer-line{padding-left:10px}}

</style>
</head>
<body>
<button id="fs" title="Полный экран (F)" aria-label="Полный экран">⛶</button>
<div id="login-view">
  <div class="login-card">
    <div class="login-brand"><div class="login-symbol" id="login-mark"></div><div><h1 class="login-title">FunPay Auto Lister</h1><div class="brand-sub">CONTROL PANEL · V2</div></div></div>
    <div class="eyebrow">ПАНЕЛЬ УПРАВЛЕНИЯ</div><div style="font:800 26px/1.22 Manrope,sans-serif;letter-spacing:-.04em">С возвращением</div>
    <div class="login-sub">Войдите по ключу доступа, паролю администратора или откройте Mini App из Telegram для автоматического входа администратора.</div>
    <form id="login-form"><div class="login-field"><label for="login-password">Пароль панели или лицензионный ключ</label><input id="login-password" type="password" autocomplete="current-password" placeholder="FREE PLAN / лицензионный ключ / пароль"></div><button class="btn btn-primary" type="submit">Войти в панель <span aria-hidden="true">→</span></button><div class="login-error" id="login-error"></div></form>
    <div class="login-note">Ключ FREE PLAN/покупки вводится сюда. Администратор с Telegram ID 8357023784 входит автоматически внутри Telegram.</div>
  </div>
</div>
<div class="scrim" id="scrim"></div>
<div class="app hidden" id="app">
  <aside class="sidebar" id="sidebar">
    <div class="brand"><div class="brand-mark" id="brand-mark"></div><div><div class="brand-title">FUNPAY LISTER</div><div class="brand-sub">AUTO LISTING SYSTEM</div></div></div>
    <div><div class="nav-label">Menu</div><nav class="nav" id="nav">
      <button class="nav-item active" data-page="dashboard"><svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg><span class="label">Dashboard</span></button>
      <button class="nav-item" data-page="lister"><svg viewBox="0 0 24 24"><path d="M4 5h16M4 12h11M4 19h16"/><circle cx="19" cy="12" r="2"/></svg><span class="label">Auto Lister</span><span class="badge">NEW</span></button>
      <button class="nav-item" data-page="search"><svg viewBox="0 0 24 24"><circle cx="10.8" cy="10.8" r="6.8"/><path d="m16 16 5 5"/></svg><span class="label">Offer Search</span></button>
      <button class="nav-item" data-page="listings"><svg viewBox="0 0 24 24"><path d="M4 7h16M4 12h16M4 17h10"/><path d="M3 4h18v16H3z"/></svg><span class="label">My Offers</span><span class="badge" id="offers-badge">—</span></button>
      <button class="nav-item" data-page="chats"><svg viewBox="0 0 24 24"><path d="M20 11.5a7.5 7.5 0 0 1-7.5 7.5H6l-3 2v-6.5A7.5 7.5 0 1 1 20 11.5Z"/><path d="M8 10h8M8 13.5h5"/></svg><span class="label">Messages</span><span class="badge" id="chats-badge">—</span></button>
      <button class="nav-item" data-page="orders"><svg viewBox="0 0 24 24"><path d="M7 3h10l3 4v14H4V7z"/><path d="M4 7h16M8 12h8M8 16h6"/></svg><span class="label">Orders</span></button>
      <button class="nav-item hidden" data-page="admin" id="admin-nav"><svg viewBox="0 0 24 24"><path d="M12 3 20 6v5c0 5-3.3 8-8 10-4.7-2-8-5-8-10V6z"/><path d="m8.5 12 2.3 2.3 4.7-5"/></svg><span class="label">Admin</span><span class="badge">ROOT</span></button>
      <button class="nav-item" data-page="settings"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="m19.4 15 .1.1 1.1 1.8-1.8 3.1-2.1-.5a8 8 0 0 1-1.7 1l-.6 2h-3.6l-.6-2a8 8 0 0 1-1.7-1l-2.1.5-1.8-3.1 1.1-1.8a8 8 0 0 1 0-2l-1.1-1.8 1.8-3.1 2.1.5a8 8 0 0 1 1.7-1l.6-2h3.6l.6 2a8 8 0 0 1 1.7 1l2.1-.5 1.8 3.1-1.1 1.8a8 8 0 0 1 0 2Z" transform="translate(-1 -1) scale(1.08)"/></svg><span class="label">Settings</span></button>
    </nav></div>
    <div class="sidebar-bottom"><div class="connection-card"><div class="connection-top"><span class="status-dot off" id="side-dot"></span><span id="side-status">FunPay не подключён</span></div><div class="connection-sub" id="side-account">Откройте настройки аккаунта</div></div><div class="side-footer">FUNPAY AUTO LISTER <span id="version">· 3.2.0</span></div></div>
  </aside>
  <header class="topbar"><button class="icon-btn mobile-menu" id="menu-toggle" aria-label="Открыть меню"><svg viewBox="0 0 24 24"><path d="M4 6h16M4 12h16M4 18h16"/></svg></button><div class="crumb"><span>Workspace</span><span>/</span><strong id="crumb-label">Dashboard</strong></div><div class="top-spacer"></div><div class="live-label"><span class="status-dot" id="top-dot"></span><span id="top-status">Нет подключения</span></div><div class="license-timer" id="license-timer" title="Оставшееся время ключа">Ключ · проверка</div><div class="top-actions"><button class="icon-btn" id="sound-btn" title="Звуки уведомлений" aria-label="Звуки уведомлений"><svg viewBox="0 0 24 24"><path d="M11 5 6 9H3v6h3l5 4z"/><path d="M15 9a4 4 0 0 1 0 6M17.5 6.5a7.5 7.5 0 0 1 0 11"/></svg></button><button class="icon-btn" id="refresh-btn" title="Обновить данные" aria-label="Обновить"><svg viewBox="0 0 24 24"><path d="M20 7v5h-5M4 17v-5h5"/><path d="M5.5 9A7 7 0 0 1 18 6l2 6M4 12l2 6a7 7 0 0 0 12.5-3"/></svg></button><div class="user-chip"><div class="user-avatar" id="user-avatar">FP</div><div><div class="user-name" id="user-name">Панель</div><div class="user-caption">Личный кабинет</div></div></div></div></header>
  <main class="main" id="main">
    <section class="page" data-view="dashboard" id="page-dashboard">
      <div class="page-head"><div><div class="eyebrow">OVERVIEW / WORKSPACE</div><h1 class="h1">Управление FunPay</h1><div class="page-desc">Офферы, сообщения и заказы — в одной панели.</div></div><div class="actions"><button class="btn" data-go="settings">Подключить аккаунт</button><button class="btn btn-primary" data-go="lister"><svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>Новый оффер</button></div></div>
      <div class="grid stats-grid"><article class="stat-card"><div class="stat-header"><span class="stat-icon" data-ico="wallet"></span>Баланс FunPay</div><div class="stat-value" id="stat-balance">—</div><div class="stat-foot" id="stat-balance-sub">Подключите аккаунт</div></article><article class="stat-card"><div class="stat-header"><span class="stat-icon" data-ico="listing"></span>Мои офферы</div><div class="stat-value" id="stat-offers">—</div><div class="stat-foot">В выбранной категории</div></article><article class="stat-card"><div class="stat-header"><span class="stat-icon" data-ico="message"></span>Чаты</div><div class="stat-value" id="stat-chats">—</div><div class="stat-foot" id="stat-unread">Непрочитанных: —</div></article><article class="stat-card"><div class="stat-header"><span class="stat-icon" data-ico="order"></span>Активные заказы</div><div class="stat-value" id="stat-orders">—</div><div class="stat-foot">Текущие продажи</div></article></div>
      <div class="grid two-col"><section class="panel"><div class="panel-head"><div><div class="panel-title">Быстрый доступ</div><div class="panel-sub">Часто используемые действия</div></div><span class="pill">WORKSPACE</span></div><div class="panel-body"><div class="quick-grid"><button class="quick-card" data-go="lister"><span class="quick-ico" data-ico="listing"></span><span><div class="quick-title">Создать оффер</div><div class="quick-text">Игра, описание, цена, количество</div></span></button><button class="quick-card" data-go="search"><span class="quick-ico" data-ico="search"></span><span><div class="quick-title">Поиск офферов</div><div class="quick-text">Сравните предложения категории</div></span></button><button class="quick-card" data-go="chats"><span class="quick-ico" data-ico="message"></span><span><div class="quick-title">Проверить чаты</div><div class="quick-text">Сообщения и непрочитанные</div></span></button><button class="quick-card" data-go="listings"><span class="quick-ico" data-ico="layers"></span><span><div class="quick-title">Мои предложения</div><div class="quick-text">Редактирование и поднятие</div></span></button></div></div></section><section class="panel"><div class="panel-head"><div><div class="panel-title">Состояние системы</div><div class="panel-sub">Подключение сервисов</div></div><span class="pill" id="system-pill">ОЖИДАНИЕ</span></div><div class="panel-body"><div class="activity"><div class="activity-row"><span class="activity-mark" id="activity-fp-mark"></span><div><div class="activity-title">Аккаунт FunPay</div><div class="activity-note" id="activity-fp-note">Подключите сессию в настройках, чтобы загружать реальные данные.</div></div></div><div class="activity-row"><span class="activity-mark" style="background:var(--good)"></span><div><div class="activity-title">Панель управления</div><div class="activity-note">Веб-интерфейс запущен. Секреты не выводятся в журнал.</div></div></div><div class="activity-row"><span class="activity-mark" style="background:var(--accent2)"></span><div><div class="activity-title">Быстрые действия</div><div class="activity-note">Звуковые уведомления настраиваются кнопкой динамика сверху.</div></div></div></div></div></section></div>
      <div class="grid dashboard-lower"><section class="panel dashboard-chat-panel"><div class="panel-head"><div><div class="panel-title">Последние сообщения</div><div class="panel-sub">Недавняя активность чатов FunPay</div></div><button class="btn btn-small" data-go="chats">Все сообщения →</button></div><div id="dashboard-chat-preview" class="dashboard-chat-list"><div class="empty-state"><strong>Загружаем сообщения…</strong></div></div></section><section class="panel dashboard-access-panel"><div class="panel-head"><div><div class="panel-title">Доступ и тарифы</div><div class="panel-sub">Состояние лицензии и планы доступа</div></div><span class="pill good">KEY SYSTEM</span></div><div class="panel-body"><div class="dashboard-plan-list"><div class="dashboard-plan-row"><span class="plan-dot"></span><b>15 ⭐</b><span>1 день</span><span class="plan-availability">Ключ</span></div><div class="dashboard-plan-row"><span class="plan-dot"></span><b>25 ⭐</b><span>1,5 дня</span><span class="plan-availability">Ключ</span></div><div class="dashboard-plan-row"><span class="plan-dot"></span><b>50 ⭐</b><span>3 дня</span><span class="plan-availability">Ключ</span></div><div class="dashboard-plan-row"><span class="plan-dot"></span><b>100 ⭐</b><span>1 неделя</span><span class="plan-availability">Ключ</span></div><div class="dashboard-plan-row"><span class="plan-dot"></span><b>400 ⭐</b><span>1 месяц</span><span class="plan-availability">Ключ</span></div><div class="dashboard-plan-row"><span class="plan-dot"></span><b>1000 ⭐</b><span>Навсегда</span><span class="plan-availability">Ключ</span></div></div><div class="dashboard-access-footer"><span class="access-lock">∞</span><span>История выданных ключей сохраняется в журнале лицензий.</span></div><button id="dashboard-admin-open" class="btn btn-primary dashboard-admin-btn hidden" data-go="admin" type="button">♛ Открыть админ-панель <span>→</span></button></div></section></div>
    </section>
    <section class="page hidden" data-view="lister" id="page-lister">
      <div class="page-head"><div><div class="eyebrow">LISTING WORKFLOW</div><h1 class="h1">Auto Lister</h1><div class="page-desc">Выберите действие, игру и параметры оффера. Поля и категории подгружаются из FunPay.</div></div></div>
      <section class="catalog-search-panel"><div class="catalog-search-top"><div class="catalog-search-symbol"><svg viewBox="0 0 24 24"><circle cx="10.5" cy="10.5" r="6.5"/><path d="m15.5 15.5 5 5"/></svg></div><div><div class="catalog-search-title">Быстрый поиск игры на FunPay</div><div class="catalog-search-sub">Начните с одной буквы — ищем реальные категории и разделы каталога.</div></div></div><div class="catalog-search-wrap"><input id="catalog-search" class="catalog-search-input" type="search" maxlength="80" autocomplete="off" placeholder="Например: roblox, cs2, rust…"></div><div id="catalog-results" class="catalog-results"><div class="catalog-result" style="pointer-events:none"><span class="catalog-result-ico">↗</span><span class="catalog-result-main"><span class="catalog-result-name">Подключите FunPay, чтобы искать категории</span><span class="catalog-result-path">Результаты будут загружены из каталога FunPay</span></span></div></div></section>
      <div class="mode-switch" role="tablist"><button type="button" class="active" data-mode="sell">Продать · создать оффер</button><button type="button" data-mode="buy">Купить · найти офферы</button></div>
      <div class="form-layout"><section class="panel form-card"><div class="section-label">01 / Категория и параметры</div><div class="field-grid"><div class="field full"><label for="game-select">Игра / категория</label><select id="game-select"><option value="">Сначала подключите FunPay</option></select><div class="field-hint">Список игр загружается из аккаунта FunPay.</div></div><div class="field full"><label for="subcategory-select">Раздел</label><select id="subcategory-select"><option value="">Выберите игру</option></select></div><div class="field full sell-only"><label for="lot-title">Название оффера</label><input id="lot-title" maxlength="200" placeholder="Например: 1 000 000 игровой валюты"></div><div class="field sell-only"><label for="lot-price">Цена</label><input id="lot-price" type="number" min="0.01" step="0.01" placeholder="150.00"></div><div class="field sell-only"><label for="lot-amount">Количество</label><input id="lot-amount" type="number" min="1" step="1" value="1"></div><div class="field full sell-only"><label for="lot-description">Описание</label><textarea id="lot-description" maxlength="5000" placeholder="Условия передачи, сроки и детали предложения"></textarea></div><div class="field full buy-only hidden"><label for="offer-query">Поиск по офферам</label><input id="offer-query" maxlength="180" placeholder="Введите предмет, сервер или ключевые слова"><div class="field-hint">Поиск выполняется в выбранной категории FunPay.</div></div></div><div class="settings-foot" style="margin-top:21px"><button class="btn btn-primary" id="lister-submit"><svg viewBox="0 0 24 24"><path d="m5 12 4 4L19 6"/></svg><span>Создать оффер</span></button><button class="btn" id="lister-reset">Очистить поля</button></div><div id="lister-result" style="margin-top:14px"></div></section>
      <aside class="preview-box"><div class="preview-icon" data-ico="listing"></div><div class="eyebrow">LIVE PREVIEW</div><div class="preview-title" id="preview-title">Ваш оффер</div><div class="preview-desc" id="preview-desc">Название и описание отобразятся здесь по мере заполнения формы.</div><div class="preview-divider"></div><div class="preview-line"><span>Категория</span><strong id="preview-game">Не выбрана</strong></div><div class="preview-line"><span>Количество</span><strong id="preview-amount">1</strong></div><div class="preview-line"><span>Статус</span><strong>Готов к проверке</strong></div><div class="preview-divider"></div><div style="font-size:10px;color:var(--muted)">Цена предложения</div><div class="preview-price" id="preview-price">—</div><div style="margin-top:21px" class="notice">Проверьте выбранную категорию, цену и описание перед отправкой. Создание оффера выполняется через подключённую сессию FunPay.</div></aside></div>
      <section class="panel hidden" id="search-results-panel" style="margin-top:17px"><div class="panel-head"><div><div class="panel-title">Результаты поиска</div><div class="panel-sub" id="search-result-sub">Публичные предложения FunPay</div></div><button class="btn btn-small" id="search-open-funpay">Открыть категорию на FunPay</button></div><div id="search-results"></div></section>
    </section>
    <section class="page hidden" data-view="search" id="page-search"><div class="page-head"><div><div class="eyebrow">MARKETPLACE EXPLORER</div><h1 class="h1">Поиск офферов</h1><div class="page-desc">Найдите предложения по игре и ключевым словам.</div></div></div><section class="panel"><div class="toolbar"><div class="field-inline"><label for="search-game">Игра</label><select id="search-game"><option value="">Выберите категорию</option></select></div><div class="field-inline"><label for="search-subcategory">Раздел</label><select id="search-subcategory"><option value="">Выберите раздел</option></select></div><input id="search-query" placeholder="Название, сервер или предмет" maxlength="180"><button class="btn btn-primary" id="search-run">Найти офферы</button><span class="toolbar-spacer"></span><button class="btn" id="search-clear">Сбросить</button></div><div id="search-table"><div class="empty-state"><svg viewBox="0 0 24 24"><circle cx="10.8" cy="10.8" r="6.8"/><path d="m16 16 5 5"/></svg><strong>Задайте параметры поиска</strong><p>Выберите игру и раздел — результаты появятся здесь.</p></div></div></section></section>
    <section class="page hidden" data-view="listings" id="page-listings"><div class="page-head"><div><div class="eyebrow">YOUR INVENTORY</div><h1 class="h1">Мои офферы</h1><div class="page-desc">Просмотр, редактирование и поднятие ваших предложений.</div></div><div class="actions"><button class="btn" id="raise-selected">Поднять выбранные</button><button class="btn btn-primary" data-go="lister">Новый оффер</button></div></div><section class="panel"><div class="toolbar"><div class="field-inline"><label for="lots-game">Игра</label><select id="lots-game"><option value="">Выберите категорию</option></select></div><div class="field-inline"><label for="lots-subcategory">Раздел</label><select id="lots-subcategory"><option value="">Выберите раздел</option></select></div><span class="toolbar-spacer"></span><button class="btn btn-small" id="lots-refresh">Обновить</button></div><div id="my-lots-table"><div class="empty-state"><svg viewBox="0 0 24 24"><path d="M4 7h16M4 12h16M4 17h10"/><path d="M3 4h18v16H3z"/></svg><strong>Выберите категорию</strong><p>Список собственных офферов загрузится после выбора раздела.</p></div></div></section></section>
    <section class="page hidden" data-view="chats" id="page-chats"><div class="page-head"><div><div class="eyebrow">CUSTOMER SUPPORT</div><h1 class="h1">Messages</h1><div class="page-desc">Чаты FunPay и история сообщений.</div></div><button class="btn" id="chats-refresh">Обновить чаты</button></div><section class="panel chat-layout"><aside class="chat-sidebar"><div class="toolbar"><input id="chat-filter" placeholder="Найти чат" style="min-width:0;width:100%"></div><div class="chat-list" id="chat-list"><div class="empty-state"><strong>Нет данных</strong><p>Подключите FunPay и загрузите чаты.</p></div></div></aside><section class="chat-main"><div class="chat-main-head" id="chat-main-head"><div class="panel-title">Выберите чат</div><div class="panel-sub">История сообщений отобразится здесь.</div></div><div class="chat-messages" id="chat-messages"><div class="empty-state"><svg viewBox="0 0 24 24"><path d="M20 11.5a7.5 7.5 0 0 1-7.5 7.5H6l-3 2v-6.5A7.5 7.5 0 1 1 20 11.5Z"/></svg><strong>Нет выбранного чата</strong><p>Выберите собеседника слева.</p></div></div><form class="chat-composer" id="chat-send-form"><input id="chat-message" placeholder="Напишите сообщение..." autocomplete="off" disabled><button class="btn btn-primary" id="chat-send" type="submit" disabled>Отправить</button></form></section></section></section>
    <section class="page hidden" data-view="orders" id="page-orders"><div class="page-head"><div><div class="eyebrow">SALES MONITOR</div><h1 class="h1">Заказы</h1><div class="page-desc">Текущие продажи в вашем аккаунте FunPay.</div></div><button class="btn" id="orders-refresh">Обновить заказы</button></div><section class="panel" id="orders-table"><div class="empty-state"><svg viewBox="0 0 24 24"><path d="M7 3h10l3 4v14H4V7zM4 7h16M8 12h8M8 16h6"/></svg><strong>Заказы ещё не загружены</strong><p>Подключите FunPay или нажмите «Обновить заказы».</p></div></section></section>
    <section class="page hidden" data-view="settings" id="page-settings"><div class="page-head"><div><div class="eyebrow">ACCOUNT CONFIGURATION</div><h1 class="h1">Настройки</h1><div class="page-desc">Подключение FunPay и параметры интерфейса.</div></div></div><div class="settings-grid"><section class="panel settings-card"><h3>Аккаунт FunPay</h3><p>Подключите действующую сессию FunPay. В интерфейс вставляется cookie <span class="mono">golden_key</span> и User-Agent того же браузера, где вы вошли в FunPay.</p><form id="fp-connect-form"><div class="field settings-field"><label for="fp-golden-key">golden_key</label><input type="password" id="fp-golden-key" autocomplete="off" placeholder="Значение cookie golden_key" required></div><div class="field settings-field"><label for="fp-user-agent">User-Agent</label><textarea id="fp-user-agent" style="min-height:76px" placeholder="Mozilla/5.0 ... Chrome/... Safari/..."></textarea><div class="field-hint">Используйте User-Agent из того же браузера. После успешного подключения поле ключа очищается.</div></div><div class="settings-foot"><button class="btn btn-primary" id="fp-connect-btn" type="submit">Подключить аккаунт</button><button class="btn btn-danger" id="fp-disconnect" type="button">Отключить</button><span class="pill" id="fp-connection-pill">Не подключён</span></div><div id="fp-connect-result" style="margin-top:13px"></div></form></section><section class="panel settings-card"><h3>Интерфейс</h3><p>Параметры сохраняются в этом браузере.</p><div class="toggle-row"><div><div class="toggle-label">Звуки интерфейса</div><div class="toggle-help">Тихий сигнал на действия и уведомления.</div></div><label class="switch"><input type="checkbox" id="sound-toggle"><span></span></label></div><div class="toggle-row"><div><div class="toggle-label">Автообновление данных</div><div class="toggle-help">Периодическая проверка чатов и статистики.</div></div><label class="switch"><input type="checkbox" id="auto-refresh-toggle" checked><span></span></label></div><div class="toggle-row"><div><div class="toggle-label">Выход из панели</div><div class="toggle-help">Завершить текущую веб-сессию.</div></div><button class="btn btn-small" id="logout-btn">Выйти</button></div><div class="security-note" style="margin-top:18px">Безопасность: <span class="mono">golden_key</span>, введённый здесь, хранится только в памяти процесса. После перезапуска подключитесь снова либо задайте защищённую переменную <span class="mono">FUNPAY_GOLDEN_KEY</span> в Render для автоматического подключения. Пароль панели <span class="mono">DASHBOARD_PASSWORD</span> необязателен для входа по ключу/Telegram.</div></section></div></section>
<section class="page hidden" data-view="admin" id="page-admin"><div class="page-head"><div><div class="eyebrow">RESTRICTED / TELEGRAM ADMIN</div><h1 class="h1">Панель администратора</h1><div class="page-desc">История всех выданных ключей. Записи не удаляются после окончания срока.</div></div><div class="actions"><button class="btn" id="admin-refresh">Обновить журнал</button><span class="pill" id="admin-license-total">— ключей</span></div></div><section class="panel admin-create-panel"><div class="panel-head"><div><div class="panel-title">Создать лицензионный ключ</div><div class="panel-sub">Выберите срок — готовый ключ появится сразу после сохранения.</div></div><span class="pill good">ADMIN</span></div><form id="admin-create-form" class="panel-body"><div class="field-grid"><div class="field"><label for="admin-duration">Срок действия</label><select id="admin-duration"><option value="1h">1 час</option><option value="6h">6 часов</option><option value="12h">12 часов</option><option value="24h" selected>1 день</option><option value="36h">1,5 дня</option><option value="3d">3 дня</option><option value="7d">7 дней</option><option value="30d">30 дней</option><option value="forever">Навсегда</option></select></div><div class="field"><label for="admin-user-id">Telegram ID для журнала (необязательно)</label><input id="admin-user-id" type="number" min="1" step="1" placeholder="Только пометка в журнале"><div class="field-hint">ID фиксируется для учёта; сам ключ пока не ограничивается конкретным аккаунтом.</div></div></div><div class="settings-foot" style="margin-top:16px"><button class="btn btn-primary" id="admin-create-btn" type="submit">＋ Сгенерировать ключ</button><span class="field-hint">Ключ сохранится в журнале, включая после истечения срока.</span></div><div id="admin-created-key" style="margin-top:12px"></div></form></section><section class="panel"><div class="panel-head"><div><div class="panel-title">Журнал лицензий</div><div class="panel-sub">FREE PLAN и покупки через Telegram Stars · сортировка от новых к старым</div></div><input id="admin-key-filter" style="max-width:230px;height:35px;padding:0 10px;border:1px solid var(--line);border-radius:10px;background:#0d0d16;font-size:11px" placeholder="Фильтр по ключу / Telegram ID"></div><div id="admin-license-list"><div class="empty-state"><strong>Загрузка журнала…</strong></div></div></section><div class="notice" style="margin-top:14px">Доступ администратора определяется подписанными данными Telegram Mini App и фиксированным Telegram ID в коде. Не открывайте WebApp через обычную браузерную ссылку, если ожидаете автоматический вход администратора.</div></section>
  </main>
</div>
<div class="toast-stack" id="toasts" aria-live="polite"></div>

<div class="modal-backdrop hidden" id="edit-modal" style="position:fixed;inset:0;z-index:300;background:#000a;backdrop-filter:blur(5px);display:grid;place-items:center;padding:17px"><div class="panel" style="width:min(580px,100%);padding:22px"><div class="panel-head" style="padding:0 0 15px"><div><div class="panel-title">Редактировать оффер</div><div class="panel-sub" id="edit-subtitle">Изменение выбранного предложения</div></div><button class="icon-btn" id="edit-close">×</button></div><form id="edit-form"><div class="field-grid" style="margin-top:18px"><div class="field full"><label for="edit-title">Название</label><input id="edit-title" required maxlength="200"></div><div class="field"><label for="edit-price">Цена</label><input id="edit-price" required type="number" min=".01" step=".01"></div><div class="field"><label for="edit-amount">Количество</label><input id="edit-amount" required type="number" min="0" step="1"></div><div class="field full"><label for="edit-description">Описание</label><textarea id="edit-description" maxlength="5000"></textarea></div><div class="field full"><label style="display:flex;gap:8px;align-items:center"><input id="edit-active" type="checkbox" style="width:16px;height:16px"> Оффер активен</label></div></div><div class="settings-foot"><button class="btn btn-primary" type="submit">Сохранить изменения</button><button class="btn" type="button" id="edit-cancel">Отмена</button></div></form></div></div>
<script>
(()=>{'use strict';
const $=s=>document.querySelector(s), $$=s=>Array.from(document.querySelectorAll(s));
const state={session:sessionStorage.getItem('fpal.session')||'',page:'dashboard',mode:'sell',connected:false,profile:null,categories:[],subcats:new Map(),chats:[],activeChat:null,orders:[],selectedLots:new Set(),editingLot:null,chatTimer:null,isAdmin:false,catalogResults:[],licenseRemaining:null};
let soundEnabled=localStorage.getItem('fpal.sound')!=='off';let autoRefresh=localStorage.getItem('fpal.refresh')!=='off';let audioCtx=null;let firstGestureDone=false;
const ICONS={brand:'<svg viewBox="0 0 24 24"><path d="M12 2.5 20 7v10l-8 4.5L4 17V7z"/><path d="m4 7 8 5 8-5M12 12v9.5M8 4.7l8 4.5v5.6l-8 4.5"/></svg>',wallet:'<svg viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="15" rx="2"/><path d="M3 8h18M16 14h2"/><path d="M6 5V3h12v2"/></svg>',listing:'<svg viewBox="0 0 24 24"><path d="M4 5h16M4 12h10M4 19h16"/><circle cx="19" cy="12" r="2"/></svg>',message:'<svg viewBox="0 0 24 24"><path d="M20 11.5a7.5 7.5 0 0 1-7.5 7.5H6l-3 2v-6.5A7.5 7.5 0 1 1 20 11.5Z"/><path d="M8 10h8M8 13.5h5"/></svg>',order:'<svg viewBox="0 0 24 24"><path d="M7 3h10l3 4v14H4V7zM4 7h16M8 12h8M8 16h6"/></svg>',search:'<svg viewBox="0 0 24 24"><circle cx="10.8" cy="10.8" r="6.8"/><path d="m16 16 5 5"/></svg>',layers:'<svg viewBox="0 0 24 24"><path d="m12 3 9 5-9 5-9-5 9-5Z"/><path d="m3 12 9 5 9-5M3 16l9 5 9-5"/></svg>'};
$('#brand-mark').innerHTML=ICONS.brand;$('#login-mark').innerHTML=ICONS.brand;$$('[data-ico]').forEach(el=>el.innerHTML=ICONS[el.dataset.ico]||ICONS.listing);
const defaultUserAgent=(navigator.userAgent&&navigator.userAgent.trim())||'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';
const uaInput=$('#fp-user-agent');if(uaInput)uaInput.value=localStorage.getItem('fpal.user-agent')||defaultUserAgent;
uaInput?.addEventListener('change',()=>localStorage.setItem('fpal.user-agent',uaInput.value.trim()));

function hashSeed(value){let h=2166136261;for(const ch of String(value??'')){h^=ch.charCodeAt(0);h=Math.imul(h,16777619)}return h>>>0}
function avatarUrl(seed,label=''){const h=hashSeed(seed||label||'FunPay'),h1=h%360,h2=(h1+75+(h%50))%360,dx=12+(h%30),dy=10+((h>>>6)%27),r=19+((h>>>12)%16);const svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 96"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop stop-color="hsl(${h1} 78% 70%)"/><stop offset="1" stop-color="hsl(${h2} 70% 38%)"/></linearGradient><radialGradient id="l"><stop stop-color="#ffffff" stop-opacity=".5"/><stop offset="1" stop-color="#ffffff" stop-opacity="0"/></radialGradient></defs><rect width="96" height="96" rx="28" fill="url(#g)"/><circle cx="${dx}" cy="${dy}" r="${r+15}" fill="url(#l)"/><circle cx="${75-(h%18)}" cy="${18+(h%26)}" r="${13+(h%17)}" fill="#fff" opacity=".15"/><path d="M0 72 Q ${20+h%20} ${40+h%16} 48 71 T96 54 V96 H0Z" fill="#090b19" opacity=".25"/><circle cx="48" cy="38" r="17" fill="#f7f4ff" opacity=".88"/><path d="M16 96 C18 69 31 62 48 62 S78 69 80 96" fill="#f7f4ff" opacity=".88"/><path d="M34 35 Q48 17 62 35" stroke="#23203e" stroke-width="5" stroke-linecap="round" fill="none" opacity=".25"/></svg>`;return 'data:image/svg+xml;charset=UTF-8,'+encodeURIComponent(svg)}
function avatarMarkup(seed,label,cls='chat-avatar'){return `<span class="${cls}"><img alt="" loading="lazy" src="${avatarUrl(seed,label)}"></span>`}
function sound(kind='click'){if(!soundEnabled)return;try{audioCtx=audioCtx||new(window.AudioContext||window.webkitAudioContext)();if(audioCtx.state==='suspended')audioCtx.resume();const osc=audioCtx.createOscillator(),gain=audioCtx.createGain();osc.type='sine';const freqs=kind==='ok'?[660,880]:kind==='error'?[220,165]:[420,560];osc.frequency.setValueAtTime(freqs[0],audioCtx.currentTime);osc.frequency.linearRampToValueAtTime(freqs[1],audioCtx.currentTime+.075);gain.gain.setValueAtTime(.0001,audioCtx.currentTime);gain.gain.exponentialRampToValueAtTime(.045,audioCtx.currentTime+.012);gain.gain.exponentialRampToValueAtTime(.0001,audioCtx.currentTime+.14);osc.connect(gain);gain.connect(audioCtx.destination);osc.start();osc.stop(audioCtx.currentTime+.15)}catch{}}
function toast(message,type='info',ms=4000){const el=document.createElement('div');el.className='toast '+(type==='ok'?'ok':type==='error'?'error':type==='warn'?'warn':'');const span=document.createElement('span');span.textContent=message;const close=document.createElement('button');close.type='button';close.textContent='×';close.addEventListener('click',()=>el.remove());el.append(span,close);$('#toasts').append(el);sound(type==='error'?'error':type==='ok'?'ok':'click');setTimeout(()=>el.remove(),ms)}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function api(path,opts={}){const headers={'Accept':'application/json',...(opts.headers||{})};if(state.session)headers['X-Dashboard-Session']=state.session;if(opts.body!==undefined){headers['Content-Type']='application/json';opts={...opts,body:JSON.stringify(opts.body)}}let res;try{res=await fetch(path,{...opts,headers})}catch{throw new Error('Не удалось связаться с сервером')}let payload=null;const text=await res.text();try{payload=text?JSON.parse(text):null}catch{payload=text}if(res.status===401&&path!='/api/login'){logoutLocal();throw new Error('Сессия истекла. Войдите снова.')}if(!res.ok){throw new Error(typeof payload?.detail==='string'?payload.detail:`Ошибка ${res.status}`)}return {data:payload,res}}
function setPage(page){const valid=['dashboard','lister','search','listings','chats','orders','settings','admin'];if(!valid.includes(page)||(page==='admin'&&!state.isAdmin))page='dashboard';state.page=page;$$('[data-view]').forEach(el=>el.classList.toggle('hidden',el.dataset.view!==page));$$('.nav-item').forEach(el=>el.classList.toggle('active',el.dataset.page===page));$('#crumb-label').textContent=({dashboard:'Dashboard',lister:'Auto Lister',search:'Offer Search',listings:'My Offers',chats:'Messages',orders:'Orders',settings:'Settings',admin:'Admin'})[page];$('#sidebar').classList.remove('open');$('#scrim').classList.remove('show');if(page==='settings')refreshConnectionStatus();if(page==='chats'&&state.connected)loadChats();if(page==='orders'&&state.connected)loadOrders();if(page==='listings'&&state.categories.length)populateAllCategorySelects();if(page==='lister'){refreshConnectionStatus().then(()=>{if(state.connected){loadCategories();if($('#catalog-search')?.value.trim())runCatalogSearch()}else{state.categories=[];populateAllCategorySelects();renderDashboardChats();renderCatalogIdleMessage()}})}if(page==='search'&&state.categories.length)populateAllCategorySelects();if(page==='admin')loadAdminLicenses();}
function logoutLocal(){state.session='';state.connected=false;sessionStorage.removeItem('fpal.session');$('#app').classList.add('hidden');$('#login-view').classList.remove('hidden');$('#login-password').value='';$('#login-error').textContent='';}
async function performLogin(){const btn=$('#login-form button[type=submit]');$('#login-error').textContent='';btn.disabled=true;btn.textContent='Проверка доступа…';try{const tg=window.Telegram&&window.Telegram.WebApp;const {data}=await api('/api/login',{method:'POST',body:{password:$('#login-password').value.trim(),init_data:tg?.initData||''}});state.session=data.token;state.isAdmin=!!data.is_admin;sessionStorage.setItem('fpal.session',state.session);$('#login-view').classList.add('hidden');$('#app').classList.remove('hidden');$('#login-password').value='';await bootApp();sound('ok')}catch(err){$('#login-error').textContent=err.message;sound('error')}finally{btn.disabled=false;btn.innerHTML='Войти в панель <span aria-hidden="true">→</span>'}}
$('#login-form').addEventListener('submit',async e=>{e.preventDefault();await performLogin()});
function logout(){if(state.session)api('/api/logout',{method:'POST'}).catch(()=>{});logoutLocal();toast('Вы вышли из панели','info')}
function updateConnection(connected,username=''){state.connected=connected;$('#side-dot').className='status-dot '+(connected?'on':'off');$('#top-dot').className='status-dot '+(connected?'on':'off');$('#side-status').textContent=connected?'FunPay подключён':'FunPay не подключён';$('#top-status').textContent=connected?'Аккаунт активен':'Нет подключения';$('#side-account').textContent=connected?(username?'@'+username:'Сессия активна'):'Откройте настройки аккаунта';$('#user-name').textContent=username?'@'+username:'Панель';$('#user-avatar').innerHTML=`<img alt="" src="${avatarUrl(state.profile?.id||username||'funpay-account',username||'FP')}">`;$('#fp-connection-pill').textContent=connected?'Подключён':'Не подключён';$('#fp-connection-pill').className='pill '+(connected?'good':'');$('#system-pill').textContent=connected?'ПОДКЛЮЧЕНО':'ОЖИДАНИЕ';$('#system-pill').className='pill '+(connected?'good':'');$('#activity-fp-mark').style.background=connected?'var(--good)':'var(--warn)';$('#activity-fp-note').textContent=connected?'Сессия активна'+(username?' · @'+username:'')+'. Данные берутся из аккаунта FunPay.':'Подключите сессию в настройках, чтобы загружать реальные данные.';renderDashboardChats();renderCatalogIdleMessage()}
async function refreshConnectionStatus(){try{const {data}=await api('/api/funpay/status');updateConnection(!!data.connected,data.profile?.username||'');if(data.connected){state.profile=data;$('#stat-balance').textContent=formatBalance(data.balance||{});$('#stat-balance-sub').textContent='Баланс аккаунта';}else{$('#stat-balance').textContent='—';$('#stat-balance-sub').textContent='Подключите аккаунт'}}catch(e){if(e.message.includes('Сессия'))return;updateConnection(false)}}
function formatBalance(b){const val=Number(b.available_rub??b.total_rub??0);return Number.isFinite(val)?val.toLocaleString('ru-RU',{maximumFractionDigits:2})+' ₽':'—'}
function renderCatalogIdleMessage(){const target=$('#catalog-results');if(!target||($('#catalog-search')?.value.trim()))return;if(!state.connected){target.innerHTML='<div class="catalog-result" style="pointer-events:none"><span class="catalog-result-ico">!</span><span class="catalog-result-main"><span class="catalog-result-name">FunPay не подключён</span><span class="catalog-result-path">Настройки → подключите golden_key и User-Agent</span></span></div>';return}target.innerHTML=`<div class="catalog-result" style="pointer-events:none"><span class="catalog-result-ico">✓</span><span class="catalog-result-main"><span class="catalog-result-name">Каталог готов к поиску</span><span class="catalog-result-path">${state.categories.length} категорий загружено · начните вводить название игры</span></span></div>`}
async function loadCategories(){if(!state.connected){state.categories=[];state.subcats.clear();populateAllCategorySelects();renderCatalogIdleMessage();return}try{const {data}=await api('/api/funpay/categories');state.categories=Array.isArray(data)?data:[];state.subcats.clear();for(const c of state.categories){if(Array.isArray(c.subcategories))state.subcats.set(String(c.id),c.subcategories)}populateAllCategorySelects();renderCatalogIdleMessage()}catch(e){renderCatalogIdleMessage();toast(e.message,'error')}}
function populateAllCategorySelects(){const pairs=[['#game-select','#subcategory-select'],['#search-game','#search-subcategory'],['#lots-game','#lots-subcategory']];for(const [gameSel,subSel] of pairs){const g=$(gameSel),s=$(subSel);if(!g||!s)continue;const storedGame=gameSel==='#game-select'?localStorage.getItem('fpal.category.game')||'':'';const storedSub=gameSel==='#game-select'?localStorage.getItem('fpal.category.sub')||'':'';const priorG=g.value||storedGame,priorS=s.value||storedSub;g.innerHTML='<option value="">'+(state.connected?'Выберите игру / категорию':'Подключите FunPay')+'</option>'+state.categories.map(c=>`<option value="${esc(c.id)}">${esc(c.name)}</option>`).join('');if(state.categories.some(c=>String(c.id)===String(priorG)))g.value=String(priorG);else if(state.categories.length===1)g.value=String(state.categories[0].id);fillSubcategories(gameSel,subSel,priorS)}}
function persistCategory(){if($('#game-select')?.value)localStorage.setItem('fpal.category.game',$('#game-select').value);if($('#subcategory-select')?.value)localStorage.setItem('fpal.category.sub',$('#subcategory-select').value)}
async function fillSubcategories(gameSelector,subSelector,keep=''){const gameId=$(gameSelector)?.value;const sub=$(subSelector);if(!sub)return;sub.innerHTML='<option value="">Загрузка разделов…</option>';if(!gameId){sub.innerHTML='<option value="">Выберите игру</option>';return}let values=state.subcats.get(String(gameId));if(!Array.isArray(values)||!values.length){try{const {data}=await api('/api/funpay/subcategories/'+encodeURIComponent(gameId));values=data;state.subcats.set(String(gameId),values)}catch(e){sub.innerHTML='<option value="">Не удалось загрузить</option>';toast(e.message,'error');return}}sub.innerHTML='<option value="">Выберите раздел</option>'+values.map(s=>`<option value="${esc(s.id)}">${esc(s.name)}</option>`).join('');if(values.some(s=>String(s.id)===String(keep)))sub.value=String(keep);else if(values.length===1)sub.value=String(values[0].id);if(gameSelector==='#game-select')updatePreview();}
function selectedCategoryName(gameSel,subSel){const c=state.categories.find(x=>String(x.id)===$(gameSel)?.value);const s=(state.subcats.get(String(c?.id))||[]).find(x=>String(x.id)===$(subSel)?.value);return s?.name||c?.name||'Не выбрана'}
function updatePreview(){const title=$('#lot-title').value.trim();$('#preview-title').textContent=title||'Ваш оффер';$('#preview-desc').textContent=$('#lot-description').value.trim()||'Название и описание отобразятся здесь по мере заполнения формы.';$('#preview-game').textContent=selectedCategoryName('#game-select','#subcategory-select');$('#preview-amount').textContent=$('#lot-amount').value||'1';const price=Number($('#lot-price').value);$('#preview-price').textContent=price>0?price.toLocaleString('ru-RU',{maximumFractionDigits:2})+' ₽':'—'}
let sessionInfo=null;let licenseTimerInterval=null;
function formatRemaining(seconds){if(seconds===null||seconds===undefined)return '∞';seconds=Math.max(0,Math.floor(seconds));const d=Math.floor(seconds/86400),h=Math.floor(seconds%86400/3600),m=Math.floor(seconds%3600/60),sec=seconds%60;if(d)return `${d}д ${h}ч ${m}м ${sec}с`;if(h)return `${h}ч ${m}м ${sec}с`;if(m)return `${m}м ${sec}с`;return `${sec}с`}
function renderLicenseTimer(){const el=$('#license-timer');if(!el)return;if(!sessionInfo){el.textContent='Ключ · проверка';return}if(sessionInfo.is_admin){el.innerHTML='<span class="license-timer-line">ADMIN ACCESS</span><span class="license-progress"><i style="width:100%"></i></span>';el.style.color='#d6caff';el.style.borderColor='#9672ff55';return}if(sessionInfo.remaining_seconds===null){el.innerHTML='<span class="license-timer-line">Ключ · ∞</span><span class="license-progress"><i style="width:100%"></i></span>';return}const remaining=Math.max(0,Number(sessionInfo.remaining_seconds)||0);const total=sessionInfo.expires_at&&sessionInfo.created_at?Math.max(1,Number(sessionInfo.expires_at)-Number(sessionInfo.created_at)):remaining;const percent=Math.max(0,Math.min(100,remaining/total*100));if(remaining<=0){el.innerHTML='<span class="license-timer-line">Ключ истёк</span><span class="license-progress"><i style="width:0%"></i></span>';el.style.color='#ff9aaa';if(!sessionInfo.expiryHandled){sessionInfo.expiryHandled=true;setTimeout(()=>{logoutLocal();toast('Срок действия ключа завершён. Получите новый ключ.','warn',6000)},700)}return}el.innerHTML=`<span class="license-timer-line">Осталось · ${esc(formatRemaining(remaining))}</span><span class="license-progress"><i style="width:${percent.toFixed(3)}%"></i></span>`;sessionInfo.remaining_seconds=Math.max(0,remaining-1)}
async function loadSessionInfo(){try{const {data}=await api('/api/session/info');sessionInfo=data;state.isAdmin=!!data.is_admin;$('#admin-nav').classList.toggle('hidden',!state.isAdmin);$('#dashboard-admin-open')?.classList.toggle('hidden',!state.isAdmin);renderLicenseTimer();if(licenseTimerInterval)clearInterval(licenseTimerInterval);licenseTimerInterval=setInterval(renderLicenseTimer,1000);if(state.isAdmin&&state.page==='admin')loadAdminLicenses()}catch{}}
async function loadAdminLicenses(){if(!state.isAdmin)return;const target=$('#admin-license-list');target.innerHTML='<div class="empty-state"><strong>Загружаем журнал лицензий…</strong></div>';try{const {data}=await api('/api/admin/licenses');const items=data.items||[];$('#admin-license-total').textContent=`${data.total} ключей`;const filter=($('#admin-key-filter').value||'').trim().toLowerCase();const filtered=items.filter(x=>`${x.key} ${x.telegram_user_id||''} ${x.plan_id}`.toLowerCase().includes(filter));if(!filtered.length){target.innerHTML='<div class="empty-state"><strong>Ключи не найдены</strong><p>Попробуйте изменить фильтр.</p></div>';return}const planName=x=>({'free':'FREE PLAN','day':'1 день','day_half':'1,5 дня','three_days':'3 дня','week':'1 неделя','month':'1 месяц','forever':'Навсегда'}[x.plan_id]||String(x.plan_id||'').replace(/^admin_/, 'Ручной ключ · '));target.innerHTML=`<div class="table-wrap admin-key-table"><table><thead><tr><th>Ключ</th><th>Telegram ID</th><th>Тариф</th><th>Создан</th><th>Истекает</th><th>Статус</th></tr></thead><tbody>${filtered.map(x=>`<tr><td><code>${esc(x.key)}</code></td><td class="mono">${esc(x.telegram_user_id||'—')}</td><td>${esc(planName(x))}</td><td>${x.created_at?new Date(Number(x.created_at)*1000).toLocaleString('ru-RU'):'—'}</td><td>${x.expires_at?new Date(Number(x.expires_at)*1000).toLocaleString('ru-RU'):'Навсегда'}</td><td><span class="license-status ${x.active?'active':'expired'}">${x.active?'АКТИВЕН':'ИСТЁК'}</span></td></tr>`).join('')}</tbody></table></div>`}catch(e){target.innerHTML=`<div class="empty-state"><strong>Не удалось загрузить журнал</strong><p>${esc(e.message)}</p></div>`;toast(e.message,'error')}}
$('#admin-create-form')?.addEventListener('submit',async e=>{e.preventDefault();if(!state.isAdmin){toast('Действие доступно только администратору','error');return}const btn=$('#admin-create-btn');const result=$('#admin-created-key');btn.disabled=true;btn.textContent='Создаём ключ…';result.innerHTML='';const rawId=$('#admin-user-id').value.trim();try{const {data}=await api('/api/admin/licenses',{method:'POST',body:{duration:$('#admin-duration').value,telegram_user_id:rawId?Number(rawId):null}});result.innerHTML=`<div class="admin-created"><span>✓</span><div style="flex:1;min-width:160px"><div class="field-hint">Ключ создан · ${esc(data.duration_title)}${data.expires_at?' · до '+esc(new Date(Number(data.expires_at)*1000).toLocaleString('ru-RU')):' · бессрочный'}</div><code id="admin-new-key">${esc(data.key)}</code></div><button class="btn btn-small" id="admin-copy-key" type="button">Копировать</button></div>`;$('#admin-copy-key').addEventListener('click',async()=>{try{await navigator.clipboard.writeText(data.key);toast('Ключ скопирован','ok')}catch{toast('Выделите и скопируйте ключ вручную','warn')}});await loadAdminLicenses();toast('Ключ сохранён в журнале','ok')}catch(err){result.innerHTML=`<div class="notice" style="border-color:#ff71884a;color:#ff9aa9">${esc(err.message)}</div>`;toast(err.message,'error')}finally{btn.disabled=false;btn.textContent='＋ Сгенерировать ключ'}});
$('#admin-refresh')?.addEventListener('click',loadAdminLicenses);$('#admin-key-filter')?.addEventListener('input',loadAdminLicenses);
$('#admin-refresh')?.addEventListener('click',loadAdminLicenses);$('#admin-key-filter')?.addEventListener('input',()=>loadAdminLicenses());
async function bootApp(){await loadSessionInfo();await refreshConnectionStatus();await loadCategories();if(state.connected){await loadDashboardData();}setPage('dashboard');$('#sound-toggle').checked=soundEnabled;$('#sound-btn').style.color=soundEnabled?'#c5b4ff':'#77778b';$('#auto-refresh-toggle').checked=autoRefresh;}
function renderDashboardChats(){const target=$('#dashboard-chat-preview');if(!target)return;if(!state.connected){target.innerHTML='<div class="empty-state"><strong>FunPay не подключён</strong><p>Откройте настройки и подключите свой аккаунт.</p><button class="btn btn-primary" data-go="settings">Открыть настройки →</button></div>';return}const rows=(state.chats||[]).slice().sort((a,b)=>String(b.last_message_date||b.last_message_timestamp||'').localeCompare(String(a.last_message_date||a.last_message_timestamp||''))).slice(0,4);if(!rows.length){target.innerHTML='<div class="empty-state"><strong>Пока нет сообщений</strong><p>Новые диалоги появятся здесь, когда они поступят в FunPay.</p></div>';return}target.innerHTML=rows.map(c=>`<button class="dashboard-chat-row" data-chat-id="${esc(c.id)}">${avatarMarkup(c.interlocutor_id||c.id,c.name||'FP')}<span class="dashboard-chat-copy"><b>${esc(c.name||'Пользователь')}</b><small>${esc(c.last_message_text||'Нет сообщений')}</small></span>${Number(c.unread_count)>0?`<span class="unread">${esc(c.unread_count)}</span>`:''}</button>`).join('')}
async function loadDashboardData(){try{const [{data:chats},{data:orders}]=await Promise.all([api('/api/funpay/chats'),api('/api/funpay/orders?limit=100')]);state.chats=chats;state.orders=orders;renderDashboardChats();$('#stat-chats').textContent=chats.length;const unread=chats.reduce((n,c)=>n+Number(c.unread_count||0),0);$('#stat-unread').textContent='Непрочитанных: '+unread;$('#chats-badge').textContent=unread||'0';$('#stat-orders').textContent=orders.length;$('#stat-offers').textContent='—';$('#offers-badge').textContent='—';}catch(e){renderDashboardChats();if(!e.message.includes('Сессия'))toast(e.message,'warn')}}
async function listerSubmit(){if(!state.connected){toast('Сначала подключите аккаунт FunPay в настройках.','warn');setPage('settings');return}const subcategoryId=Number($('#subcategory-select').value);if(!subcategoryId){toast('Выберите игру и раздел.','warn');return}if(state.mode==='buy'){await runOfferSearch('lister');return}const title=$('#lot-title').value.trim(),description=$('#lot-description').value.trim(),price=Number($('#lot-price').value),amount=Number($('#lot-amount').value||1);if(!title){toast('Введите название оффера.','warn');$('#lot-title').focus();return}if(!Number.isFinite(price)||price<=0){toast('Укажите цену больше нуля.','warn');$('#lot-price').focus();return}const btn=$('#lister-submit');btn.disabled=true;btn.querySelector('span').textContent='Создание…';$('#lister-result').innerHTML='';try{const {data}=await api('/api/funpay/lots/create',{method:'POST',body:{subcategory_id:subcategoryId,title,description,price,amount,active:true}});$('#lister-result').innerHTML='<div class="notice">Операция передана FunPay. Ответ сервера получен; обновите собственные офферы, чтобы проверить публикацию.</div>';toast('Запрос на создание оффера выполнен.','ok');$('#lot-title').value='';$('#lot-description').value='';$('#lot-price').value='';$('#lot-amount').value='1';updatePreview();if(data.result?.offer_id)$('#lister-result').innerHTML+=`<div class="field-hint" style="margin-top:9px">ID: ${esc(data.result.offer_id)}</div>`}catch(e){$('#lister-result').innerHTML=`<div class="notice" style="border-color:#ff71884a;color:#ff9aa9">${esc(e.message)}</div>`;toast(e.message,'error')}finally{btn.disabled=false;btn.querySelector('span').textContent='Создать оффер'}}
async function runOfferSearch(source='search'){if(!state.connected){toast('Подключите FunPay в настройках.','warn');setPage('settings');return}const subId=Number(source==='lister'?$('#subcategory-select').value:$('#search-subcategory').value);const q=source==='lister'?$('#offer-query').value.trim():$('#search-query').value.trim();if(!subId){toast('Выберите игру и раздел.','warn');return}const target=source==='lister'?$('#search-results'):$('#search-table');target.innerHTML='<div class="empty-state"><strong>Поиск офферов…</strong><p>Получаем результаты из FunPay.</p></div>';if(source==='lister')$('#search-results-panel').classList.remove('hidden');try{const {data}=await api(`/api/funpay/offers?subcategory_id=${encodeURIComponent(subId)}&q=${encodeURIComponent(q)}`);renderOfferTable(target,data);if(source==='lister')$('#search-result-sub').textContent=`Найдено предложений: ${data.length}`;else toast(`Найдено предложений: ${data.length}`,'ok');const catId=source==='lister'?$('#game-select').value:$('#search-game').value;const game=state.categories.find(c=>String(c.id)===catId);$('#search-open-funpay').onclick=()=>window.open(`https://funpay.com/lots/${subId}/?query=${encodeURIComponent(q)}`,'_blank','noopener');}catch(e){target.innerHTML=`<div class="empty-state"><strong>Поиск не выполнен</strong><p>${esc(e.message)}</p></div>`;toast(e.message,'error')}}
function renderOfferTable(target,offers){if(!offers.length){target.innerHTML='<div class="empty-state"><svg viewBox="0 0 24 24"><circle cx="10.8" cy="10.8" r="6.8"/><path d="m16 16 5 5"/></svg><strong>Офферы не найдены</strong><p>Попробуйте сократить запрос или выбрать другой раздел.</p></div>';return}target.innerHTML=`<div class="table-wrap"><table><thead><tr><th>Предложение</th><th>Продавец</th><th>Количество</th><th>Цена</th><th></th></tr></thead><tbody>${offers.map(o=>`<tr><td><div class="cell-main">${esc(o.title)}</div>${o.server?`<div class="cell-sub">${esc(o.server)}</div>`:''}</td><td>${esc(o.seller)}</td><td>${esc(o.amount||'—')}</td><td class="price">${esc(o.price_text||'—')}</td><td><a class="btn btn-small" href="${esc(o.url)}" target="_blank" rel="noopener noreferrer" style="text-decoration:none">Открыть</a></td></tr>`).join('')}</tbody></table></div>`}
async function loadMyLots(){if(!state.connected){toast('Подключите FunPay.','warn');return}const subId=Number($('#lots-subcategory').value);if(!subId){$('#my-lots-table').innerHTML='<div class="empty-state"><strong>Выберите раздел</strong><p>Укажите игру и раздел, чтобы загрузить собственные офферы.</p></div>';return}$('#my-lots-table').innerHTML='<div class="empty-state"><strong>Загружаем офферы…</strong></div>';try{const {data}=await api('/api/funpay/lots?subcategory_id='+encodeURIComponent(subId));$('#stat-offers').textContent=data.length;$('#offers-badge').textContent=data.length;renderMyLots(data)}catch(e){$('#my-lots-table').innerHTML=`<div class="empty-state"><strong>Не удалось загрузить офферы</strong><p>${esc(e.message)}</p></div>`;toast(e.message,'error')}}
function renderMyLots(lots){if(!lots.length){$('#my-lots-table').innerHTML='<div class="empty-state"><svg viewBox="0 0 24 24"><path d="M4 7h16M4 12h16M4 17h10"/><path d="M3 4h18v16H3z"/></svg><strong>Офферов в этом разделе нет</strong><p>Создайте первое предложение через Auto Lister.</p><button class="btn btn-primary" data-go="lister">Создать оффер</button></div>';return}$('#my-lots-table').innerHTML=`<div class="toolbar"><span class="pill">${lots.length} офферов</span><span class="toolbar-spacer"></span><span class="field-hint">Выберите предложения для массового поднятия.</span></div><div class="table-wrap"><table><thead><tr><th><input id="lot-check-all" type="checkbox" aria-label="Выбрать все"></th><th>ID</th><th>Название</th><th>Количество</th><th>Цена</th><th>Действия</th></tr></thead><tbody>${lots.map(o=>`<tr><td><input type="checkbox" class="lot-check" data-id="${esc(o.id)}" ${state.selectedLots.has(Number(o.id))?'checked':''}></td><td class="mono">#${esc(o.id)}</td><td><div class="cell-main">${esc(o.description||o.title||'Без названия')}</div><div class="cell-sub">${esc(o.subcategory_name||'FunPay')}</div></td><td>${esc(o.amount??'—')}</td><td class="price">${Number(o.price||0).toLocaleString('ru-RU',{maximumFractionDigits:2})} ${esc(o.currency||'RUB')}</td><td><div style="display:flex;gap:5px"><button class="btn btn-small" data-lot-edit="${esc(o.id)}">Изменить</button><button class="btn btn-small btn-danger" data-lot-delete="${esc(o.id)}">Удалить</button></div></td></tr>`).join('')}</tbody></table></div>`}
async function openEdit(lotId){try{const {data}=await api(`/api/funpay/lots/${lotId}/fields`);state.editingLot=lotId;$('#edit-subtitle').textContent='Оффер #'+lotId;$('#edit-title').value=data.title||'';$('#edit-description').value=data.description||'';$('#edit-price').value=data.price||'';$('#edit-amount').value=data.amount||'1';$('#edit-active').checked=!!data.active;$('#edit-modal').classList.remove('hidden')}catch(e){toast(e.message,'error')}}
function closeEdit(){$('#edit-modal').classList.add('hidden');state.editingLot=null}
$('#edit-form').addEventListener('submit',async e=>{e.preventDefault();if(!state.editingLot)return;const submit=e.submitter;submit.disabled=true;try{await api(`/api/funpay/lots/${state.editingLot}`,{method:'PUT',body:{title:$('#edit-title').value.trim(),description:$('#edit-description').value,price:Number($('#edit-price').value),amount:Number($('#edit-amount').value),active:$('#edit-active').checked}});toast('Оффер обновлён','ok');closeEdit();loadMyLots()}catch(err){toast(err.message,'error')}finally{submit.disabled=false}});
async function deleteMyLot(id){if(!confirm(`Удалить оффер #${id} на FunPay?`))return;try{await api(`/api/funpay/lots/${id}`,{method:'DELETE'});state.selectedLots.delete(Number(id));toast('Оффер удалён','ok');loadMyLots()}catch(e){toast(e.message,'error')}}
async function raiseSelected(){const ids=[...state.selectedLots];if(!ids.length){toast('Сначала отметьте офферы в таблице.','warn');return}if(!confirm(`Поднять ${ids.length} выбранных офферов? FunPay может ограничивать частоту операции.`))return;try{const {data}=await api('/api/funpay/lots/raise',{method:'POST',body:{ids}});toast(data.error?'FunPay не поднял офферы':`Запрос на поднятие отправлен: ${ids.length}` ,data.error?'warn':'ok');}catch(e){toast(e.message,'error')}}
async function loadChats(){if(!state.connected){renderDashboardChats();return}$('#chat-list').innerHTML='<div class="empty-state"><strong>Загрузка чатов…</strong></div>';try{const {data}=await api('/api/funpay/chats');state.chats=data;const unread=data.reduce((n,c)=>n+Number(c.unread_count||0),0);$('#chats-badge').textContent=unread||'0';$('#stat-chats').textContent=data.length;$('#stat-unread').textContent='Непрочитанных: '+unread;renderChats();renderDashboardChats()}catch(e){$('#chat-list').innerHTML=`<div class="empty-state"><strong>Ошибка загрузки</strong><p>${esc(e.message)}</p></div>`;toast(e.message,'error')}}
function renderChats(){const filter=$('#chat-filter').value.toLowerCase();const chats=state.chats.filter(c=>(c.name+' '+(c.last_message_text||'')).toLowerCase().includes(filter));if(!chats.length){$('#chat-list').innerHTML='<div class="empty-state"><strong>Чаты не найдены</strong><p>Попробуйте изменить запрос.</p></div>';return}$('#chat-list').innerHTML=chats.map(c=>`<button class="chat-item ${String(state.activeChat?.id)===String(c.id)?'active':''}" data-chat-id="${esc(c.id)}">${avatarMarkup(c.interlocutor_id||c.id,c.name||'FP')}<span class="chat-meta"><span class="chat-name"><span>${esc(c.name||'Пользователь')}</span>${Number(c.unread_count)>0?`<span class="unread">${esc(c.unread_count)}</span>`:''}</span><span class="chat-preview">${esc(c.last_message_text||'Нет сообщений')}</span></span></button>`).join('')}
let chatHistoryRequest=0;
function renderChatHistory(messages, keepText=''){const list=Array.isArray(messages)?messages.slice():[];if(keepText&&!list.some(m=>!m.is_incoming&&String(m.text||'')===keepText)){list.push({id:'optimistic-'+hashSeed(keepText),text:keepText,author:'Вы',is_incoming:false,timestamp:'Только что',local_pending:true})}if(!list.length){$('#chat-messages').innerHTML='<div class="empty-state"><strong>История пока пуста</strong><p>Подтверждённые сообщения появятся здесь.</p></div>';return}$('#chat-messages').innerHTML=list.map(m=>`<div class="message ${m.is_incoming?'':'outgoing'} ${m.local_pending?'pending':''}">${esc(m.text|| (m.image_link?'Изображение':'Сообщение без текста'))}${m.image_link?`<div style="margin-top:6px"><a href="${esc(m.image_link)}" target="_blank" rel="noopener noreferrer">Открыть изображение</a></div>`:''}<div class="message-meta">${esc(m.author|| (m.is_incoming?'Собеседник':'Вы'))}${m.timestamp?' · '+esc(m.timestamp):''}${m.local_pending?' · подтверждение истории…':''}</div></div>`).join('');$('#chat-messages').scrollTop=$('#chat-messages').scrollHeight}
async function openChat(id){const c=state.chats.find(x=>String(x.id)===String(id));if(!c)return;state.activeChat=c;renderChats();const requestId=++chatHistoryRequest;$('#chat-main-head').innerHTML=`<div class="panel-title">${esc(c.name||'Пользователь')}</div><div class="panel-sub">Чат FunPay · #${esc(c.id)}</div>`;$('#chat-messages').innerHTML='<div class="empty-state"><strong>Загрузка истории…</strong></div>';$('#chat-message').disabled=false;$('#chat-send').disabled=false;try{const {data}=await api('/api/funpay/chats/'+encodeURIComponent(id));if(requestId!==chatHistoryRequest||String(state.activeChat?.id)!==String(id))return;renderChatHistory(data)}catch(e){if(requestId===chatHistoryRequest)$('#chat-messages').innerHTML=`<div class="empty-state"><strong>Не удалось загрузить</strong><p>${esc(e.message)}</p></div>`}}
$('#chat-send-form').addEventListener('submit',async e=>{e.preventDefault();const text=$('#chat-message').value.trim();if(!state.activeChat||!text)return;const chatId=state.activeChat.id;const btn=$('#chat-send');btn.disabled=true;const input=$('#chat-message');input.disabled=true;const bubble=document.createElement('div');bubble.className='message outgoing pending';bubble.textContent=text;const meta=document.createElement('div');meta.className='message-meta';meta.textContent='Отправка…';bubble.append(meta);$('#chat-messages').append(bubble);$('#chat-messages').scrollTop=$('#chat-messages').scrollHeight;try{const {data}=await api(`/api/funpay/chats/${encodeURIComponent(chatId)}/send`,{method:'POST',body:{text}});if(data?.ok!==true||!data.message_id)throw new Error('FunPay не подтвердил отправку сообщения');input.value='';meta.textContent='Отправлено · '+(data.timestamp||'подтверждено FunPay');bubble.classList.remove('pending');toast('Сообщение подтверждено FunPay','ok',1800);const c=state.chats.find(x=>String(x.id)===String(chatId));if(c){c.last_message_text=text;c.last_message_author='Вы';c.last_message_date=data.timestamp||new Date().toISOString()}renderChats();renderDashboardChats();/* Update history in the background; never wipe the confirmed bubble on a transient empty response. */setTimeout(async()=>{if(String(state.activeChat?.id)!==String(chatId))return;try{const {data:history}=await api('/api/funpay/chats/'+encodeURIComponent(chatId));if(String(state.activeChat?.id)===String(chatId)){const hasText=(history||[]).some(m=>!m.is_incoming&&String(m.text||'')===text);if(hasText)renderChatHistory(history);else renderChatHistory(history,text)}}catch{/* Keep the already-confirmed message on screen until the next refresh. */}},350)}catch(err){bubble.classList.add('send-failed');meta.textContent='Не отправлено · '+err.message;toast(err.message,'error')}finally{btn.disabled=false;input.disabled=false;input.focus()}});
async function loadOrders(){if(!state.connected){toast('Подключите FunPay.','warn');return}$('#orders-table').innerHTML='<div class="empty-state"><strong>Загрузка заказов…</strong></div>';try{const {data}=await api('/api/funpay/orders?limit=100');state.orders=data;$('#stat-orders').textContent=data.length;if(!data.length){$('#orders-table').innerHTML='<div class="empty-state"><svg viewBox="0 0 24 24"><path d="M7 3h10l3 4v14H4V7zM4 7h16"/></svg><strong>Активных заказов нет</strong><p>Когда появятся продажи, они будут отображаться в этом разделе.</p></div>';return}$('#orders-table').innerHTML=`<div class="toolbar"><span class="pill">${data.length} заказов</span></div><div class="table-wrap"><table><thead><tr><th>ID</th><th>Заказ</th><th>Покупатель</th><th>Статус</th><th>Дата</th><th>Сумма</th></tr></thead><tbody>${data.map(o=>`<tr><td class="mono">#${esc(o.id)}</td><td><div class="cell-main">${esc(o.description||'Заказ FunPay')}</div><div class="cell-sub">${esc([o.game,o.server].filter(Boolean).join(' · '))}</div></td><td>${esc(o.buyer_username||'—')}</td><td><span class="pill ${o.status==='paid'?'good':''}">${esc(o.status||'—')}</span></td><td>${esc(o.date||'—')}</td><td class="price">${Number(o.price||0).toLocaleString('ru-RU',{maximumFractionDigits:2})} ${esc(o.currency||'RUB')}</td></tr>`).join('')}</tbody></table></div>`}catch(e){$('#orders-table').innerHTML=`<div class="empty-state"><strong>Не удалось загрузить заказы</strong><p>${esc(e.message)}</p></div>`;toast(e.message,'error')}}
$('#fp-connect-form').addEventListener('submit',async e=>{e.preventDefault();const btn=$('#fp-connect-btn');btn.disabled=true;btn.textContent='Подключение…';$('#fp-connect-result').innerHTML='';try{const {data}=await api('/api/funpay/connect',{method:'POST',body:{golden_key:$('#fp-golden-key').value.trim(),user_agent:($('#fp-user-agent').value.trim()||defaultUserAgent)}});$('#fp-golden-key').value='';state.profile=data.profile||null;updateConnection(true,data.profile?.username||'');localStorage.setItem('fpal.user-agent',$('#fp-user-agent').value.trim()||defaultUserAgent);$('#fp-connect-result').innerHTML='<div class="notice">Аккаунт подключён. Сессионный ключ не сохраняется в файлы, но остаётся в памяти процесса до отключения или перезапуска.</div>';await loadCategories();await loadDashboardData();toast('FunPay подключён','ok')}catch(err){$('#fp-connect-result').innerHTML=`<div class="notice" style="border-color:#ff71884a;color:#ff9aa9">${esc(err.message)}</div>`;toast(err.message,'error')}finally{btn.disabled=false;btn.textContent='Подключить аккаунт'}});
$('#fp-disconnect').addEventListener('click',async()=>{try{await api('/api/funpay/disconnect',{method:'POST'});state.categories=[];state.subcats.clear();state.chats=[];state.orders=[];updateConnection(false);populateAllCategorySelects();$('#stat-balance').textContent='—';$('#stat-offers').textContent='—';$('#stat-chats').textContent='—';$('#stat-orders').textContent='—';toast('Аккаунт отключён','ok')}catch(e){toast(e.message,'error')}});
$$('[data-page]').forEach(btn=>btn.addEventListener('click',()=>setPage(btn.dataset.page)));document.addEventListener('click',e=>{const go=e.target.closest('[data-go]');if(go){setPage(go.dataset.go);return}const ce=e.target.closest('[data-chat-id]');if(ce){if(state.page!=='chats')setPage('chats');openChat(ce.dataset.chatId);return}const edit=e.target.closest('[data-lot-edit]');if(edit)openEdit(edit.dataset.lotEdit);const del=e.target.closest('[data-lot-delete]');if(del)deleteMyLot(del.dataset.lotDelete)});

let catalogSearchTimer=null;let catalogSearchAbort=null;
async function runCatalogSearch(){const input=$('#catalog-search');const target=$('#catalog-results');if(!input||!target)return;const q=input.value.trim();if(!state.connected){target.innerHTML='<div class="catalog-result" style="pointer-events:none"><span class="catalog-result-ico">!</span><span class="catalog-result-main"><span class="catalog-result-name">Сначала подключите FunPay</span><span class="catalog-result-path">Откройте Настройки и подключите сессию</span></span></div>';return}if(catalogSearchAbort)catalogSearchAbort.abort();catalogSearchAbort=new AbortController();target.innerHTML='<div class="catalog-result" style="pointer-events:none"><span class="catalog-result-ico">···</span><span class="catalog-result-main"><span class="catalog-result-name">Ищем в каталоге FunPay…</span><span class="catalog-result-path">Реальные категории и разделы</span></span></div>';try{const {data}=await api('/api/funpay/catalog/search?q='+encodeURIComponent(q),{signal:catalogSearchAbort.signal});state.catalogResults=data||[];if(!state.catalogResults.length){target.innerHTML='<div class="catalog-result" style="pointer-events:none"><span class="catalog-result-ico">⌕</span><span class="catalog-result-main"><span class="catalog-result-name">Ничего не найдено</span><span class="catalog-result-path">Попробуйте другое слово или одну букву</span></span></div>';return}target.innerHTML=state.catalogResults.map((x,i)=>`<button type="button" class="catalog-result" data-catalog-index="${i}"><span class="catalog-result-ico">${x.type==='category'?'G':'↳'}</span><span class="catalog-result-main"><span class="catalog-result-name">${esc(x.name)}</span><span class="catalog-result-path">${x.type==='category'?'Категория':esc(x.category_name)+' · раздел'}</span></span><span class="catalog-result-arrow">›</span></button>`).join('')}catch(e){if(e.name==='AbortError')return;target.innerHTML=`<div class="catalog-result"><span class="catalog-result-ico">!</span><span class="catalog-result-main"><span class="catalog-result-name">Поиск недоступен</span><span class="catalog-result-path">${esc(e.message)}</span></span></div>`}}
$('#catalog-search')?.addEventListener('input',()=>{clearTimeout(catalogSearchTimer);catalogSearchTimer=setTimeout(runCatalogSearch,170)});
$('#catalog-results')?.addEventListener('click',async e=>{const button=e.target.closest('[data-catalog-index]');if(!button)return;const item=state.catalogResults[Number(button.dataset.catalogIndex)];if(!item)return;$('#game-select').value=String(item.category_id);await fillSubcategories('#game-select','#subcategory-select');if(item.subcategory_id!==null&&item.subcategory_id!==undefined){$('#subcategory-select').value=String(item.subcategory_id)}persistCategory();updatePreview();$('#catalog-search').value=item.type==='subcategory'?`${item.category_name} / ${item.name}`:item.name;$('#catalog-results').innerHTML=`<div class="catalog-result" style="pointer-events:none"><span class="catalog-result-ico">✓</span><span class="catalog-result-main"><span class="catalog-result-name">${esc(item.name)} выбрано</span><span class="catalog-result-path">Категория запомнена для следующих запусков</span></span></div>`;toast('Категория выбрана','ok',1800)});
$('#game-select').addEventListener('change',()=>{localStorage.setItem('fpal.category.game',$('#game-select').value);localStorage.removeItem('fpal.category.sub');fillSubcategories('#game-select','#subcategory-select').then(()=>{persistCategory();updatePreview()})});$('#search-game').addEventListener('change',()=>fillSubcategories('#search-game','#search-subcategory'));$('#lots-game').addEventListener('change',()=>fillSubcategories('#lots-game','#lots-subcategory').then(loadMyLots));$('#subcategory-select').addEventListener('change',()=>{persistCategory();updatePreview()});['#lot-title','#lot-description','#lot-price','#lot-amount'].forEach(id=>$(id).addEventListener('input',updatePreview));
$$('[data-mode]').forEach(btn=>btn.addEventListener('click',()=>{state.mode=btn.dataset.mode;$$('[data-mode]').forEach(b=>b.classList.toggle('active',b===btn));$$('.sell-only').forEach(el=>el.classList.toggle('hidden',state.mode!=='sell'));$$('.buy-only').forEach(el=>el.classList.toggle('hidden',state.mode!=='buy'));$('#lister-submit').querySelector('span').textContent=state.mode==='sell'?'Создать оффер':'Найти офферы';$('#preview-title').textContent=state.mode==='sell'?'Ваш оффер':'Поиск предложений';}));$('#lister-submit').addEventListener('click',listerSubmit);$('#lister-reset').addEventListener('click',()=>{$('#lot-title').value='';$('#lot-description').value='';$('#lot-price').value='';$('#lot-amount').value='1';$('#offer-query').value='';updatePreview()});$('#search-run').addEventListener('click',()=>runOfferSearch('search'));$('#search-query').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();runOfferSearch('search')}});$('#offer-query').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();runOfferSearch('lister')}});$('#search-clear').addEventListener('click',()=>{$('#search-query').value='';$('#search-table').innerHTML='<div class="empty-state"><strong>Задайте параметры поиска</strong><p>Выберите игру и раздел — результаты появятся здесь.</p></div>'});$('#lots-refresh').addEventListener('click',loadMyLots);$('#raise-selected').addEventListener('click',raiseSelected);$('#lot-check-all')?.addEventListener('change',e=>$$('.lot-check').forEach(ch=>{ch.checked=e.target.checked;const id=Number(ch.dataset.id);e.target.checked?state.selectedLots.add(id):state.selectedLots.delete(id)}));$('#my-lots-table').addEventListener('change',e=>{if(e.target.classList.contains('lot-check')){const id=Number(e.target.dataset.id);e.target.checked?state.selectedLots.add(id):state.selectedLots.delete(id)}});$('#chats-refresh').addEventListener('click',loadChats);$('#chat-filter').addEventListener('input',renderChats);$('#orders-refresh').addEventListener('click',loadOrders);$('#refresh-btn').addEventListener('click',async()=>{sound('click');if(state.connected){await refreshConnectionStatus();await loadDashboardData();if(state.page==='chats')loadChats();if(state.page==='orders')loadOrders();if(state.page==='listings')loadMyLots()}else toast('Подключите аккаунт FunPay в настройках.','warn')});$('#menu-toggle').addEventListener('click',()=>{$('#sidebar').classList.toggle('open');$('#scrim').classList.toggle('show')});$('#scrim').addEventListener('click',()=>{$('#sidebar').classList.remove('open');$('#scrim').classList.remove('show')});$('#edit-close').addEventListener('click',closeEdit);$('#edit-cancel').addEventListener('click',closeEdit);$('#edit-modal').addEventListener('click',e=>{if(e.target.id==='edit-modal')closeEdit()});$('#logout-btn').addEventListener('click',logout);
function setSound(value){soundEnabled=value;localStorage.setItem('fpal.sound',value?'on':'off');$('#sound-toggle').checked=value;$('#sound-btn').style.color=value?'#c5b4ff':'#77778b';if(value)sound('ok')}$('#sound-toggle').addEventListener('change',e=>setSound(e.target.checked));$('#sound-btn').addEventListener('click',()=>setSound(!soundEnabled));$('#auto-refresh-toggle').addEventListener('change',e=>{autoRefresh=e.target.checked;localStorage.setItem('fpal.refresh',autoRefresh?'on':'off');toast(autoRefresh?'Автообновление включено':'Автообновление выключено','info')});
$('#my-lots-table').addEventListener('click',e=>{const all=e.target.closest('#lot-check-all');if(all)$$('.lot-check').forEach(ch=>{ch.checked=all.checked;const id=Number(ch.dataset.id);all.checked?state.selectedLots.add(id):state.selectedLots.delete(id)})});
async function refreshTick(){if(!state.session||!autoRefresh||document.hidden)return;try{if(state.connected){const {data}=await api('/api/funpay/chats');const oldUnread=state.chats.reduce((n,c)=>n+Number(c.unread_count||0),0);state.chats=data;const unread=data.reduce((n,c)=>n+Number(c.unread_count||0),0);$('#chats-badge').textContent=unread||'0';if(unread>oldUnread){toast('Появилось новое непрочитанное сообщение','info');}if(state.page==='chats')renderChats();renderDashboardChats();}}catch{}}
setInterval(refreshTick,45000);$('#sidebar').addEventListener('click',e=>{const b=e.target.closest('.nav-item');if(b)sound('click')});
document.addEventListener('keydown',e=>{const tag=document.activeElement?.tagName;if(e.key==='Escape'){$('#sidebar').classList.remove('open');$('#scrim').classList.remove('show');closeEdit()}if(e.key.toLowerCase()==='f'&&!e.ctrlKey&&!e.metaKey&&!e.altKey&&!['INPUT','TEXTAREA','SELECT'].includes(tag)){e.preventDefault();toggleFs()}});
// Telegram Mini App fullscreen first; browser fullscreen is only a fallback outside Telegram.
const fsBtn=$('#fs');const tgApp=window.Telegram&&window.Telegram.WebApp;
const telegramFs=()=>!!(tgApp&&typeof tgApp.requestFullscreen==='function'&&typeof tgApp.isVersionAtLeast==='function'&&tgApp.isVersionAtLeast('8.0'));
const isFs=()=>telegramFs()?!!tgApp.isFullscreen:!!(document.fullscreenElement||document.webkitFullscreenElement||document.msFullscreenElement);
async function toggleFs(){
 try{
  if(telegramFs()){
   if(tgApp.isFullscreen&&typeof tgApp.exitFullscreen==='function')tgApp.exitFullscreen();
   else tgApp.requestFullscreen();
   return;
  }
  if(tgApp&&typeof tgApp.expand==='function'){tgApp.expand();return;}
  if(document.fullscreenElement){if(document.exitFullscreen)await document.exitFullscreen();return;}
  const el=document.documentElement;
  if(el.requestFullscreen)await el.requestFullscreen();else if(el.webkitRequestFullscreen)el.webkitRequestFullscreen();else throw new Error('Полноэкранный режим недоступен в этом браузере');
 }catch(e){console.warn('Fullscreen request failed:',e);if(tgApp&&tgApp.expand)tgApp.expand();}
}
function syncFullscreenButton(){fsBtn.textContent=isFs()?'✕':'⛶';document.body.classList.toggle('is-fs',isFs());}
fsBtn.addEventListener('click',toggleFs);
['fullscreenchange','webkitfullscreenchange','msfullscreenchange'].forEach(ev=>document.addEventListener(ev,syncFullscreenButton));
if(tgApp&&typeof tgApp.onEvent==='function'){
 try{tgApp.onEvent('fullscreenChanged',syncFullscreenButton);tgApp.onEvent('fullscreenFailed',()=>{syncFullscreenButton();console.warn('Telegram declined fullscreen request')});}catch{}
}
async function init(){const tg=window.Telegram&&window.Telegram.WebApp;if(tg){try{tg.ready();tg.expand();if(typeof tg.setHeaderColor==='function')tg.setHeaderColor('#101018');if(typeof tg.setBackgroundColor==='function')tg.setBackgroundColor('#0c0c13');if(typeof tg.disableVerticalSwipes==='function')tg.disableVerticalSwipes();if(typeof tg.requestFullscreen==='function'&&typeof tg.isVersionAtLeast==='function'&&tg.isVersionAtLeast('8.0')&&!tg.isFullscreen)tg.requestFullscreen();}catch{}}if(state.session){$('#login-view').classList.add('hidden');$('#app').classList.remove('hidden');try{await bootApp()}catch(e){if(!e.message.includes('Сессия'))toast(e.message,'error')}}syncFullscreenButton();if(tg?.initData&&Number(tg.initDataUnsafe?.user?.id)===8357023784){setTimeout(()=>{if($('#login-view').classList.contains('hidden'))return;performLogin()},0)}}init();
// Block browser pinch/double-tap zoom while preserving scrolling inside the app.
document.addEventListener('gesturestart',e=>e.preventDefault(),{passive:false});document.addEventListener('gesturechange',e=>e.preventDefault(),{passive:false});document.addEventListener('wheel',e=>{if(e.ctrlKey)e.preventDefault()},{passive:false});let lastTouchEnd=0;document.addEventListener('touchend',e=>{const now=Date.now();if(now-lastTouchEnd<=280)e.preventDefault();lastTouchEnd=now},{passive:false});
})();
</script>
</body></html>'''

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info", proxy_headers=True, forwarded_allow_ips="*")
