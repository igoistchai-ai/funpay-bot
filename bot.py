"""
bot.py — Telegram Tasks: Telegram-бот, веб-дашборд и API в одном файле.
Запуск:
    pip install "python-telegram-bot>=21" fastapi "uvicorn[standard]" aiosqlite python-dotenv
    echo "TELEGRAM_BOT_TOKEN=123:abc" > .env
    python bot.py
Переменные окружения:
    TELEGRAM_BOT_TOKEN  — токен бота (обязательно)
    PORT                — порт HTTP-сервера (по умолчанию 8000)
    WEBHOOK_SECRET      — секрет для заголовка X-Telegram-Bot-Api-Secret-Token (опционально)
    RENDER_EXTERNAL_URL — публичный URL; если задан, бот работает через webhook, иначе через polling
"""
import asyncio
import csv
import html
import io
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional
import aiosqlite
from dotenv import load_dotenv
from fastapi import (
    APIRouter,
    Body,
    FastAPI,
    HTTPException,
    Query,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from telegram import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    MenuButtonWebApp,
    Update,
    WebAppInfo,
)
from telegram.error import BadRequest
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    filters,
)
load_dotenv()
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
if not TOKEN:
    raise SystemExit("Не задан TELEGRAM_BOT_TOKEN. Укажите его в .env или в переменных окружения.")
PORT = int(os.getenv("PORT", "8000"))
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "").strip() or None
RENDER_URL = os.getenv("RENDER_EXTERNAL_URL", "").strip().rstrip("/")
WEBHOOK_URL = f"{RENDER_URL}/telegram/webhook" if RENDER_URL else None
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger("tasks")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
def resolve_db_path() -> str:
    """Выбирает путь к БД: DB_PATH из окружения, иначе рядом с bot.py, иначе /tmp.
    Создаёт папку, если её нет, и пропускает путь, куда нет прав на запись.
    """
    env_path = os.getenv("DB_PATH", "").strip()
    candidates = [p for p in (env_path, os.path.join(BASE_DIR, "bot.sqlite3"), os.path.join("/tmp", "bot.sqlite3")) if p]
    for path in candidates:
        folder = os.path.dirname(os.path.abspath(path))
        try:
            os.makedirs(folder, exist_ok=True)
            if os.access(folder, os.W_OK):
                return path
            log.warning("Нет прав на запись в папку %s", folder)
        except OSError as exc:
            log.warning("Путь БД недоступен %s: %s", path, exc)
    raise SystemExit("Не удалось найти папку для базы данных.")
DB_PATH = resolve_db_path()
START_PHOTO_URL = os.getenv("START_PHOTO_URL", "").strip()
APP_VERSION = "1.0.0"
START_TIME = time.monotonic()
BRAND = "TELEGRAM TASKS"
STATE: dict[str, Any] = {"bot_username": None, "bot_ready": False}
def now_iso() -> str:
    """Текущее время в UTC, ISO 8601."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
def dash_url() -> str:
    """Адрес дашборда: публичный, если задан, иначе локальный."""
    return RENDER_URL or f"http://127.0.0.1:{PORT}"
def load_start_photo() -> Any:
    """Картинка для /start: URL из START_PHOTO_URL или файл start.jpg/png/webp рядом с bot.py."""
    if START_PHOTO_URL:
        return START_PHOTO_URL
    for name in ("start.jpg", "start.png", "start.webp"):
        path = os.path.join(BASE_DIR, name)
        if os.path.isfile(path):
            with open(path, "rb") as fh:
                return fh.read()
    return None
START_PHOTO = load_start_photo()
def esc(value: Any) -> str:
    """Экранирование для parse_mode=HTML."""
    return html.escape(str(value), quote=False)
Status = Literal["todo", "in_progress", "done"]
Priority = Literal["low", "normal", "high"]
SortField = Literal["id", "title", "status", "priority", "created_at", "updated_at"]
STATUSES = ("todo", "in_progress", "done")
PRIORITIES = ("low", "normal", "high")
STATUS_LABEL = {"todo": "К выполнению", "in_progress": "В работе", "done": "Готово"}
PRIO_LABEL = {"low": "Низкий", "normal": "Обычный", "high": "Высокий"}
STATUS_ICON = {"todo": "⬜", "in_progress": "🔄", "done": "✅"}
PRIO_ICON = {"low": "🔹", "normal": "🔸", "high": "🔥"}
class TaskBase(BaseModel):
    """Общие поля задачи."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="ignore")
    title: str = Field(..., min_length=1, max_length=200)
    body: str = Field(default="", max_length=5000)
    status: Status = "todo"
    priority: Priority = "normal"
    telegram_id: Optional[int] = None
class TaskCreate(TaskBase):
    """Создание задачи."""
class TaskUpdate(TaskBase):
    """PUT: полная замена всех полей."""
class TaskPatch(BaseModel):
    """PATCH: частичное обновление, неизвестные поля запрещены."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    title: Optional[str] = Field(default=None, min_length=1, max_length=200)
    body: Optional[str] = Field(default=None, max_length=5000)
    status: Optional[Status] = None
    priority: Optional[Priority] = None
    telegram_id: Optional[int] = None
class Task(TaskBase):
    """Задача, как её отдаёт API."""
    id: int
    created_at: str
    updated_at: str
class BulkItem(BaseModel):
    """Одна операция пакетного запроса."""
    op: Literal["create", "patch", "delete"]
    id: Optional[int] = None
    data: dict[str, Any] = Field(default_factory=dict)
class BulkResult(BaseModel):
    """Результат одной операции пакета."""
    index: int
    ok: bool
    op: str
    id: Optional[int] = None
    task: Optional[Task] = None
    error: Optional[str] = None
class Stats(BaseModel):
    """Агрегированная статистика."""
    total: int
    by_status: dict[str, int]
    by_priority: dict[str, int]
    created_last_24h: int
class Health(BaseModel):
    """Состояние сервиса."""
    status: str
    version: str
    uptime_seconds: int
    bot_username: Optional[str]
    webhook: bool
SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_id INTEGER,
    title       TEXT    NOT NULL,
    body        TEXT    NOT NULL DEFAULT '',
    status      TEXT    NOT NULL DEFAULT 'todo'
                CHECK (status IN ('todo', 'in_progress', 'done')),
    priority    TEXT    NOT NULL DEFAULT 'normal'
                CHECK (priority IN ('low', 'normal', 'high')),
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_tg ON tasks (telegram_id);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks (status);
"""
SEED = [
    ("Настроить CI/CD", "GitHub Actions: тесты и деплой на Render", "in_progress", "high"),
    ("Обновить README", "Добавить раздел про переменные окружения", "todo", "low"),
    ("Ревью PR #42", "Проверить миграции и индексы", "todo", "high"),
    ("Написать тесты для API", "pytest + httpx AsyncClient", "todo", "normal"),
    ("Выбрать дизайн лендинга", "Три варианта в Figma", "done", "normal"),
    ("Созвон с командой", "Обсудить roadmap на Q4", "done", "high"),
    ("Оплатить хостинг", "Продление до конца месяца", "todo", "high"),
    ("Почистить старые ветки", "git branch --merged", "todo", "low"),
    ("Исследовать WebSocket reconnect", "Экспоненциальный backoff и jitter", "in_progress", "normal"),
    ("Добавить экспорт CSV", "Кодировка UTF-8 с BOM для Excel", "done", "normal"),
    ("Сделать бэкап БД", "Копия bot.sqlite3 раз в сутки", "todo", "normal"),
    ("Перевести тексты на русский", "Интерфейс и сообщения бота", "done", "low"),
    ("Исправить прокрутку таблицы", "Sticky header и zebra", "in_progress", "normal"),
    ("Подготовить релиз 1.0", "Changelog и теги", "todo", "high"),
    ("Проверить адаптив", "Телефон 360px и планшет", "todo", "normal"),
    ("Настроить уведомления", "Telegram при удалении задачи", "done", "normal"),
    ("Написать документацию API", "OpenAPI и примеры curl", "todo", "normal"),
    ("Ускорить запросы", "Индексы по telegram_id и status", "in_progress", "high"),
    ("Купить домен", "Проверить доступность и SSL", "todo", "low"),
    ("Записать демо-видео", "Два кадра: бот и дашборд", "todo", "normal"),
    ("Аудит безопасности", "Проверить секрет вебхука", "todo", "high"),
    ("Обновить зависимости", "python-telegram-bot и FastAPI", "todo", "normal"),
    ("Тестирование тем", "Светлая и тёмная схемы", "done", "low"),
    ("Добавить хоткеи", "Клавиши / n f Esc", "done", "low"),
    ("Собрать обратную связь", "Опрос пользователей бота", "todo", "normal"),
]
ALLOWED_FIELDS = {"title", "body", "status", "priority", "telegram_id"}
SORT_EXPR = {
    "id": "id",
    "title": "LOWER(title)",
    "status": "CASE status WHEN 'todo' THEN 1 WHEN 'in_progress' THEN 2 ELSE 3 END",
    "priority": "CASE priority WHEN 'low' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END",
    "created_at": "created_at",
    "updated_at": "updated_at",
}
_db: Optional[aiosqlite.Connection] = None
_write_lock = asyncio.Lock()
async def db() -> aiosqlite.Connection:
    """Единое соединение с БД."""
    if _db is None:
        raise RuntimeError("БД не инициализирована")
    return _db
def row_to_task(row: aiosqlite.Row) -> Task:
    """Строка SQLite → модель Task."""
    return Task(
        id=row["id"],
        telegram_id=row["telegram_id"],
        title=row["title"],
        body=row["body"],
        status=row["status"],
        priority=row["priority"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )
async def seed_tasks() -> None:
    """Заполняет БД 25 демо-задачами при первом запуске."""
    conn = await db()
    base = datetime.now(timezone.utc)
    for i, (title, body, status, priority) in enumerate(SEED, start=1):
        ts = (base - timedelta(hours=i * 3)).isoformat(timespec="seconds")
        await conn.execute(
            "INSERT INTO tasks (telegram_id, title, body, status, priority, created_at, updated_at) "
            "VALUES (NULL, ?, ?, ?, ?, ?, ?)",
            (title, body, status, priority, ts, ts),
        )
    await conn.commit()
    log.info("Добавлено демо-задач: %d", len(SEED))
async def db_init() -> None:
    """Открывает БД, создаёт схему и при необходимости заполняет демо-данными."""
    global _db
    _db = await aiosqlite.connect(DB_PATH)
    _db.row_factory = aiosqlite.Row
    await _db.execute("PRAGMA journal_mode=WAL")
    await _db.execute("PRAGMA foreign_keys=ON")
    await _db.executescript(SCHEMA)
    await _db.commit()
    async with _db.execute("SELECT COUNT(*) AS c FROM tasks") as cur:
        row = await cur.fetchone()
    if row["c"] == 0:
        await seed_tasks()
    log.info("БД готова: %s", DB_PATH)
async def close_db() -> None:
    """Закрывает соединение с БД."""
    global _db
    if _db is not None:
        await _db.close()
        _db = None
async def get_task(task_id: int) -> Optional[Task]:
    """Задача по id или None."""
    conn = await db()
    async with conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)) as cur:
        row = await cur.fetchone()
    return row_to_task(row) if row else None
async def query_tasks(
    *,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    q: Optional[str] = None,
    telegram_id: Optional[int] = None,
    sort: str = "updated_at",
    order: str = "desc",
    skip: int = 0,
    limit: int = 50,
) -> tuple[list[Task], int]:
    """Список задач с фильтрами, сортировкой и пагинацией. Возвращает (строки, total)."""
    conn = await db()
    where: list[str] = []
    params: list[Any] = []
    if status:
        where.append("status = ?")
        params.append(status)
    if priority:
        where.append("priority = ?")
        params.append(priority)
    if telegram_id is not None:
        where.append("telegram_id = ?")
        params.append(telegram_id)
    if q:
        like = f"%{q.lower()}%"
        where.append("(LOWER(title) LIKE ? OR LOWER(body) LIKE ?)")
        params.extend([like, like])
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    col = SORT_EXPR.get(sort, "updated_at")
    direction = "ASC" if order == "asc" else "DESC"
    async with conn.execute(f"SELECT COUNT(*) AS c FROM tasks{clause}", params) as cur:
        total = (await cur.fetchone())["c"]
    async with conn.execute(
        f"SELECT * FROM tasks{clause} ORDER BY {col} {direction}, id {direction} LIMIT ? OFFSET ?",
        [*params, limit, skip],
    ) as cur:
        rows = await cur.fetchall()
    return [row_to_task(r) for r in rows], total
async def create_task(data: TaskCreate) -> Task:
    """Создаёт задачу и возвращает её."""
    conn = await db()
    ts = now_iso()
    async with _write_lock:
        cur = await conn.execute(
            "INSERT INTO tasks (telegram_id, title, body, status, priority, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (data.telegram_id, data.title, data.body, data.status, data.priority, ts, ts),
        )
        new_id = cur.lastrowid
        await conn.commit()
    return await get_task(new_id)
async def update_task(task_id: int, values: dict[str, Any]) -> Optional[Task]:
    """Обновляет разрешённые поля задачи. None, если задачи нет."""
    conn = await db()
    if await get_task(task_id) is None:
        return None
    fields = {k: v for k, v in values.items() if k in ALLOWED_FIELDS}
    if not fields:
        return await get_task(task_id)
    fields["updated_at"] = now_iso()
    sets = ", ".join(f"{k} = ?" for k in fields)
    async with _write_lock:
        await conn.execute(f"UPDATE tasks SET {sets} WHERE id = ?", [*fields.values(), task_id])
        await conn.commit()
    return await get_task(task_id)
async def delete_task(task_id: int) -> Optional[Task]:
    """Удаляет задачу и возвращает удалённую запись или None."""
    existing = await get_task(task_id)
    if existing is None:
        return None
    conn = await db()
    async with _write_lock:
        await conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
        await conn.commit()
    return existing
async def task_stats() -> dict[str, Any]:
    """Статистика для дашборда и бота."""
    conn = await db()
    async with conn.execute("SELECT COUNT(*) AS c FROM tasks") as cur:
        total = (await cur.fetchone())["c"]
    by_status = {s: 0 for s in STATUSES}
    async with conn.execute("SELECT status, COUNT(*) AS c FROM tasks GROUP BY status") as cur:
        async for r in cur:
            by_status[r["status"]] = r["c"]
    by_priority = {p: 0 for p in PRIORITIES}
    async with conn.execute("SELECT priority, COUNT(*) AS c FROM tasks GROUP BY priority") as cur:
        async for r in cur:
            by_priority[r["priority"]] = r["c"]
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(timespec="seconds")
    async with conn.execute("SELECT COUNT(*) AS c FROM tasks WHERE created_at >= ?", (since,)) as cur:
        recent = (await cur.fetchone())["c"]
    return {
        "total": total,
        "by_status": by_status,
        "by_priority": by_priority,
        "created_last_24h": recent,
    }
class WSManager:
    """Набор активных WebSocket-клиентов и рассылка событий."""
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()
    @property
    def count(self) -> int:
        return len(self._clients)
    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._clients.add(ws)
    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(ws)
    async def broadcast(self, event: str, payload: Any) -> None:
        """Рассылает событие всем клиентам; мёртвые соединения удаляются."""
        message = json.dumps({"event": event, "data": payload, "ts": now_iso()}, default=str)
        async with self._lock:
            targets = list(self._clients)
        dead: list[WebSocket] = []
        for ws in targets:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self._clients.discard(ws)
            log.info("WS: удалено мёртвых клиентов: %d", len(dead))
WS = WSManager()
TG_APP: Application = Application.builder().token(TOKEN).build()
ASK_TITLE, ASK_BODY, ASK_PRIORITY, ASK_STATUS = range(4)
def fmt_task_card(task: Task) -> str:
    """Текст карточки задачи в HTML."""
    lines = [
        f"<b>#{task.id} · {esc(task.title)}</b>",
        f"{STATUS_ICON[task.status]} {STATUS_LABEL[task.status]} · "
        f"{PRIO_ICON[task.priority]} {PRIO_LABEL[task.priority]}",
    ]
    if task.body:
        lines.append("")
        lines.append(esc(task.body))
    return "\n".join(lines)
def card_kb(task: Task) -> InlineKeyboardMarkup:
    """Кнопки под карточкой задачи."""
    rows = []
    if task.status != "done":
        rows.append([InlineKeyboardButton("✅ Готово", callback_data=f"task:done:{task.id}")])
    rows.append([InlineKeyboardButton("🗑 Удалить", callback_data=f"task:del:{task.id}")])
    rows.append([InlineKeyboardButton("⬅ К списку", callback_data="menu:list")])
    return InlineKeyboardMarkup(rows)
def back_kb() -> InlineKeyboardMarkup:
    """Кнопка возврата к списку."""
    return InlineKeyboardMarkup([[InlineKeyboardButton("⬅ К списку", callback_data="menu:list")]])
def app_url() -> str:
    """Публичный адрес веб-приложения."""
    return dash_url() + "/"
def main_menu_kb() -> InlineKeyboardMarkup:
    """Кнопка открытия Web App (внутри Telegram) и быстрые действия бота."""
    if app_url().startswith("https://"):
        open_btn = InlineKeyboardButton("🚀 Открыть приложение", web_app=WebAppInfo(url=app_url()))
    else:
        open_btn = InlineKeyboardButton("🌐 Открыть приложение", callback_data="menu:dash")
    return InlineKeyboardMarkup([
        [open_btn],
        [
            InlineKeyboardButton("📋 Мои задачи", callback_data="menu:list"),
            InlineKeyboardButton("➕ Новая задача", callback_data="menu:new"),
        ],
        [InlineKeyboardButton("📊 Статистика", callback_data="menu:stats")],
    ])
async def safe_edit(query: Any, text: str, kb: Optional[InlineKeyboardMarkup] = None) -> None:
    """Редактирует сообщение, игнорируя «message is not modified»."""
    try:
        await query.edit_message_text(text, parse_mode="HTML", reply_markup=kb)
    except BadRequest as exc:
        if "not modified" not in str(exc).lower():
            raise
async def notify_owner(telegram_id: Optional[int], text: str) -> None:
    """Уведомляет владельца задачи в Telegram, если он известен."""
    if not telegram_id or not STATE["bot_ready"]:
        return
    try:
        await TG_APP.bot.send_message(chat_id=telegram_id, text=text, parse_mode="HTML")
    except Exception as exc:
        log.warning("Не удалось уведомить %s: %s", telegram_id, exc)
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/start — картинка с кнопкой открытия веб-приложения."""
    user = update.effective_user
    name = esc(user.first_name if user else "друг")
    caption = (
        f"👋 Привет, <b>{name}</b>!\n\n"
        f"<b>{BRAND}</b> — задачи в Telegram и веб-приложение с живыми обновлениями.\n\n"
        "Нажмите «Открыть приложение»."
    )
    msg = update.effective_message
    if START_PHOTO:
        try:
            await msg.reply_photo(photo=START_PHOTO, caption=caption, parse_mode="HTML", reply_markup=main_menu_kb())
            return
        except BadRequest as exc:
            log.warning("Не удалось отправить стартовое фото: %s", exc)
    await msg.reply_text(caption, parse_mode="HTML", reply_markup=main_menu_kb())
async def send_list(update: Update) -> None:
    """Последние 10 задач пользователя кнопками."""
    user_id = update.effective_user.id
    tasks, total = await query_tasks(telegram_id=user_id, sort="updated_at", order="desc", limit=10)
    msg = update.effective_message
    if not tasks:
        await msg.reply_text("📭 У вас пока нет задач. Нажмите /new, чтобы создать первую.")
        return
    rows = [
        [InlineKeyboardButton(f"{STATUS_ICON[t.status]} #{t.id} {t.title[:32]}", callback_data=f"task:open:{t.id}")]
        for t in tasks
    ]
    rows.append([InlineKeyboardButton("➕ Новая задача", callback_data="menu:new")])
    await msg.reply_text(
        f"📋 Ваши последние задачи ({len(tasks)} из {total}):",
        reply_markup=InlineKeyboardMarkup(rows),
    )
async def cmd_list(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/list — список задач."""
    await send_list(update)
async def send_stats(update: Update) -> None:
    """Статистика по статусам и приоритетам."""
    s = await task_stats()
    lines = [
        "📊 <b>Статистика</b>",
        "",
        f"Всего задач: <b>{s['total']}</b>",
        f"Создано за 24 часа: <b>{s['created_last_24h']}</b>",
        "",
        "<b>По статусам:</b>",
    ]
    lines += [f"{STATUS_ICON[k]} {STATUS_LABEL[k]}: {v}" for k, v in s["by_status"].items()]
    lines += ["", "<b>По приоритету:</b>"]
    lines += [f"{PRIO_ICON[k]} {PRIO_LABEL[k]}: {v}" for k, v in s["by_priority"].items()]
    await update.effective_message.reply_text("\n".join(lines), parse_mode="HTML")
async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/stats — статистика."""
    await send_stats(update)
async def on_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обработка кнопок главного меню (list, stats, dash)."""
    q = update.callback_query
    await q.answer()
    action = q.data.split(":")[1]
    if action == "list":
        await send_list(update)
    elif action == "stats":
        await send_stats(update)
    elif action == "dash":
        await update.effective_message.reply_text(f"🌐 Дашборд: {dash_url()}/")
async def on_task_action(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Кнопки task:open / task:done / task:del."""
    q = update.callback_query
    _, action, raw_id = q.data.split(":")
    task_id = int(raw_id)
    user_id = update.effective_user.id
    task = await get_task(task_id)
    if task is None or task.telegram_id not in (None, user_id):
        await q.answer("Задача не найдена", show_alert=True)
        return
    if action == "open":
        await q.answer()
        await safe_edit(q, fmt_task_card(task), card_kb(task))
    elif action == "done":
        if task.status == "done":
            await q.answer("Уже готово")
            return
        updated = await update_task(task_id, {"status": "done"})
        await WS.broadcast("task.updated", updated.model_dump())
        await q.answer("Готово ✅")
        await safe_edit(q, fmt_task_card(updated), card_kb(updated))
    elif action == "del":
        removed = await delete_task(task_id)
        if removed is not None:
            await WS.broadcast("task.deleted", {"id": removed.id, "telegram_id": removed.telegram_id})
        await q.answer("Удалено")
        await safe_edit(q, f"🗑 Задача #{task_id} удалена.", back_kb())
async def new_entry(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Старт диалога создания задачи."""
    context.user_data["draft"] = {}
    if update.callback_query:
        await update.callback_query.answer()
    await update.effective_message.reply_text(
        "✏️ Введите <b>название</b> задачи (до 200 символов).\n/cancel — отмена.",
        parse_mode="HTML",
    )
    return ASK_TITLE
async def new_title(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Шаг 1: название."""
    title = (update.effective_message.text or "").strip()
    if not title:
        await update.effective_message.reply_text("Название не может быть пустым. Попробуйте ещё раз.")
        return ASK_TITLE
    if len(title) > 200:
        await update.effective_message.reply_text("Слишком длинно — максимум 200 символов.")
        return ASK_TITLE
    context.user_data["draft"] = {"title": title}
    await update.effective_message.reply_text("📝 Добавьте описание или отправьте /skip.")
    return ASK_BODY
async def _ask_priority(update: Update) -> int:
    kb = InlineKeyboardMarkup([[
        InlineKeyboardButton("🔹 Низкий", callback_data="prio:low"),
        InlineKeyboardButton("🔸 Обычный", callback_data="prio:normal"),
        InlineKeyboardButton("🔥 Высокий", callback_data="prio:high"),
    ]])
    await update.effective_message.reply_text("Выберите приоритет:", reply_markup=kb)
    return ASK_PRIORITY
async def new_body(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Шаг 2: описание."""
    body = (update.effective_message.text or "").strip()
    if len(body) > 5000:
        await update.effective_message.reply_text("Слишком длинное описание — максимум 5000 символов.")
        return ASK_BODY
    context.user_data.setdefault("draft", {})["body"] = body
    return await _ask_priority(update)
async def new_body_skip(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """/skip — пропустить описание."""
    context.user_data.setdefault("draft", {})["body"] = ""
    return await _ask_priority(update)
async def prio_chosen(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Шаг 3: приоритет."""
    q = update.callback_query
    await q.answer()
    priority = q.data.split(":")[1]
    context.user_data.setdefault("draft", {})["priority"] = priority
    await q.edit_message_text(f"Приоритет: {PRIO_ICON[priority]} {PRIO_LABEL[priority]}")
    kb = InlineKeyboardMarkup([[
        InlineKeyboardButton("⬜ К выполнению", callback_data="st:todo"),
        InlineKeyboardButton("🔄 В работе", callback_data="st:in_progress"),
        InlineKeyboardButton("✅ Готово", callback_data="st:done"),
    ]])
    await q.message.reply_text("📌 Выберите статус:", reply_markup=kb)
    return ASK_STATUS
async def status_chosen(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Шаг 4: статус, сохранение задачи."""
    q = update.callback_query
    await q.answer()
    draft = context.user_data.pop("draft", {})
    status = q.data.split(":")[1]
    draft["status"] = status
    await q.edit_message_text(f"Статус: {STATUS_ICON[status]} {STATUS_LABEL[status]}")
    try:
        task = await create_task(TaskCreate(**draft, telegram_id=update.effective_user.id))
    except ValidationError as exc:
        await q.message.reply_text(f"Не удалось создать задачу: {exc.errors()[0]['msg']}")
        return ConversationHandler.END
    await WS.broadcast("task.created", task.model_dump())
    await q.message.reply_text(
        f"✅ Задача #{task.id} создана.\n\n{fmt_task_card(task)}",
        parse_mode="HTML",
        reply_markup=card_kb(task),
    )
    return ConversationHandler.END
async def cmd_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """/cancel — выход из диалога."""
    context.user_data.pop("draft", None)
    await update.effective_message.reply_text("🚫 Отменено.")
    return ConversationHandler.END
async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Глобальный обработчик ошибок бота."""
    log.error("Ошибка Telegram-обработчика", exc_info=context.error)
def build_bot() -> None:
    """Регистрирует все обработчики бота."""
    conv = ConversationHandler(
        entry_points=[
            CommandHandler("new", new_entry),
            CallbackQueryHandler(new_entry, pattern=r"^menu:new$"),
        ],
        states={
            ASK_TITLE: [MessageHandler(filters.TEXT & ~filters.COMMAND, new_title)],
            ASK_BODY: [
                CommandHandler("skip", new_body_skip),
                MessageHandler(filters.TEXT & ~filters.COMMAND, new_body),
            ],
            ASK_PRIORITY: [CallbackQueryHandler(prio_chosen, pattern=r"^prio:(low|normal|high)$")],
            ASK_STATUS: [CallbackQueryHandler(status_chosen, pattern=r"^st:(todo|in_progress|done)$")],
        },
        fallbacks=[CommandHandler("cancel", cmd_cancel)],
        per_message=False,
        name="new_task",
        allow_reentry=True,
    )
    TG_APP.add_handler(CommandHandler("start", cmd_start))
    TG_APP.add_handler(CommandHandler("list", cmd_list))
    TG_APP.add_handler(CommandHandler("stats", cmd_stats))
    TG_APP.add_handler(conv)
    TG_APP.add_handler(CallbackQueryHandler(on_menu, pattern=r"^menu:(list|stats|dash)$"))
    TG_APP.add_handler(CallbackQueryHandler(on_task_action, pattern=r"^task:(open|done|del):\d+$"))
    TG_APP.add_error_handler(on_error)
build_bot()
HTML_PAGE = r"""<!doctype html>
<html lang="ru" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="description" content="Дашборд задач Telegram Tasks: live-обновления, фильтры, экспорт">
<title>Telegram Tasks · Дашборд</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'><rect width='64' height='64' rx='14' fill='%237c5cff'/><text x='32' y='42' font-size='30' text-anchor='middle' fill='white' font-family='Arial'>T</text></svg>">
<style>
/* ==========================================================================
Telegram Tasks — дашборд
Тёмная тема по умолчанию, светлая через data-theme="light".
========================================================================== */
:root {
--bg: #0a0e1a;
--bg-elev: #111829;
--bg-solid: #0d1322;
--fg: #e7ecf8;
--fg-muted: #8a95b2;
--accent: #7c5cff;
--accent-2: #22d3ee;
--accent-3: #f472b6;
--border: rgba(255, 255, 255, 0.09);
--border-strong: rgba(255, 255, 255, 0.18);
--chip: rgba(255, 255, 255, 0.06);
--radius: 16px;
--radius-sm: 10px;
--shadow: 0 24px 60px -24px rgba(0, 0, 0, 0.7);
--blur: 20px;
--ok: #34d399;
--warn: #fbbf24;
--danger: #f43f5e;
--info: #60a5fa;
--glow: 0 0 0 1px rgba(124, 92, 255, 0.4), 0 0 24px -4px rgba(124, 92, 255, 0.55);
--ease: cubic-bezier(0.2, 0.8, 0.2, 1);
color-scheme: dark;
}
:root[data-theme="light"] {
--bg: #eef2fb;
--bg-elev: #ffffff;
--bg-solid: #f6f8fd;
--fg: #111a30;
--fg-muted: #5b6785;
--accent: #6d4aff;
--accent-2: #0891b2;
--accent-3: #db2777;
--border: rgba(17, 26, 48, 0.1);
--border-strong: rgba(17, 26, 48, 0.2);
--chip: rgba(17, 26, 48, 0.05);
--shadow: 0 20px 50px -24px rgba(30, 41, 80, 0.35);
--glow: 0 0 0 1px rgba(109, 74, 255, 0.35), 0 0 22px -6px rgba(109, 74, 255, 0.45);
color-scheme: light;
}
@media (prefers-color-scheme: light) {
:root:not([data-theme="dark"]) {
--bg: #eef2fb;
--bg-elev: #ffffff;
--bg-solid: #f6f8fd;
--fg: #111a30;
--fg-muted: #5b6785;
--border: rgba(17, 26, 48, 0.1);
--chip: rgba(17, 26, 48, 0.05);
color-scheme: light;
}
}
*,
*::before,
*::after {
box-sizing: border-box;
}
[hidden] {
display: none !important;
}
html,
body {
width: 100vw;
height: 100dvh;
margin: 0;
overflow: hidden;
}
html {
-webkit-text-size-adjust: 100%;
text-size-adjust: 100%;
}
body {
font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
font-size: 15px;
line-height: 1.5;
color: var(--fg);
background: var(--bg);
-webkit-font-smoothing: antialiased;
}
button,
input,
select,
textarea {
font: inherit;
color: inherit;
}
button {
cursor: pointer;
background: none;
border: 0;
padding: 0;
}
button:disabled {
cursor: not-allowed;
opacity: 0.5;
}
h1,
h2,
h3 {
margin: 0;
line-height: 1.2;
}
table {
border-collapse: separate;
border-spacing: 0;
}
kbd {
font: 600 11px/1 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
padding: 3px 6px;
border-radius: 6px;
border: 1px solid var(--border);
background: var(--chip);
color: var(--fg-muted);
}
::selection {
background: color-mix(in oklab, var(--accent) 35%, transparent);
}
:focus-visible {
outline: 2px solid var(--accent);
outline-offset: 2px;
}
* {
scrollbar-width: thin;
scrollbar-color: color-mix(in oklab, var(--fg) 25%, transparent) transparent;
}
*::-webkit-scrollbar {
width: 10px;
height: 10px;
}
*::-webkit-scrollbar-track {
background: transparent;
}
*::-webkit-scrollbar-thumb {
background: color-mix(in oklab, var(--fg) 22%, transparent);
border-radius: 999px;
border: 3px solid transparent;
background-clip: padding-box;
}
*::-webkit-scrollbar-thumb:hover {
background: color-mix(in oklab, var(--fg) 40%, transparent);
background-clip: padding-box;
}
body::before {
content: "";
position: fixed;
inset: -20%;
z-index: -1;
pointer-events: none;
background:
radial-gradient(60% 50% at 20% 20%, color-mix(in oklab, var(--accent) 35%, transparent), transparent 70%),
radial-gradient(50% 45% at 80% 30%, color-mix(in oklab, var(--accent-2) 28%, transparent), transparent 70%),
radial-gradient(55% 50% at 60% 90%, color-mix(in oklab, var(--accent-3) 22%, transparent), transparent 70%),
linear-gradient(120deg, var(--bg), var(--bg-solid), var(--bg));
background-size: 200% 200%;
animation: drift 30s ease infinite;
}
.app {
display: grid;
grid-template-areas:
"sidebar header"
"sidebar main";
grid-template-columns: 260px 1fr;
grid-template-rows: 64px 1fr;
width: 100vw;
height: 100dvh;
overflow: hidden;
}
.sidebar {
grid-area: sidebar;
position: sticky;
top: 0;
z-index: 40;
height: 100dvh;
display: flex;
flex-direction: column;
gap: 18px;
padding: 18px 14px;
overflow-y: auto;
background: color-mix(in oklab, var(--bg-elev) 78%, transparent);
backdrop-filter: blur(var(--blur)) saturate(160%);
-webkit-backdrop-filter: blur(var(--blur)) saturate(160%);
border-right: 1px solid var(--border);
}
.brand {
display: flex;
align-items: center;
gap: 12px;
padding: 6px 8px 14px;
border-bottom: 1px solid var(--border);
}
.brand-logo {
width: 40px;
height: 40px;
flex: none;
display: grid;
place-items: center;
border-radius: 12px;
font-weight: 800;
letter-spacing: 0.5px;
color: #fff;
background: linear-gradient(135deg, var(--accent), var(--accent-2));
box-shadow: var(--glow);
}
.brand-name {
font-weight: 700;
font-size: 13px;
letter-spacing: 0.14em;
}
.brand-ver {
font-size: 12px;
color: var(--fg-muted);
}
.nav {
display: flex;
flex-direction: column;
gap: 4px;
}
.nav-title {
font-size: 11px;
text-transform: uppercase;
letter-spacing: 0.12em;
color: var(--fg-muted);
padding: 8px 12px 4px;
}
.nav-item {
position: relative;
display: flex;
align-items: center;
gap: 12px;
width: 100%;
padding: 10px 12px;
border-radius: var(--radius-sm);
color: var(--fg-muted);
text-align: left;
transition: background 0.2s var(--ease), color 0.2s var(--ease), transform 0.2s var(--ease);
}
.nav-item:hover {
background: var(--chip);
color: var(--fg);
transform: translateX(2px);
}
.nav-item.active {
color: var(--fg);
background: linear-gradient(90deg, color-mix(in oklab, var(--accent) 22%, transparent), transparent);
box-shadow: inset 0 0 0 1px color-mix(in oklab, var(--accent) 30%, transparent);
}
.nav-item.active::before {
content: "";
position: absolute;
left: -14px;
top: 20%;
bottom: 20%;
width: 3px;
border-radius: 3px;
background: var(--accent);
box-shadow: 0 0 14px var(--accent);
}
.nav-ico {
width: 22px;
text-align: center;
font-size: 16px;
}
.nav-label {
flex: 1;
}
.nav-count {
min-width: 26px;
padding: 2px 8px;
border-radius: 999px;
background: var(--chip);
font-size: 12px;
text-align: center;
font-variant-numeric: tabular-nums;
}
.sidebar-foot {
margin-top: auto;
display: flex;
flex-direction: column;
gap: 12px;
}
.export-row {
display: grid;
grid-template-columns: 1fr 1fr;
gap: 8px;
}
.bot-status {
display: flex;
align-items: center;
gap: 10px;
padding: 10px 12px;
border-radius: var(--radius-sm);
background: var(--chip);
font-size: 13px;
}
.bot-name {
padding: 0 12px;
font-size: 12px;
color: var(--fg-muted);
overflow: hidden;
text-overflow: ellipsis;
white-space: nowrap;
}
.hotkeys {
display: flex;
flex-wrap: wrap;
align-items: center;
gap: 6px;
padding: 0 12px;
font-size: 12px;
color: var(--fg-muted);
}
.dot {
width: 9px;
height: 9px;
flex: none;
border-radius: 50%;
background: var(--fg-muted);
}
.dot.online {
background: var(--ok);
box-shadow: 0 0 0 4px color-mix(in oklab, var(--ok) 22%, transparent);
animation: pulse 2.4s infinite;
}
.dot.connecting {
background: var(--warn);
animation: blink 1s infinite;
}
.dot.offline {
background: var(--danger);
}
.header {
grid-area: header;
position: sticky;
top: 0;
z-index: 30;
min-width: 0;
display: flex;
align-items: center;
gap: 14px;
padding: 0 22px;
border-bottom: 1px solid var(--border);
background: color-mix(in oklab, var(--bg-elev) 70%, transparent);
backdrop-filter: blur(var(--blur)) saturate(160%);
-webkit-backdrop-filter: blur(var(--blur)) saturate(160%);
}
.hamburger {
display: none;
}
.crumbs {
min-width: 0;
display: flex;
align-items: center;
gap: 8px;
overflow: hidden;
white-space: nowrap;
font-size: 14px;
color: var(--fg-muted);
}
.crumbs strong {
overflow: hidden;
text-overflow: ellipsis;
color: var(--fg);
font-weight: 600;
}
.search {
position: relative;
flex: 1;
max-width: 420px;
margin-left: auto;
}
.search::before {
content: "⌕";
position: absolute;
left: 14px;
top: 50%;
z-index: 2;
transform: translateY(-50%);
font-size: 18px;
color: var(--fg-muted);
pointer-events: none;
}
.search input {
width: 100%;
height: 40px;
padding: 0 56px 0 40px;
border-radius: 999px;
border: 1px solid var(--border);
background: var(--chip);
outline: none;
transition: border-color 0.2s, box-shadow 0.2s, background 0.2s;
}
.search input:focus {
border-color: var(--accent);
box-shadow: var(--glow);
background: var(--bg-elev);
}
.search kbd {
position: absolute;
right: 10px;
top: 50%;
transform: translateY(-50%);
}
.header-actions {
display: flex;
align-items: center;
gap: 10px;
}
.avatar {
width: 38px;
height: 38px;
flex: none;
display: grid;
place-items: center;
border-radius: 50%;
font-size: 13px;
font-weight: 700;
color: #fff;
background: linear-gradient(135deg, var(--accent-3), var(--accent));
box-shadow: 0 0 0 2px var(--bg-elev), 0 0 0 3px color-mix(in oklab, var(--accent) 40%, transparent);
}
.icon-btn {
width: 40px;
height: 40px;
flex: none;
display: inline-grid;
place-items: center;
border-radius: 12px;
background: var(--chip);
border: 1px solid var(--border);
transition: transform 0.15s var(--ease), background 0.2s, color 0.2s;
}
.icon-btn:hover {
background: color-mix(in oklab, var(--accent) 18%, transparent);
transform: translateY(-1px);
}
.icon-btn:active {
transform: scale(0.96);
}
.icon-btn.sm {
width: 32px;
height: 32px;
border-radius: 9px;
font-size: 14px;
}
.icon-btn.danger:hover {
color: var(--danger);
background: color-mix(in oklab, var(--danger) 20%, transparent);
}
.btn {
display: inline-flex;
align-items: center;
justify-content: center;
gap: 8px;
height: 40px;
padding: 0 16px;
border-radius: 12px;
font-size: 14px;
font-weight: 600;
white-space: nowrap;
transition: transform 0.15s var(--ease), box-shadow 0.2s, background 0.2s, filter 0.2s;
}
.btn:hover {
transform: translateY(-1px);
filter: brightness(1.05);
}
.btn:active {
transform: scale(0.97);
}
.btn-primary {
color: #fff;
background: linear-gradient(135deg, var(--accent), #4f7bff 60%, var(--accent-2));
box-shadow: 0 10px 24px -10px var(--accent);
}
.btn-primary:hover {
box-shadow: 0 14px 30px -10px var(--accent);
}
.btn-ghost {
background: var(--chip);
border: 1px solid var(--border);
}
.btn-ghost:hover {
background: color-mix(in oklab, var(--fg) 8%, transparent);
}
.btn-danger {
color: #fff;
background: linear-gradient(135deg, #f43f5e, #fb7185);
box-shadow: 0 10px 24px -12px var(--danger);
}
.btn-sm {
height: 34px;
padding: 0 12px;
font-size: 13px;
}
.btn-block {
width: 100%;
}
.main {
grid-area: main;
min-height: 0;
display: flex;
flex-direction: column;
gap: 20px;
padding: 22px 26px 28px;
overflow-y: auto;
}
.page-head {
display: flex;
flex-wrap: wrap;
align-items: flex-end;
justify-content: space-between;
gap: 16px;
}
.page-title {
font-size: clamp(20px, 2.4vw, 28px);
font-weight: 800;
letter-spacing: -0.02em;
}
.page-sub {
font-size: 14px;
color: var(--fg-muted);
}
.card {
background: color-mix(in oklab, var(--bg-elev) 80%, transparent);
backdrop-filter: blur(var(--blur)) saturate(160%);
-webkit-backdrop-filter: blur(var(--blur)) saturate(160%);
border: 1px solid var(--border);
border-radius: var(--radius);
box-shadow: var(--shadow);
}
.stats {
display: grid;
grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
gap: 16px;
}
.stat {
position: relative;
padding: 18px 20px;
overflow: hidden;
animation: rise 0.5s var(--ease) both;
transition: transform 0.25s var(--ease), box-shadow 0.25s;
}
.stat:hover {
transform: translateY(-3px);
box-shadow: var(--glow), var(--shadow);
}
.stat::after {
content: "";
position: absolute;
right: -40px;
top: -40px;
width: 120px;
height: 120px;
border-radius: 50%;
pointer-events: none;
background: radial-gradient(circle, color-mix(in oklab, var(--accent) 35%, transparent), transparent 70%);
}
.stat:nth-child(2)::after {
background: radial-gradient(circle, color-mix(in oklab, var(--accent-2) 35%, transparent), transparent 70%);
}
.stat:nth-child(3)::after {
background: radial-gradient(circle, color-mix(in oklab, var(--ok) 35%, transparent), transparent 70%);
}
.stat:nth-child(4)::after {
background: radial-gradient(circle, color-mix(in oklab, var(--accent-3) 35%, transparent), transparent 70%);
}
.stat-top {
display: flex;
align-items: center;
gap: 10px;
font-size: 13px;
color: var(--fg-muted);
}
.stat-ico {
width: 30px;
height: 30px;
display: grid;
place-items: center;
border-radius: 10px;
background: var(--chip);
}
.stat-value {
margin-top: 10px;
font-size: clamp(26px, 3vw, 34px);
font-weight: 800;
font-variant-numeric: tabular-nums;
}
.stat-hint {
margin-top: 2px;
font-size: 12px;
color: var(--fg-muted);
}
.bar {
height: 6px;
margin-top: 12px;
overflow: hidden;
border-radius: 999px;
background: var(--chip);
}
.bar > span {
display: block;
height: 100%;
border-radius: inherit;
background: linear-gradient(90deg, var(--accent), var(--accent-2));
transition: width 0.6s var(--ease);
}
.stat-skel {
height: 118px;
background: linear-gradient(90deg, var(--chip) 25%, color-mix(in oklab, var(--fg) 10%, transparent) 37%, var(--chip) 63%);
background-size: 400% 100%;
animation: shimmer 1.4s ease infinite;
}
.panel {
container-type: inline-size;
flex: 1 1 auto;
min-height: 0;
display: flex;
flex-direction: column;
}
.toolbar {
display: flex;
flex-wrap: wrap;
align-items: center;
justify-content: space-between;
gap: 12px;
padding: 14px 16px;
border-bottom: 1px solid var(--border);
}
.filters {
display: flex;
flex-wrap: wrap;
align-items: center;
gap: 10px;
}
.select {
height: 38px;
padding: 0 34px 0 12px;
border-radius: var(--radius-sm);
border: 1px solid var(--border);
background-color: var(--chip);
appearance: none;
-webkit-appearance: none;
background-image:
linear-gradient(45deg, transparent 50%, var(--fg-muted) 50%),
linear-gradient(135deg, var(--fg-muted) 50%, transparent 50%);
background-position: calc(100% - 18px) 55%, calc(100% - 13px) 55%;
background-size: 5px 5px;
background-repeat: no-repeat;
cursor: pointer;
}
.select:focus {
outline: none;
border-color: var(--accent);
box-shadow: var(--glow);
}
.select option {
background: var(--bg-solid);
color: var(--fg);
}
.bulk {
display: flex;
flex-wrap: wrap;
align-items: center;
gap: 10px;
padding: 8px 12px;
border-radius: 12px;
background: color-mix(in oklab, var(--accent) 16%, transparent);
border: 1px solid color-mix(in oklab, var(--accent) 35%, transparent);
animation: rise 0.3s var(--ease);
}
.bulk-count {
margin-right: auto;
font-size: 13px;
font-weight: 600;
}
.table-wrap {
flex: 1 1 auto;
min-height: 0;
overflow: auto;
}
.tasks {
width: 100%;
min-width: 620px;
}
.tasks thead th {
position: sticky;
top: 0;
z-index: 2;
padding: 12px 14px;
text-align: left;
font-size: 12px;
font-weight: 700;
text-transform: uppercase;
letter-spacing: 0.08em;
color: var(--fg-muted);
background: color-mix(in oklab, var(--bg-elev) 92%, transparent);
backdrop-filter: blur(8px);
border-bottom: 1px solid var(--border);
user-select: none;
}
.tasks th[data-sort] {
cursor: pointer;
}
.tasks th[data-sort]:hover,
.tasks th.sorted {
color: var(--fg);
}
.tasks th.sorted::after {
content: "↓";
margin-left: 6px;
}
.tasks th.sorted[data-dir="asc"]::after {
content: "↑";
}
.tasks tbody tr {
transition: background 0.15s, opacity 0.25s;
}
.tasks tbody tr:nth-child(even) {
background: color-mix(in oklab, var(--fg) 2.5%, transparent);
}
.tasks tbody tr:hover {
background: color-mix(in oklab, var(--accent) 10%, transparent);
}
.tasks tbody tr.is-done .t-title {
color: var(--fg-muted);
text-decoration: line-through;
}
.tasks td {
padding: 12px 14px;
vertical-align: middle;
border-bottom: 1px solid var(--border);
}
.col-check {
width: 44px;
}
.col-id {
width: 70px;
color: var(--fg-muted);
font-variant-numeric: tabular-nums;
}
.col-actions {
white-space: nowrap;
text-align: right;
}
.col-actions .icon-btn {
margin-left: 4px;
}
.col-updated {
white-space: nowrap;
font-size: 13px;
color: var(--fg-muted);
}
.t-title {
font-weight: 600;
}
.t-body {
max-width: 48ch;
overflow: hidden;
text-overflow: ellipsis;
white-space: nowrap;
font-size: 13px;
color: var(--fg-muted);
}
.tg-tag {
display: inline-block;
margin-top: 4px;
padding: 1px 6px;
border-radius: 6px;
font-size: 10px;
font-weight: 700;
color: #2aabee;
background: color-mix(in oklab, #2aabee 25%, transparent);
}
.row-chk,
#chk-all {
width: 16px;
height: 16px;
cursor: pointer;
accent-color: var(--accent);
}
.pill {
display: inline-flex;
align-items: center;
gap: 6px;
padding: 4px 10px;
border-radius: 999px;
font-size: 12px;
font-weight: 600;
white-space: nowrap;
}
.pill::before {
content: "";
width: 6px;
height: 6px;
border-radius: 50%;
background: currentColor;
}
.pill-todo {
color: var(--info);
background: color-mix(in oklab, var(--info) 14%, transparent);
}
.pill-in_progress {
color: var(--warn);
background: color-mix(in oklab, var(--warn) 14%, transparent);
}
.pill-done {
color: var(--ok);
background: color-mix(in oklab, var(--ok) 14%, transparent);
}
.prio {
padding: 3px 9px;
border: 1px solid currentColor;
border-radius: 8px;
font-size: 12px;
font-weight: 700;
white-space: nowrap;
}
.prio-low {
color: var(--fg-muted);
}
.prio-normal {
color: var(--accent-2);
}
.prio-high {
color: var(--accent-3);
box-shadow: 0 0 14px -4px var(--accent-3);
}
.skel {
height: 14px;
border-radius: 8px;
background: linear-gradient(90deg, var(--chip) 25%, color-mix(in oklab, var(--fg) 10%, transparent) 37%, var(--chip) 63%);
background-size: 400% 100%;
animation: shimmer 1.4s ease infinite;
}
.skel-row td {
padding: 16px 14px;
}
.empty {
display: flex;
flex-direction: column;
align-items: center;
gap: 10px;
padding: 48px 16px;
text-align: center;
color: var(--fg-muted);
}
.empty-ico {
font-size: 42px;
animation: float 3s ease-in-out infinite;
}
.empty h3 {
font-size: 18px;
color: var(--fg);
}
.pager {
display: flex;
flex-wrap: wrap;
align-items: center;
justify-content: space-between;
gap: 12px;
padding: 12px 16px;
border-top: 1px solid var(--border);
font-size: 13px;
color: var(--fg-muted);
}
.pager .btn:disabled {
opacity: 0.4;
}
.modal-backdrop {
position: fixed;
inset: 0;
z-index: 100;
display: grid;
place-items: center;
padding: 16px;
background: color-mix(in oklab, #000 45%, transparent);
backdrop-filter: blur(8px);
-webkit-backdrop-filter: blur(8px);
animation: fade 0.2s ease both;
}
.modal {
width: min(520px, 100%);
max-height: calc(100dvh - 32px);
padding: 22px;
overflow-y: auto;
animation: pop 0.28s var(--ease) both;
}
.modal-head {
display: flex;
align-items: center;
justify-content: space-between;
margin-bottom: 16px;
}
.modal-title {
font-size: 18px;
font-weight: 800;
}
.modal-foot {
display: flex;
flex-wrap: wrap;
justify-content: flex-end;
gap: 10px;
margin-top: 18px;
}
.modal-foot.center {
justify-content: center;
}
body.modal-open {
overflow: hidden;
}
#confirm {
z-index: 110;
}
.confirm-box {
width: min(380px, 100%);
padding: 22px;
text-align: center;
}
.confirm-ico {
margin-bottom: 8px;
font-size: 36px;
}
.confirm-box h3 {
margin-bottom: 6px;
font-size: 18px;
}
.field {
position: relative;
margin-bottom: 18px;
}
.field input,
.field textarea,
.field select {
width: 100%;
padding: 20px 14px 8px;
border-radius: var(--radius-sm);
border: 1px solid var(--border);
background: var(--chip);
outline: none;
transition: border-color 0.2s, box-shadow 0.2s, background 0.2s;
}
.field textarea {
min-height: 110px;
resize: vertical;
}
.field label {
position: absolute;
left: 14px;
top: 14px;
color: var(--fg-muted);
pointer-events: none;
transform-origin: left top;
transition: all 0.2s var(--ease);
}
.field input:focus,
.field textarea:focus,
.field select:focus {
border-color: var(--accent);
box-shadow: var(--glow);
background: var(--bg-elev);
}
.field input:focus + label,
.field input:not(:placeholder-shown) + label,
.field textarea:focus + label,
.field textarea:not(:placeholder-shown) + label {
top: 6px;
font-size: 11px;
color: var(--accent);
}
.field select + label {
top: 6px;
font-size: 11px;
}
.field input.invalid,
.field textarea.invalid {
border-color: var(--danger);
box-shadow: 0 0 0 3px color-mix(in oklab, var(--danger) 25%, transparent);
}
.field .err {
display: block;
min-height: 16px;
margin-top: 4px;
padding-left: 2px;
font-size: 12px;
color: var(--danger);
}
.grid-2 {
display: grid;
grid-template-columns: 1fr 1fr;
gap: 12px;
}
.toasts {
position: fixed;
top: 16px;
right: 16px;
z-index: 200;
width: min(360px, calc(100vw - 32px));
display: flex;
flex-direction: column;
gap: 10px;
pointer-events: none;
}
.toast {
pointer-events: auto;
display: flex;
align-items: flex-start;
gap: 10px;
padding: 12px 12px 12px 14px;
border-radius: 14px;
border: 1px solid var(--border);
border-left: 3px solid var(--info);
background: color-mix(in oklab, var(--bg-elev) 88%, transparent);
backdrop-filter: blur(16px);
-webkit-backdrop-filter: blur(16px);
box-shadow: var(--shadow);
font-size: 14px;
animation: slideIn 0.35s var(--ease) both;
}
.toast.out {
animation: slideOut 0.3s var(--ease) both;
}
.toast-ok {
border-left-color: var(--ok);
}
.toast-warn {
border-left-color: var(--warn);
}
.toast-error {
border-left-color: var(--danger);
}
.toast-ico {
font-weight: 800;
}
.toast-msg {
flex: 1;
min-width: 0;
overflow-wrap: anywhere;
}
.toast-x {
padding: 0 2px;
font-size: 18px;
line-height: 1;
color: var(--fg-muted);
}
.scrim {
position: fixed;
inset: 0;
z-index: 35;
visibility: hidden;
opacity: 0;
pointer-events: none;
background: rgba(0, 0, 0, 0.45);
backdrop-filter: blur(3px);
-webkit-backdrop-filter: blur(3px);
transition: opacity 0.25s;
}
.scrim.show {
visibility: visible;
opacity: 1;
pointer-events: auto;
}
@keyframes drift {
0% { background-position: 0% 50%; }
50% { background-position: 100% 50%; }
100% { background-position: 0% 50%; }
}
@keyframes rise {
from { opacity: 0; transform: translateY(10px); }
to { opacity: 1; transform: none; }
}
@keyframes pop {
from { opacity: 0; transform: scale(0.96); }
to { opacity: 1; transform: none; }
}
@keyframes fade {
from { opacity: 0; }
to { opacity: 1; }
}
@keyframes slideIn {
from { opacity: 0; transform: translateX(40px); }
to { opacity: 1; transform: none; }
}
@keyframes slideOut {
to { opacity: 0; transform: translateX(40px); }
}
@keyframes shimmer {
0% { background-position: 100% 0; }
100% { background-position: -100% 0; }
}
@keyframes pulse {
0%,
100% { opacity: 1; }
50% { opacity: 0.55; }
}
@keyframes blink {
50% { opacity: 0.2; }
}
@keyframes float {
0%,
100% { transform: translateY(0); }
50% { transform: translateY(-6px); }
}
@container (max-width: 680px) {
.col-updated {
display: none;
}
.t-body {
max-width: 26ch;
}
}
@media (max-width: 1100px) {
.app {
grid-template-columns: 220px 1fr;
}
}
@media (max-width: 899px) {
.app {
grid-template-areas:
"header"
"main";
grid-template-columns: 1fr;
grid-template-rows: 64px 1fr;
}
.sidebar {
position: fixed;
top: 0;
left: 0;
width: min(290px, 84vw);
height: 100dvh;
transform: translateX(-102%);
transition: transform 0.32s var(--ease);
box-shadow: var(--shadow);
}
.sidebar.open {
transform: translateX(0);
}
.hamburger {
display: inline-grid;
}
.scrim {
display: block;
}
.main {
padding: 16px 14px 20px;
}
.header {
gap: 10px;
padding: 0 14px;
}
.crumbs {
display: none;
}
.search {
margin-left: 0;
}
.stats {
grid-template-columns: repeat(2, 1fr);
gap: 12px;
}
}
@media (min-width: 900px) {
.scrim {
display: none;
}
}
@media (max-width: 599px) {
.stats {
grid-template-columns: 1fr 1fr;
}
.stat {
padding: 14px;
}
.stat-value {
font-size: 24px;
}
.stat-hint {
display: none;
}
.search input {
padding-right: 12px;
}
.search kbd {
display: none;
}
.btn-label {
display: none;
}
.btn {
padding: 0 12px;
}
.toolbar {
padding: 12px;
}
.filters {
width: 100%;
}
.filters .select {
flex: 1 1 140px;
}
.page-title {
font-size: 22px;
}
.pager {
justify-content: center;
text-align: center;
}
.toasts {
top: auto;
right: 12px;
bottom: 12px;
left: 12px;
width: auto;
}
.grid-2 {
grid-template-columns: 1fr;
}
.modal {
padding: 18px;
}
}
@media (pointer: coarse) {
.icon-btn {
width: 44px;
height: 44px;
}
.icon-btn.sm {
width: 38px;
height: 38px;
}
.btn {
height: 44px;
}
.nav-item {
padding: 12px;
}
.row-chk,
#chk-all {
width: 20px;
height: 20px;
}
}
:root[data-theme="light"] .sidebar,
:root[data-theme="light"] .header {
box-shadow: 0 10px 30px -18px rgba(30, 41, 80, 0.35);
}
:root[data-theme="light"] .tasks thead th {
background: color-mix(in oklab, #ffffff 92%, transparent);
}
:root[data-theme="light"] .stat-skel,
:root[data-theme="light"] .skel {
background-color: var(--chip);
}
@media (prefers-reduced-motion: reduce) {
*,
*::before,
*::after {
animation-duration: 0.001ms !important;
animation-iteration-count: 1 !important;
transition-duration: 0.001ms !important;
scroll-behavior: auto !important;
}
}
</style>
<script src="https://telegram.org/js/telegram-web-app.js"></script>
</head>
<body>
<div class="app" id="app">
<aside class="sidebar" id="sidebar" aria-label="Навигация">
<div class="brand">
<div class="brand-logo">TT</div>
<div>
<div class="brand-name">TELEGRAM TASKS</div>
<div class="brand-ver" id="ver">v1.0.0</div>
</div>
</div>
<nav class="nav" aria-label="Разделы">
<div class="nav-title">Разделы</div>
<button class="nav-item active" data-view="all" aria-current="page">
<span class="nav-ico">📋</span><span class="nav-label">Все задачи</span><span class="nav-count" data-count="all">0</span>
</button>
<button class="nav-item" data-view="todo">
<span class="nav-ico">⬜</span><span class="nav-label">К выполнению</span><span class="nav-count" data-count="todo">0</span>
</button>
<button class="nav-item" data-view="in_progress">
<span class="nav-ico">🔄</span><span class="nav-label">В работе</span><span class="nav-count" data-count="in_progress">0</span>
</button>
<button class="nav-item" data-view="done">
<span class="nav-ico">✅</span><span class="nav-label">Готово</span><span class="nav-count" data-count="done">0</span>
</button>
<button class="nav-item" data-view="high">
<span class="nav-ico">🔥</span><span class="nav-label">Высокий приоритет</span><span class="nav-count" data-count="high">0</span>
</button>
</nav>
<div class="sidebar-foot">
<div class="nav-title">Экспорт</div>
<div class="export-row">
<button class="btn btn-ghost btn-sm" data-export="csv">CSV</button>
<button class="btn btn-ghost btn-sm" data-export="json">JSON</button>
</div>
<div class="bot-status">
<span class="dot" id="ws-dot"></span>
<span id="ws-text">Соединение…</span>
</div>
<div class="bot-name" id="bot-name">бот: загрузка…</div>
<div class="hotkeys">
<kbd>/</kbd> поиск <kbd>n</kbd> новая <kbd>f</kbd> экран <kbd>Esc</kbd> закрыть
</div>
</div>
</aside>
<div class="scrim" id="scrim"></div>
<header class="header">
<button class="icon-btn hamburger" id="burger" aria-label="Открыть меню">☰</button>
<nav class="crumbs" aria-label="Путь">
<span>Главная</span><span>/</span><strong id="crumb-now">Все задачи</strong>
</nav>
<div class="search">
<input id="search" type="search" placeholder="Поиск по названию и описанию" aria-label="Поиск" autocomplete="off">
<kbd>/</kbd>
</div>
<div class="header-actions">
<button class="icon-btn" id="btn-theme" title="Сменить тему" aria-label="Сменить тему">☀</button>
<button class="icon-btn" id="btn-full" title="Во весь экран (f)" aria-label="Во весь экран">⛶</button>
<button class="btn btn-primary" id="btn-new" title="Новая задача (n)">+ <span class="btn-label">Задача</span></button>
<div class="avatar" title="Вы">TG</div>
</div>
</header>
<main class="main" id="main">
<div class="page-head">
<div>
<h1 class="page-title">Задачи</h1>
<div class="page-sub">Синхронизировано с Telegram-ботом в реальном времени</div>
</div>
</div>
<section class="stats" id="stats" aria-label="Статистика">
<div class="card stat-skel"></div>
<div class="card stat-skel"></div>
<div class="card stat-skel"></div>
<div class="card stat-skel"></div>
</section>
<section class="card panel" aria-label="Таблица задач">
<div class="toolbar">
<div class="filters">
<select class="select" id="f-status" aria-label="Фильтр по статусу">
<option value="">Любой статус</option>
<option value="todo">К выполнению</option>
<option value="in_progress">В работе</option>
<option value="done">Готово</option>
</select>
<select class="select" id="f-priority" aria-label="Фильтр по приоритету">
<option value="">Любой приоритет</option>
<option value="low">Низкий</option>
<option value="normal">Обычный</option>
<option value="high">Высокий</option>
</select>
</div>
<div class="bulk" id="bulk" hidden>
<span class="bulk-count" id="bulk-count">Выбрано: 0</span>
<button class="btn btn-ghost btn-sm" id="bulk-done">✅ Выполнить</button>
<button class="btn btn-danger btn-sm" id="bulk-del">🗑 Удалить</button>
<button class="btn btn-ghost btn-sm" id="bulk-clear">Снять выбор</button>
</div>
</div>
<div class="table-wrap">
<table class="tasks">
<thead>
<tr>
<th class="col-check"><input type="checkbox" id="chk-all" aria-label="Выбрать все на странице"></th>
<th class="col-id" data-sort="id" role="button" tabindex="0">#</th>
<th data-sort="title" role="button" tabindex="0">Название</th>
<th data-sort="status" role="button" tabindex="0">Статус</th>
<th data-sort="priority" role="button" tabindex="0">Приоритет</th>
<th class="col-updated" data-sort="updated_at" role="button" tabindex="0">Обновлено</th>
<th class="col-actions">Действия</th>
</tr>
</thead>
<tbody id="rows"></tbody>
</table>
</div>
<div class="pager">
<button class="btn btn-ghost btn-sm" id="prev">← Назад</button>
<span id="page-info">Страница 1</span>
<button class="btn btn-ghost btn-sm" id="next">Вперёд →</button>
</div>
</section>
</main>
</div>
<div class="modal-backdrop" id="modal" hidden>
<div class="modal card" role="dialog" aria-modal="true" aria-labelledby="modal-title">
<div class="modal-head">
<h2 class="modal-title" id="modal-title">Новая задача</h2>
<button class="icon-btn sm" id="m-close" aria-label="Закрыть">✕</button>
</div>
<form id="task-form" novalidate>
<div class="field">
<input id="m-title" name="title" placeholder=" " maxlength="200" autocomplete="off">
<label for="m-title">Название</label>
<span class="err" id="e-m-title"></span>
</div>
<div class="field">
<textarea id="m-body" name="body" placeholder=" " maxlength="5000"></textarea>
<label for="m-body">Описание</label>
<span class="err" id="e-m-body"></span>
</div>
<div class="grid-2">
<div class="field">
<select id="m-status" name="status">
<option value="todo">К выполнению</option>
<option value="in_progress">В работе</option>
<option value="done">Готово</option>
</select>
<label for="m-status">Статус</label>
</div>
<div class="field">
<select id="m-priority" name="priority">
<option value="low">Низкий</option>
<option value="normal">Обычный</option>
<option value="high">Высокий</option>
</select>
<label for="m-priority">Приоритет</label>
</div>
</div>
<div class="modal-foot">
<button type="button" class="btn btn-ghost" id="m-cancel">Отмена</button>
<button type="submit" class="btn btn-primary" id="m-save">Сохранить</button>
</div>
</form>
</div>
</div>
<div class="modal-backdrop" id="confirm" hidden>
<div class="modal card confirm-box" role="alertdialog" aria-modal="true" aria-labelledby="confirm-title">
<div class="confirm-ico">⚠️</div>
<h3 id="confirm-title">Подтвердите</h3>
<p class="page-sub" id="confirm-text"></p>
<div class="modal-foot center">
<button class="btn btn-ghost" id="confirm-cancel">Отмена</button>
<button class="btn btn-danger" id="confirm-ok">Удалить</button>
</div>
</div>
</div>
<div class="toasts" id="toasts" aria-live="polite"></div>
<script>
(() => {
"use strict";
const API = "/api/v1";
const PAGE_SIZE = 10;
const VIEWS = {
all: { title: "Все задачи" },
todo: { title: "К выполнению", status: "todo" },
in_progress: { title: "В работе", status: "in_progress" },
done: { title: "Готово", status: "done" },
high: { title: "Высокий приоритет", priority: "high" },
};
const STATUS_LABEL = { todo: "К выполнению", in_progress: "В работе", done: "Готово" };
const PRIO_LABEL = { low: "Низкий", normal: "Обычный", high: "Высокий" };
const TOAST_ICON = { info: "ℹ", ok: "✓", warn: "⚠", error: "!" };
const state = {
view: "all",
status: "",
priority: "",
q: "",
sort: "updated_at",
order: "desc",
page: 1,
total: 0,
tasks: [],
selected: new Set(),
editId: null,
editTask: null,
reqSeq: 0,
};
let ws = null;
let wsAttempts = 0;
let pingTimer = null;
let reconnectTimer = null;
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const esc = (value) =>
String(value ?? "").replace(/[&<>"']/g, (c) => ({
"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
})[c]);
const fmtDate = (iso) => {
const d = new Date(iso);
if (isNaN(d)) return "—";
return d.toLocaleString("ru-RU", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
};
const debounce = (fn, ms) => {
let timer = null;
return (...args) => {
clearTimeout(timer);
timer = setTimeout(() => fn(...args), ms);
};
};
const setText = (sel, value) => {
const el = $(sel);
if (el) el.textContent = String(value);
};
const store = {
get(key, fallback) {
try {
const raw = localStorage.getItem(key);
return raw === null ? fallback : JSON.parse(raw);
} catch {
return fallback;
}
},
set(key, value) {
try {
localStorage.setItem(key, JSON.stringify(value));
} catch {
}
},
};
async function api(path, opts = {}) {
const init = { method: opts.method || "GET", headers: { Accept: "application/json" } };
if (opts.body !== undefined) {
init.headers["Content-Type"] = "application/json";
init.body = JSON.stringify(opts.body);
}
let res;
try {
res = await fetch(API + path, init);
} catch {
throw new Error("Нет связи с сервером");
}
if (res.status === 204) return { data: null, res };
const text = await res.text();
let data = null;
try {
data = text ? JSON.parse(text) : null;
} catch {
data = text;
}
if (!res.ok) {
let message = `Ошибка ${res.status}`;
if (data && typeof data.detail === "string") message = data.detail;
else if (data && Array.isArray(data.detail)) message = "Проверьте заполнение полей";
throw new Error(message);
}
return { data, res };
}
function toast(message, type = "info", ms = 4000) {
const box = $("#toasts");
const el = document.createElement("div");
el.className = `toast toast-${type}`;
el.setAttribute("role", "status");
el.innerHTML =
`<span class="toast-ico">${TOAST_ICON[type] || "ℹ"}</span>` +
`<span class="toast-msg">${esc(message)}</span>` +
`<button class="toast-x" aria-label="Закрыть">×</button>`;
const close = () => {
el.classList.add("out");
setTimeout(() => el.remove(), 300);
};
el.querySelector(".toast-x").addEventListener("click", close);
box.appendChild(el);
setTimeout(close, ms);
}
function applyTheme(theme) {
document.documentElement.setAttribute("data-theme", theme);
$("#btn-theme").textContent = theme === "light" ? "☾" : "☀";
}
function initTheme() {
const saved = store.get("tt.theme", null);
const prefersLight = window.matchMedia && matchMedia("(prefers-color-scheme: light)").matches;
applyTheme(saved || (prefersLight ? "light" : "dark"));
}
function toggleTheme() {
const next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
applyTheme(next);
store.set("tt.theme", next);
}
function toggleFullscreen() {
if (!document.fullscreenElement) {
const root = document.documentElement;
if (!root.requestFullscreen) {
toast("Полноэкранный режим недоступен", "warn");
return;
}
const p = root.requestFullscreen();
if (p && p.catch) p.catch(() => toast("Полноэкранный режим недоступен", "warn"));
} else if (document.exitFullscreen) {
document.exitFullscreen();
}
}
function openDrawer(open) {
$("#sidebar").classList.toggle("open", open);
$("#scrim").classList.toggle("show", open);
}
function setView(name, { closeDrawer = true } = {}) {
const key = name in VIEWS ? name : "all";
const view = VIEWS[key];
state.view = key;
state.status = view.status || "";
state.priority = view.priority || "";
state.page = 1;
$$(".nav-item").forEach((btn) => {
const on = btn.dataset.view === key;
btn.classList.toggle("active", on);
if (on) btn.setAttribute("aria-current", "page");
else btn.removeAttribute("aria-current");
});
setText("#crumb-now", view.title);
$("#f-status").value = state.status;
$("#f-priority").value = state.priority;
store.set("tt.view", key);
if (closeDrawer) openDrawer(false);
loadTasks();
}
function buildQuery() {
const p = new URLSearchParams();
p.set("skip", String((state.page - 1) * PAGE_SIZE));
p.set("limit", String(PAGE_SIZE));
if (state.status) p.set("status", state.status);
if (state.priority) p.set("priority", state.priority);
if (state.q) p.set("q", state.q);
p.set("sort", state.sort);
p.set("order", state.order);
return "/tasks?" + p.toString();
}
function matchesFilters(task) {
if (state.status && task.status !== state.status) return false;
if (state.priority && task.priority !== state.priority) return false;
if (state.q) {
const hay = `${task.title} ${task.body}`.toLowerCase();
if (!hay.includes(state.q.toLowerCase())) return false;
}
return true;
}
function renderSkeleton() {
$("#rows").innerHTML = Array.from({ length: 6 }, () =>
`<tr class="skel-row"><td colspan="7"><div class="skel"></div></td></tr>`
).join("");
}
async function loadTasks({ silent = false } = {}) {
const seq = ++state.reqSeq;
if (!silent) renderSkeleton();
try {
const { data, res } = await api(buildQuery());
if (seq !== state.reqSeq) return;
state.tasks = data;
state.total = Number(res.headers.get("X-Total-Count") || data.length);
const maxPage = Math.max(1, Math.ceil(state.total / PAGE_SIZE));
if (state.page > maxPage) {
state.page = maxPage;
return loadTasks({ silent: true });
}
state.selected = new Set([...state.selected].filter((id) => data.some((t) => t.id === id)));
renderRows();
renderPager();
updateBulk();
updateSortHeaders();
} catch (err) {
if (seq === state.reqSeq) {
toast(err.message, "error");
renderRows();
}
}
}
function rowHTML(t) {
const checked = state.selected.has(t.id) ? " checked" : "";
const doneClass = t.status === "done" ? " is-done" : "";
const toggleIcon = t.status === "done" ? "↺" : "✓";
const toggleTip = t.status === "done" ? "Вернуть в работу" : "Отметить готовым";
return `
<tr data-id="${t.id}" class="${doneClass.trim()}">
<td class="col-check"><input type="checkbox" class="row-chk" aria-label="Выбрать #${t.id}"${checked}></td>
<td class="col-id">#${t.id}</td>
<td>
<div class="t-title">${esc(t.title)}</div>
${t.body ? `<div class="t-body">${esc(t.body)}</div>` : ""}
${t.telegram_id ? `<span class="tg-tag">TG</span>` : ""}
</td>
<td><span class="pill pill-${esc(t.status)}">${esc(STATUS_LABEL[t.status])}</span></td>
<td><span class="prio prio-${esc(t.priority)}">${esc(PRIO_LABEL[t.priority])}</span></td>
<td class="col-updated">${esc(fmtDate(t.updated_at))}</td>
<td class="col-actions">
<button class="icon-btn sm" data-act="toggle" title="${toggleTip}" aria-label="${toggleTip}">${toggleIcon}</button>
<button class="icon-btn sm" data-act="edit" title="Редактировать" aria-label="Редактировать">✎</button>
<button class="icon-btn sm danger" data-act="delete" title="Удалить" aria-label="Удалить">🗑</button>
</td>
</tr>`;
}
function renderRows() {
const tbody = $("#rows");
if (!state.tasks.length) {
tbody.innerHTML = `
<tr><td colspan="7">
<div class="empty">
<div class="empty-ico">🗂</div>
<h3>Ничего не найдено</h3>
<p>Измените фильтры или создайте новую задачу.</p>
<button class="btn btn-primary" id="empty-new">+ Создать задачу</button>
</div>
</td></tr>`;
$("#empty-new").addEventListener("click", () => openModal(null));
$("#chk-all").checked = false;
return;
}
tbody.innerHTML = state.tasks.map(rowHTML).join("");
$("#chk-all").checked = state.tasks.every((t) => state.selected.has(t.id));
}
function replaceRow(task) {
const idx = state.tasks.findIndex((t) => t.id === task.id);
if (idx === -1) return;
state.tasks[idx] = task;
const tr = $(`tr[data-id="${task.id}"]`);
if (tr) tr.outerHTML = rowHTML(task);
}
function removeRowLocal(id) {
state.tasks = state.tasks.filter((t) => t.id !== id);
state.selected.delete(id);
const tr = $(`tr[data-id="${id}"]`);
if (tr) tr.remove();
if (!state.tasks.length) renderRows();
updateBulk();
}
function renderPager() {
const pages = Math.max(1, Math.ceil(state.total / PAGE_SIZE));
setText("#page-info", `Страница ${state.page} из ${pages} · всего ${state.total}`);
$("#prev").disabled = state.page <= 1;
$("#next").disabled = state.page >= pages;
}
function updateSortHeaders() {
$$("th[data-sort]").forEach((th) => {
const on = th.dataset.sort === state.sort;
th.classList.toggle("sorted", on);
th.dataset.dir = on ? state.order : "";
th.setAttribute("aria-sort", on ? (state.order === "asc" ? "ascending" : "descending") : "none");
});
}
function updateBulk() {
const n = state.selected.size;
$("#bulk").hidden = n === 0;
setText("#bulk-count", `Выбрано: ${n}`);
$("#chk-all").checked = state.tasks.length > 0 && state.tasks.every((t) => state.selected.has(t.id));
}
async function loadStats() {
try {
const { data } = await api("/stats");
const done = data.by_status.done || 0;
const pct = data.total ? Math.round((done / data.total) * 100) : 0;
const cards = [
{ label: "Всего задач", value: data.total, ico: "📋", hint: `${data.created_last_24h} за 24 часа` },
{ label: "В работе", value: data.by_status.in_progress || 0, ico: "🔄", hint: `${data.by_status.todo || 0} в очереди` },
{ label: "Готово", value: done, ico: "✅", hint: `${pct}% выполнено`, bar: pct },
{ label: "Высокий приоритет", value: data.by_priority.high || 0, ico: "🔥", hint: `${data.by_priority.low || 0} с низким` },
];
$("#stats").innerHTML = cards
.map((c) => `
<article class="stat card">
<div class="stat-top">
<span class="stat-ico">${c.ico}</span>
<span>${esc(c.label)}</span>
</div>
<div class="stat-value">${esc(c.value)}</div>
<div class="stat-hint">${esc(c.hint)}</div>
${c.bar !== undefined ? `<div class="bar"><span style="width:${c.bar}%"></span></div>` : ""}
</article>`)
.join("");
const counts = {
all: data.total,
todo: data.by_status.todo || 0,
in_progress: data.by_status.in_progress || 0,
done: done,
high: data.by_priority.high || 0,
};
Object.entries(counts).forEach(([key, value]) => setText(`[data-count="${key}"]`, value));
} catch (err) {
toast("Статистика: " + err.message, "warn");
}
}
async function toggleDone(task) {
const prev = { ...task };
const next = task.status === "done" ? "todo" : "done";
const optimistic = { ...task, status: next };
if (matchesFilters(optimistic)) replaceRow(optimistic);
else removeRowLocal(task.id);
try {
const { data } = await api(`/tasks/${task.id}`, { method: "PATCH", body: { status: next } });
toast(next === "done" ? "Задача выполнена" : "Задача возвращена в работу", "ok");
loadStats();
loadTasks({ silent: true });
return data;
} catch (err) {
toast("Не удалось сохранить: " + err.message, "error");
loadTasks({ silent: true });
return prev;
}
}
function askConfirm(title, text, okLabel = "Удалить") {
return new Promise((resolve) => {
const box = $("#confirm");
setText("#confirm-title", title);
setText("#confirm-text", text);
$("#confirm-ok").textContent = okLabel;
box.hidden = false;
const finish = (value) => {
box.hidden = true;
$("#confirm-ok").onclick = null;
$("#confirm-cancel").onclick = null;
resolve(value);
};
$("#confirm-ok").onclick = () => finish(true);
$("#confirm-cancel").onclick = () => finish(false);
$("#confirm-ok").focus();
});
}
async function deleteTask(task) {
const ok = await askConfirm(
`Удалить задачу #${task.id}?`,
`«${task.title}» будет удалена без возможности восстановления.`
);
if (!ok) return;
const snapshot = state.tasks.slice();
removeRowLocal(task.id);
try {
await api(`/tasks/${task.id}`, { method: "DELETE" });
state.total = Math.max(0, state.total - 1);
renderPager();
toast("Задача удалена", "ok");
loadStats();
if (!state.tasks.length && state.page > 1) {
state.page -= 1;
loadTasks({ silent: true });
}
} catch (err) {
state.tasks = snapshot;
renderRows();
updateBulk();
toast("Ошибка удаления: " + err.message, "error");
}
}
async function bulkApply(kind) {
const ids = [...state.selected];
if (!ids.length) return;
if (kind === "delete") {
const ok = await askConfirm(`Удалить ${ids.length} задач?`, "Действие необратимо.");
if (!ok) return;
}
const ops = ids.map((id) =>
kind === "delete"
? { op: "delete", id }
: { op: "patch", id, data: { status: "done" } }
);
try {
const { data } = await api("/tasks/bulk", { method: "POST", body: ops });
const failed = data.filter((r) => !r.ok).length;
toast(
failed ? `Готово: ${data.length - failed}, с ошибкой: ${failed}` : `Готово: ${data.length}`,
failed ? "warn" : "ok"
);
state.selected.clear();
loadTasks();
loadStats();
} catch (err) {
toast(err.message, "error");
}
}
function setFieldError(inputId, message) {
const input = $("#" + inputId);
const err = $("#e-" + inputId);
if (input) input.classList.toggle("invalid", Boolean(message));
if (err) err.textContent = message || "";
}
function clearFormErrors() {
setFieldError("m-title", "");
setFieldError("m-body", "");
}
function validateForm() {
clearFormErrors();
let ok = true;
const title = $("#m-title").value.trim();
const body = $("#m-body").value.trim();
if (!title) {
setFieldError("m-title", "Укажите название");
ok = false;
} else if (title.length > 200) {
setFieldError("m-title", "Не длиннее 200 символов");
ok = false;
}
if (body.length > 5000) {
setFieldError("m-body", "Не длиннее 5000 символов");
ok = false;
}
return ok;
}
function fillForm(task) {
$("#m-title").value = task.title;
$("#m-body").value = task.body || "";
$("#m-status").value = task.status;
$("#m-priority").value = task.priority;
}
async function openModal(id) {
state.editId = id;
state.editTask = null;
$("#task-form").reset();
clearFormErrors();
setText("#modal-title", id ? `Задача #${id}` : "Новая задача");
$("#m-save").textContent = "Сохранить";
$("#modal").hidden = false;
document.body.classList.add("modal-open");
if (id) {
try {
const { data } = await api(`/tasks/${id}`);
state.editTask = data;
fillForm(data);
} catch (err) {
closeModal();
toast(err.message, "error");
return;
}
} else {
$("#m-status").value = "todo";
$("#m-priority").value = "normal";
}
setTimeout(() => $("#m-title").focus(), 60);
}
function closeModal() {
$("#modal").hidden = true;
document.body.classList.remove("modal-open");
state.editId = null;
state.editTask = null;
}
async function onSubmit(event) {
event.preventDefault();
if (!validateForm()) return;
const payload = {
title: $("#m-title").value.trim(),
body: $("#m-body").value.trim(),
status: $("#m-status").value,
priority: $("#m-priority").value,
telegram_id: state.editTask ? state.editTask.telegram_id : null,
};
const btn = $("#m-save");
btn.disabled = true;
btn.textContent = "Сохранение…";
try {
if (state.editId) {
const optimistic = { ...state.editTask, ...payload, id: state.editId };
if (matchesFilters(optimistic)) replaceRow(optimistic);
await api(`/tasks/${state.editId}`, { method: "PUT", body: payload });
toast("Изменения сохранены", "ok");
} else {
await api("/tasks", { method: "POST", body: payload });
toast("Задача создана", "ok");
state.page = 1;
}
closeModal();
loadTasks({ silent: true });
loadStats();
} catch (err) {
toast(err.message, "error");
} finally {
btn.disabled = false;
btn.textContent = "Сохранить";
}
}
function exportFile(fmt) {
const link = document.createElement("a");
link.href = `${API}/export?format=${fmt}`;
link.download = "";
document.body.appendChild(link);
link.click();
link.remove();
toast(`Экспорт ${fmt.toUpperCase()} запущен`, "info");
}
async function loadHealth() {
try {
const { data } = await api("/health");
setText("#ver", "v" + data.version);
setText("#bot-name", data.bot_username ? "@" + data.bot_username : "бот не подключён");
} catch {
setText("#bot-name", "нет связи с сервером");
}
}
const scheduleRefresh = debounce(() => {
loadTasks({ silent: true });
loadStats();
}, 250);
function setWsStatus(status, text) {
const dot = $("#ws-dot");
dot.className = "dot " + status;
setText("#ws-text", text);
}
function scheduleReconnect() {
wsAttempts += 1;
const base = Math.min(30000, 500 * 2 ** Math.min(wsAttempts, 6));
const jitter = Math.random() * 400;
clearTimeout(reconnectTimer);
reconnectTimer = setTimeout(connectWs, base + jitter);
}
function handleEvent(msg) {
if (msg.event === "task.created") {
if (msg.data && msg.data.telegram_id) {
toast(`Новая задача из Telegram: «${msg.data.title}»`, "info");
}
scheduleRefresh();
} else if (msg.event === "task.updated" || msg.event === "task.deleted") {
scheduleRefresh();
}
}
function connectWs() {
clearTimeout(reconnectTimer);
const proto = location.protocol === "https:" ? "wss:" : "ws:";
try {
ws = new WebSocket(`${proto}//${location.host}/ws`);
} catch {
scheduleReconnect();
return;
}
setWsStatus("connecting", "Подключение…");
ws.onopen = () => {
wsAttempts = 0;
setWsStatus("online", "Онлайн · live");
clearInterval(pingTimer);
pingTimer = setInterval(() => {
if (ws && ws.readyState === WebSocket.OPEN) ws.send("ping");
}, 25000);
};
ws.onmessage = (ev) => {
let msg;
try {
msg = JSON.parse(ev.data);
} catch {
return;
}
handleEvent(msg);
};
ws.onclose = () => {
clearInterval(pingTimer);
setWsStatus("offline", "Нет связи · переподключение");
scheduleReconnect();
};
ws.onerror = () => {
try {
ws.close();
} catch {
}
};
}
function bindUi() {
$("#btn-theme").addEventListener("click", toggleTheme);
$("#btn-full").addEventListener("click", toggleFullscreen);
$("#btn-new").addEventListener("click", () => openModal(null));
$("#burger").addEventListener("click", () => {
openDrawer(!$("#sidebar").classList.contains("open"));
});
$("#scrim").addEventListener("click", () => openDrawer(false));
$$(".nav-item").forEach((btn) => {
btn.addEventListener("click", () => setView(btn.dataset.view));
});
$$("[data-export]").forEach((btn) => {
btn.addEventListener("click", () => exportFile(btn.dataset.export));
});
const onSearch = debounce(() => {
state.q = $("#search").value.trim();
state.page = 1;
loadTasks();
}, 300);
$("#search").addEventListener("input", onSearch);
$("#f-status").addEventListener("change", (e) => {
state.status = e.target.value;
state.page = 1;
loadTasks();
});
$("#f-priority").addEventListener("change", (e) => {
state.priority = e.target.value;
state.page = 1;
loadTasks();
});
$$("th[data-sort]").forEach((th) => {
const sortBy = () => {
const field = th.dataset.sort;
if (state.sort === field) {
state.order = state.order === "asc" ? "desc" : "asc";
} else {
state.sort = field;
state.order = field === "title" || field === "status" ? "asc" : "desc";
}
state.page = 1;
loadTasks();
};
th.addEventListener("click", sortBy);
th.addEventListener("keydown", (e) => {
if (e.key === "Enter" || e.key === " ") {
e.preventDefault();
sortBy();
}
});
});
$("#prev").addEventListener("click", () => {
if (state.page > 1) {
state.page -= 1;
loadTasks();
}
});
$("#next").addEventListener("click", () => {
state.page += 1;
loadTasks();
});
$("#chk-all").addEventListener("change", (e) => {
state.tasks.forEach((t) => {
if (e.target.checked) state.selected.add(t.id);
else state.selected.delete(t.id);
});
renderRows();
updateBulk();
});
const tbody = $("#rows");
tbody.addEventListener("change", (e) => {
if (!e.target.classList.contains("row-chk")) return;
const id = Number(e.target.closest("tr").dataset.id);
if (e.target.checked) state.selected.add(id);
else state.selected.delete(id);
updateBulk();
});
tbody.addEventListener("click", (e) => {
const tr = e.target.closest("tr[data-id]");
const btn = e.target.closest("[data-act]");
if (!tr || !btn) return;
const task = state.tasks.find((t) => t.id === Number(tr.dataset.id));
if (!task) return;
if (btn.dataset.act === "toggle") toggleDone(task);
if (btn.dataset.act === "edit") openModal(task.id);
if (btn.dataset.act === "delete") deleteTask(task);
});
$("#bulk-done").addEventListener("click", () => bulkApply("done"));
$("#bulk-del").addEventListener("click", () => bulkApply("delete"));
$("#bulk-clear").addEventListener("click", () => {
state.selected.clear();
renderRows();
updateBulk();
});
$("#task-form").addEventListener("submit", onSubmit);
$("#m-close").addEventListener("click", closeModal);
$("#m-cancel").addEventListener("click", closeModal);
$("#modal").addEventListener("click", (e) => {
if (e.target.id === "modal") closeModal();
});
document.addEventListener("keydown", onKeydown);
document.addEventListener("visibilitychange", () => {
if (document.visibilityState === "visible" && (!ws || ws.readyState > WebSocket.OPEN)) {
connectWs();
}
});
}
function onKeydown(e) {
const tag = (e.target.tagName || "").toLowerCase();
const typing = ["input", "textarea", "select"].includes(tag) || e.target.isContentEditable;
if (e.key === "Escape") {
if (!$("#confirm").hidden) {
$("#confirm-cancel").click();
return;
}
if (!$("#modal").hidden) {
closeModal();
return;
}
if ($("#sidebar").classList.contains("open")) openDrawer(false);
if (typing) e.target.blur();
return;
}
if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
if (!$("#modal").hidden || !$("#confirm").hidden) return;
if (e.key === "/") {
e.preventDefault();
$("#search").focus();
} else if (e.key === "n" || e.key === "N") {
e.preventDefault();
openModal(null);
} else if (e.key === "f" || e.key === "F") {
e.preventDefault();
toggleFullscreen();
}
}
function init() {
const tg = window.Telegram && window.Telegram.WebApp;
if (tg) {
try {
tg.ready();
tg.expand();
} catch {
}
}
initTheme();
bindUi();
const savedView = store.get("tt.view", "all");
setView(savedView, { closeDrawer: false });
loadStats();
loadHealth();
connectWs();
}
init();
})();
</script>
</html>
"""
@asynccontextmanager
async def lifespan(app: FastAPI):
    await db_init()
    await TG_APP.initialize()
    await TG_APP.start()
    me = await TG_APP.bot.get_me()
    STATE["bot_username"] = me.username
    if WEBHOOK_URL:
        await TG_APP.bot.set_webhook(
            url=WEBHOOK_URL,
            secret_token=WEBHOOK_SECRET,
            allowed_updates=Update.ALL_TYPES,
            drop_pending_updates=True,
        )
        log.info("Режим webhook: %s", WEBHOOK_URL)
    else:
        await TG_APP.bot.delete_webhook(drop_pending_updates=True)
        await TG_APP.updater.start_polling(allowed_updates=Update.ALL_TYPES)
        log.info("Режим polling")
    if app_url().startswith("https://"):
        try:
            await TG_APP.bot.set_chat_menu_button(
                menu_button=MenuButtonWebApp(text="Задачи", web_app=WebAppInfo(url=app_url()))
            )
        except Exception as exc:
            log.warning("Не удалось поставить кнопку меню: %s", exc)
    STATE["bot_ready"] = True
    log.info("Приложение: %s", app_url())
    try:
        yield
    finally:
        STATE["bot_ready"] = False
        if TG_APP.updater and TG_APP.updater.running:
            await TG_APP.updater.stop()
        await TG_APP.stop()
        await TG_APP.shutdown()
        await close_db()
app = FastAPI(
    title=BRAND,
    version=APP_VERSION,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url=None,
    openapi_url="/api/openapi.json",
)
app.add_middleware(GZipMiddleware, minimum_size=512)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Location", "X-Total-Count", "X-Response-Time"],
)
@app.middleware("http")
async def timing_middleware(request: Request, call_next):
    """Добавляет заголовок X-Response-Time к каждому HTTP-ответу."""
    started = time.perf_counter()
    response = await call_next(request)
    response.headers["X-Response-Time"] = f"{(time.perf_counter() - started) * 1000:.2f}ms"
    return response
api = APIRouter(prefix="/api/v1")
@api.get("/health", response_model=Health)
async def health() -> Health:
    """Состояние сервиса и бота."""
    return Health(
        status="ok",
        version=APP_VERSION,
        uptime_seconds=int(time.monotonic() - START_TIME),
        bot_username=STATE["bot_username"],
        webhook=bool(WEBHOOK_URL),
    )
@api.get("/tasks", response_model=list[Task])
async def list_tasks(
    response: Response,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    status: Optional[Status] = None,
    priority: Optional[Priority] = None,
    q: Optional[str] = Query(None, max_length=200),
    sort: SortField = "updated_at",
    order: Literal["asc", "desc"] = "desc",
    telegram_id: Optional[int] = None,
) -> list[Task]:
    """Список задач: фильтры, поиск, сортировка, пагинация. Общее число — в X-Total-Count."""
    tasks, total = await query_tasks(
        status=status,
        priority=priority,
        q=q.strip() if q else None,
        telegram_id=telegram_id,
        sort=sort,
        order=order,
        skip=skip,
        limit=limit,
    )
    response.headers["X-Total-Count"] = str(total)
    return tasks
@api.get("/tasks/{task_id}", response_model=Task)
async def get_one(task_id: int) -> Task:
    """Одна задача по id."""
    task = await get_task(task_id)
    if task is None:
        raise HTTPException(404, "Задача не найдена")
    return task
@api.post("/tasks", response_model=Task, status_code=201)
async def create(payload: TaskCreate, response: Response) -> Task:
    """Создание задачи. Возвращает 201 и Location."""
    task = await create_task(payload)
    response.headers["Location"] = f"/api/v1/tasks/{task.id}"
    await WS.broadcast("task.created", task.model_dump())
    return task
@api.put("/tasks/{task_id}", response_model=Task)
async def replace(task_id: int, payload: TaskUpdate) -> Task:
    """Полная замена задачи."""
    task = await update_task(task_id, payload.model_dump())
    if task is None:
        raise HTTPException(404, "Задача не найдена")
    await WS.broadcast("task.updated", task.model_dump())
    return task
@api.patch("/tasks/{task_id}", response_model=Task)
async def patch(task_id: int, payload: TaskPatch) -> Task:
    """Частичное обновление задачи."""
    changes = payload.model_dump(exclude_unset=True)
    changes = {k: v for k, v in changes.items() if v is not None or k == "telegram_id"}
    if not changes:
        raise HTTPException(422, "Нет полей для обновления")
    task = await update_task(task_id, changes)
    if task is None:
        raise HTTPException(404, "Задача не найдена")
    await WS.broadcast("task.updated", task.model_dump())
    return task
@api.delete("/tasks/{task_id}", status_code=204)
async def remove(task_id: int) -> Response:
    """Удаление задачи. Владелец в Telegram получает уведомление."""
    task = await delete_task(task_id)
    if task is None:
        raise HTTPException(404, "Задача не найдена")
    await WS.broadcast("task.deleted", {"id": task.id, "telegram_id": task.telegram_id})
    await notify_owner(task.telegram_id, f"🗑 Задача #{task.id} «{esc(task.title)}» удалена из дашборда.")
    return Response(status_code=204)
@api.get("/stats", response_model=Stats)
async def stats() -> Stats:
    """Агрегированная статистика."""
    return Stats(**(await task_stats()))
@api.post("/tasks/bulk", response_model=list[BulkResult])
async def bulk_tasks(items: list[BulkItem] = Body(...)) -> list[BulkResult]:
    """Пакетные операции create / patch / delete, результат по каждому элементу."""
    if not items or len(items) > 100:
        raise HTTPException(422, "Допустимо от 1 до 100 операций за запрос")
    results: list[BulkResult] = []
    for idx, item in enumerate(items):
        try:
            if item.op == "create":
                task = await create_task(TaskCreate(**item.data))
                await WS.broadcast("task.created", task.model_dump())
                results.append(BulkResult(index=idx, ok=True, op=item.op, id=task.id, task=task))
            elif item.op == "patch":
                if item.id is None:
                    raise ValueError("Не указан id")
                changes = TaskPatch(**item.data).model_dump(exclude_unset=True)
                changes = {k: v for k, v in changes.items() if v is not None or k == "telegram_id"}
                task = await update_task(item.id, changes)
                if task is None:
                    raise LookupError("Задача не найдена")
                await WS.broadcast("task.updated", task.model_dump())
                results.append(BulkResult(index=idx, ok=True, op=item.op, id=task.id, task=task))
            else:
                if item.id is None:
                    raise ValueError("Не указан id")
                removed = await delete_task(item.id)
                if removed is None:
                    raise LookupError("Задача не найдена")
                await WS.broadcast("task.deleted", {"id": removed.id, "telegram_id": removed.telegram_id})
                await notify_owner(removed.telegram_id, f"🗑 Задача #{removed.id} удалена из дашборда.")
                results.append(BulkResult(index=idx, ok=True, op=item.op, id=removed.id))
        except (ValueError, TypeError, LookupError) as exc:
            results.append(BulkResult(index=idx, ok=False, op=item.op, id=item.id, error=str(exc)))
    return results
@api.get("/export")
async def export(fmt: Literal["json", "csv"] = Query("json", alias="format")) -> StreamingResponse:
    """Экспорт всех задач в JSON или CSV (CSV с BOM для Excel)."""
    tasks, _ = await query_tasks(sort="id", order="asc", limit=100000)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"tasks-{stamp}.{fmt}"
    disposition = {"Content-Disposition": f'attachment; filename="{filename}"'}
    if fmt == "json":
        data = json.dumps([t.model_dump() for t in tasks], ensure_ascii=False, indent=2)
        return StreamingResponse(
            iter([data]),
            media_type="application/json; charset=utf-8",
            headers=disposition,
        )
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=["id", "telegram_id", "title", "body", "status", "priority", "created_at", "updated_at"],
    )
    writer.writeheader()
    for t in tasks:
        writer.writerow(t.model_dump())
    return StreamingResponse(
        iter(["﻿" + buf.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers=disposition,
    )
app.include_router(api)
@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    """Живые события задач. Клиент может слать 'ping' для keep-alive."""
    await WS.connect(ws)
    try:
        await ws.send_text(json.dumps({"event": "hello", "data": {"clients": WS.count}, "ts": now_iso()}))
        while True:
            message = await ws.receive_text()
            if message == "ping":
                await ws.send_text(json.dumps({"event": "pong", "data": {}, "ts": now_iso()}))
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        await WS.disconnect(ws)
@app.post("/telegram/webhook")
async def telegram_webhook(request: Request) -> dict[str, bool]:
    """Приём апдейтов Telegram в режиме webhook."""
    if WEBHOOK_SECRET and request.headers.get("X-Telegram-Bot-Api-Secret-Token") != WEBHOOK_SECRET:
        raise HTTPException(403, "Неверный секрет вебхука")
    data = await request.json()
    update = Update.de_json(data, TG_APP.bot)
    await TG_APP.process_update(update)
    return {"ok": True}
@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    """Фронтенд дашборда (встроен в этот файл)."""
    return HTMLResponse(HTML_PAGE, headers={"Cache-Control": "no-store"})
if __name__ == "__main__":
    import uvicorn
    host = "0.0.0.0" if RENDER_URL else os.getenv("HOST", "127.0.0.1")
    uvicorn.run(app, host=host, port=PORT, log_level="info", proxy_headers=True, forwarded_allow_ips="*")
