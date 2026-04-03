# ─── Standard Library ────────────────────────────────────────────
import asyncio
import io
import logging
import os
import sqlite3
from datetime import datetime, timezone
from typing import Dict, Optional

# ─── Third-Party ─────────────────────────────────────────────────
import requests
from aiohttp import web
from dotenv import load_dotenv

from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import (
    Message,
    ReplyKeyboardMarkup,
    KeyboardButton,
    ReplyKeyboardRemove,
)
from aiogram.webhook.aiohttp_server import SimpleRequestHandler, setup_application

# ─── Load .env (local dev only; Railway uses its own env vars) ───
load_dotenv()

# ══════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ══════════════════════════════════════════════════════════════════

BOT_TOKEN: str = os.environ["BOT_TOKEN"]          # Required — crash early if missing
PASSWORD: str = os.environ["PASSWORD"]            # Required
GITHUB_RAW_URL: str = os.environ["GITHUB_RAW_URL"]  # Required

ADMIN_CHAT_ID: int = 8499435987                   # Hardcoded admin ID

WEBHOOK_HOST: Optional[str] = os.getenv("WEBHOOK_HOST")          # Optional
WEBHOOK_PATH: str = os.getenv("WEBHOOK_PATH", "/webhook")
PORT: int = int(os.getenv("PORT", "8080"))
WEBHOOK_URL: str = f"{WEBHOOK_HOST}{WEBHOOK_PATH}" if WEBHOOK_HOST else ""

DB_PATH: str = os.path.join("data", "access_logs.db")

# ─── Button label (single source of truth) ───────────────────────
BTN_NOVA = "🔑 Nova XLSX"

# ─── Rate-limit: max attempts per user before a cooldown kicks in ─
MAX_ATTEMPTS: int = 5          # wrong-password attempts
ATTEMPT_WINDOW: int = 300      # seconds (5 minutes)

# ══════════════════════════════════════════════════════════════════
#  LOGGING
# ══════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("nova_bot")

# ══════════════════════════════════════════════════════════════════
#  DATABASE  (SQLite — stored in data/access_logs.db)
# ══════════════════════════════════════════════════════════════════

def _db_connect() -> sqlite3.Connection:
    """Return a connection to the SQLite database, creating it if needed."""
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create tables on first run."""
    with _db_connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS access_logs (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                username   TEXT,
                chat_id    INTEGER NOT NULL,
                accessed_at TEXT NOT NULL
            )
            """
        )
        conn.commit()
    logger.info("Database initialised at %s", DB_PATH)


def log_access(user_id: int, username: Optional[str], chat_id: int) -> None:
    """Insert one access-log row."""
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _db_connect() as conn:
        conn.execute(
            "INSERT INTO access_logs (user_id, username, chat_id, accessed_at) VALUES (?, ?, ?, ?)",
            (user_id, username or "unknown", chat_id, ts),
        )
        conn.commit()


def total_access_count() -> int:
    """Return total number of successful file-access events."""
    with _db_connect() as conn:
        row = conn.execute("SELECT COUNT(*) AS cnt FROM access_logs").fetchone()
        return row["cnt"] if row else 0


def unique_user_count() -> int:
    """Return number of distinct users who accessed the file."""
    with _db_connect() as conn:
        row = conn.execute("SELECT COUNT(DISTINCT user_id) AS cnt FROM access_logs").fetchone()
        return row["cnt"] if row else 0


# ══════════════════════════════════════════════════════════════════
#  FSM STATES
# ══════════════════════════════════════════════════════════════════

class FileAccess(StatesGroup):
    waiting_for_password = State()   # Bot is expecting the user to type a password


# ══════════════════════════════════════════════════════════════════
#  RATE LIMITER  (in-memory, per user_id)
# ══════════════════════════════════════════════════════════════════

# Structure: { user_id: {"count": int, "window_start": float} }
_rate_store: Dict[int, dict] = {}


def _is_rate_limited(user_id: int) -> bool:
    """
    Return True if the user has exceeded MAX_ATTEMPTS wrong-password
    guesses within ATTEMPT_WINDOW seconds.
    Resets the window automatically once it expires.
    """
    import time
    now = time.monotonic()
    record = _rate_store.get(user_id)

    if record is None:
        _rate_store[user_id] = {"count": 0, "window_start": now}
        return False

    if now - record["window_start"] > ATTEMPT_WINDOW:
        # Window expired — reset
        _rate_store[user_id] = {"count": 0, "window_start": now}
        return False

    return record["count"] >= MAX_ATTEMPTS


def _record_failed_attempt(user_id: int) -> int:
    """
    Increment the failed-attempt counter for this user.
    Returns the new count.
    """
    import time
    now = time.monotonic()
    record = _rate_store.setdefault(user_id, {"count": 0, "window_start": now})

    if now - record["window_start"] > ATTEMPT_WINDOW:
        record["count"] = 0
        record["window_start"] = now

    record["count"] += 1
    return record["count"]


def _reset_attempts(user_id: int) -> None:
    """Clear rate-limit record after a successful authentication."""
    _rate_store.pop(user_id, None)


# ══════════════════════════════════════════════════════════════════
#  KEYBOARDS
# ══════════════════════════════════════════════════════════════════

def main_keyboard() -> ReplyKeyboardMarkup:
    """Persistent main keyboard with the single Nova XLSX button."""
    return ReplyKeyboardMarkup(
        keyboard=[[KeyboardButton(text=BTN_NOVA)]],
        resize_keyboard=True,
        one_time_keyboard=False,
        input_field_placeholder="Tap the button below ↓",
    )


# ══════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════

def _now_utc_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


async def _download_file_bytes(url: str) -> bytes:
    """
    Synchronously download a file from a URL using requests and return
    raw bytes. Runs in the default executor so it won't block the event loop.
    """
    loop = asyncio.get_running_loop()

    def _fetch() -> bytes:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        return resp.content

    return await loop.run_in_executor(None, _fetch)


# ══════════════════════════════════════════════════════════════════
#  ROUTER & HANDLERS
# ══════════════════════════════════════════════════════════════════

router = Router()


# ──────────────────────────────────────────────────────────────────
#  /start
# ──────────────────────────────────────────────────────────────────

@router.message(CommandStart())
async def cmd_start(message: Message, state: FSMContext) -> None:
    """Greet the user and show the main keyboard."""
    await state.clear()   # Reset any ongoing FSM state
    logger.info("User %s (%s) started the bot.", message.from_user.id, message.from_user.username)
    await message.answer(
        "Welcome to Nova Bot! 🔑 Please use the keyboard below to access the protected file.",
        reply_markup=main_keyboard(),
    )


# ──────────────────────────────────────────────────────────────────
#  /help
# ──────────────────────────────────────────────────────────────────

@router.message(Command("help"))
async def cmd_help(message: Message, state: FSMContext) -> None:
    """Show usage instructions."""
    await state.clear()
    await message.answer(
        "ℹ️ <b>Nova Bot — Help</b>\n\n"
        "• Tap <b>🔑 Nova XLSX</b> to request access to the protected file.\n"
        "• Enter the password when prompted.\n"
        "• On success the file will be sent directly to this chat.\n\n"
        "Commands:\n"
        "  /start  — Restart the bot\n"
        "  /help   — Show this message\n"
        "  /cancel — Cancel current operation",
        reply_markup=main_keyboard(),
    )


# ──────────────────────────────────────────────────────────────────
#  /cancel
# ──────────────────────────────────────────────────────────────────

@router.message(Command("cancel"))
async def cmd_cancel(message: Message, state: FSMContext) -> None:
    """Allow user to abort whatever they are currently doing."""
    current = await state.get_state()
    await state.clear()
    if current:
        await message.answer(
            "✅ Operation cancelled. Tap the button whenever you're ready.",
            reply_markup=main_keyboard(),
        )
    else:
        await message.answer(
            "Nothing to cancel. Tap the button below to begin.",
            reply_markup=main_keyboard(),
        )


# ──────────────────────────────────────────────────────────────────
#  /admin  (admin only)
# ──────────────────────────────────────────────────────────────────

@router.message(Command("admin"))
async def cmd_admin(message: Message) -> None:
    """Show admin statistics. Restricted to ADMIN_CHAT_ID."""
    if message.from_user.id != ADMIN_CHAT_ID:
        await message.answer("⛔ You are not authorised to use this command.")
        logger.warning(
            "Unauthorised /admin attempt by user %s (%s).",
            message.from_user.id,
            message.from_user.username,
        )
        return

    total = total_access_count()
    unique = unique_user_count()
    await message.answer(
        f"🛠 <b>Admin Panel — Nova Bot</b>\n\n"
        f"📦 Total file deliveries : <b>{total}</b>\n"
        f"👥 Unique users served   : <b>{unique}</b>\n\n"
        f"🕒 Report time: {_now_utc_str()}",
    )


# ──────────────────────────────────────────────────────────────────
#  Button: "🔑 Nova XLSX"  → ask for password
# ──────────────────────────────────────────────────────────────────

@router.message(F.text == BTN_NOVA)
async def btn_nova_xlsx(message: Message, state: FSMContext) -> None:
    """User tapped the Nova XLSX button — enter password-waiting state."""
    user_id = message.from_user.id

    # Check rate limit before even asking for a password
    if _is_rate_limited(user_id):
        await message.answer(
            f"⏳ Too many failed attempts. Please wait {ATTEMPT_WINDOW // 60} minutes before trying again."
        )
        logger.warning("Rate-limited user %s tried to access Nova XLSX.", user_id)
        return

    await state.set_state(FileAccess.waiting_for_password)
    await message.answer(
        "Please enter the password to access NovaYeasT.xlsx file:",
        reply_markup=ReplyKeyboardRemove(),   # Hide keyboard while typing password
    )


# ──────────────────────────────────────────────────────────────────
#  Password input handler
# ──────────────────────────────────────────────────────────────────

@router.message(FileAccess.waiting_for_password)
async def process_password(message: Message, state: FSMContext, bot: Bot) -> None:
    """Validate the password and either send the file or reject access."""
    user_id = message.from_user.id
    username = message.from_user.username
    chat_id = message.chat.id
    entered = message.text or ""

    # ── Rate-limit double-check ───────────────────────────────────
    if _is_rate_limited(user_id):
        await state.clear()
        await message.answer(
            f"⏳ Too many failed attempts. Please wait {ATTEMPT_WINDOW // 60} minutes before trying again.",
            reply_markup=main_keyboard(),
        )
        return

    # ── Wrong password ────────────────────────────────────────────
    if entered != PASSWORD:
        attempts = _record_failed_attempt(user_id)
        remaining = max(0, MAX_ATTEMPTS - attempts)

        logger.warning(
            "Wrong password from user %s (%s). Attempts: %d/%d.",
            user_id, username, attempts, MAX_ATTEMPTS,
        )

        if remaining == 0:
            await state.clear()
            await message.answer(
                f"❌ Incorrect password or access denied. You cannot access the file.\n\n"
                f"⏳ Maximum attempts reached. Please wait {ATTEMPT_WINDOW // 60} minutes.",
                reply_markup=main_keyboard(),
            )
        else:
            # Stay in FSM state so user can retry immediately
            await message.answer(
                f"❌ Incorrect password or access denied. You cannot access the file.\n\n"
                f"You have <b>{remaining}</b> attempt(s) remaining.",
            )
        return

    # ── Correct password ──────────────────────────────────────────
    await state.clear()
    _reset_attempts(user_id)

    # Let the user know we're working on it
    status_msg = await message.answer("⏳ Downloading file, please wait…")

    try:
        file_bytes = await _download_file_bytes(GITHUB_RAW_URL)
    except requests.exceptions.HTTPError as exc:
        logger.error("HTTP error downloading file: %s", exc)
        await status_msg.delete()
        await message.answer(
            "⚠️ Could not retrieve the file right now (HTTP error). Please try again later.",
            reply_markup=main_keyboard(),
        )
        return
    except Exception as exc:
        logger.exception("Unexpected error downloading file: %s", exc)
        await status_msg.delete()
        await message.answer(
            "⚠️ An unexpected error occurred while fetching the file. Please try again later.",
            reply_markup=main_keyboard(),
        )
        return

    # Delete the "please wait" message before sending the file
    await status_msg.delete()

    # Send the file as a Telegram document
    file_io = io.BytesIO(file_bytes)
    file_io.name = "NovaYeasT.xlsx"

    await message.answer_document(
        document=file_io,
        caption="Here is your NovaYeasT.xlsx file ✅",
        reply_markup=main_keyboard(),
    )

    # ── Persist the access event ──────────────────────────────────
    log_access(user_id=user_id, username=username, chat_id=chat_id)

    logger.info(
        "File delivered to user %s (%s) in chat %s.", user_id, username, chat_id
    )

    # ── Notify admin ──────────────────────────────────────────────
    timestamp = _now_utc_str()
    admin_text = (
        "🚨 <b>User accessed file!</b>\n\n"
        f"Username : @{username or 'N/A'}\n"
        f"User ID  : <code>{user_id}</code>\n"
        f"Chat ID  : <code>{chat_id}</code>\n"
        f"Time     : {timestamp}"
    )
    try:
        await bot.send_message(chat_id=ADMIN_CHAT_ID, text=admin_text)
    except Exception as exc:
        # Non-fatal — log the error but don't bother the user
        logger.warning("Could not notify admin: %s", exc)


# ──────────────────────────────────────────────────────────────────
#  Catch-all: unrecognised messages outside an FSM state
# ──────────────────────────────────────────────────────────────────

@router.message()
async def fallback(message: Message, state: FSMContext) -> None:
    """Gently redirect any unrecognised input back to the main flow."""
    current = await state.get_state()
    if current:
        # User is mid-flow — they probably sent something random; ignore gracefully
        return
    await message.answer(
        "I didn't understand that. Tap the button below or use /help.",
        reply_markup=main_keyboard(),
    )


# ══════════════════════════════════════════════════════════════════
#  BOT STARTUP / SHUTDOWN
# ══════════════════════════════════════════════════════════════════

async def on_startup(bot: Bot) -> None:
    init_db()
    if WEBHOOK_URL:
        await bot.set_webhook(WEBHOOK_URL)
        logger.info("Webhook set → %s", WEBHOOK_URL)
    else:
        # Make sure no stale webhook is registered when running in polling mode
        await bot.delete_webhook(drop_pending_updates=True)
        logger.info("Running in long-polling mode.")


async def on_shutdown(bot: Bot) -> None:
    logger.info("Shutting down — closing bot session.")
    if WEBHOOK_URL:
        await bot.delete_webhook()
    await bot.session.close()


# ══════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════

def main() -> None:
    bot = Bot(
        token=BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    storage = MemoryStorage()
    dp = Dispatcher(storage=storage)

    # Register lifecycle hooks
    dp.startup.register(on_startup)
    dp.shutdown.register(on_shutdown)

    # Mount the single router
    dp.include_router(router)

    if WEBHOOK_URL:
        # ── Webhook mode (Railway with a public domain) ───────────
        logger.info("Starting in WEBHOOK mode on port %d…", PORT)
        app = web.Application()
        handler = SimpleRequestHandler(dispatcher=dp, bot=bot)
        handler.register(app, path=WEBHOOK_PATH)
        setup_application(app, dp, bot=bot)
        web.run_app(app, host="0.0.0.0", port=PORT)
    else:
        # ── Polling mode (local dev / Railway without custom domain) ─
        logger.info("Starting in POLLING mode…")
        asyncio.run(dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types()))


if __name__ == "__main__":
    main()
