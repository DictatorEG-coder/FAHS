import sqlite3
from fahs.config import settings, ensure_data_dir

def connect():
    ensure_data_dir()
    db = sqlite3.connect(settings.database_path)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            reminders INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS group_settings (
            chat_id INTEGER PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 0,
            auto_delete INTEGER NOT NULL DEFAULT 0
        );
        """)

def touch_user(user_id: int):
    with connect() as db:
        db.execute("INSERT OR IGNORE INTO users(user_id) VALUES(?)", (user_id,))

def set_reminders(user_id: int, enabled: bool):
    touch_user(user_id)
    with connect() as db:
        db.execute("UPDATE users SET reminders=? WHERE user_id=?", (int(enabled), user_id))

def get_reminders(user_id: int) -> bool:
    with connect() as db:
        row = db.execute("SELECT reminders FROM users WHERE user_id=?", (user_id,)).fetchone()
        return bool(row["reminders"]) if row else False

def set_group(chat_id: int, enabled: bool, auto_delete: bool = False):
    with connect() as db:
        db.execute("""INSERT INTO group_settings(chat_id,enabled,auto_delete) VALUES(?,?,?)
        ON CONFLICT(chat_id) DO UPDATE SET enabled=excluded.enabled,auto_delete=excluded.auto_delete""",
        (chat_id, int(enabled), int(auto_delete)))

def get_group(chat_id: int):
    with connect() as db:
        row = db.execute("SELECT enabled,auto_delete FROM group_settings WHERE chat_id=?", (chat_id,)).fetchone()
        return (bool(row["enabled"]), bool(row["auto_delete"])) if row else (False, False)

def stats():
    with connect() as db:
        users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        reminders = db.execute("SELECT COUNT(*) FROM users WHERE reminders=1").fetchone()[0]
        groups = db.execute("SELECT COUNT(*) FROM group_settings WHERE enabled=1").fetchone()[0]
        return users, reminders, groups
