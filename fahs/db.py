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
            last_reminder_date TEXT,
            reminder_interval INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS group_settings (
            chat_id INTEGER PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 0,
            auto_delete INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS group_allowlist (
            chat_id INTEGER NOT NULL,
            domain TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(chat_id, domain)
        );
        """)
        columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
        if "last_reminder_date" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN last_reminder_date TEXT")
        if "reminder_interval" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN reminder_interval INTEGER NOT NULL DEFAULT 1")

def touch_user(user_id: int):
    with connect() as db:
        db.execute("INSERT OR IGNORE INTO users(user_id) VALUES(?)", (user_id,))

def set_reminders(user_id: int, enabled: bool):
    touch_user(user_id)
    with connect() as db:
        db.execute("UPDATE users SET reminders=?, last_reminder_date=NULL WHERE user_id=?", (int(enabled), user_id))

def get_reminders(user_id: int) -> bool:
    with connect() as db:
        row = db.execute("SELECT reminders FROM users WHERE user_id=?", (user_id,)).fetchone()
        return bool(row["reminders"]) if row else False

def reminder_users():
    with connect() as db:
        rows = db.execute("SELECT user_id FROM users WHERE reminders=1").fetchall()
        return [int(row["user_id"]) for row in rows]

def get_reminder_interval(user_id: int) -> int:
    with connect() as db:
        row = db.execute("SELECT reminder_interval FROM users WHERE user_id=?", (user_id,)).fetchone()
        return int(row["reminder_interval"]) if row else 1

def set_reminder_interval(user_id: int, days: int):
    if days not in (1, 2):
        raise ValueError("Reminder interval must be one or two days")
    touch_user(user_id)
    with connect() as db:
        db.execute("UPDATE users SET reminder_interval=? WHERE user_id=?", (days, user_id))

def reminder_due(user_id: int, day: str) -> bool:
    from datetime import date
    with connect() as db:
        row = db.execute("SELECT last_reminder_date, reminder_interval FROM users WHERE user_id=?", (user_id,)).fetchone()
        if not row:
            return False
        last = row["last_reminder_date"]
        if not last:
            return True
        return (date.fromisoformat(day) - date.fromisoformat(last)).days >= int(row["reminder_interval"])

def mark_reminder_sent(user_id: int, day: str):
    with connect() as db:
        db.execute("UPDATE users SET last_reminder_date=? WHERE user_id=?", (day, user_id))

def reminder_sent_today(user_id: int, day: str) -> bool:
    with connect() as db:
        row = db.execute("SELECT last_reminder_date FROM users WHERE user_id=?", (user_id,)).fetchone()
        return bool(row and row["last_reminder_date"] == day)

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

def delete_user(user_id: int):
    with connect() as db:
        db.execute("DELETE FROM users WHERE user_id=?", (user_id,))

def add_group_domain(chat_id: int, domain: str) -> bool:
    with connect() as db:
        count = db.execute("SELECT COUNT(*) FROM group_allowlist WHERE chat_id=?", (chat_id,)).fetchone()[0]
        if count >= 100:
            return False
        db.execute("INSERT OR IGNORE INTO group_allowlist(chat_id,domain) VALUES(?,?)", (chat_id, domain))
        return True

def remove_group_domain(chat_id: int, domain: str) -> bool:
    with connect() as db:
        cur = db.execute("DELETE FROM group_allowlist WHERE chat_id=? AND domain=?", (chat_id, domain))
        return cur.rowcount > 0

def group_domain_allowed(chat_id: int, host: str) -> bool:
    with connect() as db:
        rows = db.execute("SELECT domain FROM group_allowlist WHERE chat_id=?", (chat_id,)).fetchall()
        domains = [row["domain"] for row in rows]
    return any(host == domain or host.endswith("." + domain) for domain in domains)

def list_group_domains(chat_id: int) -> list[str]:
    with connect() as db:
        rows = db.execute("SELECT domain FROM group_allowlist WHERE chat_id=? ORDER BY domain", (chat_id,)).fetchall()
        return [row["domain"] for row in rows]
