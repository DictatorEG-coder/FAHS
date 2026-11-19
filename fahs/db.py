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
        CREATE TABLE IF NOT EXISTS scan_stats (
            level TEXT PRIMARY KEY,
            count INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS content_items (
            category TEXT NOT NULL,
            item_key TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            deleted INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(category, item_key)
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

def record_scan(level: str):
    allowed = {"خطر حرج", "مرتفع", "متوسط", "مؤشرات اشتباه", "لم تظهر مؤشرات اشتباه أولية", "تعذر إكمال الفحص"}
    if level not in allowed:
        level = "تعذر إكمال الفحص"
    with connect() as db:
        db.execute(
            "INSERT INTO scan_stats(level,count) VALUES(?,1) "
            "ON CONFLICT(level) DO UPDATE SET count=count+1",
            (level,),
        )

def stats():
    with connect() as db:
        users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        reminders = db.execute("SELECT COUNT(*) FROM users WHERE reminders=1").fetchone()[0]
        groups = db.execute("SELECT COUNT(*) FROM group_settings WHERE enabled=1").fetchone()[0]
        scans = db.execute("SELECT COALESCE(SUM(count),0) FROM scan_stats").fetchone()[0]
        levels = {row["level"]: int(row["count"]) for row in db.execute("SELECT level,count FROM scan_stats")}
        return users, reminders, groups, int(scans), levels

def delete_user(user_id: int):
    with connect() as db:
        db.execute("DELETE FROM users WHERE user_id=?", (user_id,))

def add_group_domain(chat_id: int, domain: str) -> bool:
    with connect() as db:
        exists = db.execute("SELECT 1 FROM group_allowlist WHERE chat_id=? AND domain=?", (chat_id, domain)).fetchone()
        if exists:
            return True
        count = db.execute("SELECT COUNT(*) FROM group_allowlist WHERE chat_id=?", (chat_id,)).fetchone()[0]
        if count >= 100:
            return False
        db.execute("INSERT INTO group_allowlist(chat_id,domain) VALUES(?,?)", (chat_id, domain))
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


def list_users():
    """Return registered private-chat user IDs for admin broadcasts."""
    with connect() as db:
        rows = db.execute("SELECT user_id FROM users ORDER BY user_id").fetchall()
        return [int(row["user_id"]) for row in rows]


def get_content_overrides(category: str) -> dict[str, dict]:
    with connect() as db:
        rows = db.execute(
            "SELECT item_key,title,body,deleted FROM content_items WHERE category=?",
            (category,),
        ).fetchall()
        return {
            row["item_key"]: {
                "title": row["title"],
                "body": row["body"],
                "deleted": bool(row["deleted"]),
            }
            for row in rows
        }


def save_content_item(category: str, item_key: str, title: str, body: str):
    with connect() as db:
        db.execute(
            """INSERT INTO content_items(category,item_key,title,body,deleted)
            VALUES(?,?,?,?,0)
            ON CONFLICT(category,item_key) DO UPDATE SET
            title=excluded.title, body=excluded.body, deleted=0,
            updated_at=CURRENT_TIMESTAMP""",
            (category, item_key, title, body),
        )


def hide_content_item(category: str, item_key: str):
    with connect() as db:
        db.execute(
            """INSERT INTO content_items(category,item_key,title,body,deleted)
            VALUES(?,?, '', '', 1)
            ON CONFLICT(category,item_key) DO UPDATE SET deleted=1,
            updated_at=CURRENT_TIMESTAMP""",
            (category, item_key),
        )


def get_content_item(category: str, item_key: str):
    with connect() as db:
        row = db.execute(
            "SELECT title,body,deleted FROM content_items WHERE category=? AND item_key=?",
            (category, item_key),
        ).fetchone()
        return dict(row) if row else None
