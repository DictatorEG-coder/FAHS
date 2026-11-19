from dataclasses import dataclass
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

@dataclass(frozen=True)
class Settings:
    bot_token: str = os.getenv("BOT_TOKEN", "")
    admin_ids: tuple[int, ...] = tuple(int(x.strip()) for x in os.getenv("ADMIN_IDS", "").split(",") if x.strip().isdigit())
    database_path: str = os.getenv("DATABASE_PATH", "data/fahs.sqlite3")
    request_timeout: float = float(os.getenv("REQUEST_TIMEOUT", "8"))
    max_redirects: int = int(os.getenv("MAX_REDIRECTS", "5"))
    max_url_length: int = int(os.getenv("MAX_URL_LENGTH", "2048"))
    updates_url: str = os.getenv("UPDATES_URL", "")
    developer_url: str = os.getenv("DEVELOPER_URL", "")
    support_url: str = os.getenv("SUPPORT_URL", "")
    openphish_feed_url: str = os.getenv("OPENPHISH_FEED_URL", "")

settings = Settings()

def ensure_data_dir() -> None:
    Path(settings.database_path).parent.mkdir(parents=True, exist_ok=True)
