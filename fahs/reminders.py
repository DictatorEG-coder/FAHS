import asyncio
import logging
from aiogram.exceptions import TelegramForbiddenError
from datetime import datetime
from zoneinfo import ZoneInfo
from aiogram import Bot
from fahs import db

MESSAGES = [
    "سُبْحَانَ اللَّهِ وَبِحَمْدِهِ، سُبْحَانَ اللَّهِ الْعَظِيمِ.",
    "اللهم صلِّ وسلم على نبينا محمد.",
    "اللهم اغفر لنا ولوالدينا وللمؤمنين.",
]

RETRY_DELAY_SECONDS = 300


async def _deliver_user(bot: Bot, user_id: int, day: str, retry_after: dict[int, float], now: float):
    if now < retry_after.get(user_id, 0):
        return
    if not db.get_reminders(user_id) or not db.reminder_due(user_id, day):
        return

    try:
        await bot.send_message(user_id, MESSAGES[datetime.now(ZoneInfo("Africa/Cairo")).timetuple().tm_yday % len(MESSAGES)])
    except TelegramForbiddenError:
        db.set_reminders(user_id, False)
        retry_after.pop(user_id, None)
    except Exception:
        # Keep the reminder due; retry after a short cooldown instead of silently losing it for the day.
        logging.exception("Failed to deliver an opted-in reminder")
        retry_after[user_id] = now + RETRY_DELAY_SECONDS
    else:
        db.mark_reminder_sent(user_id, day)
        retry_after.pop(user_id, None)


async def reminder_loop(bot: Bot):
    # Opt-in only. A successful delivery is recorded once per Cairo calendar day.
    retry_after: dict[int, float] = {}
    loop = asyncio.get_running_loop()
    while True:
        now = datetime.now(ZoneInfo("Africa/Cairo"))
        if now.hour >= 10:
            day = now.date().isoformat()
            for user_id in db.reminder_users():
                await _deliver_user(bot, user_id, day, retry_after, loop.time())
                await asyncio.sleep(0.1)
        await asyncio.sleep(30)
