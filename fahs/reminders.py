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

async def reminder_loop(bot: Bot):
    # Opt-in only. Process each Cairo calendar day once; the database prevents duplicates after restarts.
    processed_day = None
    while True:
        now = datetime.now(ZoneInfo("Africa/Cairo"))
        day = now.date().isoformat()
        if now.hour >= 10 and processed_day != day:
            processed_day = day
            for user_id in db.reminder_users():
                if not db.get_reminders(user_id) or not db.reminder_due(user_id, day):
                    continue
                try:
                    await bot.send_message(user_id, MESSAGES[now.timetuple().tm_yday % len(MESSAGES)])
                    db.mark_reminder_sent(user_id, day)
                except TelegramForbiddenError:
                    db.set_reminders(user_id, False)
                except Exception:
                    logging.exception("Failed to deliver an opted-in reminder")
                    db.mark_reminder_sent(user_id, day)
                await asyncio.sleep(0.1)
        await asyncio.sleep(30)
