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
    # Opt-in only; each user chooses daily or every-other-day delivery.
    while True:
        now = datetime.now(ZoneInfo("Africa/Cairo"))
        day = now.date().isoformat()
        if now.hour == 10 and now.minute < 5:
            for user_id in db.reminder_users():
                if not db.reminder_due(user_id, day):
                    continue
                try:
                    await bot.send_message(user_id, MESSAGES[now.timetuple().tm_yday % len(MESSAGES)])
                    db.mark_reminder_sent(user_id, day)
                except TelegramForbiddenError:
                    db.set_reminders(user_id, False)
                except Exception:
                    logging.exception("Failed to deliver an opted-in reminder")
                    db.mark_reminder_sent(user_id, day)
            await asyncio.sleep(300)
        await asyncio.sleep(30)
