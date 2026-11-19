import asyncio
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
    # Optional subscription only. One quiet reminder at 10:00 Africa/Cairo.
    while True:
        now = datetime.now(ZoneInfo("Africa/Cairo"))
        if now.hour == 10 and now.minute < 5:
            for user_id in db.reminder_users():
                try:
                    await bot.send_message(user_id, MESSAGES[now.timetuple().tm_yday % len(MESSAGES)])
                except Exception:
                    pass
            await asyncio.sleep(300)
        await asyncio.sleep(30)
