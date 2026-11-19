import asyncio
import logging
from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.types import BotCommand
from fahs.config import settings
from fahs.db import init_db
from fahs.handlers import router
from fahs.reminders import reminder_loop

async def main():
    if not settings.bot_token:
        raise RuntimeError("BOT_TOKEN is missing. Copy .env.example to .env and configure it.")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    init_db()
    bot = Bot(settings.bot_token, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    await bot.set_my_commands([
        BotCommand(command="start", description="القائمة الرئيسية"),
        BotCommand(command="help", description="طريقة الاستخدام"),
        BotCommand(command="fahs_on", description="تفعيل فحص روابط المجموعة للمشرفين"),
        BotCommand(command="fahs_off", description="إيقاف فحص روابط المجموعة للمشرفين"),
        BotCommand(command="admin", description="إحصاءات المشغّل"),
    ])
    dp = Dispatcher()
    dp.include_router(router)
    task = asyncio.create_task(reminder_loop(bot))
    try:
        await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())
    finally:
        task.cancel()
        await bot.session.close()

if __name__ == "__main__":
    asyncio.run(main())
