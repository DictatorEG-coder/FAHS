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
        BotCommand(command="my_id", description="عرض معرّفك في تيليجرام"),
        BotCommand(command="fahs_on", description="تفعيل فحص روابط المجموعة للمشرفين"),
        BotCommand(command="fahs_off", description="إيقاف فحص روابط المجموعة للمشرفين"),
        BotCommand(command="fahs_status", description="عرض حالة حماية المجموعة"),
        BotCommand(command="fahs_delete_on", description="تفعيل حذف الروابط عالية الخطورة"),
        BotCommand(command="fahs_delete_off", description="إيقاف الحذف التلقائي"),
        BotCommand(command="fahs_allow", description="استثناء نطاق في المجموعة"),
        BotCommand(command="fahs_unallow", description="إزالة استثناء نطاق"),
        BotCommand(command="fahs_allowlist", description="عرض نطاقات الاستثناء"),
        BotCommand(command="admin", description="إحصاءات المشغّل"),
        BotCommand(command="delete_my_data", description="حذف بياناتك من قاعدة البوت"),
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
