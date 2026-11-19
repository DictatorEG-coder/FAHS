import re
import time
from datetime import datetime
from zoneinfo import ZoneInfo
from collections import defaultdict, deque
from aiogram import Router, F
from aiogram.filters import CommandStart, Command
from aiogram.types import Message, CallbackQuery
from fahs import db
from fahs.content import TIPS, SCAMS, DATA_RISKS, EMERGENCY, QUIZ, GLOSSARY
from fahs.keyboards import main_menu, back_menu, settings_menu, emergency_menu
from fahs.scanner import scan_url
from fahs.config import settings

router = Router()
URL_RE = re.compile(r"(?i)(?:(?:https?://|www\.)[^\s<>]+|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?::\d+)?(?:/[^\s<>]*)?)")
SCAN_EVENTS = defaultdict(deque)

TIP_TEXT = "سُبْحَانَ اللَّهِ وَبِحَمْدِهِ، سُبْحَانَ اللَّهِ الْعَظِيمِ\n\nاللهم صلِّ وسلم على نبينا محمد."

def welcome():
    return ("<b>فَحْص | FAHS SECURITY</b>\n"
            "<i>لا تثق... تحقّق.</i>\n\n"
            "مساعدك للتوعية الرقمية وفحص مؤشرات خطورة الروابط. "
            "أرسل رابطًا نصيًا لفحصه، أو اختر أحد الأقسام.\n\n"
            "تنبيه: لا توجد نتيجة تثبت أمان أي رابط بنسبة 100%.")

@router.message(CommandStart())
async def start(message: Message):
    db.touch_user(message.from_user.id)
    await message.answer(welcome(), reply_markup=main_menu())

@router.message(Command("help"))
async def help_cmd(message: Message):
    await message.answer("أرسل الرابط كنص عادي أو استخدم القائمة. لا ترسل كلمات مرور أو رموز تحقق أو روابط خاصة تحتوي بيانات دخول.", reply_markup=main_menu())

@router.message(Command("fahs_on"))
async def group_on(message: Message):
    if message.chat.type not in {"group", "supergroup"}:
        return
    member = await message.chat.get_member(message.from_user.id)
    if member.status not in {"administrator", "creator"}:
        await message.reply("هذا الأمر متاح لمشرفي المجموعة فقط.")
        return
    _, auto_delete = db.get_group(message.chat.id)
    db.set_group(message.chat.id, True, auto_delete)
    await message.reply("تم تفعيل فحص الروابط التي تصل إلى البوت. يعتمد الرصد على رسائل تيليجرام التي يسمح إعداد الخصوصية والصلاحيات للبوت برؤيتها.")

@router.message(Command("fahs_off"))
async def group_off(message: Message):
    if message.chat.type not in {"group", "supergroup"}:
        return
    member = await message.chat.get_member(message.from_user.id)
    if member.status not in {"administrator", "creator"}:
        await message.reply("هذا الأمر متاح لمشرفي المجموعة فقط.")
        return
    db.set_group(message.chat.id, False, False)
    await message.reply("تم إيقاف فحص روابط المجموعة.")

async def send_scan(message: Message, raw: str) -> bool:
    actor = message.from_user.id if message.from_user else message.chat.id
    now = time.monotonic()
    events = SCAN_EVENTS[actor]
    while events and now - events[0] > 60:
        events.popleft()
    if len(events) >= 8:
        await message.reply("تم بلوغ حد الفحص المؤقت. انتظر دقيقة ثم حاول مجددًا.")
        return False
    events.append(now)
    result = await scan_url(raw)
    reasons = "\n".join("• " + x for x in result["reasons"])
    host = result.get("host") or "غير متاح"
    checked_at = datetime.now(ZoneInfo("Africa/Cairo")).strftime("%Y-%m-%d %H:%M")
    redirects = max(0, len(result.get("chain", [])) - 1)
    text = (f"<b>نتيجة فحص فَحْص</b>\n"
            f"التصنيف: <b>{result['level']}</b>\n"
            f"النطاق: <code>{host}</code>\n"
            f"وقت الفحص: <code>{checked_at}</code>\n"
            f"التحويلات المرصودة: <code>{redirects}</code>\n\n"
            f"<b>المؤشرات:</b>\n{reasons}\n\n"
            "<i>هذه قراءة أولية للمؤشرات وليست ضمانًا للأمان أو حكمًا قاطعًا. لا تُدخل بياناتك في موقع لم تتحقق منه.</i>")
    if message.chat.type in {"group", "supergroup"}:
        enabled, auto_delete = db.get_group(message.chat.id)
        if enabled and auto_delete and result["level"] in {"خطر حرج", "مرتفع"}:
            try:
                await message.delete()
                await message.answer("🛑 <b>حُذف رابط يحمل مؤشرات خطورة مرتفعة.</b>\\n" + text, disable_web_page_preview=True)
                return True
            except Exception:
                await message.reply("🛑 رُصد رابط عالي الخطورة، لكن تعذر حذف الرسالة. راجع صلاحيات البوت.", disable_web_page_preview=True)
                return False
    await message.reply(text, disable_web_page_preview=True)
    return False


@router.message(Command("fahs_delete_on"))
async def group_delete_on(message: Message):
    if message.chat.type not in {"group", "supergroup"} or not message.from_user:
        return
    member = await message.chat.get_member(message.from_user.id)
    if member.status not in {"administrator", "creator"}:
        await message.reply("هذا الأمر متاح لمشرفي المجموعة فقط.")
        return
    bot_member = await message.chat.get_member((await message.bot.get_me()).id)
    if bot_member.status != "administrator" or not getattr(bot_member, "can_delete_messages", False):
        await message.reply("يجب ترقية البوت إلى مشرف ومنحه صلاحية حذف الرسائل أولًا.")
        return
    db.set_group(message.chat.id, True, True)
    await message.reply("فُعّل الحذف التلقائي للروابط المصنفة خطرًا حرجًا أو مرتفعًا. قد تحدث نتائج اشتباه خاطئة؛ ويمكن إيقافه بالأمر /fahs_delete_off.")

@router.message(Command("fahs_delete_off"))
async def group_delete_off(message: Message):
    if message.chat.type not in {"group", "supergroup"} or not message.from_user:
        return
    member = await message.chat.get_member(message.from_user.id)
    if member.status not in {"administrator", "creator"}:
        await message.reply("هذا الأمر متاح لمشرفي المجموعة فقط.")
        return
    enabled, _ = db.get_group(message.chat.id)
    db.set_group(message.chat.id, enabled, False)
    await message.reply("تم إيقاف الحذف التلقائي.")


@router.message(Command("admin"))
async def admin_stats(message: Message):
    if not message.from_user or message.from_user.id not in settings.admin_ids:
        return
    users, reminders, groups = db.stats()
    await message.answer(
        f"<b>لوحة فَحْص</b>\nالمستخدمون المسجلون: {users}\n"
        f"المشتركون في التذكير: {reminders}\nالمجموعات المفعّل بها الفحص: {groups}")

@router.message(F.text | F.caption)
async def text_router(message: Message):
    if message.chat.type in {"group", "supergroup"}:
        enabled, _ = db.get_group(message.chat.id)
        if not enabled:
            return
    source_text = message.text or message.caption or ""
    matches = URL_RE.findall(source_text)
    entities = (message.entities or []) + (message.caption_entities or [])
    matches.extend(entity.url for entity in entities if entity.type == "text_link" and entity.url)
    if not matches:
        return
    for match in matches[:3]:
        raw = match.rstrip(".,،؛!؟)]}")
        deleted = await send_scan(message, raw)
        if deleted:
            break

@router.callback_query(F.data == "home")
async def home(call: CallbackQuery):
    await call.message.edit_text(welcome(), reply_markup=main_menu())
    await call.answer()

@router.callback_query(F.data == "scan")
async def scan_prompt(call: CallbackQuery):
    await call.message.answer("أرسل الرابط كنص في رسالة منفصلة. لا ترسل رابطًا خاصًا يحتوي رموز دخول أو بيانات حساسة.")
    await call.answer()

@router.callback_query(F.data == "protect")
async def protect(call: CallbackQuery):
    text = ("<b>قواعد الحماية الأساسية</b>\\n"
    "1. استخدم كلمة مرور فريدة وطويلة لكل حساب، واحفظها في مدير موثوق.\\n"
    "2. فعّل المصادقة الثنائية، ويفضل تطبيق مصادقة أو مفتاح أمان حيث يتاح.\\n"
    "3. لا تشارك OTP أو رموز الاسترداد مع أي شخص.\\n"
    "4. افتح المواقع من التطبيق الرسمي أو اكتب العنوان بنفسك، ولا تثق بالشعار وحده.\\n"
    "5. راجع جلسات تيليجرام والبريد والحسابات المهمة، وأنهِ الجلسات غير المعروفة.\\n"
    "6. أمّن بريدك الإلكتروني؛ فهو غالبًا مفتاح استعادة بقية الحسابات.\\n"
    "7. فعّل تنبيهات العمليات البنكية، واتصل بالبنك عبر رقمه الرسمي عند الشك.\\n"
    "8. حدّث الهاتف والكمبيوتر والتطبيقات، وثبّت البرامج من المتاجر والمواقع الرسمية.\\n"
    "9. لا تمنح صلاحيات إمكانية الوصول أو إدارة الجهاز لتطبيق غير موثوق.\\n"
    "10. استخدم قفل شاشة قويًا، ونسخًا احتياطية دورية، وشبكة Wi-Fi محمية.\\n"
    "11. لا تمسح QR أو تفتح رابطًا مختصرًا قبل رؤية الوجهة والتحقق منها.\\n"
    "12. علّم الأطفال ألا يشاركوا الموقع أو الصور أو رموز التحقق مع الغرباء.")
    await call.message.edit_text(text, reply_markup=back_menu())
    await call.answer()

@router.callback_query(F.data.in_({"scams","ai_scams","data"}))
async def library(call: CallbackQuery):
    if call.data == "scams":
        data = SCAMS
        title = "موسوعة أساليب الاحتيال"
    elif call.data == "ai_scams":
        data = {"استنساخ الصوت والفيديو": SCAMS["الاحتيال بالذكاء الاصطناعي"],
                "التزييف العميق": "قد تُنشأ صور أو مقاطع تبدو حقيقية. لا تعتمد على المظهر وحده؛ اطلب تحققًا مستقلًا من الشخص أو الجهة.",
                "الرسائل الآلية": "قد تنتج رسائل مقنعة ومخصصة. افحص الطلب والمرسل والرابط بدل الحكم على جودة اللغة."}
        title = "الاحتيال المدعوم بالذكاء الاصطناعي"
    else:
        data = DATA_RISKS
        title = "مخاطر مشاركة البيانات"
    body = "<b>" + title + "</b>\n\n" + "\n\n".join(f"<b>{k}</b>\n{v}" for k,v in data.items())
    await call.message.edit_text(body, reply_markup=back_menu())
    await call.answer()

@router.callback_query(F.data == "emergency")
async def emergency(call: CallbackQuery):
    await call.message.edit_text("اختر ما حدث لك للحصول على خطوات أولية:", reply_markup=emergency_menu())
    await call.answer()

@router.callback_query(F.data.startswith("em:"))
async def emergency_detail(call: CallbackQuery):
    keys = {"otp": "شاركت رمز تحقق", "password": "أدخلت كلمة المرور في صفحة مزيفة", "money": "حوّلت أموالًا", "app": "ثبّت تطبيقًا مشبوهًا", "extortion": "تعرضت للابتزاز", "telegram": "فقدت حساب تيليجرام", "leak": "تسربت بياناتي"}
    key = keys.get(call.data[3:], "")
    body = EMERGENCY.get(key, "أوقف التفاعل، واحتفظ بالأدلة، وتواصل مع الجهة الرسمية المعنية.")
    await call.message.edit_text(f"<b>خطوات أولية</b>\n{body}\n\nلا تحذف الأدلة، وتواصل مع البنك أو المنصة أو الجهات الرسمية عبر قنواتها الموثقة.", reply_markup=back_menu())
    await call.answer()

@router.callback_query(F.data == "tip")
async def tip(call: CallbackQuery):
    import random
    await call.message.edit_text("💡 <b>نصيحة اليوم</b>\n" + random.choice(TIPS), reply_markup=back_menu())
    await call.answer()

@router.callback_query(F.data == "about")
async def about(call: CallbackQuery):
    await call.message.edit_text(
        "<b>عن فَحْص</b>\nبوت توعوي يساعدك على فهم مؤشرات خطورة الروابط وأساليب الاحتيال الرقمي. "
        "لا يفحص الصور أو الملفات، ولا يضمن اكتشاف كل تهديد.\n\n"
        "إذا أفادك فَحْص، فلا تنسَ الدعاء لمن ساهم في إنشائه: اللهم بارك في هذا العمل، واجعله نافعًا للناس.",
        reply_markup=back_menu())
    await call.answer()

@router.callback_query(F.data == "settings")
async def settings_page(call: CallbackQuery):
    await call.message.edit_text("التذكيرات الإيمانية اختيارية ويمكن إيقافها في أي وقت.", reply_markup=settings_menu(db.get_reminders(call.from_user.id), db.get_reminder_interval(call.from_user.id)))
    await call.answer()

@router.callback_query(F.data == "reminders_toggle")
async def reminders_toggle(call: CallbackQuery):
    enabled = not db.get_reminders(call.from_user.id)
    db.set_reminders(call.from_user.id, enabled)
    note = "فُعّلت التذكيرات الاختيارية." if enabled else "أُوقفت التذكيرات."
    await call.message.edit_text(note + "\nتصل التذكيرات وفق التكرار المحدد، ويمكنك إيقافها من هنا.", reply_markup=settings_menu(enabled, db.get_reminder_interval(call.from_user.id)))
    await call.answer()

@router.callback_query(F.data == "quiz")
async def quiz(call: CallbackQuery):
    import random
    index = random.randrange(len(QUIZ))
    question, options, correct, explanation = QUIZ[index]
    from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
    rows = [[InlineKeyboardButton(text=opt, callback_data=f"q:{index}:{i}") for i,opt in enumerate(options)]]
    await call.message.edit_text("🎯 <b>اختبر نفسك</b>\n" + question, reply_markup=InlineKeyboardMarkup(inline_keyboard=rows))
    await call.answer()

@router.callback_query(F.data.startswith("q:"))
async def quiz_answer(call: CallbackQuery):
    _, q, a = call.data.split(":")
    question, options, correct, explanation = QUIZ[int(q)]
    result = "إجابة صحيحة." if int(a) == correct else "ليست الإجابة الصحيحة."
    await call.message.edit_text(f"{result}\n{explanation}", reply_markup=back_menu())
    await call.answer()

@router.callback_query(F.data == "privacy")
async def privacy(call: CallbackQuery):
    await call.message.edit_text(
        "<b>سياسة الخصوصية المختصرة</b>\n"
        "يحتفظ فَحْص بمعرّف تيليجرام وإعدادات التذكير، ومعرّف المجموعة وإعدادات حمايتها عند تفعيلها. "
        "يعالج نص الرابط مؤقتًا ولا يحفظه افتراضيًا. وفي المجموعات قد يحذف الرسائل المصنفة خطرًا حرجًا أو مرتفعًا إذا فعّل المشرف ذلك. لا ترسل روابط خاصة أو رموز وصول. "
        "قد يتصل الفاحص بالنطاق العام للتحقق من التحويلات، ولا يرسل الرابط إلى خدمة سمعة خارجية. "
        "يمكنك إيقاف التذكيرات في أي وقت. التفاصيل في ملف PRIVACY.md بالمستودع.",
        reply_markup=back_menu())
    await call.answer()


@router.callback_query(F.data == "glossary")
async def glossary(call: CallbackQuery):
    body = "<b>قاموس الأمن الرقمي</b>\n\n" + "\n\n".join(
        f"<b>{term}</b>\n{meaning}" for term, meaning in GLOSSARY.items())
    await call.message.edit_text(body, reply_markup=back_menu())
    await call.answer()

@router.callback_query(F.data == "reminder_interval_toggle")
async def reminder_interval_toggle(call: CallbackQuery):
    current = db.get_reminder_interval(call.from_user.id)
    updated = 2 if current == 1 else 1
    db.set_reminder_interval(call.from_user.id, updated)
    label = "كل يومين" if updated == 2 else "يوميًا"
    await call.message.edit_text(
        f"تم ضبط التذكير {label}. موعد الإرسال الحالي 10:00 صباحًا بتوقيت القاهرة.",
        reply_markup=settings_menu(db.get_reminders(call.from_user.id), updated))
    await call.answer()
