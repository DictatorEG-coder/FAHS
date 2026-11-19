import re
from aiogram import Router, F
from aiogram.filters import CommandStart, Command
from aiogram.types import Message, CallbackQuery
from fahs import db
from fahs.content import TIPS, SCAMS, DATA_RISKS, EMERGENCY, QUIZ, GLOSSARY
from fahs.keyboards import main_menu, back_menu, settings_menu, emergency_menu
from fahs.scanner import scan_url
from fahs.config import settings

router = Router()
URL_RE = re.compile(r"(?i)(?:(?:https?://|www\\.)[^\\s<>]+|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,}(?::\\d+)?(?:/[^\\s<>]*)?)")
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
    db.set_group(message.chat.id, True)
    await message.reply("تم تفعيل فحص الروابط التي تصل إلى البوت. يعتمد الرصد على رسائل تيليجرام التي يسمح إعداد الخصوصية والصلاحيات للبوت برؤيتها.")

@router.message(Command("fahs_off"))
async def group_off(message: Message):
    if message.chat.type not in {"group", "supergroup"}:
        return
    member = await message.chat.get_member(message.from_user.id)
    if member.status not in {"administrator", "creator"}:
        await message.reply("هذا الأمر متاح لمشرفي المجموعة فقط.")
        return
    db.set_group(message.chat.id, False)
    await message.reply("تم إيقاف فحص روابط المجموعة.")

async def send_scan(message: Message, raw: str):
    result = await scan_url(raw)
    reasons = "\n".join("• " + x for x in result["reasons"])
    host = result.get("host") or "غير متاح"
    text = (f"<b>نتيجة فحص فَحْص</b>\n"
            f"التصنيف: <b>{result['level']}</b>\n"
            f"النطاق: <code>{host}</code>\n\n"
            f"<b>المؤشرات:</b>\n{reasons}\n\n"
            "<i>هذه قراءة أولية للمؤشرات وليست ضمانًا للأمان أو حكمًا قاطعًا. لا تُدخل بياناتك في موقع لم تتحقق منه.</i>")
    await message.reply(text, disable_web_page_preview=True)


@router.message(Command("admin"))
async def admin_stats(message: Message):
    if not message.from_user or message.from_user.id not in settings.admin_ids:
        return
    users, reminders, groups = db.stats()
    await message.answer(
        f"<b>لوحة فَحْص</b>\nالمستخدمون المسجلون: {users}\n"
        f"المشتركون في التذكير: {reminders}\nالمجموعات المفعّل بها الفحص: {groups}")

@router.message(F.text)
async def text_router(message: Message):
    if message.chat.type in {"group", "supergroup"}:
        enabled, _ = db.get_group(message.chat.id)
        if not enabled:
            return
    matches = URL_RE.findall(message.text or "")
    if not matches:
        return
    raw = matches[0].rstrip(".,،؛!؟)]}")
    await send_scan(message, raw)

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
    text = ("<b>قواعد الحماية الأساسية</b>\n"
    "1. استخدم كلمة مرور فريدة لكل خدمة ومدير كلمات مرور موثوقًا.\n"
    "2. فعّل المصادقة الثنائية، ولا تشارك OTP مطلقًا.\n"
    "3. افتح المواقع من التطبيق الرسمي أو اكتب العنوان بنفسك.\n"
    "4. راجع الجلسات النشطة وألغِ غير المعروف منها.\n"
    "5. حدّث الهاتف والكمبيوتر والتطبيقات باستمرار.\n"
    "6. لا تثبّت APK من مصدر مجهول ولا تمنح صلاحيات عشوائية.\n"
    "7. تحقّق من طلبات المال عبر قناة اتصال ثانية.")
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
    key = call.data[3:]
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
    await call.message.edit_text("التذكيرات الإيمانية اختيارية ويمكن إيقافها في أي وقت.", reply_markup=settings_menu(db.get_reminders(call.from_user.id)))
    await call.answer()

@router.callback_query(F.data == "reminders_toggle")
async def reminders_toggle(call: CallbackQuery):
    enabled = not db.get_reminders(call.from_user.id)
    db.set_reminders(call.from_user.id, enabled)
    note = "فُعّلت التذكيرات الاختيارية." if enabled else "أُوقفت التذكيرات."
    await call.message.edit_text(note + "\nتصل التذكيرات مرة يوميًا في موعد ثابت، ويمكنك إيقافها من هنا.", reply_markup=settings_menu(enabled))
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
        "يحتفظ فَحْص بمعرّف تيليجرام وإعدادات التذكير الاختيارية فقط لتقديم الخدمة. "
        "لا يحفظ نصوص الروابط المفحوصة افتراضيًا. لا ترسل روابط خاصة أو رموز وصول. "
        "قد يتصل الفاحص بالنطاق العام للتحقق من التحويلات، ولا يرسل الرابط إلى خدمة سمعة خارجية. "
        "يمكنك إيقاف التذكيرات في أي وقت. التفاصيل في ملف PRIVACY.md بالمستودع.",
        reply_markup=back_menu())
    await call.answer()


@router.callback_query(F.data == "glossary")
async def glossary(call: CallbackQuery):
    body = "<b>قاموس الأمن الرقمي</b>\\n\\n" + "\\n\\n".join(
        f"<b>{term}</b>\\n{meaning}" for term, meaning in GLOSSARY.items())
    await call.message.edit_text(body, reply_markup=back_menu())
    await call.answer()
