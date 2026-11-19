import re
import asyncio
import uuid
from html import escape
import ipaddress
from urllib.parse import urlsplit
import time
from datetime import datetime
from zoneinfo import ZoneInfo
from collections import OrderedDict, deque
from aiogram import Router, F
from aiogram.filters import CommandStart, Command
from aiogram.types import Message, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton
from fahs import db
from fahs.content import TIPS, SCAMS, AI_SCAMS, DATA_RISKS, EMERGENCY, QUIZ, GLOSSARY
from fahs.keyboards import main_menu, back_menu, settings_menu, emergency_menu, scan_result_menu
from fahs.scanner import scan_url, _normalise
from fahs.config import settings

router = Router()
URL_RE = re.compile(r"(?i)(?:(?:https?://|www\.)[^\s<>]+|(?<![@a-z0-9._-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?::\d+)?(?:/[^\s<>]*)?|(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s<>]*)?)")
# Bounded in-memory rate limits: per sender and across the whole bot process.
SCAN_EVENTS = OrderedDict()
GLOBAL_SCAN_EVENTS = deque()
MAX_RATE_BUCKETS = 10_000
USER_SCAN_LIMIT = 8
GLOBAL_SCAN_LIMIT = 120
RATE_WINDOW_SECONDS = 60

def _trim_events(events: deque, now: float) -> None:
    while events and now - events[0] >= RATE_WINDOW_SECONDS:
        events.popleft()

def _allow_scan(actor: int, now: float | None = None) -> bool:
    now = time.monotonic() if now is None else now
    _trim_events(GLOBAL_SCAN_EVENTS, now)
    if len(GLOBAL_SCAN_EVENTS) >= GLOBAL_SCAN_LIMIT:
        return False

    events = SCAN_EVENTS.pop(actor, deque())
    _trim_events(events, now)
    if len(events) >= USER_SCAN_LIMIT:
        SCAN_EVENTS[actor] = events
        while len(SCAN_EVENTS) > MAX_RATE_BUCKETS:
            SCAN_EVENTS.popitem(last=False)
        return False

    events.append(now)
    SCAN_EVENTS[actor] = events
    while len(SCAN_EVENTS) > MAX_RATE_BUCKETS:
        SCAN_EVENTS.popitem(last=False)
    GLOBAL_SCAN_EVENTS.append(now)
    return True

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

@router.message(Command("my_id"))
async def my_id(message: Message):
    if message.chat.type != "private" or not message.from_user:
        await message.reply("استخدم هذا الأمر في المحادثة الخاصة مع فَحْص.")
        return
    await message.answer(f"معرّف تيليجرام الخاص بك: <code>{message.from_user.id}</code>\nاستخدمه في متغير ADMIN_IDS إذا كنت مشغّل البوت.")


@router.message(Command("help"))
async def help_cmd(message: Message):
    await message.answer("أرسل الرابط كنص عادي أو استخدم القائمة. لا ترسل كلمات مرور أو رموز تحقق أو روابط خاصة تحتوي بيانات دخول.", reply_markup=main_menu())

@router.message(Command("fahs_on"))
async def group_on(message: Message):
    if message.chat.type not in {"group", "supergroup"} or not message.from_user:
        return
    member = await message.chat.get_member(message.from_user.id)
    if member.status not in {"administrator", "creator"}:
        await message.reply("هذا الأمر متاح لمشرفي المجموعة فقط.")
        return
    _, auto_delete = db.get_group(message.chat.id)
    db.set_group(message.chat.id, True, auto_delete)
    await message.reply("تم تفعيل فحص الروابط التي تصل إلى البوت. يعتمد الرصد على رسائل تيليجرام التي يسمح إعداد الخصوصية والصلاحيات للبوت برؤيتها.")


def _group_admin(message: Message) -> bool:
    return bool(message.from_user and message.chat.type in {"group", "supergroup"})

async def _require_group_admin(message: Message) -> bool:
    if not _group_admin(message):
        return False
    member = await message.chat.get_member(message.from_user.id)
    if member.status not in {"administrator", "creator"}:
        await message.reply("هذا الأمر متاح لمشرفي المجموعة فقط.")
        return False
    return True

def _allowlist_domain_arg(message: Message) -> str | None:
    raw = (message.text or "").split(maxsplit=1)
    if len(raw) != 2:
        return None
    value = raw[1].strip().lower().rstrip(".")
    if "://" in value or any(ch in value for ch in "/\\@?#:") or "*" in value:
        return None
    try:
        domain = value.encode("idna").decode("ascii")
        ipaddress.ip_address(domain)
    except UnicodeError:
        return None
    except ValueError:
        pass
    else:
        return None
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2:
        return None
    if any(not re.fullmatch(r"(?!-)[a-z0-9-]{1,63}(?<!-)", label) for label in labels):
        return None
    return domain

@router.message(Command("fahs_allow"))
async def group_allow(message: Message):
    if not await _require_group_admin(message):
        return
    domain = _allowlist_domain_arg(message)
    if not domain:
        await message.reply("استخدم الأمر هكذا: /fahs_allow example.com — اكتب اسم نطاق فقط دون رابط أو مسار.")
        return
    if not db.add_group_domain(message.chat.id, domain):
        await message.reply("وصلت المجموعة إلى الحد الأقصى وهو 100 نطاق.")
        return
    await message.reply(f"أُضيف <code>{escape(domain)}</code> إلى قائمة الاستثناءات. ستُتجاوز روابط هذا النطاق ونطاقاته الفرعية في فحص المجموعة.")

@router.message(Command("fahs_unallow"))
async def group_unallow(message: Message):
    if not await _require_group_admin(message):
        return
    domain = _allowlist_domain_arg(message)
    if not domain:
        await message.reply("استخدم الأمر هكذا: /fahs_unallow example.com")
        return
    removed = db.remove_group_domain(message.chat.id, domain)
    await message.reply("حُذف النطاق من قائمة الاستثناءات." if removed else "هذا النطاق غير موجود في قائمة الاستثناءات.")

@router.message(Command("fahs_allowlist"))
async def group_allowlist(message: Message):
    if not await _require_group_admin(message):
        return
    domains = db.list_group_domains(message.chat.id)
    if not domains:
        await message.reply("قائمة الاستثناءات فارغة.")
        return
    for offset in range(0, len(domains), 12):
        body = "\n".join(f"• <code>{escape(domain)}</code>" for domain in domains[offset:offset + 12])
        title = "<b>النطاقات المستثناة في هذه المجموعة</b>\n" if offset == 0 else ""
        await message.reply(title + body)

@router.message(Command("fahs_status"))
async def group_status(message: Message):
    if not await _require_group_admin(message):
        return
    enabled, auto_delete = db.get_group(message.chat.id)
    domains = db.list_group_domains(message.chat.id)
    scan_label = "مفعّل" if enabled else "متوقف"
    delete_label = "مفعّل" if auto_delete else "متوقف"
    await message.reply(
        "<b>حالة حماية فَحْص في هذه المجموعة</b>\n"
        f"فحص الروابط: <b>{scan_label}</b>\n"
        f"الحذف التلقائي: <b>{delete_label}</b>\n"
        f"النطاقات المستثناة: <b>{len(domains)} / 100</b>"
    )


@router.message(Command("fahs_off"))
async def group_off(message: Message):
    if message.chat.type not in {"group", "supergroup"} or not message.from_user:
        return
    member = await message.chat.get_member(message.from_user.id)
    if member.status not in {"administrator", "creator"}:
        await message.reply("هذا الأمر متاح لمشرفي المجموعة فقط.")
        return
    db.set_group(message.chat.id, False, False)
    await message.reply("تم إيقاف فحص روابط المجموعة.")

def _extract_message_urls(message: Message) -> list[str]:
    """Extract up to three unique visible or embedded text links without fetching them."""
    source_text = message.text or message.caption or ""
    entities = (message.entities or []) + (message.caption_entities or [])
    matches = URL_RE.findall(source_text)
    matches.extend(entity.url for entity in entities if entity.type == "text_link" and entity.url)

    unique = []
    seen = set()
    for match in matches:
        raw = match.rstrip(".,،؛!؟)]}")
        if not raw:
            continue
        try:
            key = _normalise(raw)
        except (ValueError, UnicodeError):
            key = raw.strip().lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(raw)
        if len(unique) == 3:
            break
    return unique


async def send_scan(message: Message, raw: str) -> bool:
    actor = message.from_user.id if message.from_user else message.chat.id
    if not _allow_scan(actor):
        await message.reply("تم بلوغ حد الفحص المؤقت. انتظر دقيقة ثم حاول مجددًا.", reply_markup=scan_result_menu())
        return False
    result = await scan_url(raw)
    db.record_scan(result["level"])
    reasons = "\n".join("• " + escape(x) for x in result["reasons"])
    host = escape(result.get("host") or "غير متاح")
    source = escape(result.get("source") or "تحليل محلي")
    checked_sources = "، ".join(escape(x) for x in result.get("sources_checked", [])) or "لا توجد مصادر خارجية مفعّلة"
    unavailable_sources = "، ".join(escape(x) for x in result.get("sources_unavailable", []))
    checked_at = datetime.now(ZoneInfo("Africa/Cairo")).strftime("%Y-%m-%d %H:%M")
    redirects = max(0, len(result.get("chain", [])) - 1)
    text = (f"<b>نتيجة فحص فَحْص</b>\n"
            f"التصنيف: <b>{result['level']}</b>\n"
            f"النطاق: <code>{host}</code>\n"
            f"مصدر المطابقة: <code>{source}</code>\n"
            f"مصادر السمعة المتاحة: <code>{checked_sources}</code>\n"
            + (f"مصادر تعذر الوصول إليها: <code>{unavailable_sources}</code>\n" if unavailable_sources else "")
            + f"وقت الفحص: <code>{checked_at}</code>\n"
            f"التحويلات المرصودة: <code>{redirects}</code>\n\n"
            f"<b>المؤشرات:</b>\n{reasons}\n\n"
            "<i>هذه قراءة أولية للمؤشرات وليست ضمانًا للأمان أو حكمًا قاطعًا. لا تُدخل بياناتك في موقع لم تتحقق منه.</i>")
    if message.chat.type in {"group", "supergroup"}:
        enabled, auto_delete = db.get_group(message.chat.id)
        if enabled and auto_delete and message.text is not None and result["level"] in {"خطر حرج", "مرتفع"}:
            try:
                await message.delete()
                await message.answer("🛑 <b>حُذف رابط يحمل مؤشرات خطورة مرتفعة.</b>\n" + text, reply_markup=scan_result_menu(), disable_web_page_preview=True)
                return True
            except Exception:
                await message.reply("🛑 رُصد رابط عالي الخطورة، لكن تعذر حذف الرسالة. راجع صلاحيات البوت.", reply_markup=scan_result_menu(), disable_web_page_preview=True)
                return False
    await message.reply(text, reply_markup=scan_result_menu(), disable_web_page_preview=True)
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



@router.message(Command("delete_my_data"))
async def delete_my_data(message: Message):
    if message.chat.type != "private":
        await message.reply("نفّذ هذا الأمر في المحادثة الخاصة مع فَحْص حفاظًا على خصوصيتك.")
        return
    if message.from_user:
        db.delete_user(message.from_user.id)
        await message.answer("حُذفت إعداداتك ومعرّفك من قاعدة بيانات فَحْص. لا يشمل ذلك سجل رسائل تيليجرام أو بيانات تحتفظ بها المنصة.")

def _admin_keyboard():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📝 إدارة المحتوى", callback_data="admin_content")],
        [InlineKeyboardButton(text="📣 إذاعة رسالة", callback_data="admin_broadcast")],
    ])


def _is_admin(user_id: int | None) -> bool:
    return bool(user_id and user_id in settings.admin_ids)


@router.message(Command("admin"))
async def admin_stats(message: Message):
    if not message.from_user or not _is_admin(message.from_user.id):
        return
    users, reminders, groups, scans, levels = db.stats()
    level_lines = "\n".join(f"• {escape(level)}: {count}" for level, count in sorted(levels.items()))
    await message.answer(
        f"<b>لوحة فَحْص</b>\nالمستخدمون المسجلون: {users}\n"
        f"المشتركون في التذكير: {reminders}\nالمجموعات المفعّل بها الفحص: {groups}\n"
        f"إجمالي الفحوصات: {scans}\n<b>توزيع النتائج:</b>\n{level_lines or 'لا توجد فحوصات بعد'}",
        reply_markup=_admin_keyboard())


ADMIN_STATES = {}
PENDING_BROADCASTS = {}


def _admin_category_keyboard():
    rows = [[InlineKeyboardButton(text=label, callback_data=f"admin_cat:{key}")]
            for key, label in CONTENT_CATEGORIES.items()]
    rows.append([InlineKeyboardButton(text="⬅️ لوحة الإدارة", callback_data="admin_panel")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def _admin_items_keyboard(category: str, items):
    rows = [[InlineKeyboardButton(text=f"{i + 1}. {item[1][:42]}", callback_data=f"admin_pick:{category}:{i}")]
            for i, item in enumerate(items)]
    rows.append([InlineKeyboardButton(text="➕ إضافة محتوى", callback_data=f"admin_add:{category}")])
    rows.append([InlineKeyboardButton(text="⬅️ الأقسام", callback_data="admin_content")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


@router.callback_query(F.data == "admin_panel")
async def admin_panel(call: CallbackQuery):
    if not _is_admin(call.from_user.id):
        await call.answer("غير مصرح.", show_alert=True)
        return
    await call.message.edit_text("<b>لوحة إدارة فَحْص</b>\nاختر العملية:", reply_markup=_admin_keyboard())
    await call.answer()


@router.callback_query(F.data == "admin_content")
async def admin_content(call: CallbackQuery):
    if not _is_admin(call.from_user.id):
        await call.answer("غير مصرح.", show_alert=True)
        return
    await call.message.edit_text("<b>إدارة المحتوى</b>\nاختر القسم الذي تريد تحديثه:", reply_markup=_admin_category_keyboard())
    await call.answer()


@router.callback_query(F.data.startswith("admin_cat:"))
async def admin_content_category(call: CallbackQuery):
    if not _is_admin(call.from_user.id):
        await call.answer("غير مصرح.", show_alert=True)
        return
    category = call.data.split(":", 1)[1]
    if category not in CONTENT_CATEGORIES:
        await call.answer("قسم غير معروف.", show_alert=True)
        return
    items = _catalog_items(category)
    await call.message.edit_text(
        f"<b>{escape(CONTENT_CATEGORIES[category])}</b>\nعدد العناصر: {len(items)}\nاختر عنصرًا لتعديله أو حذفه:",
        reply_markup=_admin_items_keyboard(category, items))
    await call.answer()


@router.callback_query(F.data.startswith("admin_pick:"))
async def admin_content_pick(call: CallbackQuery):
    if not _is_admin(call.from_user.id):
        await call.answer("غير مصرح.", show_alert=True)
        return
    try:
        _, category, raw_index = call.data.split(":")
        item = _catalog_items(category)[int(raw_index)]
    except (ValueError, IndexError):
        await call.answer("العنصر غير متاح.", show_alert=True)
        return
    key, title, body = item
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✏️ تعديل", callback_data=f"admin_edit:{category}:{raw_index}")],
        [InlineKeyboardButton(text="🗑️ حذف", callback_data=f"admin_del:{category}:{raw_index}")],
        [InlineKeyboardButton(text="⬅️ رجوع", callback_data=f"admin_cat:{category}")],
    ])
    preview = body[:2600] + ("…" if len(body) > 2600 else "")
    await call.message.edit_text(f"<b>{escape(title)}</b>\n\n{escape(preview)}", reply_markup=keyboard)
    await call.answer()


@router.callback_query(F.data.startswith("admin_add:"))
async def admin_content_add(call: CallbackQuery):
    if not _is_admin(call.from_user.id):
        await call.answer("غير مصرح.", show_alert=True)
        return
    category = call.data.split(":", 1)[1]
    if category not in CONTENT_CATEGORIES:
        await call.answer("قسم غير معروف.", show_alert=True)
        return
    if len(_catalog_items(category)) >= 80:
        await call.answer("وصل القسم إلى الحد الأقصى وهو 80 عنصرًا.", show_alert=True)
        return
    ADMIN_STATES[call.from_user.id] = {"mode": "content_add", "category": category}
    await call.message.answer(
        "أرسل المحتوى في رسالة واحدة بهذا التنسيق:\n"
        "<code>العنوان في السطر الأول\nثم اكتب الشرح كاملًا في الأسطر التالية</code>\n"
        "الحد الأقصى للعنوان 90 حرفًا وللمحتوى 3500 حرف. أرسل /cancel للإلغاء.")
    await call.answer()


@router.callback_query(F.data.startswith("admin_edit:"))
async def admin_content_edit(call: CallbackQuery):
    if not _is_admin(call.from_user.id):
        await call.answer("غير مصرح.", show_alert=True)
        return
    try:
        _, category, raw_index = call.data.split(":")
        key, title, body = _catalog_items(category)[int(raw_index)]
    except (ValueError, IndexError):
        await call.answer("العنصر غير متاح.", show_alert=True)
        return
    ADMIN_STATES[call.from_user.id] = {"mode": "content_edit", "category": category, "item_key": key}
    await call.message.answer(
        f"أرسل النسخة الجديدة من «{escape(title)}» بالتنسيق نفسه: العنوان في السطر الأول ثم المحتوى.\n"
        "أرسل /cancel للإلغاء.")
    await call.answer()


@router.callback_query(F.data.startswith("admin_del:"))
async def admin_content_delete(call: CallbackQuery):
    if not _is_admin(call.from_user.id):
        await call.answer("غير مصرح.", show_alert=True)
        return
    try:
        _, category, raw_index = call.data.split(":")
        key, title, _ = _catalog_items(category)[int(raw_index)]
    except (ValueError, IndexError):
        await call.answer("العنصر غير متاح.", show_alert=True)
        return
    db.hide_content_item(category, key)
    items = _catalog_items(category)
    await call.message.edit_text(
        f"حُذف «{escape(title)}» من العرض العام. يمكنك إضافة محتوى بديل في القسم.",
        reply_markup=_admin_items_keyboard(category, items))
    await call.answer("تم إخفاء العنصر.")


@router.callback_query(F.data == "admin_broadcast")
async def admin_broadcast_start(call: CallbackQuery):
    if not _is_admin(call.from_user.id):
        await call.answer("غير مصرح.", show_alert=True)
        return
    ADMIN_STATES[call.from_user.id] = {"mode": "broadcast"}
    await call.message.answer(
        "أرسل الآن الرسالة التي تريد إذاعتها. يمكنك إرسال نص أو صورة أو فيديو أو ملف أو رسالة بتنسيقها. "
        "سأعرض معاينة أولًا ولن تُرسل إلى أحد قبل تأكيدك.\nأرسل /cancel للإلغاء.")
    await call.answer()


@router.message(lambda message: bool(message.chat.type == "private" and message.from_user and message.from_user.id in ADMIN_STATES))
async def admin_state_input(message: Message):
    user_id = message.from_user.id
    state = ADMIN_STATES.get(user_id)
    if not state or message.chat.type != "private":
        return
    if message.text and message.text.strip() == "/cancel":
        ADMIN_STATES.pop(user_id, None)
        await message.answer("أُلغيت العملية.", reply_markup=_admin_keyboard())
        return
    if state["mode"] in {"content_add", "content_edit"}:
        if not message.text:
            await message.answer("أرسل المحتوى كنص، مع العنوان في السطر الأول.")
            return
        parts = message.text.strip().split("\n", 1)
        title = parts[0].strip()
        body = parts[1].strip() if len(parts) > 1 else ""
        max_body = 500 if state["category"] == "glossary" else 3500
        if not title or not body or len(title) > 90 or len(body) > max_body:
            await message.answer(f"التنسيق غير صحيح. يلزم عنوان لا يتجاوز 90 حرفًا، ثم سطر جديد، ومحتوى من 1 إلى {max_body} حرف.")
            return
        key = state.get("item_key") or uuid.uuid4().hex
        db.save_content_item(state["category"], key, title, body)
        category = state["category"]
        ADMIN_STATES.pop(user_id, None)
        await message.answer("حُفظ المحتوى. سيظهر التحديث فورًا للمستخدمين دون تحديث محرك فحص الروابط.",
                             reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                                 [InlineKeyboardButton(text="إدارة القسم", callback_data=f"admin_cat:{category}")],
                                 [InlineKeyboardButton(text="لوحة الإدارة", callback_data="admin_panel")],
                             ]))
        return
    if state["mode"] == "broadcast":
        PENDING_BROADCASTS[user_id] = (message.chat.id, message.message_id)
        ADMIN_STATES.pop(user_id, None)
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="✅ تأكيد الإذاعة للجميع", callback_data="broadcast_confirm")],
            [InlineKeyboardButton(text="❌ إلغاء", callback_data="broadcast_cancel")],
        ])
        await message.answer("هذه معاينة للرسالة. لن يتم الإرسال إلا بعد الضغط على تأكيد.")
        await message.copy_to(chat_id=message.chat.id)
        await message.answer(f"عدد المستخدمين المسجلين حاليًا: {len(db.list_users())}\nهل تريد إرسال هذه الرسالة؟", reply_markup=keyboard)


@router.callback_query(F.data == "broadcast_cancel")
async def broadcast_cancel(call: CallbackQuery):
    if not _is_admin(call.from_user.id):
        await call.answer("غير مصرح.", show_alert=True)
        return
    PENDING_BROADCASTS.pop(call.from_user.id, None)
    await call.message.edit_text("أُلغيت الإذاعة.")
    await call.answer()


@router.callback_query(F.data == "broadcast_confirm")
async def broadcast_confirm(call: CallbackQuery):
    if not _is_admin(call.from_user.id):
        await call.answer("غير مصرح.", show_alert=True)
        return
    pending = PENDING_BROADCASTS.pop(call.from_user.id, None)
    if not pending:
        await call.answer("لا توجد إذاعة معلقة.", show_alert=True)
        return
    source_chat, source_message = pending
    await call.answer("بدأت الإذاعة.")
    recipients = db.list_users()
    sent = failed = 0
    status = await call.message.edit_text(f"بدأت الإذاعة إلى {len(recipients)} مستخدم...")
    for user_id in recipients:
        try:
            await call.bot.copy_message(chat_id=user_id, from_chat_id=source_chat, message_id=source_message)
            sent += 1
        except Exception as exc:
            retry_after = getattr(exc, "retry_after", None)
            if retry_after:
                await asyncio.sleep(min(float(retry_after) + 1, 60))
                try:
                    await call.bot.copy_message(chat_id=user_id, from_chat_id=source_chat, message_id=source_message)
                    sent += 1
                except Exception:
                    failed += 1
            else:
                failed += 1
        await asyncio.sleep(0.05)
    await status.edit_text(
        f"<b>انتهت الإذاعة</b>\nإجمالي المستلمين: {len(recipients)}\n"
        f"نجح الإرسال: {sent}\nتعذر الإرسال: {failed}")


@router.message(Command("cancel"))
async def admin_cancel_command(message: Message):
    if message.from_user and _is_admin(message.from_user.id):
        ADMIN_STATES.pop(message.from_user.id, None)
        await message.answer("أُلغيت العملية.", reply_markup=_admin_keyboard())


@router.message(F.text | F.caption)
async def text_router(message: Message):
    if message.from_user and message.from_user.is_bot:
        return
    if message.chat.type in {"group", "supergroup"}:
        enabled, _ = db.get_group(message.chat.id)
        if not enabled:
            return
    for raw in _extract_message_urls(message):
        if message.chat.type in {"group", "supergroup"}:
            try:
                host = urlsplit(raw if "://" in raw else "https://" + raw).hostname or ""
                host = host.encode("idna").decode("ascii").lower().rstrip(".")
            except (ValueError, UnicodeError):
                host = ""
            if host and db.group_domain_allowed(message.chat.id, host):
                continue
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

@router.callback_query(F.data == "group_help")
async def group_help(call: CallbackQuery):
    body = (
        "<b>حماية مجموعات تيليجرام</b>\n"
        "أضف فَحْص إلى المجموعة، ثم امنحه صلاحية رؤية الرسائل. يلزم أن يكون مشرفًا لحذف الرسائل.\n\n"
        "<b>أوامر المشرفين:</b>\n"
        "• <code>/fahs_on</code> تفعيل فحص الروابط.\n"
        "• <code>/fahs_off</code> إيقاف الفحص.\n"
        "• <code>/fahs_status</code> عرض حالة الحماية.\n"
        "• <code>/fahs_delete_on</code> تفعيل حذف الروابط ذات الخطورة المرتفعة أو الحرجة.\n"
        "• <code>/fahs_delete_off</code> إيقاف الحذف التلقائي.\n"
        "• <code>/fahs_allow example.com</code> استثناء نطاق موثوق.\n"
        "• <code>/fahs_unallow example.com</code> إزالة الاستثناء.\n"
        "• <code>/fahs_allowlist</code> عرض النطاقات المستثناة.\n\n"
        "<b>تنبيه:</b> الحذف التلقائي قد يتأثر بنتيجة اشتباه خاطئة؛ ابدأ بالفحص دون حذف، ولا تستثنِ نطاقًا إلا بعد التحقق منه."
    )
    await call.message.edit_text(body, reply_markup=back_menu())
    await call.answer()


PROTECTION_GUIDES = {
    "accounts": ("حماية الحسابات", "• كلمة مرور طويلة وفريدة لكل خدمة، مع مدير كلمات مرور موثوق.\n• فعّل المصادقة الثنائية، وفضّل مفتاح أمان أو تطبيق مصادقة.\n• أمّن بريد الاسترداد أولًا وراجع الجلسات والأجهزة دوريًا.\n• لا تشارك OTP أو رموز الاسترداد مطلقًا.\n• عند الاشتباه: غيّر كلمة المرور من جهاز سليم، وأنهِ الجلسات وألغِ رموز الوصول المكشوفة."),
    "phone": ("أمان الهاتف", "• حدّث النظام والتطبيقات باستمرار.\n• ثبّت من المتاجر الرسمية وراجع المطور والصلاحيات.\n• لا تمنح إمكانية الوصول أو إدارة الجهاز أو VPN لتطبيق مجهول.\n• استخدم قفلًا قويًا وأخفِ الإشعارات الحساسة.\n• فعّل العثور على الجهاز والنسخ الاحتياطي واختبر الاستعادة."),
    "links": ("الروابط والتصفح", "• افحص اسم النطاق حرفًا حرفًا وانتبه للحروف المتشابهة.\n• HTTPS يشفر الاتصال ولا يثبت شرعية الموقع.\n• لا تسجل الدخول من رابط رسالة؛ افتح التطبيق الرسمي بنفسك.\n• احذر الروابط المختصرة والتنزيلات والنوافذ المنبثقة.\n• عاين عنوان QR قبل فتحه ولا تدخل بياناتك في صفحات غير متحقق منها."),
    "money": ("حماية الأموال والمدفوعات", "• فعّل إشعارات العمليات وحدود الدفع.\n• لا تشارك بيانات البطاقة أو رمز الأمان أو OTP.\n• تحقق من اسم المستفيد والمبلغ قبل التحويل.\n• لا تثق بصورة إيصال؛ تحقق داخل تطبيق البنك.\n• عند تحويل مشبوه اتصل بالبنك فورًا من قنواته الرسمية واحتفظ برقم البلاغ."),
    "privacy": ("الخصوصية والبيانات", "• قلّل نشر رقمك وعنوانك وموقعك وصور الوثائق.\n• راجع من يستطيع رؤية رقمك وصورتك وحالتك وموقعك.\n• أخفِ البيانات والإشعارات قبل مشاركة لقطات الشاشة.\n• أوقف الموقع المباشر بعد انتهاء الحاجة.\n• لا تنشر مفاتيح API أو ملفات الجلسات أو رموز الاسترداد."),
    "wifi": ("الشبكات والاتصال", "• غيّر كلمة مرور جهاز التوجيه الافتراضية وحدّثه.\n• استخدم WPA2-AES أو WPA3 وكلمة مرور قوية.\n• تجنب المعاملات الحساسة على شبكات عامة غير موثوقة.\n• لا تتصل تلقائيًا بنقاط مفتوحة.\n• VPN لا يجعل الموقع الذي تزوره موثوقًا ولا يمنع التصيد."),
    "telegram": ("أمان تيليجرام", "• فعّل التحقق بخطوتين وأمّن بريد الاسترداد.\n• راجع الإعدادات ← الأجهزة وأنهِ الجلسات المجهولة.\n• لا تشارك رمز تسجيل الدخول مع شخص أو بوت.\n• قيّد من يستطيع إضافتك للمجموعات ورؤية رقمك.\n• احذر بوتات الجوائز والدعم واسترداد الحساب التي تطلب رموزًا."),
    "backups": ("النسخ الاحتياطي", "• أنشئ نسخًا منتظمة للملفات المهمة.\n• شفّر النسخ الحساسة واحتفظ بنسخة منفصلة عن الجهاز.\n• اختبر استعادة عينة؛ وجود النسخة لا يثبت سلامتها.\n• احتفظ برموز الاسترداد في مكان آمن منفصل."),
    "social": ("الشبكات الاجتماعية", "• لا تثق بحساب بسبب صورته أو الأصدقاء المشتركين.\n• تحقق من طلبات المال بمكالمة على رقم محفوظ.\n• لا تنشر وثائقك أو موقعك لحظة بلحظة.\n• راجع التطبيقات المرتبطة وألغِ غير الضروري.\n• بلّغ عن الحسابات المنتحلة ولا تفاوض المبتز."),
    "family": ("حماية الأسرة والأطفال", "• اتفقوا على كلمة تحقق عائلية للطلبات العاجلة.\n• علّم الأطفال عدم مشاركة الصور أو الموقع أو الرموز.\n• اجعل الإبلاغ عن رسالة مريبة آمنًا بلا توبيخ.\n• راجع إعدادات الخصوصية والمشتريات بما يناسب العمر.")
}


CONTENT_CATEGORIES = {
    "scams": "موسوعة الاحتيال",
    "ai_scams": "احتيال الذكاء الاصطناعي",
    "data": "مخاطر مشاركة البيانات",
    "protection": "أدلة الحماية",
    "emergency": "حالات الطوارئ",
    "glossary": "قاموس الأمن الرقمي",
}


def _catalog_items(category: str):
    """Return stable-key content items merged with persistent admin overrides."""
    if category == "protection":
        base = {key: (title, body) for key, (title, body) in PROTECTION_GUIDES.items()}
    elif category == "emergency":
        base = {title: (title, body) for title, body in EMERGENCY.items()}
    elif category == "glossary":
        base = {term: (term, meaning) for term, meaning in GLOSSARY.items()}
    else:
        base_map = {"scams": SCAMS, "ai_scams": AI_SCAMS, "data": DATA_RISKS}
        base = {key: (key, body) for key, body in base_map.get(category, {}).items()}

    overrides = db.get_content_overrides(category)
    result = []
    for key, (title, body) in base.items():
        override = overrides.get(key)
        if override and override["deleted"]:
            continue
        if override:
            title, body = override["title"], override["body"]
        result.append((key, title, body))
    for key, override in overrides.items():
        if key not in base and not override["deleted"]:
            result.append((key, override["title"], override["body"]))
    return result

@router.callback_query(F.data == "protect")
async def protect(call: CallbackQuery):
    items = _catalog_items("protection")
    rows = []
    for i in range(0, len(items), 2):
        row = [InlineKeyboardButton(text=items[i][1], callback_data=f"guide:{items[i][0]}")]
        if i + 1 < len(items):
            row.append(InlineKeyboardButton(text=items[i + 1][1], callback_data=f"guide:{items[i + 1][0]}"))
        rows.append(row)
    rows.append([InlineKeyboardButton(text="⬅️ القائمة الرئيسية", callback_data="home")])
    await call.message.edit_text("<b>مركز الحماية الرقمية</b>\nاختر المجال لفتح دليل عملي:", reply_markup=InlineKeyboardMarkup(inline_keyboard=rows))
    await call.answer()

@router.callback_query(F.data.startswith("guide:"))
async def protection_guide(call: CallbackQuery):
    key = call.data.split(":", 1)[1]
    item = next((x for x in _catalog_items("protection") if x[0] == key), None)
    if not item:
        await call.answer("هذا الدليل غير متاح.", show_alert=True)
        return
    _, title, body = item
    await call.message.edit_text(f"<b>{escape(title)}</b>\n\n{escape(body)}", reply_markup=InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📚 أدلة الحماية", callback_data="protect")],
        [InlineKeyboardButton(text="⬅️ القائمة الرئيسية", callback_data="home")]
    ]))
    await call.answer()

@router.callback_query(F.data.in_({"scams", "ai_scams", "data"}))
async def library(call: CallbackQuery):
    if call.data == "scams":
        data, title = SCAMS, "موسوعة أساليب الاحتيال"
    elif call.data == "ai_scams":
        data, title = AI_SCAMS, "الاحتيال المدعوم بالذكاء الاصطناعي"
    else:
        data, title = DATA_RISKS, "مخاطر مشاركة البيانات"

    items = _catalog_items(call.data)
    rows = []
    for index in range(0, len(items), 2):
        row = [
            InlineKeyboardButton(text=items[index][1], callback_data=f"lib:{call.data}:{index}")
        ]
        if index + 1 < len(items):
            row.append(InlineKeyboardButton(
                text=items[index + 1][1],
                callback_data=f"lib:{call.data}:{index + 1}",
            ))
        rows.append(row)
    rows.append([InlineKeyboardButton(text="⬅️ القائمة الرئيسية", callback_data="home")])
    await call.message.edit_text(
        f"<b>{escape(title)}</b>\nاختر الموضوع الذي تريد قراءته:",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=rows),
    )
    await call.answer()


@router.callback_query(F.data.startswith("lib:"))
async def library_detail(call: CallbackQuery):
    try:
        _, category, raw_index = call.data.split(":", 2)
        index = int(raw_index)
    except (ValueError, AttributeError):
        await call.answer("تعذر فتح الموضوع.", show_alert=True)
        return

    titles = {
        "scams": "موسوعة أساليب الاحتيال",
        "ai_scams": "الاحتيال بالذكاء الاصطناعي",
        "data": "مخاطر مشاركة البيانات",
    }
    if category not in titles:
        await call.answer("هذا القسم غير متاح.", show_alert=True)
        return
    title = titles[category]
    items = _catalog_items(category)
    if index < 0 or index >= len(items):
        await call.answer("الموضوع غير موجود.", show_alert=True)
        return

    _, heading, explanation = items[index]
    navigation = []
    if index > 0:
        navigation.append(InlineKeyboardButton(
            text="⬅️ السابق", callback_data=f"lib:{category}:{index - 1}"
        ))
    if index + 1 < len(items):
        navigation.append(InlineKeyboardButton(
            text="التالي ➡️", callback_data=f"lib:{category}:{index + 1}"
        ))
    rows = [navigation] if navigation else []
    rows.append([
        InlineKeyboardButton(text="قائمة الموضوعات", callback_data=category),
        InlineKeyboardButton(text="الرئيسية", callback_data="home"),
    ])
    await call.message.edit_text(
        f"<b>{escape(heading)}</b>\n\n{escape(explanation)}\n\n"
        f"<i>{index + 1} من {len(items)} — {escape(title)}</i>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=rows),
    )
    await call.answer()

@router.callback_query(F.data == "emergency")
async def emergency(call: CallbackQuery):
    items = _catalog_items("emergency")
    rows = [[InlineKeyboardButton(text=title[:60], callback_data=f"em_item:{i}")]
            for i, (_, title, _) in enumerate(items)]
    rows.append([InlineKeyboardButton(text="⬅️ القائمة الرئيسية", callback_data="home")])
    await call.message.edit_text(
        "اختر ما حدث لك للحصول على خطوات أولية:",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=rows))
    await call.answer()


@router.callback_query(F.data.startswith("em_item:"))
async def emergency_dynamic_detail(call: CallbackQuery):
    try:
        index = int(call.data.split(":", 1)[1])
        _, title, body = _catalog_items("emergency")[index]
    except (ValueError, IndexError):
        await call.answer("هذه الحالة غير متاحة.", show_alert=True)
        return
    await call.message.edit_text(
        f"<b>{escape(title)}</b>\n\n{escape(body)}\n\n"
        "لا تحذف الأدلة، وتواصل مع البنك أو المنصة أو الجهات الرسمية عبر قنواتها الموثقة.",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="⬅️ حالات الطوارئ", callback_data="emergency")],
            [InlineKeyboardButton(text="القائمة الرئيسية", callback_data="home")],
        ]))
    await call.answer()

@router.callback_query(F.data.startswith("em:"))
async def emergency_detail(call: CallbackQuery):
    keys = {
        "otp": "شاركت رمز تحقق",
        "password": "أدخلت كلمة المرور في صفحة مزيفة",
        "money": "حوّلت أموالًا",
        "app": "ثبّت تطبيقًا مشبوهًا",
        "extortion": "تعرضت للابتزاز",
        "telegram": "فقدت حساب تيليجرام",
        "leak": "تسربت بياناتي",
        "account": "حسابي مخترق أو جلسة غريبة",
        "phone": "فقدت هاتفي أو سُرق",
        "card": "بيانات بطاقتي مكشوفة",
        "sim": "شريحة هاتفي توقفت فجأة",
        "link": "ضغطت رابطًا مشبوهًا",
    }
    key = keys.get(call.data[3:], "")
    emergency_items = {item_key: body for item_key, _, body in _catalog_items("emergency")}
    body = emergency_items.get(key, "أوقف التفاعل، واحتفظ بالأدلة، وتواصل مع الجهة الرسمية المعنية.")
    await call.message.edit_text(f"<b>خطوات أولية</b>\n{body}\n\nلا تحذف الأدلة، وتواصل مع البنك أو المنصة أو الجهات الرسمية عبر قنواتها الموثقة.", reply_markup=back_menu())
    await call.answer()

@router.callback_query(F.data == "tip")
async def tip(call: CallbackQuery):
    index = datetime.now(ZoneInfo("Africa/Cairo")).timetuple().tm_yday % len(TIPS)
    await call.message.edit_text("💡 <b>نصيحة اليوم</b>\n" + TIPS[index], reply_markup=back_menu())
    await call.answer()

@router.callback_query(F.data == "about")
async def about(call: CallbackQuery):
    await call.message.edit_text(
        "<b>عن فَحْص</b>\nبوت توعوي يساعدك على فهم مؤشرات خطورة الروابط وأساليب الاحتيال الرقمي. "
        "لا يفحص الصور أو الملفات، ولا يضمن اكتشاف كل تهديد.\n\n"
        "إذا أفادك فَحْص، فلا تنسَ الدعاء لمن ساهم في إنشائه: اللهم بارك في هذا العمل، واجعله نافعًا للناس.",
        reply_markup=back_menu())
    await call.answer()

@router.callback_query(F.data == "delete_data_prompt")
async def delete_data_prompt(call: CallbackQuery):
    if call.message.chat.type != "private":
        await call.answer("نفّذ حذف بياناتك في المحادثة الخاصة.", show_alert=True)
        return
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="نعم، احذف بياناتي", callback_data="delete_data_confirm")],
        [InlineKeyboardButton(text="إلغاء", callback_data="settings")],
    ])
    await call.message.edit_text(
        "<b>تأكيد حذف البيانات</b>\\nسيحذف فَحْص معرّفك وإعدادات التذكير المخزنة في قاعدة البوت. "
        "لن يحذف ذلك رسائل تيليجرام أو بيانات تحتفظ بها المنصة أو إحصاءات الفحوصات المجمعة.",
        reply_markup=keyboard,
    )
    await call.answer()

@router.callback_query(F.data == "delete_data_confirm")
async def delete_data_confirm(call: CallbackQuery):
    if call.message.chat.type != "private":
        await call.answer("نفّذ حذف بياناتك في المحادثة الخاصة.", show_alert=True)
        return
    db.delete_user(call.from_user.id)
    await call.message.edit_text(
        "حُذفت إعداداتك ومعرّفك من قاعدة بيانات فَحْص. يمكنك استخدام البوت مجددًا، وستُنشأ بيانات إعدادات جديدة عند الحاجة.",
        reply_markup=back_menu(),
    )
    await call.answer("تم تنفيذ الحذف من قاعدة البوت.")

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

async def _send_quiz_question(call: CallbackQuery):
    import random
    index = random.randrange(len(QUIZ))
    question, options, _, _ = QUIZ[index]
    rows = [[
        InlineKeyboardButton(text=opt, callback_data=f"q:{index}:{i}")
        for i, opt in enumerate(options)
    ]]
    rows.append([InlineKeyboardButton(text="⬅️ القائمة الرئيسية", callback_data="home")])
    await call.message.edit_text(
        "🎯 <b>اختبر نفسك</b>\n" + question,
        reply_markup=InlineKeyboardMarkup(inline_keyboard=rows),
    )

@router.callback_query(F.data == "quiz")
async def quiz(call: CallbackQuery):
    await _send_quiz_question(call)
    await call.answer()

@router.callback_query(F.data == "quiz_next")
async def quiz_next(call: CallbackQuery):
    await _send_quiz_question(call)
    await call.answer()

@router.callback_query(F.data.startswith("q:"))
async def quiz_answer(call: CallbackQuery):
    try:
        _, raw_question, raw_answer = call.data.split(":")
        question_index, answer_index = int(raw_question), int(raw_answer)
        question, options, correct, explanation = QUIZ[question_index]
        if answer_index < 0 or answer_index >= len(options):
            raise ValueError("invalid answer")
    except (ValueError, IndexError):
        await call.answer("انتهت صلاحية هذا السؤال. ابدأ اختبارًا جديدًا.", show_alert=True)
        return

    result = "✅ إجابة صحيحة." if answer_index == correct else "❌ ليست الإجابة الصحيحة."
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🎯 سؤال آخر", callback_data="quiz_next")],
        [InlineKeyboardButton(text="📚 اقرأ دليل الحماية", callback_data="protect")],
        [InlineKeyboardButton(text="⬅️ القائمة الرئيسية", callback_data="home")],
    ])
    await call.message.edit_text(
        f"{result}\\n\\n<b>{escape(question)}</b>\\n"
        f"إجابتك: {escape(options[answer_index])}\\n"
        f"الإجابة الصحيحة: {escape(options[correct])}\\n\\n"
        f"<b>التفسير:</b>\\n{escape(explanation)}",
        reply_markup=keyboard,
    )
    await call.answer()

@router.callback_query(F.data == "privacy")
async def privacy(call: CallbackQuery):
    await call.message.edit_text(
        "<b>سياسة الخصوصية المختصرة</b>\n"
        "يحتفظ فَحْص بمعرّف تيليجرام وإعدادات التذكير، ومعرّف المجموعة وإعدادات حمايتها عند تفعيلها. "
        "يعالج نص الرابط مؤقتًا ولا يحفظه افتراضيًا. وفي المجموعات قد يحذف الرسائل المصنفة خطرًا حرجًا أو مرتفعًا إذا فعّل المشرف ذلك. لا ترسل روابط خاصة أو رموز وصول. "
        "قد يتصل الفاحص بالنطاق العام للتحقق من التحويلات، ولا يرسل الرابط إلى خدمة سمعة خارجية. "
        "يمكنك إيقاف التذكيرات أو حذف بياناتك من قاعدة البوت بالأمر /delete_my_data. التفاصيل في ملف PRIVACY.md بالمستودع.",
        reply_markup=back_menu())
    await call.answer()


GLOSSARY_PAGE_SIZE = 5

async def _show_glossary_page(call: CallbackQuery, page: int):
    entries = [(title, body) for _, title, body in _catalog_items("glossary")]
    pages = max(1, (len(entries) + GLOSSARY_PAGE_SIZE - 1) // GLOSSARY_PAGE_SIZE)
    page = max(0, min(page, pages - 1))
    selected = entries[page * GLOSSARY_PAGE_SIZE:(page + 1) * GLOSSARY_PAGE_SIZE]
    body = "<b>📖 قاموس الأمن الرقمي</b>\\n\\n" + "\\n\\n".join(
        f"<b>{escape(term)}</b>\\n{escape(meaning)}" for term, meaning in selected
    )
    rows = []
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="⬅️ السابق", callback_data=f"glossary_page:{page - 1}"))
    if page + 1 < pages:
        nav.append(InlineKeyboardButton(text="التالي ➡️", callback_data=f"glossary_page:{page + 1}"))
    if nav:
        rows.append(nav)
    rows.append([InlineKeyboardButton(text="⬅️ القائمة الرئيسية", callback_data="home")])
    body += f"\\n\\n<i>صفحة {page + 1} من {pages} — {len(entries)} مصطلحًا</i>"
    await call.message.edit_text(body, reply_markup=InlineKeyboardMarkup(inline_keyboard=rows))

@router.callback_query(F.data == "glossary")
async def glossary(call: CallbackQuery):
    await _show_glossary_page(call, 0)
    await call.answer()

@router.callback_query(F.data.startswith("glossary_page:"))
async def glossary_page(call: CallbackQuery):
    try:
        page = int(call.data.split(":", 1)[1])
    except (ValueError, IndexError):
        await call.answer("تعذر فتح الصفحة.", show_alert=True)
        return
    await _show_glossary_page(call, page)
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
