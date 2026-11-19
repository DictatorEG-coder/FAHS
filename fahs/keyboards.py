from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from fahs.config import settings

def main_menu():
    rows = [
        [InlineKeyboardButton(text="🔎 فحص رابط", callback_data="scan"), InlineKeyboardButton(text="🛡️ كيف أحمي نفسي؟", callback_data="protect")],
        [InlineKeyboardButton(text="📚 موسوعة الاحتيال", callback_data="scams"), InlineKeyboardButton(text="🧠 احتيال الذكاء الاصطناعي", callback_data="ai_scams")],
        [InlineKeyboardButton(text="🔐 مخاطر مشاركة البيانات", callback_data="data"), InlineKeyboardButton(text="🚨 تعرضت للاحتيال", callback_data="emergency")],
        [InlineKeyboardButton(text="🎯 اختبر نفسك", callback_data="quiz"), InlineKeyboardButton(text="💡 نصيحة اليوم", callback_data="tip")],
        [InlineKeyboardButton(text="⚙️ الإعدادات", callback_data="settings"), InlineKeyboardButton(text="ℹ️ عن فَحْص", callback_data="about")],
        [InlineKeyboardButton(text="📖 قاموس الأمن الرقمي", callback_data="glossary")],
        [InlineKeyboardButton(text="📜 سياسة الخصوصية", callback_data="privacy")]
    ]
    links = []
    for title, url in [("قناة التحديثات", settings.updates_url), ("التواصل مع المطور", settings.developer_url), ("ادعم فَحْص", settings.support_url)]:
        if url.startswith("https://") or url.startswith("http://") or url.startswith("tg://"):
            links.append(InlineKeyboardButton(text=title, url=url))
    if links:
        rows.append(links)
    return InlineKeyboardMarkup(inline_keyboard=rows)

def back_menu():
    return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="⬅️ القائمة الرئيسية", callback_data="home")]])

def settings_menu(reminders: bool):
    label = "إيقاف التذكيرات" if reminders else "تفعيل التذكيرات الاختيارية"
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=label, callback_data="reminders_toggle")],
        [InlineKeyboardButton(text="⬅️ القائمة الرئيسية", callback_data="home")]
    ])

def emergency_menu():
    return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text=x, callback_data="em:"+x)] for x in ("شاركت رمز تحقق","أدخلت كلمة المرور في صفحة مزيفة","حوّلت أموالًا","ثبّت تطبيقًا مشبوهًا","تعرضت للابتزاز")]+[[InlineKeyboardButton(text="⬅️ القائمة الرئيسية", callback_data="home")]])
