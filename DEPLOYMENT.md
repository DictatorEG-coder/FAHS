# دليل تشغيل ونشر فَحْص

## المتطلبات
- خادم Linux محدث.
- Docker Engine وDocker Compose plugin.
- رمز بوت من BotFather.
- اتصال إنترنت صادر إلى Telegram API ومصادر السمعة الاختيارية والنطاقات العامة التي يفحصها المستخدمون.

## الإعداد الأولي
1. استنسخ المستودع:
   `git clone https://github.com/DictatorEG-coder/FAHS.git`
2. ادخل مجلد المشروع:
   `cd FAHS`
3. أنشئ ملف الإعدادات:
   `cp .env.example .env`
4. افتح `.env` وأضف:
   - `BOT_TOKEN`: رمز البوت من BotFather.
   - `ADMIN_IDS`: معرّف حساب تيليجرام الذي يدير البوت، ويمكن إضافة أكثر من معرّف مفصول بفواصل. يمكنك تشغيل البوت أولًا ثم إرسال `/my_id` في المحادثة الخاصة لمعرفة معرّفك، وإضافته إلى `.env` ثم إعادة تشغيل الحاوية.
   - `URLHAUS_AUTH_KEY`: اختياري، مفتاح URLhaus.
   - `OPENPHISH_FEED_URL`: اختياري، رابط الخلاصة المسموح به وفق شروط OpenPhish.
   - `UPDATES_URL`, `DEVELOPER_URL`, `SUPPORT_URL`: الروابط الفعلية لأزرار القائمة.
5. احمِ ملف الأسرار:
   `chmod 600 .env`
6. تحقق من إعداد Compose:
   `docker compose config -q`
7. ابنِ وشغّل:
   `docker compose up -d --build`
8. راجع الحالة والسجلات:
   `docker compose ps`
   `docker compose logs -f fahs`

## إعداد تيليجرام
- أرسل `/start` للبوت في المحادثة الخاصة.
- أضف البوت إلى المجموعة عند الحاجة.
- اضبط Privacy Mode من BotFather وفق سياسة المجموعة، ثم استخدم `/fahs_on` من مشرف.
- لا تمنح صلاحية حذف الرسائل إلا إذا قررت تفعيل الحذف التلقائي عبر `/fahs_delete_on`.
- راجع قائمة الاستثناءات دوريًا؛ النطاق المستثنى يتجاوز الفحص له وللنطاقات الفرعية.

## التحديث
بعد سحب التحديثات من GitHub:
```bash
git pull origin main
docker compose up -d --build
docker compose logs --tail=100 fahs
```

## نسخة احتياطية لقاعدة البيانات
قاعدة SQLite محفوظة في مجلد البيانات الدائم داخل الحاوية. أنشئ نسخة متسقة باستخدام SQLite backup API:
```bash
docker compose exec -T fahs python -c "import sqlite3; s=sqlite3.connect('/app/data/fahs.sqlite3'); d=sqlite3.connect('/app/data/fahs-backup.sqlite3'); s.backup(d); d.close(); s.close()"
CID=$(docker compose ps -q fahs)
docker cp "$CID":/app/data/fahs-backup.sqlite3 ./fahs-backup.sqlite3
docker compose exec -T fahs rm /app/data/fahs-backup.sqlite3
```
احفظ النسخة في مكان آمن ومشفّر، ولا ترفعها إلى المستودع. اختبر الاستعادة دوريًا على نسخة منفصلة.

## تنبيهات أمنية
- لا تضع `.env` أو رمز البوت أو مفاتيح API في GitHub أو في رسائل عامة. إذا تسرّب رمز البوت، أبطله وأنشئ رمزًا جديدًا عبر BotFather.
- لا تستخدم `docker compose down -v` إلا إذا كنت تقصد حذف مجلد البيانات الدائم.
- فعّل جدارًا ناريًا وسياسة خروج شبكي تمنع الوصول إلى loopback والشبكات الخاصة وعناوين metadata؛ فحص IP داخل التطبيق طبقة دفاع مهمة لكنه لا يغني عن ضبط الشبكة.
- لا تفعّل OpenPhish Community Feed في استخدام تجاري قبل التأكد من الترخيص.
- ابدأ دون الحذف التلقائي في المجموعات، ثم اختبر التصنيفات قبل تفعيله.
- لا يفحص فَحْص الصور أو الملفات، ولا يضمن اكتشاف جميع الروابط الضارة.
