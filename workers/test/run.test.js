import assert from "node:assert/strict";
import { makeD1 } from "./d1shim.js";
import { entitiesToHtml, chunkText } from "../src/util.js";
import { isPrivateHost, normalizeUrl, analyzeLocal, extractUrls, scanUrl } from "../src/scanner.js";

let pass = 0;
const t = async (name, fn) => { try { await fn(); pass++; console.log("✅", name); } catch (e) { console.log("❌", name, "\n", e.stack); process.exitCode = 1; } };

// ---- محاكاة الشبكة
const calls = [];
const externalCalls = [];
let msgId = 100;
globalThis.fetch = async (url, opts = {}) => {
  const u = String(url);
  if (!u.startsWith("https://api.telegram.org/")) externalCalls.push(u);
  const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json" } });
  if (u.startsWith("https://api.telegram.org/")) {
    const method = u.split("/").pop();
    const body = JSON.parse(opts.body || "{}");
    calls.push({ method, body });
    if (method === "getChatMember") return json({ ok: true, result: { status: "administrator" } });
    if (method === "copyMessage" && body.chat_id === 999) return json({ ok: false, error_code: 403, description: "blocked" });
    return json({ ok: true, result: { message_id: ++msgId } });
  }
  if (u.includes("virustotal.com/api/v3/urls/") ) return json({ data: { attributes: { last_analysis_date: Date.now() / 1000, last_analysis_stats: { malicious: 7, suspicious: 1, harmless: 50, undetected: 20 } } } });
  if (u.includes("virustotal")) return json({}, 404);
  if (opts.method === "HEAD") {
    if (u.startsWith("http://bit.ly/")) return new Response(null, { status: 301, headers: { location: "https://evil-login.example.xyz/verify" } });
    return new Response(null, { status: 200 });
  }
  return json({}, 404);
};
const last = (m) => [...calls].reverse().find((c) => c.method === m);
const reset = () => (calls.length = 0);

const { handleUpdate } = await import("../src/index.js");
const { processBroadcasts } = await import("../src/admin.js");
const env = { DB: makeD1(), BOT_TOKEN: "T", OWNER_ID: "1", ADMIN_IDS: "2,3", WEBHOOK_SECRET: "s", VT_API_KEY: "k", BROADCAST_BATCH: "25" };
const ctx = { waitUntil: (p) => p };
const msg = (from, text, extra = {}) => ({ update_id: 1, message: { message_id: ++msgId, chat: { id: from, type: "private" }, from: { id: from, is_bot: false }, text, ...extra } });
const cbq = (from, data) => ({ update_id: 2, callback_query: { id: "c" + Math.random(), from: { id: from }, data, message: { message_id: 5, chat: { id: from, type: "private" }, text: "x" } } });
const kbTexts = (c) => (c?.body.reply_markup?.inline_keyboard || []).flat().map((b) => b.text);

await t("entitiesToHtml: تنسيق متداخل وهروب", () => {
  assert.equal(entitiesToHtml("a<b", []), "a&lt;b");
  assert.equal(entitiesToHtml("hello world", [{ type: "bold", offset: 0, length: 5 }, { type: "italic", offset: 6, length: 5 }]), "<b>hello</b> <i>world</i>");
  assert.equal(entitiesToHtml("abc", [{ type: "bold", offset: 0, length: 3 }, { type: "italic", offset: 0, length: 3 }]), "<b><i>abc</i></b>");
  assert.equal(entitiesToHtml("x", [{ type: "text_link", offset: 0, length: 1, url: "javascript:alert(1)" }]), "x");
});
await t("chunkText", () => assert.ok(chunkText("a\n".repeat(5000)).every((c) => c.length <= 3800)));
await t("SSRF: حجب العناوين الداخلية", () => {
  for (const h of ["localhost", "127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.1", "172.16.0.1", "foo.internal", "intranet", new URL("http://2130706433").hostname, new URL("http://[::1]").hostname, "100.64.0.1"]) assert.ok(isPrivateHost(h), h);
  assert.ok(!isPrivateHost("example.com"));
});
await t("normalizeUrl يرفض javascript: و file:", () => {
  assert.ok(normalizeUrl("javascript:alert(1)").error);
  assert.ok(normalizeUrl("file:///etc/passwd").error);
  assert.equal(normalizeUrl("example.com/a").url.hostname, "example.com");
  assert.equal(normalizeUrl("https://user:pass@example.com").hasUserInfo, true);
});
await t("التحليل المحلي: انتحال وتمويه", () => {
  assert.ok(analyzeLocal(new URL("http://paypal.login-secure.xyz/verify")).score >= 70);
  assert.equal(analyzeLocal(new URL("https://www.google.com/")).score, 0);
});
await t("تحذير منصات الاستضافة المشتركة وPunycode", () => {
  assert.ok(analyzeLocal(new URL("https://demo.workers.dev/")).score >= 30);
  assert.ok(analyzeLocal(new URL("https://xn--e1afmkfd.example/")).score >= 30);
  assert.ok(analyzeLocal(new URL("https://bit.ly/abc")).score >= 20);
  assert.ok(analyzeLocal(new URL("https://evil.example/google.com/login")).score >= 20);
});
await t("التقاط صيغ روابط الويب والروابط ذات البروتوكولات الأخرى", () => {
  const links = extractUrls("https://example.com ftp://files.example.com tg://resolve?domain=test");
  const ipLinks = extractUrls("192.0.2.1/login");
  assert.ok(links.some((x) => x.startsWith("https://")));
  assert.ok(links.some((x) => x.startsWith("ftp://")));
  assert.ok(links.some((x) => x.startsWith("tg://")));
  assert.ok(ipLinks.some((x) => x.startsWith("192.0.2.1")));
  assert.ok(extractUrls("hxxps://example[.]com").some((x) => x.includes("example.com")));
  assert.ok(normalizeUrl("hxxps://example.com").url);
  assert.ok(normalizeUrl("ftp://files.example.com").error);
});
await t("userinfo لا يرفع الخطورة وحده ويظهر كتحذير خصوصية", async () => {
  const a = analyzeLocal(new URL("https://login.example@google.com/"));
  assert.equal(a.score, 0);
  assert.ok(a.reasons.some((x) => x.includes("تنبيه خصوصية")));
});
await t("نهاية تقرير الفحص تتضمن الصلاة على النبي ﷺ", async () => {
  const r = await scanUrl({}, "https://example.com/");
  assert.ok(r.text.endsWith("🌿 وصلِّ على النبي ﷺ"));
});
await t("تحذير المعرفات الشخصية في معاملات الرابط", async () => {
  const r = await scanUrl({}, "https://demo.workers.dev/?chatId=123456");
  assert.ok(r.text.includes("معرّف أو بيانات شخصية"));
  assert.equal(r.verdict.level, "warn");
});

await t("/start: يزرع المحتوى ويعرض القائمة", async () => {
  reset(); await handleUpdate(env, ctx, msg(50, "/start"));
  const c = last("sendMessage"); const tx = kbTexts(c);
  assert.ok(tx.includes("🔍 فحص رابط") && tx.includes("🛡 كيف أحمي نفسي") && tx.includes("📚 مصطلحات مهمة"), tx.join("|"));
  assert.ok(!tx.includes("⚙️ لوحة الإدارة"), "المستخدم العادي لا يرى لوحة الإدارة");
});
await t("المشرف الإضافي يرى لوحة الإدارة", async () => {
  reset(); await handleUpdate(env, ctx, msg(2, "/start"));
  assert.ok(kbTexts(last("sendMessage")).includes("⚙️ لوحة الإدارة"));
});
await t("المالك يرى زر لوحة الإدارة", async () => {
  reset(); await handleUpdate(env, ctx, msg(1, "/start"));
  assert.ok(kbTexts(last("sendMessage")).includes("⚙️ لوحة الإدارة"));
});
await t("تصفح قسم فرعي وتعديل الرسالة", async () => {
  reset(); await handleUpdate(env, ctx, cbq(50, "s:3"));
  const e = last("editMessageText"); assert.ok(e.body.text.includes("مخاطر الذكاء الاصطناعي"));
  assert.ok(kbTexts(e).includes("🤝 كلمة السر العائلية"));
  reset(); await handleUpdate(env, ctx, cbq(50, "s:33"));
  assert.ok(last("editMessageText").body.text.includes("كلمة السر العائلية"));
});
await t("المصطلحات: 24 مصطلحاً", async () => {
  reset(); await handleUpdate(env, ctx, cbq(50, "s:5"));
  assert.equal(kbTexts(last("editMessageText")).filter((x) => /\||API|DNS|VPS/.test(x)).length >= 20, true);
});
await t("فحص رابط مشبوه محلياً دون إرسال تلقائي إلى VirusTotal", async () => {
  reset(); await handleUpdate(env, ctx, msg(50, "شوف http://paypal.login-secure.xyz/verify"));
  const e = last("editMessageText"); assert.ok(e.body.text.includes("خطير"), e.body.text);
  assert.equal(externalCalls.length, 0, "the scanner must not contact external services by default");
  assert.ok(!e.body.reply_markup.inline_keyboard.flat().some((b) => b.url?.includes("virustotal.com/gui/url/")));
});
await t("تفعيل خيار VirusTotal وحده لا يسمح بالإرسال الخارجي", async () => {
  const { setSetting } = await import("../src/db.js");
  await setSetting(env, "vt_enabled", "1");
  externalCalls.length = 0; reset();
  await handleUpdate(env, ctx, msg(51, "https://example.com/login"));
  assert.equal(externalCalls.length, 0);
  await setSetting(env, "vt_enabled", "0");
});
await t("الرابط المختصر لا يُفتح ولا تُخمن وجهته", async () => {
  reset(); await handleUpdate(env, ctx, msg(50, "http://bit.ly/abc"));
  const e = last("editMessageText"); assert.ok(e.body.text.includes("لم نفتح الرابط") && e.body.text.includes("لا يمكن تأكيد الوجهة النهائية"), e.body.text);
});
await t("فحص رابط داخلي مرفوض (SSRF)", async () => {
  reset(); await handleUpdate(env, ctx, msg(50, "http://169.254.169.254/latest/meta-data"));
  assert.ok(last("editMessageText").body.text.includes("لا يمكن فحص العناوين الداخلية"));
});
await t("الصور/الملفات: رد بأن المتاح الروابط فقط", async () => {
  reset(); await handleUpdate(env, ctx, msg(50, undefined, { photo: [{ file_id: "p" }], text: undefined }));
  assert.ok(last("sendMessage").body.text.includes("فحص الروابط"));
});
await t("حد الفحص لكل ساعة", async () => {
  const { setSetting } = await import("../src/db.js");
  await setSetting(env, "scan_limit_per_hour", "2");
  reset();
  for (let i = 0; i < 4; i++) await handleUpdate(env, ctx, msg(77, "https://example.com/" + i));
  assert.ok(calls.some((c) => c.body.text?.includes("للحد الأقصى")));
  await setSetting(env, "scan_limit_per_hour", "20");
});
await t("غير المالك لا يدخل لوحة الإدارة", async () => {
  reset(); await handleUpdate(env, ctx, cbq(50, "a:home"));
  const a = last("answerCallbackQuery"); assert.ok(a.body.show_alert);
  assert.equal(last("editMessageText"), undefined);
});
await t("المالك: إضافة قسم ثم نص منسق ثم رابط", async () => {
  reset(); await handleUpdate(env, ctx, cbq(1, "a:t:0")); assert.ok(kbTexts(last("editMessageText")).includes("➕ قسم رئيسي جديد"));
  await handleUpdate(env, ctx, cbq(1, "a:ns:0"));
  reset(); await handleUpdate(env, ctx, msg(1, "🆕 قسم تجريبي"));
  const cb = last("sendMessage").body.reply_markup.inline_keyboard.flat().find((b) => b.text.includes("فتح القسم"));
  const id = cb.callback_data.split(":")[2];
  await handleUpdate(env, ctx, cbq(1, `a:nb:${id}`));
  await handleUpdate(env, ctx, msg(1, "مرحبا بالعالم", { entities: [{ type: "bold", offset: 0, length: 5 }] }));
  await handleUpdate(env, ctx, cbq(1, `a:nl:${id}`));
  await handleUpdate(env, ctx, msg(1, "موقعنا | https://example.com"));
  reset(); await handleUpdate(env, ctx, cbq(50, `s:${id}`));
  const e = last("editMessageText");
  assert.ok(e.body.text.includes("<b>مرحبا</b> بالعالم"), e.body.text);
  assert.ok(e.body.reply_markup.inline_keyboard.flat().some((b) => b.url === "https://example.com"));
  // إخفاء القسم
  await handleUpdate(env, ctx, cbq(1, `a:vis:${id}`));
  reset(); await handleUpdate(env, ctx, cbq(50, "home"));
  assert.ok(!kbTexts(last("sendMessage")).includes("🆕 قسم تجريبي"));
  // حذف
  await handleUpdate(env, ctx, cbq(1, `a:delc:${id}`));
  const { getSection } = await import("../src/db.js"); assert.equal(await getSection(env, Number(id)), null);
});
await t("المالك: حظر وإلغاء حظر", async () => {
  await handleUpdate(env, ctx, cbq(1, "a:bn")); await handleUpdate(env, ctx, msg(1, "50"));
  reset(); await handleUpdate(env, ctx, msg(50, "/start")); assert.equal(calls.length, 0, "المحظور لا يتلقى رداً");
  await handleUpdate(env, ctx, cbq(1, "a:bn")); await handleUpdate(env, ctx, msg(1, "-50"));
  reset(); await handleUpdate(env, ctx, msg(50, "/start")); assert.ok(last("sendMessage"));
});
await t("المالك: إذاعة بالدفعات مع استبعاد من حظر البوت", async () => {
  await handleUpdate(env, ctx, msg(999, "/start"));
  await handleUpdate(env, ctx, cbq(1, "a:bc"));
  await handleUpdate(env, ctx, msg(1, "إعلان مهم"));
  reset(); await handleUpdate(env, ctx, cbq(1, "a:bcgo"));
  await processBroadcasts(env); await processBroadcasts(env);
  const copies = calls.filter((c) => c.method === "copyMessage");
  assert.ok(copies.length >= 3, "copies=" + copies.length);
  assert.ok(calls.some((c) => c.body.text?.includes("اكتملت الإذاعة")));
  const { first } = await import("../src/db.js");
  assert.equal((await first(env, "SELECT active FROM users WHERE id=999")).active, 0);
});
await t("حماية المجموعات: التفعيل والفحص والإيقاف", async () => {
  const groupMessage = (from, text) => ({ update_id: 77, message: { message_id: ++msgId, chat: { id: -100123, type: "supergroup" }, from: { id: from, is_bot: false }, text } });
  reset(); await handleUpdate(env, ctx, groupMessage(50, "/fahs_on"));
  assert.ok(last("sendMessage").body.text.includes("تم تفعيل"));
  reset(); await handleUpdate(env, ctx, groupMessage(50, "https://paypal.login-secure.xyz/verify"));
  assert.ok(last("editMessageText")?.body.text.includes("خطير"));
  reset(); await handleUpdate(env, ctx, groupMessage(50, "/fahs_off"));
  assert.ok(last("sendMessage").body.text.includes("إيقاف"));
});
await t("حذف بيانات المستخدم", async () => {
  reset(); await handleUpdate(env, ctx, msg(77, "/delete_my_data"));
  const { first } = await import("../src/db.js");
  assert.equal(await first(env, "SELECT id FROM users WHERE id=77"), null);
  assert.ok(last("sendMessage").body.text.includes("حُذفت بيانات حسابك"));
});
await t("الإحصائيات والإعدادات", async () => {
  reset(); await handleUpdate(env, ctx, cbq(1, "a:st")); const s = last("editMessageText").body.text; assert.ok(s.includes("إحصائيات") && /عمليات الفحص: <b>[1-9]/.test(s), s);
  await handleUpdate(env, ctx, cbq(1, "a:tg:maintenance"));
  reset(); await handleUpdate(env, ctx, msg(50, "/start")); assert.ok(last("sendMessage").body.text.includes("الصيانة"));
  await handleUpdate(env, ctx, cbq(1, "a:tg:maintenance"));
});
await t("ويب هوك: رفض بدون السر", async () => {
  const w = (await import("../src/index.js")).default;
  const r = await w.fetch(new Request("https://x.dev/webhook", { method: "POST", body: "{}" }), env, ctx);
  assert.equal(r.status, 403);
  const r2 = await w.fetch(new Request("https://x.dev/setup?key=bad"), env, ctx); assert.equal(r2.status, 405);
  const r3 = await w.fetch(new Request("https://x.dev/setup", { method: "POST", headers: { "x-fahs-setup-secret": "bad" } }), env, ctx); assert.equal(r3.status, 403);
});
console.log(`\n${pass} اختباراً نجح`);
