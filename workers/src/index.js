// فَحْص | FAHS - نقطة الدخول (Cloudflare Worker)
import { ensureDb, touchUser, getState, setState, clearState, rateLimit, getSetting, run } from "./db.js";
import { send, kb, btn, tg, answerCb } from "./telegram.js";
import { showHome, showSection, mainMenu } from "./content.js";
import { handleAdminCallback, handleAdminMessage, adminHome, processBroadcasts } from "./admin.js";
import { scanUrl, extractUrls } from "./scanner.js";
import { now } from "./util.js";

const isOwnerId = (env, id) => {
  const ids = [env.OWNER_ID, ...(env.ADMIN_IDS || "").split(",")].map((x) => String(x || "").trim()).filter(Boolean);
  return ids.includes(String(id));
};

const COMMANDS = [
  { command: "start", description: "القائمة الرئيسية" },
  { command: "scan", description: "فحص رابط" },
  { command: "help", description: "المساعدة" },
  { command: "my_id", description: "عرض معرّفك في تيليجرام" },
  { command: "delete_my_data", description: "حذف بياناتك من قاعدة البوت" },
  { command: "fahs_on", description: "تفعيل فحص روابط المجموعة للمشرفين" },
  { command: "fahs_off", description: "إيقاف فحص روابط المجموعة للمشرفين" },
  { command: "fahs_status", description: "حالة حماية المجموعة" },
];

const SCAN_KB = kb([[btn("🔍 فحص رابط آخر", "scan"), btn("🏠 الرئيسية", "home")]]);

async function doScan(env, chatId, uid, rawUrls, owner) {
  if (!owner) {
    const limit = parseInt(await getSetting(env, "scan_limit_per_hour"), 10) || 20;
    const ok = await rateLimit(env, `scan:${uid}`, 3600, limit);
    if (!ok) return send(env, chatId, "⏳ وصلت للحد الأقصى من عمليات الفحص هذه الساعة. حاول لاحقاً.", { reply_markup: SCAN_KB });
  }
  const useVt = (await getSetting(env, "vt_enabled")) === "1" && !!env.VT_API_KEY && env.VT_EXTERNAL_SCAN_CONSENT === "1";
  for (const raw of rawUrls) {
    const wait = await send(env, chatId, "⏳ جارٍ فحص الرابط... قد يستغرق حتى 20 ثانية.");
    let res;
    try {
      res = await scanUrl(env, raw, { useVt });
    } catch (e) {
      console.log("scan error", e?.message);
      res = { error: "حدث خطأ غير متوقع أثناء الفحص. حاول مرة أخرى." };
    }
    const mid = wait?.result?.message_id;
    if (res.error) {
      await tg(env, "editMessageText", { chat_id: chatId, message_id: mid, text: `⚠️ ${res.error}`, reply_markup: SCAN_KB });
      continue;
    }
    // نخزن النطاق فقط (بدون الرابط الكامل) لأغراض الإحصاء
    await run(env, "INSERT INTO scans (ts,verdict,host) VALUES (?,?,?)", now(), res.verdict.level, res.host.slice(0, 100));
    const rows = [];
    if (res.vtLink) rows.push([{ text: "📄 تقرير VirusTotal الكامل", url: res.vtLink }]);
    rows.push(...SCAN_KB.inline_keyboard);
    const r = await tg(env, "editMessageText", {
      chat_id: chatId, message_id: mid, text: res.text, parse_mode: "HTML",
      link_preview_options: { is_disabled: true }, reply_markup: kb(rows),
    });
    if (!r.ok) await send(env, chatId, res.text, { reply_markup: kb(rows) });
  }
}

async function onMessage(env, ctx, m) {
  if (!m.from || m.from.is_bot) return;
  if (m.chat.type !== "private") {
    const uid = m.from.id;
    const groupText = m.text || m.caption || "";
    const groupCmd = groupText.startsWith("/") ? groupText.split(/[\s@]/)[0].toLowerCase() : null;
    if (["/fahs_on", "/fahs_off", "/fahs_status"].includes(groupCmd)) {
      const member = await tg(env, "getChatMember", { chat_id: m.chat.id, user_id: uid });
      const status = member?.result?.status;
      if (!member.ok || !["creator", "administrator"].includes(status)) {
        return send(env, m.chat.id, "هذه الأوامر متاحة لمشرفي المجموعة فقط.");
      }
      const current = await env.DB.prepare("SELECT enabled FROM group_settings WHERE chat_id=?").bind(m.chat.id).first();
      if (groupCmd === "/fahs_status") {
        return send(env, m.chat.id, current?.enabled ? "🟢 حماية فَحْص مفعّلة في هذه المجموعة." : "⚪ حماية فَحْص متوقفة في هذه المجموعة.");
      }
      const enabled = groupCmd === "/fahs_on" ? 1 : 0;
      await run(env, "INSERT INTO group_settings (chat_id,enabled,updated) VALUES (?,?,?) ON CONFLICT(chat_id) DO UPDATE SET enabled=excluded.enabled,updated=excluded.updated", m.chat.id, enabled, now());
      return send(env, m.chat.id, enabled ? "🛡 تم تفعيل فحص الروابط في هذه المجموعة." : "تم إيقاف فحص الروابط في هذه المجموعة.");
    }
    const setting = await env.DB.prepare("SELECT enabled FROM group_settings WHERE chat_id=?").bind(m.chat.id).first();
    if (!setting?.enabled) return;
    if (!(await rateLimit(env, "group-scan:" + uid, 60, 8))) return;
    const groupUrls = extractUrls(groupText, m.entities || m.caption_entities || []);
    if (groupUrls.length) return doScan(env, m.chat.id, uid, groupUrls, false);
    return;
  }
  const uid = m.from.id;
  const owner = isOwnerId(env, uid);
  const user = await touchUser(env, uid);
  if (user?.banned && !owner) return;

  if (!owner) {
    if (!(await rateLimit(env, `flood:${uid}`, 60, 25))) return; // حماية من الإغراق
    if ((await getSetting(env, "maintenance")) === "1") return send(env, m.chat.id, await getSetting(env, "maintenance_text"));
  }

  const text = m.text || "";
  const cmd = text.startsWith("/") ? text.split(/[\s@]/)[0].toLowerCase() : null;

  if (cmd === "/start" || cmd === "/menu") { await clearState(env, uid); return showHome(env, m.chat.id, owner); }
  if (cmd === "/my_id") return send(env, m.chat.id, `معرّفك في تيليجرام: <code>${uid}</code>`);
  if (cmd === "/delete_my_data") {
    await env.DB.batch([
      env.DB.prepare("DELETE FROM users WHERE id=?").bind(uid),
      env.DB.prepare("DELETE FROM states WHERE user_id=?").bind(uid),
      env.DB.prepare("DELETE FROM rl WHERE key IN (?,?,?)").bind("flood:" + uid, "scan:" + uid, "group-scan:" + uid),
    ]);
    return send(env, m.chat.id, "🧹 حُذفت بيانات حسابك وإعداداتك المحفوظة لدى فَحْص. لا نخزّن روابط الفحص كاملة.");
  }
  if (cmd === "/help") return send(env, m.chat.id, "ℹ️ <b>المساعدة</b>\n\nأرسل لي أي رابط وسأفحصه، أو تصفّح الأقسام من القائمة.\nيمكنك إرسال حتى 3 روابط في رسالة واحدة.\n\n🔒 لا نحفظ الروابط التي تفحصها.", { reply_markup: await mainMenu(env, owner) });
  if (cmd === "/admin" && owner) { await clearState(env, uid); return send(env, m.chat.id, "⚙️ <b>لوحة الإدارة</b>", { reply_markup: kb([[btn("فتح لوحة الإدارة", "a:home")]]) }); }
  if (cmd === "/scan") { await setState(env, uid, "await_url"); return send(env, m.chat.id, "🔍 أرسل الرابط الذي تريد فحصه:"); }

  const st = await getState(env, uid);
  if (owner && st && st.state !== "await_url") return handleAdminMessage(env, m, st, ctx);

  const urls = extractUrls(text || m.caption || "", m.entities || m.caption_entities || []);
  if (urls.length) { if (st) await clearState(env, uid); return doScan(env, m.chat.id, uid, urls, owner); }

  if (st?.state === "await_url") return send(env, m.chat.id, "⚠️ لم أجد رابطاً في رسالتك. أرسل رابطاً صحيحاً مثل: <code>example.com</code>");

  if (m.photo || m.document || m.video || m.voice || m.audio) {
    return send(env, m.chat.id, "📎 فحص الملفات والصور غير متاح حالياً، المتاح <b>فحص الروابط</b> فقط.\nأرسل لي الرابط وسأفحصه.", { reply_markup: await mainMenu(env, owner) });
  }
  return showHome(env, m.chat.id, owner);
}

async function onCallback(env, ctx, cb) {
  const msg = cb.message;
  if (!msg || msg.chat.type !== "private") return answerCb(env, cb.id);
  const uid = cb.from.id;
  const owner = isOwnerId(env, uid);
  const user = await touchUser(env, uid);
  if (user?.banned && !owner) return answerCb(env, cb.id);
  if (!owner) {
    if (!(await rateLimit(env, `flood:${uid}`, 60, 40))) return answerCb(env, cb.id, "⏳ الرجاء التمهل قليلاً");
    if ((await getSetting(env, "maintenance")) === "1") return answerCb(env, cb.id, "🛠 البوت تحت الصيانة", true);
  }
  const d = cb.data || "";
  if (d.startsWith("a:")) {
    if (!owner) return answerCb(env, cb.id, "غير مصرّح", true);
    return handleAdminCallback(env, cb, ctx);
  }
  await answerCb(env, cb.id);
  if (d === "home") { await clearState(env, uid); return showHome(env, msg.chat.id, owner); }
  if (d === "scan") {
    await setState(env, uid, "await_url");
    return send(env, msg.chat.id, "🔍 <b>فحص رابط</b>\n\nأرسل الرابط الذي تريد فحصه (حتى 3 روابط).\n💡 لا تفتحه قبل الفحص!", { reply_markup: kb([[btn("🏠 الرئيسية", "home")]]) });
  }
  if (d.startsWith("s:")) {
    const id = parseInt(d.slice(2), 10);
    if (Number.isFinite(id)) return showSection(env, msg.chat.id, id, owner, msg);
  }
}

export async function handleUpdate(env, ctx, update) {
  await ensureDb(env);
  if (update.message) return onMessage(env, ctx, update.message);
  if (update.callback_query) return onCallback(env, ctx, update.callback_query);
  if (update.my_chat_member) {
    const c = update.my_chat_member;
    if (c.chat.type === "private" && ["kicked", "left"].includes(c.new_chat_member?.status)) {
      await run(env, "UPDATE users SET active=0 WHERE id=?", c.chat.id);
    }
  }
}

// مقارنة آمنة زمنياً
function safeEqual(a = "", b = "") {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    try {
      if (!env.BOT_TOKEN || (!env.OWNER_ID && !env.ADMIN_IDS) || !env.WEBHOOK_SECRET) {
        return new Response("FAHS: missing secrets (BOT_TOKEN / OWNER_ID or ADMIN_IDS / WEBHOOK_SECRET)", { status: 500 });
      }
      if (url.pathname === "/webhook" && request.method === "POST") {
        if (!safeEqual(request.headers.get("x-telegram-bot-api-secret-token") || "", env.WEBHOOK_SECRET)) {
          return new Response("forbidden", { status: 403 });
        }
        const update = await request.json();
        // نرد على تيليجرام فوراً ونكمل المعالجة في الخلفية
        ctx.waitUntil(
          handleUpdate(env, ctx, update).catch((e) => console.log("update error:", e?.stack || e?.message))
        );
        return new Response("ok");
      }
      if (url.pathname === "/setup" && request.method === "POST") {
        if (!safeEqual(request.headers.get("x-fahs-setup-secret") || "", env.WEBHOOK_SECRET)) return new Response("forbidden", { status: 403 });
        await ensureDb(env);
        const hook = await tg(env, "setWebhook", {
          url: `${url.origin}/webhook`,
          secret_token: env.WEBHOOK_SECRET,
          allowed_updates: ["message", "callback_query", "my_chat_member"],
        });
        await tg(env, "setMyCommands", { commands: COMMANDS });
        return new Response(JSON.stringify({ webhook: hook.ok, description: hook.description, vt_key: !!env.VT_API_KEY }, null, 2), {
          headers: { "content-type": "application/json" },
        });
      }
      if (url.pathname === "/setup") return new Response("استخدم POST مع ترويسة x-fahs-setup-secret لإعداد Webhook.", { status: 405, headers: { Allow: "POST" } });
      return new Response("FAHS bot is running ✅", { status: 200 });
    } catch (e) {
      console.log("fetch error:", e?.stack || e?.message);
      return new Response("error", { status: 500 });
    }
  },

  // مهمة كل دقيقة: إكمال الإذاعات
  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => { await ensureDb(env); await processBroadcasts(env); })().catch((e) => console.log("cron error:", e?.message)));
  },
};
