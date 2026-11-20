// لوحة إدارة المالك داخل تيليجرام
import { tg, send, kb, btn, answerCb, editOrSend } from "./telegram.js";
import {
  first, all, run, getSetting, setSetting, getState, setState, clearState,
  getSection, getChildren, getBlocks, deleteSectionTree, moveSection,
} from "./db.js";
import { entitiesToHtml, esc, now } from "./util.js";

const BACK_HOME = [btn("🔙 لوحة الإدارة", "a:home"), btn("🏠 الرئيسية", "home")];
const isConfiguredAdmin = (env, id) => [env.OWNER_ID, ...(env.ADMIN_IDS || "").split(",")].map((x) => String(x || "").trim()).includes(String(id));

export async function adminHome(env, msg) {
  const t = "⚙️ <b>لوحة الإدارة</b>\n\nاختر ما تريد:";
  const m = kb([
    [btn("🗂 إدارة الأقسام والأزرار", "a:t:0")],
    [btn("📢 إذاعة", "a:bc"), btn("📊 الإحصائيات", "a:st")],
    [btn("🚫 حظر / إلغاء حظر", "a:bn"), btn("⚙️ الإعدادات", "a:set")],
    [btn("🏠 الرئيسية", "home")],
  ]);
  return msg ? editOrSend(env, msg, t, { reply_markup: m }) : null;
}

// ---------- عرض شجرة الأقسام
async function showTree(env, msg, id) {
  let title = "🗂 <b>الأقسام الرئيسية</b>";
  let sec = null;
  if (id) {
    sec = await getSection(env, id);
    if (!sec) return editOrSend(env, msg, "القسم غير موجود.", { reply_markup: kb([BACK_HOME]) });
    const blocks = await getBlocks(env, id);
    title = `🗂 <b>${esc(sec.title)}</b>\nالحالة: ${sec.visible ? "👁 ظاهر" : "🙈 مخفي"} • عناصر المحتوى: ${blocks.length}`;
  }
  const children = await getChildren(env, id, false);
  const rows = [];
  let row = [];
  for (const c of children) {
    row.push(btn(`${c.visible ? "" : "🙈 "}${c.title}`, `a:t:${c.id}`));
    if (row.length === 2 || c.title.length > 22) { rows.push(row); row = []; }
  }
  if (row.length) rows.push(row);
  rows.push([btn(id ? "➕ قسم/زر فرعي" : "➕ قسم رئيسي جديد", `a:ns:${id}`)]);
  if (sec) {
    rows.push([btn("📝 إضافة محتوى", `a:nb:${id}`), btn("🔗 إضافة رابط", `a:nl:${id}`)]);
    rows.push([btn("🧾 عرض/حذف المحتوى", `a:bl:${id}`), btn("✏️ تغيير الاسم", `a:rn:${id}`)]);
    rows.push([btn("⬆️ للأعلى", `a:up:${id}`), btn("⬇️ للأسفل", `a:dn:${id}`), btn(sec.visible ? "🙈 إخفاء" : "👁 إظهار", `a:vis:${id}`)]);
    rows.push([btn("👀 معاينة كمستخدم", `s:${id}`), btn("🗑 حذف القسم", `a:del:${id}`)]);
    rows.push([btn("🔙 رجوع", sec.parent_id ? `a:t:${sec.parent_id}` : "a:t:0"), btn("⚙️ الإدارة", "a:home")]);
  } else {
    rows.push([btn("🔙 لوحة الإدارة", "a:home")]);
  }
  return editOrSend(env, msg, title, { reply_markup: kb(rows) });
}

async function showBlocks(env, msg, id) {
  const blocks = await getBlocks(env, id);
  const sec = await getSection(env, id);
  const labels = { text: "📝 نص", photo: "🖼 صورة", video: "🎬 فيديو", document: "📎 ملف", animation: "🎞 GIF", link: "🔗 رابط" };
  let t = `🧾 <b>محتوى «${esc(sec?.title || "")}»</b>\n\n`;
  const rows = [];
  if (!blocks.length) t += "لا يوجد محتوى.";
  blocks.forEach((b, i) => {
    const prev = b.type === "link" ? `${b.caption} → ${b.content}` : b.type === "text" ? b.content.replace(/<[^>]+>/g, "") : b.caption ? b.caption.replace(/<[^>]+>/g, "") : "";
    t += `${i + 1}. ${labels[b.type] || b.type}: ${esc(prev.slice(0, 60))}${prev.length > 60 ? "…" : ""}\n`;
    rows.push([btn(`🗑 حذف ${i + 1}`, `a:bd:${b.id}:${id}`), ...(i > 0 ? [btn(`⬆️ ${i + 1}`, `a:bu:${b.id}:${id}`)] : [])]);
  });
  rows.push([btn("🔙 رجوع", `a:t:${id}`)]);
  return editOrSend(env, msg, t.slice(0, 3900), { reply_markup: kb(rows) });
}

async function moveBlockUp(env, blockId, secId) {
  const blocks = await getBlocks(env, secId);
  const i = blocks.findIndex((b) => b.id === blockId);
  if (i <= 0) return;
  [blocks[i - 1], blocks[i]] = [blocks[i], blocks[i - 1]];
  await env.DB.batch(blocks.map((b, k) => env.DB.prepare("UPDATE blocks SET position=? WHERE id=?").bind(k, b.id)));
}

// ---------- الإحصائيات
async function showStats(env, msg) {
  const t = now();
  const c = async (sql, ...a) => (await first(env, sql, ...a))?.n ?? 0;
  const users = await c("SELECT COUNT(*) n FROM users");
  const d1 = await c("SELECT COUNT(*) n FROM users WHERE last_seen>?", t - 86400);
  const d7 = await c("SELECT COUNT(*) n FROM users WHERE last_seen>?", t - 7 * 86400);
  const banned = await c("SELECT COUNT(*) n FROM users WHERE banned=1");
  const left = await c("SELECT COUNT(*) n FROM users WHERE active=0");
  const scans = await c("SELECT COUNT(*) n FROM scans");
  const s24 = await c("SELECT COUNT(*) n FROM scans WHERE ts>?", t - 86400);
  const dang = await c("SELECT COUNT(*) n FROM scans WHERE verdict='danger'");
  const warn = await c("SELECT COUNT(*) n FROM scans WHERE verdict='warn'");
  const ok = await c("SELECT COUNT(*) n FROM scans WHERE verdict='ok'");
  const text = `📊 <b>إحصائيات فَحْص</b>\n\n👥 المستخدمون: <b>${users}</b>\n• نشطون خلال 24 ساعة: ${d1}\n• نشطون خلال 7 أيام: ${d7}\n• محظورون: ${banned}\n• أوقفوا البوت: ${left}\n\n🔍 عمليات الفحص: <b>${scans}</b>\n• آخر 24 ساعة: ${s24}\n• 🔴 خطير: ${dang}  🟡 مشبوه: ${warn}  🟢 سليم: ${ok}`;
  return editOrSend(env, msg, text, { reply_markup: kb([[btn("🔄 تحديث", "a:st")], BACK_HOME]) });
}

// ---------- الإعدادات
async function showSettings(env, msg) {
  const m = (await getSetting(env, "maintenance")) === "1";
  const vt = (await getSetting(env, "vt_enabled")) === "1";
  const lim = await getSetting(env, "scan_limit_per_hour");
  const vtReady = vt && !!env.VT_API_KEY && env.VT_EXTERNAL_SCAN_CONSENT === "1";
  const vtNote = !env.VT_API_KEY ? " (المفتاح غير مضاف)" : env.VT_EXTERNAL_SCAN_CONSENT !== "1" ? " (الإرسال الخارجي غير مصرح)" : "";
  const text = `⚙️ <b>إعدادات البوت</b>\n\n🛠 وضع الصيانة: <b>${m ? "مفعّل" : "متوقف"}</b>\n🛡 VirusTotal: <b>${vtReady ? "جاهز" : "غير نشط"}</b>${vtNote}\n⚠️ تفعيل VirusTotal يرسل الرابط إلى خدمة خارجية.\n⏱ حد الفحص لكل مستخدم/ساعة: <b>${lim}</b>`;
  return editOrSend(env, msg, text, {
    reply_markup: kb([
      [btn(m ? "✅ إيقاف الصيانة" : "🛠 تفعيل الصيانة", "a:tg:maintenance")],
      [btn(vt ? "⏸ إيقاف VirusTotal" : "▶️ تفعيل VirusTotal", "a:tg:vt_enabled")],
      [btn("⏱ تغيير حد الفحص", "a:ed:scan_limit_per_hour"), btn("👋 تغيير رسالة الترحيب", "a:ed:welcome_text")],
      [btn("🛠 تغيير رسالة الصيانة", "a:ed:maintenance_text")],
      BACK_HOME,
    ]),
  });
}

// ---------- الإذاعة
async function startBroadcast(env, uid, msg) {
  await setState(env, uid, "bc_wait", {});
  return editOrSend(env, msg, "📢 <b>إذاعة جديدة</b>\n\nأرسل الآن الرسالة التي تريد إذاعتها (نص، صورة، فيديو، ملف...) وستُنسخ كما هي لجميع المستخدمين.\n\nللإلغاء اضغط الزر.", {
    reply_markup: kb([[btn("❌ إلغاء", "a:cancel")]]),
  });
}

export async function processBroadcasts(env) {
  const bc = await first(env, "SELECT * FROM broadcasts WHERE status='running' ORDER BY id LIMIT 1");
  if (!bc) return;
  const batch = Math.min(40, parseInt(env.BROADCAST_BATCH || "25", 10) || 25);
  const users = await all(env, "SELECT id FROM users WHERE id>? AND banned=0 AND active=1 ORDER BY id LIMIT ?", bc.last_user, batch);
  if (!users.length) {
    await run(env, "UPDATE broadcasts SET status='done' WHERE id=?", bc.id);
    await send(env, bc.from_chat, `✅ <b>اكتملت الإذاعة</b>\nوصلت: ${bc.sent}\nفشلت: ${bc.failed}`);
    return;
  }
  let sent = 0, failed = 0, last = bc.last_user, stop = false;
  for (const u of users) {
    const r = await tg(env, "copyMessage", { chat_id: u.id, from_chat_id: bc.from_chat, message_id: bc.message_id });
    if (r.ok) sent++;
    else {
      if (r.error_code === 429) { stop = true; break; } // نكمل في الدورة القادمة
      failed++;
      if (r.error_code === 403 || r.error_code === 400) await run(env, "UPDATE users SET active=0 WHERE id=?", u.id);
    }
    last = u.id;
  }
  await run(env, "UPDATE broadcasts SET sent=sent+?, failed=failed+?, last_user=? WHERE id=?", sent, failed, last, bc.id);
}

// ---------- الحظر
async function banPrompt(env, uid, msg) {
  await setState(env, uid, "ban_wait", {});
  return editOrSend(env, msg, "🚫 <b>الحظر</b>\n\nأرسل معرّف المستخدم الرقمي (ID).\nلإلغاء الحظر عن شخص أرسل: <code>-ID</code> (مثال: <code>-123456</code>).", {
    reply_markup: kb([[btn("❌ إلغاء", "a:cancel")]]),
  });
}

// ---------- معالج أزرار المالك
export async function handleAdminCallback(env, cb, ctx) {
  const msg = cb.message;
  const uid = cb.from.id;
  const p = cb.data.split(":"); // a, action, ...
  const act = p[1];
  const n = (i) => parseInt(p[i], 10);
  await answerCb(env, cb.id);

  switch (act) {
    case "home": await clearState(env, uid); return adminHome(env, msg);
    case "cancel": await clearState(env, uid); return adminHome(env, msg);
    case "t": await clearState(env, uid); return showTree(env, msg, n(2));
    case "ns":
      await setState(env, uid, "new_section", { parent: n(2) });
      return editOrSend(env, msg, "➕ أرسل <b>اسم</b> القسم أو الزر الجديد (يمكن إضافة إيموجي في أوله).", { reply_markup: kb([[btn("❌ إلغاء", `a:t:${n(2)}`)]]) });
    case "rn":
      await setState(env, uid, "rename", { id: n(2) });
      return editOrSend(env, msg, "✏️ أرسل الاسم الجديد:", { reply_markup: kb([[btn("❌ إلغاء", `a:t:${n(2)}`)]]) });
    case "nb":
      await setState(env, uid, "new_block", { id: n(2) });
      return editOrSend(env, msg, "📝 أرسل المحتوى الآن: <b>نص</b> (يدعم التنسيق: عريض، مائل، روابط) أو <b>صورة</b> أو <b>فيديو</b> أو <b>ملف</b> أو <b>GIF</b> (مع وصف إن شئت).", { reply_markup: kb([[btn("❌ إلغاء", `a:t:${n(2)}`)]]) });
    case "nl":
      await setState(env, uid, "new_link", { id: n(2) });
      return editOrSend(env, msg, "🔗 أرسل الرابط بهذه الصيغة:\n<code>عنوان الزر | https://example.com</code>\n\nيظهر كزر في أسفل القسم.", { reply_markup: kb([[btn("❌ إلغاء", `a:t:${n(2)}`)]]) });
    case "bl": return showBlocks(env, msg, n(2));
    case "bd":
      await run(env, "DELETE FROM blocks WHERE id=?", n(2));
      return showBlocks(env, msg, n(3));
    case "bu":
      await moveBlockUp(env, n(2), n(3));
      return showBlocks(env, msg, n(3));
    case "up": await moveSection(env, n(2), -1); return showTree(env, msg, n(2));
    case "dn": await moveSection(env, n(2), 1); return showTree(env, msg, n(2));
    case "vis":
      await run(env, "UPDATE sections SET visible=1-visible WHERE id=?", n(2));
      return showTree(env, msg, n(2));
    case "del": {
      const sec = await getSection(env, n(2));
      return editOrSend(env, msg, `⚠️ <b>تأكيد الحذف</b>\n\nسيُحذف «${esc(sec?.title || "")}» مع كل أقسامه الفرعية ومحتواه نهائياً.`, {
        reply_markup: kb([[btn("✅ نعم، احذف", `a:delc:${n(2)}`), btn("❌ إلغاء", `a:t:${n(2)}`)]]),
      });
    }
    case "delc": {
      const sec = await getSection(env, n(2));
      const parent = sec ? sec.parent_id : 0;
      await deleteSectionTree(env, n(2));
      return showTree(env, msg, parent);
    }
    case "bc": return startBroadcast(env, uid, msg);
    case "bcgo": {
      const st = await getState(env, uid);
      if (!st || st.state !== "bc_confirm") return adminHome(env, msg);
      const total = (await first(env, "SELECT COUNT(*) n FROM users WHERE banned=0 AND active=1"))?.n || 0;
      await run(env, "UPDATE broadcasts SET status='cancelled' WHERE status='running'");
      await run(env, "INSERT INTO broadcasts (from_chat,message_id,status,total,created) VALUES (?,?, 'running', ?, ?)", st.data.chat, st.data.mid, total, now());
      await clearState(env, uid);
      ctx.waitUntil(processBroadcasts(env));
      return editOrSend(env, msg, `🚀 بدأت الإذاعة إلى ${total} مستخدم. تُرسل على دفعات تلقائياً، وسيصلك إشعار عند الاكتمال.`, { reply_markup: kb([BACK_HOME]) });
    }
    case "st": return showStats(env, msg);
    case "bn": return banPrompt(env, uid, msg);
    case "set": await clearState(env, uid); return showSettings(env, msg);
    case "tg": {
      const key = p[2] === "vt_enabled" ? "vt_enabled" : "maintenance";
      const cur = await getSetting(env, key);
      await setSetting(env, key, cur === "1" ? "0" : "1");
      return showSettings(env, msg);
    }
    case "ed": {
      const key = p[2];
      if (!["scan_limit_per_hour", "welcome_text", "maintenance_text"].includes(key)) return;
      await setState(env, uid, "edit_setting", { key });
      const hint = key === "scan_limit_per_hour" ? "أرسل رقماً (مثال 20)." : "أرسل النص الجديد (يدعم التنسيق).";
      return editOrSend(env, msg, `✏️ ${hint}`, { reply_markup: kb([[btn("❌ إلغاء", "a:set")]]) });
    }
    default: return;
  }
}

// ---------- معالج رسائل المالك أثناء الإدخال
export async function handleAdminMessage(env, m, st, ctx) {
  const uid = m.from.id;
  const chat = m.chat.id;
  const text = m.text || "";
  const done = (t, back) => send(env, chat, t, { reply_markup: kb([back]) });

  switch (st.state) {
    case "new_section": {
      const title = text.trim();
      if (!title) return send(env, chat, "أرسل اسماً نصياً.");
      if (title.length > 90) return send(env, chat, "⚠️ الحد الأقصى لاسم القسم 90 حرفاً.");
      const count = (await first(env, "SELECT COUNT(*) n FROM sections WHERE parent_id=?", st.data.parent))?.n ?? 0;
      if (count >= 80) return send(env, chat, "⚠️ بلغ هذا المستوى الحد الأقصى: 80 قسماً فرعياً.");
      const pos = (await first(env, "SELECT COALESCE(MAX(position),-1)+1 p FROM sections WHERE parent_id=?", st.data.parent))?.p ?? 0;
      const r = await run(env, "INSERT INTO sections (parent_id,title,position,visible) VALUES (?,?,?,1)", st.data.parent, title, pos);
      await clearState(env, uid);
      const id = r.meta.last_row_id;
      return done(`✅ تم إنشاء «${esc(title)}».\nافتحه وأضف المحتوى والأزرار.`, [btn("📂 فتح القسم", `a:t:${id}`), btn("🔙 رجوع", `a:t:${st.data.parent}`)]);
    }
    case "rename": {
      const title = text.trim();
      if (!title) return send(env, chat, "أرسل اسماً نصياً.");
      if (title.length > 90) return send(env, chat, "⚠️ الحد الأقصى للاسم 90 حرفاً.");
      await run(env, "UPDATE sections SET title=? WHERE id=?", title, st.data.id);
      await clearState(env, uid);
      return done("✅ تم تغيير الاسم.", [btn("📂 رجوع للقسم", `a:t:${st.data.id}`)]);
    }
    case "new_block": {
      const id = st.data.id;
      const count = (await first(env, "SELECT COUNT(*) n FROM blocks WHERE section_id=?", id))?.n ?? 0;
      if (count >= 80) return send(env, chat, "⚠️ بلغ هذا القسم الحد الأقصى: 80 عنصراً.");
      let type, content, caption = null;
      if (m.text) { type = "text"; if (m.text.length > 3500) return send(env, chat, "⚠️ الحد الأقصى للنص 3500 حرف. قسّمه إلى عناصر."); content = entitiesToHtml(m.text, m.entities); }
      else if (m.photo) { type = "photo"; content = m.photo[m.photo.length - 1].file_id; }
      else if (m.video) { type = "video"; content = m.video.file_id; }
      else if (m.animation) { type = "animation"; content = m.animation.file_id; }
      else if (m.document) { type = "document"; content = m.document.file_id; }
      else return send(env, chat, "⚠️ نوع غير مدعوم. أرسل نصاً أو صورة أو فيديو أو ملفاً أو GIF.");
      if (type !== "text") caption = entitiesToHtml(m.caption || "", m.caption_entities).slice(0, 1000) || null;
      const pos = (await first(env, "SELECT COALESCE(MAX(position),-1)+1 p FROM blocks WHERE section_id=?", id))?.p ?? 0;
      await run(env, "INSERT INTO blocks (section_id,position,type,content,caption) VALUES (?,?,?,?,?)", id, pos, type, content, caption);
      await clearState(env, uid);
      return done("✅ تمت إضافة المحتوى.", [btn("➕ إضافة آخر", `a:nb:${id}`), btn("📂 القسم", `a:t:${id}`)]);
    }
    case "new_link": {
      const parts = text.split("|");
      const url = (parts[1] || "").trim();
      const title = (parts[0] || "").trim();
      let parsed;
      try { parsed = new URL(url); } catch {}
      if (!title || title.length > 60 || !parsed || !["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password || url.length > 2048) return send(env, chat, "⚠️ الصيغة: <code>عنوان (حتى 60 حرفاً) | https://example.com</code>");
      const id = st.data.id;
      const pos = (await first(env, "SELECT COALESCE(MAX(position),-1)+1 p FROM blocks WHERE section_id=?", id))?.p ?? 0;
      await run(env, "INSERT INTO blocks (section_id,position,type,content,caption) VALUES (?,?,'link',?,?)", id, pos, url, title);
      await clearState(env, uid);
      return done("✅ تمت إضافة الرابط كزر.", [btn("🔗 إضافة آخر", `a:nl:${id}`), btn("📂 القسم", `a:t:${id}`)]);
    }
    case "bc_wait": {
      await setState(env, uid, "bc_confirm", { chat, mid: m.message_id });
      await send(env, chat, "👆 هذه معاينة الإذاعة. هل تريد إرسالها لجميع المستخدمين؟", {
        reply_to_message_id: m.message_id,
        reply_markup: kb([[btn("🚀 إرسال للجميع", "a:bcgo"), btn("❌ إلغاء", "a:cancel")]]),
      });
      return;
    }
    case "ban_wait": {
      const unban = text.trim().startsWith("-");
      const id = parseInt(text.replace(/[^\d]/g, ""), 10);
      if (!id) return send(env, chat, "⚠️ أرسل رقم ID صحيحاً.");
      if (isConfiguredAdmin(env, id)) return send(env, chat, "لا يمكنك حظر أحد مشرفي البوت.");
      await run(env, "INSERT INTO users (id,first_seen,last_seen,banned) VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET banned=excluded.banned", id, now(), now(), unban ? 0 : 1);
      await clearState(env, uid);
      return done(unban ? `✅ أُلغي الحظر عن <code>${id}</code>.` : `🚫 تم حظر <code>${id}</code>.`, BACK_HOME);
    }
    case "edit_setting": {
      const key = st.data.key;
      let value;
      if (key === "scan_limit_per_hour") {
        value = parseInt(text, 10);
        if (!value || value < 1 || value > 1000) return send(env, chat, "⚠️ أرسل رقماً بين 1 و1000.");
      } else {
        if (!m.text) return send(env, chat, "⚠️ أرسل نصاً.");
        if (m.text.length > 3500) return send(env, chat, "⚠️ الحد الأقصى للنص 3500 حرف.");
        value = entitiesToHtml(m.text, m.entities);
      }
      await setSetting(env, key, value);
      await clearState(env, uid);
      return done("✅ تم الحفظ.", [btn("⚙️ الإعدادات", "a:set")]);
    }
    default:
      await clearState(env, uid);
  }
}
