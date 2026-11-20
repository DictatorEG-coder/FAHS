// عرض الأقسام والمحتوى للمستخدمين
import { tg, send, kb, btn, urlBtn, answerCb } from "./telegram.js";
import { getSection, getChildren, getBlocks, getSetting } from "./db.js";
import { chunkText } from "./util.js";

export async function mainMenu(env, isOwner) {
  const top = await getChildren(env, 0);
  const rows = [[btn("🔍 فحص رابط", "scan")]];
  let row = [];
  for (const s of top) {
    row.push(btn(s.title, `s:${s.id}`));
    if (row.length === 2) { rows.push(row); row = []; }
  }
  if (row.length) rows.push(row);
  if (isOwner) rows.push([btn("⚙️ لوحة الإدارة", "a:home")]);
  return kb(rows);
}

export async function showHome(env, chatId, isOwner) {
  const text = await getSetting(env, "welcome_text");
  return send(env, chatId, text, { reply_markup: await mainMenu(env, isOwner) });
}

async function sectionKeyboard(env, sec, children, linkBlocks, isOwner) {
  const rows = [];
  let row = [];
  for (const c of children) {
    row.push(btn(c.title, `s:${c.id}`));
    if (row.length === 2 || c.title.length > 22) { rows.push(row); row = []; }
  }
  if (row.length) rows.push(row);
  for (const l of linkBlocks) rows.push([urlBtn(`🔗 ${l.caption || "رابط"}`, l.content)]);
  const nav = [];
  nav.push(btn("🔙 رجوع", sec.parent_id ? `s:${sec.parent_id}` : "home"));
  nav.push(btn("🏠 الرئيسية", "home"));
  rows.push(nav);
  if (isOwner) rows.push([btn("✏️ تعديل هذا القسم", `a:t:${sec.id}`)]);
  return kb(rows);
}

// msg: الرسالة التي ضُغط زرها (لتعديلها بدل إغراق المحادثة)
export async function showSection(env, chatId, id, isOwner, msg = null) {
  const sec = await getSection(env, id);
  if (!sec || (!sec.visible && !isOwner)) {
    return send(env, chatId, "⚠️ هذا القسم غير متاح.", { reply_markup: await mainMenu(env, isOwner) });
  }
  const children = await getChildren(env, id, !isOwner);
  const blocks = await getBlocks(env, id);
  const linkBlocks = blocks.filter((b) => b.type === "link");
  const content = blocks.filter((b) => b.type !== "link");
  const markup = await sectionKeyboard(env, sec, children, linkBlocks, isOwner);

  if (!content.length) {
    const t = `<b>${sec.title.replace(/[<>&]/g, "")}</b>\n\nلا يوجد محتوى في هذا القسم بعد.`;
    return msg ? editSafe(env, msg, t, markup) : send(env, chatId, t, { reply_markup: markup });
  }
  // نص واحد فقط: نعدّل الرسالة الحالية لتجربة أنظف على الجوال
  if (content.length === 1 && content[0].type === "text" && msg && content[0].content.length < 3800) {
    return editSafe(env, msg, content[0].content, markup);
  }
  for (let i = 0; i < content.length; i++) {
    const b = content[i];
    const last = i === content.length - 1;
    const extra = last ? { reply_markup: markup } : {};
    if (b.type === "text") {
      const parts = chunkText(b.content);
      for (let j = 0; j < parts.length; j++) {
        const lastPart = last && j === parts.length - 1;
        await send(env, chatId, parts[j], lastPart ? { reply_markup: markup } : {});
      }
    } else {
      const method = { photo: "sendPhoto", video: "sendVideo", document: "sendDocument", animation: "sendAnimation" }[b.type];
      if (!method) continue;
      const field = b.type;
      await tg(env, method, {
        chat_id: chatId,
        [field]: b.content,
        caption: (b.caption || "").slice(0, 1024) || undefined,
        parse_mode: "HTML",
        ...extra,
      });
    }
  }
}

async function editSafe(env, msg, text, markup) {
  const r = await tg(env, "editMessageText", {
    chat_id: msg.chat.id,
    message_id: msg.message_id,
    text,
    parse_mode: "HTML",
    link_preview_options: { is_disabled: true },
    reply_markup: markup,
  });
  if (!r.ok && !/not modified/i.test(r.description || "")) {
    return send(env, msg.chat.id, text, { reply_markup: markup });
  }
  return r;
}
