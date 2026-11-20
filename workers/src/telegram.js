// طبقة التواصل مع Telegram Bot API
import { sleep } from "./util.js";

export async function tg(env, method, payload = {}) {
  try {
    const res = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json().catch(() => ({ ok: false, description: "bad json" }));
    if (!data.ok) {
      // لا نطبع التوكن أبداً في السجلات
      console.log(`TG ${method} failed:`, data.error_code, data.description);
    }
    return data;
  } catch (e) {
    console.log(`TG ${method} error:`, e?.message);
    return { ok: false, description: String(e?.message || e) };
  }
}

export const kb = (rows) => ({ inline_keyboard: rows });
export const btn = (text, data) => ({ text, callback_data: data });
export const urlBtn = (text, url) => ({ text, url });

export function send(env, chat_id, text, extra = {}) {
  return tg(env, "sendMessage", {
    chat_id,
    text,
    parse_mode: "HTML",
    link_preview_options: { is_disabled: true },
    ...extra,
  });
}

// تعديل الرسالة، وعند الفشل (مثلاً الرسالة وسائط) نرسل رسالة جديدة
export async function editOrSend(env, msg, text, extra = {}) {
  if (msg && msg.text !== undefined) {
    const r = await tg(env, "editMessageText", {
      chat_id: msg.chat.id,
      message_id: msg.message_id,
      text,
      parse_mode: "HTML",
      link_preview_options: { is_disabled: true },
      ...extra,
    });
    if (r.ok || /not modified/i.test(r.description || "")) return r;
  }
  return send(env, msg.chat.id, text, extra);
}

export const answerCb = (env, id, text = "", alert = false) =>
  tg(env, "answerCallbackQuery", { callback_query_id: id, text, show_alert: alert });

export { sleep };
