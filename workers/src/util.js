// أدوات مساعدة عامة

export const now = () => Math.floor(Date.now() / 1000);

export function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// تقسيم النص الطويل (حد تيليجرام 4096) عند أسطر جديدة قدر الإمكان
export function chunkText(text, max = 3800) {
  if (text.length <= max) return [text];
  const out = [];
  let rest = text;
  while (rest.length > max) {
    let cut = rest.lastIndexOf("\n", max);
    if (cut < max * 0.5) cut = max;
    out.push(rest.slice(0, cut));
    rest = rest.slice(cut).replace(/^\n/, "");
  }
  if (rest) out.push(rest);
  return out;
}

// تحويل كيانات تيليجرام (bold/italic/...) إلى HTML آمن
// ملاحظة: إزاحات تيليجرام بوحدات UTF-16 وهي نفس ترقيم سلاسل JavaScript.
export function entitiesToHtml(text, entities) {
  text = text ?? "";
  if (!entities || !entities.length) return esc(text);
  const tagFor = (e) => {
    switch (e.type) {
      case "bold": return ["<b>", "</b>"];
      case "italic": return ["<i>", "</i>"];
      case "underline": return ["<u>", "</u>"];
      case "strikethrough": return ["<s>", "</s>"];
      case "spoiler": return ["<tg-spoiler>", "</tg-spoiler>"];
      case "code": return ["<code>", "</code>"];
      case "pre": return ["<pre>", "</pre>"];
      case "blockquote": return ["<blockquote>", "</blockquote>"];
      case "text_link":
        return /^https?:\/\//i.test(e.url || "")
          ? [`<a href="${esc(e.url).replace(/"/g, "&quot;")}">`, "</a>"]
          : null;
      default: return null;
    }
  };
  const opens = {};
  const closes = {};
  entities.forEach((e, i) => {
    const t = tagFor(e);
    if (!t) return;
    const item = { i, start: e.offset, end: e.offset + e.length, t };
    (opens[item.start] ||= []).push(item);
    (closes[item.end] ||= []).push(item);
  });
  let out = "";
  for (let pos = 0; pos <= text.length; pos++) {
    if (closes[pos]) {
      closes[pos].sort((a, b) => b.start - a.start || b.i - a.i);
      for (const it of closes[pos]) out += it.t[1];
    }
    if (opens[pos]) {
      opens[pos].sort((a, b) => b.end - a.end || a.i - b.i);
      for (const it of opens[pos]) out += it.t[0];
    }
    if (pos < text.length) out += esc(text[pos]);
  }
  return out;
}

export function b64url(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
