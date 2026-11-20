// فحص محلي يحافظ على الخصوصية؛ لا يفتح وجهة الرابط أو يتتبع تحويلاتها
import { b64url, esc, sleep } from "./util.js";

const SHORTENERS = new Set([
  "bit.ly","bitly.com","tinyurl.com","t.co","goo.gl","is.gd","cutt.ly","rebrand.ly","shorturl.at","ow.ly",
  "buff.ly","tiny.cc","rb.gy","t.ly","s.id","lnkd.in","v.gd","shorte.st","adf.ly","bl.ink","soo.gd","clck.ru","qr.ae","tr.ee","urlz.fr","short.io","kutt.it","cutt.ly","t2m.io","reurl.cc","tiny.one","linktr.ee",
]);
const HOSTING_PLATFORMS = new Set([
  "workers.dev","pages.dev","vercel.app","netlify.app","github.io","web.app","firebaseapp.com",
  "onrender.com","fly.dev","ngrok-free.app","ngrok.io","trycloudflare.com","replit.app","repl.co",
  "glitch.me","herokuapp.com","surge.sh","duckdns.org","no-ip.org","serveo.net","localtunnel.me",
]);
const BAD_TLDS = new Set([
  "zip","mov","top","xyz","tk","ml","ga","cf","gq","click","country","work","support","rest","icu","cyou","buzz","loan","monster","sbs","cfd","vip","bid","men","stream","download","gdn","kim","party","review","trade","webcam","win",
]);
const KEYWORDS = ["login","signin","verify","verification","secure","account","update","wallet","bank","confirm","password","free","gift","claim","airdrop","prize","otp","support","suspend","unlock","recover","bonus","reward"];
const FILE_EXT = new Set(["txt","pdf","jpg","jpeg","png","gif","doc","docx","xls","xlsx","mp3","mp4","py","js","json","md","csv","apk","exe"]);
const BRANDS = {
  paypal: ["paypal.com"], telegram: ["telegram.org","t.me","telegram.me","telegram.dog"], whatsapp: ["whatsapp.com","wa.me","whatsapp.net"],
  apple: ["apple.com","icloud.com"], google: ["google.com","gmail.com","goo.gl","youtube.com","gstatic.com","googleapis.com"],
  microsoft: ["microsoft.com","live.com","office.com","outlook.com","microsoftonline.com"], facebook: ["facebook.com","fb.com","fb.me","meta.com"],
  instagram: ["instagram.com"], binance: ["binance.com"], amazon: ["amazon.com","amazon.sa","amazon.ae","amazon.eg","amazon.co.uk","amazon.de"],
  netflix: ["netflix.com"], tiktok: ["tiktok.com"], steam: ["steampowered.com","steamcommunity.com"], discord: ["discord.com","discord.gg","discordapp.com"],
  alrajhi: ["alrajhibank.com.sa"], stcpay: ["stcpay.com.sa"], snapchat: ["snapchat.com"], twitter: ["twitter.com","x.com"], coinbase: ["coinbase.com"], metamask: ["metamask.io"],
};

export const hostMatches = (host, dom) => host === dom || host.endsWith("." + dom);

// ---------- حماية SSRF
export function isPrivateHost(host) {
  const h = host.toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal") || h.endsWith(".lan") || h.endsWith(".home") || h.endsWith(".corp")) return true;
  if (h.startsWith("[")) return true; // لا نتصل بعناوين IPv6 مباشرة
  if (!h.includes(".")) return true; // أسماء بدون نقطة (شبكات داخلية)
  const m = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    if (a === 0 || a === 10 || a === 127 || a >= 224) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 192 && b === 0) return true;
    if (a === 198 && (b === 18 || b === 19)) return true;
  }
  return false;
}

// ---------- استخراج وتنظيف الروابط
export function extractUrls(text, entities = []) {
  const found = [];
  const source = text.replace(/\[(?:\.|dot)\]|\(\.\)|\{\.\}/gi, ".");
  for (const e of entities || []) {
    if (e.type === "text_link" && e.url) found.push(e.url);
    if (e.type === "url") found.push(text.substr(e.offset, e.length));
  }
  const re = /(?:https?:\/\/|hxxps?:\/\/|www\.|(?:ftp|ftps|sftp|ssh|smb|tg|mailto|tel|sms|magnet|intent|file|javascript|data|blob|geo|skype|whatsapp|discord|market|facetime|bitcoin|ethereum|zoommtg|slack|signal|steam|viber|line|fb|instagram|youtube):)[^\s<>"'،]+|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?:\/[^\s<>"'،]*)?|\b[a-z0-9\p{L}-]{1,63}(?:\.[a-z0-9\p{L}-]{1,63})*\.[a-z\p{L}]{2,24}\b(?::\d{1,5})?(?:\/[^\s<>"'،]*)?/giu;
  for (const m of source.matchAll(re)) {
    const ext = m[0].split("/")[0].split(".").pop().toLowerCase();
    if (FILE_EXT.has(ext) && !m[0].includes("/")) continue; // اسم ملف وليس نطاقاً
    found.push(m[0]);
  }
  const out = [];
  for (let u of found) {
    u = u.replace(/[)\].,;:!؟،]+$/g, "");
    if (u.length > 2048) continue;
    if (!out.some((x) => x.toLowerCase() === u.toLowerCase())) out.push(u);
  }
  return out.slice(0, 3);
}

export function normalizeUrl(raw) {
  let s = raw.trim()
    .replace(/^hxxps:/i, "https:")
    .replace(/^hxxp:/i, "http:")
    .replace(/\[(?:\.|dot)\]|\(\.\)|\{\.\}/gi, ".");
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    if (/^[a-z][a-z0-9+.-]*:/i.test(s) && !/^[a-z0-9.-]+:\d+/i.test(s)) return { error: "نوع الرابط غير مدعوم (يُفحص http و https فقط)." };
    s = "http://" + s;
  }
  let u;
  try { u = new URL(s); } catch { return { error: "الرابط غير صالح." }; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return { error: "يُفحص http و https فقط." };
  const hasUserInfo = !!(u.username || u.password);
  if (u.hostname.length > 253 || u.href.length > 2048) return { error: "الرابط أطول من الحد المسموح." };
  return { url: u, assumedScheme: !/^https?:\/\//i.test(raw.trim()), hasUserInfo };
}

// لا يفتح FAHS الروابط ولا يتصل بوجهاتها. تتبع التحويلات عبر fetch داخل Worker
// لا يتيح تثبيت عنوان IP بعد DNS؛ لذلك نمتنع عنه لتجنب SSRF وDNS rebinding.
export async function followRedirects(startUrl) {
  return { chain: [startUrl.href], final: startUrl, unresolved: true };
}

// ---------- التحليل المحلي
export function analyzeLocal(url, chainLen = 1, finalUrl = null) {
  const reasons = [];
  let score = 0;
  const add = (pts, txt) => { score += pts; reasons.push(txt); };
  const target = finalUrl || url;
  const host = target.hostname.toLowerCase().replace(/\.$/, "");
  const full = target.href;
  const labels = host.split(".");
  const tld = labels[labels.length - 1];

  if (url.protocol === "http:") add(10, "الرابط لا يستخدم تشفير HTTPS");
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) add(30, "الرابط يستخدم عنوان IP بدل اسم موقع");
  if (host.includes("xn--")) add(30, "اسم النطاق يحتوي ترميزاً (Punycode) قد يخفي حروفاً مشابهة لحروف أخرى");
  // بيانات userinfo قد تخفي الوجهة بصرياً، لكنها ليست دليلاً كافياً على الخبث وحدها.
  const hasUserInfo = !!(target.username || target.password);
  if (labels.length > 4) add(10, "عدد كبير من النطاقات الفرعية");
  if (host.length > 40) add(10, "اسم النطاق طويل بشكل غير معتاد");
  const hostedOnSharedPlatform = [...HOSTING_PLATFORMS].some((suffix) => hostMatches(host, suffix));
  if (hostedOnSharedPlatform) add(30, "الرابط مستضاف على منصة استضافة مشتركة؛ هذا لا يثبت الخبث لكنه لا يثبت موثوقية صاحب الصفحة أيضاً");
  if ((host.match(/-/g) || []).length >= 3) add(10, "اسم النطاق يحتوي شرطات كثيرة");
  if (BAD_TLDS.has(tld)) add(20, `امتداد النطاق (.${tld}) شائع في الروابط الاحتيالية`);
  if (full.length > 200) add(5, "الرابط طويل جداً");

  const kwHost = KEYWORDS.filter((k) => host.includes(k));
  if (kwHost.length) add(Math.min(25, kwHost.length * 10), `كلمات مريبة في اسم النطاق: ${kwHost.join(", ")}`);
  const kwPath = KEYWORDS.filter((k) => (target.pathname + target.search).toLowerCase().includes(k));
  if (kwPath.length) add(Math.min(15, kwPath.length * 5), "كلمات تتعلق بتسجيل الدخول أو التحقق داخل مسار الرابط");
  if (/(?:camera|webcam|photo|capture|snapshot|getusermedia|microphone|record)/i.test(target.pathname + target.search)) {
    add(20, "الرابط يحتوي مؤشرات مرتبطة بالكاميرا أو الميكروفون أو التقاط الوسائط؛ لا يمكن إثبات سلوك الصفحة دون تحليلها");
  }
  if (/(?:redirect|returnurl|return_url|continue|next|target|dest|destination|url)=https?(?:%3a|:)/i.test(target.search)) {
    add(20, "الرابط يحتوي وجهة تحويل مضمّنة قد تقود إلى موقع آخر");
  }
  const pathText = (target.pathname + target.search).toLowerCase();
  for (const [brand, doms] of Object.entries(BRANDS)) {
    if (pathText.includes(brand) && !doms.some((d) => hostMatches(host, d))) {
      add(20, `يظهر اسم «${brand}» داخل مسار الرابط وليس في نطاقه الرسمي؛ تحقق من الوجهة`);
      break;
    }
  }

  for (const [brand, doms] of Object.entries(BRANDS)) {
    if (host.includes(brand) && !doms.some((d) => hostMatches(host, d))) {
      add(35, `يذكر اسم «${brand}» لكنه ليس من نطاقاتها الرسمية (احتمال انتحال)`);
      break;
    }
  }
  // تمويه: حرف رقمي بدل حرفي (paypa1 ...)
  const leet = host.replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/5/g, "s");
  if (leet !== host) {
    for (const [brand, doms] of Object.entries(BRANDS)) {
      if (leet.includes(brand) && !host.includes(brand) && !doms.some((d) => hostMatches(host, d))) {
        add(30, `اسم النطاق يقلّد «${brand}» باستبدال حروف بأرقام`);
        break;
      }
    }
  }
  if (SHORTENERS.has(host) || SHORTENERS.has(url.hostname.toLowerCase())) add(20, "رابط مختصر يخفي الوجهة الأصلية");
  if (chainLen > 3) add(10, "تحويلات متعددة قبل الوصول للوجهة");
  if (finalUrl && finalUrl.hostname.toLowerCase() !== url.hostname.toLowerCase()) {
    if (!SHORTENERS.has(url.hostname.toLowerCase())) add(5, "الرابط يحوّلك إلى موقع مختلف");
  }
  if (hasUserInfo) reasons.push("تنبيه خصوصية: يحتوي الرابط على بيانات قبل علامة @؛ تحقق من اسم النطاق الحقيقي ولا تُدخل بياناتك.");
  return { score, reasons };
}

// ---------- VirusTotal
export async function vtLookup(env, urlStr) {
  if (!env.VT_API_KEY) return { skipped: "no_key" };
  const headers = { "x-apikey": env.VT_API_KEY };
  const id = b64url(urlStr);
  const link = `https://www.virustotal.com/gui/url/${id}`;
  const stats = (s) => ({ malicious: s.malicious || 0, suspicious: s.suspicious || 0, harmless: s.harmless || 0, undetected: s.undetected || 0, timeout: s.timeout || 0 });
  try {
    let r = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, { headers, signal: AbortSignal.timeout(8000) });
    if (r.status === 429) return { error: "rate" };
    if (r.status === 401 || r.status === 403) return { error: "auth" };
    if (r.ok) {
      const j = await r.json();
      const a = j?.data?.attributes;
      const age = Date.now() / 1000 - (a?.last_analysis_date || 0);
      if (a?.last_analysis_stats && age < 7 * 86400) {
        const st = stats(a.last_analysis_stats);
        return { ...st, total: st.malicious + st.suspicious + st.harmless + st.undetected, link };
      }
    }
    // غير موجود أو قديم: نرسله للتحليل
    r = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: { ...headers, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ url: urlStr }).toString(),
      signal: AbortSignal.timeout(8000),
    });
    if (r.status === 429) return { error: "rate" };
    if (!r.ok) return { error: "submit" };
    const aid = (await r.json())?.data?.id;
    if (!aid) return { error: "submit" };
    for (let i = 0; i < 4; i++) {
      await sleep(3500);
      const ar = await fetch(`https://www.virustotal.com/api/v3/analyses/${aid}`, { headers, signal: AbortSignal.timeout(8000) });
      if (ar.status === 429) return { error: "rate" };
      if (!ar.ok) continue;
      const aj = await ar.json();
      if (aj?.data?.attributes?.status === "completed") {
        const st = stats(aj.data.attributes.stats || {});
        return { ...st, total: st.malicious + st.suspicious + st.harmless + st.undetected, link };
      }
    }
    return { error: "pending", link };
  } catch (e) {
    return { error: "network" };
  }
}

// ---------- الحكم النهائي
export function verdictFrom(localScore, vt) {
  let score = localScore;
  if (vt && vt.total !== undefined) {
    score += Math.min(80, vt.malicious * 25) + Math.min(30, vt.suspicious * 10);
  }
  const vtMal = vt?.malicious || 0;
  let level;
  if (vtMal >= 3 || score >= 70) level = "danger";
  else if (score >= 50) level = "high";
  else if (vtMal >= 1 || (vt?.suspicious || 0) >= 1 || score >= 20) level = "warn";
  else level = "ok";
  return { level, score };
}

const LEVEL_TXT = {
  danger: "🔴 <b>خطير</b>",
  high: "🟠 <b>خطورة مرتفعة</b>",
  warn: "🟡 <b>مشبوه</b>",
  ok: "🟢 <b>لم تُكتشف مؤشرات خطر واضحة</b>",
};
const ADVICE = {
  danger: "⛔ <b>لا تفتح الرابط ولا تُدخل أي بيانات.</b> احذف الرسالة، وإن كانت من شخص تعرفه فتواصل معه بقناة أخرى.",
  high: "🟠 <b>مخاطر مرتفعة.</b> لا تفتح الرابط ولا تمنحه صلاحيات أو بيانات، وتحقق من الجهة عبر موقعها الرسمي.",
  warn: "⚠️ <b>تعامل بحذر.</b> لا تُدخل كلمة مرور أو رمزاً أو بيانات بنكية، وتأكد من المصدر بقناة أخرى.",
  ok: "ℹ️ هذه النتيجة <b>لا تعني ضماناً كاملاً</b>؛ فالروابط الجديدة قد لا تكون مرصودة بعد. لا تُدخل بياناتك إلا إن كنت متأكداً من الجهة.",
};
const VT_ERR = {
  rate: "خدمة VirusTotal مشغولة حالياً (حد الطلبات)، حاول بعد دقيقة.",
  auth: "مفتاح VirusTotal غير صالح (راجع إعدادات البوت).",
  pending: "التحليل ما زال جارياً لدى VirusTotal؛ أعد الفحص بعد قليل.",
  submit: "تعذر إرسال الرابط إلى VirusTotal.",
  network: "تعذر الاتصال بـ VirusTotal.",
};

export function formatReport({ original, chain, finalUrl, local, vt, vtEnabled, verdict, notes = [] }) {
  const lines = [];
  lines.push("🔍 <b>تقرير فحص الرابط</b>");
  lines.push("");
  lines.push(`🌐 <b>النطاق:</b> <code>${esc((finalUrl || original).hostname)}</code>`);
  if (chain.length > 1) {
    lines.push(`🔀 <b>الوجهة النهائية</b> (بعد ${chain.length - 1} تحويل):\n<code>${esc(shorten(chain[chain.length - 1], 180))}</code>`);
  }
  lines.push(`📊 <b>مستوى الخطورة:</b> ${LEVEL_TXT[verdict.level]}`);
  lines.push(`📈 <b>مؤشر الاشتباه:</b> ${Math.min(100, verdict.score)}/100`);
  lines.push("");
  if (vt && vt.total !== undefined) {
    lines.push(`🛡 <b>VirusTotal:</b> ${vt.malicious} خطير، ${vt.suspicious} مشبوه، من أصل ${vt.total} محرك فحص`);
  } else if (vtEnabled && vt?.error) {
    lines.push(`🛡 <b>VirusTotal:</b> ${VT_ERR[vt.error] || "غير متاح"}`);
  } else {
    lines.push(vt?.skipped === "sensitive_url" ? "🛡 <b>VirusTotal:</b> لم نرسل الرابط لأنه قد يحتوي على رمز أو بيانات خاصة." : "🛡 <b>VirusTotal:</b> غير مفعّل (التحليل المحلي فقط)");
  }
  if (local.reasons.length) {
    lines.push("");
    lines.push("⚠️ <b>ملاحظات التحليل:</b>");
    for (const r of local.reasons.slice(0, 8)) lines.push(`• ${esc(r)}`);
  }
  for (const n of notes) lines.push(`• ${esc(n)}`);
  lines.push("");
  lines.push(ADVICE[verdict.level]);
  lines.push("");
  lines.push("🌿 وصلِّ على النبي ﷺ");
  return lines.join("\n");
}

const shorten = (s, n) => (s.length > n ? s.slice(0, n) + "…" : s);

// ---------- الدالة الرئيسية
export async function scanUrl(env, raw, { useVt = false } = {}) {
  const n = normalizeUrl(raw);
  if (n.error) return { error: n.error };
  const url = n.url;
  if (isPrivateHost(url.hostname)) {
    return { error: "لا يمكن فحص العناوين الداخلية أو المحلية (localhost / شبكات خاصة) لأسباب أمنية." };
  }
  const notes = [];
  if (n.assumedScheme) notes.push("لم يحدد الرابط بروتوكولاً، افترضنا http.");
  const red = await followRedirects(url);
  if (SHORTENERS.has(url.hostname.toLowerCase()) || /(?:^|[?&])(redirect|url|target|dest|next)=/i.test(url.search)) {
    notes.push("لم نفتح الرابط أو نتصل بوجهته؛ لذلك لا يمكن تأكيد الوجهة النهائية أو التحويلات.");
  }
  const finalUrl = red.final && red.chain.length > 1 ? red.final : null;
  const local = analyzeLocal(url, red.chain.length, finalUrl);
  const target = (finalUrl || url).href;
  const sensitiveKeys = [...url.searchParams.keys()].map((key) => key.toLowerCase().replace(/[^a-z0-9]/g, ""));
  const sensitive = !!(url.username || url.password) || sensitiveKeys.some((key) => /^(?:token|accesstoken|auth|authorization|session|code|verificationcode|otp|password|secret|key|sid|ticket|jwt|signature|cookie|credential|pin|chatid|userid|user_id|email|phone|mobile|accountid)$/.test(key)) || /(?:token|auth|session|otp|password|secret|signature)/i.test(url.hash);
  if (sensitive) {
    local.reasons.push("تنبيه خصوصية: قد يحتوي الرابط على معرّف أو بيانات شخصية/رمز وصول ضمن معاملات العنوان؛ تجنّب نشره علناً.");

  }
  const vt = useVt && !sensitive ? await vtLookup(env, target) : { skipped: sensitive ? "sensitive_url" : "disabled" };
  const verdict = verdictFrom(local.score, vt);
  const text = formatReport({ original: url, chain: red.chain, finalUrl, local, vt, vtEnabled: useVt && !!env.VT_API_KEY, verdict, notes });
  return { text, verdict, host: (finalUrl || url).hostname, vtLink: vt?.link || null };
}
