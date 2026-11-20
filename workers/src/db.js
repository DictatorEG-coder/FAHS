
// قاعدة البيانات (Cloudflare D1) - إنشاء الجداول تلقائياً عند أول تشغيل
import { SEED_SECTIONS, SEED_BLOCKS } from "./seed.js";
import { now } from "./util.js";

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, first_seen INTEGER, last_seen INTEGER, banned INTEGER DEFAULT 0, active INTEGER DEFAULT 1)`,
  `CREATE TABLE IF NOT EXISTS sections (id INTEGER PRIMARY KEY AUTOINCREMENT, parent_id INTEGER DEFAULT 0, title TEXT NOT NULL, position INTEGER DEFAULT 0, visible INTEGER DEFAULT 1)`,
  `CREATE TABLE IF NOT EXISTS blocks (id INTEGER PRIMARY KEY AUTOINCREMENT, section_id INTEGER NOT NULL, position INTEGER DEFAULT 0, type TEXT NOT NULL, content TEXT, caption TEXT)`,
  `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`,
  `CREATE TABLE IF NOT EXISTS states (user_id INTEGER PRIMARY KEY, state TEXT, data TEXT, updated INTEGER)`,
  `CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, verdict TEXT, host TEXT)`,
  `CREATE TABLE IF NOT EXISTS rl (key TEXT PRIMARY KEY, win INTEGER, n INTEGER)`,
  `CREATE TABLE IF NOT EXISTS broadcasts (id INTEGER PRIMARY KEY AUTOINCREMENT, from_chat INTEGER, message_id INTEGER, status TEXT, last_user INTEGER DEFAULT 0, sent INTEGER DEFAULT 0, failed INTEGER DEFAULT 0, total INTEGER DEFAULT 0, created INTEGER)`,
  `CREATE TABLE IF NOT EXISTS group_settings (chat_id INTEGER PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 0, updated INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS idx_blocks_sec ON blocks(section_id, position)`,
  `CREATE INDEX IF NOT EXISTS idx_sections_parent ON sections(parent_id, position)`,
];

export const DEFAULT_SETTINGS = {
  welcome_text:
    "🟢 <b>أهلاً بك في فَحْص | FAHS</b>\n\nبوت الأمن الرقمي: افحص أي رابط مشبوه قبل أن تفتحه، وتعلّم كيف تحمي نفسك وعائلتك من الاحتيال الإلكتروني.\n\n👇 اختر من القائمة:",
  maintenance: "0",
  scan_limit_per_hour: "20",
  vt_enabled: "0",
  maintenance_text: "🛠 البوت تحت الصيانة حالياً، حاول لاحقاً.",
};

let ready = false;

export async function ensureDb(env) {
  if (ready) return;
  const db = env.DB;
  await db.batch(SCHEMA.map((s) => db.prepare(s)));
  const seeded = await db.prepare("SELECT value FROM settings WHERE key='seeded'").first();
  if (!seeded) {
    const st = [];
    for (const s of SEED_SECTIONS) {
      st.push(
        db
          .prepare("INSERT OR IGNORE INTO sections (id,parent_id,title,position,visible) VALUES (?,?,?,?,1)")
          .bind(s.id, s.parent || 0, s.title, s.pos)
      );
    }
    let p = 0;
    for (const b of SEED_BLOCKS) {
      st.push(
        db
          .prepare("INSERT INTO blocks (section_id,position,type,content,caption) VALUES (?,?,?,?,?)")
          .bind(b.sec, p++, "text", b.text, null)
      );
    }
    for (const [k, v] of Object.entries(DEFAULT_SETTINGS)) {
      st.push(db.prepare("INSERT OR IGNORE INTO settings (key,value) VALUES (?,?)").bind(k, v));
    }
    st.push(db.prepare("INSERT OR REPLACE INTO settings (key,value) VALUES ('seeded','1')"));
    // دفعات صغيرة لتفادي حدود D1
    for (let i = 0; i < st.length; i += 50) await db.batch(st.slice(i, i + 50));
  }
  // ترحيل إضافي آمن: إضافة أقسام توعية الروابط للمستخدمين الحاليين دون إعادة زرع المحتوى القديم.
  const menuV2 = await db.prepare("SELECT value FROM settings WHERE key='scanner_menu_v2_seeded'").first();
  if (!menuV2) {
    const extra = [];
    for (const s of SEED_SECTIONS.filter((x) => [45, 46, 47, 48, 49].includes(x.id))) {
      extra.push(db.prepare("INSERT OR IGNORE INTO sections (id,parent_id,title,position,visible) VALUES (?,?,?,?,1)").bind(s.id, s.parent || 0, s.title, s.pos));
    }
    for (const b of SEED_BLOCKS.filter((x) => [45, 46, 47].includes(x.sec))) {
      extra.push(db.prepare("INSERT INTO blocks (section_id,position,type,content,caption) VALUES (?,?,?,?,?)").bind(b.sec, 0, "text", b.text, null));
    }
    extra.push(db.prepare("INSERT OR REPLACE INTO settings (key,value) VALUES ('scanner_menu_v2_seeded','1')"));
    for (let i = 0; i < extra.length; i += 50) await db.batch(extra.slice(i, i + 50));
  }
  ready = true;
}

export const resetReady = () => (ready = false);

export const first = (env, sql, ...args) => env.DB.prepare(sql).bind(...args).first();
export const all = async (env, sql, ...args) => (await env.DB.prepare(sql).bind(...args).all()).results || [];
export const run = (env, sql, ...args) => env.DB.prepare(sql).bind(...args).run();

// ---- الإعدادات
export async function getSetting(env, key) {
  const r = await first(env, "SELECT value FROM settings WHERE key=?", key);
  return r ? r.value : DEFAULT_SETTINGS[key] ?? null;
}
export const setSetting = (env, key, value) =>
  run(env, "INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, String(value));

// ---- حالة المحادثة (للإدخال متعدد الخطوات)
export async function getState(env, uid) {
  const r = await first(env, "SELECT state,data FROM states WHERE user_id=?", uid);
  if (!r) return null;
  let data = {};
  try { data = JSON.parse(r.data || "{}"); } catch {}
  return { state: r.state, data };
}
export const setState = (env, uid, state, data = {}) =>
  run(env, "INSERT INTO states (user_id,state,data,updated) VALUES (?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET state=excluded.state,data=excluded.data,updated=excluded.updated", uid, state, JSON.stringify(data), now());
export const clearState = (env, uid) => run(env, "DELETE FROM states WHERE user_id=?", uid);

// ---- تحديد المعدل: يرجع true إن كان مسموحاً
export async function rateLimit(env, key, windowSec, max) {
  const t = now();
  const win = Math.floor(t / windowSec);
  const r = await first(env, "SELECT win,n FROM rl WHERE key=?", key);
  if (!r || r.win !== win) {
    await run(env, "INSERT INTO rl (key,win,n) VALUES (?,?,1) ON CONFLICT(key) DO UPDATE SET win=excluded.win,n=1", key, win);
    return true;
  }
  if (r.n >= max) return false;
  await run(env, "UPDATE rl SET n=n+1 WHERE key=?", key);
  return true;
}

// ---- المستخدمون
export async function touchUser(env, uid) {
  const t = now();
  await run(env, "INSERT INTO users (id,first_seen,last_seen) VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen, active=1", uid, t, t);
  return first(env, "SELECT banned FROM users WHERE id=?", uid);
}

// ---- الأقسام
export const getSection = (env, id) => first(env, "SELECT * FROM sections WHERE id=?", id);
export const getChildren = (env, parent, onlyVisible = true) =>
  all(env, `SELECT * FROM sections WHERE parent_id=? ${onlyVisible ? "AND visible=1" : ""} ORDER BY position,id`, parent);
export const getBlocks = (env, sec) => all(env, "SELECT * FROM blocks WHERE section_id=? ORDER BY position,id", sec);

export async function deleteSectionTree(env, id) {
  const rows = await all(
    env,
    `WITH RECURSIVE t(id) AS (SELECT id FROM sections WHERE id=? UNION ALL SELECT s.id FROM sections s JOIN t ON s.parent_id=t.id) SELECT id FROM t`,
    id
  );
  const ids = rows.map((r) => r.id);
  if (!ids.length) return 0;
  const ph = ids.map(() => "?").join(",");
  await env.DB.batch([
    env.DB.prepare(`DELETE FROM blocks WHERE section_id IN (${ph})`).bind(...ids),
    env.DB.prepare(`DELETE FROM sections WHERE id IN (${ph})`).bind(...ids),
  ]);
  return ids.length;
}

export async function moveSection(env, id, dir) {
  const s = await getSection(env, id);
  if (!s) return;
  const sibs = await getChildren(env, s.parent_id, false);
  const idx = sibs.findIndex((x) => x.id === id);
  const j = idx + dir;
  if (idx < 0 || j < 0 || j >= sibs.length) return;
  [sibs[idx], sibs[j]] = [sibs[j], sibs[idx]];
  await env.DB.batch(sibs.map((x, i) => env.DB.prepare("UPDATE sections SET position=? WHERE id=?").bind(i, x.id)));
}
