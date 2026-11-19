// محاكي بسيط لـ D1 فوق node:sqlite لأغراض الاختبار المحلي
import { DatabaseSync } from "node:sqlite";
export function makeD1() {
  const db = new DatabaseSync(":memory:");
  const mk = (sql, args = []) => ({
    bind: (...a) => mk(sql, a),
    first: async () => db.prepare(sql).get(...args) ?? null,
    all: async () => ({ results: db.prepare(sql).all(...args) }),
    run: async () => { const r = db.prepare(sql).run(...args); return { meta: { last_row_id: Number(r.lastInsertRowid), changes: Number(r.changes) } }; },
  });
  return {
    prepare: (sql) => mk(sql),
    batch: async (list) => { const out = []; for (const s of list) out.push(await s.run()); return out; },
  };
}
