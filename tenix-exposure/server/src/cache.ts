// Computed answers per organization (the Overview runs a dozen aggregate queries over every finding), kept until the organization's data changes.
// The key says who asked what; the version says which data it was computed from, so a sync, a failed sync or a KEV change makes the next read recompute.
// Nothing is served before tenantScope() has authorized the request: this module only remembers results, it decides nothing about access.
// Two layers: memory (300 entries) and the result_cache table, so a restart does not make the next page view slow. warmAll() refills both after start.
import { all, get, now, run } from "./db.ts";

const MAX = 300;
const store = new Map<string, { ver: string; json: string }>();
const inflight = new Map<string, Promise<string>>();
export const stats = { memoryHits: 0, databaseHits: 0, builds: 0, lastBuildMs: 0, totalBuildMs: 0, slowestMs: 0, warmedAt: 0, warming: false };

async function version(cids: string[]): Promise<string> {
  const rows = cids.length ? await all<{ cid: string; data_as_of: number | null; last_run_at: number }>(`SELECT cid, data_as_of, last_run_at FROM cid_status WHERE cid IN (${cids.map(() => "?").join(",")}) ORDER BY cid`, ...cids) : [];
  const kev = (await get<{ n: number }>("SELECT COUNT(*) n FROM kev"))!.n;
  const snap = cids.length ? (await get<{ n: number; t: number | null }>(`SELECT COUNT(*) n, MAX(ts) t FROM snapshots WHERE cid IN (${cids.map(() => "?").join(",")})`, ...cids))! : { n: 0, t: 0 };
  const ret = cids.length ? (await get<{ t: number | null }>(`SELECT MAX(s.changed_at) t FROM tenant_settings s JOIN tenant_cids x ON x.tenant_id = s.tenant_id WHERE x.cid IN (${cids.map(() => "?").join(",")})`, ...cids))!.t ?? 0 : 0;
  const ext = cids.length ? (await get<{ t: number | null }>(`SELECT MAX(last_run_at) t FROM external_sync WHERE cid IN (${cids.map(() => "?").join(",")})`, ...cids))!.t ?? 0 : 0;
  // the host inventory and the rollups change on their own schedule (hourly hosts sync, rollup refresh), the v2 pages read both
  const hs = cids.length ? (await get<{ t: number | null }>(`SELECT MAX(COALESCE(as_of, 0) + last_run_at) t FROM hosts_sync WHERE cid IN (${cids.map(() => "?").join(",")})`, ...cids))!.t ?? 0 : 0;
  const ru = cids.length ? (await get<{ t: number | null }>(`SELECT MAX(n) t FROM cid_counts WHERE key = 'rollupAt' AND cid IN (${cids.map(() => "?").join(",")})`, ...cids))!.t ?? 0 : 0;
  return `${rows.map((r) => `${r.cid}:${r.data_as_of ?? 0}:${r.last_run_at}`).join(",")}|${cids.length}|${kev}|${snap.n}:${snap.t ?? 0}|${ext}|${ret}|${hs}|${ru}`;
}

/** For tests: what a restart does to the memory layer. */
export const forgetMemory = () => store.clear();

function remember(key: string, ver: string, json: string) {
  store.delete(key);
  store.set(key, { ver, json });
  if (store.size > MAX) store.delete(store.keys().next().value!);
}

export async function cached<T>(key: string, cids: string[], build: () => Promise<T>): Promise<T> {
  const ver = await version(cids);
  const hit = store.get(key);
  if (hit && hit.ver === ver) { stats.memoryHits++; return JSON.parse(hit.json) as T; }
  const saved = await get<{ ver: string; json: string }>("SELECT ver, json FROM result_cache WHERE key = ?", key);
  if (saved && saved.ver === ver) { stats.databaseHits++; remember(key, ver, saved.json); return JSON.parse(saved.json) as T; }
  const tag = `${key}@${ver}`;
  let p = inflight.get(tag); // concurrent first reads share one computation
  if (!p) {
    const t0 = Date.now();
    p = build().then(async (v) => {
      const json = JSON.stringify(v);
      const ms = Date.now() - t0;
      stats.builds++; stats.lastBuildMs = ms; stats.totalBuildMs += ms; stats.slowestMs = Math.max(stats.slowestMs, ms);
      await run(`INSERT INTO result_cache (key, ver, json, built_at, build_ms) VALUES (?,?,?,?,?)
                 ON CONFLICT (key) DO UPDATE SET ver = excluded.ver, json = excluded.json, built_at = excluded.built_at, build_ms = excluded.build_ms`, key, ver, json, now(), ms).catch(() => {});
      return json;
    }).finally(() => inflight.delete(tag));
    inflight.set(tag, p);
  }
  const json = await p;
  remember(key, ver, json);
  return JSON.parse(json) as T;
}

/** Called after a CID has been stored: recompute what the first page view would ask for, so nobody waits for it. */
export const warmers: ((cid: string) => Promise<void>)[] = [];
export function warmAfterSync(cid: string) { for (const w of warmers) void w(cid).catch((e) => console.error("[cache] warm-up failed", e)); }
/** After a start: every organization's default answers, one CID at a time so the database is not hit all at once. */
export async function warmAll() {
  stats.warming = true;
  try {
    for (const { cid } of await all<{ cid: string }>("SELECT cid FROM tenant_cids ORDER BY cid")) for (const w of warmers) await w(cid).catch((e) => console.error("[cache] warm-up failed", e));
    stats.warmedAt = now();
  } finally { stats.warming = false; }
}
