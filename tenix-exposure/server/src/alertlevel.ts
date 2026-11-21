// Two levels per (CVE, host): the CVE level (its severity) and the asset level (how much the machine matters to the customer). The notify level is a 4x4 matrix lookup
// (editable per organization) and is raised to CRITICAL on evidence that the machine is being attacked. Nothing here writes to Falcon: the only call is the read-only Alerts query.
import { all, get, now, run } from "./db.ts";
import { FalconClient, configFor } from "./falcon.ts";

export const LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
export type Level = (typeof LEVELS)[number];
/** The asset level adds "no level known"; for the matrix it counts as Medium. */
export type AssetLevel = Level | "UNASSIGNED";
export type Matrix = Record<Level, Record<Level, Level>>; // matrix[cveLevel][assetLevel]
const rank = (l: Level) => LEVELS.indexOf(l); // 0 = Critical

/** Equal -> that level; else the lower one >= High -> the higher; else one step below the higher (floor Low). */
export function defaultLevel(cve: Level, asset: Level): Level {
  if (cve === asset) return cve;
  const hi = Math.min(rank(cve), rank(asset)), lo = Math.max(rank(cve), rank(asset));
  return LEVELS[lo <= 1 ? hi : Math.min(3, hi + 1)];
}
export const DEFAULT_MATRIX: Matrix = Object.fromEntries(LEVELS.map((c) => [c, Object.fromEntries(LEVELS.map((a) => [a, defaultLevel(c, a)]))])) as Matrix;

/** null when `v` is not a complete 4x4 matrix of levels. */
export function parseMatrix(v: unknown): Matrix | null {
  if (!v || typeof v !== "object") return null;
  const out: any = {};
  for (const c of LEVELS) {
    const row = (v as any)[c];
    if (!row || typeof row !== "object") return null;
    out[c] = {};
    for (const a of LEVELS) { if (!(LEVELS as readonly unknown[]).includes(row[a])) return null; out[c][a] = row[a]; }
  }
  return out;
}

/** Severity text from Falcon (CRITICAL..LOW, NONE = informational) to a matrix level; informational counts as Low. */
export const cveLevelOf = (sev: string): Level => ((LEVELS as readonly string[]).includes(sev) ? (sev as Level) : "LOW");
export const matrixAsset = (a: AssetLevel): Level => (a === "UNASSIGNED" ? "MEDIUM" : a);
export const lookup = (m: Matrix, cve: Level, asset: AssetLevel): Level => m[cve][matrixAsset(asset)];
export const higher = (a: Level, b: Level): Level => (rank(a) <= rank(b) ? a : b);

// ---------------------------------------------------------------- asset level
const fromText = (v: string | null | undefined): Level | null => { const u = String(v ?? "").trim().toUpperCase(); return (LEVELS as readonly string[]).includes(u) ? (u as Level) : null; };
export type AssetSource = "watchlist" | "falcon" | "group" | "none";
export interface Asset { level: AssetLevel; source: AssetSource }

/** (a) the watchlist's manual level, (b) Falcon's own asset criticality (hosts.criticality, read by the hosts sync), (c) the highest level mapped to one of the host's groups, (d) unassigned. */
export async function assetLevels(tenantId: string, aids: string[]): Promise<Map<string, Asset>> {
  const out = new Map<string, Asset>();
  const uniq = [...new Set(aids)];
  if (!uniq.length) return out;
  const cids = (await all<{ cid: string }>("SELECT cid FROM tenant_cids WHERE tenant_id = ?", tenantId)).map((r) => r.cid);
  const manual = new Map((await all<{ aid: string; criticality: string }>("SELECT aid, criticality FROM watch_hosts WHERE tenant_id = ? AND criticality IS NOT NULL", tenantId)).map((r) => [r.aid, r.criticality]));
  const groups = new Map((await all<{ group_name: string; level: Level }>("SELECT group_name, level FROM notify_group_levels WHERE tenant_id = ?", tenantId)).map((r) => [r.group_name.toLowerCase(), r.level]));
  const inv = new Map<string, { criticality: string | null; groups: string[] }>();
  for (let i = 0; cids.length && i < uniq.length; i += 1000) {
    const part = uniq.slice(i, i + 1000);
    for (const r of await all<{ aid: string; criticality: string | null; groups: string[] }>(`SELECT aid, criticality, groups FROM hosts WHERE cid IN (${cids.map(() => "?").join(",")}) AND aid IN (${part.map(() => "?").join(",")})`, ...cids, ...part))
      inv.set(r.aid, r);
  }
  for (const aid of uniq) {
    const h = inv.get(aid);
    const a = fromText(manual.get(aid)), f = fromText(h?.criticality);
    const g = (h?.groups ?? []).map((n) => groups.get(n.toLowerCase())).filter((x): x is Level => !!x).sort((x, y) => rank(x) - rank(y))[0];
    out.set(aid, a ? { level: a, source: "watchlist" } : f ? { level: f, source: "falcon" } : g ? { level: g, source: "group" } : { level: "UNASSIGNED", source: "none" });
  }
  return out;
}

// ---------------------------------------------------------------- evidence of an attack on the machine
export interface Esc { type: "alert" | "kev" | "exploited"; alertId?: string; days: number }
export const evidenceHooks = {
  ttlMs: 30 * 60_000, statusTtlMs: 60 * 60_000, maxLookups: 30, gapMs: 150,
  sleep: (ms: number) => new Promise<void>((r) => setTimeout(r, ms)),
  /** One read-only GET of the Alerts API: how many alerts Falcon has on this device since `sinceMs`, and the newest one's id. */
  query: async (cid: string, aid: string, sinceMs: number): Promise<{ ok: true; count: number; newest: string | null } | { ok: false; status: number }> => {
    const cfg = await configFor(cid);
    if (!cfg) return { ok: false, status: 0 };
    const key = `${cfg.baseUrl}|${cfg.clientId}|${cfg.clientSecret}`;
    if (liveClient?.key !== key) liveClient = { key, client: new FalconClient(cfg) };
    const since = new Date(Math.floor(sinceMs / 1000) * 1000).toISOString().replace(".000Z", "Z");
    const r = await liveClient.client.get("/alerts/queries/alerts/v2", { filter: `device.device_id:'${aid}'+created_timestamp:>'${since}'`, sort: "created_timestamp|desc", limit: 1 });
    if (!r.ok) return { ok: false, status: r.status };
    const total = r.data?.meta?.pagination?.total;
    return { ok: true, count: typeof total === "number" ? total : (r.data?.resources ?? []).length, newest: typeof r.data?.resources?.[0] === "string" ? r.data.resources[0].slice(0, 200) : null };
  },
};
let liveClient: { key: string; client: FalconClient } | null = null;
const AID = /^[0-9a-f]{32}$/i; // also keeps anything but a sensor id out of the FQL filter

export type EvidenceState = "unknown" | "ok" | "forbidden";
export async function evidenceStatus(tenantId: string): Promise<{ state: EvidenceState; checkedAt: number | null }> {
  const r = await get<{ state: string; checked_at: number }>("SELECT state, checked_at FROM attack_evidence WHERE tenant_id = ? AND aid = '*'", tenantId);
  return r ? { state: r.state === "forbidden" ? "forbidden" : "ok", checkedAt: r.checked_at } : { state: "unknown", checkedAt: null };
}
const setStatus = (tenantId: string, state: "ok" | "forbidden") =>
  run(`INSERT INTO attack_evidence (tenant_id, aid, state, days, alerts, alert_id, checked_at) VALUES (?, '*', ?, 0, 0, NULL, ?) ON CONFLICT (tenant_id, aid) DO UPDATE SET state = excluded.state, checked_at = excluded.checked_at`, tenantId, state, now());

/** The machines (of this organization) that have a Falcon alert in the last `days` days. Cached; at most `maxLookups` uncached machines per call (`fresh` false = cache only);
 *  a 403 (the API client lacks the Alerts read scope) is remembered for an hour and no more calls are made: no escalation, never an error. */
export async function attackEvidence(tenantId: string, aids: string[], days: number, fresh = true): Promise<Map<string, Esc>> {
  const out = new Map<string, Esc>();
  const want = [...new Set(aids)].filter((a) => AID.test(a));
  if (!want.length) return out;
  const t = now();
  const st = await get<{ state: string; checked_at: number }>("SELECT state, checked_at FROM attack_evidence WHERE tenant_id = ? AND aid = '*'", tenantId);
  if (st?.state === "forbidden" && t - st.checked_at < evidenceHooks.statusTtlMs) return out;
  const cached = new Map<string, { state: string; alert_id: string | null }>();
  for (let i = 0; i < want.length; i += 1000) {
    const part = want.slice(i, i + 1000);
    for (const r of await all<{ aid: string; state: string; alert_id: string | null }>(`SELECT aid, state, alert_id FROM attack_evidence WHERE tenant_id = ? AND days = ? AND checked_at > ? AND aid IN (${part.map(() => "?").join(",")})`, tenantId, days, t - evidenceHooks.ttlMs, ...part))
      cached.set(r.aid, r);
  }
  for (const [aid, r] of cached) if (r.state === "alert") out.set(aid, { type: "alert", alertId: r.alert_id ?? undefined, days });
  const todo = want.filter((a) => !cached.has(a)).slice(0, fresh ? evidenceHooks.maxLookups : 0);
  if (!todo.length) return out;
  const cids = (await all<{ cid: string }>("SELECT cid FROM tenant_cids WHERE tenant_id = ?", tenantId)).map((r) => r.cid);
  const where = new Map<string, string>();
  for (const r of await all<{ aid: string; cid: string }>(`SELECT DISTINCT aid, cid FROM hosts WHERE cid IN (${cids.map(() => "?").join(",") || "NULL"}) AND aid IN (${todo.map(() => "?").join(",")})`, ...cids, ...todo)) where.set(r.aid, r.cid);
  for (const r of await all<{ aid: string; cid: string }>(`SELECT DISTINCT aid, cid FROM roll_host WHERE cid IN (${cids.map(() => "?").join(",") || "NULL"}) AND aid IN (${todo.map(() => "?").join(",")})`, ...cids, ...todo)) if (!where.has(r.aid)) where.set(r.aid, r.cid);
  let errors = 0;
  for (const aid of todo) {
    const cid = where.get(aid);
    if (!cid) continue; // not a machine of this organization: never asked
    const r = await evidenceHooks.query(cid, aid, t - days * 86_400_000).catch(() => ({ ok: false as const, status: 0 }));
    if (!r.ok) {
      if (r.status === 403) { await setStatus(tenantId, "forbidden"); return out; }
      if (++errors >= 3) return out; // Falcon is unwell: stop asking, nothing is cached
      continue;
    }
    await run(`INSERT INTO attack_evidence (tenant_id, aid, state, days, alerts, alert_id, checked_at) VALUES (?,?,?,?,?,?,?)
               ON CONFLICT (tenant_id, aid) DO UPDATE SET state = excluded.state, days = excluded.days, alerts = excluded.alerts, alert_id = excluded.alert_id, checked_at = excluded.checked_at`,
      tenantId, aid, r.count > 0 ? "alert" : "none", days, r.count, r.newest, now());
    if (r.count > 0) out.set(aid, { type: "alert", alertId: r.newest ?? undefined, days });
    if (!st || st.state !== "ok") await setStatus(tenantId, "ok");
    await evidenceHooks.sleep(evidenceHooks.gapMs);
  }
  return out;
}

/** One cheap call (at most once an hour per organization) so the settings can say whether the API client may read alerts. */
export async function probeEvidence(tenantId: string): Promise<void> {
  const st = await evidenceStatus(tenantId);
  if (st.checkedAt && now() - st.checkedAt < evidenceHooks.statusTtlMs) return;
  const row = await get<{ aid: string; cid: string }>("SELECT h.aid, h.cid FROM hosts h JOIN tenant_cids x ON x.cid = h.cid WHERE x.tenant_id = ? ORDER BY h.aid LIMIT 1", tenantId);
  if (!row || !AID.test(row.aid)) return;
  const r = await evidenceHooks.query(row.cid, row.aid, now() - 86_400_000).catch(() => ({ ok: false as const, status: 0 }));
  if (r.ok) await setStatus(tenantId, "ok"); else if (r.status === 403) await setStatus(tenantId, "forbidden");
}
