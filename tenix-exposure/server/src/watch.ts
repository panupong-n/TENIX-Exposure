// The watchlist: hosts an organization chose to keep an eye on (shared by its users), and the automatic "watch items" next to them.
// Every route goes through tenantScope(); an aid that is not a host of the organization's CIDs is a 404, the same as an unknown one.
import { all, audit, byName, get, isSoc, now, run } from "./db.ts";
import { HttpError, route, type Ctx } from "./http.ts";
import { inList, tenantScope, type Scope } from "./scope.ts";
import { cached, warmers } from "./cache.ts";
import { urgentFor } from "./feeds.ts";

export const WATCH_LIMIT = 200;
const SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"];
const AID = /^[0-9A-Za-z_.:-]{6,128}$/;
const DAY = 86_400_000;

/** The aids a tenant watches: for the other pages that show a star on a host row. */
export async function watchedSet(tenantId: string): Promise<Set<string>> {
  return new Set((await all<{ aid: string }>("SELECT aid FROM watch_hosts WHERE tenant_id = ?", tenantId)).map((r) => r.aid));
}

/** The host as the tenant's own CIDs know it (rollup first, then the host inventory when that table exists). null = not this tenant's host. */
async function ownHost(s: Scope, aid: string): Promise<{ cid: string; hostname: string | null } | null> {
  if (!s.cids.length) return null;
  const r = await get<{ cid: string; hostname: string | null }>(`SELECT cid, MAX(hostname) AS hostname FROM roll_host WHERE cid IN ${inList(s.cids)} AND aid = ? GROUP BY cid LIMIT 1`, ...s.cids, aid);
  if (r) return r;
  try { return (await get<{ cid: string; hostname: string | null }>(`SELECT cid, hostname FROM hosts WHERE cid IN ${inList(s.cids)} AND aid = ? LIMIT 1`, ...s.cids, aid)) ?? null; } catch { return null; } // no inventory table yet
}

interface WatchRow { aid: string; cid: string; hostname: string | null; note: string; criticality: string | null; added_by_name: string | null; added_at: number }

async function hostRows(s: Scope, rows: WatchRow[]) {
  if (!rows.length) return [];
  const aids = rows.map((r) => r.aid);
  const ph = inList(aids);
  const since = now() - DAY;
  const roll = new Map((await all<any>(`SELECT aid, MIN(rank) AS rank, SUM(critical) AS critical, SUM(high) AS high, BOOL_OR(src = 'external') AS external FROM roll_host WHERE cid IN ${inList(s.cids)} AND aid IN ${ph} GROUP BY aid`, ...s.cids, ...aids)).map((r) => [r.aid, r]));
  // one pass over the stored findings of just these hosts (the (cid, aid) index): P1 = Critical, ExPRT Critical, exploited, or in CISA KEV
  const fin = new Map((await all<any>(
    `SELECT aid, COUNT(*) AS n, MAX(synced_at) AS synced, COUNT(*) FILTER (WHERE p1) AS p1, COUNT(*) FILTER (WHERE kev) AS kev,
            COUNT(*) FILTER (WHERE first_seen >= ?) AS new_n, COUNT(*) FILTER (WHERE first_seen >= ? AND p1) AS new_p1, COUNT(*) FILTER (WHERE first_seen >= ? AND severity = 'CRITICAL') AS new_crit
     FROM (SELECT f.aid, f.severity, f.first_seen, f.synced_at, EXISTS (SELECT 1 FROM kev k WHERE k.cve_id = f.cve_id) AS kev,
                  (f.severity = 'CRITICAL' OR UPPER(COALESCE(f.exprt, '')) = 'CRITICAL' OR COALESCE(f.exploit_status, 0) >= 60 OR EXISTS (SELECT 1 FROM kev k WHERE k.cve_id = f.cve_id)) AS p1
           FROM findings_t f WHERE f.cid IN ${inList(s.cids)} AND f.aid IN ${ph}) x GROUP BY aid`, since, since, since, ...s.cids, ...aids)).map((r) => [r.aid, r]));
  let seen = new Map<string, number | null>();
  try { seen = new Map((await all<{ aid: string; last_seen: number | null }>(`SELECT aid, last_seen FROM hosts WHERE cid IN ${inList(s.cids)} AND aid IN ${ph}`, ...s.cids, ...aids)).map((r) => [r.aid, r.last_seen])); } catch { /* no inventory yet */ }
  const out = rows.map((w) => {
    const r = roll.get(w.aid), f = fin.get(w.aid);
    const held = !!(r || f);
    return {
      aid: w.aid, hostname: w.hostname, note: w.note, criticality: w.criticality, addedBy: w.added_by_name, addedAt: w.added_at,
      worstSeverity: r ? SEV[r.rank] : null, p1: f ? f.p1 : held ? 0 : null, critical: r ? r.critical : null, high: r ? r.high : null,
      newFindings24h: f?.new_n ?? 0, newP1_24h: f?.new_p1 ?? 0, newCritical24h: f?.new_crit ?? 0, kevCves: f?.kev ?? 0,
      lastSeen: seen.get(w.aid) ?? null, lastSynced: f?.synced ?? null, missing: !held && !seen.has(w.aid), external: !!r?.external,
    };
  });
  // new first, then P1 (most first), then name
  const byN = new Map(byName(out.map((o) => ({ name: o.hostname ?? o.aid, o }))).map((x, i) => [x.o.aid, i]));
  return out.sort((a, b) => Number(b.newFindings24h > 0) - Number(a.newFindings24h > 0) || (b.p1 ?? -1) - (a.p1 ?? -1) || byN.get(a.aid)! - byN.get(b.aid)!);
}

async function rowsOf(s: Scope, aids?: string[]) {
  const rows = await all<WatchRow>(`SELECT aid, cid, hostname, note, criticality, added_by_name, added_at FROM watch_hosts WHERE tenant_id = ?${aids ? ` AND aid IN ${inList(aids)}` : ""}`, s.tenantId, ...(aids ?? []));
  return hostRows(s, rows);
}
const count = async (s: Scope) => (await get<{ n: number }>("SELECT COUNT(*) n FROM watch_hosts WHERE tenant_id = ?", s.tenantId))!.n;

/** Critical findings first seen in the last 24 h, as one grouped item. Cached per sync version (a scan of the CID's findings); warmed after every sync. */
async function criticalNew(s: Scope) {
  return cached(`critnew|${s.tenantId}`, s.cids, async () => {
    if (!s.cids.length) return null;
    const r = (await get<{ findings: number; devices: number; at: number | null }>(
      `SELECT COUNT(*) AS findings, COUNT(DISTINCT cid || aid) AS devices, MAX(first_seen) AS at FROM findings_t WHERE cid IN ${inList(s.cids)} AND severity = 'CRITICAL' AND first_seen >= ?`, ...s.cids, now() - DAY))!;
    return r.findings ? { findings: r.findings, devices: r.devices, at: r.at } : null;
  });
}
warmers.push(async (cid) => {
  const t = await get<{ tenant_id: string }>("SELECT tenant_id FROM tenant_cids WHERE cid = ?", cid);
  if (!t) return;
  const cids = (await all<{ cid: string }>("SELECT cid FROM tenant_cids WHERE tenant_id = ?", t.tenant_id)).map((x) => x.cid);
  await criticalNew({ tenantId: t.tenant_id, tenantName: "", cids });
});

/** The automatic items: what urgentFor() says (first impact, KEV entered), the grouped new Criticals, and news that hits the organization. */
async function autoItems(s: Scope, soc: boolean) {
  const items: Record<string, unknown>[] = [];
  for (const u of await urgentFor(s.tenantId, s.cids))
    for (const reason of u.reasons) items.push({ type: reason, cve: u.cve, title: u.title, devices: u.devices, severity: u.severity, at: u.at });
  const crit = await criticalNew(s);
  if (crit) items.push({ type: "critical_new", findings: crit.findings, devices: crit.devices, severity: "CRITICAL", at: crit.at });
  const prefs = await get<{ news_possible: boolean }>("SELECT news_possible FROM notify_prefs WHERE tenant_id = ?", s.tenantId);
  const news = await all<any>(
    `SELECT m.cve, m.state, m.devices, m.last_changed AS at, p.title,
            (SELECT CASE MIN(r.rank) WHEN 0 THEN 'CRITICAL' WHEN 1 THEN 'HIGH' WHEN 2 THEN 'MEDIUM' WHEN 3 THEN 'LOW' ELSE 'NONE' END FROM roll_cve r WHERE r.cve_id = m.cve AND r.cid IN ${inList(s.cids)}) AS severity
     FROM news_match m LEFT JOIN cve_public p ON p.id = m.cve WHERE m.tenant_id = ? AND (m.state = 'exact' OR (m.state = 'possible' AND ?::boolean)) AND m.last_changed >= ?
     ORDER BY m.last_changed DESC LIMIT 20`, ...s.cids, s.tenantId, String(soc || !!prefs?.news_possible), now() - 14 * DAY);
  for (const n of news) items.push({ type: "cve_news", cve: n.cve, title: n.title, state: n.state, devices: n.devices, severity: n.severity ?? (n.state === "exact" ? "NONE" : null), at: n.at });
  return items.sort((a, b) => (b.at as number ?? 0) - (a.at as number ?? 0)).slice(0, 50);
}

async function state(s: Scope) {
  if (!s.cids.length) return { state: "no_cids", dataAsOf: null };
  const rows = await all<{ state: string; data_as_of: number | null }>(`SELECT state, data_as_of FROM cid_status WHERE cid IN ${inList(s.cids)}`, ...s.cids);
  if (rows.length < s.cids.length) return { state: "not_synced", dataAsOf: null };
  return { state: rows.some((r) => r.state === "failed") ? "failed" : rows.some((r) => r.state === "partial") ? "partial" : "complete", dataAsOf: rows.every((r) => r.data_as_of) ? Math.min(...rows.map((r) => r.data_as_of!)) : null };
}

route("GET", "/api/exposure/watchlist", async (c) => {
  const s = await tenantScope(c, "watchlist");
  const hosts = await rowsOf(s);
  const suggestions = hosts.length || !s.cids.length ? [] : (await all<any>(
    `SELECT aid, MAX(hostname) AS hostname, SUM(critical) AS critical, SUM(exploited) AS exploited FROM roll_host WHERE cid IN ${inList(s.cids)} GROUP BY aid ORDER BY critical DESC, exploited DESC, hostname, aid LIMIT 3`, ...s.cids))
    .map((r) => ({ aid: r.aid, hostname: r.hostname, p1: null as number | null, critical: r.critical, exploited: r.exploited }));
  return { tenant: { id: s.tenantId, name: s.tenantName }, limit: WATCH_LIMIT, canEdit: true, completeness: await state(s), hosts, suggestions, auto: await autoItems(s, isSoc(c.user!.role)) };
});

const note = (v: unknown) => {
  if (v === undefined || v === null) return "";
  if (typeof v !== "string" || v.length > 200 || /[\u0000-\u0008\u000b-\u001f]/.test(v)) throw new HttpError(400, "note must be text of at most 200 characters", "invalid_note");
  return v.trim();
};
const who = (c: Ctx) => c.user!.name || c.user!.email;

/** undefined = not given (a new host gets High, a known one keeps its level); null or "" = no manual level (Falcon's criticality or the host group decides). */
const crit = (v: unknown): string | null | undefined => {
  if (v === undefined) return undefined;
  if (v === null || v === "") return null;
  if (typeof v !== "string" || !["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(v.toUpperCase())) throw new HttpError(400, "criticality must be CRITICAL, HIGH, MEDIUM, LOW or empty", "invalid_criticality");
  return v.toUpperCase();
};

async function add(c: Ctx, s: Scope, aids: string[], text: string | undefined, level?: string | null) {
  const found = new Map<string, { cid: string; hostname: string | null }>();
  for (const aid of aids) {
    if (!AID.test(aid)) throw new HttpError(400, "Invalid host id", "invalid_aid");
    const h = await ownHost(s, aid);
    if (!h) { await audit({ actor: c.user, tenantId: s.tenantId, action: "watch.add", resource: aid.slice(0, 64), result: "denied", ip: c.ip }); throw new HttpError(404, "Not found"); }
    found.set(aid, h);
  }
  const have = new Set((await all<{ aid: string }>("SELECT aid FROM watch_hosts WHERE tenant_id = ?", s.tenantId)).map((r) => r.aid));
  if (have.size + aids.filter((a) => !have.has(a)).length > WATCH_LIMIT) throw new HttpError(409, `At most ${WATCH_LIMIT} hosts can be watched`, "watch_limit");
  const t = now();
  for (const [aid, h] of found) {
    // a PUT without a note keeps the note that is there
    await run(`INSERT INTO watch_hosts (tenant_id, aid, cid, hostname, note, added_by, added_by_name, added_at, updated_at, criticality) VALUES (?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT (tenant_id, aid) DO UPDATE SET hostname = COALESCE(excluded.hostname, watch_hosts.hostname), note = CASE WHEN ?::boolean THEN excluded.note ELSE watch_hosts.note END, updated_at = excluded.updated_at,
                 criticality = CASE WHEN ?::boolean THEN excluded.criticality ELSE watch_hosts.criticality END`,
      s.tenantId, aid, h.cid, h.hostname, text ?? "", c.user!.id, who(c), t, t, level === undefined ? "HIGH" : level, String(text !== undefined), String(level !== undefined));
    await audit({ actor: c.user, tenantId: s.tenantId, action: have.has(aid) ? "watch.note" : "watch.add", resource: aid, result: "ok", ip: c.ip, detail: h.hostname });
  }
}

route("PUT", "/api/exposure/watchlist/:aid", async (c) => {
  const s = await tenantScope(c, "watchlist");
  await add(c, s, [c.params.aid], c.body.note === undefined ? undefined : note(c.body.note), crit(c.body.criticality));
  return { host: (await rowsOf(s, [c.params.aid]))[0], count: await count(s) };
});
route("PUT", "/api/exposure/watchlist", async (c) => {
  const s = await tenantScope(c, "watchlist");
  const aids = c.body.aids;
  if (!Array.isArray(aids) || !aids.length || aids.length > 50 || !aids.every((a) => typeof a === "string")) throw new HttpError(400, "aids must be a list of 1 to 50 host ids", "invalid_aid");
  const before = await count(s);
  await add(c, s, [...new Set(aids as string[])], c.body.note === undefined ? undefined : note(c.body.note), crit(c.body.criticality));
  return { added: (await count(s)) - before, count: await count(s) };
});
route("DELETE", "/api/exposure/watchlist/:aid", async (c) => {
  const s = await tenantScope(c, "watchlist");
  const gone = await get<{ aid: string }>("DELETE FROM watch_hosts WHERE tenant_id = ? AND aid = ? RETURNING aid", s.tenantId, c.params.aid);
  if (gone) await audit({ actor: c.user, tenantId: s.tenantId, action: "watch.remove", resource: c.params.aid, result: "ok", ip: c.ip });
  return { removed: !!gone, count: await count(s) };
});
