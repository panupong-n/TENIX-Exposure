// API v2, the Overview: GET /api/exposure/v2/summary (headline, tiers, severity, facts, freshness), /v2/trend (daily history) and the SOC portfolio /api/exposure/portfolio.
// Contract: scratchpad/api-v2-contract-A.md. Everything is endpoint findings only (Falcon EASM findings are not hosts, CVEs, tiers or severities here) and goes through tenantScope().
// The numbers come from the small rollups of rollup.ts, the exact Falcon counts (cid_counts) and the daily history; nothing here scans findings.
import { all, audit, get, isSoc, now } from "./db.ts";
import { HttpError, route, type Ctx } from "./http.ts";
import { inList, tenantScope, type Scope } from "./scope.ts";
import { cached, warmers } from "./cache.ts";
import { completeness } from "./exposure.ts";
import { allMappedCids } from "./falcon.ts";

export const SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"] as const;
export const EXPRT = [null, "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const; // roll_cve.exprt_lvl / roll_fix.exprt_lvl 0..4
const DAY = 86_400_000;
export const today = () => new Date().toISOString().slice(0, 10);

/** The cache key of a v2 answer: who asked (CIDs only for super admins), what, and the normalised query (without the tenant, which is in the key already). */
export function cacheKey(c: Ctx, name: string, s: Scope, soc: boolean): string {
  const q = [...c.query].filter(([k]) => k !== "tenantId").sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([k, v]) => `${k}=${v}`).join("&");
  return `v2:${name}|${s.tenantId}|${soc}|${q}`;
}

// ---------- exact Falcon counts for sensor findings (cid_counts, written by every sync run) ----------
export interface EndpointCounts { get(key: string): number | null; asOf: number | null }
export async function endpointCounts(cids: string[]): Promise<EndpointCounts> {
  const sums = new Map<string, number>(), have = new Map<string, number>();
  let asOf: number | null = null;
  if (cids.length) for (const r of await all<{ key: string; n: number; as_of: number }>(`SELECT key, n, as_of FROM cid_counts WHERE cid IN ${inList(cids)}`, ...cids)) {
    sums.set(r.key, (sums.get(r.key) ?? 0) + r.n); have.set(r.key, (have.get(r.key) ?? 0) + 1);
    if (r.key === "s_total") asOf = asOf === null ? r.as_of : Math.min(asOf, r.as_of);
  }
  return { get: (k) => (have.get(k) === cids.length && cids.length ? sums.get(k)! : null), asOf };
}

/** Falcon's exact tier counts of sensor findings (kx + c - kxc, p12, total): each is null when a count is missing. */
export function falconTiers(e: EndpointCounts) {
  const kx = e.get("s_kx"), c = e.get("s_c"), kxc = e.get("s_kxc"), p12 = e.get("s_p12"), total = e.get("s_total");
  const p1 = kx !== null && c !== null && kxc !== null ? Math.max(0, kx + c - kxc) : null;
  return { p1, p2: p1 !== null && p12 !== null ? Math.max(0, p12 - p1) : null, p3: p12 !== null && total !== null ? Math.max(0, total - p12) : null, total };
}

export async function hostsSyncState(cids: string[]) {
  const none = { state: "not_synced" as const, asOf: null as number | null, lastRunAt: null as number | null, hosts: 0 };
  if (!cids.length) return none;
  const rows = await all<{ state: string; as_of: number | null; last_run_at: number }>(`SELECT state, as_of, last_run_at FROM hosts_sync WHERE cid IN ${inList(cids)}`, ...cids);
  const have = rows.filter((r) => r.as_of);
  if (rows.length < cids.length || have.length < cids.length) return { ...none, lastRunAt: rows.length ? Math.max(...rows.map((r) => r.last_run_at)) : null, ...(have.length ? { asOf: Math.min(...have.map((r) => r.as_of!)) } : {}), state: rows.some((r) => r.state === "failed") && !have.length ? ("failed" as const) : ("not_synced" as const), hosts: (await get<{ n: number }>(`SELECT COUNT(*) n FROM hosts WHERE cid IN ${inList(cids)}`, ...cids))!.n };
  const state = rows.some((r) => r.state === "failed") ? "failed" : rows.some((r) => r.state === "partial") ? "partial" : "complete";
  return { state: state as "complete" | "partial" | "failed", asOf: Math.min(...rows.map((r) => r.as_of!)), lastRunAt: Math.max(...rows.map((r) => r.last_run_at)), hosts: (await get<{ n: number }>(`SELECT COUNT(*) n FROM hosts WHERE cid IN ${inList(cids)}`, ...cids))!.n };
}

/** The level of design-spec 4.2: share of hosts with a P1 (<5% low, 5-19% medium, 20-59% high, >=60% critical), one step up when a KEV with a CISA due date in the past is P1 on an internet-facing host. */
export function levelOf(share: number, escalate: boolean) {
  const order = ["low", "medium", "high", "critical"];
  const base = share >= 0.6 ? 3 : share >= 0.2 ? 2 : share >= 0.05 ? 1 : 0;
  return { key: order[Math.min(3, base + (escalate ? 1 : 0))], base: order[base], escalated: escalate && base < 3, share, reasons: escalate ? ["kev_overdue_internet"] : [] };
}
const needsData = (state: string) => ["not_synced", "no_cids", "no_connection"].includes(state);

async function buildSummary(s: Scope, soc: boolean) {
  const w = `cid IN ${inList(s.cids)}`, we = `${w} AND src = 'endpoint'`;
  const comp = await completeness(s, soc);
  const e = await endpointCounts(s.cids);
  const hs = await hostsSyncState(s.cids);
  const t = today();
  const h = (await get<any>(
    `SELECT COALESCE(SUM(p1), 0) p1, COALESCE(SUM(p2), 0) p2, COALESCE(SUM(p3), 0) p3, COUNT(*) FILTER (WHERE p1 > 0) hp1, COUNT(*) FILTER (WHERE p2 > 0) hp2, COUNT(*) FILTER (WHERE p3 > 0) hp3,
            COUNT(*) FILTER (WHERE inet AND p1 > 0) inet_p1_hosts, COALESCE(SUM(p1) FILTER (WHERE inet), 0) inet_p1, COUNT(*) FILTER (WHERE inet) inet_hosts, COUNT(*) FILTER (WHERE kev_cves > 0) kev_hosts, COUNT(*) FILTER (WHERE findings > 0) with_findings, COUNT(*) n
     FROM roll_host WHERE ${we}`, ...s.cids))!;
  const cv = (await get<any>(
    `SELECT COUNT(DISTINCT cve_id) FILTER (WHERE tier = 1) p1_cves, COUNT(DISTINCT cve_id) FILTER (WHERE kev = 1) kev_cves FROM roll_cve WHERE ${we}`, ...s.cids))!;
  const fx = (await get<{ n: number }>(`SELECT COUNT(DISTINCT fix_id) n FROM roll_fix WHERE ${w} AND p1 > 0`, ...s.cids))!;
  const sevHeld = Object.fromEntries(SEV.map((x) => [x, 0])) as Record<string, number>;
  for (const r of await all<{ severity: string; n: number }>(`SELECT severity, SUM(n) n FROM roll_sev WHERE ${we} GROUP BY severity`, ...s.cids)) sevHeld[r.severity] = r.n;
  const overdue = (await get<any>(
    `SELECT COALESCE(SUM(r.p1) FILTER (WHERE r.p1 > 0), 0) AS p1_findings, COUNT(DISTINCT r.cve_id) FILTER (WHERE r.p1 > 0) AS cves,
            COUNT(DISTINCT r.cve_id) FILTER (WHERE r.p1 > 0 AND r.inet > 0) AS inet_cves
     FROM roll_cve r JOIN kev k ON k.cve_id = r.cve_id WHERE r.${we} AND k.due_date IS NOT NULL AND k.due_date < ?`, ...s.cids, t))!;
  const ext = (await get<any>(`SELECT COALESCE(SUM(n) FILTER (WHERE src = 'external'), 0) findings FROM roll_sev WHERE ${w}`, ...s.cids))!;
  const assets = (await get<{ n: number }>(`SELECT COUNT(*) n FROM external_assets WHERE ${w}`, ...s.cids))!.n;

  // hosts: the inventory is the truth; hosts that only the findings know are added; before the first inventory the findings are all we have
  const inv = (await get<any>(
    `SELECT COUNT(*) total, COUNT(*) FILTER (WHERE last_seen < ?) stale7, COUNT(*) FILTER (WHERE last_seen < ?) stale30, COUNT(*) FILTER (WHERE dup_group IS NOT NULL) dups, COUNT(*) FILTER (WHERE stale_twin) twins,
            COUNT(*) FILTER (WHERE EXISTS (SELECT 1 FROM roll_host r WHERE r.cid = hosts.cid AND r.aid = hosts.aid AND r.src = 'endpoint' AND r.findings > 0)) with_findings
     FROM hosts WHERE ${w}`, now() - 7 * DAY, now() - 30 * DAY, ...s.cids))!;
  const extra = inv.total ? (await get<{ n: number }>(`SELECT COUNT(*) n FROM roll_host r WHERE ${we} AND NOT EXISTS (SELECT 1 FROM hosts x WHERE x.cid = r.cid AND x.aid = r.aid)`, ...s.cids))!.n : 0;
  const fromInventory = inv.total > 0;
  const hostsTotal = fromInventory ? inv.total + extra : h.n;
  const withFindings = fromInventory ? inv.with_findings + extra : h.with_findings;

  const share = hostsTotal ? h.hp1 / hostsTotal : 0;
  const level = needsData(comp.state) || !hostsTotal ? null : levelOf(share, overdue.inet_cves > 0);
  const falcon = falconTiers(e);
  const exactSev = ["critical", "high", "medium", "low", "total"].every((k) => e.get(`s_${k}`) !== null);
  const fc = comp.falconCounts as null | { total: number; critical: number; high: number; medium: number; low: number; kev: number; exprtCritical: number; exploited: number };
  const severity = exactSev
    ? { CRITICAL: e.get("s_critical")!, HIGH: e.get("s_high")!, MEDIUM: e.get("s_medium")!, LOW: e.get("s_low")!, NONE: Math.max(0, e.get("s_total")! - e.get("s_critical")! - e.get("s_high")! - e.get("s_medium")! - e.get("s_low")!), total: e.get("s_total")!, source: "falcon" as const, endpointOnly: true }
    : fc ? { CRITICAL: fc.critical, HIGH: fc.high, MEDIUM: fc.medium, LOW: fc.low, NONE: Math.max(0, fc.total - fc.critical - fc.high - fc.medium - fc.low), total: fc.total, source: "falcon" as const, endpointOnly: false }
      : { ...sevHeld, total: Object.values(sevHeld).reduce((a, b) => a + b, 0), source: "held" as const, endpointOnly: true };
  const tier = (key: "p1" | "p2" | "p3", held: number, hosts: number) => {
    const f = falcon[key];
    return { held, total: f ?? held, exact: f !== null || (key === "p1" && !!comp.coverage?.priorityPass), source: f !== null ? ("falcon" as const) : ("held" as const), hosts };
  };
  const P1 = tier("p1", h.p1, h.hp1), P2 = tier("p2", h.p2, h.hp2), P3 = tier("p3", h.p3, h.hp3);
  const hist = await history(s.cids, 8);
  const latest = hist[hist.length - 1];
  const base = latest ? [...hist].reverse().find((x) => x.day <= new Date(Date.parse(latest.day) - 7 * DAY).toISOString().slice(0, 10)) ?? (hist.length > 1 ? hist[0] : null) : null;
  const rollupAt = (await get<{ n: number | null }>(`SELECT MIN(n) n FROM cid_counts WHERE ${w} AND key = 'rollupAt'`, ...s.cids))?.n ?? null;
  return {
    tenant: { id: s.tenantId, name: s.tenantName }, completeness: comp, hostsSync: hs,
    headline: {
      p1: h.p1, p1Source: "held" as const, p1Exact: !!comp.coverage?.priorityPass, hostsWithP1: h.hp1, hostsTotal, hostShare: share, p1Cves: cv.p1_cves, p1Fixes: fx.n, internetP1Hosts: h.inet_p1_hosts, level,
      delta7: base && latest && base.day !== latest.day ? { p1: latest.p1 - base.p1, pct: base.p1 ? (latest.p1 - base.p1) / base.p1 : null, from: base.day, partial: Date.parse(latest.day) - Date.parse(base.day) < 7 * DAY } : null,
    },
    hosts: { total: hostsTotal, source: fromInventory ? "inventory" : "findings", withFindings, withoutFindings: Math.max(0, hostsTotal - withFindings), withP1: h.hp1, stale7: inv.stale7, stale30: inv.stale30, duplicates: inv.dups, staleTwins: inv.twins, internetFacing: h.inet_hosts },
    tiers: { P1, P2, P3, suppressedIncluded: e.get("s_suppressed") ?? 0, heldTotal: P1.held + P2.held + P3.held, falconTotal: falcon.total, atLeast: ![P1, P2, P3].every((x) => x.exact) },
    severity: { ...severity, held: sevHeld },
    facts: { kev: e.get("s_kev") ?? fc?.kev ?? null, exploited: e.get("s_exploited") ?? fc?.exploited ?? null, exprtCritical: e.get("s_exprtCritical") ?? fc?.exprtCritical ?? null, kevCves: cv.kev_cves, kevHosts: h.kev_hosts,
      internetP1: h.inet_p1, kevOverdue: overdue.cves, source: e.get("s_kev") !== null ? "falcon" : fc ? "falcon" : "held" },
    external: { findings: ext.findings, assets, note: "EASM findings are not part of any number above" },
    freshness: { findings: { state: comp.state, asOf: comp.dataAsOf }, hosts: { state: hs.state, asOf: hs.asOf }, rollupAt, falconCountsAsOf: e.asOf },
  };
}

/** One point per UTC day, summed over the CIDs of an organization (a CID missing a day simply adds nothing that day). */
async function history(cids: string[], days: number) {
  if (!cids.length) return [];
  const since = new Date(Date.now() - days * DAY).toISOString().slice(0, 10);
  return await all<{ day: string; p1: number; p2: number; p3: number; hosts_p1: number; hosts_total: number; critical: number | null; high: number | null; medium: number | null; low: number | null; none: number | null; held: number; kev: number | null; exploited: number | null }>(
    `SELECT day, SUM(p1)::bigint p1, SUM(p2)::bigint p2, SUM(p3)::bigint p3, SUM(hosts_p1)::bigint hosts_p1, SUM(hosts_total)::bigint hosts_total, SUM(critical)::bigint critical, SUM(high)::bigint high, SUM(medium)::bigint medium,
            SUM(low)::bigint low, SUM("none")::bigint "none", SUM(held)::bigint held, SUM(kev)::bigint kev, SUM(exploited)::bigint exploited FROM hist_day WHERE cid IN ${inList(cids)} AND day >= ? GROUP BY day ORDER BY day`, ...cids, since);
}

route("GET", "/api/exposure/v2/summary", async (c) => {
  const s = await tenantScope(c, "summary2");
  const soc = isSoc(c.user!.role);
  return cached(cacheKey(c, "summary", s, soc), s.cids, () => buildSummary(s, soc));
});

route("GET", "/api/exposure/v2/trend", async (c) => {
  const s = await tenantScope(c, "trend2");
  const days = [7, 30, 90].includes(Number(c.query.get("days"))) ? Number(c.query.get("days")) : 30;
  return cached(cacheKey(c, "trend", s, false), s.cids, async () => {
    const pts = await history(s.cids, days);
    const first = s.cids.length ? (await get<{ day: string | null }>(`SELECT MIN(day) AS day FROM hist_day WHERE cid IN ${inList(s.cids)}`, ...s.cids))!.day : null;
    const closed = s.cids.length ? (await get<{ n: number }>(`SELECT COUNT(*) n FROM finding_closed WHERE cid IN ${inList(s.cids)} AND closed_at >= ? AND (provider IS NULL OR provider NOT ILIKE '%EASM%')`, ...s.cids, now() - 7 * DAY))!.n : 0;
    const last = pts[pts.length - 1];
    const wk = last ? [...pts].reverse().find((x) => x.day <= new Date(Date.parse(last.day) - 7 * DAY).toISOString().slice(0, 10)) : null;
    return {
      days, since: new Date(Date.now() - days * DAY).toISOString().slice(0, 10), startedAt: first,
      points: pts.map((x) => ({ day: x.day, p1: x.p1, p2: x.p2, p3: x.p3, hostsP1: x.hosts_p1, hostsTotal: x.hosts_total, critical: x.critical, high: x.high, medium: x.medium, low: x.low, none: x.none, held: x.held, kev: x.kev, exploited: x.exploited })),
      week: { closed, net: last && wk ? last.p1 - wk.p1 : null },
    };
  });
});

// ---------- the SOC portfolio ----------
route("GET", "/api/exposure/portfolio", { roles: ["super_admin"] }, async (c) => {
  await audit({ actor: c.user, action: "read:portfolio", result: "allowed", ip: c.ip });
  const cids = await allMappedCids();
  return cached("v2:portfolio", cids, () => buildPortfolio());
});

async function buildPortfolio() {
  const t = now(), td = today();
  const tenants = await all<{ id: string; name: string }>("SELECT id, name FROM tenants");
  const cidsOf = new Map<string, string[]>();
  for (const r of await all<{ cid: string; tenant_id: string }>("SELECT cid, tenant_id FROM tenant_cids ORDER BY cid")) (cidsOf.get(r.tenant_id) ?? cidsOf.set(r.tenant_id, []).get(r.tenant_id)!).push(r.cid);
  const by = <T extends { tenant_id: string }>(rows: T[]) => new Map(rows.map((r) => [r.tenant_id, r]));
  const rh = by(await all<any>(`SELECT x.tenant_id, COALESCE(SUM(h.p1), 0) p1, COUNT(*) FILTER (WHERE h.p1 > 0) hp1, COUNT(*) n, COALESCE(SUM(h.critical), 0) crit FROM roll_host h JOIN tenant_cids x ON x.cid = h.cid WHERE h.src = 'endpoint' GROUP BY 1`));
  const inv = by(await all<any>(`SELECT x.tenant_id, COUNT(*) n FROM hosts h JOIN tenant_cids x ON x.cid = h.cid GROUP BY 1`));
  const crit = by(await all<any>(`SELECT x.tenant_id, COALESCE(SUM(n), 0) n FROM roll_sev r JOIN tenant_cids x ON x.cid = r.cid WHERE r.src = 'endpoint' AND r.severity = 'CRITICAL' GROUP BY 1`));
  const kevNew = by(await all<any>(`SELECT tenant_id, COUNT(*) n FROM alerts WHERE reason = 'kev_added' AND created_at >= ? GROUP BY 1`, t - 7 * DAY));
  const over = by(await all<any>(`SELECT x.tenant_id, COALESCE(SUM(r.p1), 0) n FROM roll_cve r JOIN tenant_cids x ON x.cid = r.cid JOIN kev k ON k.cve_id = r.cve_id WHERE r.src = 'endpoint' AND k.due_date IS NOT NULL AND k.due_date < ? GROUP BY 1`, td));
  const overInet = by(await all<any>(`SELECT x.tenant_id, COUNT(*) n FROM roll_cve r JOIN tenant_cids x ON x.cid = r.cid JOIN kev k ON k.cve_id = r.cve_id WHERE r.src = 'endpoint' AND r.p1 > 0 AND r.inet > 0 AND k.due_date IS NOT NULL AND k.due_date < ? GROUP BY 1`, td));
  const pending = by(await all<any>(`SELECT x.tenant_id, COUNT(*) n FROM external_assets e JOIN tenant_cids x ON x.cid = e.cid WHERE COALESCE(e.review, '') <> 'reviewed' GROUP BY 1`));
  const hist = await all<{ tenant_id: string; day: string; p1: number }>(`SELECT x.tenant_id, h.day, SUM(h.p1)::bigint p1 FROM hist_day h JOIN tenant_cids x ON x.cid = h.cid WHERE h.day >= ? GROUP BY 1, 2 ORDER BY 2`, new Date(t - 14 * DAY).toISOString().slice(0, 10));
  const runs = await all<{ tenant_id: string; ts: number; state: string; ms: number }>(`SELECT x.tenant_id, r.started_at ts, r.state, (r.finished_at - r.started_at) ms FROM sync_runs r JOIN tenant_cids x ON x.cid = r.cid WHERE r.started_at >= ? ORDER BY r.started_at`, t - DAY);

  const out: any[] = [];
  for (const tn of tenants) {
    const cids = cidsOf.get(tn.id) ?? [];
    const comp = await completeness({ tenantId: tn.id, tenantName: tn.name, cids }, true);
    const r = rh.get(tn.id), hostsTotal = (inv.get(tn.id)?.n || r?.n || 0) as number;
    const broken = ["failed", "no_connection"].includes(comp.state);
    const ageH = comp.dataAsOf ? (t - comp.dataAsOf) / 3_600_000 : null;
    const stale = broken || (comp.dataAsOf !== null && t - comp.dataAsOf > DAY) || (comp.dataAsOf === null && !["no_cids"].includes(comp.state));
    const series = hist.filter((x) => x.tenant_id === tn.id).map((x) => x.p1);
    const share = hostsTotal && r ? r.hp1 / hostsTotal : 0;
    const days = hist.filter((x) => x.tenant_id === tn.id);
    const lastP = days[days.length - 1], baseP = lastP ? [...days].reverse().find((x) => x.day <= new Date(Date.parse(lastP.day) - 7 * DAY).toISOString().slice(0, 10)) ?? (days.length > 1 ? days[0] : null) : null;
    const attention: string[] = [];
    if (broken) attention.push("broken_connection");
    if ((kevNew.get(tn.id)?.n ?? 0) > 0) attention.push("kev_new");
    if ((over.get(tn.id)?.n ?? 0) > 0) attention.push("p1_overdue");
    if (comp.state === "partial") attention.push("partial");
    if (stale && !broken) attention.push("stale");
    const cov = comp.coverage;
    out.push({
      id: tn.id, name: tn.name, state: comp.state, reason: comp.reason, asOf: comp.dataAsOf, lastRunAt: comp.lastRunAt, ageHours: ageH, stale,
      p1: r?.p1 ?? 0, p1Delta7: broken || !baseP || !lastP || baseP.day === lastP.day ? null : lastP.p1 - baseP.p1, p1Spark: broken ? null : series,
      hostsWithP1: r?.hp1 ?? 0, hosts: hostsTotal, hostShare: share, level: needsData(comp.state) || !hostsTotal ? null : levelOf(share, (overInet.get(tn.id)?.n ?? 0) > 0).key,
      critical: crit.get(tn.id)?.n ?? 0, kevNew7d: kevNew.get(tn.id)?.n ?? 0, p1Overdue: over.get(tn.id)?.n ?? 0, easmPendingReview: pending.get(tn.id)?.n ?? 0,
      mode: cov && cov.scope !== "all" ? "scoped" : cov && cov.falconTotal && cov.held < cov.falconTotal ? "priority" : "full", heldShare: cov?.falconTotal ? Math.min(1, cov.held / cov.falconTotal) : null,
      sync24h: runs.filter((x) => x.tenant_id === tn.id).map((x) => ({ at: x.ts, state: x.state, ms: x.ms })), attention,
    });
  }
  const ORDER = ["broken_connection", "kev_new", "p1_overdue", "partial", "stale"];
  const perHost = (x: (typeof out)[number]) => (x.hosts ? x.p1 / x.hosts : 0);
  const score = (x: (typeof out)[number]) => [x.attention.includes("broken_connection") || x.attention.includes("stale") ? 1 : 0, x.kevNew7d, x.p1Overdue, perHost(x)];
  const cmp = (a: (typeof out)[number], b: (typeof out)[number]) => { const x = score(a), y = score(b); for (let i = 0; i < 4; i++) if (x[i] !== y[i]) return y[i] - x[i]; return a.name < b.name ? -1 : 1; };
  const sorted = [...out].sort(cmp);
  const attention = sorted.filter((x) => x.attention.length).map((x) => ({ tenantId: x.id, name: x.name, reasons: [...x.attention].sort((a, b) => ORDER.indexOf(a) - ORDER.indexOf(b)), detail: { kevNew7d: x.kevNew7d, p1Overdue: x.p1Overdue, ageHours: x.ageHours } }))
    .sort((a, b) => ORDER.indexOf(a.reasons[0]) - ORDER.indexOf(b.reasons[0]));
  const states = ["complete", "partial", "failed", "not_synced", "no_connection", "no_cids"];
  const shared = (await all<any>(
    `SELECT r.cve_id, MAX(r.kev) kev, COUNT(DISTINCT x.tenant_id)::int tenants, SUM(r.hosts)::int hosts, MIN(r.rank) rank, MAX(r.exprt_lvl) lvl
     FROM roll_cve r JOIN tenant_cids x ON x.cid = r.cid WHERE r.src = 'endpoint' AND r.tier = 1 GROUP BY r.cve_id HAVING COUNT(DISTINCT x.tenant_id) >= 2 ORDER BY 3 DESC, 4 DESC, 1 LIMIT 10`));
  return {
    generatedAt: t,
    summary: { tenants: out.length, byState: Object.fromEntries(states.map((k) => [k, out.filter((x) => x.state === k).length])), kevNew7d: out.reduce((a, x) => a + x.kevNew7d, 0), p1Overdue: out.filter((x) => x.p1Overdue > 0).length, stale: out.filter((x) => x.stale).length },
    tenants: sorted, attention, sharedCves: shared.map((r) => ({ cveId: r.cve_id, kev: !!r.kev, tenants: r.tenants, hosts: r.hosts, severity: SEV[r.rank], exprt: EXPRT[r.lvl] })),
  };
}

export { HttpError };

/** The tenant (and its CIDs) that owns a CID, for the warm-up after a sync. */
export async function scopeOfCid(cid: string): Promise<Scope | null> {
  const t = await get<{ id: string; name: string }>("SELECT t.id, t.name FROM tenant_cids x JOIN tenants t ON t.id = x.tenant_id WHERE x.cid = ?", cid);
  if (!t) return null;
  return { tenantId: t.id, tenantName: t.name, cids: (await all<{ cid: string }>("SELECT cid FROM tenant_cids WHERE tenant_id = ? ORDER BY cid", t.id)).map((r) => r.cid) };
}
/** After a sync the Overview's first read is a cache hit. */
warmers.push(async (cid) => {
  const s = await scopeOfCid(cid);
  if (!s) return;
  const fake = { query: new URLSearchParams() } as Ctx;
  for (const soc of [false, true]) await cached(cacheKey(fake, "summary", s, soc), s.cids, () => buildSummary(s, soc));
});
