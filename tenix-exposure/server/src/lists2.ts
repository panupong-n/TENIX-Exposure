// API v2, the lists: fixes (+ drawer), hosts (+ drawer), vulnerabilities, and their CSV exports. Contract: scratchpad/api-v2-contract-A.md.
// Endpoint findings only; every route goes through tenantScope(). Lists read the small rollups (roll_fix, roll_host, roll_cve, roll_fix_host, roll_fix_cve) and the host inventory, never millions of findings.
// Names are sorted with nameOrder (Thai dictionary order) in Node: the lists are a few thousand rows (7,790 hosts).
import { all, audit, get, isSoc, nameOrder, now } from "./db.ts";
import { HttpError, route, type Ctx } from "./http.ts";
import { inList, tenantScope, type Scope } from "./scope.ts";
import { cached, warmers } from "./cache.ts";
import { EXPRT, SEV, cacheKey, today, hostsSyncState, scopeOfCid } from "./overview.ts";
import { completeness } from "./exposure.ts";
import { watchedSet } from "./watch.ts";

const DAY = 86_400_000;
const TIER = [null, "P1", "P2", "P3"] as const;
const CVE_ID = /^[A-Z0-9][A-Z0-9._-]{2,63}$/;
const esc = (v: string) => v.replace(/[\\%_]/g, "\\$&");
const like = (v: string) => `%${esc(v)}%`;
type Arg = string | number;

function paging(c: Ctx) {
  const page = Math.max(1, Number(c.query.get("page")) || 1);
  const size = Math.min(100, Math.max(1, Number(c.query.get("pageSize")) || 25));
  return { page, size, offset: (page - 1) * size };
}
const bad = (what: string): never => { throw new HttpError(400, `Invalid ${what}`, "invalid_filter"); };
function tiersOf(q: URLSearchParams): number[] | null {
  const v = q.get("tier");
  if (!v) return null;
  const out = new Set<number>();
  for (const x of v.split(",")) { const m = /^P?([123])$/i.exec(x.trim()); if (!m) bad("tier"); out.add(Number(m![1])); }
  return [...out];
}
const flag = (q: URLSearchParams, k: string) => { const v = q.get(k); if (v === null || v === "" || v === "0") return false; if (v === "1") return true; return bad(k); };
const text = (q: URLSearchParams, k: string, max = 100) => (q.get(k) ?? "").trim().slice(0, max);
const sevRank = (v: string) => { const i = SEV.indexOf(v.toUpperCase() as (typeof SEV)[number]); return i < 0 ? bad("severity") : i; };
const exprtLvl = (v: string) => { const i = EXPRT.indexOf(v.toUpperCase() as any); return i < 1 ? bad("exprt") : i; };
const iso = (ms: number | null) => (ms ? new Date(ms).toISOString() : "");

// ---------- fixes ----------
const fixTitle = (rem: string | null) => (rem ? rem.split("\n")[0].replace(/^-\s*/, "").slice(0, 300) : null);
interface FixAgg { fix_id: number; product: string | null; vendor: string | null; findings: number; p1: number; p2: number; cves: number; p1_cves: number; kev_cves: number; hosts: number; p1_hosts: number; inet_hosts: number; rank: number; lvl: number; first_seen: number | null; remediation: string | null; remediation_json: string | null }
const FIX_AGG = `SELECT f.fix_id, MAX(f.product) product, MAX(f.vendor) vendor, SUM(f.findings)::int findings, SUM(f.p1)::int p1, SUM(f.p2)::int p2, SUM(f.cves)::int cves, SUM(f.p1_cves)::int p1_cves, SUM(f.kev_cves)::int kev_cves,
  SUM(f.hosts)::int hosts, SUM(f.p1_hosts)::int p1_hosts, SUM(f.inet_hosts)::int inet_hosts, MIN(f.rank)::int rank, MAX(f.exprt_lvl)::int lvl, MIN(f.first_seen) first_seen, rs.remediation, rs.remediation_json
  FROM roll_fix f LEFT JOIN rem_sets rs ON rs.id = f.fix_id`;
function fixFilters(c: Ctx, s: Scope) {
  const conds = [`f.cid IN ${inList(s.cids)}`]; const args: Arg[] = [...s.cids];
  const t = tiersOf(c.query);
  if (t) {
    if (t.includes(3)) bad("tier (fixes cover P1 and P2)");
    conds.push(`(${t.map((x) => (x === 1 ? "f.p1 > 0" : "f.p2 > 0")).join(" OR ")})`);
  }
  if (flag(c.query, "kev")) conds.push("f.kev_cves > 0");
  if (flag(c.query, "internet")) conds.push("f.inet_hosts > 0");
  const q = text(c.query, "q");
  if (q) { conds.push("(rs.remediation ILIKE ? ESCAPE '\\' OR f.product ILIKE ? ESCAPE '\\')"); args.push(like(q), like(q)); }
  return { where: conds.join(" AND "), args };
}
function fixRow(r: FixAgg, p1Total: number) {
  const first = r.first_seen;
  return {
    id: String(r.fix_id), title: fixTitle(r.remediation), action: r.remediation ? (r.remediation.split("\n")[1] ?? "").replace(/^-\s*/, "").slice(0, 300) || null : null,
    link: firstLink(r.remediation_json), product: r.product, vendor: r.vendor, noFix: r.fix_id === 0,
    p1: r.p1, p2: r.p2, findings: r.findings, cves: r.cves, p1Cves: r.p1_cves, kevCves: r.kev_cves, hosts: r.hosts, p1Hosts: r.p1_hosts, internetHosts: r.inet_hosts,
    severity: SEV[r.rank], exprt: EXPRT[r.lvl], firstSeen: first, ageDays: first ? Math.floor((now() - first) / DAY) : null, impactShare: p1Total ? r.p1 / p1Total : 0,
  };
}
function parseLinks(json: string | null): { action: string; link: string | null; type: string | null }[] { try { return json ? JSON.parse(json) : []; } catch { return []; } }
const firstLink = (json: string | null) => parseLinks(json).find((x) => x.link)?.link ?? null;

async function fixList(c: Ctx, s: Scope) {
  const { where, args } = fixFilters(c, s);
  const rows = await all<FixAgg>(`${FIX_AGG} WHERE ${where} GROUP BY f.fix_id, rs.remediation, rs.remediation_json`, ...args);
  const p1Total = (await get<{ n: number }>(`SELECT COALESCE(SUM(p1), 0)::int n FROM roll_fix WHERE cid IN ${inList(s.cids)}`, ...s.cids))!.n;
  const title = (r: FixAgg) => fixTitle(r.remediation) ?? r.product ?? "";
  const sorts: Record<string, (a: FixAgg, b: FixAgg) => number> = {
    impact: (a, b) => b.p1 - a.p1 || b.kev_cves - a.kev_cves || b.hosts - a.hosts || b.lvl - a.lvl || (a.first_seen ?? Infinity) - (b.first_seen ?? Infinity),
    hosts: (a, b) => b.hosts - a.hosts || b.p1 - a.p1, cves: (a, b) => b.cves - a.cves || b.p1 - a.p1,
    title: (a, b) => nameOrder.compare(title(a), title(b)), age: (a, b) => (a.first_seen ?? Infinity) - (b.first_seen ?? Infinity),
  };
  const sort = c.query.get("sort") ?? "impact";
  if (!sorts[sort]) bad("sort");
  rows.sort((a, b) => sorts[sort](a, b) || nameOrder.compare(title(a), title(b)) || a.fix_id - b.fix_id);
  return { rows, p1Total, all: (await get<{ n: number }>(`SELECT COUNT(DISTINCT fix_id)::int n FROM roll_fix WHERE cid IN ${inList(s.cids)}`, ...s.cids))!.n };
}

async function buildFixes(c: Ctx, s: Scope, soc: boolean) {
  const { page, size, offset } = paging(c);
  const f = await fixList(c, s);
  return {
    total: f.rows.length, page, pageSize: size, group: "fix", rows: f.rows.slice(offset, offset + size).map((r) => fixRow(r, f.p1Total)),
    totals: { fixes: f.all, p1: f.p1Total, withKev: f.rows.filter((r) => r.kev_cves > 0).length }, completeness: await completeness(s, soc),
  };
}
route("GET", "/api/exposure/v2/fixes", async (c) => {
  const s = await tenantScope(c, "fixes2");
  const soc = isSoc(c.user!.role);
  return cached(cacheKey(c, "fixes", s, soc), s.cids, () => buildFixes(c, s, soc));
});

const fixId = (c: Ctx) => { if (!/^\d{1,16}$/.test(c.params.id)) throw new HttpError(404, "Not found"); return Number(c.params.id); };

route("GET", "/api/exposure/v2/fixes/:id", async (c) => {
  const id = fixId(c);
  const s = await tenantScope(c, `fix:${id}`);
  const soc = isSoc(c.user!.role);
  return cached(cacheKey(c, `fix${id}`, s, soc), s.cids, async () => {
    const r = (await all<FixAgg>(`${FIX_AGG} WHERE f.cid IN ${inList(s.cids)} AND f.fix_id = ? GROUP BY f.fix_id, rs.remediation, rs.remediation_json`, ...s.cids, id))[0];
    if (!r) throw new HttpError(404, "Not found");
    const p1Total = (await get<{ n: number }>(`SELECT COALESCE(SUM(p1), 0)::int n FROM roll_fix WHERE cid IN ${inList(s.cids)}`, ...s.cids))!.n;
    const row = fixRow(r, p1Total);
    const cves = await fixCves(s, id, 25, 0, c.query);
    const hosts = await hostsOfFix(c, s, soc, id, 25, 0);
    return {
      id: row.id, title: row.title, actions: r.remediation ? r.remediation.split("\n").map((x) => x.replace(/^-\s*/, "")).filter(Boolean) : [], links: parseLinks(r.remediation_json), product: row.product, noFix: row.noFix,
      summary: { p1: row.p1, p2: row.p2, p3: Math.max(0, row.findings - row.p1 - row.p2), cves: row.cves, p1Cves: row.p1Cves, kevCves: row.kevCves, hosts: row.hosts, p1Hosts: row.p1Hosts, internetHosts: row.internetHosts, severity: row.severity, exprt: row.exprt, firstSeen: row.firstSeen, ageDays: row.ageDays, impactShare: row.impactShare },
      cves, hosts, completeness: await completeness(s, soc),
    };
  });
});

async function fixCves(s: Scope, id: number, size: number, offset: number, q: URLSearchParams) {
  const conds = [`fc.cid IN ${inList(s.cids)}`, "fc.fix_id = ?"]; const args: Arg[] = [...s.cids, id];
  const t = tiersOf(q);
  if (t) conds.push(`fc.tier IN (${t.join(",")})`);
  const search = text(q, "q");
  if (search) { conds.push("fc.cve_id ILIKE ? ESCAPE '\\'"); args.push(like(search)); }
  const where = conds.join(" AND ");
  const total = (await get<{ n: number }>(`SELECT COUNT(DISTINCT fc.cve_id)::int n FROM roll_fix_cve fc WHERE ${where}`, ...args))!.n;
  const rows = await all<any>(
    `SELECT fc.cve_id, MIN(fc.tier) tier, SUM(fc.hosts)::int hosts, SUM(fc.findings)::int findings, MAX(fc.kev) kev, MIN(c.rank) rank, MAX(c.base_score) base_score, MAX(c.exprt_lvl) lvl, MAX(c.exploit_status) exploit_status, MAX(k.due_date) due
     FROM roll_fix_cve fc LEFT JOIN roll_cve c ON c.cid = fc.cid AND c.src = 'endpoint' AND c.cve_id = fc.cve_id LEFT JOIN kev k ON k.cve_id = fc.cve_id
     WHERE ${where} GROUP BY fc.cve_id ORDER BY MIN(fc.tier), MAX(fc.kev) DESC, SUM(fc.hosts) DESC, fc.cve_id LIMIT ? OFFSET ?`, ...args, size, offset);
  const td = today();
  return { total, rows: rows.map((r) => ({ cveId: r.cve_id, tier: TIER[r.tier], severity: SEV[r.rank ?? 4], baseScore: r.base_score, exprt: EXPRT[r.lvl ?? 0], exploitStatus: r.exploit_status, kev: !!r.kev, kevDueDate: r.due ?? null, overdue: !!r.due && r.due < td, hosts: r.hosts, findings: r.findings })) };
}
route("GET", "/api/exposure/v2/fixes/:id/cves", async (c) => {
  const id = fixId(c);
  const s = await tenantScope(c, `fix-cves:${id}`);
  if (!(await get("SELECT 1 FROM roll_fix WHERE fix_id = ? AND cid IN " + inList(s.cids), id, ...s.cids))) throw new HttpError(404, "Not found");
  const { page, size, offset } = paging(c);
  return cached(cacheKey(c, `fixcves${id}`, s, false), s.cids, async () => ({ ...(await fixCves(s, id, size, offset, c.query)), page, pageSize: size }));
});
route("GET", "/api/exposure/v2/fixes/:id/hosts", async (c) => {
  const id = fixId(c);
  const s = await tenantScope(c, `fix-hosts:${id}`);
  const soc = isSoc(c.user!.role);
  if (!(await get("SELECT 1 FROM roll_fix WHERE fix_id = ? AND cid IN " + inList(s.cids), id, ...s.cids))) throw new HttpError(404, "Not found");
  const { page, size, offset } = paging(c);
  return cached(cacheKey(c, `fixhosts${id}`, s, soc), s.cids, async () => ({ ...(await hostsOfFix(c, s, soc, id, size, offset)), page, pageSize: size }));
});

// ---------- hosts ----------
/** The population of the host list: every host of the inventory, plus hosts that only the findings know (inInventory:false). Two copies of the CID list as parameters. */
const popSql = (cids: string[]) => `(SELECT COALESCE(h.cid, r.cid) AS cid, COALESCE(h.aid, r.aid) AS aid, (h.aid IS NOT NULL) AS in_inv, COALESCE(h.hostname, r.hostname) AS hostname, COALESCE(h.platform, r.platform) AS platform,
    h.os_version, h.os_build, COALESCE(h.local_ip, r.local_ip) AS local_ip, COALESCE(h.external_ip, r.external_ip) AS external_ip, h.mac, h.serial, h.agent_version, h.machine_domain, h.site,
    COALESCE(h.ou, '{}') AS ou, COALESCE(h.tags, '{}') AS tags, COALESCE(h.groups, '{}') AS groups, h.product_type, h.criticality, h.first_seen, h.last_seen, COALESCE(h.rfm, false) AS rfm, COALESCE(h.contained, false) AS contained,
    h.dup_group, h.dup_role, h.dup_reason, h.dup_newer, COALESCE(h.stale_twin, false) AS stale_twin,
    COALESCE(r.p1, 0) AS p1, COALESCE(r.p2, 0) AS p2, COALESCE(r.p3, 0) AS p3, COALESCE(r.findings, 0) AS findings, COALESCE(r.critical, 0) AS critical, COALESCE(r.kev_cves, 0) AS kev_cves, COALESCE(r.exploited, 0) AS exploited,
    COALESCE(r.fixes, 0) AS fixes, r.tier, r.rank, COALESCE(r.inet, false) AS inet
  FROM (SELECT * FROM hosts WHERE cid IN ${inList(cids)}) h FULL JOIN (SELECT * FROM roll_host WHERE src = 'endpoint' AND cid IN ${inList(cids)}) r ON h.cid = r.cid AND h.aid = r.aid) pop`;

function hostFilters(c: Ctx, cveAids: string[] | null) {
  const conds: string[] = []; const args: Arg[] = [];
  const q = c.query;
  const t = tiersOf(q);
  if (t) conds.push(`(${t.map((x) => (x === 1 ? "pop.p1 > 0" : x === 2 ? "pop.p2 > 0" : "pop.p3 > 0")).join(" OR ")})`);
  const hf = q.get("hasFindings"); if (hf !== null && hf !== "") { if (hf !== "0" && hf !== "1") bad("hasFindings"); conds.push(hf === "1" ? "pop.findings > 0" : "pop.findings = 0"); }
  for (const [k, col] of [["platform", "platform"], ["type", "product_type"], ["criticality", "criticality"]] as const) { const v = text(q, k, 60); if (v) { conds.push(`lower(pop.${col}) = lower(?)`); args.push(v); } }
  if (flag(q, "internet")) conds.push("pop.inet");
  const g = text(q, "group", 120); if (g) { conds.push("? = ANY(pop.groups)"); args.push(g); }
  const tag = text(q, "tag", 120); if (tag) { conds.push("? = ANY(pop.tags)"); args.push(tag); }
  const seen = q.get("seen") ?? "all";
  if (seen === "active") { conds.push("(pop.last_seen IS NULL OR pop.last_seen >= ?)"); args.push(now() - 30 * DAY); }
  else if (seen === "stale7") { conds.push("pop.last_seen < ?"); args.push(now() - 7 * DAY); }
  else if (seen === "stale30") { conds.push("pop.last_seen < ?"); args.push(now() - 30 * DAY); }
  else if (seen !== "all") bad("seen");
  if (flag(q, "duplicates")) conds.push("pop.dup_group IS NOT NULL");
  const cve = text(q, "cve", 70).toUpperCase();
  if (cve) { // hosts that have this CVE: the aids come from an index read of the CVE's rows (hostKeys resolves them first), not from a join the planner may turn into a table scan
    if (!CVE_ID.test(cve)) bad("cve");
    conds.push("pop.aid = ANY(?::text[])"); args.push(cveAids ?? ([] as any));
  }
  const s = text(q, "q");
  if (s) { conds.push("(pop.hostname ILIKE ? ESCAPE '\\' OR pop.local_ip ILIKE ? ESCAPE '\\' OR pop.aid ILIKE ? ESCAPE '\\' OR pop.serial ILIKE ? ESCAPE '\\')"); args.push(like(s), like(s), like(s), like(s)); }
  return { conds, args };
}

const HOST_SORTS: Record<string, [(a: any, b: any) => number, "asc" | "desc"]> = {
  p1: [(a, b) => b.p1 - a.p1 || b.critical - a.critical || b.crit - a.crit || Number(b.inet) - Number(a.inet), "desc"],
  hostname: [(a, b) => nameOrder.compare(a.hostname ?? "", b.hostname ?? ""), "asc"],
  lastSeen: [(a, b) => (b.last_seen ?? 0) - (a.last_seen ?? 0), "desc"],
  critical: [(a, b) => b.critical - a.critical || b.kev_cves - a.kev_cves, "desc"],
  findings: [(a, b) => b.findings - a.findings, "desc"],
  os: [(a, b) => nameOrder.compare(a.os_version ?? a.platform ?? "", b.os_version ?? b.platform ?? ""), "asc"],
};

/** Every host that matches, as sort keys only; Node orders them (Thai names) and the caller loads the rows of one page. */
async function hostKeys(c: Ctx, s: Scope, extraJoin = "", extraArgs: Arg[] = []) {
  const cve = text(c.query, "cve", 70).toUpperCase();
  if (cve && !CVE_ID.test(cve)) bad("cve");
  const cveAids = cve ? (await all<{ aid: string }>(`SELECT DISTINCT aid FROM findings_t WHERE cid IN ${inList(s.cids)} AND cve_id = ? AND suppressed = 0 AND (provider IS NULL OR provider NOT ILIKE '%EASM%')`, ...s.cids, cve)).map((r) => r.aid) : null;
  const { conds, args } = hostFilters(c, cveAids);
  const sort = c.query.get("sort") ?? "p1";
  const spec = HOST_SORTS[sort] ?? bad("sort");
  const dir = c.query.get("dir");
  if (dir && dir !== "asc" && dir !== "desc") bad("dir");
  const keys = await all<any>(
    `SELECT pop.cid, pop.aid, pop.hostname, pop.p1, pop.critical, pop.kev_cves, pop.findings, pop.last_seen, pop.os_version, pop.platform, pop.inet, (lower(COALESCE(pop.criticality, '')) = 'critical')::int AS crit
     FROM ${popSql(s.cids)} ${extraJoin} ${conds.length ? `WHERE ${conds.join(" AND ")}` : ""}`, ...s.cids, ...s.cids, ...extraArgs, ...args);
  const flip = dir && dir !== spec[1] ? -1 : 1;
  keys.sort((a, b) => flip * spec[0](a, b) || nameOrder.compare(a.hostname ?? "", b.hostname ?? "") || (a.aid < b.aid ? -1 : 1));
  return keys as { cid: string; aid: string }[];
}

async function hostRows(s: Scope, soc: boolean, keys: { cid: string; aid: string }[], tenantId: string, extra?: (r: any) => object, joinFix?: number) {
  if (!keys.length) return [];
  const rows = await all<any>(
    `SELECT pop.* ${joinFix === undefined ? "" : ", p.findings AS fix_findings, p.p1 AS fix_p1"} FROM ${popSql(s.cids)} ${joinFix === undefined ? "" : "JOIN roll_fix_host p ON p.cid = pop.cid AND p.aid = pop.aid AND p.fix_id = ?"}
     WHERE pop.cid || '/' || pop.aid = ANY(?::text[])`, ...s.cids, ...s.cids, ...(joinFix === undefined ? [] : [joinFix]), keys.map((k) => `${k.cid}/${k.aid}`) as any);
  const by = new Map(rows.map((r) => [`${r.cid}/${r.aid}`, r]));
  let watched: Set<string> | null = null;
  try { watched = await watchedSet(tenantId); } catch { watched = null; } // the watchlist backend may not be there (yet): watched stays null
  return keys.map((k) => by.get(`${k.cid}/${k.aid}`)).filter(Boolean).map((r) => ({ ...hostRow(r, soc, watched), ...(extra ? extra(r) : {}) }));
}

function hostRow(r: any, soc: boolean, watched: Set<string> | null) {
  const t = now();
  const days = r.last_seen ? (t - r.last_seen) / DAY : null;
  return {
    key: soc ? `${r.cid}/${r.aid}` : r.aid, aid: r.aid, ...(soc ? { cid: r.cid } : {}), inInventory: r.in_inv,
    hostname: r.hostname, platform: r.platform, osVersion: r.os_version, osBuild: r.os_build || null, productType: r.product_type, criticality: r.criticality,
    localIp: r.local_ip, externalIp: r.external_ip, mac: r.mac, serial: r.serial, agentVersion: r.agent_version, machineDomain: r.machine_domain, site: r.site, ou: r.ou,
    groups: r.groups.slice(0, 5), groupsMore: Math.max(0, r.groups.length - 5), tags: r.tags, firstSeen: r.first_seen, lastSeen: r.last_seen,
    daysSinceSeen: days === null ? null : Math.round(days * 10) / 10, stale: days === null ? "unknown" : days > 30 ? "stale30" : days > 7 ? "stale7" : "fresh",
    duplicate: r.dup_group ? { role: r.dup_role, staleTwin: r.stale_twin, reason: r.dup_reason, newerAid: r.dup_newer } : null,
    contained: r.contained, reducedFunctionality: r.rfm, internetFacing: r.inet,
    p1: r.p1, p2: r.p2, p3: r.p3, findings: r.findings, critical: r.critical, kevCves: r.kev_cves, exploited: r.exploited, fixes: r.fixes,
    worstSeverity: r.findings > 0 && r.rank !== null ? SEV[r.rank] : null, tier: r.tier ? TIER[r.tier] : null, watched: watched ? watched.has(r.aid) : null,
  };
}

async function hostFacets(s: Scope) {
  return (await get<any>(
    `SELECT COUNT(*)::int AS "all", (COUNT(*) FILTER (WHERE pop.findings > 0))::int AS "withFindings", (COUNT(*) FILTER (WHERE pop.p1 > 0))::int AS "withP1", (COUNT(*) FILTER (WHERE pop.inet))::int AS internet,
            (COUNT(*) FILTER (WHERE pop.last_seen < ?))::int AS stale7, (COUNT(*) FILTER (WHERE pop.last_seen < ?))::int AS stale30, (COUNT(*) FILTER (WHERE pop.dup_group IS NOT NULL))::int AS duplicates,
            (COUNT(*) FILTER (WHERE pop.stale_twin))::int AS "staleTwins", (COUNT(*) FILTER (WHERE pop.findings = 0))::int AS "noFindings" FROM ${popSql(s.cids)}`, now() - 7 * DAY, now() - 30 * DAY, ...s.cids, ...s.cids))!;
}

async function buildHosts(c: Ctx, s: Scope, soc: boolean) {
  const { page, size, offset } = paging(c);
  const keys = await hostKeys(c, s);
  return {
    total: keys.length, page, pageSize: size, facets: await hostFacets(s), rows: await hostRows(s, soc, keys.slice(offset, offset + size), s.tenantId),
    hostsSync: await hostsSyncState(s.cids), completeness: await completeness(s, soc),
  };
}
route("GET", "/api/exposure/v2/hosts", async (c) => {
  const s = await tenantScope(c, "hosts2");
  const soc = isSoc(c.user!.role);
  const key = cacheKey(c, "hosts", s, soc);
  // the star of a watched host is live state of another table: a watched answer is never served from the cache of a different moment
  return cached(key, s.cids, () => buildHosts(c, s, soc));
});

async function hostsOfFix(c: Ctx, s: Scope, soc: boolean, id: number, size: number, offset: number) {
  const keys = await hostKeys(c, s, "JOIN roll_fix_host fx ON fx.cid = pop.cid AND fx.aid = pop.aid AND fx.fix_id = ?", [id]);
  return { total: keys.length, rows: await hostRows(s, soc, keys.slice(offset, offset + size), s.tenantId, (r) => ({ fixFindings: r.fix_findings, fixP1: r.fix_p1 }), id) };
}

// ---------- the device drawer ----------
const exprtOrder = (e: string | null) => (e === "CRITICAL" ? 4 : e === "HIGH" ? 3 : e === "MEDIUM" ? 2 : e === "LOW" ? 1 : 0);
/** The same rule as rollup.ts, for the CVEs of one host. */
export const tierOf = (f: { kev: boolean; exploit_status: number | null; severity: string; exprt: string | null }) =>
  f.kev || (f.exploit_status ?? 0) >= 60 || (f.severity === "CRITICAL" && f.exprt === "CRITICAL") ? 1 : f.severity === "CRITICAL" || f.exprt === "HIGH" || f.exprt === "CRITICAL" || f.exploit_status === 30 ? 2 : 3;

route("GET", "/api/exposure/v2/hosts/:aid", async (c) => {
  const s = await tenantScope(c, "host2");
  const soc = isSoc(c.user!.role);
  const aid = c.params.aid;
  const hit = (await all<any>(`SELECT pop.cid, pop.aid FROM ${popSql(s.cids)} WHERE pop.aid = ? LIMIT 1`, ...s.cids, ...s.cids, aid))[0];
  if (!hit) throw new HttpError(404, "Not found");
  const [host] = await hostRows(s, soc, [hit], s.tenantId);
  const sev = Object.fromEntries(SEV.map((x) => [x, 0])) as Record<string, number>;
  const fs = await all<any>(
    `SELECT f.cve_id, f.severity, f.base_score, f.exprt, f.exploit_status, f.product, f.rem_set, (c.cisa_kev = 1 OR EXISTS (SELECT 1 FROM kev k WHERE k.cve_id = f.cve_id)) AS kev
     FROM findings_t f LEFT JOIN cves c ON c.id = f.cve_id WHERE f.cid = ? AND f.aid = ? AND f.suppressed = 0`, hit.cid, hit.aid);
  const byCve = new Map<string, any>();
  for (const f of fs) {
    sev[f.severity] = (sev[f.severity] ?? 0) + 1;
    const t = tierOf({ kev: !!f.kev, exploit_status: f.exploit_status, severity: f.severity, exprt: f.exprt });
    const prev = byCve.get(f.cve_id);
    if (!prev || t < prev.tier) byCve.set(f.cve_id, { ...f, tier: t });
  }
  const cves = [...byCve.values()].sort((a, b) => a.tier - b.tier || Number(!!b.kev) - Number(!!a.kev) || exprtOrder(b.exprt) - exprtOrder(a.exprt) || (b.exploit_status ?? 0) - (a.exploit_status ?? 0) || (b.base_score ?? 0) - (a.base_score ?? 0) || (a.cve_id < b.cve_id ? -1 : 1));
  const fixes = await all<any>(
    `SELECT p.fix_id, p.p1, p.p2, rs.remediation, (SELECT COUNT(*) FROM roll_fix_cve fc WHERE fc.cid = p.cid AND fc.fix_id = p.fix_id AND EXISTS (SELECT 1 FROM findings_t g WHERE g.cid = p.cid AND g.aid = p.aid AND g.cve_id = fc.cve_id AND g.suppressed = 0))::int AS cves,
            f.kev_cves, f.rank, f.product FROM roll_fix_host p JOIN roll_fix f ON f.cid = p.cid AND f.fix_id = p.fix_id LEFT JOIN rem_sets rs ON rs.id = p.fix_id WHERE p.cid = ? AND p.aid = ? ORDER BY p.p1 DESC, p.p2 DESC, p.fix_id LIMIT 26`, hit.cid, hit.aid);
  const fixOf = new Map<string, number>(); // the first (largest) fix that closes each CVE: for the CVE rows
  for (const f of fs) if (f.rem_set !== null && !fixOf.has(f.cve_id)) fixOf.set(f.cve_id, f.rem_set);
  return {
    aid, ...(soc ? { cid: hit.cid } : {}), inInventory: host.inInventory, host, tiers: { P1: host.p1, P2: host.p2, P3: host.p3 }, severity: sev,
    fixes: fixes.slice(0, 25).map((f) => ({ id: String(f.fix_id), title: fixTitle(f.remediation) ?? f.product, p1: f.p1, p2: f.p2, cves: f.cves, kevCves: f.kev_cves, severity: SEV[f.rank] })), fixesMore: Math.max(0, fixes.length - 25),
    cves: cves.slice(0, 50).map((f) => ({ cveId: f.cve_id, tier: TIER[f.tier], severity: f.severity, baseScore: f.base_score, exprt: f.exprt, exploitStatus: f.exploit_status, kev: !!f.kev, product: f.product, fixId: fixOf.has(f.cve_id) ? String(fixOf.get(f.cve_id)) : null })),
    cvesTotal: cves.length, completeness: await completeness(s, soc),
  };
});

// ---------- vulnerabilities ----------
async function vulnRows(c: Ctx, s: Scope, size: number, offset: number) {
  const conds = [`rc.cid IN ${inList(s.cids)}`, "rc.src = 'endpoint'"]; const args: Arg[] = [...s.cids];
  const t = tiersOf(c.query); if (t) conds.push(`rc.tier IN (${t.join(",")})`);
  const sev = c.query.get("severity"); if (sev) { conds.push("rc.rank = ?"); args.push(sevRank(sev)); }
  const ex = c.query.get("exprt"); if (ex) { conds.push("rc.exprt_lvl = ?"); args.push(exprtLvl(ex)); }
  if (flag(c.query, "kev")) conds.push("rc.kev = 1");
  if (flag(c.query, "exploited")) conds.push("rc.exploit_status >= 60");
  if (flag(c.query, "internet")) conds.push("rc.inet > 0");
  const fix = c.query.get("fix"); if (fix) { if (!/^\d{1,16}$/.test(fix)) bad("fix"); conds.push(`EXISTS (SELECT 1 FROM roll_fix_cve fc WHERE fc.cid = rc.cid AND fc.cve_id = rc.cve_id AND fc.fix_id = ?)`); args.push(Number(fix)); }
  const q = text(c.query, "q"); if (q) { conds.push("(rc.cve_id ILIKE ? ESCAPE '\\' OR rc.products ILIKE ? ESCAPE '\\')"); args.push(like(q), like(q)); }
  const sorts: Record<string, string> = {
    priority: "MIN(rc.tier), MAX(rc.kev) DESC, MAX(rc.exprt_lvl) DESC, MAX(rc.exploit_status) DESC NULLS LAST, (SUM(rc.inet) > 0) DESC, MAX(rc.base_score) DESC NULLS LAST, SUM(rc.hosts) DESC, MIN(rc.first_seen) ASC NULLS LAST, rc.cve_id",
    severity: "MIN(rc.rank), SUM(rc.hosts) DESC, rc.cve_id", cvss: "MAX(rc.base_score) DESC NULLS LAST, MIN(rc.rank), rc.cve_id", hosts: "SUM(rc.hosts) DESC, MIN(rc.rank), rc.cve_id",
    age: "MIN(rc.first_seen) ASC NULLS LAST, rc.cve_id", new: "MIN(rc.first_seen) DESC NULLS LAST, rc.cve_id",
  };
  const order = sorts[c.query.get("sort") ?? "priority"] ?? bad("sort");
  const where = conds.join(" AND ");
  const total = (await get<{ n: number }>(`SELECT COUNT(DISTINCT rc.cve_id)::int n FROM roll_cve rc WHERE ${where}`, ...args))!.n;
  const rows = await all<any>(
    `SELECT rc.cve_id, MIN(rc.tier) tier, MIN(rc.rank) rank, MAX(rc.base_score) base_score, MAX(rc.exprt_lvl) lvl, MAX(rc.exploit_status) exploit_status, MAX(rc.kev) kev, SUM(rc.hosts)::int hosts, SUM(rc.inet)::int inet,
            SUM(rc.findings)::int findings, SUM(rc.p1)::int p1, MAX(rc.kind) kind, MAX(rc.product) product, MIN(rc.first_seen) first_seen
     FROM roll_cve rc WHERE ${where} GROUP BY rc.cve_id ORDER BY ${order} LIMIT ? OFFSET ?`, ...args, size, offset);
  const ids = rows.map((r) => r.cve_id);
  const due = new Map((ids.length ? await all<{ cve_id: string; due_date: string | null }>("SELECT cve_id, due_date FROM kev WHERE cve_id = ANY(?::text[])", ids as any) : []).map((r) => [r.cve_id, r.due_date]));
  const pub = new Map((ids.length ? await all<{ id: string; published_at: string | null }>("SELECT id, published_at FROM cves WHERE id = ANY(?::text[])", ids as any) : []).map((r) => [r.id, r.published_at]));
  const fx = ids.length ? await all<any>(
    `SELECT DISTINCT ON (fc.cve_id) fc.cve_id, fc.fix_id, rs.remediation, (COUNT(*) OVER (PARTITION BY fc.cve_id))::int AS n FROM roll_fix_cve fc LEFT JOIN rem_sets rs ON rs.id = fc.fix_id
     WHERE fc.cid IN ${inList(s.cids)} AND fc.cve_id = ANY(?::text[]) ORDER BY fc.cve_id, fc.hosts DESC, fc.fix_id`, ...s.cids, ids as any) : [];
  const fixBy = new Map(fx.map((r) => [r.cve_id, r]));
  const td = today();
  return {
    total, rows: rows.map((r) => {
      const f = fixBy.get(r.cve_id), d = due.get(r.cve_id) ?? null, why: string[] = [], sevName = SEV[r.rank];
      if (r.tier === 1) { if (r.kev) why.push("kev"); if ((r.exploit_status ?? 0) >= 60) why.push("exploited"); if (sevName === "CRITICAL" && r.lvl === 4) why.push("critical_exprt"); }
      else if (r.tier === 2) { if (sevName === "CRITICAL") why.push("critical"); if (r.lvl >= 3) why.push("exprt_high"); if (r.exploit_status === 30) why.push("exploit_code"); }
      return {
        cveId: r.cve_id, tier: TIER[r.tier], severity: sevName, baseScore: r.base_score, exprt: EXPRT[r.lvl], exploitStatus: r.exploit_status, kev: !!r.kev, kevDueDate: d, overdue: !!d && d < td, whyTier: why,
        hosts: r.hosts, internetHosts: r.inet, findings: r.findings, p1Findings: r.p1, kind: r.kind, product: r.product, firstSeen: r.first_seen, ageDays: r.first_seen ? Math.floor((now() - r.first_seen) / DAY) : null,
        fix: f ? { id: String(f.fix_id), title: fixTitle(f.remediation) ?? r.product, fixes: f.n } : null, published: pub.get(r.cve_id) ?? null,
      };
    }),
  };
}
async function buildVulns(c: Ctx, s: Scope, soc: boolean) {
  if (c.query.get("group") === "fix") return buildFixes(c, s, soc);
  if (c.query.get("group") && c.query.get("group") !== "cve") bad("group");
  const { page, size, offset } = paging(c);
  const facets = (await get<any>(
    `SELECT (COUNT(DISTINCT cve_id) FILTER (WHERE tier = 1))::int AS "P1", (COUNT(DISTINCT cve_id) FILTER (WHERE tier = 2))::int AS "P2", (COUNT(DISTINCT cve_id) FILTER (WHERE tier = 3))::int AS "P3", (COUNT(DISTINCT cve_id) FILTER (WHERE kev = 1))::int AS kev
     FROM roll_cve WHERE cid IN ${inList(s.cids)} AND src = 'endpoint'`, ...s.cids))!;
  return { ...(await vulnRows(c, s, size, offset)), page, pageSize: size, group: "cve", facets, completeness: await completeness(s, soc) };
}
route("GET", "/api/exposure/v2/vulnerabilities", async (c) => {
  const s = await tenantScope(c, "vulnerabilities2");
  const soc = isSoc(c.user!.role);
  return cached(cacheKey(c, "vulns", s, soc), s.cids, () => buildVulns(c, s, soc));
});

// ---------- CSV (scoped, streamed, formula-injection safe) ----------
const ROW_LIMIT = 200_000, CHUNK = 2000;
/** A text cell that starts with = + - @ TAB or CR is prefixed with a quote so a spreadsheet never runs it as a formula; numbers are written as numbers. */
export function csvCell(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (typeof v === "number") return Number.isFinite(v) ? String(v) : "";
  if (typeof v === "boolean") return v ? "true" : "false";
  let t = Array.isArray(v) ? v.join("; ") : String(v);
  if (/^[=+\-@\t\r]/.test(t)) t = `'${t}`;
  return /[",\n\r]/.test(t) ? `"${t.replace(/"/g, '""')}"` : t;
}
const slug = (n: string) => n.normalize("NFKD").replace(/[^\w]+/g, "-").replace(/^-+|-+$/g, "").toLowerCase().slice(0, 40) || "org";

/** `page` returns [cid, columns] rows; super admins get the cid as the first column, customers never do. */
export async function sendCsv(c: Ctx, s: Scope, name: string, header: string[], total: number, page: (offset: number, limit: number) => Promise<[string, unknown[]][]>) {
  const soc = isSoc(c.user!.role);
  if (!soc) await audit({ actor: c.user, tenantId: s.tenantId, action: `export:${name}`, resource: s.tenantId, result: "ok", ip: c.ip, detail: String(total) });
  const rows = Math.min(total, ROW_LIMIT);
  const res = c.res;
  res.writeHead(200, {
    "Content-Type": "text/csv; charset=utf-8", "Cache-Control": "no-store", "Content-Disposition": `attachment; filename="${name}-${slug(s.tenantName)}-${today()}.csv"`,
    "X-Total-Rows": String(total), "X-Row-Limit": String(ROW_LIMIT), ...(total > ROW_LIMIT ? { "X-Truncated": "1" } : {}),
  });
  const w = async (chunk: string) => { if (!res.write(chunk)) await new Promise<void>((ok) => res.once("drain", ok)); };
  await w("\uFEFF" + (soc ? ["cid", ...header] : header).map(csvCell).join(",") + "\r\n");
  for (let off = 0; off < rows; off += CHUNK) {
    const part = await page(off, Math.min(CHUNK, rows - off));
    await w(part.map(([cid, r]) => (soc ? [cid, ...r] : r).map(csvCell).join(",")).join("\r\n") + (part.length ? "\r\n" : ""));
  }
  res.end();
}

route("GET", "/api/exposure/v2/fixes.csv", async (c) => {
  const s = await tenantScope(c, "export:fixes");
  const f = await fixList(c, s);
  return sendCsv(c, s, "fixes", ["fix_id", "fix", "product", "p1", "p2", "cves", "p1_cves", "kev_cves", "hosts", "p1_hosts", "internet_hosts", "max_severity", "max_exprt", "first_seen", "age_days"], f.rows.length,
    async (o, n) => f.rows.slice(o, o + n).map((r): [string, unknown[]] => { const x = fixRow(r, f.p1Total); return ["", [x.id, x.title ?? x.product, x.product, x.p1, x.p2, x.cves, x.p1Cves, x.kevCves, x.hosts, x.p1Hosts, x.internetHosts, x.severity, x.exprt, iso(x.firstSeen), x.ageDays]]; }));
});

route("GET", "/api/exposure/v2/fixes/:id/hosts.csv", async (c) => {
  const id = fixId(c);
  const s = await tenantScope(c, `export:fix-hosts:${id}`);
  const soc = isSoc(c.user!.role);
  const fix = (await all<FixAgg>(`${FIX_AGG} WHERE f.cid IN ${inList(s.cids)} AND f.fix_id = ? GROUP BY f.fix_id, rs.remediation, rs.remediation_json`, ...s.cids, id))[0];
  if (!fix) throw new HttpError(404, "Not found");
  const keys = await hostKeys(c, s, "JOIN roll_fix_host fx ON fx.cid = pop.cid AND fx.aid = pop.aid AND fx.fix_id = ?", [id]);
  const title = fixTitle(fix.remediation) ?? fix.product;
  return sendCsv(c, s, "fix-hosts", ["fix", "hostname", "ip", "os", "type", "criticality", "last_seen", "p1", "p2", "fix_findings", "internet", "groups"], keys.length, async (o, n) =>
    (await hostRows(s, soc, keys.slice(o, o + n), s.tenantId, undefined, id)).map((r: any): [string, unknown[]] => [r.cid ?? "", [title, r.hostname, r.localIp, r.osVersion ?? r.platform, r.productType, r.criticality, iso(r.lastSeen), r.fixP1, r.fixP1 === undefined ? "" : r.fixFindings - r.fixP1, r.fixFindings, r.internetFacing, r.groups]]));
});

route("GET", "/api/exposure/v2/hosts.csv", async (c) => {
  const s = await tenantScope(c, "export:hosts");
  const soc = isSoc(c.user!.role);
  const keys = await hostKeys(c, s);
  return sendCsv(c, s, "hosts", ["hostname", "ip", "external_ip", "os", "os_build", "type", "criticality", "internet", "p1", "p2", "p3", "critical", "kev_cves", "fixes", "last_seen", "first_seen", "stale", "duplicate", "groups", "tags", "site", "agent_version"], keys.length, async (o, n) =>
    (await hostRows(s, soc, keys.slice(o, o + n), s.tenantId)).map((r: any): [string, unknown[]] => [r.cid ?? "", [r.hostname, r.localIp, r.externalIp, r.osVersion ?? r.platform, r.osBuild, r.productType, r.criticality, r.internetFacing, r.p1, r.p2, r.p3, r.critical, r.kevCves, r.fixes,
      iso(r.lastSeen), iso(r.firstSeen), r.stale, r.duplicate ? `${r.duplicate.role}${r.duplicate.staleTwin ? " (stale twin)" : ""} by ${r.duplicate.reason}` : "", r.groups, r.tags, r.site, r.agentVersion]]));
});

route("GET", "/api/exposure/v2/vulnerabilities.csv", async (c) => {
  const s = await tenantScope(c, "export:vulnerabilities");
  if (c.query.get("group") === "fix") throw new HttpError(400, "Use /fixes.csv for the by-fix list", "invalid_filter");
  const first = await vulnRows(c, s, 1, 0);
  return sendCsv(c, s, "vulnerabilities", ["cve", "tier", "severity", "cvss", "exprt", "exploit_status", "kev", "kev_due", "hosts", "internet_hosts", "findings", "product", "fix", "first_seen", "age_days"], first.total, async (o, n) =>
    (await vulnRows(c, s, n, o)).rows.map((r): [string, unknown[]] => ["", [r.cveId, r.tier, r.severity, r.baseScore, r.exprt, r.exploitStatus, r.kev, r.kevDueDate, r.hosts, r.internetHosts, r.findings, r.product, r.fix?.title ?? "", iso(r.firstSeen), r.ageDays]]));
});

// ---------- the v2 CVE drawer ----------
/** One call for the CVE drawer: tier and why, severity and ExPRT, KEV with due date, the fixes that close it, the product versions it sits on, and its first hosts. A CVE this tenant does not have is { found: false }. */
route("GET", "/api/exposure/v2/vulnerabilities/:cve", async (c) => {
  const cve = c.params.cve.toUpperCase();
  if (!CVE_ID.test(cve)) throw new HttpError(400, "Invalid vulnerability id");
  const s = await tenantScope(c, `cve2:${cve}`);
  const soc = isSoc(c.user!.role);
  return cached(cacheKey(c, `cve${cve}`, s, soc), s.cids, async () => {
    const r = (await all<any>(
      `SELECT MIN(rc.tier) tier, MIN(rc.rank) rank, MAX(rc.base_score) base_score, MAX(rc.exprt_lvl) lvl, MAX(rc.exploit_status) exploit_status, MAX(rc.kev) kev, SUM(rc.hosts)::int hosts, SUM(rc.inet)::int inet, SUM(rc.findings)::int findings,
              SUM(rc.p1)::int p1, MAX(rc.kind) kind, MIN(rc.first_seen) first_seen FROM roll_cve rc WHERE rc.cid IN ${inList(s.cids)} AND rc.src = 'endpoint' AND rc.cve_id = ?`, ...s.cids, cve))[0];
    if (!r || !r.hosts) return { found: false, cveId: cve, completeness: await completeness(s, soc) };
    const due = (await get<{ due_date: string | null }>("SELECT due_date FROM kev WHERE cve_id = ?", cve))?.due_date ?? null;
    const sevName = SEV[r.rank], why: string[] = [];
    if (r.tier === 1) { if (r.kev) why.push("kev"); if ((r.exploit_status ?? 0) >= 60) why.push("exploited"); if (sevName === "CRITICAL" && r.lvl === 4) why.push("critical_exprt"); }
    else if (r.tier === 2) { if (sevName === "CRITICAL") why.push("critical"); if (r.lvl >= 3) why.push("exprt_high"); if (r.exploit_status === 30) why.push("exploit_code"); }
    const fixes = await all<any>(
      `SELECT fc.fix_id, SUM(fc.hosts)::int hosts, SUM(fc.findings)::int findings, rs.remediation, rs.remediation_json FROM roll_fix_cve fc LEFT JOIN rem_sets rs ON rs.id = fc.fix_id
       WHERE fc.cid IN ${inList(s.cids)} AND fc.cve_id = ? GROUP BY fc.fix_id, rs.remediation, rs.remediation_json ORDER BY 2 DESC, 1 LIMIT 10`, ...s.cids, cve);
    const versions = await all<any>(
      `SELECT product, MAX(vendor) vendor, COUNT(DISTINCT aid)::int hosts FROM findings_t WHERE cid IN ${inList(s.cids)} AND cve_id = ? AND suppressed = 0 AND (provider IS NULL OR provider NOT ILIKE '%EASM%') GROUP BY product ORDER BY 3 DESC, 1 NULLS LAST LIMIT 20`, ...s.cids, cve);
    const keys = await hostKeys({ query: new URLSearchParams([["cve", cve]]) } as Ctx, s);
    return {
      found: true, cveId: cve, tier: TIER[r.tier], whyTier: why, severity: sevName, baseScore: r.base_score, exprt: EXPRT[r.lvl], exploitStatus: r.exploit_status, kev: !!r.kev, kevDueDate: due, overdue: !!due && due < today(), kind: r.kind,
      hosts: r.hosts, internetHosts: r.inet, findings: r.findings, p1Findings: r.p1, firstSeen: r.first_seen, ageDays: r.first_seen ? Math.floor((now() - r.first_seen) / DAY) : null,
      fixes: fixes.map((f) => ({ id: String(f.fix_id), title: fixTitle(f.remediation), link: firstLink(f.remediation_json), hosts: f.hosts, findings: f.findings })),
      versions: versions.map((v) => ({ product: v.product, vendor: v.vendor, hosts: v.hosts })),
      hostsList: { total: keys.length, rows: await hostRows(s, soc, keys.slice(0, 25), s.tenantId) }, completeness: await completeness(s, soc),
    };
  });
});

/** After a sync: the default fix list and device list of the organization are computed, so the first page view is a cache hit. */
warmers.push(async (cid) => {
  const s = await scopeOfCid(cid);
  if (!s) return;
  const fake = { query: new URLSearchParams() } as Ctx;
  for (const soc of [false, true]) {
    await cached(cacheKey(fake, "fixes", s, soc), s.cids, () => buildFixes(fake, s, soc));
    await cached(cacheKey(fake, "hosts", s, soc), s.cids, () => buildHosts(fake, s, soc));
  }
});
