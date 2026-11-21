import { all, get, isSoc, now } from "./db.ts";
import { HttpError, route, type Ctx } from "./http.ts";
import { loadCoverage, lookupSoftware, type SoftwareFact } from "./falcon.ts";
import { ensurePublic, impactOf, publicInfo, urgentFor } from "./feeds.ts";
import { inList, tenantScope, type Scope } from "./scope.ts";
import { cached, warmers } from "./cache.ts";

const RANK = "CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END";
const SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"] as const;
// CVE ids, and CrowdStrike's own ids (CS-C24-...) for findings that have no CVE, such as misconfigurations on external assets
const CVE = /^[A-Z0-9][A-Z0-9._-]{2,63}$/;
const TREND_DAYS = [7, 14, 30, 90, 180, 365];
/** "endpoint" = devices with the Falcon sensor, "external" = internet-facing assets found by Falcon EASM. Fixed SQL, never user text. */
function sourceSql(q: URLSearchParams): string {
  const v = q.get("source") ?? "";
  if (v === "external") return " AND provider ILIKE '%EASM%'";
  if (v === "endpoint") return " AND (provider IS NULL OR provider NOT ILIKE '%EASM%')";
  if (v) throw new HttpError(400, "Invalid source");
  return "";
}
/** The same choice for the rollup tables (roll_cve, roll_host, roll_sev, roll_age), where the source is a column. */
function srcSql(q: URLSearchParams): string {
  const v = q.get("source") ?? "";
  if (v === "external" || v === "endpoint") return ` AND src = '${v}'`;
  if (v) throw new HttpError(400, "Invalid source");
  return "";
}
const like = (q: string) => `%${q.replace(/[\\%_]/g, "\\$&")}%`;

function page(c: Ctx) {
  const pageNo = Math.max(1, Number(c.query.get("page")) || 1);
  const size = Math.min(100, Math.max(1, Number(c.query.get("pageSize")) || 25));
  return { pageNo, size, offset: (pageNo - 1) * size };
}

/** How trustworthy the numbers are. "complete" is the only state that supports "nothing found".
 *  coverage: what is stored versus what Falcon counts (a big organization stores only the fix-first slice, so rows are not the whole picture); falconCounts: Falcon's exact totals. */
export async function completeness(s: Scope, soc: boolean) {
  const empty = { reason: null, coverage: null, falconCounts: null };
  if (!s.cids.length) return { state: "no_cids" as const, dataAsOf: null, lastRunAt: null, ...empty, cids: [] };
  // CIDs but no login for any of them: nothing is read, whatever old data there is
  if (!(await get("SELECT 1 FROM falcon_connections WHERE cid IN " + inList(s.cids), ...s.cids))) return { state: "no_connection" as const, dataAsOf: null, lastRunAt: null, ...empty, cids: [] };
  const rows = await all<{ cid: string; state: string; data_as_of: number | null; last_run_at: number; detail_json: string; reason: string | null }>(
    `SELECT cid, state, data_as_of, last_run_at, detail_json, reason FROM cid_status WHERE cid IN ${inList(s.cids)}`, ...s.cids);
  const detail = (r: (typeof rows)[number]) => ({ cid: r.cid, state: r.state, reason: r.reason, detail: JSON.parse(r.detail_json) });
  if (rows.length < s.cids.length) {
    return { state: "not_synced" as const, dataAsOf: null, lastRunAt: null, ...empty, cids: soc ? rows.map(detail) : [] };
  }
  const worst = rows.some((r) => r.state === "failed") ? "failed" : rows.some((r) => r.state === "partial") ? "partial" : "complete";
  const asOf = rows.every((r) => r.data_as_of) ? Math.min(...rows.map((r) => r.data_as_of!)) : null;
  return {
    state: worst as "complete" | "partial" | "failed", dataAsOf: asOf, lastRunAt: Math.max(...rows.map((r) => r.last_run_at)),
    reason: rows.find((r) => r.state === worst && r.reason)?.reason ?? null, ...(await loadCoverage(s.cids)),
    // CIDs and error details are for SOC staff only
    cids: soc ? rows.map(detail) : [],
  };
}

route("GET", "/api/exposure/summary", async (c) => {
  const s = await tenantScope(c, "summary");
  const soc = isSoc(c.user!.role);
  return cached(`summary|${s.tenantId}|${soc}|${c.query.get("source") ?? ""}|${c.query.get("days") ?? ""}`, s.cids, () => buildSummary(s, soc, c.query));
});
async function buildSummary(s: Scope, soc: boolean, query: URLSearchParams) {
  const w = `cid IN ${inList(s.cids)}${srcSql(query)}`; // on the rollups of rollup.ts: the same numbers as grouping the findings, without reading millions of rows
  const sev = Object.fromEntries(SEV.map((x) => [x, 0])) as Record<string, number>;
  for (const r of await all<{ severity: string; n: number }>(`SELECT severity, SUM(n) n FROM roll_sev WHERE ${w} GROUP BY severity`, ...s.cids)) sev[r.severity] = r.n;
  const totals = {
    findings: (await get<{ n: number }>(`SELECT COALESCE(SUM(n), 0) n FROM roll_sev WHERE ${w}`, ...s.cids))!.n,
    hosts: (await get<{ n: number }>(`SELECT COUNT(DISTINCT cid || aid) n FROM roll_host WHERE ${w}`, ...s.cids))!.n,
    ...(await get<{ cves: number; exploited: number }>(`SELECT COUNT(DISTINCT cve_id) cves, COUNT(DISTINCT CASE WHEN exploit_status >= 60 THEN cve_id END) exploited FROM roll_cve WHERE ${w}`, ...s.cids))!,
  };
  const topCves = (await all(
    `SELECT cve_id AS "cveId", MIN(rank) AS rank, MAX(base_score) AS "baseScore", MAX(exploit_status) AS "exploitStatus", SUM(hosts) AS hosts
     FROM roll_cve WHERE ${w} GROUP BY cve_id ORDER BY rank, hosts DESC, cve_id LIMIT 10`, ...s.cids))
    .map((r: any) => ({ ...r, severity: SEV[r.rank], rank: undefined }));
  const topHosts = (await all(
    `SELECT cid, aid, MAX(hostname) AS hostname, MAX(platform) AS platform, SUM(cves) AS cves, SUM(critical) AS critical, SUM(high) AS high, SUM(medium) AS medium
     FROM roll_host WHERE ${w} GROUP BY cid, aid ORDER BY critical DESC, cves DESC, hostname, aid LIMIT 10`, ...s.cids))
    .map((r: any) => (soc ? r : { ...r, cid: undefined }));
  const days = TREND_DAYS.includes(Number(query.get("days"))) ? Number(query.get("days")) : 30;
  const since = now() - days * 86400_000;
  // the last snapshot of each day per CID, then summed across the tenant's CIDs
  const trend = await all(
    `SELECT day, SUM(critical) critical, SUM(high) high, SUM(medium) medium, SUM(low) low FROM (
       SELECT DISTINCT ON (cid, day) cid, to_char(to_timestamp(ts / 1000.0) AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS day, critical, high, medium, low
       FROM snapshots WHERE cid IN ${inList(s.cids)} AND ts >= ? ORDER BY cid, day, ts DESC
     ) x GROUP BY day ORDER BY day`, ...s.cids, since);
  // what was closed: findings that were open in the previous complete read and are gone from a later complete one
  const closed = (await get<{ d7: number; d30: number }>(
    `SELECT COUNT(*) FILTER (WHERE closed_at >= ?) AS d7, COUNT(*) AS d30 FROM finding_closed WHERE cid IN ${inList(s.cids)} AND closed_at >= ?${sourceSql(query)}`,
    now() - 7 * 86400_000, ...s.cids, now() - 30 * 86400_000))!;
  return { tenant: { id: s.tenantId, name: s.tenantName }, completeness: await completeness(s, soc), severity: sev, totals, topCves, topHosts, trend, days, closed: { last7: closed.d7, last30: closed.d30 } };
}

// The management part of the Overview ("internet-facing" = found by Falcon EASM, or a sensor device Falcon marks as internet exposed).
// The Source filter applies to the totals, KEV and ages. The source split and the external list are about the source itself, so they ignore it.
route("GET", "/api/exposure/executive", async (c) => {
  const s = await tenantScope(c, "executive");
  const soc = isSoc(c.user!.role);
  return cached(`executive|${s.tenantId}|${soc}|${c.query.get("source") ?? ""}`, s.cids, () => buildExecutive(s, soc, c.query));
});
async function buildExecutive(s: Scope, soc: boolean, query: URLSearchParams) {
  const all_ = `cid IN ${inList(s.cids)}`;
  const w = `${all_}${sourceSql(query)}`; // on findings (small slices: KEV, external assets)
  const r = `${all_}${srcSql(query)}`; // on the rollups
  const t = now();
  const DAY = 86400_000;
  const head = {
    ...(await get<{ internetCriticalHigh: number; critical: number; high: number }>(
      `SELECT COALESCE(SUM(n) FILTER (WHERE inet AND severity IN ('CRITICAL','HIGH')), 0) AS "internetCriticalHigh", COALESCE(SUM(n) FILTER (WHERE severity = 'CRITICAL'), 0) AS critical,
              COALESCE(SUM(n) FILTER (WHERE severity = 'HIGH'), 0) AS high FROM roll_sev WHERE ${r}`, ...s.cids))!,
    ...(await get<{ internetDevices: number; devices: number }>(
      `SELECT COUNT(DISTINCT CASE WHEN inet THEN cid || aid END) AS "internetDevices", COUNT(DISTINCT cid || aid) AS devices FROM roll_host WHERE ${r}`, ...s.cids))!,
  };
  const kevIds = "f.cve_id IN (SELECT id FROM cves WHERE cisa_kev = 1)";
  const kev = (await get<{ cves: number; devices: number }>(
    `SELECT COUNT(DISTINCT f.cve_id) AS cves, COUNT(DISTINCT f.cid || f.aid) AS devices FROM findings f WHERE ${kevIds} AND f.${w}`, ...s.cids))!;
  const bySource = { endpoint: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0 }, external: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0 } } as Record<string, Record<string, number>>;
  for (const x of await all<{ src: string; severity: string; n: number }>(`SELECT src, severity, SUM(n) AS n FROM roll_sev WHERE ${all_} GROUP BY 1, 2`, ...s.cids)) bySource[x.src][x.severity] = x.n;
  // age of Critical and High findings, from Falcon's own first-seen time
  const aging = { d30: 0, d90: 0, d180: 0, older: 0, unknown: 0 } as Record<string, number>;
  for (const x of await all<{ b: string; n: number }>(`SELECT bucket AS b, SUM(n) AS n FROM roll_age WHERE ${r} GROUP BY 1`, ...s.cids)) aging[x.b] = x.n; // the age buckets are as of the last refresh
  const topKev = (await all(
    `SELECT x.cve_id AS "cveId", MIN(x.rank) AS rank, MAX(x.base_score) AS "baseScore", SUM(x.hosts) AS hosts
     FROM roll_cve x JOIN cves k ON k.id = x.cve_id WHERE k.cisa_kev = 1 AND x.${r}
     GROUP BY x.cve_id ORDER BY rank, hosts DESC, x.cve_id LIMIT 5`, ...s.cids))
    .map((r: any) => ({ ...r, severity: SEV[r.rank], rank: undefined }));
  const external = {
    assets: (await get<{ n: number }>(`SELECT COUNT(DISTINCT cid || aid) AS n FROM findings WHERE ${all_} AND provider ILIKE '%EASM%'`, ...s.cids))!.n,
    top: (await all<{ cid: string; aid: string; hostname: string | null; rank: number; findings: number; ports: string | null }>(
      `SELECT cid, aid, MAX(hostname) AS hostname, MIN(${RANK}) AS rank, COUNT(*) AS findings, STRING_AGG(DISTINCT port, ', ') AS ports
       FROM findings WHERE ${all_} AND provider ILIKE '%EASM%' GROUP BY cid, aid ORDER BY rank, findings DESC, hostname, aid LIMIT 5`, ...s.cids))
      .map((r) => ({ cid: soc ? r.cid : undefined, aid: r.aid, hostname: r.hostname, severity: SEV[r.rank], findings: r.findings, ports: (r.ports ?? "").split(", ").filter(Boolean).slice(0, 4) })),
  };
  return {
    tenant: { id: s.tenantId, name: s.tenantName }, completeness: await completeness(s, soc),
    totals: { critical: head.critical, high: head.high, devices: head.devices, internetDevices: head.internetDevices, internetCriticalHigh: head.internetCriticalHigh },
    kev: { cves: kev.cves, devices: kev.devices }, bySource, aging, topKev, external,
  };
}


/** The external attack surface, as Falcon's own Exposure management dashboard counts it: internet-facing IP addresses and domains (read from Falcon EASM), and what is wrong on them (their findings). */
route("GET", "/api/exposure/easm", async (c) => {
  const s = await tenantScope(c, "easm");
  return cached(`easm|${s.tenantId}`, s.cids, () => buildEasm(s));
});
async function buildEasm(s: Scope) {
  const w = `cid IN ${inList(s.cids)}`;
  const count = async (sql: string, ...p: (string | number)[]) => Object.fromEntries((await all<{ k: string | null; n: number }>(sql, ...s.cids, ...p)).map((r) => [r.k ?? "", r.n]));
  const ips = `${w} AND asset_type = 'ip'`, roots = `${w} AND asset_type <> 'ip' AND dns_type = 'root'`;
  const totals = (await get<{ ips: number; roots: number; subs: number }>(
    `SELECT COUNT(*) FILTER (WHERE asset_type = 'ip') ips, COUNT(*) FILTER (WHERE asset_type <> 'ip' AND dns_type = 'root') roots, COUNT(*) FILTER (WHERE asset_type <> 'ip' AND dns_type <> 'root') subs FROM external_assets WHERE ${w}`, ...s.cids))!;
  const review = (rows: Record<string, number>) => { // "not reviewed" is an empty triage status; anything Falcon calls reviewed is counted as reviewed
    let reviewed = 0, not = 0;
    for (const [k, n] of Object.entries(rows)) if (/^reviewed$/i.test(k)) reviewed += n; else not += n;
    return { reviewed, notReviewed: not };
  };
  const ext = `${w} AND provider ILIKE '%EASM%'`;
  const sync = s.cids.length ? await all<{ state: string; as_of: number | null; last_run_at: number; detail_json: string }>(`SELECT state, as_of, last_run_at, detail_json FROM external_sync WHERE cid IN ${inList(s.cids)}`, ...s.cids) : [];
  const state = !s.cids.length ? "no_cids" : sync.length < s.cids.length ? "not_synced" : sync.some((x) => x.state === "failed") ? "failed" : sync.some((x) => x.state === "partial") ? "partial" : "complete";
  return {
    state, asOf: sync.length && sync.every((x) => x.as_of) ? Math.min(...sync.map((x) => x.as_of!)) : null, lastRunAt: sync.length ? Math.max(...sync.map((x) => x.last_run_at)) : null,
    assets: { ips: totals.ips, rootDomains: totals.roots, subdomains: totals.subs },
    perimeter: await count(`SELECT COALESCE(perimeter, 'unknown') k, COUNT(*) n FROM external_assets WHERE ${ips} GROUP BY 1`),
    reviewIps: review(await count(`SELECT review k, COUNT(*) n FROM external_assets WHERE ${ips} GROUP BY 1`)),
    reviewRootDomains: review(await count(`SELECT review k, COUNT(*) n FROM external_assets WHERE ${roots} GROUP BY 1`)),
    online: await count(`SELECT COALESCE(status, 'unknown') k, COUNT(*) n FROM external_assets WHERE ${ips} GROUP BY 1`),
    discoveredBy: await count(`SELECT COALESCE(discovered_by, 'unknown') k, COUNT(*) n FROM external_assets WHERE ${w} GROUP BY 1`),
    cloud: (await all<{ k: string; n: number }>(`SELECT cloud k, COUNT(*) n FROM external_assets WHERE ${ips} AND cloud IS NOT NULL GROUP BY 1 ORDER BY n DESC, k LIMIT 6`, ...s.cids)),
    // what is wrong on the internet-facing assets: the findings Falcon EASM reported
    findings: {
      total: (await get<{ n: number }>(`SELECT COUNT(*) n FROM findings WHERE ${ext}`, ...s.cids))!.n,
      assets: (await get<{ n: number }>(`SELECT COUNT(DISTINCT cid || aid) n FROM findings WHERE ${ext}`, ...s.cids))!.n,
      byExprt: await count(`SELECT UPPER(COALESCE(NULLIF(exprt, ''), 'UNKNOWN')) k, COUNT(*) n FROM findings WHERE ${ext} GROUP BY 1`),
      byType: await count(`SELECT COALESCE(NULLIF(kind, ''), 'Other') k, COUNT(*) n FROM findings WHERE ${ext} GROUP BY 1`),
      bySeverity: await count(`SELECT severity k, COUNT(*) n FROM findings WHERE ${ext} GROUP BY 1`),
    },
  };
}

route("GET", "/api/exposure/vulnerabilities", async (c) => {
  const s = await tenantScope(c, "vulnerabilities");
  const { pageNo, size, offset } = page(c);
  const conds = [`cid IN ${inList(s.cids)}${srcSql(c.query)}`]; // roll_cve: one row per CID, source and CVE
  const args: (string | number)[] = [...s.cids];
  const q = (c.query.get("q") ?? "").trim().slice(0, 100);
  if (q) { conds.push("(cve_id ILIKE ? ESCAPE '\\' OR products ILIKE ? ESCAPE '\\')"); args.push(like(q), like(q)); }
  const sev = (c.query.get("severity") ?? "").toUpperCase();
  if (sev) {
    if (!(SEV as readonly string[]).includes(sev)) throw new HttpError(400, "Invalid severity");
    conds.push("rank = ?"); args.push(SEV.indexOf(sev as (typeof SEV)[number]));
  }
  const sorts: Record<string, string> = { severity: "rank, hosts DESC, cve_id", hosts: "hosts DESC, rank, cve_id", cvss: `"baseScore" DESC NULLS LAST, rank, cve_id` };
  const order = sorts[c.query.get("sort") ?? "severity"] ?? sorts.severity;
  const where = conds.join(" AND ");
  const total = (await get<{ n: number }>(`SELECT COUNT(DISTINCT cve_id) n FROM roll_cve WHERE ${where}`, ...args))!.n;
  const rows = (await all(
    `SELECT cve_id AS "cveId", MIN(rank) AS rank, MAX(base_score) AS "baseScore", MAX(exprt) AS exprt, MAX(exploit_status) AS "exploitStatus", MAX(kind) AS kind, MAX(product) AS product,
            SUM(hosts) AS hosts, SUM(findings) AS findings
     FROM roll_cve WHERE ${where} GROUP BY cve_id ORDER BY ${order} LIMIT ? OFFSET ?`, ...args, size, offset) as any[])
    .map((r) => ({ ...r, severity: SEV[r.rank], rank: undefined }));
  // public facts about each CVE on this page: published date and whether CISA lists it as exploited
  const facts = rows.length ? await all<{ id: string; cisa_kev: number; published_at: string | null }>(
    `SELECT id, cisa_kev, published_at FROM cves WHERE id IN ${inList(rows.map((r) => r.cveId))}`, ...rows.map((r) => r.cveId)) : [];
  for (const r of rows) {
    const f = facts.find((x) => x.id === r.cveId);
    r.kev = !!f?.cisa_kev; r.published = f?.published_at ?? null;
  }
  return { rows, total, page: pageNo, pageSize: size, completeness: await completeness(s, isSoc(c.user!.role)) };
});

route("GET", "/api/exposure/vulnerabilities/:cve", async (c) => {
  const cve = c.params.cve.toUpperCase();
  if (!CVE.test(cve)) throw new HttpError(400, "Invalid vulnerability id");
  const s = await tenantScope(c, `cve:${cve}`);
  const soc = isSoc(c.user!.role);
  const where = `cve_id = ? AND cid IN ${inList(s.cids)}`;
  const rows = await all<any>(
    `SELECT cid, aid, hostname, platform, local_ip, product, vendor, status, severity, base_score, exprt, exploit_status, remediation, provider, kind,
            risk_score, exploitability, first_seen, os_version, internet_exposure, port
     FROM findings WHERE ${where} ORDER BY ${RANK}, hostname, aid LIMIT 200`, cve, ...s.cids);
  const comp = await completeness(s, soc);
  // Public facts are shown whether or not this organization has the CVE. They never add to its numbers: "impact" comes only from its own Falcon findings.
  if (/^CVE-\d{4}-\d{4,7}$/.test(cve)) await ensurePublic([cve]);
  const pub = (await publicInfo([cve])).get(cve)!;
  if (!rows.length) return { found: false, cveId: cve, completeness: comp, public: pub, impact: await impactOf(s.tenantId, 0, pub.publishedAt) };
  const top = rows[0];
  const total = (await get<{ n: number }>(`SELECT COUNT(DISTINCT cid || aid) n FROM findings WHERE ${where}`, cve, ...s.cids))!.n;
  const hostRows = await all<any>(
    `SELECT cid, aid, MAX(hostname) AS hostname, MAX(platform) AS platform, MAX(provider) AS provider, MAX(local_ip) AS local_ip, MIN(product) AS product, COUNT(DISTINCT product) AS products,
            COUNT(*) AS findings, MIN(status) AS status, MIN(${RANK}) AS rank, MAX(os_version) AS os_version, MAX(internet_exposure) AS internet_exposure, MIN(first_seen) AS first_seen, MAX(risk_score) AS risk_score
     FROM findings WHERE ${where} GROUP BY cid, aid ORDER BY MIN(${RANK}), MAX(hostname), aid LIMIT 200`, cve, ...s.cids);
  const products = await all<{ product: string | null; vendor: string | null; n: number }>(
    `SELECT product, MAX(vendor) AS vendor, COUNT(DISTINCT cid || aid) AS n FROM findings WHERE ${where} GROUP BY product ORDER BY n DESC, product LIMIT 8`, cve, ...s.cids);
  // how it is exposed, over every device with this finding (not only the 200 listed)
  const ex = (await get<any>(
    `SELECT MAX(risk_score) AS "riskScore", MIN(first_seen) AS "firstSeen",
            COUNT(DISTINCT CASE WHEN internet_exposure = 'Yes' THEN cid || aid END) AS "internetFacing",
            COUNT(DISTINCT CASE WHEN exploitability = 'exploitable' THEN cid || aid END) AS exploitable,
            COUNT(DISTINCT CASE WHEN status = 'reopen' THEN cid || aid END) AS reopened
     FROM findings WHERE ${where}`, cve, ...s.cids))!;
  const ports = (await all<{ port: string }>(`SELECT DISTINCT port FROM findings WHERE ${where} AND port IS NOT NULL ORDER BY port LIMIT 10`, cve, ...s.cids)).map((p) => p.port);
  const info = await get<any>("SELECT * FROM cves WHERE id = ?", cve); // public vulnerability facts, not tenant data
  const list = (v: string | undefined) => (v ? (JSON.parse(v) as string[]) : []);
  const actions = [...new Set(rows.flatMap((r) => (r.remediation ?? "").split("\n").filter(Boolean)))];
  return {
    found: true, cveId: cve, public: pub, impact: await impactOf(s.tenantId, total, pub.publishedAt), severity: top.severity, baseScore: Math.max(...rows.map((r) => r.base_score ?? 0)), exprt: top.exprt, kind: top.kind,
    exploitStatus: Math.max(...rows.map((r) => r.exploit_status ?? 0)), remediation: actions, completeness: comp,
    about: info ? {
      description: info.description, publishedAt: info.published_at, vector: info.vector, exploitabilityScore: info.exploitability_score, impactScore: info.impact_score,
      cwes: list(info.cwes), types: list(info.types), references: list(info.references_json), advisories: list(info.advisories_json), cisaKev: !!info.cisa_kev,
    } : null,
    products: products.map((p) => ({ name: p.product, vendor: p.vendor, devices: p.n })),
    exposure: { ...ex, ports },
    devicesTotal: total,
    // one row per device (a device with several findings of this CVE counts once; `findings` says how many)
    hosts: hostRows.map((r) => ({
      cid: soc ? r.cid : undefined, key: soc ? `${r.cid}/${r.aid}` : r.aid, aid: r.aid, hostname: r.hostname, platform: r.platform, provider: r.provider, localIp: r.local_ip,
      product: r.product, products: Number(r.products), findings: Number(r.findings), status: r.status, severity: SEV[r.rank], osVersion: r.os_version, internetExposure: r.internet_exposure, firstSeen: r.first_seen, riskScore: r.risk_score,
    })),
  };
});

/** Urgent items of the organization: a CVE it has for the first time, or one that just entered CISA's KEV list while still open here. */
route("GET", "/api/exposure/urgent", async (c) => {
  const s = await tenantScope(c, "urgent");
  return { items: await urgentFor(s.tenantId, s.cids) };
});

route("GET", "/api/exposure/hosts", async (c) => {
  const s = await tenantScope(c, "hosts");
  const soc = isSoc(c.user!.role);
  const { pageNo, size, offset } = page(c);
  const conds = [`cid IN ${inList(s.cids)}${srcSql(c.query)}`]; // roll_host: one row per CID, source and device
  const args: (string | number)[] = [...s.cids];
  const q = (c.query.get("q") ?? "").trim().slice(0, 100);
  if (q) { conds.push("(hostname ILIKE ? ESCAPE '\\' OR local_ip ILIKE ? ESCAPE '\\' OR aid ILIKE ? ESCAPE '\\')"); args.push(like(q), like(q), like(q)); }
  const where = conds.join(" AND ");
  const total = (await get<{ n: number }>(`SELECT COUNT(*) n FROM (SELECT 1 FROM roll_host WHERE ${where} GROUP BY cid, aid) x`, ...args))!.n;
  const rows = (await all(
    `SELECT cid, aid, MAX(hostname) AS hostname, MAX(platform) AS platform, MAX(local_ip) AS "localIp", MAX(provider) AS provider, SUM(cves) AS cves, MAX(external_ip) AS "externalIp",
            SUM(critical) AS critical, SUM(high) AS high, SUM(medium) AS medium, SUM(exploited) AS exploited, MIN(rank) AS rank
     FROM roll_host WHERE ${where} GROUP BY cid, aid ORDER BY critical DESC, cves DESC, hostname, aid LIMIT ? OFFSET ?`, ...args, size, offset))
    .map((r: any) => ({ ...r, key: soc ? `${r.cid}/${r.aid}` : r.aid, cid: soc ? r.cid : undefined, severity: SEV[r.rank], rank: undefined }));
  return { rows, total, page: pageNo, pageSize: size, completeness: await completeness(s, soc) };
});

const softwareCache = new Map<string, { at: number; value: unknown }>();
/**
 * How Falcon detected the CVE on each device: installed version, where the software was found, and the version that fixes it.
 * Read from Falcon on demand (never stored), only for the tenant's own findings. "unavailable" means we could not ask, which is not "nothing".
 */
route("GET", "/api/exposure/vulnerabilities/:cve/software", async (c) => {
  const cve = c.params.cve.toUpperCase();
  if (!CVE.test(cve)) throw new HttpError(400, "Invalid vulnerability id");
  const s = await tenantScope(c, `cve-software:${cve}`);
  const hit = softwareCache.get(`${s.tenantId}|${cve}`);
  if (hit && Date.now() - hit.at < 300_000) return hit.value;
  const rows = await all<{ cid: string; aid: string; eval_id: string }>(
    `SELECT cid, aid, eval_id FROM findings WHERE cve_id = ? AND cid IN ${inList(s.cids)} AND eval_id IS NOT NULL AND (provider IS NULL OR provider NOT ILIKE '%EASM%')
     ORDER BY ${RANK}, hostname, aid LIMIT 200`, cve, ...s.cids);
  let value: unknown = { state: "none", versions: [], fixedIn: [], rows: [] };
  if (rows.length) {
    let facts: Map<string, SoftwareFact> | null = null;
    try { // each CID is asked with its own login
      facts = new Map();
      for (const cid of new Set(rows.map((r) => r.cid))) {
        const f = await lookupSoftware(cid, [...new Set(rows.filter((r) => r.cid === cid).map((r) => r.eval_id))]);
        if (!f) { facts = null; break; }
        for (const [k, v] of f) facts.set(k, v);
      }
    } catch { facts = null; }
    if (!facts) return { state: "unavailable", versions: [], fixedIn: [], rows: [] }; // not cached: try again next time
    const out = rows.map((r) => ({ aid: r.aid, ...(facts!.get(r.eval_id) ?? { installed: null, path: null, fixedIn: null }) }));
    const count = new Map<string, Set<string>>();
    for (const o of out) if (o.installed) (count.get(o.installed) ?? count.set(o.installed, new Set()).get(o.installed)!).add(o.aid);
    value = {
      state: "ok", rows: out,
      versions: [...count].map(([version, d]) => ({ version, devices: d.size })).sort((a, b) => b.devices - a.devices).slice(0, 10),
      fixedIn: [...new Set(out.map((o) => o.fixedIn).filter(Boolean))].slice(0, 5),
    };
  }
  softwareCache.set(`${s.tenantId}|${cve}`, { at: Date.now(), value });
  return value;
});

const FINDINGS_SHOWN = 300, PRODUCTS_SHOWN = 10, CVES_PER_PRODUCT = 3;

// The CID never travels in the URL: a device is looked up by its AID among the CIDs the caller may see,
// so a device outside the scope is indistinguishable from one that does not exist.
route("GET", "/api/exposure/hosts/:aid", async (c) => {
  const s = await tenantScope(c, "host");
  const soc = isSoc(c.user!.role);
  const aid = c.params.aid;
  const first = await get<{ cid: string }>(`SELECT cid FROM findings WHERE aid = ? AND cid IN ${inList(s.cids)} ORDER BY cid LIMIT 1`, aid, ...s.cids);
  if (!first) throw new HttpError(404, "Not found");
  const cid = first.cid; // one CID per AID in practice; never mix two
  const info = (await get<any>(
    `SELECT MAX(hostname) AS hostname, MAX(platform) AS platform, MAX(local_ip) AS "localIp", MAX(external_ip) AS "externalIp", MAX(provider) AS provider FROM findings WHERE aid = ? AND cid = ?`, aid, cid))!;
  const counts = Object.fromEntries(SEV.map((x) => [x, 0])) as Record<string, number>;
  for (const r of await all<{ severity: string; n: number }>("SELECT severity, COUNT(*) n FROM findings WHERE aid = ? AND cid = ? GROUP BY severity", aid, cid)) counts[r.severity] = r.n;
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  const findings = await all<any>(
    `SELECT cve_id, severity, base_score, exploit_status, product, status, remediation, kind FROM findings WHERE aid = ? AND cid = ?
     ORDER BY ${RANK}, base_score DESC NULLS LAST, cve_id LIMIT ${FINDINGS_SHOWN}`, aid, cid);
  // the device -> product -> CVE tree: the riskiest products, and the worst few CVEs of each
  const prod = await all<any>(
    `SELECT COALESCE(product, '') AS product, COUNT(*) AS total, MIN(${RANK}) AS rank FROM findings WHERE aid = ? AND cid = ?
     GROUP BY 1 ORDER BY rank, total DESC, product LIMIT ${PRODUCTS_SHOWN}`, aid, cid);
  const totalProducts = (await get<{ n: number }>("SELECT COUNT(DISTINCT COALESCE(product, '')) n FROM findings WHERE aid = ? AND cid = ?", aid, cid))!.n;
  const top = await all<any>(
    `SELECT product, cve_id, severity FROM (
       SELECT COALESCE(product, '') AS product, cve_id, severity,
              ROW_NUMBER() OVER (PARTITION BY COALESCE(product, '') ORDER BY ${RANK}, base_score DESC NULLS LAST, cve_id) AS rn
       FROM findings WHERE aid = ? AND cid = ?) x WHERE rn <= ${CVES_PER_PRODUCT}`, aid, cid);
  const products = prod.map((p) => {
    const cves = top.filter((t) => t.product === p.product).map((t) => ({ cveId: t.cve_id, severity: t.severity }));
    return { name: p.product || null, total: p.total, severity: SEV[p.rank], cves, more: Math.max(0, p.total - cves.length) };
  });
  return {
    cid: soc ? cid : undefined, aid, hostname: info.hostname, platform: info.platform, provider: info.provider, localIp: info.localIp, externalIp: info.externalIp,
    counts, total, truncated: total > findings.length,
    findings: findings.map((r) => ({ cveId: r.cve_id, severity: r.severity, baseScore: r.base_score, exploitStatus: r.exploit_status, product: r.product, status: r.status, remediation: r.remediation, kind: r.kind })),
    products, productsMore: Math.max(0, totalProducts - products.length),
  };
});

const GRAPH_DEVICES = 60;
/** The new graph (graph2.ts) answers the same path when `lens` is given; without it the old graph below answers. */
export const graphLens: { handler: null | ((c: Ctx) => Promise<unknown>) } = { handler: null };
/**
 * Overview graph: the most widespread CVEs and the devices linked to them. Bounded on purpose
 * (n CVEs, at most 60 devices), with the real totals alongside so the page can say what is left out.
 */
route("GET", "/api/exposure/graph", async (c) => {
  if (c.query.has("lens") && graphLens.handler) return graphLens.handler(c);
  const s = await tenantScope(c, "graph");
  const n = Math.min(40, Math.max(5, Number(c.query.get("cves")) || 20));
  const sev = (c.query.get("severity") ?? "").toUpperCase();
  if (sev && !(SEV as readonly string[]).includes(sev)) throw new HttpError(400, "Invalid severity");
  const base = `cid IN ${inList(s.cids)}${sourceSql(c.query)}`; // on findings: the rows of a few CVEs, by index
  const rb = `cid IN ${inList(s.cids)}${srcSql(c.query)}`; // on the rollups
  const where = sev ? `${rb} AND rank = ?` : rb;
  const args: (string | number)[] = sev ? [...s.cids, SEV.indexOf(sev as (typeof SEV)[number])] : [...s.cids];
  const totals = {
    devices: (await get<{ n: number }>(`SELECT COUNT(DISTINCT cid || aid) n FROM roll_host WHERE ${rb}`, ...s.cids))!.n,
    ...(await get<{ cves: number; findings: number }>(`SELECT COUNT(DISTINCT cve_id) cves, COALESCE(SUM(findings), 0) findings FROM roll_cve WHERE ${rb}`, ...s.cids))!,
  };
  // What to look at first. Not a guess: each reason is a fact we hold, and the score only orders them.
  //   CISA KEV (public list of vulnerabilities exploited in real attacks) ........ 1000
  //   Falcon exploit status: actively used 90 / easily accessible 60 / available 30  600 / 300 / 100
  //   Falcon ExPRT rating (CrowdStrike's own exploit-likelihood model) ........... up to 3 x 70
  //   on a device exposed to the internet (Falcon) ................................ 200
  //   Falcon severity (Critical 400, High 300, Medium 100) + CVSS x 10 + devices (max 100)
  const cves = (await all<any>(
    `SELECT g.*, (CASE WHEN EXISTS (SELECT 1 FROM kev k WHERE k.cve_id = g.id) OR EXISTS (SELECT 1 FROM cves c WHERE c.id = g.id AND c.cisa_kev = 1) THEN 1 ELSE 0 END) AS kev
     FROM (SELECT cve_id AS id, MIN(rank) AS rank, MAX(base_score) AS score, SUM(hosts) AS devices, MAX(exploit_status) AS ex, MAX(exprt_rank) AS exprt, SUM(inet) AS inet
           FROM roll_cve WHERE ${where} GROUP BY cve_id) g
     ORDER BY (CASE g.rank WHEN 0 THEN 400 WHEN 1 THEN 300 WHEN 2 THEN 100 ELSE 0 END)
            + (CASE WHEN EXISTS (SELECT 1 FROM kev k WHERE k.cve_id = g.id) OR EXISTS (SELECT 1 FROM cves c WHERE c.id = g.id AND c.cisa_kev = 1) THEN 1000 ELSE 0 END)
            + (CASE WHEN g.ex >= 90 THEN 600 WHEN g.ex >= 60 THEN 300 WHEN g.ex >= 30 THEN 100 ELSE 0 END) + g.exprt * 70
            + (CASE WHEN g.inet > 0 THEN 200 ELSE 0 END) + COALESCE(g.score, 0) * 10 + LEAST(g.devices, 100) DESC, g.id
     LIMIT ${n}`, ...args))
    .map((r) => {
      const reasons = [r.kev ? "kev" : "", r.ex >= 60 ? "exploited" : "", r.exprt >= 2 ? "exprt" : "", r.inet > 0 ? "internet" : ""].filter(Boolean);
      const priority = (r.rank === 0 ? 400 : r.rank === 1 ? 300 : r.rank === 2 ? 100 : 0) + (r.kev ? 1000 : 0) + (r.ex >= 90 ? 600 : r.ex >= 60 ? 300 : r.ex >= 30 ? 100 : 0) + r.exprt * 70 + (r.inet > 0 ? 200 : 0) + (r.score ?? 0) * 10 + Math.min(r.devices, 100);
      return { id: r.id as string, severity: SEV[r.rank], score: r.score as number | null, devices: r.devices as number, kev: !!r.kev, exploitStatus: r.ex as number | null, internetDevices: r.inet as number, priority: Math.round(priority), reasons };
    });
  if (!cves.length) return { totals, cves: [], devices: [], links: [], devicesShown: 0, completeness: await completeness(s, isSoc(c.user!.role)) };
  const rows = await all<any>(
    `SELECT aid, MAX(hostname) AS hostname, MAX(platform) AS platform, MAX(provider) AS provider, cve_id, MIN(${RANK}) AS rank
     FROM findings WHERE ${base} AND cve_id IN ${inList(cves.map((x) => x.id))} GROUP BY aid, cve_id`, ...s.cids, ...cves.map((x) => x.id));
  const byDevice = new Map<string, { aid: string; hostname: string | null; platform: string | null; provider: string | null; worst: number; links: Set<string> }>();
  for (const r of rows) {
    const d = byDevice.get(r.aid) ?? { aid: r.aid, hostname: r.hostname, platform: r.platform, provider: r.provider, worst: 4, links: new Set<string>() };
    d.worst = Math.min(d.worst, r.rank);
    d.links.add(r.cve_id);
    byDevice.set(r.aid, d);
  }
  const shown = [...byDevice.values()].sort((a, b) => a.worst - b.worst || b.links.size - a.links.size || (a.hostname ?? "").localeCompare(b.hostname ?? "")).slice(0, GRAPH_DEVICES);
  const cveIndex = new Map(cves.map((x, i) => [x.id, i]));
  return {
    totals, cves,
    devices: shown.map((d) => ({ aid: d.aid, hostname: d.hostname, platform: d.platform, provider: d.provider, severity: SEV[d.worst] })),
    links: shown.flatMap((d, i) => [...d.links].map((id) => [i, cveIndex.get(id)!])),
    devicesShown: shown.length, devicesLinked: byDevice.size,
    completeness: await completeness(s, isSoc(c.user!.role)),
  };
});

/** After a sync the next page view should not wait for the aggregates: compute the default Overview of the organization that owns this CID. */
warmers.push(async (cid) => {
  const t = await get<{ id: string; name: string }>("SELECT t.id, t.name FROM tenant_cids x JOIN tenants t ON t.id = x.tenant_id WHERE x.cid = ?", cid);
  if (!t) return;
  const cids = (await all<{ cid: string }>("SELECT cid FROM tenant_cids WHERE tenant_id = ? ORDER BY cid", t.id)).map((r) => r.cid);
  const s: Scope = { tenantId: t.id, tenantName: t.name, cids };
  const none = new URLSearchParams();
  for (const soc of [false, true]) { // members and super admins each have their own entry (a super admin's answer carries CIDs)
    await cached(`summary|${t.id}|${soc}||`, cids, () => buildSummary(s, soc, none));
    await cached(`executive|${t.id}|${soc}|`, cids, () => buildExecutive(s, soc, none));
    await cached(`easm|${t.id}`, cids, () => buildEasm(s));
  }
});
