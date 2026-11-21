import { all, get, isSoc } from "./db.ts";
import { HttpError, route, type Ctx } from "./http.ts";
import { inList, tenantScope, type Scope } from "./scope.ts";
import { sendCsv } from "./lists2.ts";

// Software inventory from Falcon Discover: what is installed on the tenant's devices (applications, packages, browser and IDE extensions, AI models).
const TYPES = ["application", "browser_extension", "dev_package", "ide_extension", "llm", "mcp"];
const like = (q: string) => `%${q.replace(/[\\%_]/g, "\\$&")}%`;

/** A software item is identified by (type, vendor, name). The key travels in the URL, so it is base64url JSON and re-validated here. */
const keyOf = (type: string, vendor: string, name: string) => Buffer.from(JSON.stringify([type, vendor, name])).toString("base64url");
function parseKey(k: string): [string, string, string] {
  try {
    const v = JSON.parse(Buffer.from(k, "base64url").toString("utf8"));
    if (Array.isArray(v) && v.length === 3 && v.every((x) => typeof x === "string") && TYPES.includes(v[0]) && v[2]) return v as [string, string, string];
  } catch { /* falls through */ }
  throw new HttpError(400, "Invalid software id");
}

/** Same meaning as the vulnerability pages: only "complete" supports "nothing found". */
async function completeness(s: Scope, soc: boolean) {
  if (!s.cids.length) return { state: "no_cids" as const, dataAsOf: null, lastRunAt: null, cids: [] };
  const rows = await all<{ cid: string; state: string; as_of: number | null; last_run_at: number; detail_json: string }>(
    `SELECT cid, state, as_of, last_run_at, detail_json FROM software_sync WHERE cid IN ${inList(s.cids)}`, ...s.cids);
  const detail = (r: (typeof rows)[number]) => ({ cid: r.cid, state: r.state, detail: JSON.parse(r.detail_json) as string[] });
  if (rows.length < s.cids.length) return { state: "not_synced" as const, dataAsOf: null, lastRunAt: null, cids: soc ? rows.map(detail) : [] };
  const worst = rows.some((r) => r.state === "failed") ? "failed" : rows.some((r) => r.state === "partial") ? "partial" : "complete";
  return {
    state: worst as "complete" | "partial" | "failed", dataAsOf: rows.every((r) => r.as_of) ? Math.min(...rows.map((r) => r.as_of!)) : null,
    lastRunAt: Math.max(...rows.map((r) => r.last_run_at)), cids: soc ? rows.map(detail) : [],
  };
}

/** The software list, shared by the page and its CSV: P1 and KEV CVEs per item come from roll_soft (product-name match, see rollup.ts refreshSoftware). */
async function softwareRows(c: Ctx, s: Scope, size: number, offset: number) {
  const conds = [`x.cid IN ${inList(s.cids)}`];
  const args: (string | number)[] = [...s.cids];
  const type = c.query.get("type") ?? "";
  if (type) {
    if (!TYPES.includes(type)) throw new HttpError(400, "Invalid type");
    conds.push("x.type = ?"); args.push(type);
  }
  const q = (c.query.get("q") ?? "").trim().slice(0, 100);
  if (q) { conds.push("(x.name ILIKE ? ESCAPE '\\' OR x.vendor ILIKE ? ESCAPE '\\')"); args.push(like(q), like(q)); }
  if (c.query.get("flagged") === "1") conds.push("x.suspicious = 1");
  const having: string[] = [];
  for (const [k, col] of [["p1", "p1_cves"], ["kev", "kev_cves"]] as const) {
    const v = c.query.get(k);
    if (v && v !== "0" && v !== "1") throw new HttpError(400, `Invalid ${k}`);
    if (v === "1") having.push(`COALESCE(MAX(rs.${col}), 0) > 0`);
  }
  const where = conds.join(" AND ");
  const sorts: Record<string, string> = {
    devices: "devices DESC, name", name: "name, vendor", recent: `"firstSeen" DESC NULLS LAST, name`,
    risk: `"p1Cves" DESC, "kevCves" DESC, devices DESC, name`,
  };
  const sort = c.query.get("sort") ?? "devices";
  if (!sorts[sort]) throw new HttpError(400, "Invalid sort");
  const from = `FROM software x LEFT JOIN roll_soft rs ON rs.cid = x.cid AND rs.type = x.type AND rs.vendor = x.vendor AND rs.name = x.name WHERE ${where} GROUP BY x.type, x.vendor, x.name${having.length ? ` HAVING ${having.join(" AND ")}` : ""}`;
  const total = (await get<{ n: number }>(`SELECT COUNT(*) n FROM (SELECT 1 ${from}) t`, ...args))!.n;
  const rows = (await all<any>(
    `SELECT x.type, x.vendor, x.name, MAX(x.category) AS category, COUNT(DISTINCT x.host_id) AS devices, COUNT(DISTINCT x.version) AS versions, MIN(x.first_seen) AS "firstSeen",
            MAX(x.suspicious) AS suspicious, MAX(x.latest) AS latest, COALESCE(MAX(rs.p1_cves), 0)::int AS "p1Cves", COALESCE(MAX(rs.kev_cves), 0)::int AS "kevCves"
     ${from} ORDER BY ${sorts[sort]} LIMIT ? OFFSET ?`, ...args, size, offset))
    .map((r) => ({ ...r, key: keyOf(r.type, r.vendor, r.name), suspicious: !!r.suspicious }));
  return { rows, total };
}

route("GET", "/api/exposure/software", async (c: Ctx) => {
  const s = await tenantScope(c, "software");
  const soc = isSoc(c.user!.role);
  const pageNo = Math.max(1, Number(c.query.get("page")) || 1);
  const size = Math.min(100, Math.max(1, Number(c.query.get("pageSize")) || 25));
  // totals ignore the type/search filters so the type chips always show the whole inventory
  const base = `cid IN ${inList(s.cids)}`;
  const byType = await all<{ type: string; items: number; devices: number }>(
    `SELECT type, COUNT(DISTINCT (name, vendor)) AS items, COUNT(DISTINCT host_id) AS devices FROM software WHERE ${base} GROUP BY type ORDER BY items DESC`, ...s.cids);
  const { rows, total } = await softwareRows(c, s, size, (pageNo - 1) * size);
  const devices = (await get<{ n: number }>(`SELECT COUNT(DISTINCT host_id) n FROM software WHERE ${base}`, ...s.cids))!.n;
  return { rows, total, page: pageNo, pageSize: size, byType, devices, completeness: await completeness(s, soc) };
});

/** CSV of the software list (same filters and order), scoped, streamed, formula-safe: see lists2.ts sendCsv. */
route("GET", "/api/exposure/software.csv", async (c: Ctx) => {
  const s = await tenantScope(c, "export:software");
  const first = await softwareRows(c, s, 1, 0);
  return sendCsv(c, s, "software", ["name", "vendor", "type", "category", "devices", "versions", "p1_cves", "kev_cves", "suspicious", "first_seen", "latest_version"], first.total, async (o, n) =>
    (await softwareRows(c, s, n, o)).rows.map((r: any): [string, unknown[]] => ["", [r.name, r.vendor, r.type, r.category, r.devices, r.versions, r.p1Cves, r.kevCves, r.suspicious, r.firstSeen ? new Date(r.firstSeen).toISOString() : "", r.latest]]));
});

route("GET", "/api/exposure/software/:key", async (c: Ctx) => {
  const [type, vendor, name] = parseKey(c.params.key);
  const s = await tenantScope(c, "software-item");
  const where = `cid IN ${inList(s.cids)} AND type = ? AND vendor = ? AND name = ?`;
  const args = [...s.cids, type, vendor, name];
  const info = await get<any>(
    `SELECT MAX(category) AS category, MAX(suspicious) AS suspicious, MAX(threat) AS threat, MAX(latest) AS latest, MAX(link) AS link, MAX(host_app) AS "hostApp",
            MIN(first_seen) AS "firstSeen", MAX(updated_at) AS "updatedAt", COUNT(DISTINCT host_id) AS devices, COUNT(*) AS instances FROM software WHERE ${where}`, ...args);
  if (!info || !info.instances) return { found: false, completeness: await completeness(s, isSoc(c.user!.role)) };
  const versions = await all(`SELECT version, COUNT(DISTINCT host_id) AS devices FROM software WHERE ${where} GROUP BY version ORDER BY devices DESC, version LIMIT 30`, ...args);
  // a device only links to its drawer when that device also has findings in this tenant (the drawer reads findings)
  const hosts = await all<any>(
    `SELECT h.aid, h.hostname, h.platform, MAX(x.version) AS version, MAX(x.enabled) AS enabled, MAX(x.first_seen) AS "firstSeen",
            EXISTS (SELECT 1 FROM findings f WHERE f.aid = h.aid AND f.cid IN ${inList(s.cids)}) AS "hasFindings"
     FROM software x LEFT JOIN software_hosts h ON h.cid = x.cid AND h.host_id = x.host_id
     WHERE x.cid IN ${inList(s.cids)} AND x.type = ? AND x.vendor = ? AND x.name = ?
     GROUP BY h.aid, h.hostname, h.platform ORDER BY hostname NULLS LAST LIMIT 200`, ...s.cids, ...s.cids, type, vendor, name);
  return {
    found: true, key: keyOf(type, vendor, name), type, vendor, name, ...info, suspicious: !!info.suspicious,
    versions, hosts: hosts.map((h) => ({ ...h, aid: h.hasFindings ? h.aid : null, hasFindings: undefined })), completeness: await completeness(s, isSoc(c.user!.role)),
  };
});
