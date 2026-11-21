// API v2, the graph (graph-design.md, server section): GET /api/exposure/graph?lens=fix|matrix|focus (the same path as the old graph, which answers when there is no `lens`),
// /graph/list, /graph/search and /graph/meta. Page payloads are tiny rollups (<= 60 nodes, <= 100 links), never rows.
// Reads roll_fix_host / roll_fix_cve / roll_prod_host (the pairs), roll_fix_dim / roll_prod_dim (the cells per host group, OS or site) and roll_dim; the focus of a CVE or a host reads the findings by index.
// Endpoint findings of tier P1 and P2 only; every route goes through tenantScope() and is cached (the default lens is warmed after a sync).
import { all, get, isSoc, nameOrder } from "./db.ts";
import { HttpError, route, type Ctx } from "./http.ts";
import { inList, tenantScope, type Scope } from "./scope.ts";
import { cached, warmers } from "./cache.ts";
import { completeness, graphLens } from "./exposure.ts";
import { EXPRT, SEV, cacheKey } from "./overview.ts";
import { watchedSet } from "./watch.ts";

type Arg = string | number;
type Dim = "group" | "os" | "site";
const DIMS: Dim[] = ["group", "os", "site"];
const bad = (what: string): never => { throw new HttpError(400, `Invalid ${what}`, "invalid_filter"); };
const text = (c: Ctx, k: string, max = 200) => (c.query.get(k) ?? "").trim().slice(0, max);
const clamp = (n: number, a: number, b: number) => Math.min(b, Math.max(a, n));
const esc = (v: string) => v.replace(/[\\%_]/g, "\\$&");
const fixTitle = (rem: string | null) => (rem ? rem.split("\n")[0].replace(/^-\s*/, "").slice(0, 300) : null);

interface Gf { set: "1" | "12" | "k"; inet: boolean; top: number; by: Dim; sel: { dim: Dim; id: string }[]; tiers: string }
/** The metric of a (fix, host) pair for the chosen tier set: P1 findings, P1+P2 findings, or KEV findings (all KEV findings are P1). */
const metric = (g: Gf, a = "p") => (g.set === "1" ? `${a}.p1` : g.set === "12" ? `(${a}.p1 + ${a}.p2)` : `${a}.kev`);
const pairCond = (g: Gf, a = "p") => `${metric(g, a)} > 0${g.inet ? ` AND ${a}.inet` : ""}`;
/** The column of a rollup row (roll_fix, roll_prod, roll_fix_dim, roll_prod_dim) for the chosen set: h = hosts, f = findings; with internet=1 the internet-facing variants hi / fi. */
const cellCol = (g: Gf, kind: "h" | "f") => `${kind}${g.inet ? "i" : ""}${g.set}`;
/** Host-level test on roll_host for the chosen set (distinct hosts overall are not additive over fixes, so they come from the host rollup). */
const hostCond = (g: Gf, a = "p") => `${g.set === "1" ? `${a}.p1 > 0` : g.set === "12" ? `${a}.p1 + ${a}.p2 > 0` : `${a}.kev_cves > 0`}${g.inet ? ` AND ${a}.inet` : ""}`;

async function parseFilters(c: Ctx, s: Scope): Promise<Gf> {
  const t = (c.query.get("tier") ?? "P1").split(",").map((x) => x.trim().toUpperCase().replace(/^(\d)$/, "P$1")).filter(Boolean).sort().join(",");
  if (t !== "P1" && t !== "P1,P2") bad("tier (the graph shows P1 or P1,P2)");
  const kev = c.query.get("kev") === "1", inet = c.query.get("internet") === "1";
  for (const [k, v] of [["kev", c.query.get("kev")], ["internet", c.query.get("internet")]]) if (v && v !== "0" && v !== "1") bad(k as string);
  const top = clamp(Number(c.query.get("top")) || 10, 5, 20);
  const asked = c.query.get("by");
  if (asked && !DIMS.includes(asked as Dim)) bad("by");
  const hasGroups = s.cids.length ? !!(await get(`SELECT 1 FROM roll_dim WHERE cid IN ${inList(s.cids)} AND dim = 'group' LIMIT 1`, ...s.cids)) : false;
  const by = (asked as Dim) ?? (hasGroups ? "group" : "os");
  const sel = DIMS.filter((d) => text(c, d)).map((d) => ({ dim: d, id: text(c, d, 120) }));
  return { set: kev ? "k" : t === "P1" ? "1" : "12", inet, top, by, sel, tiers: t };
}

/** Rows (aid, dim_id) of one dimension for the CIDs; a host with no inventory row has its OS from its findings. */
function dimRows(dim: Dim, cids: string[]): { sql: string; args: Arg[] } {
  const ph = inList(cids);
  if (dim === "group") return { sql: `SELECT aid, g AS dim_id FROM hosts, unnest(groups) g WHERE cid IN ${ph} AND g <> ''`, args: [...cids] };
  if (dim === "site") return { sql: `SELECT aid, site AS dim_id FROM hosts WHERE cid IN ${ph} AND COALESCE(site, '') <> ''`, args: [...cids] };
  return { sql: `SELECT aid, COALESCE(NULLIF(os_version, ''), NULLIF(platform, ''), 'unknown') AS dim_id FROM hosts WHERE cid IN ${ph}
    UNION ALL SELECT r.aid, COALESCE(NULLIF(r.platform, ''), 'unknown') FROM roll_host r WHERE r.cid IN ${ph} AND r.src = 'endpoint' AND NOT EXISTS (SELECT 1 FROM hosts h WHERE h.cid = r.cid AND h.aid = r.aid)`, args: [...cids, ...cids] };
}
/** The hosts inside every selected dimension value (group=, os=, site=): an `AND p.aid IN (...)` clause. */
function selClause(g: Gf, cids: string[], alias = "p"): { sql: string; args: Arg[] } {
  let sql = ""; const args: Arg[] = [];
  for (const x of g.sel) { const d = dimRows(x.dim, cids); sql += ` AND ${alias}.aid IN (SELECT aid FROM (${d.sql}) dd WHERE dd.dim_id = ?)`; args.push(...d.args, x.id); }
  return { sql, args };
}
const sevOf = (rank: number | null) => (rank === null ? null : SEV[rank]);

async function titles(ids: number[]) {
  const rows = ids.length ? await all<{ id: number; remediation: string | null }>("SELECT id, remediation FROM rem_sets WHERE id = ANY(?::bigint[])", ids as any) : [];
  return new Map(rows.map((r) => [r.id, fixTitle(r.remediation)]));
}
const nodeOther = (rows: { findings: number }[]) => ({ count: rows.length, findings: rows.reduce((a, r) => a + r.findings, 0) });

// ---------- lens = fix ----------
interface LeftFix { fix_id: number; hosts: number; findings: number; p1: number; p2: number; kev: number; inet: number }
async function fixNodes(s: Scope, g: Gf) {
  const ph = inList(s.cids), sel = selClause(g, s.cids);
  const h = cellCol(g, "h"), f = cellCol(g, "f"), f1 = `f${g.inet ? "i" : ""}1`, f12 = `f${g.inet ? "i" : ""}12`, fk = `f${g.inet ? "i" : ""}k`;
  let rows: LeftFix[];
  if (g.sel.length <= 1) { // the default and one chosen value: a small rollup row per fix (or per fix and value), no pairs
    const from = g.sel.length ? `roll_fix_dim x WHERE x.cid IN ${ph} AND x.dim = ? AND x.dim_id = ?` : `roll_fix x WHERE x.cid IN ${ph}`;
    rows = await all<LeftFix>(
      `SELECT x.fix_id, SUM(x.${h})::int hosts, SUM(x.${f})::int findings, SUM(x.${f1})::int p1, (SUM(x.${f12}) - SUM(x.${f1}))::int p2, SUM(x.${fk})::int kev, SUM(x.${g.set === "k" ? "hik" : g.set === "1" ? "hi1" : "hi12"})::int inet
       FROM ${from} AND x.${h} > 0 GROUP BY x.fix_id ORDER BY 3 DESC, 2 DESC, 1`, ...s.cids, ...(g.sel.length ? [g.sel[0].dim, g.sel[0].id] : []));
  } else {
    rows = await all<LeftFix>(
      `SELECT p.fix_id, COUNT(*)::int hosts, SUM(${metric(g)})::int findings, SUM(p.p1)::int p1, SUM(p.p2)::int p2, SUM(p.kev)::int kev, (COUNT(*) FILTER (WHERE p.inet))::int inet
       FROM roll_fix_host p WHERE p.cid IN ${ph} AND ${pairCond(g)}${sel.sql} GROUP BY p.fix_id ORDER BY 3 DESC, 2 DESC, 1`, ...s.cids, ...sel.args);
  }
  const totals = (await get<{ hosts: number }>(`SELECT COUNT(*)::int hosts FROM roll_host p WHERE p.cid IN ${ph} AND p.src = 'endpoint' AND ${hostCond(g)}${sel.sql}`, ...s.cids, ...sel.args))!;
  return { rows, hosts: totals.hosts };
}
async function buildFixLens(s: Scope, g: Gf, soc: boolean) {
  const all_ = await fixNodes(s, g);
  const drawn = all_.rows.slice(0, g.top), rest = all_.rows.slice(g.top);
  const names = await titles(drawn.map((r) => r.fix_id));
  const meta = new Map((drawn.length ? await all<any>(`SELECT fix_id, MAX(product) product FROM roll_fix WHERE cid IN ${inList(s.cids)} AND fix_id = ANY(?::bigint[]) GROUP BY fix_id`, ...s.cids, drawn.map((r) => r.fix_id) as any) : []).map((r) => [r.fix_id, r.product]));
  const left = drawn.map((r) => ({ id: String(r.fix_id), label: names.get(r.fix_id) ?? meta.get(r.fix_id) ?? null, noFix: r.fix_id === 0, product: meta.get(r.fix_id) ?? null, hosts: r.hosts, findings: r.findings, p1: r.p1, p2: r.p2, kev: r.kev, inet: r.inet }));
  const out: any = { lens: "fix", by: g.by, tier: g.tiers, totals: { hosts: all_.hosts, findings: all_.rows.reduce((a, r) => a + r.findings, 0), fixes: all_.rows.length }, left, leftOther: { count: rest.length, findings: rest.reduce((a, r) => a + r.findings, 0), p1: rest.reduce((a, r) => a + r.p1, 0) } };
  Object.assign(out, await rightSide(s, g, drawn.map((r) => r.fix_id), "fix"));
  return { ...out, completeness: await completeness(s, soc) };
}

/** The right column for a set of fixes (or one product): host groups / OS / sites, or, when a value is chosen, its top hosts. links = [left index, right index, hosts] (cells are exact distinct hosts; never summed across fixes). */
async function rightSide(s: Scope, g: Gf, ids: (number | string)[], kind: "fix" | "product") {
  if (!ids.length) return { mode: "dim", right: [], rightOther: { count: 0, total: 0 }, links: [] };
  const table = kind === "fix" ? "roll_fix_host" : "roll_prod_host", key = kind === "fix" ? "fix_id" : "product", arr = kind === "fix" ? "bigint" : "text";
  const sel = selClause(g, s.cids);
  const ph = inList(s.cids);
  if (g.sel.length) { // a value is chosen: the hosts of it
    const hosts = await all<any>(
      `SELECT p.aid, SUM(${metric(g)})::int n, (BOOL_OR(p.inet)) inet FROM ${table} p WHERE p.cid IN ${ph} AND ${key} = ANY(?::${arr}[]) AND ${pairCond(g)}${sel.sql} GROUP BY p.aid ORDER BY 2 DESC, 1 LIMIT 12`, ...s.cids, ids as any, ...sel.args);
    const info = new Map((hosts.length ? await all<any>(`SELECT aid, hostname, COALESCE(os_version, platform) os FROM (SELECT aid, hostname, os_version, platform FROM hosts WHERE cid IN ${ph} UNION ALL SELECT aid, hostname, NULL, platform FROM roll_host WHERE cid IN ${ph} AND src = 'endpoint') x WHERE aid = ANY(?::text[])`, ...s.cids, ...s.cids, hosts.map((h) => h.aid) as any) : []).map((r) => [r.aid, r]));
    const total = (await get<{ n: number; c: number }>(`SELECT COALESCE(SUM(${metric(g)}), 0)::int n, COUNT(DISTINCT p.aid)::int c FROM ${table} p WHERE p.cid IN ${ph} AND ${key} = ANY(?::${arr}[]) AND ${pairCond(g)}${sel.sql}`, ...s.cids, ids as any, ...sel.args))!;
    const links = hosts.length ? await all<any>(`SELECT p.${key} k, p.aid, ${metric(g)}::int n FROM ${table} p WHERE p.cid IN ${ph} AND p.${key} = ANY(?::${arr}[]) AND p.aid = ANY(?::text[]) AND ${pairCond(g)}`, ...s.cids, ids as any, hosts.map((h) => h.aid) as any) : [];
    return {
      mode: "host", right: hosts.map((h) => ({ id: h.aid, label: info.get(h.aid)?.hostname ?? h.aid.slice(0, 8), sub: info.get(h.aid)?.os ?? null, n: h.n, inet: h.inet })), rightOther: { count: Math.max(0, total.c - hosts.length), total: Math.max(0, total.n - hosts.reduce((a, h) => a + h.n, 0)) },
      links: links.map((l) => [ids.findIndex((x) => String(x) === String(l.k)), hosts.findIndex((h) => h.aid === l.aid), l.n]).filter((l) => l[0] >= 0 && l[1] >= 0),
    };
  }
  // distinct hosts affected per group, over the drawn fixes
  const d = dimRows(g.by, s.cids);
  const groups = await all<any>(
    `SELECT dd.dim_id, COUNT(DISTINCT p.aid)::int hosts, SUM(${metric(g)})::int total FROM ${table} p JOIN (${d.sql}) dd ON dd.aid = p.aid WHERE p.cid IN ${ph} AND p.${key} = ANY(?::${arr}[]) AND ${pairCond(g)} GROUP BY dd.dim_id ORDER BY 2 DESC, 3 DESC, 1`, ...d.args, ...s.cids, ids as any);
  groups.sort((a, b) => b.hosts - a.hosts || b.total - a.total || nameOrder.compare(a.dim_id, b.dim_id));
  const shown = groups.slice(0, 8), other = groups.slice(8);
  const cells = shown.length ? await all<any>(
    `SELECT fix_id AS k, dim_id, ${cellCol(g, "h")} AS n FROM roll_fix_dim WHERE cid IN ${ph} AND dim = ? AND fix_id = ANY(?::bigint[]) AND dim_id = ANY(?::text[]) AND ${cellCol(g, "h")} > 0`, ...s.cids, g.by, ids.filter((x) => kind === "fix") as any, shown.map((x) => x.dim_id) as any) : [];
  const pcells = kind === "product" && shown.length ? await all<any>(
    `SELECT product AS k, dim_id, ${cellCol(g, "h")} AS n FROM roll_prod_dim WHERE cid IN ${ph} AND dim = ? AND product = ANY(?::text[]) AND dim_id = ANY(?::text[]) AND ${cellCol(g, "h")} > 0`, ...s.cids, g.by, ids as any, shown.map((x) => x.dim_id) as any) : [];
  const use = kind === "fix" ? cells : pcells;
  return {
    mode: "dim", right: shown.map((x) => ({ id: x.dim_id, label: x.dim_id, hosts: x.hosts, total: x.total })), rightOther: { count: other.length, total: other.reduce((a, x) => a + x.total, 0) },
    links: use.map((l) => [ids.findIndex((x) => String(x) === String(l.k)), shown.findIndex((x) => x.dim_id === l.dim_id), l.n]).filter((l) => l[0] >= 0 && l[1] >= 0),
  };
}

// ---------- lens = matrix ----------
async function buildMatrix(s: Scope, g: Gf, soc: boolean) {
  const ph = inList(s.cids), sel = selClause(g, s.cids);
  const prods = g.sel.length
    ? await all<any>(`SELECT p.product, COUNT(*)::int hosts, SUM(${metric(g)})::int findings FROM roll_prod_host p WHERE p.cid IN ${ph} AND ${pairCond(g)}${sel.sql} GROUP BY p.product ORDER BY 3 DESC, 2 DESC, 1`, ...s.cids, ...sel.args)
    : await all<any>(`SELECT x.product, SUM(x.${cellCol(g, "h")})::int hosts, SUM(x.${cellCol(g, "f")})::int findings FROM roll_prod x WHERE x.cid IN ${ph} AND x.${cellCol(g, "h")} > 0 GROUP BY x.product ORDER BY 3 DESC, 2 DESC, 1`, ...s.cids);
  const rows = prods.slice(0, 12), rest = prods.slice(12);
  const d = dimRows(g.by, s.cids);
  const cols = rows.length ? await all<any>(
    `SELECT dd.dim_id, COUNT(DISTINCT p.aid)::int hosts, SUM(${metric(g)})::int total FROM roll_prod_host p JOIN (${d.sql}) dd ON dd.aid = p.aid WHERE p.cid IN ${ph} AND p.product = ANY(?::text[]) AND ${pairCond(g)} GROUP BY dd.dim_id`, ...d.args, ...s.cids, rows.map((r) => r.product) as any) : [];
  cols.sort((a, b) => b.hosts - a.hosts || b.total - a.total || nameOrder.compare(a.dim_id, b.dim_id));
  const shown = cols.slice(0, 8);
  const cells = rows.length && shown.length ? await all<any>(
    `SELECT product, dim_id, ${cellCol(g, "h")} AS n FROM roll_prod_dim WHERE cid IN ${ph} AND dim = ? AND product = ANY(?::text[]) AND dim_id = ANY(?::text[])`, ...s.cids, g.by, rows.map((r) => r.product) as any, shown.map((x) => x.dim_id) as any) : [];
  const fx = rows.length ? await all<any>(`SELECT DISTINCT ON (product) product, fix_id FROM roll_fix WHERE cid IN ${ph} AND product = ANY(?::text[]) ORDER BY product, p1 DESC, fix_id`, ...s.cids, rows.map((r) => r.product) as any) : [];
  const names = await titles(fx.map((f) => f.fix_id));
  const fixOf = new Map(fx.map((f) => [f.product, { id: String(f.fix_id), title: names.get(f.fix_id) ?? null }]));
  const tot = (await get<{ hosts: number }>(`SELECT COUNT(*)::int hosts FROM roll_host p WHERE p.cid IN ${ph} AND p.src = 'endpoint' AND ${hostCond(g)}${sel.sql}`, ...s.cids, ...sel.args))!;
  return {
    lens: "matrix", by: g.by, tier: g.tiers, totals: { hosts: tot.hosts, findings: prods.reduce((a, r) => a + r.findings, 0), products: prods.length },
    cols: shown.map((x) => ({ id: x.dim_id, label: x.dim_id, hosts: x.hosts, total: x.total })), colOther: { count: Math.max(0, cols.length - shown.length), total: cols.slice(8).reduce((a, x) => a + x.total, 0) },
    rows: rows.map((r) => ({ id: r.product, label: r.product, hosts: r.hosts, findings: r.findings, fix: fixOf.get(r.product) ?? null, cells: shown.map((x) => cells.find((c) => c.product === r.product && c.dim_id === x.dim_id)?.n ?? 0) })),
    rowsOther: nodeOther(rest), completeness: await completeness(s, soc),
  };
}

// ---------- lens = focus ----------
async function hostInfo(s: Scope, aid: string) {
  return (await all<any>(`SELECT cid, aid, hostname, COALESCE(os_version, platform) os, groups FROM (SELECT cid, aid, hostname, os_version, platform, groups FROM hosts WHERE cid IN ${inList(s.cids)} AND aid = ?
    UNION ALL SELECT cid, aid, hostname, NULL, platform, '{}' FROM roll_host WHERE cid IN ${inList(s.cids)} AND src = 'endpoint' AND aid = ?) x LIMIT 1`, ...s.cids, aid, ...s.cids, aid))[0];
}
async function buildFocus(c: Ctx, s: Scope, g: Gf, soc: boolean) {
  const type = c.query.get("type") ?? bad("type"), id = text(c, "id", 300);
  if (!["fix", "product", "cve", "host"].includes(type) || !id) bad("type or id");
  const ph = inList(s.cids), sel = selClause(g, s.cids);
  const notFound = () => new HttpError(404, "Not found");
  if (type === "fix") {
    if (!/^\d{1,16}$/.test(id)) throw notFound();
    const fid = Number(id);
    const agg = (await all<any>(`SELECT p.fix_id, COUNT(*)::int hosts, COALESCE(SUM(${metric(g)}), 0)::int findings, COALESCE(SUM(p.p1), 0)::int p1, (COUNT(*) FILTER (WHERE p.inet))::int inet FROM roll_fix_host p WHERE p.cid IN ${ph} AND p.fix_id = ? AND ${pairCond(g)}${sel.sql} GROUP BY p.fix_id`, ...s.cids, fid, ...sel.args))[0];
    if (!agg) throw notFound();
    const fx = (await all<any>(`SELECT MAX(product) product, MAX(cves) cves, MAX(kev_cves) kev_cves, MIN(rank) rank, MAX(exprt_lvl) lvl FROM roll_fix WHERE cid IN ${ph} AND fix_id = ?`, ...s.cids, fid))[0];
    const names = await titles([fid]);
    const cves = await all<any>(
      `SELECT fc.cve_id, SUM(fc.hosts)::int n, MIN(fc.tier) tier, MAX(fc.kev) kev, MIN(c.rank) rank FROM roll_fix_cve fc LEFT JOIN roll_cve c ON c.cid = fc.cid AND c.src = 'endpoint' AND c.cve_id = fc.cve_id
       WHERE fc.cid IN ${ph} AND fc.fix_id = ? AND fc.tier <= ? ${g.set === "k" ? "AND fc.kev = 1" : ""} GROUP BY fc.cve_id ORDER BY MIN(fc.tier), MAX(fc.kev) DESC, 2 DESC, 1`, ...s.cids, fid, g.set === "1" || g.set === "k" ? 1 : 2);
    const right = await rightSide(s, g, [fid], "fix");
    return { lens: "focus", type, center: { id, label: names.get(fid) ?? fx?.product ?? null, sub: fx?.product ?? null, hosts: agg.hosts, findings: agg.findings, cves: fx?.cves ?? 0, kev: (fx?.kev_cves ?? 0) > 0, inetHosts: agg.inet, sev: sevOf(fx?.rank ?? null), exprt: EXPRT[fx?.lvl ?? 0], tier: agg.p1 > 0 ? "P1" : "P2" },
      left: cves.slice(0, 12).map((r) => ({ kind: "cve", id: r.cve_id, label: r.cve_id, sub: null, n: r.n, sev: sevOf(r.rank), kev: !!r.kev })), leftOther: { count: Math.max(0, cves.length - 12), n: cves.slice(12).reduce((a, r) => a + r.n, 0) },
      mode: right.mode, right: right.right, rightOther: right.rightOther, links: right.links, totals: { hosts: agg.hosts }, completeness: await completeness(s, soc) };
  }
  if (type === "product") {
    const agg = (await all<any>(`SELECT COUNT(*)::int hosts, COALESCE(SUM(${metric(g)}), 0)::int findings, (COUNT(*) FILTER (WHERE p.inet))::int inet FROM roll_prod_host p WHERE p.cid IN ${ph} AND p.product = ? AND ${pairCond(g)}${sel.sql}`, ...s.cids, id, ...sel.args))[0];
    if (!agg || !agg.hosts) throw notFound();
    const cves = await all<any>(`SELECT cve_id, SUM(hosts)::int n, MIN(tier) tier, MAX(kev) kev, MIN(rank) rank FROM roll_cve WHERE cid IN ${ph} AND src = 'endpoint' AND position(? in COALESCE(products, product, '')) > 0 AND tier <= ? ${g.set === "k" ? "AND kev = 1" : ""} GROUP BY cve_id ORDER BY MIN(tier), MAX(kev) DESC, 2 DESC, 1`, ...s.cids, id, g.set === "12" ? 2 : 1);
    const right = await rightSide(s, g, [id], "product");
    return { lens: "focus", type, center: { id, label: id, sub: null, hosts: agg.hosts, findings: agg.findings, cves: cves.length, kev: cves.some((r) => r.kev), inetHosts: agg.inet, sev: sevOf(cves.length ? Math.min(...cves.map((r) => r.rank)) : null), tier: cves.some((r) => r.tier === 1) ? "P1" : "P2" },
      left: cves.slice(0, 12).map((r) => ({ kind: "cve", id: r.cve_id, label: r.cve_id, sub: null, n: r.n, sev: sevOf(r.rank), kev: !!r.kev })), leftOther: { count: Math.max(0, cves.length - 12), n: cves.slice(12).reduce((a, r) => a + r.n, 0) },
      mode: right.mode, right: right.right, rightOther: right.rightOther, links: right.links, totals: { hosts: agg.hosts }, completeness: await completeness(s, soc) };
  }
  if (type === "cve") {
    const cve = id.toUpperCase();
    const row = (await all<any>(`SELECT MIN(tier) tier, MIN(rank) rank, MAX(exprt_lvl) lvl, MAX(kev) kev, SUM(hosts)::int hosts, SUM(findings)::int findings, SUM(inet)::int inet, MAX(product) product FROM roll_cve WHERE cid IN ${ph} AND src = 'endpoint' AND cve_id = ?`, ...s.cids, cve))[0];
    if (!row || !row.hosts) throw notFound();
    const fixes = await all<any>(`SELECT fc.fix_id, SUM(fc.hosts)::int n, MAX(fc.kev) kev FROM roll_fix_cve fc WHERE fc.cid IN ${ph} AND fc.cve_id = ? GROUP BY fc.fix_id ORDER BY 2 DESC, 1`, ...s.cids, cve);
    const names = await titles(fixes.slice(0, 12).map((f) => f.fix_id));
    const d = dimRows(g.by, s.cids);
    const selF = selClause(g, s.cids, "f");
    const groups = g.sel.length ? [] : await all<any>(`SELECT dd.dim_id, COUNT(DISTINCT f.aid)::int hosts FROM findings_t f JOIN (${d.sql}) dd ON dd.aid = f.aid WHERE f.cid IN ${ph} AND f.cve_id = ? AND f.suppressed = 0 AND (f.provider IS NULL OR f.provider NOT ILIKE '%EASM%')${g.inet ? " AND f.internet_exposure = 'Yes'" : ""} GROUP BY dd.dim_id`, ...d.args, ...s.cids, cve);
    groups.sort((a, b) => b.hosts - a.hosts || nameOrder.compare(a.dim_id, b.dim_id));
    let right: any = { mode: "dim", right: groups.slice(0, 8).map((x) => ({ id: x.dim_id, label: x.dim_id, hosts: x.hosts, total: x.hosts })), rightOther: { count: Math.max(0, groups.length - 8), hosts: 0, total: groups.slice(8).reduce((a, x) => a + x.hosts, 0) } };
    if (g.sel.length) {
      const hosts = await all<any>(`SELECT f.aid, COUNT(*)::int n, MAX(f.hostname) hostname, MAX(f.os_version) os FROM findings_t f WHERE f.cid IN ${ph} AND f.cve_id = ? AND f.suppressed = 0${selF.sql} GROUP BY f.aid ORDER BY 2 DESC, 1 LIMIT 12`, ...s.cids, cve, ...selF.args);
      right = { mode: "host", right: hosts.map((h) => ({ id: h.aid, label: h.hostname ?? h.aid.slice(0, 8), sub: h.os, n: h.n, inet: false })), rightOther: { count: 0, total: 0 } };
    }
    return { lens: "focus", type, center: { id: cve, label: cve, sub: row.product, hosts: row.hosts, findings: row.findings, cves: 1, kev: !!row.kev, inetHosts: row.inet, sev: sevOf(row.rank), exprt: EXPRT[row.lvl], tier: `P${row.tier}` },
      left: fixes.slice(0, 12).map((f) => ({ kind: "fix", id: String(f.fix_id), label: names.get(f.fix_id) ?? null, sub: null, n: f.n, kev: !!f.kev })), leftOther: { count: Math.max(0, fixes.length - 12), n: fixes.slice(12).reduce((a, f) => a + f.n, 0) },
      ...right, links: [], totals: { hosts: row.hosts }, completeness: await completeness(s, soc) };
  }
  // host
  const h = await hostInfo(s, id);
  if (!h) throw notFound();
  const fixes = await all<any>(`SELECT p.fix_id, p.p1, p.p2, p.kev, p.findings FROM roll_fix_host p WHERE p.cid = ? AND p.aid = ? AND ${pairCond({ ...g, inet: false })} ORDER BY ${metric(g)} DESC, p.fix_id`, h.cid, id);
  const names = await titles(fixes.slice(0, 12).map((f) => f.fix_id));
  const roll = (await get<any>(`SELECT p1, p2, kev_cves, inet, rank, fixes FROM roll_host WHERE cid = ? AND aid = ? AND src = 'endpoint'`, h.cid, id));
  const dimIds = DIMS.length && g.by === "group" ? (h.groups as string[]) : [];
  const counts = dimIds.length ? new Map((await all<any>(`SELECT dim_id, hosts FROM roll_dim WHERE cid = ? AND dim = 'group' AND dim_id = ANY(?::text[])`, h.cid, dimIds as any)).map((r) => [r.dim_id, r.hosts])) : new Map();
  return { lens: "focus", type, center: { id, label: h.hostname ?? id.slice(0, 8), sub: h.os, hosts: 1, findings: (roll?.p1 ?? 0) + (roll?.p2 ?? 0), cves: roll?.fixes ?? 0, kev: (roll?.kev_cves ?? 0) > 0, inetHosts: roll?.inet ? 1 : 0, sev: sevOf(roll?.rank ?? null), tier: (roll?.p1 ?? 0) > 0 ? "P1" : roll?.p2 ? "P2" : null },
    left: fixes.slice(0, 12).map((f) => ({ kind: "fix", id: String(f.fix_id), label: names.get(f.fix_id) ?? null, sub: null, n: f.findings, kev: f.kev > 0 })), leftOther: { count: Math.max(0, fixes.length - 12), n: fixes.slice(12).reduce((a, f) => a + f.findings, 0) },
    mode: "dim", right: dimIds.slice(0, 8).map((d) => ({ id: d, label: d, hosts: counts.get(d) ?? 0, total: counts.get(d) ?? 0 })), rightOther: { count: Math.max(0, dimIds.length - 8), total: 0 }, links: [], totals: { hosts: 1 }, completeness: await completeness(s, soc) };
}

// ---------- the routes ----------
graphLens.handler = async (c: Ctx) => {
  const s = await tenantScope(c, "graph2");
  const soc = isSoc(c.user!.role);
  const lens = c.query.get("lens");
  if (lens !== "fix" && lens !== "matrix" && lens !== "focus") bad("lens");
  const g = await parseFilters(c, s);
  return cached(cacheKey(c, "graph", s, soc), s.cids, () => (lens === "fix" ? buildFixLens(s, g, soc) : lens === "matrix" ? buildMatrix(s, g, soc) : buildFocus(c, s, g, soc)));
};

route("GET", "/api/exposure/graph/meta", async (c) => {
  const s = await tenantScope(c, "graph-meta");
  const soc = isSoc(c.user!.role);
  return cached(cacheKey(c, "graphmeta", s, soc), s.cids, async () => {
    const rows = s.cids.length ? await all<{ dim: Dim; dim_id: string; hosts: number }>(`SELECT dim, dim_id, SUM(hosts)::int hosts FROM roll_dim WHERE cid IN ${inList(s.cids)} GROUP BY dim, dim_id`, ...s.cids) : [];
    const list = (d: Dim) => rows.filter((r) => r.dim === d).map((r) => ({ id: r.dim_id, label: r.dim_id, hosts: r.hosts })).sort((a, b) => nameOrder.compare(a.label, b.label));
    const t = (await get<any>(`SELECT COALESCE(SUM(p1), 0)::int p1, COALESCE(SUM(p2), 0)::int p2, COALESCE(SUM(p3), 0)::int p3 FROM roll_host WHERE cid IN ${inList(s.cids)} AND src = 'endpoint'`, ...s.cids))!;
    const comp = await completeness(s, soc);
    return { dims: { group: rows.some((r) => r.dim === "group"), os: rows.some((r) => r.dim === "os"), site: rows.some((r) => r.dim === "site") }, groups: list("group"), os: list("os"), sites: list("site"),
      tiers: { P1: t.p1 > 0, P2: t.p2 > 0, P3: t.p3 > 0 }, held: comp.coverage?.held ?? null, falconTotal: comp.coverage?.falconTotal ?? null, completeness: comp };
  });
});

route("GET", "/api/exposure/graph/search", async (c) => {
  const s = await tenantScope(c, "graph-search");
  const q = text(c, "q", 100);
  if (q.length < 2) return { items: [] };
  const like = `%${esc(q)}%`, ph = inList(s.cids), items: { kind: string; id: string; label: string | null; sub: string | null }[] = [];
  if (!s.cids.length) return { items };
  for (const r of await all<any>(`SELECT cve_id, MAX(product) product FROM roll_cve WHERE cid IN ${ph} AND src = 'endpoint' AND cve_id ILIKE ? ESCAPE '\\' GROUP BY cve_id ORDER BY MIN(tier), SUM(hosts) DESC, 1 LIMIT 4`, ...s.cids, like)) items.push({ kind: "cve", id: r.cve_id, label: r.cve_id, sub: r.product });
  for (const r of await all<any>(`SELECT f.fix_id, rs.remediation, MAX(f.product) product FROM roll_fix f JOIN rem_sets rs ON rs.id = f.fix_id WHERE f.cid IN ${ph} AND rs.remediation ILIKE ? ESCAPE '\\' GROUP BY f.fix_id, rs.remediation ORDER BY SUM(f.p1) DESC, 1 LIMIT 4`, ...s.cids, like)) items.push({ kind: "fix", id: String(r.fix_id), label: fixTitle(r.remediation), sub: r.product });
  for (const r of await all<any>(`SELECT product, SUM(f1)::int p1 FROM roll_prod WHERE cid IN ${ph} AND product ILIKE ? ESCAPE '\\' GROUP BY product ORDER BY 2 DESC, 1 LIMIT 4`, ...s.cids, like)) items.push({ kind: "product", id: r.product, label: r.product, sub: null });
  const hosts = await all<any>(`SELECT DISTINCT ON (aid) aid, hostname, COALESCE(os_version, platform) os FROM (SELECT aid, hostname, os_version, platform FROM hosts WHERE cid IN ${ph} UNION ALL SELECT aid, hostname, NULL, platform FROM roll_host WHERE cid IN ${ph} AND src = 'endpoint') x WHERE hostname ILIKE ? ESCAPE '\\' ORDER BY aid LIMIT 200`, ...s.cids, ...s.cids, like);
  hosts.sort((a, b) => nameOrder.compare(a.hostname ?? "", b.hostname ?? "")); // Thai dictionary order
  for (const r of hosts.slice(0, 4)) items.push({ kind: "host", id: r.aid, label: r.hostname, sub: r.os });
  return { items };
});

route("GET", "/api/exposure/graph/list", async (c) => {
  const s = await tenantScope(c, "graph-list");
  const soc = isSoc(c.user!.role);
  const kind = c.query.get("kind") ?? "";
  if (!["fix", "product", "host", "hostCves"].includes(kind)) bad("kind");
  const g = await parseFilters(c, s);
  const page = Math.max(1, Number(c.query.get("page")) || 1), size = 50, offset = (page - 1) * size;
  return cached(cacheKey(c, "graphlist", s, soc), s.cids, async () => {
    const ph = inList(s.cids), sel = selClause(g, s.cids);
    if (kind === "fix") {
      const r = await fixNodes(s, g);
      const part = r.rows.slice(offset, offset + size), names = await titles(part.map((x) => x.fix_id));
      return { total: r.rows.length, page, pageSize: size, rows: part.map((x) => ({ id: String(x.fix_id), label: names.get(x.fix_id) ?? null, hosts: x.hosts, findings: x.findings, p1: x.p1, kev: x.kev, inet: x.inet })) };
    }
    if (kind === "product") {
      const rows = g.sel.length
        ? await all<any>(`SELECT p.product, COUNT(*)::int hosts, SUM(${metric(g)})::int findings, SUM(p.p1)::int p1, SUM(p.kev)::int kev, (COUNT(*) FILTER (WHERE p.inet))::int inet FROM roll_prod_host p WHERE p.cid IN ${ph} AND ${pairCond(g)}${sel.sql} GROUP BY p.product ORDER BY 3 DESC, 2 DESC, 1`, ...s.cids, ...sel.args)
        : await all<any>(`SELECT x.product, SUM(x.${cellCol(g, "h")})::int hosts, SUM(x.${cellCol(g, "f")})::int findings, SUM(x.f${g.inet ? "i" : ""}1)::int p1, SUM(x.f${g.inet ? "i" : ""}k)::int kev, SUM(x.hi${g.set})::int inet FROM roll_prod x WHERE x.cid IN ${ph} AND x.${cellCol(g, "h")} > 0 GROUP BY x.product ORDER BY 3 DESC, 2 DESC, 1`, ...s.cids);
      return { total: rows.length, page, pageSize: size, rows: rows.slice(offset, offset + size).map((x) => ({ id: x.product, label: x.product, hosts: x.hosts, findings: x.findings, p1: x.p1, kev: x.kev, inet: x.inet })) };
    }
    if (kind === "hostCves") {
      const aid = text(c, "id");
      const h = await hostInfo(s, aid);
      if (!h) throw new HttpError(404, "Not found");
      const rows = await all<any>(
        `SELECT f.cve_id, MIN(CASE WHEN (cv.cisa_kev = 1 OR EXISTS (SELECT 1 FROM kev k WHERE k.cve_id = f.cve_id)) OR f.exploit_status >= 60 OR (f.severity = 'CRITICAL' AND f.exprt = 'CRITICAL') THEN 1
           WHEN f.severity = 'CRITICAL' OR f.exprt IN ('HIGH', 'CRITICAL') OR f.exploit_status = 30 THEN 2 ELSE 3 END) tier, MIN(CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END) rank,
           MAX(f.base_score) score, MAX(f.exploit_status) ex, BOOL_OR(cv.cisa_kev = 1) kev
         FROM findings_t f LEFT JOIN cves cv ON cv.id = f.cve_id WHERE f.cid = ? AND f.aid = ? AND f.suppressed = 0 GROUP BY f.cve_id ORDER BY 2, 3, 4 DESC NULLS LAST, 1`, h.cid, aid);
      return { total: rows.length, page, pageSize: size, rows: rows.slice(offset, offset + size).map((r) => ({ id: r.cve_id, label: r.cve_id, tier: `P${r.tier}`, sev: SEV[r.rank], score: r.score, kev: !!r.kev })) };
    }
    // kind = host: the hosts of one entity (type + id), or of the whole filter when none is given
    const type = c.query.get("type"), id = text(c, "id", 300);
    let from = "roll_fix_host", key = "";
    const args: Arg[] = [];
    if (type === "fix") { if (!/^\d{1,16}$/.test(id)) throw new HttpError(404, "Not found"); key = "AND p.fix_id = ?"; args.push(Number(id)); }
    else if (type === "product") { from = "roll_prod_host"; key = "AND p.product = ?"; args.push(id); }
    else if (type) bad("type");
    const rows = await all<any>(`SELECT p.cid, p.aid, SUM(${metric(g)})::int n, SUM(p.kev)::int kev, SUM(p.p1)::int p1, BOOL_OR(p.inet) inet FROM ${from} p WHERE p.cid IN ${ph} AND ${pairCond(g)} ${key}${sel.sql} GROUP BY p.cid, p.aid`, ...s.cids, ...args, ...sel.args);
    const ids = rows.map((r) => r.aid);
    const info = new Map((ids.length ? await all<any>(`SELECT aid, hostname, groups, COALESCE(os_version, platform) os FROM (SELECT aid, hostname, groups, os_version, platform FROM hosts WHERE cid IN ${ph} UNION ALL SELECT aid, hostname, '{}', NULL, platform FROM roll_host WHERE cid IN ${ph} AND src = 'endpoint') x WHERE aid = ANY(?::text[])`, ...s.cids, ...s.cids, ids as any) : []).map((r) => [r.aid, r]));
    const rk = new Map((ids.length ? await all<any>(`SELECT aid, rank FROM roll_host WHERE cid IN ${ph} AND src = 'endpoint' AND aid = ANY(?::text[])`, ...s.cids, ids as any) : []).map((r) => [r.aid, r.rank]));
    rows.sort((a, b) => b.n - a.n || nameOrder.compare(info.get(a.aid)?.hostname ?? "", info.get(b.aid)?.hostname ?? "") || (a.aid < b.aid ? -1 : 1));
    let watched: Set<string> | null = null;
    try { watched = await watchedSet(s.tenantId); } catch { watched = null; }
    return { total: rows.length, page, pageSize: size, rows: rows.slice(offset, offset + size).map((r) => ({ aid: r.aid, ...(soc ? { cid: r.cid } : {}), name: info.get(r.aid)?.hostname ?? r.aid.slice(0, 8), group: info.get(r.aid)?.groups?.[0] ?? null, os: info.get(r.aid)?.os ?? null, inet: r.inet, n: r.n, kev: r.kev, p1: r.p1, sev: sevOf(rk.get(r.aid) ?? null), watched: watched ? watched.has(r.aid) : null })) };
  });
});

/** After a sync the default lens (P1, no filters) of the organization that owns the CID is computed, so the first page view is a cache hit. */
warmers.push(async (cid) => {
  const t = await get<{ id: string; name: string }>("SELECT t.id, t.name FROM tenant_cids x JOIN tenants t ON t.id = x.tenant_id WHERE x.cid = ?", cid);
  if (!t) return;
  const cids = (await all<{ cid: string }>("SELECT cid FROM tenant_cids WHERE tenant_id = ? ORDER BY cid", t.id)).map((r) => r.cid);
  const s: Scope = { tenantId: t.id, tenantName: t.name, cids };
  const none = new URLSearchParams([["lens", "fix"]]);
  const fake = { query: none } as Ctx;
  const g = await parseFilters(fake, s);
  for (const soc of [false, true]) await cached(cacheKey(fake, "graph", s, soc), cids, () => buildFixLens(s, g, soc));
});
