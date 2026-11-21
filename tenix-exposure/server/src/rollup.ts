// Per-CID rollups of the findings: what every customer page reads at 17 million rows instead of grouping them on each request.
// refreshRollups() rebuilds the rows of one CID from findings_t in one transaction (readers see the old or the new numbers, never a mix).
// Every number is exactly what the same GROUP BY over the rows gives (tests compare them); only the age buckets move with the clock, until the next refresh.
//
// Tiers (design-spec 4.1), computed here on every finding, never stored on the 17M rows (the KEV list changes on its own):
//   P1 = in CISA KEV, or exploit status >= 60, or severity CRITICAL and ExPRT CRITICAL
//   P2 = not P1 and (severity CRITICAL, or ExPRT HIGH/CRITICAL, or exploit status 30)        P3 = the rest
// Suppressed findings are in no rollup. Falcon EASM findings (src = 'external') are in the older tables under their own src and in none of the fix / graph tables.
import { all, get, insertMany, now, pool, run, tx } from "./db.ts";

export const RANK_SQL = "CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END";
const SRC = "CASE WHEN provider ILIKE '%EASM%' THEN 'external' ELSE 'endpoint' END";
const INET = "COALESCE(internet_exposure = 'Yes' OR provider ILIKE '%EASM%', false)";
const ENDPOINT = "(provider IS NULL OR provider NOT ILIKE '%EASM%')";
const EXPRT_LVL = "CASE UPPER(exprt) WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END";
/** The findings of one CID with `tier` (1..3) and `kevf` (CVE is in CISA's list) added; the one `?` is the CID. Suppressed rows are left out. */
const KEV = "(f.cve_id IN (SELECT id FROM cves WHERE cisa_kev = 1) OR f.cve_id IN (SELECT cve_id FROM kev))";
export const baseSql = (cid = "?") => `(SELECT y.*, CASE WHEN y.kevf OR y.exploit_status >= 60 OR (y.severity = 'CRITICAL' AND y.exprt = 'CRITICAL') THEN 1
    WHEN y.severity = 'CRITICAL' OR y.exprt IN ('HIGH', 'CRITICAL') OR y.exploit_status = 30 THEN 2 ELSE 3 END AS tier
  FROM (SELECT f.*, ${KEV} AS kevf FROM findings_t f WHERE f.cid = ${cid} AND f.suppressed = 0) y) x`;
const BASE = baseSql();
const lit = (s: string) => `'${s.replace(/'/g, "''")}'`;

export interface Held { held: number; priority: number; hosts: number; cves: number }

/** One of the aggregate queries, on its own connection: they run side by side, so the big table is read once (PostgreSQL shares a sequential scan between queries that start together)
 *  and every core is used (parallel workers are off, see db.ts). The answers are a few thousand rows. */
async function aggregate<T>(sql: string, ...p: (string | number)[]): Promise<T[]> {
  const c = await pool.connect();
  try {
    await c.query("BEGIN READ ONLY");
    await c.query("SET LOCAL work_mem = '256MB'");
    let i = 0;
    const r = (await c.query(sql.replace(/\?/g, () => `$${++i}`), p)).rows as T[];
    await c.query("COMMIT");
    return r;
  } catch (e) { await c.query("ROLLBACK").catch(() => {}); throw e; } finally { c.release(); }
}
/** A staging table filled on the server (CREATE TABLE AS): the big pair lists never travel through Node. Dropped by the caller. */
async function stage(name: string, sql: string): Promise<void> {
  const c = await pool.connect();
  try { await c.query("SET work_mem = '256MB'"); await c.query(`CREATE UNLOGGED TABLE ${name} AS ${sql}`); } finally { await c.query("RESET work_mem").catch(() => {}); c.release(); }
}
/** At most `n` of the tasks at a time (the pool has 10 connections and the pages need some). */
async function limited<T>(n: number, tasks: (() => Promise<T>)[]): Promise<T[]> {
  const out: T[] = new Array(tasks.length); let next = 0;
  await Promise.all(Array.from({ length: Math.min(n, tasks.length) }, async () => { for (;;) { const i = next++; if (i >= tasks.length) return; out[i] = await tasks[i](); } }));
  return out;
}

const ROLL_TABLES = ["roll_cve", "roll_host", "roll_sev", "roll_age", "roll_fix", "roll_fix_host", "roll_fix_cve", "roll_prod_host", "roll_p1_prod", "roll_prod"];
const DIM_TABLES = ["roll_fix_dim", "roll_prod_dim", "roll_dim"];
/** Every per-CID table of this file, for the code that removes a CID or an organization. */
export const ROLLUP_CID_TABLES = [...ROLL_TABLES, ...DIM_TABLES, "roll_soft", "hist_day", "hosts", "hosts_sync"];
const PRODUCTS_KEPT = 300;
/** Falcon writes a product as name + version ("Google Chrome 120.0"): the version starts at the first token that begins with a digit (or v + digit). */
const VERSION_TAIL = String.raw`'\s+[vV]?[0-9].*$'`;

/** The host dimensions of the graph: a host group (many per host), the site, and the OS. A host without an inventory row still has its OS (from its findings). */
const hostDims = (cid: string) => `SELECT aid, 'group' AS dim, g AS dim_id FROM hosts, unnest(groups) g WHERE cid = ${cid} AND g <> ''
  UNION ALL SELECT aid, 'site', site FROM hosts WHERE cid = ${cid} AND COALESCE(site, '') <> ''
  UNION ALL SELECT aid, 'os', COALESCE(NULLIF(os_version, ''), NULLIF(platform, ''), 'unknown') FROM hosts WHERE cid = ${cid}
  UNION ALL SELECT r.aid, 'os', COALESCE(NULLIF(r.platform, ''), 'unknown') FROM roll_host r WHERE r.cid = ${cid} AND r.src = 'endpoint' AND NOT EXISTS (SELECT 1 FROM hosts h WHERE h.cid = ${cid} AND h.aid = r.aid)`;
const SET_EXPRS = ["COUNT(*) FILTER (WHERE p.p1 > 0)::int", "COUNT(*) FILTER (WHERE p.p1 > 0 AND p.inet)::int", "COALESCE(SUM(p.p1), 0)::int", "COALESCE(SUM(p.p1) FILTER (WHERE p.inet), 0)::int",
  "COUNT(*) FILTER (WHERE p.p1 + p.p2 > 0)::int", "COUNT(*) FILTER (WHERE p.p1 + p.p2 > 0 AND p.inet)::int", "COALESCE(SUM(p.p1 + p.p2), 0)::int", "COALESCE(SUM(p.p1 + p.p2) FILTER (WHERE p.inet), 0)::int",
  "COUNT(*) FILTER (WHERE p.kev > 0)::int", "COUNT(*) FILTER (WHERE p.kev > 0 AND p.inet)::int", "COALESCE(SUM(p.kev), 0)::int", "COALESCE(SUM(p.kev) FILTER (WHERE p.inet), 0)::int"];
const SET_COLS = SET_EXPRS.join(", ");
const SET_NAMES = "h1, hi1, f1, fi1, h12, hi12, f12, fi12, hk, hik, fk, fik";

/** Rebuilds the graph dimension tables of one CID from the pair tables and the host inventory. Cheap (the pairs are a few hundred thousand rows); runs after every rollup refresh and after every hosts sync. */
export async function refreshDims(cid: string): Promise<void> {
  const L = lit(cid);
  await tx(async () => {
    for (const t of DIM_TABLES) await run(`DELETE FROM ${t} WHERE cid = ?`, cid);
    await run(`INSERT INTO roll_dim (cid, dim, dim_id, hosts) SELECT ${L}, dim, dim_id, COUNT(DISTINCT aid)::int FROM (${hostDims(L)}) hd GROUP BY dim, dim_id`);
    await run(`INSERT INTO roll_fix_dim (cid, dim, dim_id, fix_id, ${SET_NAMES})
               SELECT p.cid, hd.dim, hd.dim_id, p.fix_id, ${SET_COLS} FROM roll_fix_host p JOIN (${hostDims(L)}) hd ON hd.aid = p.aid WHERE p.cid = ${L} GROUP BY p.cid, hd.dim, hd.dim_id, p.fix_id`);
    await run(`INSERT INTO roll_prod_dim (cid, dim, dim_id, product, ${SET_NAMES})
               SELECT p.cid, hd.dim, hd.dim_id, p.product, ${SET_COLS} FROM roll_prod_host p JOIN (${hostDims(L)}) hd ON hd.aid = p.aid WHERE p.cid = ${L} GROUP BY p.cid, hd.dim, hd.dim_id, p.product`);
  });
}

/** P1 and KEV CVEs per Discover software item (type, vendor, name), matched by product name: an equi-join on the lower-cased name, with and without the version. Heuristic (the two sources name things alike, not identically);
 *  runs after every rollup refresh and after every software sync. */
export async function refreshSoftware(cid: string): Promise<void> {
  await tx(async () => {
    await run("DELETE FROM roll_soft WHERE cid = ?", cid);
    await run(`INSERT INTO roll_soft (cid, type, vendor, name, p1_cves, kev_cves)
               SELECT s.cid, s.type, s.vendor, s.name, COUNT(DISTINCT p.cve_id)::int, (COUNT(DISTINCT p.cve_id) FILTER (WHERE p.kev = 1))::int
               FROM (SELECT DISTINCT cid, type, vendor, name FROM software WHERE cid = ?) s JOIN roll_p1_prod p ON p.cid = s.cid AND p.key = lower(s.name) GROUP BY s.cid, s.type, s.vendor, s.name`, cid);
  });
}

/** Rebuilds the rollups of one CID from findings_t. The reads run side by side; the swap is one short transaction (readers see the old or the new numbers, never a mix). */
export async function refreshRollups(cid: string, keep?: readonly string[]): Promise<Held> {
  const t = Date.now(), DAY = 86400_000;
  const L = lit(cid), B = baseSql(L);
  const tag = `stg_${cid.replace(/[^0-9a-z]/gi, "").slice(0, 8).toLowerCase()}_${Math.random().toString(36).slice(2, 8)}`;
  const stg = { fh: `${tag}_fh`, fc: `${tag}_fc`, fx: `${tag}_fx`, ph: `${tag}_ph`, pp: `${tag}_pp`, kv: `${tag}_kv` };
  const P12 = `x.tier <= 2 AND (x.provider IS NULL OR x.provider NOT ILIKE '%EASM%')`;
  try {
    const [cves, products, hosts, sev, age] = (await limited<any[]>(5, [
      () => aggregate<any>(`SELECT ${SRC} AS src, cve_id, MIN(${RANK_SQL}) AS rank, MAX(base_score) AS base_score, MAX(exprt) AS exprt, MAX(exploit_status) AS exploit_status, MAX(kind) AS kind, MAX(product) AS product,
             COUNT(DISTINCT aid) AS hosts, COUNT(*) AS findings, COUNT(*) FILTER (WHERE severity = 'CRITICAL' OR exprt = 'CRITICAL' OR exploit_status >= 60) AS pri,
             MAX(CASE UPPER(exprt) WHEN 'CRITICAL' THEN 3 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 1 ELSE 0 END) AS exprt_rank, COUNT(DISTINCT CASE WHEN ${INET} THEN aid END) AS inet,
             MIN(tier) AS tier, COUNT(*) FILTER (WHERE tier = 1) AS p1, COUNT(*) FILTER (WHERE tier = 2) AS p2, BOOL_OR(kevf)::int AS kev, MIN(first_seen) AS first_seen, MAX(${EXPRT_LVL}) AS exprt_lvl
      FROM ${BASE} GROUP BY 1, 2`, cid),
      // what products a CVE is on (the list page searches them): the distinct (CVE, product) pairs first, then one string per CVE
      () => aggregate<any>(`SELECT src, cve_id, LEFT(STRING_AGG(product, ' | '), 4000) AS products FROM (SELECT DISTINCT ${SRC} AS src, cve_id, product FROM ${BASE} WHERE product IS NOT NULL) d GROUP BY src, cve_id`, cid),
      () => aggregate<any>(`SELECT ${SRC} AS src, aid, MAX(hostname) AS hostname, MAX(platform) AS platform, MAX(local_ip) AS local_ip, MAX(external_ip) AS external_ip, MAX(provider) AS provider, COUNT(DISTINCT cve_id) AS cves,
             COUNT(DISTINCT CASE WHEN severity = 'CRITICAL' THEN cve_id END) AS critical, COUNT(DISTINCT CASE WHEN severity = 'HIGH' THEN cve_id END) AS high, COUNT(DISTINCT CASE WHEN severity = 'MEDIUM' THEN cve_id END) AS medium,
             COUNT(DISTINCT CASE WHEN exploit_status >= 60 THEN cve_id END) AS exploited, MIN(${RANK_SQL}) AS rank, COUNT(*) AS findings, COALESCE(BOOL_OR(${INET}), false) AS inet,
             COUNT(*) FILTER (WHERE tier = 1) AS p1, COUNT(*) FILTER (WHERE tier = 2) AS p2, COUNT(*) FILTER (WHERE tier = 3) AS p3, MIN(tier) AS tier
      FROM ${BASE} GROUP BY 1, 2`, cid),
      () => aggregate<any>(`SELECT ${SRC} AS src, ${INET} AS inet, severity, COUNT(*) AS n FROM ${BASE} GROUP BY 1, 2, 3`, cid),
      () => aggregate<any>(`SELECT ${SRC} AS src, CASE WHEN first_seen IS NULL THEN 'unknown' WHEN first_seen >= ? THEN 'd30' WHEN first_seen >= ? THEN 'd90' WHEN first_seen >= ? THEN 'd180' ELSE 'older' END AS bucket, COUNT(*) AS n
      FROM ${BASE} WHERE severity IN ('CRITICAL','HIGH') GROUP BY 1, 2`, t - 30 * DAY, t - 90 * DAY, t - 180 * DAY, cid),
    ]));
    // fix / product pairs, built on the server (P1 and P2 endpoint findings only)
    await limited(6, [
      () => stage(stg.fh, `SELECT COALESCE(rem_set, 0)::bigint AS fix_id, aid, COUNT(*)::int AS findings, (COUNT(*) FILTER (WHERE tier = 1))::int AS p1, (COUNT(*) FILTER (WHERE tier = 2))::int AS p2,
        (COUNT(*) FILTER (WHERE kevf))::int AS kev, COALESCE(BOOL_OR(${INET}), false) AS inet FROM ${B} WHERE ${P12} GROUP BY 1, 2`),
      () => stage(stg.fc, `SELECT COALESCE(rem_set, 0)::bigint AS fix_id, cve_id, COUNT(DISTINCT aid)::int AS hosts, COUNT(*)::int AS findings, MIN(tier)::smallint AS tier, (BOOL_OR(kevf))::int::smallint AS kev
        FROM ${B} WHERE ${P12} GROUP BY 1, 2`),
      () => stage(stg.fx, `SELECT COALESCE(rem_set, 0)::bigint AS fix_id, MAX(product) AS product, MAX(vendor) AS vendor, MIN(${RANK_SQL})::smallint AS rank, MAX(${EXPRT_LVL})::smallint AS exprt_lvl, MIN(first_seen) AS first_seen
        FROM ${B} WHERE ${P12} GROUP BY 1`),
      () => stage(stg.ph, `WITH b AS MATERIALIZED (SELECT product, aid, tier, kevf, ${INET} AS inet FROM ${B} WHERE ${P12} AND product IS NOT NULL),
        top AS (SELECT product FROM b GROUP BY product ORDER BY COUNT(*) FILTER (WHERE tier = 1) DESC, COUNT(*) DESC, product LIMIT ${PRODUCTS_KEPT})
        SELECT b.product, b.aid, COUNT(*)::int AS findings, (COUNT(*) FILTER (WHERE tier = 1))::int AS p1, (COUNT(*) FILTER (WHERE tier = 2))::int AS p2, (COUNT(*) FILTER (WHERE kevf))::int AS kev, COALESCE(BOOL_OR(b.inet), false) AS inet
        FROM b JOIN top USING (product) GROUP BY b.product, b.aid`),
      () => stage(stg.kv, `SELECT aid, COUNT(DISTINCT cve_id)::int AS n FROM ${B} WHERE kevf AND ${ENDPOINT} GROUP BY aid`),
      () => stage(stg.pp, `SELECT DISTINCT lower(k) AS key, cve_id, kev FROM (
          SELECT product AS k, cve_id, kevf::int::smallint AS kev FROM ${B} WHERE x.tier = 1 AND ${P12.replace("x.tier <= 2 AND ", "")} AND product IS NOT NULL
          UNION ALL SELECT regexp_replace(product, ${VERSION_TAIL}, ''), cve_id, kevf::int::smallint FROM ${B} WHERE x.tier = 1 AND ${P12.replace("x.tier <= 2 AND ", "")} AND product IS NOT NULL) y WHERE k <> ''`),
    ]);
    const prod = new Map(products.map((p) => [`${p.src}|${p.cve_id}`, p.products as string]));
    await tx(async () => {
      for (const x of ROLL_TABLES) await run(`DELETE FROM ${x} WHERE cid = ?`, cid);
      await insertMany("roll_cve", ["cid", "src", "cve_id", "rank", "base_score", "exprt", "exploit_status", "kind", "product", "products", "hosts", "findings", "pri", "exprt_rank", "inet", "tier", "p1", "p2", "kev", "first_seen", "exprt_lvl"],
        cves.map((r) => [cid, r.src, r.cve_id, r.rank, r.base_score, r.exprt, r.exploit_status, r.kind, r.product, prod.get(`${r.src}|${r.cve_id}`) ?? null, r.hosts, r.findings, r.pri, r.exprt_rank, r.inet, r.tier, r.p1, r.p2, r.kev, r.first_seen, r.exprt_lvl]));
      await insertMany("roll_host", ["cid", "src", "aid", "hostname", "platform", "local_ip", "external_ip", "provider", "cves", "critical", "high", "medium", "exploited", "rank", "findings", "inet", "p1", "p2", "p3", "kev_cves", "tier"],
        hosts.map((r) => [cid, r.src, r.aid, r.hostname, r.platform, r.local_ip, r.external_ip, r.provider, r.cves, r.critical, r.high, r.medium, r.exploited, r.rank, r.findings, r.inet, r.p1, r.p2, r.p3, 0, r.tier])); // kev_cves is filled from the staged KEV query below
      await insertMany("roll_sev", ["cid", "src", "inet", "severity", "n"], sev.map((r) => [cid, r.src, r.inet, r.severity, r.n]));
      await insertMany("roll_age", ["cid", "src", "bucket", "n"], age.map((r) => [cid, r.src, r.bucket, r.n]));
      await run("SET LOCAL work_mem = '256MB'");
      await run(`INSERT INTO roll_fix_host SELECT ${L}, fix_id, aid, findings, p1, p2, kev, inet FROM ${stg.fh} ORDER BY fix_id, aid`); // sorted: the primary key is filled in order, not at random
      await run(`INSERT INTO roll_fix_cve SELECT ${L}, fix_id, cve_id, hosts, findings, tier, kev FROM ${stg.fc} ORDER BY fix_id, cve_id`);
      await run(`INSERT INTO roll_p1_prod SELECT ${L}, key, cve_id, kev FROM ${stg.pp} ORDER BY key, cve_id`);
      await run(`INSERT INTO roll_prod_host SELECT ${L}, product, aid, findings, p1, p2, kev, inet FROM ${stg.ph} ORDER BY product, aid`);
      await run(`INSERT INTO roll_prod (cid, product, ${SET_NAMES}) SELECT ${L}, p.product, ${SET_COLS} FROM roll_prod_host p WHERE p.cid = ${L} GROUP BY p.product`);
      await run(`INSERT INTO roll_fix (cid, fix_id, product, vendor, findings, p1, p2, cves, p1_cves, kev_cves, hosts, p1_hosts, inet_hosts, rank, exprt_lvl, first_seen, ${SET_NAMES})
                 SELECT ${L}, fx.fix_id, fx.product, fx.vendor, h.findings, h.p1, h.p2, COALESCE(c.cves, 0), COALESCE(c.p1_cves, 0), COALESCE(c.kev_cves, 0), h.hosts, h.p1_hosts, h.inet_hosts, fx.rank, fx.exprt_lvl, fx.first_seen, h.s1, h.s2, h.s3, h.s4, h.s5, h.s6, h.s7, h.s8, h.s9, h.s10, h.s11, h.s12
                 FROM ${stg.fx} fx
                 JOIN (SELECT p.fix_id, SUM(p.findings)::int findings, SUM(p.p1)::int p1, SUM(p.p2)::int p2, COUNT(*)::int hosts, (COUNT(*) FILTER (WHERE p.p1 > 0))::int p1_hosts, (COUNT(*) FILTER (WHERE p.inet))::int inet_hosts,
                              ${SET_EXPRS.map((x, i) => `${x} AS s${i + 1}`).join(", ")}
                       FROM roll_fix_host p WHERE p.cid = ${L} GROUP BY p.fix_id) h USING (fix_id)
                 LEFT JOIN (SELECT fix_id, COUNT(*)::int cves, (COUNT(*) FILTER (WHERE tier = 1))::int p1_cves, (COUNT(*) FILTER (WHERE kev = 1))::int kev_cves FROM roll_fix_cve WHERE cid = ${L} GROUP BY fix_id) c USING (fix_id)`);
      await run(`UPDATE roll_host h SET kev_cves = k.n FROM ${stg.kv} k WHERE h.cid = ${L} AND h.src = 'endpoint' AND h.aid = k.aid`);
      await run(`UPDATE roll_host h SET fixes = x.n FROM (SELECT aid, COUNT(*)::int n FROM roll_fix_host WHERE cid = ${L} GROUP BY aid) x WHERE h.cid = ${L} AND h.src = 'endpoint' AND h.aid = x.aid`);
      await run("INSERT INTO cid_counts (cid, key, n, as_of) VALUES (?, 'rollupAt', ?, ?) ON CONFLICT (cid, key) DO UPDATE SET n = excluded.n, as_of = excluded.as_of", cid, t, t);
    });
    await refreshDims(cid);
    await refreshSoftware(cid);
  } finally {
    for (const n of Object.values(stg)) await pool.query(`DROP TABLE IF EXISTS ${n}`).catch(() => {});
  }
  await recordHistory(cid).catch((e) => console.error("[history] could not write the daily row:", (e as Error).message));
  return rollupTotals(cid, keep);
}

/** One row per CID per UTC day, written after every rollup refresh and every sync run (the last write of the day stays): P1/P2/P3 held, hosts with P1, and Falcon's exact counts of that moment. */
export async function recordHistory(cid: string): Promise<void> {
  if ((await rollupAt(cid)) === null) return;
  const h = (await get<{ p1: number; p2: number; p3: number; hp1: number; held: number }>(
    `SELECT COALESCE(SUM(p1), 0)::bigint AS p1, COALESCE(SUM(p2), 0)::bigint AS p2, COALESCE(SUM(p3), 0)::bigint AS p3, (COUNT(*) FILTER (WHERE p1 > 0))::bigint AS hp1,
            COALESCE((SELECT SUM(n) FROM roll_sev WHERE cid = ? AND src = 'endpoint'), 0)::bigint AS held FROM roll_host WHERE cid = ? AND src = 'endpoint'`, cid, cid))!;
  const inv = (await get<{ n: number }>("SELECT COUNT(*)::bigint AS n FROM hosts WHERE cid = ?", cid))!.n;
  const hostsTotal = inv || (await get<{ n: number }>("SELECT COUNT(*)::bigint AS n FROM roll_host WHERE cid = ? AND src = 'endpoint'", cid))!.n;
  const c: Record<string, number> = {};
  for (const r of await all<{ key: string; n: number }>("SELECT key, n FROM cid_counts WHERE cid = ?", cid)) c[r.key] = r.n;
  const pick = (k: string) => c[`s_${k}`] ?? c[k] ?? null; // sensor-only Falcon count when we have it
  const sevSum = ["critical", "high", "medium", "low"].every((k) => pick(k) !== null) ? ["critical", "high", "medium", "low"].reduce((a, k) => a + pick(k)!, 0) : null;
  const total = c.s_total ?? c.total ?? null;
  const day = new Date().toISOString().slice(0, 10);
  await run(`INSERT INTO hist_day (cid, day, p1, p2, p3, held, hosts_p1, hosts_total, critical, high, medium, low, "none", kev, exploited, falcon_json, written_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
             ON CONFLICT (cid, day) DO UPDATE SET p1 = excluded.p1, p2 = excluded.p2, p3 = excluded.p3, held = excluded.held, hosts_p1 = excluded.hosts_p1, hosts_total = excluded.hosts_total, critical = excluded.critical, high = excluded.high,
               medium = excluded.medium, low = excluded.low, "none" = excluded."none", kev = excluded.kev, exploited = excluded.exploited, falcon_json = excluded.falcon_json, written_at = excluded.written_at`,
    cid, day, h.p1, h.p2, h.p3, h.held, h.hp1, hostsTotal, pick("critical"), pick("high"), pick("medium"), pick("low"), total !== null && sevSum !== null ? Math.max(0, total - sevSum) : null, pick("kev"), pick("exploited"), JSON.stringify(c), now());
}

/** When the rollups of a CID were last rebuilt (null: never). */
export async function rollupAt(cid: string): Promise<number | null> {
  return (await get<{ n: number }>("SELECT n FROM cid_counts WHERE cid = ? AND key = 'rollupAt'", cid))?.n ?? null;
}

/** What the rollups of a CID add up to (cheap: the rollups are small). priority = the fix-first findings (Critical severity, ExPRT Critical, exploited, or a CVE CISA lists).
 *  held counts the findings of the severities the organization keeps (rows of an unticked severity wait for their purge date and are not part of the scope); without `keep`, all of them. */
export async function rollupTotals(cid: string, keep?: readonly string[]): Promise<Held> {
  return (await get<Held>(
    `SELECT COALESCE((SELECT SUM(n) FROM roll_sev WHERE cid = ? AND (?::text[] IS NULL OR severity = ANY(?::text[]))), 0)::bigint AS held,
            COALESCE((SELECT SUM(r.pri) + COALESCE(SUM(r.findings - r.pri) FILTER (WHERE EXISTS (SELECT 1 FROM cves c WHERE c.id = r.cve_id AND c.cisa_kev = 1)), 0) FROM roll_cve r WHERE r.cid = ?), 0)::bigint AS priority,
            (SELECT COUNT(DISTINCT aid) FROM roll_host WHERE cid = ?)::bigint AS hosts, (SELECT COUNT(DISTINCT cve_id) FROM roll_cve WHERE cid = ?)::bigint AS cves`, cid, (keep ?? null) as any, (keep ?? null) as any, cid, cid, cid))!;
}

/** The headline numbers of one organization (what the tenant list shows), from the rollups: findings, Critical findings, devices and the CVEs CISA lists as exploited. */
export async function tenantStats(tenantId: string) {
  return (await get<{ findings: number; critical: number; devices: number; kev: number }>(
    `SELECT COALESCE((SELECT SUM(n) FROM roll_sev r JOIN tenant_cids x ON x.cid = r.cid WHERE x.tenant_id = ?), 0)::bigint AS findings,
            COALESCE((SELECT SUM(n) FROM roll_sev r JOIN tenant_cids x ON x.cid = r.cid WHERE x.tenant_id = ? AND r.severity = 'CRITICAL'), 0)::bigint AS critical,
            (SELECT COUNT(DISTINCT h.cid || h.aid) FROM roll_host h JOIN tenant_cids x ON x.cid = h.cid WHERE x.tenant_id = ?)::bigint AS devices,
            (SELECT COUNT(DISTINCT r.cve_id) FROM roll_cve r JOIN tenant_cids x ON x.cid = r.cid JOIN cves v ON v.id = r.cve_id WHERE x.tenant_id = ? AND v.cisa_kev = 1)::bigint AS kev`,
    tenantId, tenantId, tenantId, tenantId))!;
}
