// The rollups every customer page reads must equal what grouping the findings row by row gives.
import { testDatabaseUrl } from "./test-db.ts";
process.env.TENIX_DATABASE_URL = testDatabaseUrl();
process.env.TENIX_DB_SCHEMA = `r_${Math.random().toString(36).slice(2, 10)}`;
process.env.TENIX_SECRET_KEY = Buffer.alloc(32, 7).toString("base64");
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";

const dbm = await import("../src/db.ts");
const roll = await import("../src/rollup.ts");

const A = "a".repeat(32), B = "b".repeat(32);
const COLS = ["cid", "finding_id", "aid", "cve_id", "severity", "base_score", "exprt", "exploit_status", "hostname", "platform", "local_ip", "external_ip", "product", "status", "rem_set", "synced_at", "provider", "kind", "vendor", "eval_id", "risk_score", "exploitability", "first_seen", "os_version", "internet_exposure", "port"];
let n = 0;
const row = (cid: string, aid: string, cve: string, o: Record<string, unknown> = {}) => {
  const r: Record<string, unknown> = { cid, finding_id: `f${++n}`, aid, cve_id: cve, severity: "HIGH", base_score: 7, exprt: "HIGH", exploit_status: 0, hostname: `h-${aid}`, platform: "Windows", local_ip: "10.0.0.1", external_ip: null, product: "Prod 1", status: "open",
    rem_set: null, synced_at: 1, provider: null, kind: "Vulnerability", vendor: null, eval_id: null, risk_score: null, exploitability: null, first_seen: Date.now() - 10 * 86400_000, os_version: null, internet_exposure: "No", port: null, ...o };
  return COLS.map((c) => r[c] as string | number | null);
};
const all = <T = any>(sql: string, ...p: any[]) => dbm.all<T>(sql, ...p);
const key = (rows: any[]) => JSON.stringify(rows);

before(async () => {
  const h = (i: number) => `${i}`.padStart(32, "0");
  const rows = [
    row(A, h(1), "CVE-2026-0001", { severity: "CRITICAL", exprt: "CRITICAL", exploit_status: 90, internet_exposure: "Yes", product: "Prod 1" }),
    row(A, h(1), "CVE-2026-0002", { severity: "HIGH", exploit_status: 60 }),
    row(A, h(1), "CVE-2026-0002", { severity: "HIGH", product: "Prod 2" }), // the same CVE twice on a device (two products): one device
    row(A, h(2), "CVE-2026-0001", { severity: "CRITICAL", exprt: "CRITICAL", exploit_status: 90 }),
    row(A, h(2), "CVE-2026-0003", { severity: "MEDIUM", exprt: "MEDIUM", product: null, first_seen: null }),
    row(A, h(3), "CVE-2026-0004", { severity: "LOW", exprt: "LOW", first_seen: Date.now() - 400 * 86400_000 }),
    row(A, "cid_ASxyz_" + "e".repeat(20), "CS-C24-A1", { severity: "HIGH", provider: "Falcon EASM", kind: "Misconfiguration", hostname: "shop.example.com", product: null }),
    row(A, h(4), "CVE-2026-0005", { severity: "WEIRD", exprt: null, base_score: null, exploit_status: null }), // a severity Falcon invented: NONE
    row(B, h(1), "CVE-2026-0001", { severity: "CRITICAL", exprt: "CRITICAL" }),
  ];
  await dbm.insertMany("findings_t", COLS, rows);
  await roll.refreshRollups(A); await roll.refreshRollups(B);
});
after(async () => { await dbm.pool.query(`DROP SCHEMA ${process.env.TENIX_DB_SCHEMA} CASCADE`); await dbm.pool.end(); });

const RANK = roll.RANK_SQL;
const SRC = "CASE WHEN provider ILIKE '%EASM%' THEN 'external' ELSE 'endpoint' END";

describe("rollups equal the row-level truth", () => {
  test("per CVE", async () => {
    const truth = await all(`SELECT cid, ${SRC} AS src, cve_id, MIN(${RANK})::int AS rank, MAX(base_score) AS base_score, MAX(exprt) AS exprt, MAX(exploit_status) AS exploit_status, MAX(kind) AS kind, MAX(product) AS product,
      COUNT(DISTINCT aid)::int AS hosts, COUNT(*)::int AS findings, COUNT(DISTINCT CASE WHEN internet_exposure = 'Yes' OR provider ILIKE '%EASM%' THEN aid END)::int AS inet FROM findings WHERE cid IN ('${A}','${B}') GROUP BY 1, 2, 3 ORDER BY 1, 2, 3`);
    const got = await all(`SELECT cid, src, cve_id, rank::int, base_score, exprt, exploit_status, kind, product, hosts, findings, inet FROM roll_cve ORDER BY cid, src, cve_id`);
    assert.equal(key(got), key(truth));
    const dup = got.find((r) => r.cve_id === "CVE-2026-0002" && r.cid === A)!;
    assert.deepEqual([dup.hosts, dup.findings], [1, 2], "two findings of one CVE on one device are one device");
  });

  test("the products of a CVE (what the list searches) and the fix-first count", async () => {
    const p = (await all("SELECT products FROM roll_cve WHERE cid = ? AND cve_id = 'CVE-2026-0002'", A))[0].products as string;
    assert.deepEqual(p.split(" | ").sort(), ["Prod 1", "Prod 2"]);
    assert.equal((await all("SELECT products FROM roll_cve WHERE cid = ? AND cve_id = 'CVE-2026-0003'", A))[0].products, null);
    const truth = await all(`SELECT cve_id, COUNT(*) FILTER (WHERE severity = 'CRITICAL' OR exprt = 'CRITICAL' OR exploit_status >= 60)::int AS pri FROM findings WHERE cid = '${A}' GROUP BY 1 ORDER BY 1`);
    assert.equal(key(await all("SELECT cve_id, pri FROM roll_cve WHERE cid = ? ORDER BY cve_id", A)), key(truth));
  });

  test("per device", async () => {
    const truth = await all(`SELECT cid, ${SRC} AS src, aid, MAX(hostname) AS hostname, MAX(platform) AS platform, MAX(local_ip) AS local_ip, MAX(external_ip) AS external_ip, MAX(provider) AS provider, COUNT(DISTINCT cve_id)::int AS cves,
      COUNT(DISTINCT CASE WHEN severity = 'CRITICAL' THEN cve_id END)::int AS critical, COUNT(DISTINCT CASE WHEN severity = 'HIGH' THEN cve_id END)::int AS high, COUNT(DISTINCT CASE WHEN severity = 'MEDIUM' THEN cve_id END)::int AS medium,
      COUNT(DISTINCT CASE WHEN exploit_status >= 60 THEN cve_id END)::int AS exploited, MIN(${RANK})::int AS rank, COUNT(*)::int AS findings, COALESCE(BOOL_OR(internet_exposure = 'Yes' OR provider ILIKE '%EASM%'), false) AS inet
      FROM findings WHERE cid IN ('${A}','${B}') GROUP BY 1, 2, 3 ORDER BY 1, 2, 3`);
    const got = await all(`SELECT cid, src, aid, hostname, platform, local_ip, external_ip, provider, cves, critical, high, medium, exploited, rank::int, findings, inet FROM roll_host ORDER BY cid, src, aid`);
    assert.equal(key(got), key(truth));
  });

  test("per severity, and the age of Critical and High findings", async () => {
    assert.equal(key(await all("SELECT cid, src, inet, severity, n::int FROM roll_sev ORDER BY 1, 2, 3, 4")),
      key(await all(`SELECT cid, ${SRC} AS src, COALESCE(internet_exposure = 'Yes' OR provider ILIKE '%EASM%', false) AS inet, severity, COUNT(*)::int AS n FROM findings GROUP BY 1, 2, 3, 4 ORDER BY 1, 2, 3, 4`)));
    const age = Object.fromEntries((await all("SELECT bucket, SUM(n)::int AS n FROM roll_age WHERE cid = ? GROUP BY 1", A)).map((r) => [r.bucket, r.n]));
    assert.deepEqual(age, { d30: 5 }, "five Critical or High findings seen in the last 30 days");
  });

  test("held, fix-first and device counts; a refresh replaces the rows of that CID only, and again changes nothing", async () => {
    const h = await roll.refreshRollups(A);
    assert.deepEqual(h, { held: 8, priority: 3, hosts: 5, cves: 6 });
    const before = key(await all("SELECT * FROM roll_cve WHERE cid = ? ORDER BY cve_id, src", A));
    await dbm.run("DELETE FROM findings_t WHERE cid = ? AND cve_id = 'CVE-2026-0004'", A);
    assert.equal((await roll.refreshRollups(A)).held, 7);
    assert.equal((await all("SELECT * FROM roll_cve WHERE cid = ? AND cve_id = 'CVE-2026-0004'", A)).length, 0);
    assert.equal((await all("SELECT * FROM roll_cve WHERE cid = ?", B)).length, 1, "the other CID is untouched");
    assert.notEqual(before, key(await all("SELECT * FROM roll_cve WHERE cid = ? ORDER BY cve_id, src", A)));
  });

  test("the headline numbers of an organization", async () => {
    await dbm.run("INSERT INTO tenants (id, name, created_at) VALUES ('t1','One',1)");
    await dbm.run("INSERT INTO tenant_cids (cid, tenant_id) VALUES (?, 't1')", A);
    await dbm.run("INSERT INTO cves (id, cisa_kev, updated_at) VALUES ('CVE-2026-0001', 1, 1)");
    assert.deepEqual(await roll.tenantStats("t1"), { findings: 7, critical: 2, devices: 4, kev: 1 });
  });
});
