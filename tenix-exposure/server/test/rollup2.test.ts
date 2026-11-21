// The v2 rollups (tiers, fixes, pairs, graph cells, daily history) must equal what the findings give row by row, computed here independently in JavaScript.
import { testDatabaseUrl } from "./test-db.ts";
process.env.TENIX_DATABASE_URL = testDatabaseUrl();
process.env.TENIX_DB_SCHEMA = `r2_${Math.random().toString(36).slice(2, 8)}`;
process.env.TENIX_SECRET_KEY = Buffer.alloc(32, 7).toString("base64");
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";

const dbm = await import("../src/db.ts");
const roll = await import("../src/rollup.ts");
const hostsMod = await import("../src/hosts.ts");
const lists = await import("../src/lists2.ts");

const A = "a".repeat(32), B = "b".repeat(32);
const COLS = ["cid", "finding_id", "aid", "cve_id", "severity", "base_score", "exprt", "exploit_status", "hostname", "platform", "local_ip", "external_ip", "product", "status", "rem_set", "synced_at", "provider", "kind", "vendor", "eval_id", "risk_score", "exploitability", "first_seen", "os_version", "internet_exposure", "port", "suppressed"];
let n = 0;
const rows: any[] = [];
const add = (cid: string, aid: string, cve: string, o: Record<string, unknown> = {}) => {
  const r: Record<string, unknown> = { cid, finding_id: `f${++n}`, aid, cve_id: cve, severity: "HIGH", base_score: 7, exprt: "LOW", exploit_status: 0, hostname: `h-${aid.slice(0, 2)}`, platform: "Windows", local_ip: "10.0.0.1", external_ip: null, product: "Prod A", status: "open",
    rem_set: 11, synced_at: 1, provider: "Falcon sensor", kind: "Vulnerability", vendor: null, eval_id: null, risk_score: null, exploitability: null, first_seen: Date.now() - 5 * 86400_000, os_version: null, internet_exposure: "No", port: null, suppressed: 0, ...o };
  rows.push(r);
};
const h = (i: number) => `${i}`.padStart(32, "0");
// brute-force tier, written from the design-spec sentence and not from the SQL
const KEV = new Set(["CVE-K"]);
const tier = (r: any) => (KEV.has(r.cve_id) || (r.exploit_status ?? 0) >= 60 || (r.severity === "CRITICAL" && r.exprt === "CRITICAL") ? 1 : r.severity === "CRITICAL" || r.exprt === "HIGH" || r.exprt === "CRITICAL" || r.exploit_status === 30 ? 2 : 3);
const live = () => rows.filter((r) => r.cid === A && r.suppressed === 0 && !/EASM/.test(r.provider ?? ""));
const GROUPS: Record<number, string[]> = { 1: ["Servers"], 2: ["Servers", "Finance"], 3: ["Finance"], 4: [], 5: ["Servers"] };

before(async () => {
  await dbm.run("INSERT INTO cves (id, cisa_kev, updated_at) VALUES ('CVE-K', 1, 1) ON CONFLICT DO NOTHING");
  await dbm.run("INSERT INTO rem_sets (id, remediation, remediation_json) VALUES (11, '- Update Prod A', NULL), (22, '- Patch Prod B', NULL)");
  add(A, h(1), "CVE-K", { severity: "MEDIUM", rem_set: 11, internet_exposure: "Yes" });                          // P1 by KEV
  add(A, h(1), "CVE-E", { exploit_status: 60, rem_set: 11 });                                                    // P1 by exploit status
  add(A, h(2), "CVE-CC", { severity: "CRITICAL", exprt: "CRITICAL", rem_set: 11 });                              // P1 by Critical + ExPRT Critical
  add(A, h(2), "CVE-C", { severity: "CRITICAL", exprt: "MEDIUM", rem_set: 22, product: "Prod B" });              // P2 by Critical alone
  add(A, h(3), "CVE-X", { severity: "HIGH", exprt: "HIGH", rem_set: 22, product: "Prod B" });                    // P2 by ExPRT High
  add(A, h(3), "CVE-X30", { exploit_status: 30, rem_set: 22, product: "Prod B" });                               // P2 by exploit code
  add(A, h(4), "CVE-L", { severity: "LOW", rem_set: 22, product: "Prod B" });                                    // P3
  add(A, h(4), "CVE-N", { severity: "MEDIUM", rem_set: null, product: null });                                   // P3 without a fix
  add(A, h(5), "CVE-CC", { severity: "CRITICAL", exprt: "CRITICAL", rem_set: 11 });                              // the same CVE on a second host
  add(A, h(5), "CVE-SUP", { severity: "CRITICAL", exprt: "CRITICAL", rem_set: 11, suppressed: 1 });              // suppressed: nowhere
  add(A, `${A}_AS999`, "CS-C24-1", { severity: "CRITICAL", exprt: "CRITICAL", provider: "Falcon EASM", rem_set: 11, kind: "Misconfiguration" }); // external: not a host, not a CVE, not a tier
  add(B, h(1), "CVE-CC", { severity: "CRITICAL", exprt: "CRITICAL", rem_set: 11 });
  await dbm.insertMany("findings_t", COLS, rows.map((r) => COLS.map((c) => r[c])));
  // the inventory: hosts 1-5 plus a host with no finding at all
  for (const i of [1, 2, 3, 4, 5, 6]) await dbm.run("INSERT INTO hosts (cid, aid, hostname, platform, os_version, groups, site, synced_at, last_seen) VALUES (?,?,?,?,?,?,?,?,?)", A, h(i), `HOST-${i}`, "Windows", i % 2 ? "Windows 11" : "RHEL 8", (GROUPS[i] ?? []) as any, i < 3 ? "HQ" : "", 1, Date.now());
  await roll.refreshRollups(A); await roll.refreshRollups(B);
});
after(async () => { await dbm.pool.query(`DROP SCHEMA ${process.env.TENIX_DB_SCHEMA} CASCADE`); await dbm.pool.end(); });
const q = <T = any>(sql: string, ...p: any[]) => dbm.all<T>(sql, ...p);
const key = (x: unknown) => JSON.stringify(x);

describe("tiers", () => {
  test("the tier of every CVE matches the design-spec rule, suppressed and external findings are in no rollup", async () => {
    const want = new Map<string, number>();
    for (const r of live()) want.set(r.cve_id, Math.min(want.get(r.cve_id) ?? 3, tier(r)));
    const got = new Map((await q("SELECT cve_id, tier FROM roll_cve WHERE cid = ? AND src = 'endpoint'", A)).map((r) => [r.cve_id, r.tier]));
    assert.deepEqual([...got].sort(), [...want].sort());
    assert.equal(got.get("CVE-K"), 1); assert.equal(got.get("CVE-E"), 1); assert.equal(got.get("CVE-CC"), 1); assert.equal(got.get("CVE-C"), 2); assert.equal(got.get("CVE-X"), 2); assert.equal(got.get("CVE-X30"), 2); assert.equal(got.get("CVE-L"), 3);
    assert.ok(!got.has("CVE-SUP") && !got.has("CS-C24-1"), "suppressed and external findings are not CVEs of the endpoint rollup");
    assert.equal((await q("SELECT 1 FROM roll_sev WHERE cid = ? AND src = 'external'", A)).length, 1, "the external finding is counted under its own source");
    assert.equal(lists.tierOf({ kev: false, exploit_status: 60, severity: "LOW", exprt: null }), 1, "the host drawer uses the same rule in JavaScript");
    for (const r of live()) assert.equal(lists.tierOf({ kev: KEV.has(r.cve_id), exploit_status: r.exploit_status, severity: r.severity, exprt: r.exprt }), tier(r), r.cve_id);
  });

  test("per host: P1/P2/P3 findings, KEV CVEs, fixes; the external asset is not a host", async () => {
    const got = await q("SELECT aid, p1, p2, p3, kev_cves, fixes, tier FROM roll_host WHERE cid = ? AND src = 'endpoint' ORDER BY aid", A);
    const aids = [...new Set(live().map((r) => r.aid))].sort();
    assert.deepEqual(got.map((r) => r.aid), aids);
    for (const x of got) {
      const mine = live().filter((r) => r.aid === x.aid);
      assert.deepEqual([x.p1, x.p2, x.p3], [1, 2, 3].map((t) => mine.filter((r) => tier(r) === t).length), x.aid);
      assert.equal(x.kev_cves, new Set(mine.filter((r) => KEV.has(r.cve_id)).map((r) => r.cve_id)).size);
      assert.equal(x.fixes, new Set(mine.filter((r) => tier(r) <= 2).map((r) => r.rem_set ?? 0)).size, "fixes = distinct fixes of P1/P2 findings");
      assert.equal(x.tier, Math.min(...mine.map(tier)));
    }
    assert.ok(!got.some((r) => r.aid.includes("_AS")), "an EASM asset is not a host");
  });
});

describe("fixes, their pairs and the graph cells", () => {
  const p12 = () => live().filter((r) => tier(r) <= 2);
  test("roll_fix: one row per fix with P1/P2 counts, CVEs, hosts and KEV CVEs", async () => {
    const got = await q("SELECT fix_id, findings, p1, p2, cves, p1_cves, kev_cves, hosts, p1_hosts, inet_hosts FROM roll_fix WHERE cid = ? ORDER BY fix_id", A);
    const ids = [...new Set(p12().map((r) => r.rem_set ?? 0))].sort((a, b) => a - b);
    assert.deepEqual(got.map((r) => r.fix_id), ids);
    for (const f of got) {
      const mine = p12().filter((r) => (r.rem_set ?? 0) === f.fix_id);
      const cve = new Map<string, number>();
      for (const r of mine) cve.set(r.cve_id, Math.min(cve.get(r.cve_id) ?? 9, tier(r)));
      assert.deepEqual([f.findings, f.p1, f.p2, f.cves, f.p1_cves, f.kev_cves, f.hosts, f.p1_hosts, f.inet_hosts],
        [mine.length, mine.filter((r) => tier(r) === 1).length, mine.filter((r) => tier(r) === 2).length, cve.size, [...cve.values()].filter((t) => t === 1).length, [...cve.keys()].filter((c) => KEV.has(c)).length,
          new Set(mine.map((r) => r.aid)).size, new Set(mine.filter((r) => tier(r) === 1).map((r) => r.aid)).size, new Set(mine.filter((r) => r.internet_exposure === "Yes").map((r) => r.aid)).size], `fix ${f.fix_id}`);
    }
    assert.ok(!got.some((f) => f.fix_id === 0), "a finding that is P3 and has no fix is outside the P1/P2 fixes");
  });

  test("fix-level and product-level totals per set (P1, P1+P2, KEV; with internet) equal the findings", async () => {
    const p1 = (r: any) => tier(r) === 1, kev = (r: any) => KEV.has(r.cve_id), all_ = () => true;
    const sets = (mine: any[], by: (r: any) => string) => {
      // internet exposure is a property of the host: a (fix | product, host) pair is internet-facing when any of its findings says so
      const inetPairs = new Set(mine.filter((r) => r.internet_exposure === "Yes").map((r) => `${by(r)}|${r.aid}`));
      const inet = (r: any) => inetPairs.has(`${by(r)}|${r.aid}`);
      const hosts = (pred: (r: any) => boolean) => new Set(mine.filter(pred).map((r) => r.aid)).size, count = (pred: (r: any) => boolean) => mine.filter(pred).length;
      const both = (a: (r: any) => boolean, b: (r: any) => boolean) => (r: any) => a(r) && b(r);
      return { h1: hosts(p1), hi1: hosts(both(p1, inet)), f1: count(p1), fi1: count(both(p1, inet)), h12: hosts(all_), hi12: hosts(inet), f12: count(all_), fi12: count(inet), hk: hosts(kev), hik: hosts(both(kev, inet)), fk: count(kev), fik: count(both(kev, inet)) };
    };
    for (const f of await q("SELECT * FROM roll_fix WHERE cid = ?", A)) {
      const want = sets(p12().filter((r) => (r.rem_set ?? 0) === f.fix_id), (r) => String(r.rem_set ?? 0));
      assert.deepEqual(Object.fromEntries(Object.keys(want).map((k) => [k, f[k]])), want, `fix ${f.fix_id}`);
    }
    for (const x of await q("SELECT * FROM roll_prod WHERE cid = ?", A)) {
      const want = sets(p12().filter((r) => r.product === x.product), (r) => r.product);
      assert.deepEqual(Object.fromEntries(Object.keys(want).map((k) => [k, x[k]])), want, `product ${x.product}`);
    }
    const host = await q("SELECT aid, kev_cves FROM roll_host WHERE cid = ? AND src = 'endpoint' ORDER BY aid", A);
    assert.deepEqual(host.map((r) => r.kev_cves), host.map((r) => new Set(live().filter((x) => x.aid === r.aid && KEV.has(x.cve_id)).map((x) => x.cve_id)).size));
  });

  test("pairs (fix x host, fix x CVE) equal the findings", async () => {
    const got = await q("SELECT fix_id, aid, findings, p1, p2, kev FROM roll_fix_host WHERE cid = ? ORDER BY fix_id, aid", A);
    const want = new Map<string, any>();
    for (const r of p12()) { const k = `${r.rem_set ?? 0}|${r.aid}`; const x = want.get(k) ?? { fix_id: r.rem_set ?? 0, aid: r.aid, findings: 0, p1: 0, p2: 0, kev: 0 }; x.findings++; if (tier(r) === 1) x.p1++; else x.p2++; if (KEV.has(r.cve_id)) x.kev++; want.set(k, x); }
    assert.equal(key(got), key([...want.values()].sort((a, b) => a.fix_id - b.fix_id || (a.aid < b.aid ? -1 : 1))));
    const fc = await q("SELECT fix_id, cve_id, hosts, findings, tier FROM roll_fix_cve WHERE cid = ? ORDER BY fix_id, cve_id", A);
    assert.equal(fc.length, new Set(p12().map((r) => `${r.rem_set ?? 0}|${r.cve_id}`)).size);
    assert.equal(fc.find((r) => r.cve_id === "CVE-CC")!.hosts, 2, "the same CVE on two hosts is two hosts of its fix");
  });

  test("graph cells per host group: exact distinct hosts, for P1 and P1+P2, with and without internet", async () => {
    const cells = await q("SELECT dim, dim_id, fix_id, h1, hi1, f1, h12, hi12, f12, hk, hik, fk FROM roll_fix_dim WHERE cid = ? AND dim = 'group' ORDER BY dim_id, fix_id", A);
    const want: any[] = [];
    for (const [g, aids] of Object.entries({ Servers: [1, 2, 5], Finance: [2, 3] })) {
      const fixes = [...new Set(p12().filter((r) => aids.some((i) => r.aid === h(i))).map((r) => r.rem_set ?? 0))];
      for (const f of fixes) {
        const mine = p12().filter((r) => (r.rem_set ?? 0) === f && aids.some((i) => r.aid === h(i)));
        const hosts = (pred: (r: any) => boolean) => new Set(mine.filter(pred).map((r) => r.aid)).size, count = (pred: (r: any) => boolean) => mine.filter(pred).length;
        const inet = (r: any) => r.internet_exposure === "Yes", p1 = (r: any) => tier(r) === 1, kev = (r: any) => KEV.has(r.cve_id), all_ = () => true;
        want.push({ dim: "group", dim_id: g, fix_id: f, h1: hosts(p1), hi1: hosts((r) => p1(r) && inet(r)), f1: count(p1), h12: hosts(all_), hi12: hosts(inet), f12: count(all_), hk: hosts(kev), hik: hosts((r) => kev(r) && inet(r)), fk: count(kev) });
      }
    }
    const strip = (x: any[]) => x.filter((c) => c.h12 > 0).map((c) => ({ ...c }));
    assert.equal(key(strip(cells)), key(strip(want).sort((a, b) => (a.dim_id < b.dim_id ? -1 : a.dim_id > b.dim_id ? 1 : a.fix_id - b.fix_id))));
    const dims = Object.fromEntries((await q("SELECT dim_id, hosts FROM roll_dim WHERE cid = ? AND dim = 'group'", A)).map((r) => [r.dim_id, r.hosts]));
    assert.deepEqual(dims, { Servers: 3, Finance: 2 }, "hosts per group come from the inventory (hosts with no finding count too)");
    assert.equal((await q("SELECT 1 FROM roll_dim WHERE cid = ? AND dim = 'site' AND dim_id = 'HQ'", A)).length, 1);
    assert.equal((await q("SELECT hosts FROM roll_dim WHERE cid = ? AND dim = 'os' AND dim_id = 'RHEL 8'", A))[0].hosts, 3, "the OS of the inventory");
  });

  test("another CID is untouched by a refresh, and a second refresh changes nothing", async () => {
    const before = key(await q("SELECT * FROM roll_fix_host WHERE cid = ? ORDER BY fix_id, aid", A));
    const other = key(await q("SELECT * FROM roll_fix WHERE cid = ?", B));
    await roll.refreshRollups(A);
    assert.equal(key(await q("SELECT * FROM roll_fix_host WHERE cid = ? ORDER BY fix_id, aid", A)), before);
    assert.equal(key(await q("SELECT * FROM roll_fix WHERE cid = ?", B)), other);
    assert.deepEqual((await q("SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema() AND table_name LIKE 'stg\\_%'")), [], "the staging tables are dropped");
  });
});

describe("daily history", () => {
  test("one row per CID per UTC day: tier counts, hosts with P1 and the inventory size; a second write the same day replaces it", async () => {
    await dbm.run("INSERT INTO cid_counts (cid, key, n, as_of) VALUES (?, 's_critical', 7, 1), (?, 's_high', 5, 1), (?, 's_medium', 3, 1), (?, 's_low', 1, 1), (?, 's_total', 20, 1), (?, 's_kev', 2, 1) ON CONFLICT DO NOTHING", A, A, A, A, A, A);
    await roll.recordHistory(A); await roll.recordHistory(A);
    const day = new Date().toISOString().slice(0, 10);
    const rows_ = await q("SELECT * FROM hist_day WHERE cid = ?", A);
    assert.equal(rows_.length, 1);
    const x = rows_[0];
    assert.equal(x.day, day);
    const l = live();
    assert.deepEqual([x.p1, x.p2, x.p3, x.hosts_p1, x.hosts_total], [l.filter((r) => tier(r) === 1).length, l.filter((r) => tier(r) === 2).length, l.filter((r) => tier(r) === 3).length, new Set(l.filter((r) => tier(r) === 1).map((r) => r.aid)).size, 6]);
    assert.deepEqual([x.critical, x.high, x.medium, x.low, x.none, x.kev], [7, 5, 3, 1, 4, 2], "Falcon's exact counts of the moment (sensor-only when present); the rest is Informational");
  });
});

describe("hosts inventory helpers", () => {
  const mk = (aid: string, hostname: string, last: number, o: Record<string, unknown> = {}): any => ({ cid: A, aid, hostname, platform: "Windows", os_version: "Windows 11", os_build: null, agent_version: null, first_seen: 1, last_seen: last, local_ip: null, external_ip: null, mac: null, serial: null, machine_domain: null, site: null, ou: [], tags: [], groups: [], product_type: null, criticality: null, rfm: false, contained: false, status: "normal", dup_group: null, dup_role: null, dup_reason: null, dup_newer: null, stale_twin: false, ...o });
  const DAY = 86400_000, t = Date.now();
  test("duplicates by hostname, serial or MAC: the newest check-in is the keeper, the older twin is stale only when it stopped at least a day earlier", () => {
    const xs = [mk("1", "PC-1.corp", t), mk("2", "pc-1", t - 40 * DAY), mk("3", "LAP-9", t, { serial: "SN12345" }), mk("4", "OTHER", t - 2 * DAY, { serial: "sn12345" }), mk("5", "SAME-DAY", t), mk("6", "same-day", t - 3600_000),
      mk("7", "M-1", t, { mac: "AA-BB-CC-DD-EE-01" }), mk("8", "M-2", t - 5 * DAY, { mac: "aa:bb:cc:dd:ee:01" }), mk("9", "WSL-HOST", t, { os_version: "WSL 2.0" }), mk("10", "WSL-HOST", t, { os_version: "Windows 11" }),
      mk("11", "J-1", t, { serial: "To be filled by O.E.M." }), mk("12", "J-2", t, { serial: "To be filled by O.E.M." }), mk("13", "10.1.1.1", t), mk("14", "10.1.1.1", t), mk("15", "ALONE", t)];
    hostsMod.markDuplicates(xs);
    const by = Object.fromEntries(xs.map((x) => [x.aid, x]));
    assert.deepEqual([by["1"].dup_role, by["2"].dup_role, by["2"].stale_twin, by["2"].dup_newer, by["2"].dup_reason], ["newest", "older", true, "1", "hostname"], "FQDN and short name, any case, are one name");
    assert.deepEqual([by["3"].dup_role, by["4"].dup_role, by["4"].stale_twin, by["4"].dup_reason], ["newest", "older", true, "serial"]);
    assert.deepEqual([by["5"].dup_role, by["6"].dup_role, by["6"].stale_twin], ["newest", "older", false], "both seen within a day: possible duplicates, not a stale twin");
    assert.deepEqual([by["7"].dup_role, by["8"].dup_role, by["8"].dup_reason], ["newest", "older", "mac"]);
    assert.equal(by["9"].dup_group, null, "a Linux WSL instance shares the Windows name on purpose");
    assert.equal(by["11"].dup_group, null, "a placeholder serial number identifies nothing");
    assert.equal(by["13"].dup_group, null, "an IP address is not a name");
    assert.equal(by["15"].dup_group, null);
  });

  test("csv cells: text that starts like a formula is neutralised, numbers stay numbers, quotes and line breaks are escaped", () => {
    assert.equal(lists.csvCell("=HYPERLINK(\"http://x\")"), `"'=HYPERLINK(""http://x"")"`);
    for (const f of ["+1+1", "-2+3", "@SUM(A1)", "\tcmd", "\rcmd"]) assert.ok(lists.csvCell(f).replace(/^"/, "").startsWith("'"), f);
    assert.equal(lists.csvCell(-5), "-5"); assert.equal(lists.csvCell(null), ""); assert.equal(lists.csvCell(true), "true");
    assert.equal(lists.csvCell("a,b"), '"a,b"'); assert.equal(lists.csvCell(["x", "y"]), "x; y"); assert.equal(lists.csvCell("ปกติ"), "ปกติ");
  });
});
