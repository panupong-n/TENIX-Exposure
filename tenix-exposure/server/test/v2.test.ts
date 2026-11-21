// API v2 (summary, fixes, hosts, vulnerabilities, trend, portfolio, CSV, graph) against the mock Falcon: the numbers must agree between the pages, a tenant must never read another's, and the inventory is the truth for hosts.
import { testDatabaseUrl } from "./test-db.ts";
process.env.TENIX_DATABASE_URL = testDatabaseUrl();
process.env.TENIX_DB_SCHEMA = `v2_${Math.random().toString(36).slice(2, 8)}`;
process.env.TENIX_SECRET_KEY = Buffer.alloc(32, 7).toString("base64");
process.env.TENIX_DEV_FALCON_URL_OK = "1";
process.env.MOCK_RICH = "1"; // CVE details, KEV flags and external (EASM) findings
import assert from "node:assert/strict";
import { type AddressInfo } from "node:net";
import { after, before, describe, test } from "node:test";
import { CID_ONE, CID_TWO, MOCK_CLIENT, MOCK_SECRET, startMock } from "./mock-falcon.ts";

const { createApp } = await import("../src/http.ts");
for (const m of ["auth", "team", "exposure", "software", "system", "connections", "overview", "lists2", "graph2"]) await import(`../src/${m}.ts`);
const falcon = await import("../src/falcon.ts");
const dbm = await import("../src/db.ts");
const crypto = await import("../src/crypto.ts");
const ov = await import("../src/overview.ts");
falcon.hooks.sleep = async () => {};
falcon.hooks.rollupMinMs = 0;
falcon.hooks.pageSizes = [500];

class Client {
  jar = new Map<string, string>();
  base: string;
  constructor(base: string) { this.base = base; }
  async raw(path: string) {
    const r = await fetch(this.base + path, { headers: this.jar.size ? { Cookie: [...this.jar].map(([k, v]) => `${k}=${v}`).join("; ") } : {} });
    return r;
  }
  async req(method: string, path: string, body?: unknown) {
    const r = await fetch(this.base + path, { method, headers: { "Content-Type": "application/json", ...(this.jar.size ? { Cookie: [...this.jar].map(([k, v]) => `${k}=${v}`).join("; ") } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
    for (const sc of r.headers.getSetCookie()) { const [kv] = sc.split(";"); const i = kv.indexOf("="); const v = kv.slice(i + 1); if (/Max-Age=0/.test(sc) || !v) this.jar.delete(kv.slice(0, i)); else this.jar.set(kv.slice(0, i), v); }
    return { status: r.status, body: (await r.json().catch(() => null)) as any };
  }
  get = (p: string) => this.req("GET", p);
  post = (p: string, b: unknown = {}) => this.req("POST", p, b);
}
const PW = "correct-horse-battery-1";
let base = "", mock: Awaited<ReturnType<typeof startMock>>["control"], mockUrl = "";
const servers: { close: () => void }[] = [];
const ids: Record<string, string> = {};
async function adopt(email: string, role: "super_admin" | "member", memberships: { tenantId: string; role: "admin" | "operator" }[] = []) {
  const raw = crypto.token();
  await dbm.run("INSERT INTO invites (id, email, role, memberships_json, kind, token_hash, expires_at, created_at) VALUES (?,?,?,?,?,?,?,?)", crypto.uuid(), email, role, JSON.stringify(memberships), "invite", crypto.sha256(raw), Date.now() + 1e6, Date.now());
  const c = new Client(base);
  const r = await c.post(`/api/invites/${raw}/accept`, { name: email.split("@")[0], password: PW });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return c;
}
async function waitSync(admin: Client) {
  for (let i = 0; i < 400; i++) { const r = await admin.get("/api/integrations/falcon"); if (!r.body.sync.running) return r.body; await new Promise((ok) => setTimeout(ok, 50)); }
  throw new Error("sync did not finish");
}
const runSync = async (tenantId?: string) => { assert.equal((await admin.post("/api/integrations/falcon/sync", tenantId ? { tenantId } : {})).status, 200); return waitSync(admin); };

let admin: Client, a1: Client, b1: Client, soc: Client;
const A = () => `?tenantId=${ids.ta}`;
const KEVS = new Set<string>();

// the tier rule, written from the design-spec sentence (not from the code under test)
const tierOf = (f: any) => (KEVS.has(f.cve.id) || (f.cve.exploit_status ?? 0) >= 60 || (f.cve.severity === "CRITICAL" && f.cve.exprt_rating === "CRITICAL") ? 1 : f.cve.severity === "CRITICAL" || ["HIGH", "CRITICAL"].includes(f.cve.exprt_rating) || f.cve.exploit_status === 30 ? 2 : 3);
const endpointRows = (cid: string) => mock.data.findings.filter((f) => f.cid === cid && ["open", "reopen"].includes(f.status) && !/EASM/.test(f.data_providers?.[0]?.provider ?? "") && !f.suppression_info?.is_suppressed);
const devices = (cid: string) => [...mock.data.devices.values()].filter((d) => d.cid === cid);

before(async () => {
  const s = createApp();
  await new Promise<void>((ok) => s.listen(0, "127.0.0.1", ok));
  base = `http://127.0.0.1:${(s.address() as AddressInfo).port}`;
  servers.push(s);
  const m = await startMock();
  mockUrl = m.url; mock = m.control; servers.push(m.server);
  // KEV is a property of the CVE: every row of a KEV CVE carries the flag (as Falcon does)
  const kevCves = new Set(mock.data.findings.filter((f) => f.cve.cisa_info?.is_cisa_kev).map((f) => f.cve.id));
  for (const f of mock.data.findings) if (f.cve.id) f.cve.cisa_info = { is_cisa_kev: kevCves.has(f.cve.id) };
  admin = await adopt("admin@v2.test", "super_admin");
  const ta = (await admin.post("/api/tenants", { name: "Alpha Corp" })).body.tenant, tb = (await admin.post("/api/tenants", { name: "Beta Ltd" })).body.tenant;
  Object.assign(ids, { ta: ta.id, tb: tb.id });
  a1 = await adopt("alice@alpha.test", "member", [{ tenantId: ta.id, role: "operator" }]);
  b1 = await adopt("bob@beta.test", "member", [{ tenantId: tb.id, role: "operator" }]);
  soc = await adopt("sam@v2.test", "member", [{ tenantId: ta.id, role: "operator" }, { tenantId: tb.id, role: "operator" }]);
  for (const [t, cid] of [[ta, CID_ONE], [tb, CID_TWO]] as const) assert.equal((await admin.post(`/api/tenants/${t.id}/falcon`, { baseUrl: mockUrl, clientId: MOCK_CLIENT, clientSecret: MOCK_SECRET, cid })).status, 200);
  assert.equal((await admin.post("/api/integrations/falcon/sync", {})).status, 200);
  const done = await waitSync(admin);
  assert.deepEqual(done.cids.map((x: any) => x.state), ["complete", "complete"]);
  for (const r of await dbm.all<{ id: string }>("SELECT id FROM cves WHERE cisa_kev = 1")) KEVS.add(r.id);
  assert.ok(KEVS.size > 0, "the fixture has KEV CVEs");
});
after(async () => {
  servers.forEach((s) => s.close());
  await dbm.pool.query(`DROP SCHEMA ${process.env.TENIX_DB_SCHEMA} CASCADE`);
  await dbm.pool.end();
});

describe("the numbers agree between summary, lists, drawers and graph", () => {
  test("summary: held tiers equal the tier rule over the mock's endpoint findings, EASM is not in them, the inventory is the host count", async () => {
    const r = await a1.get("/api/exposure/v2/summary");
    assert.equal(r.status, 200, JSON.stringify(r.body));
    const rows = endpointRows(CID_ONE), t = (n: number) => rows.filter((f) => tierOf(f) === n).length;
    assert.deepEqual([r.body.tiers.P1.held, r.body.tiers.P2.held, r.body.tiers.P3.held], [t(1), t(2), t(3)]);
    assert.equal(r.body.headline.p1, t(1));
    assert.ok(mock.data.findings.some((f) => /EASM/.test(f.data_providers?.[0]?.provider ?? "")), "the fixture has EASM findings");
    assert.equal(r.body.hosts.total, devices(CID_ONE).length, "hosts = the inventory (including hosts without findings), not distinct aids in findings");
    assert.equal(r.body.hosts.source, "inventory");
    assert.ok(r.body.hosts.withoutFindings >= 10, "the ten quiet hosts are counted");
    assert.equal(r.body.hostsSync.state, "complete");
    assert.equal(r.body.headline.hostsTotal, devices(CID_ONE).length);
    assert.equal(r.body.headline.hostShare, r.body.headline.hostsWithP1 / r.body.headline.hostsTotal);
    assert.ok(["low", "medium", "high", "critical"].includes(r.body.headline.level.key));
    assert.equal(r.body.headline.p1Exact, true);
  });

  test("tiers: Falcon's exact counts (nested counts are not needed) equal the held ones when everything is held; severity is the sensor-only exact count and ExPRT is its own number", async () => {
    const r = (await a1.get("/api/exposure/v2/summary")).body, rows = endpointRows(CID_ONE);
    for (const [k, n] of [["P1", 1], ["P2", 2], ["P3", 3]] as const) assert.deepEqual([r.tiers[k].source, r.tiers[k].total, r.tiers[k].exact], ["falcon", rows.filter((f) => tierOf(f) === n).length, true], k);
    assert.equal(r.tiers.atLeast, false);
    assert.equal(r.severity.source, "falcon"); assert.equal(r.severity.endpointOnly, true);
    assert.equal(r.severity.CRITICAL, rows.filter((f) => f.cve.severity === "CRITICAL").length);
    assert.equal(r.severity.total, rows.length);
    const fc = r.completeness.falconCounts;
    assert.ok(fc.critical > r.severity.CRITICAL, "Falcon's all-provider count also holds the EASM findings; v2 does not");
    assert.equal(r.facts.exprtCritical, rows.filter((f) => f.cve.exprt_rating === "CRITICAL").length);
    assert.equal(r.facts.exploited, rows.filter((f) => [60, 70, 80, 90].includes(f.cve.exploit_status)).length);
    assert.ok("exprtCritical" in r.facts && "CRITICAL" in r.severity, "severity and ExPRT are separate numbers (the mock gives every CVE the same value for both, Falcon does not)");
    assert.ok(r.external.findings > 0 && r.external.assets > 0);
  });

  test("a missing Falcon count turns the tiers into 'at least' instead of a wrong number", async () => {
    await dbm.run("DELETE FROM cid_counts WHERE cid = ? AND key = 's_p12'", CID_ONE);
    const r = (await soc.get(`/api/exposure/v2/summary${A()}&x=1`)).body; // another key: not the cached answer
    assert.equal(r.tiers.P2.source, "held"); assert.equal(r.tiers.P2.exact, false); assert.equal(r.tiers.atLeast, true);
    assert.equal(r.tiers.P1.source, "falcon");
  });

  test("fixes: the P1 of all fixes adds up to the headline, the list, drawer, hosts and CVE pages agree, 'by fix' is the same list", async () => {
    const sum = (await a1.get("/api/exposure/v2/summary")).body.headline;
    const all = (await a1.get("/api/exposure/v2/fixes?pageSize=100")).body;
    assert.equal(all.totals.p1, sum.p1);
    let p1 = 0, page = 1, total = 0;
    for (;;) { const p = (await a1.get(`/api/exposure/v2/fixes?pageSize=5&page=${page}`)).body; p1 += p.rows.reduce((a: number, x: any) => a + x.p1, 0); total = p.total; if (page * 5 >= p.total) break; page++; }
    assert.equal(p1, sum.p1, "the P1 of every fix, page by page, is the P1 of the headline");
    assert.equal(sum.p1Fixes, (await a1.get("/api/exposure/v2/fixes?tier=P1")).body.total);
    const top = all.rows[0];
    assert.ok(all.rows.every((x: any, i: number) => i === 0 || all.rows[i - 1].p1 >= x.p1), "default sort: P1 closed first");
    const d = (await a1.get(`/api/exposure/v2/fixes/${top.id}`)).body;
    assert.equal(d.summary.p1 + d.summary.p2 + d.summary.p3, top.findings, "the fix drawer's P1 + P2 + P3 add up to the findings of the fix (no NaN)");
    assert.equal(d.summary.p1, top.p1); assert.equal(d.hosts.total, top.hosts); assert.equal(d.cves.total, top.cves); assert.equal(d.title, top.title);
    assert.ok(d.actions.length >= 1);
    const h2 = (await a1.get(`/api/exposure/v2/fixes/${top.id}/hosts?pageSize=100`)).body;
    assert.equal(h2.total, top.hosts); assert.equal(h2.rows.length, Math.min(100, top.hosts));
    assert.ok(h2.rows.every((x: any) => x.fixFindings > 0));
    const c2 = (await a1.get(`/api/exposure/v2/fixes/${top.id}/cves?pageSize=100`)).body;
    assert.equal(c2.total, top.cves);
    const viaVulns = (await a1.get(`/api/exposure/v2/vulnerabilities?fix=${top.id}`)).body;
    assert.equal(viaVulns.total, top.cves, "the CVE list filtered by fix has the CVEs the fix closes");
    assert.deepEqual((await a1.get("/api/exposure/v2/vulnerabilities?group=fix&pageSize=5")).body.rows.map((x: any) => x.id), (await a1.get("/api/exposure/v2/fixes?pageSize=5")).body.rows.map((x: any) => x.id));
    assert.equal((await a1.get("/api/exposure/v2/fixes?tier=P3")).status, 400);
  });

  test("hosts: the inventory is the population (quiet hosts appear), P1 hosts agree with the summary, the host drawer agrees with its row, EASM assets are never hosts", async () => {
    const sum = (await a1.get("/api/exposure/v2/summary")).body;
    const list = (await a1.get("/api/exposure/v2/hosts?pageSize=100")).body;
    assert.equal(list.total, devices(CID_ONE).length);
    assert.equal(list.facets.all, sum.hosts.total); assert.equal(list.facets.withP1, sum.headline.hostsWithP1);
    assert.equal((await a1.get("/api/exposure/v2/hosts?tier=P1")).body.total, sum.headline.hostsWithP1);
    assert.ok(list.facets.noFindings >= 10);
    const quiet = (await a1.get("/api/exposure/v2/hosts?hasFindings=0&pageSize=100")).body;
    assert.equal(quiet.total, list.facets.noFindings);
    assert.ok(quiet.rows.every((x: any) => x.findings === 0 && x.p1 === 0 && x.inInventory && x.worstSeverity === null && x.tier === null));
    assert.ok(quiet.rows.some((x: any) => /^QUIET-/.test(x.hostname)));
    assert.ok(!list.rows.some((x: any) => /_AS/.test(x.aid)), "an EASM asset is not a host");
    assert.equal(list.rows.reduce((a: number, x: any) => a + x.p1, 0) <= sum.headline.p1, true);
    const top = list.rows[0];
    assert.ok(top.p1 >= list.rows[1].p1, "default sort: P1 first");
    const d = (await a1.get(`/api/exposure/v2/hosts/${top.aid}`)).body;
    assert.deepEqual([d.tiers.P1, d.tiers.P2, d.tiers.P3], [top.p1, top.p2, top.p3]);
    assert.equal(d.cvesTotal, new Set(endpointRows(CID_ONE).filter((f) => f.aid === top.aid).map((f) => f.cve.id)).size);
    assert.ok(d.cves.every((x: any, i: number) => i === 0 || d.cves[i - 1].tier <= x.tier), "the CVEs of a host come in tier order");
    assert.deepEqual(d.cves.map((x: any) => x.tier).filter((t: string) => t === "P1").length > 0, top.p1 > 0);
    assert.equal(Object.values(d.severity).reduce((a: number, x: any) => a + x, 0), endpointRows(CID_ONE).filter((f) => f.aid === top.aid).length);
    assert.ok(d.host.groups.every((g: string) => !/^grp\d$/.test(g)), "group ids became names");
    assert.ok(top.groups.length >= 1 && top.osVersion && top.lastSeen && top.serial, "the inventory carries what findings do not");
  });

  test("stale and duplicate hosts come from the real check-in and the inventory", async () => {
    const sum = (await a1.get("/api/exposure/v2/summary")).body.hosts;
    const old = devices(CID_ONE).filter((d) => Date.now() - Date.parse(d.last_seen) > 30 * 86400_000).length, mid = devices(CID_ONE).filter((d) => Date.now() - Date.parse(d.last_seen) > 7 * 86400_000).length;
    assert.equal(sum.stale30, old); assert.equal(sum.stale7, mid);
    assert.equal((await a1.get("/api/exposure/v2/hosts?seen=stale30")).body.total, old);
    assert.equal((await a1.get("/api/exposure/v2/hosts?seen=active")).body.total, devices(CID_ONE).length - old);
    const dups = (await a1.get("/api/exposure/v2/hosts?duplicates=1&pageSize=100")).body;
    assert.ok(dups.total > 0 && dups.rows.every((x: any) => x.duplicate && ["newest", "older"].includes(x.duplicate.role)));
    const names = new Map<string, number>();
    for (const d of devices(CID_ONE)) { const k = (d.hostname ?? "").toLowerCase().split(".")[0]; if (k.length >= 2 && !/^\d+\.\d+\.\d+\.\d+$/.test(d.hostname)) names.set(k, (names.get(k) ?? 0) + 1); }
    const bySerial = new Map<string, number>(); for (const d of devices(CID_ONE)) bySerial.set(d.serial_number, (bySerial.get(d.serial_number) ?? 0) + 1);
    assert.ok(bySerial.size === devices(CID_ONE).length, "the mock's serial numbers are unique, so every duplicate here is by name");
    assert.equal(dups.total, [...names.values()].filter((n) => n > 1).reduce((a, b) => a + b, 0), "hosts in a shared-name group");
    const twin = dups.rows.find((x: any) => x.duplicate.staleTwin);
    assert.ok(!twin || twin.duplicate.role === "older");
  });

  test("hosts sort: names come out in Thai dictionary order, not by code point", async () => {
    const thai = ["เก้า", "ขนม", "แมว", "กา", "ไก่", "ค้อน"];
    const some = await dbm.all<{ aid: string }>("SELECT aid FROM hosts WHERE cid = ? ORDER BY aid LIMIT 6", CID_ONE);
    for (const [i, x] of some.entries()) await dbm.run("UPDATE hosts SET hostname = ? WHERE cid = ? AND aid = ?", `~${thai[i]}`, CID_ONE, x.aid);
    const got = (await a1.get("/api/exposure/v2/hosts?q=~&sort=hostname&pageSize=100")).body.rows.map((x: any) => x.hostname);
    const expect = thai.map((x) => `~${x}`).sort(dbm.nameOrder.compare);
    assert.deepEqual(got, expect);
    assert.notDeepEqual(got, thai.map((x) => `~${x}`).sort(), "a code point sort would order it differently");
  });

  test("vulnerabilities: tiers and 'why', severity and ExPRT both exposed, KEV with due date, default order is the priority key", async () => {
    const v = (await a1.get("/api/exposure/v2/vulnerabilities?pageSize=100")).body;
    const sum = (await a1.get("/api/exposure/v2/summary")).body;
    assert.equal(v.facets.P1, sum.headline.p1Cves);
    assert.equal(v.total, v.facets.P1 + v.facets.P2 + v.facets.P3);
    const order = v.rows.map((x: any) => [Number(x.tier.slice(1)), x.kev ? 0 : 1]);
    assert.deepEqual(order, [...order].sort((a: number[], b: number[]) => a[0] - b[0] || a[1] - b[1]), "tier first, then KEV");
    const kev = v.rows.find((x: any) => x.kev), p1 = v.rows.find((x: any) => x.tier === "P1");
    assert.ok(kev && kev.whyTier.includes("kev") && p1.whyTier.length > 0);
    assert.ok(v.rows.every((x: any) => "severity" in x && "exprt" in x && (x.tier === "P3" || x.fix)), "P1 and P2 CVEs name their fix");
    assert.equal((await a1.get("/api/exposure/v2/vulnerabilities?kev=1")).body.total, sum.headline.p1Cves >= 1 ? v.rows.filter((x: any) => x.kev).length + (v.total > 100 ? 0 : 0) : 0, "the KEV filter finds the KEV CVEs");
    assert.equal((await a1.get("/api/exposure/v2/vulnerabilities?tier=P1")).body.total, v.facets.P1);
    assert.equal((await a1.get("/api/exposure/v2/vulnerabilities?severity=NOPE")).status, 400);
    assert.equal((await a1.get("/api/exposure/v2/vulnerabilities?sort=bogus")).status, 400);
  });

  test("trend: the daily history has today's row with the headline numbers", async () => {
    const tr = await a1.get("/api/exposure/v2/trend?days=30");
    assert.equal(tr.status, 200, JSON.stringify(tr.body));
    const t = tr.body, sum = (await a1.get("/api/exposure/v2/summary")).body;
    assert.equal(t.points.length, 1);
    assert.equal(t.points[0].p1, sum.headline.p1); assert.equal(t.points[0].hostsTotal, sum.hosts.total);
    assert.equal(t.points[0].critical, sum.severity.CRITICAL);
    assert.equal(t.startedAt, t.points[0].day);
    assert.equal(sum.headline.delta7, null, "a delta needs two days");
  });
});

describe("graph", () => {
  test("lens=fix: top fixes by P1, links are exact distinct hosts per group, payload under budget", async () => {
    const r = await a1.get("/api/exposure/graph?lens=fix");
    assert.equal(r.status, 200, JSON.stringify(r.body));
    const g = r.body;
    assert.ok(g.left.length > 0 && g.left.length <= 10 && g.right.length <= 8);
    assert.ok(JSON.stringify(g).length < 16 * 1024);
    const fixes = (await a1.get("/api/exposure/v2/fixes?tier=P1&pageSize=100")).body;
    assert.equal(g.totals.fixes, fixes.total, "the graph counts the same fixes as the list");
    assert.equal(g.left[0].p1, fixes.rows.find((x: any) => x.id === g.left[0].id).p1);
    assert.equal(g.totals.hosts, (await a1.get("/api/exposure/v2/summary")).body.headline.hostsWithP1);
    // exact cells: brute force from the mock and the inventory
    const inv = new Map(devices(CID_ONE).map((d) => [d.device_id, d]));
    const groupName = (id: string) => mock.data.hostGroups.find((x) => x.id === id)!.name;
    for (const [li, ri, n] of g.links) {
      const fixId = g.left[li].id, grp = g.right[ri].id;
      const hosts = new Set<string>();
      const sets = await dbm.all<{ aid: string }>("SELECT aid FROM roll_fix_host WHERE cid = ? AND fix_id = ? AND p1 > 0", CID_ONE, Number(fixId));
      for (const x of sets) if ((inv.get(x.aid)?.groups ?? []).map(groupName).includes(grp)) hosts.add(x.aid);
      assert.equal(n, hosts.size, `${fixId} x ${grp}`);
    }
    assert.ok(g.links.every(([a, b]: number[]) => a < g.left.length && b < g.right.length));
    assert.deepEqual(g.right.map((x: any) => x.hosts), [...g.right.map((x: any) => x.hosts)].sort((a: number, b: number) => b - a));
  });

  test("filters (tier, KEV, internet), a chosen group turns the right column into hosts, bad values are refused", async () => {
    const p12 = (await a1.get("/api/exposure/graph?lens=fix&tier=P1,P2")).body, p1 = (await a1.get("/api/exposure/graph?lens=fix")).body;
    assert.ok(p12.totals.findings >= p1.totals.findings && p12.totals.hosts >= p1.totals.hosts);
    const kev = (await a1.get("/api/exposure/graph?lens=fix&kev=1")).body;
    assert.ok(kev.totals.findings <= p1.totals.findings && kev.left.every((x: any) => x.kev > 0));
    const grp = (await a1.get(`/api/exposure/graph?lens=fix&group=${encodeURIComponent("Servers")}`)).body;
    assert.equal(grp.mode, "host");
    assert.ok(grp.right.length <= 12 && grp.right.every((x: any) => x.id && x.label));
    assert.ok(grp.totals.hosts <= p1.totals.hosts);
    for (const bad of ["tier=P3", "tier=P2", "kev=x", "by=nope", "lens=nope"]) assert.equal((await a1.get(`/api/exposure/graph?lens=${bad.startsWith("lens") ? "nope" : "fix"}&${bad}`)).status, 400, bad);
  });

  test("lens=matrix, lens=focus (fix, product, cve, host), list, search and meta", async () => {
    const m = (await a1.get("/api/exposure/graph?lens=matrix")).body;
    assert.ok(m.rows.length > 0 && m.rows.length <= 12 && m.cols.length <= 8);
    assert.ok(m.rows.every((r: any) => r.cells.length === m.cols.length));
    assert.ok(JSON.stringify(m).length < 8 * 1024);
    const fx = (await a1.get("/api/exposure/graph?lens=fix")).body.left[0];
    const f = (await a1.get(`/api/exposure/graph?lens=focus&type=fix&id=${fx.id}`)).body;
    assert.equal(f.center.hosts, fx.hosts); assert.ok(f.left.length > 0 && f.left.every((x: any) => x.kind === "cve"));
    const cveId = f.left[0].id;
    const c = (await a1.get(`/api/exposure/graph?lens=focus&type=cve&id=${cveId}`)).body;
    assert.equal(c.center.id, cveId); assert.ok(c.left.some((x: any) => x.id === fx.id), "the CVE's fixes include the fix we came from");
    const p = (await a1.get(`/api/exposure/graph?lens=focus&type=product&id=${encodeURIComponent(m.rows[0].id)}`)).body;
    assert.equal(p.center.id, m.rows[0].id);
    const aid = (await a1.get("/api/exposure/v2/hosts?tier=P1&pageSize=1")).body.rows[0].aid;
    const h = (await a1.get(`/api/exposure/graph?lens=focus&type=host&id=${aid}`)).body;
    assert.equal(h.center.id, aid); assert.ok(h.left.length > 0);
    for (const x of [f, c, p, h]) assert.ok(JSON.stringify(x).length < 12 * 1024);
    const list = (await a1.get(`/api/exposure/graph/list?kind=host&type=fix&id=${fx.id}`)).body;
    assert.equal(list.total, fx.hosts); assert.ok(list.rows.length <= 50 && list.rows.every((r: any) => r.aid && "watched" in r));
    assert.equal((await a1.get("/api/exposure/graph/list?kind=fix")).body.total, (await a1.get("/api/exposure/v2/fixes?tier=P1")).body.total);
    assert.ok((await a1.get(`/api/exposure/graph/list?kind=hostCves&id=${aid}`)).body.total > 0);
    const sr = (await a1.get(`/api/exposure/graph/search?q=${encodeURIComponent(cveId.slice(0, 8))}`)).body;
    assert.ok(sr.items.some((x: any) => x.kind === "cve") && JSON.stringify(sr).length < 3 * 1024);
    assert.deepEqual((await a1.get("/api/exposure/graph/search?q=a")).body.items, []);
    const meta = (await a1.get("/api/exposure/graph/meta")).body;
    assert.deepEqual(meta.groups.map((x: any) => x.label), mock.data.hostGroups.map((x) => x.name).sort(dbm.nameOrder.compare), "group names, Thai dictionary order");
    assert.equal(meta.dims.group, true); assert.equal(meta.tiers.P3, true);
    assert.ok(JSON.stringify(meta).length < 6 * 1024);
  });

  test("the old graph (no lens) still answers with its old shape", async () => {
    const old = (await a1.get("/api/exposure/graph")).body;
    assert.ok(Array.isArray(old.cves) && Array.isArray(old.devices) && old.totals);
  });
});

describe("tenant isolation and roles", () => {
  const paths = (cid: string, aid: string) => [
    "/api/exposure/v2/summary", "/api/exposure/v2/trend", "/api/exposure/v2/fixes", "/api/exposure/v2/hosts", "/api/exposure/v2/vulnerabilities", `/api/exposure/v2/hosts/${aid}`,
    "/api/exposure/graph?lens=fix", "/api/exposure/graph?lens=matrix", "/api/exposure/graph/meta", "/api/exposure/graph/search?q=CVE", "/api/exposure/graph/list?kind=fix",
    "/api/exposure/v2/fixes.csv", "/api/exposure/v2/hosts.csv", "/api/exposure/v2/vulnerabilities.csv",
  ].map((p) => p);
  test("a customer of Beta cannot name Alpha's tenant on any v2 endpoint (404, same as a missing one)", async () => {
    const aid = (await a1.get("/api/exposure/v2/hosts?pageSize=1")).body.rows[0].aid;
    for (const p of paths(CID_ONE, aid)) {
      const r = await b1.raw(`${p}${p.includes("?") ? "&" : "?"}tenantId=${ids.ta}`);
      assert.equal(r.status, 404, p);
    }
    assert.equal((await b1.raw(`/api/exposure/v2/fixes/1?tenantId=${ids.ta}`)).status, 404);
  });
  test("an aid of another tenant is a 404 on the host drawer, the graph focus and the graph list", async () => {
    const bAid = (await b1.get("/api/exposure/v2/hosts?pageSize=1")).body.rows[0].aid;
    assert.equal((await a1.get(`/api/exposure/v2/hosts/${bAid}`)).status, 404);
    assert.equal((await a1.get(`/api/exposure/graph?lens=focus&type=host&id=${bAid}`)).status, 404);
    assert.equal((await a1.get(`/api/exposure/graph/list?kind=hostCves&id=${bAid}`)).status, 404);
    assert.equal((await a1.get("/api/exposure/v2/fixes/999999999")).status, 404);
    assert.equal((await a1.get("/api/exposure/v2/fixes/abc")).status, 404);
    const a = (await a1.get("/api/exposure/v2/hosts?pageSize=100")).body.rows.map((x: any) => x.aid);
    assert.ok(!a.includes(bAid));
    const alpha = JSON.stringify([(await a1.get("/api/exposure/v2/hosts?pageSize=100")).body, (await a1.get("/api/exposure/v2/fixes?pageSize=100")).body, (await a1.get("/api/exposure/graph?lens=fix")).body]);
    for (const d of devices(CID_TWO)) assert.ok(!alpha.includes(d.device_id), "no host of Beta in Alpha's answers");
  });
  test("customers never get a CID; a super admin does; the CSV files follow", async () => {
    for (const p of ["/api/exposure/v2/summary", "/api/exposure/v2/hosts", "/api/exposure/v2/fixes", "/api/exposure/v2/vulnerabilities", "/api/exposure/graph?lens=fix", "/api/exposure/graph/list?kind=host", "/api/exposure/graph/meta"]) {
      const r = await a1.raw(p), t = await r.text();
      assert.ok(!t.includes(CID_ONE) && !t.includes(CID_TWO), p);
    }
    for (const p of ["/api/exposure/v2/hosts.csv", "/api/exposure/v2/fixes.csv"]) assert.ok(!(await (await a1.raw(p)).text()).includes(CID_ONE), p);
    const sh = (await admin.get(`/api/exposure/v2/hosts${A()}&pageSize=1`)).body.rows[0];
    assert.equal(sh.cid, CID_ONE); assert.equal(sh.key, `${CID_ONE}/${sh.aid}`);
    assert.equal(((await (await admin.raw(`/api/exposure/v2/hosts.csv${A()}`)).text()).split("\n")[0]).replace("﻿", "").split(",")[0], "cid");
  });
  test("a super admin must name the organization; a member of two names one; 'all organizations' has no graph", async () => {
    for (const c of [admin, soc]) for (const p of ["/api/exposure/v2/summary", "/api/exposure/v2/fixes", "/api/exposure/graph?lens=fix"]) {
      const r = await c.get(p); assert.equal(r.status, 400, p); assert.equal(r.body.code, "tenant_required");
    }
    assert.equal((await soc.get(`/api/exposure/v2/summary?tenantId=${ids.tb}`)).status, 200);
  });
  test("the portfolio is for super admins only", async () => {
    for (const c of [a1, b1, soc]) assert.equal((await c.get("/api/exposure/portfolio")).status, 403);
    const r = await admin.get("/api/exposure/portfolio");
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(r.body.tenants.map((x: any) => x.name).sort(), ["Alpha Corp", "Beta Ltd"]);
    const a = r.body.tenants.find((x: any) => x.name === "Alpha Corp");
    const sum = (await admin.get(`/api/exposure/v2/summary${A()}`)).body;
    assert.deepEqual([a.p1, a.hostsWithP1, a.hosts, a.state, a.level], [sum.headline.p1, sum.headline.hostsWithP1, sum.hosts.total, "complete", sum.headline.level.key], "the portfolio row is the tenant's summary");
    assert.equal(r.body.summary.tenants, 2); assert.equal(r.body.summary.byState.complete, 2);
    assert.ok("sync24h" in a && Array.isArray(a.sync24h) && a.sync24h.length >= 1);
    assert.ok(r.body.attention.length === 0 || r.body.attention.every((x: any) => x.reasons.length));
  });
});

describe("exports", () => {
  test("CSV: scoped, one row per fix, BOM, headers, formula injection neutralised", async () => {
    const hosts = await dbm.all<{ aid: string }>("SELECT aid FROM hosts WHERE cid = ? ORDER BY aid LIMIT 1", CID_ONE);
    await dbm.run("UPDATE hosts SET hostname = ? WHERE cid = ? AND aid = ?", "=cmd|' /C calc'!A0", CID_ONE, hosts[0].aid);
    const r = await a1.raw("/api/exposure/v2/hosts.csv");
    assert.equal(r.status, 200);
    assert.match(r.headers.get("content-type") ?? "", /text\/csv/);
    assert.match(r.headers.get("content-disposition") ?? "", /attachment; filename="hosts-alpha-corp-\d{4}-\d{2}-\d{2}\.csv"/);
    const body = await r.text();
    assert.deepEqual([...new Uint8Array(await (await a1.raw("/api/exposure/v2/hosts.csv")).arrayBuffer()).slice(0, 3)], [0xef, 0xbb, 0xbf], "UTF-8 BOM (Excel opens Thai correctly)");
    const lines = body.trim().split("\r\n");
    assert.equal(lines.length - 1, devices(CID_ONE).length + 0, "one row per host of the inventory");
    assert.equal(Number(r.headers.get("x-total-rows")), devices(CID_ONE).length);
    assert.ok(lines.some((l) => l.includes(`"'=cmd|' /C calc'!A0"`) || l.includes("'=cmd|")), "the formula is neutralised");
    assert.ok(!lines.some((l) => l.startsWith("=") || l.includes(",=cmd")));
    const f = await (await a1.raw("/api/exposure/v2/fixes.csv")).text();
    assert.equal(f.trim().split("\r\n").length - 1, (await a1.get("/api/exposure/v2/fixes")).body.total);
    const top = (await a1.get("/api/exposure/v2/fixes")).body.rows[0];
    const hc = await (await a1.raw(`/api/exposure/v2/fixes/${top.id}/hosts.csv`)).text();
    assert.equal(hc.trim().split("\r\n").length - 1, top.hosts, "the IT hand-off has one row per host of the fix");
    const vc = await a1.raw("/api/exposure/v2/vulnerabilities.csv?tier=P1");
    assert.equal((await vc.text()).trim().split("\r\n").length - 1, Number(vc.headers.get("x-total-rows")));
    assert.equal((await a1.raw("/api/exposure/v2/hosts.csv?seen=bogus")).status, 400);
    const aud = await dbm.all("SELECT 1 FROM audit WHERE action LIKE 'export:%' AND actor_email = 'alice@alpha.test'");
    assert.ok(aud.length >= 3, "customer exports are audited");
  });
});

describe("list-page additions: software risk, hosts by CVE, the v2 CVE drawer", () => {
  const p1Cves = (prefix: string) => new Set(endpointRows(CID_ONE).filter((f) => tierOf(f) === 1 && (f.apps?.[0]?.product_name_version ?? "").startsWith(prefix)).map((f) => f.cve.id));
  test("software: P1 and KEV CVEs per item (matched by product name), sort=risk, p1/kev filters, CSV, scope", async () => {
    const r = await a1.get("/api/exposure/software?pageSize=100");
    assert.equal(r.status, 200, JSON.stringify(r.body));
    const chrome = r.body.rows.find((x: any) => x.name === "Google Chrome");
    assert.ok(chrome && chrome.p1Cves === p1Cves("Google Chrome").size, `p1Cves ${chrome?.p1Cves} vs ${p1Cves("Google Chrome").size}`);
    assert.equal(chrome.kevCves, [...p1Cves("Google Chrome")].filter((c) => KEVS.has(c)).length);
    assert.ok(r.body.rows.every((x: any) => Number.isInteger(x.p1Cves) && Number.isInteger(x.kevCves)));
    const risk = (await a1.get("/api/exposure/software?sort=risk&pageSize=100")).body;
    assert.deepEqual(risk.rows.map((x: any) => x.p1Cves), [...risk.rows.map((x: any) => x.p1Cves)].sort((a: number, b: number) => b - a), "P1 CVEs first");
    const only = (await a1.get("/api/exposure/software?p1=1&pageSize=100")).body;
    assert.ok(only.total > 0 && only.total < r.body.total && only.rows.every((x: any) => x.p1Cves > 0));
    assert.ok((await a1.get("/api/exposure/software?kev=1&pageSize=100")).body.rows.every((x: any) => x.kevCves > 0));
    assert.equal((await a1.get("/api/exposure/software?p1=2")).status, 400);
    assert.equal((await a1.get("/api/exposure/software?sort=nope")).status, 400);
    const csv = await a1.raw("/api/exposure/software.csv?p1=1");
    assert.equal(csv.status, 200);
    const lines = (await csv.text()).trim().split("\r\n");
    assert.equal(lines.length - 1, only.total); assert.ok(lines[0].includes("p1_cves") && !lines[0].startsWith("cid"));
    assert.ok(!lines.join("\n").includes(CID_ONE));
    assert.equal((await b1.raw(`/api/exposure/software.csv?tenantId=${ids.ta}`)).status, 404);
  });
  test("hosts list: ?cve= keeps the hosts that have that CVE (and only this tenant's)", async () => {
    const cve = [...p1Cves("")][0];
    const want = new Set(endpointRows(CID_ONE).filter((f) => f.cve.id === cve).map((f) => f.aid));
    const r = (await a1.get(`/api/exposure/v2/hosts?cve=${cve}&pageSize=100`)).body;
    assert.equal(r.total, want.size); assert.ok(r.rows.every((x: any) => want.has(x.aid)));
    assert.equal((await a1.get("/api/exposure/v2/hosts?cve=not%20a%20cve")).status, 400);
    assert.equal((await b1.get(`/api/exposure/v2/hosts?cve=${cve}&tenantId=${ids.ta}`)).status, 404);
  });
  test("v2 CVE drawer: tier, why, KEV, fixes, versions and hosts in one call; completeness; unknown CVE is found:false; foreign tenant 404", async () => {
    const cve = [...p1Cves("")].find((c) => KEVS.has(c)) ?? [...p1Cves("")][0];
    const d = (await a1.get(`/api/exposure/v2/vulnerabilities/${cve}`)).body;
    const rows = endpointRows(CID_ONE).filter((f) => f.cve.id === cve);
    assert.equal(d.found, true); assert.equal(d.tier, "P1"); assert.ok(d.whyTier.length > 0);
    assert.equal(d.hosts, new Set(rows.map((f) => f.aid)).size); assert.equal(d.findings, rows.length);
    assert.equal(d.hostsList.total, d.hosts); assert.ok(d.fixes.length > 0 && d.versions.length > 0 && d.completeness.state);
    assert.equal(d.kev, KEVS.has(cve));
    assert.equal(d.versions.reduce((a: number, v: any) => a + v.hosts, 0) >= d.hosts, true);
    assert.deepEqual((await a1.get("/api/exposure/v2/vulnerabilities/CVE-1999-0001")).body.found, false);
    assert.equal((await b1.get(`/api/exposure/v2/vulnerabilities/${cve}?tenantId=${ids.ta}`)).status, 404);
    assert.ok(!JSON.stringify(d).includes(CID_ONE));
    const fix = (await a1.get(`/api/exposure/v2/fixes/${d.fixes[0].id}`)).body;
    assert.ok(fix.completeness.state, "the fix drawer carries completeness");
  });
});

describe("what changes in Falcon", () => {
  test("a finding that Falcon expired leaves the data like a closed one, and the counts follow", async () => {
    const before = (await a1.get("/api/exposure/v2/summary?x=exp")).body;
    const victim = endpointRows(CID_ONE).find((f) => tierOf(f) === 1)!;
    mock.touch(victim, "expired");
    await runSync(ids.ta);
    assert.equal((await dbm.all("SELECT 1 FROM findings_t WHERE cid = ? AND finding_id = ?", CID_ONE, victim.id)).length, 0, "the expired finding is gone");
    assert.equal((await dbm.all("SELECT 1 FROM finding_closed WHERE cid = ? AND finding_id = ?", CID_ONE, victim.id)).length, 1, "and recorded as closed");
    const after_ = (await a1.get("/api/exposure/v2/summary?x=exp2")).body;
    assert.equal(after_.headline.p1, before.headline.p1 - 1);
    assert.equal(after_.tiers.P1.total, before.tiers.P1.total - 1, "Falcon's exact P1 count dropped too");
  });
  test("a suppressed finding stays stored but is in no tier and no count", async () => {
    const victim = endpointRows(CID_ONE).find((f) => tierOf(f) === 2)!;
    const before = (await a1.get("/api/exposure/v2/summary?x=sup")).body;
    victim.suppression_info = { is_suppressed: true };
    mock.touch(victim);
    await runSync(ids.ta);
    assert.equal((await dbm.get<any>("SELECT suppressed FROM findings_t WHERE cid = ? AND finding_id = ?", CID_ONE, victim.id))!.suppressed, 1);
    const after_ = (await a1.get("/api/exposure/v2/summary?x=sup2")).body;
    assert.equal(after_.tiers.P2.held, before.tiers.P2.held - 1);
    assert.equal(after_.tiers.P2.held, before.tiers.P2.held - 1);
    assert.equal(after_.tiers.suppressedIncluded, 1, "Falcon's own tier totals still count it, and the page says by how many");
  });
  test("a failed inventory read keeps the old inventory and says so; a complete one replaces it (a host that left is gone)", async () => {
    const total = devices(CID_ONE).length;
    mock.fail("/devices/combined/devices/v1", 500, 99);
    await runSync(ids.ta);
    mock.clearFailures();
    const s = (await a1.get("/api/exposure/v2/summary?x=hs")).body;
    assert.equal(s.hosts.total, total, "nothing was wiped");
    assert.equal((await dbm.get<any>("SELECT state, as_of FROM hosts_sync WHERE cid = ?", CID_ONE))!.state, "failed");
    const gone = [...mock.data.devices.values()].find((d) => d.cid === CID_ONE && /^QUIET-/.test(d.hostname))!;
    mock.data.devices.delete(gone.device_id);
    await runSync(ids.ta);
    assert.equal((await a1.get("/api/exposure/v2/summary?x=hs2")).body.hosts.total, total - 1);
    assert.equal((await dbm.get<any>("SELECT state FROM hosts_sync WHERE cid = ?", CID_ONE))!.state, "complete");
  });
});

describe("level (design-spec 4.2)", () => {
  test("the share of hosts with a P1 sets the level; an overdue KEV on an internet-facing host raises it one step, up to critical", () => {
    const k = (s: number, e = false) => ov.levelOf(s, e).key;
    assert.deepEqual([k(0), k(0.049), k(0.05), k(0.199), k(0.2), k(0.599), k(0.6), k(1)], ["low", "low", "medium", "medium", "high", "high", "critical", "critical"]);
    assert.deepEqual([k(0.01, true), k(0.1, true), k(0.3, true), k(0.7, true)], ["medium", "high", "critical", "critical"]);
    assert.deepEqual(ov.levelOf(0.7, true), { key: "critical", base: "critical", escalated: false, share: 0.7, reasons: ["kev_overdue_internet"] });
  });
});
