// Watchlist, notification settings, CVE news matching and EASM extras. Rows are seeded straight into the database (no Falcon mock): what is under test is what the
// organization sees and what LINE is told. Every endpoint is also tried as another organization's user.
import { testDatabaseUrl } from "./test-db.ts";
process.env.TENIX_DATABASE_URL = testDatabaseUrl();
process.env.TENIX_DB_SCHEMA = `t_${Math.random().toString(36).slice(2, 10)}`;
process.env.TENIX_SECRET_KEY = Buffer.alloc(32, 7).toString("base64");
process.env.TENIX_DEV_FALCON_URL_OK = "1";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { after, before, describe, test } from "node:test";

const { createApp } = await import("../src/http.ts");
await import("../src/auth.ts");
await import("../src/team.ts");
await import("../src/exposure.ts");
const line = await import("../src/line.ts");
const falcon = await import("../src/falcon.ts");
const feeds = await import("../src/feeds.ts");
const news = await import("../src/news.ts");
await import("../src/watch.ts");
await import("../src/notify.ts");
await import("../src/easm.ts");
const dbm = await import("../src/db.ts");
const crypto = await import("../src/crypto.ts");
const { refreshRollups } = await import("../src/rollup.ts");
feeds.feedHooks.fetch = async () => new Response("", { status: 404 }); // no CVE Program in these tests

const PW = "correct-horse-battery-1";
let base = "";
const servers: { close: () => void }[] = [];
class Client {
  jar = new Map<string, string>();
  async req(method: string, path: string, body?: unknown) {
    const h: Record<string, string> = {};
    if (body !== undefined) h["Content-Type"] = "application/json";
    if (this.jar.size) h.Cookie = [...this.jar].map(([k, v]) => `${k}=${v}`).join("; ");
    const r = await fetch(base + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
    for (const sc of r.headers.getSetCookie()) { const [kv] = sc.split(";"); const i = kv.indexOf("="); const v = kv.slice(i + 1); if (/Max-Age=0/.test(sc) || !v) this.jar.delete(kv.slice(0, i)); else this.jar.set(kv.slice(0, i), v); }
    return { status: r.status, body: (await r.json().catch(() => null)) as any };
  }
  get = (p: string) => this.req("GET", p);
}
async function adopt(email: string, role: "super_admin" | "member", memberships: { tenantId: string; role: "admin" | "operator" }[] = []) {
  const raw = crypto.token();
  await dbm.run("INSERT INTO invites (id, email, role, memberships_json, kind, token_hash, expires_at, created_at) VALUES (?,?,?,?,?,?,?,?)", crypto.uuid(), email, role, JSON.stringify(memberships), "invite", crypto.sha256(raw), Date.now() + 1e6, Date.now());
  const c = new Client();
  assert.equal((await c.req("POST", `/api/invites/${raw}/accept`, { name: email.split("@")[0], password: PW })).status, 200);
  return c;
}

const hex = (n: number, ch = "a") => n.toString(16).padStart(32, ch);
const CID = { A: hex(1, "1"), B: hex(2, "2"), C: hex(3, "3"), D: hex(4, "4") };
const T: Record<string, string> = {};
const HOST = { a1: hex(0xa1), a2: hex(0xa2), a3: hex(0xa3), b1: hex(0xb1) };
const NAME: Record<string, string> = { [HOST.a1]: "ALPHA-WEB-01", [HOST.a2]: "ALPHA-DB-02", [HOST.a3]: "ALPHA-PC-03", [HOST.b1]: "BETA-SECRET-01" };
let n = 0;
async function finding(cid: string, aid: string, cve: string, severity: string, o: { first?: number; exprt?: string; exploit?: number; provider?: string } = {}) {
  await dbm.run(`INSERT INTO findings_t (cid, finding_id, aid, cve_id, severity, base_score, exprt, exploit_status, hostname, platform, status, synced_at, first_seen, provider, product) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    cid, `f${++n}`, aid, cve, severity, 7.5, o.exprt ?? null, o.exploit ?? null, NAME[aid] ?? "host", "Windows", "open", Date.now(), o.first ?? Date.now() - 40 * 86400_000, o.provider ?? null, "Example 1.0");
}
const status = (cid: string, asOf = Date.now() + 60_000) => dbm.run(`INSERT INTO cid_status (cid, state, detail_json, data_as_of, last_run_at) VALUES (?,?,?,?,?) ON CONFLICT (cid) DO UPDATE SET state = excluded.state, data_as_of = excluded.data_as_of`, cid, "complete", "[]", asOf, Date.now());

let admin: Client, aAdmin: Client, aOp: Client, bAdmin: Client, bOp: Client, cOp: Client;

before(async () => {
  const s = createApp();
  await new Promise<void>((ok) => s.listen(0, "127.0.0.1", ok));
  base = `http://127.0.0.1:${(s.address() as AddressInfo).port}`;
  servers.push(s);
  for (const k of ["A", "B", "C", "D"] as const) {
    T[k] = crypto.uuid();
    await dbm.run("INSERT INTO tenants (id, name, created_at) VALUES (?,?,?)", T[k], `Org ${k}`, Date.now());
    await dbm.run("INSERT INTO tenant_cids (cid, tenant_id) VALUES (?,?)", CID[k], T[k]);
  }
  admin = await adopt("admin@x.test", "super_admin");
  aAdmin = await adopt("amy@a.test", "member", [{ tenantId: T.A, role: "admin" }]);
  aOp = await adopt("alice@a.test", "member", [{ tenantId: T.A, role: "operator" }]);
  bAdmin = await adopt("bea@b.test", "member", [{ tenantId: T.B, role: "admin" }]);
  bOp = await adopt("bob@b.test", "member", [{ tenantId: T.B, role: "operator" }]);
  cOp = await adopt("cy@c.test", "member", [{ tenantId: T.C, role: "operator" }]);
  // Alpha: three hosts. CVE-1111 on all three (Critical on a1 and a2, High on a3), CVE-2222 Critical on a1 only, one brand-new Critical on a2.
  await finding(CID.A, HOST.a1, "CVE-2026-1111", "CRITICAL"); await finding(CID.A, HOST.a1, "CVE-2026-2222", "CRITICAL");
  await finding(CID.A, HOST.a2, "CVE-2026-1111", "CRITICAL", { first: Date.now() - 3600_000 }); await finding(CID.A, HOST.a3, "CVE-2026-1111", "HIGH");
  await finding(CID.A, HOST.a3, "CVE-2026-3333", "LOW");
  await finding(CID.B, HOST.b1, "CVE-2026-9999", "CRITICAL");
  for (const k of ["A", "B", "C", "D"] as const) { await status(CID[k], k === "D" ? 1000 : Date.now() + 60_000); await refreshRollups(CID[k]); }
});
after(async () => {
  servers.forEach((s) => s.close());
  await dbm.pool.query(`DROP SCHEMA ${process.env.TENIX_DB_SCHEMA} CASCADE`);
  await dbm.pool.end();
});

describe("watchlist", () => {
  test("add, note, list with live numbers, remove; any member may write", async () => {
    assert.equal((await aOp.req("PUT", `/api/exposure/watchlist/${HOST.a1}`, { note: "front door" })).status, 200);
    const r = await aAdmin.req("PUT", `/api/exposure/watchlist/${HOST.a2}`, {});
    assert.equal(r.status, 200);
    assert.equal(r.body.count, 2);
    const l = (await aOp.get("/api/exposure/watchlist")).body;
    assert.equal(l.canEdit, true);
    assert.deepEqual(l.hosts.map((h: any) => h.hostname), ["ALPHA-DB-02", "ALPHA-WEB-01"], "new first (a2 has a Critical from the last hour), then P1");
    const a1 = l.hosts.find((h: any) => h.aid === HOST.a1);
    assert.deepEqual([a1.note, a1.worstSeverity, a1.p1, a1.addedBy, a1.missing], ["front door", "CRITICAL", 2, "alice", false]);
    const a2 = l.hosts.find((h: any) => h.aid === HOST.a2);
    assert.deepEqual([a2.newFindings24h, a2.newCritical24h, a2.newP1_24h], [1, 1, 1]);
    // a PUT without a note keeps the note; with one it replaces it
    await aAdmin.req("PUT", `/api/exposure/watchlist/${HOST.a1}`, {});
    assert.equal((await aOp.get("/api/exposure/watchlist")).body.hosts.find((h: any) => h.aid === HOST.a1).note, "front door");
    assert.equal((await aOp.req("PUT", `/api/exposure/watchlist/${HOST.a1}`, { note: "x".repeat(201) })).status, 400);
    assert.equal((await aOp.req("DELETE", `/api/exposure/watchlist/${HOST.a2}`, {})).body.count, 1);
    assert.deepEqual((await aOp.req("DELETE", `/api/exposure/watchlist/${HOST.a2}`, {})).body.removed, false);
    assert.ok((await dbm.get("SELECT 1 FROM audit WHERE action = 'watch.add' AND tenant_id = ?", T.A)));
  });

  test("a host of another organization, or an unknown one, is a 404 and nothing is stored", async () => {
    assert.equal((await aOp.req("PUT", `/api/exposure/watchlist/${HOST.b1}`, {})).status, 404);
    assert.equal((await aOp.req("PUT", `/api/exposure/watchlist/${hex(0xdead)}`, {})).status, 404);
    assert.equal((await aOp.req("PUT", "/api/exposure/watchlist", { aids: [HOST.a3, HOST.b1] })).status, 404);
    assert.equal((await dbm.get<{ n: number }>("SELECT COUNT(*) n FROM watch_hosts WHERE aid = ? OR aid = ?", HOST.b1, HOST.a3))!.n, 0, "bulk is all or nothing");
    assert.equal((await aOp.req("PUT", "/api/exposure/watchlist", { aids: [HOST.a3] })).body.added, 1);
    await aOp.req("DELETE", `/api/exposure/watchlist/${HOST.a3}`, {});
  });

  test("another organization never sees or changes the list; ?tenantId= of a foreign tenant is 404", async () => {
    assert.equal((await bOp.get(`/api/exposure/watchlist?tenantId=${T.A}`)).status, 404);
    assert.equal((await bOp.req("PUT", `/api/exposure/watchlist/${HOST.a1}?tenantId=${T.A}`, {})).status, 404);
    assert.equal((await bOp.req("DELETE", `/api/exposure/watchlist/${HOST.a1}?tenantId=${T.A}`, {})).status, 404);
    assert.equal((await bOp.get("/api/exposure/watchlist")).body.hosts.length, 0);
    assert.equal((await bOp.req("DELETE", `/api/exposure/watchlist/${HOST.a1}`, {})).body.removed, false, "B cannot remove A's host by guessing the aid");
    assert.equal((await aOp.get("/api/exposure/watchlist")).body.hosts.length, 1);
    assert.equal((await admin.get("/api/exposure/watchlist")).status, 400, "the SOC must name a tenant");
    assert.equal((await admin.get(`/api/exposure/watchlist?tenantId=${T.A}`)).body.hosts.length, 1);
    assert.equal((await new Client().get("/api/exposure/watchlist")).status, 401);
  });

  test("empty list suggests hosts; the 200 limit; auto items carry new Criticals", async () => {
    const empty = (await cOp.get("/api/exposure/watchlist")).body;
    assert.deepEqual([empty.hosts, empty.suggestions], [[], []], "an organization with no findings has nothing to suggest");
    const sug = (await bOp.get("/api/exposure/watchlist")).body.suggestions;
    assert.deepEqual(sug.map((x: any) => x.hostname), ["BETA-SECRET-01"]);
    const auto = (await aOp.get("/api/exposure/watchlist")).body.auto;
    assert.ok(auto.some((x: any) => x.type === "critical_new" && x.findings === 1 && x.devices === 1), JSON.stringify(auto));
    assert.ok(!JSON.stringify(auto).includes("BETA"), "no other organization in the items");
    for (let i = 0; i < 198; i++) await dbm.run("INSERT INTO watch_hosts (tenant_id, aid, cid, note, added_at, updated_at) VALUES (?,?,?,?,?,?)", T.A, `fake-${String(i).padStart(6, "0")}`, CID.A, "", 1, 1);
    assert.equal((await aOp.req("PUT", `/api/exposure/watchlist/${HOST.a2}`, {})).body.count, 200);
    assert.equal((await aOp.req("PUT", `/api/exposure/watchlist/${HOST.a3}`, {})).status, 409);
    await dbm.run("DELETE FROM watch_hosts WHERE tenant_id = ? AND aid LIKE 'fake-%'", T.A);
    await dbm.run("DELETE FROM watch_hosts WHERE tenant_id = ? AND aid <> ?", T.A, HOST.a1);
  });
});

describe("notification settings and LINE delivery", () => {
  test("GET shows defaults; only an admin of the tenant (or super admin) may change; other tenants cannot even read", async () => {
    const g = (await aOp.get(`/api/tenants/${T.A}/notify`)).body;
    assert.deepEqual([g.isDefault, g.canEdit, g.prefs.devicesMode, g.prefs.topN, g.prefs.severities.length, g.watchedCount], [true, false, "all", 10, 5, 1]);
    assert.equal((await aOp.req("PUT", `/api/tenants/${T.A}/notify`, { topN: 5 })).status, 404);
    assert.equal((await bAdmin.req("PUT", `/api/tenants/${T.A}/notify`, { topN: 5 })).status, 404);
    assert.equal((await bOp.get(`/api/tenants/${T.A}/notify`)).status, 404);
    for (const bad of [{ severities: [] }, { severities: ["BAD"] }, { devicesMode: "some" }, { topN: 0 }, { topN: 101 }, { maxNames: 51 }, { enabled: "yes" }])
      assert.equal((await aAdmin.req("PUT", `/api/tenants/${T.A}/notify`, bad)).status, 400, JSON.stringify(bad));
    assert.equal((await aAdmin.req("PUT", `/api/tenants/${T.A}/notify`, { severities: ["CRITICAL"], devicesMode: "top", topN: 2 })).body.isDefault, false);
    assert.equal((await dbm.get<{ n: number }>("SELECT COUNT(*) n FROM notify_prefs WHERE tenant_id = ?", T.B))!.n, 0, "another tenant has no row");
    assert.equal((await admin.req("PUT", `/api/tenants/${T.A}/notify`, { severities: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"], devicesMode: "all", topN: 10 })).body.canEdit, true);
    await dbm.run("DELETE FROM notify_prefs WHERE tenant_id = ?", T.A);
  });

  // news in a SOC chat that names CVE-2026-1111 (Alpha: 3 devices, Critical) and CVE-2026-3333 (Alpha: only a Low) is answered to Alpha's group and the SOC's
  const SOC = "Csoc000000000000000000000000000001", GA = "Cgroup0000000000000000000000000a", GB = "Cgroup0000000000000000000000000b", SRC = "Csrc0000000000000000000000000001";
  const sent: { to: string; text: string }[] = [];
  const cfg: any = { secret: "s", token: "t", sources: new Map([[SRC, null]]), allowedChats: [SRC], answerChats: [SOC], tenantDests: new Map(), chatNames: {}, forwardUrl: "" };
  before(async () => {
    line.hooks.line = async (_t, _m, _u, body: any) => { for (const m of body?.messages ?? []) sent.push({ to: body.to, text: JSON.stringify(m) }); return { ok: true, status: 200, data: Buffer.alloc(0) }; };
    await dbm.run("INSERT INTO line_chats (chat_id, role, tenant_id, created_at) VALUES (?, 'source', NULL, 1), (?, 'destination', NULL, 1), (?, 'destination', ?, 1), (?, 'destination', ?, 1)", SRC, SOC, GA, T.A, GB, T.B);
  });
  const post = async (cves: string) => {
    sent.length = 0;
    await Promise.all(await line.handleEvents([{ type: "message", webhookEventId: crypto.uuid(), source: { groupId: SRC }, message: { id: crypto.uuid(), type: "text", text: `news ${cves}` } }], cfg));
    return { a: sent.filter((x) => x.to === GA).map((x) => x.text).join(""), b: sent.filter((x) => x.to === GB).map((x) => x.text).join(""), soc: sent.filter((x) => x.to === SOC).map((x) => x.text).join("") };
  };
  const put = (b: object) => aAdmin.req("PUT", `/api/tenants/${T.A}/notify`, b);

  test("no row: exactly today's behaviour, and Beta's group never gets Alpha's names", async () => {
    const r = await post("CVE-2026-1111");
    for (const nm of Object.values(NAME).slice(0, 3)) assert.ok(r.a.includes(nm), nm);
    assert.ok(!r.a.includes("BETA-SECRET") && !r.b.includes("ALPHA"), "isolation");
    assert.ok(r.b.includes("ไม่พบเครื่องที่เกี่ยวข้อง") || r.b.length > 0);
  });

  test("severity off means no message for that organization; P1 always overrides for KEV; other organizations are untouched", async () => {
    await put({ severities: ["LOW"] });
    let r = await post("CVE-2026-1111");
    assert.equal(r.a, "", "Critical is off: no message to Alpha's group");
    assert.ok(r.b.length > 0, "Beta still gets its answer");
    assert.ok(r.soc.includes("ALPHA-WEB-01") || r.soc.includes("CVE-2026-1111"), "the SOC chat still gets the answer");
    r = await post("CVE-2026-3333");
    assert.ok(r.a.includes("ALPHA-PC-03"), "Low is on");
    await dbm.run("INSERT INTO kev (cve_id, first_seen_at) VALUES ('CVE-2026-1111', 1) ON CONFLICT DO NOTHING");
    r = await post("CVE-2026-1111");
    assert.ok(r.a.includes("ALPHA-WEB-01"), "KEV is P1: sent although Critical is not ticked");
    await put({ p1Always: false });
    assert.equal((await post("CVE-2026-1111")).a, "", "with P1 always off the tick decides");
    await put({ enabled: false, severities: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"] });
    assert.equal((await post("CVE-2026-1111")).a, "", "switched off");
    await put({ enabled: true, p1Always: true });
  });

  test("mode watched: empty list sends counts only; with a watched host only that host is named", async () => {
    await dbm.run("DELETE FROM watch_hosts WHERE tenant_id = ?", T.A);
    await put({ devicesMode: "watched" });
    let r = await post("CVE-2026-1111");
    assert.ok(r.a.includes("ไม่มีเครื่องที่เฝ้าอยู่ได้รับผลกระทบ") && !r.a.includes("ALPHA-WEB-01"), "counts only");
    assert.ok(r.a.includes('"text":"3"'), "the true device count is still there");
    await aOp.req("PUT", `/api/exposure/watchlist/${HOST.a3}`, {});
    r = await post("CVE-2026-1111");
    assert.ok(r.a.includes("ALPHA-PC-03") && !r.a.includes("ALPHA-WEB-01") && !r.a.includes("ALPHA-DB-02"));
  });

  test("mode top N: the most important devices (Critical CVEs, then CVE count), then maxNames cuts the rest", async () => {
    await put({ devicesMode: "top", topN: 1 });
    let r = await post("CVE-2026-1111");
    assert.ok(r.a.includes("ALPHA-WEB-01") && !r.a.includes("ALPHA-DB-02") && !r.a.includes("ALPHA-PC-03"), "a1 has two Critical CVEs");
    await put({ topN: 2 });
    r = await post("CVE-2026-1111");
    assert.ok(r.a.includes("ALPHA-WEB-01") && r.a.includes("ALPHA-DB-02") && !r.a.includes("ALPHA-PC-03"));
    await put({ devicesMode: "all", maxNames: 1 });
    r = await post("CVE-2026-1111");
    assert.ok(r.a.includes("และอีก 2 เครื่อง") && (r.a.match(/ALPHA-/g) ?? []).length >= 1 && !r.a.includes("ALPHA-PC-03"));
  });

  test("preview returns the cards the group would get, for this organization only; test needs a LINE group", async () => {
    await put({ devicesMode: "all", maxNames: 50 });
    const p = (await aAdmin.req("POST", `/api/tenants/${T.A}/notify/preview`, { devicesMode: "top", topN: 1 })).body;
    assert.equal(p.sample, false);
    const text = JSON.stringify(p.messages);
    assert.ok(text.includes("ALPHA-WEB-01") && !text.includes("ALPHA-PC-03") && !text.includes("BETA"));
    assert.equal((await aAdmin.req("POST", `/api/tenants/${T.A}/notify/preview`, { severities: ["LOW"], p1Always: false })).body.dropped, true, "its top CVE is Critical: nothing would be sent");
  });
  test("preview of an organization without findings is a sample; foreign preview is 404", async () => {
    const s = (await new Client().get("/")).status; void s;
    assert.equal((await bOp.req("POST", `/api/tenants/${T.A}/notify/preview`, {})).status, 404);
    assert.equal((await bOp.req("POST", `/api/tenants/${T.B}/notify/preview`, {})).status, 404, "an operator may not use the editing tools");
    const c = await adopt("cadmin@c.test", "member", [{ tenantId: T.C, role: "admin" }]);
    const p = (await c.req("POST", `/api/tenants/${T.C}/notify/preview`, {})).body;
    assert.deepEqual([p.sample, p.cve], [true, null]);
    assert.ok(JSON.stringify(p.messages).includes("ตัวอย่าง-PC-01"));
    assert.equal((await c.req("POST", `/api/tenants/${T.C}/notify/test`, {})).status, 400, "no LINE group");
  });
});

describe("CVE news per organization", () => {
  const SOC_SRC = "Cnews00000000000000000000000001", B_SRC = "Cnews0000000000000000000000000b";
  async function newsItem(chat: string, cves: string[], url = "https://example.org/a") {
    const id = crypto.uuid();
    await dbm.run("INSERT INTO news_items (id, received_at, kind, chat, text, urls_json) VALUES (?,?,?,?,?,?)", id, Date.now(), "text", chat, "x", JSON.stringify([url]));
    for (const c of cves) await dbm.run("INSERT INTO news_cves (news_id, cve_id, source) VALUES (?,?,'message')", id, c);
  }
  const calls: string[] = [];
  before(async () => {
    news.newsHooks.notify = async (t, cve, state, devices) => { calls.push(`${t}|${cve}|${state}|${devices}`); return true; };
    await dbm.run("INSERT INTO line_chats (chat_id, role, tenant_id, created_at) VALUES (?, 'source', NULL, 1), (?, 'source', ?, 1) ON CONFLICT DO NOTHING", SOC_SRC, B_SRC, T.B);
    // Beta runs a product named in the CVE record (a possible match); Delta's data is older than the news (cannot conclude)
    await dbm.run("INSERT INTO software_hosts (cid, host_id, aid, hostname) VALUES (?,?,?,?)", CID.B, "h1", HOST.b1, "BETA-SECRET-01");
    await dbm.run("INSERT INTO software (cid, id, host_id, type, name, vendor, version) VALUES (?,?,?,?,?,?,?)", CID.B, "s1", "h1", "application", "Acme Frobnicator 4.2", "Acme", "4.2");
    await dbm.run("INSERT INTO cve_public (id, state, ingested_at, affected_json, title) VALUES (?,?,?,?,?)", "CVE-2026-1111", "PUBLISHED", Date.now(), JSON.stringify([{ vendor: "Acme", product: "Frobnicator" }]), "Frobnicator RCE");
    await newsItem(SOC_SRC, ["CVE-2026-1111"]);
    await newsItem(B_SRC, ["CVE-2026-7777"]); // news Beta's own chat posted
    await dbm.run("INSERT INTO roll_cve (cid, src, cve_id, rank, hosts, findings, pri, exprt_rank, inet) VALUES (?, 'endpoint', 'CVE-2026-7777', 0, 1, 1, 1, 0, 0)", CID.A); // Alpha happens to have it too
  });

  test("states per organization: exact, possible (software name), not_affected, wait; deduped; the news of another organization's chat never reaches a tenant", async () => {
    await news.matchNews({ notify: false });
    const st = async (t: string, cve: string) => (await dbm.get<any>("SELECT state, devices FROM news_match WHERE tenant_id = ? AND cve = ?", T[t], cve));
    assert.deepEqual(await st("A", "CVE-2026-1111"), { state: "exact", devices: 3 });
    // Beta's findings do not have CVE-1111 and its read is newer than the news: only the software name keeps it from "not affected"
    assert.deepEqual(await st("B", "CVE-2026-1111"), { state: "possible", devices: 1 });
    assert.equal((await st("C", "CVE-2026-1111")).state, "not_affected");
    assert.equal((await st("D", "CVE-2026-1111")).state, "wait", "data older than the news cannot conclude");
    await news.matchNews({ notify: false });
    assert.equal((await dbm.get<{ n: number }>("SELECT COUNT(*) n FROM news_match WHERE cve = 'CVE-2026-1111'"))!.n, 4, "recomputing makes no second row");
    assert.equal(await st("A", "CVE-2026-7777"), undefined, "news from Beta's own chat is not Alpha's news, although Alpha has the CVE");
    assert.equal((await st("B", "CVE-2026-7777")).state, "not_affected", "Beta (its own chat, complete newer read, no such findings)");
  });

  test("customers see counts; possible only when allowed; host names only when allowed; the SOC sees everything", async () => {
    const a = (await aOp.get("/api/exposure/news")).body;
    const i1 = a.items.find((x: any) => x.cve === "CVE-2026-1111");
    assert.deepEqual([a.items.map((x: any) => x.cve).sort(), i1.state, i1.devices, i1.severity, a.counts.exact], [["CVE-2026-1111", "CVE-2026-3333"], "exact", 3, "CRITICAL", 2]); // 3333 came with the LINE tests above
    assert.equal(a.showHostNames, false);
    assert.ok(!JSON.stringify(a).includes("ALPHA-WEB"));
    const d = (await aOp.get("/api/exposure/news/CVE-2026-1111")).body;
    assert.deepEqual([d.hostsHidden, d.hosts, d.drawer, d.public.title], [true, null, "/api/exposure/vulnerabilities/CVE-2026-1111", "Frobnicator RCE"]);
    assert.equal((await aOp.get("/api/exposure/news/CVE-2026-7777")).status, 404, "Alpha has no news row for Beta's CVE");
    await aAdmin.req("PUT", `/api/tenants/${T.A}/notify`, { newsHostNames: true });
    assert.deepEqual((await aOp.get("/api/exposure/news/CVE-2026-1111")).body.hosts.map((h: any) => h.hostname).sort(), ["ALPHA-DB-02", "ALPHA-PC-03", "ALPHA-WEB-01"]);
    // Beta: possible is hidden by default
    const b = (await bOp.get("/api/exposure/news")).body;
    assert.ok(b.items.every((x: any) => x.state !== "possible") && b.counts.possible === 0);
    assert.equal((await bOp.get("/api/exposure/news/CVE-2026-1111")).status, 404);
    assert.equal((await bAdmin.req("PUT", `/api/tenants/${T.B}/notify`, { newsPossible: true })).status, 200);
    const b2 = (await bOp.get("/api/exposure/news?state=possible")).body;
    assert.deepEqual([b2.items.length, b2.items[0].state, b2.counts.possible], [1, "possible", 1]);
    const dd = (await bOp.get("/api/exposure/news/CVE-2026-1111")).body;
    assert.deepEqual([dd.possible.products, dd.possible.software.map((s: any) => s.name), dd.hosts], [["Frobnicator"], ["Acme Frobnicator 4.2"], null]);
    assert.equal((await bOp.get(`/api/exposure/news?tenantId=${T.A}`)).status, 404);
    assert.equal((await aOp.get("/api/exposure/news?state=bogus")).status, 400);
    assert.equal((await admin.get("/api/exposure/news")).status, 400);
    assert.equal((await admin.get(`/api/exposure/news?tenantId=${T.C}`)).body.items[0].state, "not_affected");
    assert.deepEqual((await aOp.get("/api/exposure/news?kev=1")).body.items.map((x: any) => x.cve), ["CVE-2026-1111"], "CVE-1111 is in KEV (seeded above)");
  });

  test("SOC view across organizations is super admin only", async () => {
    assert.equal((await aAdmin.get("/api/exposure/news-soc")).status, 403);
    assert.equal((await bOp.get("/api/exposure/news-soc")).status, 403);
    const s = (await admin.get("/api/exposure/news-soc")).body;
    const x = s.items.find((i: any) => i.cve === "CVE-2026-1111");
    assert.deepEqual([x.exactTenants, x.possibleTenants, x.totalDevices, x.tenants.length, x.sources], [1, 1, 3, 4, ["https://example.org/a"]]);
    assert.ok(s.counts.exact >= 1);
  });

  test("a tenant is told once when a CVE becomes exact, and again only on a material change; an answered news is not announced twice", async () => {
    await dbm.run("DELETE FROM news_match");
    calls.length = 0;
    await news.matchNews({ markNotified: true }); // the bot has just answered: Alpha holds exact/3 and is not told again
    assert.deepEqual(calls, [`${T.B}|CVE-2026-1111|possible|1`], "only Beta's possible match (it allowed those) is news");
    calls.length = 0;
    await news.matchNews();
    assert.deepEqual(calls, [], "same state, same devices: silence");
    // Gamma (C) gets the CVE later, from a sync
    await finding(CID.C, hex(0xc1), "CVE-2026-1111", "HIGH"); await refreshRollups(CID.C);
    await news.matchNews();
    assert.deepEqual(calls, [`${T.C}|CVE-2026-1111|exact|1`]);
    await news.matchNews();
    assert.equal(calls.length, 1, "no second message for the same state");
    // Alpha grows from 3 to 7 devices (more than doubles)
    for (let i = 0; i < 4; i++) await finding(CID.A, hex(0xa100 + i), "CVE-2026-1111", "HIGH");
    await refreshRollups(CID.A);
    await news.matchNews();
    assert.deepEqual(calls.slice(1), [`${T.A}|CVE-2026-1111|exact|7`]);
    await news.matchNews();
    assert.equal(calls.length, 2);
    await dbm.run("DELETE FROM news_match WHERE tenant_id = ?", T.B);
    await bAdmin.req("PUT", `/api/tenants/${T.B}/notify`, { newsPossible: false });
    calls.length = 0;
    await news.matchNews();
    assert.deepEqual(calls.filter((c: string) => c.startsWith(`${T.B}|`)), [], "possible is not announced unless the organization allows it");
  });
});

describe("EASM extras", () => {
  const T0 = Date.now();
  const ext = (id: string, cid: string, o: Partial<any> = {}) => ({
    cid, id, asset_type: "ip", dns_type: null, perimeter: "official", review: "", criticality: "Unassigned", status: "online", internet_exposure: "Yes", ip: `10.0.0.${id.length}`, fqdn: null, cloud: "AWS", isp: "AMAZON-02",
    discovered_by: "surface", first_seen: T0 - 30 * 86400_000, last_seen: T0, country: "SG", city: "Singapore", region: null, asn: 16509, ptr: "ptr.example", discovery_json: JSON.stringify([{ entity: "1.2.3.4", type: "ip", clue: "cert" }]), services: [], ...o,
  });
  const svc = (port: number, o: Partial<any> = {}) => ({ svc: `s${port}`, port, transport: "tcp", protocol: "https", status: "online", status_code: 200, os: null, first_seen: T0, last_seen: T0, apps_json: JSON.stringify([{ name: "IIS", vendor: "Microsoft", version: "10", category: "Web", cpe: null }]),
    tls_version: null, cert_issuer: null, cert_subject: null, cert_from: null, cert_to: null, cert_sig: null, cert_fingerprint: null, ...o });
  const ID = { expired: "e".repeat(40), risky: "f".repeat(41), plain: "c".repeat(42), fresh: "d".repeat(43), beta: "b".repeat(44), dom: "9".repeat(45) };
  before(async () => {
    await falcon.storeExternal(CID.A, { state: "complete", read: 5, total: 5, missing: [], rows: [
      ext(ID.expired, CID.A, { services: [svc(443, { tls_version: "3", cert_issuer: "CA", cert_subject: "a.example", cert_to: T0 - 40 * 86400_000, cert_from: T0 - 400 * 86400_000 }), svc(80, { protocol: "http" })] }),
      ext(ID.risky, CID.A, { review: "reviewed", services: [svc(3389, { protocol: "rdp" }), svc(443, { cert_to: T0 + 10 * 86400_000, tls_version: "3" })] }),
      ext(ID.plain, CID.A, { review: "reviewed", first_seen: T0 - 90 * 86400_000, services: [svc(443, { cert_to: T0 + 300 * 86400_000, tls_version: "3" })] }),
      ext(ID.fresh, CID.A, { first_seen: T0 - 3600_000, status: "offline" }),
      ext(ID.dom, CID.A, { asset_type: "dns_domain", dns_type: "root", ip: null, fqdn: "alpha.example" }),
    ] });
    await falcon.storeExternal(CID.B, { state: "complete", read: 1, total: 1, missing: [], rows: [ext(ID.beta, CID.B, { services: [svc(21), svc(443, { cert_to: T0 - 1000, tls_version: "3" })] })] });
    await finding(CID.A, ID.expired, "CVE-2026-4444", "HIGH", { provider: "Falcon EASM" });
  });
  const list = async (c: Client, q = "") => (await c.get(`/api/exposure/easm/assets${q}`)).body;

  test("list: default order is not reviewed and new first; filters for expired certificate, risky port, type, review", async () => {
    const all = await list(aOp);
    assert.equal(all.total, 5);
    assert.deepEqual(all.items.map((i: any) => i.id).slice(0, 2), [ID.fresh, ID.expired].sort((a, b) => (a === ID.fresh ? -1 : 1)), "new and unreviewed first");
    assert.ok(all.items.findIndex((i: any) => i.id === ID.plain) > all.items.findIndex((i: any) => i.id === ID.expired), "reviewed ones later");
    assert.deepEqual((await list(aOp, "?expiredCert=1")).items.map((i: any) => i.id), [ID.expired]);
    assert.deepEqual((await list(aOp, "?riskyPort=1")).items.map((i: any) => [i.id, i.riskyPorts]), [[ID.risky, [3389]]]);
    assert.deepEqual((await list(aOp, "?expiringCert=1")).items.map((i: any) => i.id), [ID.risky]);
    assert.deepEqual((await list(aOp, "?type=dns_domain")).items.map((i: any) => i.id), [ID.dom]);
    assert.deepEqual((await list(aOp, "?review=reviewed&sort=name")).items.map((i: any) => i.id).sort(), [ID.plain, ID.risky].sort());
    assert.equal((await list(aOp, "?isNew=1")).total, 1);
    const e = all.items.find((i: any) => i.id === ID.expired);
    assert.deepEqual([e.ports, e.serviceCount, e.expiredCerts, e.country, e.asn, e.findings], [[80, 443], 2, 1, "SG", 16509, { count: 1, worstSeverity: "HIGH" }]);
    assert.equal((await aOp.get("/api/exposure/easm/assets?sort=bogus")).status, 400);
  });

  test("services summary and the old page keep working", async () => {
    const sv = (await aOp.get("/api/exposure/easm/services")).body;
    assert.deepEqual([sv.services, sv.expiredCerts, sv.expiringCerts30, sv.riskyPorts, sv.assetsWithRiskyPorts, sv.newLast7d], [5, 1, 1, 1, 1, 1]);
    assert.equal((await aOp.get("/api/exposure/easm")).body.assets.ips, 4);
  });

  test("drawer: services with TLS, discovery path, vulnerabilities; another organization's asset is 404", async () => {
    const d = (await aOp.get(`/api/exposure/easm/assets/${ID.expired}`)).body;
    const https = d.services.find((s: any) => s.port === 443);
    assert.deepEqual([https.tls.expired, https.tls.issuer, https.tls.expiresInDays < -30, https.applications[0].name, d.discovery[0].clue, d.ptr], [true, "CA", true, "IIS", "cert", "ptr.example"]);
    assert.equal(d.services.find((s: any) => s.port === 80).tls, null);
    assert.deepEqual(d.vulnerabilities.map((v: any) => v.cve), ["CVE-2026-4444"]);
    assert.equal((await bOp.get(`/api/exposure/easm/assets/${ID.expired}`)).status, 404);
    assert.equal((await aOp.get(`/api/exposure/easm/assets/${ID.beta}`)).status, 404);
    assert.equal((await bOp.get(`/api/exposure/easm/assets?tenantId=${T.A}`)).status, 404);
    assert.equal((await bOp.get(`/api/exposure/easm/services?tenantId=${T.A}`)).status, 404);
    assert.deepEqual((await list(bOp)).items.map((i: any) => i.id), [ID.beta]);
    assert.equal((await bOp.get("/api/exposure/easm/services")).body.riskyPorts, 1);
    assert.ok(!JSON.stringify(await list(aOp)).includes(CID.A), "no CIDs for customers");
  });

  test("the collector reads location, ASN, discovery path and services from the FEM record", async () => {
    const record = { id: "x".repeat(40), cid: CID.D, asset_type: "ip", perimeter: "official", first_seen: "2026-11-09T11:10:57Z", last_seen: "2026-11-17T20:09:13Z", triage: { status: "" }, status: "online",
      ip: { ip_address: "52.1.2.3", asn: 16509, ptr: "p", isp: "AMAZON-02", location: { country_code: "SG", city: "Singapore" }, services: [
        { id: "svc1", port: 443, transport: "tcp", protocol: "https", status_code: 200, last_seen: "2026-11-17T20:09:13Z", applications: [{ vendor: "Microsoft", name: "IIS", version: "10.0" }],
          tls: { version: "3", certificate: { valid_to: "2025-11-29T23:59:59Z", signature_algorithm: "sha256WithRSAEncryption", issuer: { common_name: "Some CA" }, subject: { common_name: "a.example" } } } }] },
      discovery: { path: { steps: [{ entity: "52.1.2.3", entity_type: "ip", clue: "IP contains a service which has SSL cert" }] } } };
    const client: any = { get: async (path: string) => path.includes("queries") ? { ok: true, data: { resources: [record.id], meta: { pagination: { total: 1 } } } } : { ok: true, data: { resources: [record] } } };
    const r = (await falcon.collectExternalAll(client)).get(CID.D)!;
    const a = r.rows[0];
    assert.deepEqual([a.country, a.city, a.asn, a.ptr, JSON.parse(a.discovery_json!)[0].type], ["SG", "Singapore", 16509, "p", "ip"]);
    assert.deepEqual([a.services![0].port, a.services![0].cert_issuer, a.services![0].cert_to, a.services![0].tls_version], [443, "Some CA", Date.parse("2025-11-29T23:59:59Z"), "3"]);
  });
});
