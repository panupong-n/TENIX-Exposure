import { testDatabaseUrl } from "./test-db.ts";
process.env.TENIX_DATABASE_URL = testDatabaseUrl(); // overrides any value from the shell; throws unless 127.0.0.1:5433/tenix_test
process.env.TENIX_DB_SCHEMA = `t_${Math.random().toString(36).slice(2, 10)}`; // throwaway schema per run
process.env.TENIX_SECRET_KEY = Buffer.alloc(32, 7).toString("base64");
process.env.TENIX_DEV_FALCON_URL_OK = "1";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import net, { type AddressInfo } from "node:net";
import { after, before, describe, test } from "node:test";
import { CID_ONE, CID_TWO, MOCK_CLIENT, MOCK_SECRET, startMock } from "./mock-falcon.ts";

const { createApp } = await import("../src/http.ts");
await import("../src/auth.ts");
await import("../src/team.ts");
await import("../src/exposure.ts");
await import("../src/software.ts");
const line = await import("../src/line.ts");
const falcon = await import("../src/falcon.ts");
const feeds = await import("../src/feeds.ts");
await import("../src/system.ts");
await import("../src/connections.ts");
/** The CVE Program, as far as these tests are concerned: only what is put in PUBLISHED exists, everything else is a 404. Nothing here touches the network. */
const PUBLISHED = new Map<string, any>();
const cveRecord = (id: string, o: { published?: string; updated?: string; state?: string; description?: string; score?: number } = {}) => ({
  cveMetadata: { cveId: id, state: o.state ?? "PUBLISHED", datePublished: o.published ?? "2023-05-01T00:00:00.000Z", dateUpdated: o.updated ?? o.published ?? "2023-05-01T00:00:00.000Z", assignerShortName: "test" },
  containers: { cna: { title: `Title of ${id}`, descriptions: [{ lang: "en", value: o.description ?? `Description of ${id}` }], references: [{ url: "https://example.org/advisory" }],
    problemTypes: [{ descriptions: [{ cweId: "CWE-79" }] }], metrics: o.score === undefined ? [] : [{ cvssV3_1: { baseScore: o.score, baseSeverity: "CRITICAL", vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" } }] } },
});
const DELTA: any[] = []; // what deltaLog.json says, newest first
const KEV = { etag: "k0", list: [] as string[] };
feeds.feedHooks.fetch = async (url, init) => {
  if (url.endsWith("deltaLog.json")) return new Response(JSON.stringify(DELTA), { status: 200 });
  if (url.endsWith("known_exploited_vulnerabilities.json")) {
    if (((init?.headers ?? {}) as Record<string, string>)["If-None-Match"] === KEV.etag) return new Response(null, { status: 304 });
    return new Response(JSON.stringify({ catalogVersion: KEV.etag, vulnerabilities: KEV.list.map((cveID) => ({ cveID, vulnerabilityName: cveID, vendorProject: "V", product: "P", shortDescription: "s", dateAdded: "2026-11-18", dueDate: "2026-12-09", knownRansomwareCampaignUse: "Unknown", requiredAction: "Patch" })) }), { status: 200, headers: { etag: KEV.etag } });
  }
  const id = /CVE-\d{4}-\d+/.exec(url)?.[0]; const r = id ? PUBLISHED.get(id) : null;
  return r ? new Response(JSON.stringify(r), { status: 200 }) : new Response("", { status: 404 });
};
const dbm = await import("../src/db.ts");
const crypto = await import("../src/crypto.ts");
falcon.hooks.sleep = async () => {}; // no real waiting for backoff
falcon.hooks.rollupMinMs = 0; // the pages are looked at after every run
falcon.hooks.pageSizes = [500]; // small pages, so the fixtures need several requests and the cursor is exercised

class Client {
  base: string;
  jar = new Map<string, string>();
  constructor(base: string) { this.base = base; }
  async req(method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
    const h: Record<string, string> = { ...headers };
    if (body !== undefined && !h["Content-Type"]) h["Content-Type"] = "application/json";
    if (this.jar.size) h.Cookie = [...this.jar].map(([k, v]) => `${k}=${v}`).join("; ");
    const r = await fetch(this.base + path, { method, headers: h, body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body) });
    for (const sc of r.headers.getSetCookie()) {
      const [kv] = sc.split(";");
      const i = kv.indexOf("=");
      const v = kv.slice(i + 1);
      if (/Max-Age=0/.test(sc) || !v) this.jar.delete(kv.slice(0, i)); else this.jar.set(kv.slice(0, i), v);
    }
    return { status: r.status, body: (await r.json().catch(() => null)) as any };
  }
  get = (p: string) => this.req("GET", p);
  post = (p: string, b: unknown = {}) => this.req("POST", p, b);
}

const PW = "correct-horse-battery-1";
let base = "";
let mockUrl = "";
let mock: Awaited<ReturnType<typeof startMock>>["control"];
const servers: { close: () => void }[] = [];
const cl = () => new Client(base);
const ids: Record<string, string> = {};

type Mem = { tenantId: string; role: "admin" | "operator" };
/** Create an invite directly in the database (what the first-run bootstrap does) and accept it. */
async function adopt(email: string, role: "super_admin" | "member", memberships: Mem[] = [], name = email.split("@")[0]) {
  const raw = crypto.token();
  await dbm.run("INSERT INTO invites (id, email, role, memberships_json, kind, token_hash, expires_at, created_at) VALUES (?,?,?,?,?,?,?,?)",
    crypto.uuid(), email, role, JSON.stringify(memberships), "invite", crypto.sha256(raw), Date.now() + 1e6, Date.now());
  const c = cl();
  const r = await c.post(`/api/invites/${raw}/accept`, { name, password: PW });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return c;
}
const op = (tenantId: string): Mem[] => [{ tenantId, role: "operator" }];
const adm = (tenantId: string): Mem[] => [{ tenantId, role: "admin" }];
async function login(email: string, password = PW) {
  const c = cl();
  const r = await c.post("/api/auth/login", { email, password });
  return { c, r };
}
async function waitSync(admin: Client) {
  for (let i = 0; i < 200; i++) {
    const r = await admin.get("/api/integrations/falcon");
    if (!r.body.sync.running) return r.body;
    await new Promise((ok) => setTimeout(ok, 50));
  }
  throw new Error("sync did not finish");
}

let admin: Client, a1: Client, b1: Client, aAdmin: Client, soc: Client, xUser: Client;

before(async () => {
  const s = createApp();
  await new Promise<void>((ok) => s.listen(0, "127.0.0.1", ok));
  base = `http://127.0.0.1:${(s.address() as AddressInfo).port}`;
  servers.push(s);
  const m = await startMock();
  mockUrl = m.url;
  mock = m.control;
  servers.push(m.server);

  admin = await adopt("admin@tenix.test", "super_admin");
  const ta = (await admin.post("/api/tenants", { name: "Alpha Corp" })).body.tenant;
  const tb = (await admin.post("/api/tenants", { name: "Beta Ltd" })).body.tenant;
  const tx = (await admin.post("/api/tenants", { name: "Unmapped Inc" })).body.tenant;
  Object.assign(ids, { ta: ta.id, tb: tb.id, tx: tx.id });
  a1 = await adopt("alice@alpha.test", "member", op(ta.id));
  aAdmin = await adopt("amy@alpha.test", "member", adm(ta.id));
  b1 = await adopt("bob@beta.test", "member", op(tb.id));
  xUser = await adopt("xena@unmapped.test", "member", op(tx.id));
  // an operator of two tenants (the old "SOC analyst"): must say which one on every request
  soc = await adopt("sam@tenix.test", "member", [...op(ta.id), ...op(tb.id)]);
  // each organization has its OWN connection (there is no shared login); the mock accepts one client for both CIDs
  for (const [t, cid] of [[ta, CID_ONE], [tb, CID_TWO]] as const) {
    const r = await admin.post(`/api/tenants/${t.id}/falcon`, { baseUrl: mockUrl, clientId: MOCK_CLIENT, clientSecret: MOCK_SECRET, cid });
    assert.equal(r.status, 200, JSON.stringify(r.body));
  }
  assert.equal((await admin.post("/api/integrations/falcon/sync", {})).status, 200);
  const done = await waitSync(admin);
  assert.deepEqual(done.cids.map((x: any) => x.state), ["complete", "complete"]);
});
after(async () => {
  servers.forEach((s) => s.close());
  await dbm.pool.query(`DROP SCHEMA ${process.env.TENIX_DB_SCHEMA} CASCADE`);
  await dbm.pool.end();
});

describe("accounts, invites and sessions", () => {
  test("invite link: preview, accept once, then it is dead", async () => {
    const raw = crypto.token();
    await dbm.run("INSERT INTO invites (id, email, role, memberships_json, kind, token_hash, expires_at, created_at) VALUES (?,?,?,?,?,?,?,?)",
      crypto.uuid(), "new@alpha.test", "member", JSON.stringify(op(ids.ta)), "invite", crypto.sha256(raw), Date.now() + 1e6, Date.now());
    const c = cl();
    const info = await c.get(`/api/invites/${raw}`);
    assert.deepEqual([info.status, info.body.email, info.body.tenants], [200, "new@alpha.test", [{ name: "Alpha Corp", role: "operator" }]]);
    assert.equal((await c.post(`/api/invites/${raw}/accept`, { name: "New", password: "short" })).status, 400);
    const ok = await c.post(`/api/invites/${raw}/accept`, { name: "New", password: PW });
    assert.equal(ok.status, 200);
    assert.equal((await c.get("/api/auth/me")).body.user.email, "new@alpha.test");
    assert.equal((await cl().get(`/api/invites/${raw}`)).status, 404);
    assert.equal((await cl().post(`/api/invites/${raw}/accept`, { name: "x", password: PW })).status, 404);
  });

  test("expired and revoked invites are refused", async () => {
    const mk = async (extra: string) => {
      const raw = crypto.token();
      await dbm.run(`INSERT INTO invites (id, email, role, memberships_json, kind, token_hash, expires_at, created_at ${extra ? ", revoked_at" : ""}) VALUES (?,?,?,?,?,?,?,? ${extra ? ",?" : ""})`,
        ...[crypto.uuid(), `${raw.slice(0, 5).toLowerCase()}@x.test`, "member", "[]", "invite", crypto.sha256(raw), extra ? Date.now() + 1e6 : Date.now() - 1, Date.now(), ...(extra ? [Date.now()] : [])] as any);
      return raw;
    };
    assert.equal((await cl().get(`/api/invites/${await mk("")}`)).status, 404);
    assert.equal((await cl().get(`/api/invites/${await mk("revoked")}`)).status, 404);
  });

  test("login: generic error, no session without credentials, 5 failures lock the pair", async () => {
    const wrong = await login("alice@alpha.test", "not-the-password");
    const ghost = await login("nobody@alpha.test", "not-the-password");
    assert.deepEqual([wrong.r.status, ghost.r.status], [401, 401]);
    assert.equal(wrong.r.body.error, ghost.r.body.error);
    assert.equal((await cl().get("/api/auth/me")).status, 401);
    let last = 0;
    for (let i = 0; i < 6; i++) last = (await login("lock@alpha.test", "nope-nope-nope")).r.status;
    assert.equal(last, 429);
  });

  test("password change revokes other sessions", async () => {
    const e = "pw@alpha.test";
    const c1 = await adopt(e, "member", op(ids.ta));
    const c2 = (await login(e)).c;
    const r = await c1.post("/api/account/password", { currentPassword: PW, newPassword: "another-long-password-2" });
    assert.equal(r.status, 200);
    assert.equal((await c2.get("/api/auth/me")).status, 401);
    assert.equal((await c1.get("/api/auth/me")).status, 200);
    assert.equal((await login(e, "another-long-password-2")).r.status, 200);
  });

  test("disabled users are signed out and cannot log in; admin reset link restores access", async () => {
    const e = "dis@alpha.test";
    const c = await adopt(e, "member", op(ids.ta));
    const uid = (await c.get("/api/auth/me")).body.user.id;
    assert.equal((await aAdmin.post(`/api/team/users/${uid}/disable`)).status, 200);
    assert.equal((await c.get("/api/auth/me")).status, 401);
    assert.equal((await login(e)).r.status, 401);
    await aAdmin.post(`/api/team/users/${uid}/enable`);
    const link = (await aAdmin.post(`/api/team/users/${uid}/reset-password`)).body.link as string;
    const tok = link.split("/").pop()!;
    const fresh = cl();
    assert.equal((await fresh.post(`/api/invites/${tok}/accept`, { password: "brand-new-password-3" })).body.status, "reset");
    assert.equal((await login(e, "brand-new-password-3")).r.status, 200);
  });

  test("mutating requests need JSON and a same-origin Origin", async () => {
    const c = cl();
    assert.equal((await c.req("POST", "/api/auth/login", "email=a&password=b", { "Content-Type": "application/x-www-form-urlencoded" })).status, 415);
    assert.equal((await c.req("POST", "/api/auth/login", { email: "a@b.c", password: "x" }, { Origin: "https://evil.example" })).status, 403);
  });
});

describe("optional TOTP MFA", () => {
  test("users without MFA sign in with a password alone; enabling is opt-in; codes are single-use", async () => {
    const e = "mfa@alpha.test";
    const c = await adopt(e, "member", op(ids.ta));
    assert.equal((await login(e)).r.body.status, "ok");
    assert.equal((await c.get("/api/auth/me")).body.user.totpEnabled, false);

    const setup = (await c.post("/api/account/mfa/setup")).body;
    assert.match(setup.uri, /^otpauth:\/\/totp\/10CYBER%20Exposure:mfa%40alpha\.test\?secret=[A-Z2-7]+/);
    const step = Math.floor(Date.now() / 30000);
    assert.equal((await c.post("/api/account/mfa/enable", { code: "000000" })).status, 400);
    assert.equal((await c.post("/api/account/mfa/enable", { code: crypto.hotp(setup.secret, step) })).status, 200);
    assert.equal((await c.post("/api/account/mfa/setup")).status, 409);

    // the code used to enable cannot be reused to sign in
    const first = await login(e);
    assert.equal(first.r.body.status, "mfa_required");
    assert.equal((await first.c.get("/api/auth/me")).status, 401, "mfa stage is not a session");
    assert.equal((await first.c.post("/api/auth/login/mfa", { code: crypto.hotp(setup.secret, step) })).status, 401);
    assert.equal((await first.c.post("/api/auth/login/mfa", { code: "abcdef" })).status, 401);
    const good = await first.c.post("/api/auth/login/mfa", { code: crypto.hotp(setup.secret, step + 1) });
    assert.equal(good.status, 200);
    assert.equal((await first.c.get("/api/auth/me")).status, 200);
    // the same code again, from a new login, is a replay
    const again = await login(e);
    assert.equal((await again.c.post("/api/auth/login/mfa", { code: crypto.hotp(setup.secret, step + 1) })).status, 401);

    // admin can clear a lost authenticator; the user then signs in with the password again
    const uid = good.body.user.id;
    assert.equal((await aAdmin.post(`/api/team/users/${uid}/reset-mfa`)).status, 200);
    assert.equal((await login(e)).r.body.status, "ok");
  });

  test("disabling needs the password and a fresh code", async () => {
    const e = "mfa2@alpha.test";
    const c = await adopt(e, "member", op(ids.ta));
    const s = (await c.post("/api/account/mfa/setup")).body;
    const step = Math.floor(Date.now() / 30000);
    await c.post("/api/account/mfa/enable", { code: crypto.hotp(s.secret, step) });
    assert.equal((await c.post("/api/account/mfa/disable", { password: "wrong-password-xx", code: crypto.hotp(s.secret, step + 1) })).status, 400);
    assert.equal((await c.post("/api/account/mfa/disable", { password: PW, code: crypto.hotp(s.secret, step + 1) })).status, 200);
    assert.equal((await c.get("/api/auth/me")).body.user.totpEnabled, false);
  });
});

describe("roles and invites", () => {
  const mem = (tenantId: string, role: "admin" | "operator" = "operator") => [{ tenantId, role }];

  test("only tenant admins and super admins reach team routes; operators never", async () => {
    for (const c of [a1, b1, soc]) {
      assert.equal((await c.get("/api/team/users")).status, 403);
      assert.equal((await c.post("/api/team/invites", { email: "q@q.test", role: "member", memberships: mem(ids.ta) })).status, 403);
    }
    assert.equal((await aAdmin.get("/api/team/users")).status, 200);
    assert.equal((await a1.get("/api/audit")).status, 403);
  });

  test("a tenant admin invites inside their own tenant only, never super admins", async () => {
    const ok = await aAdmin.post("/api/team/invites", { email: "teammate@alpha.test", role: "member", memberships: mem(ids.ta) });
    assert.equal(ok.status, 200);
    assert.match(ok.body.link, /\/accept-invite\/[\w-]{40,}$/);
    assert.equal((await aAdmin.post("/api/team/invites", { email: "s@x.test", role: "super_admin" })).status, 403);
    assert.equal((await aAdmin.post("/api/team/invites", { email: "o@x.test", role: "member", memberships: mem(ids.tb) })).status, 403, "foreign tenant");
    assert.equal((await aAdmin.post("/api/team/invites", { email: "o2@x.test", role: "member", memberships: [...mem(ids.ta), ...mem(ids.tb)] })).status, 403, "one foreign tenant spoils the list");
    assert.equal((await aAdmin.post("/api/team/invites", { email: "o3@x.test", role: "member", memberships: [] })).status, 400, "a member needs a tenant");
    assert.equal((await aAdmin.post("/api/team/invites", { email: "alice@alpha.test", role: "member", memberships: mem(ids.ta) })).status, 409);
    const list = (await aAdmin.get("/api/team/invites")).body.invites;
    assert.ok(list.length > 0 && list.every((i: any) => i.tenants.every((t: any) => t.name === "Alpha Corp")));
    assert.ok(!JSON.stringify(list).includes(ok.body.link.split("/").pop()), "token is never listed");
  });

  test("invite link works end to end; the new user lands in the invited tenants with the invited roles", async () => {
    const inv = await admin.post("/api/team/invites", { email: "multi@x.test", role: "member", memberships: [...mem(ids.ta, "admin"), ...mem(ids.tb)] });
    const c = cl();
    const acc = await c.post(`/api/invites/${inv.body.link.split("/").pop()}/accept`, { name: "Multi", password: PW });
    assert.equal(acc.status, 200);
    const me = (await c.get("/api/auth/me")).body.user;
    assert.deepEqual(me.tenants.map((t: any) => [t.name, t.role]), [["Alpha Corp", "admin"], ["Beta Ltd", "operator"]]);
    assert.equal(me.manager, true);
    assert.equal(me.soc, false);
    // two tenants: has to choose; with a tenantId it works for both and not for a third
    assert.equal((await c.get("/api/exposure/summary")).status, 400);
    assert.equal((await c.get(`/api/exposure/summary?tenantId=${ids.tb}`)).status, 200);
    assert.equal((await c.get(`/api/exposure/summary?tenantId=${ids.tx}`)).status, 404);
  });

  test("regenerate kills the old link, revoke removes it", async () => {
    const inv = await admin.post("/api/team/invites", { email: "flow@beta.test", role: "member", memberships: mem(ids.tb) });
    const t1 = inv.body.link.split("/").pop();
    const regen = await admin.post(`/api/team/invites/${inv.body.invite.id}/regenerate`);
    assert.equal((await cl().get(`/api/invites/${t1}`)).status, 404);
    const pendingNow = (await admin.get("/api/team/invites")).body.invites.find((i: any) => i.email === "flow@beta.test");
    assert.equal((await admin.req("DELETE", `/api/team/invites/${pendingNow.id}`, {})).status, 200);
    assert.equal((await cl().get(`/api/invites/${regen.body.link.split("/").pop()}`)).status, 404);
  });

  test("tenant admin: sees only users of their tenant, can disable and delete them, cannot touch other tenants or super admins", async () => {
    const mine = await adopt("mine@alpha.test", "member", op(ids.ta));
    const theirs = await adopt("theirs@beta.test", "member", op(ids.tb));
    const shared = await adopt("shared@both.test", "member", [...op(ids.ta), ...op(ids.tb)]);
    const idOf = async (c: Client) => (await c.get("/api/auth/me")).body.user.id as string;
    const [mineId, theirsId, sharedId] = [await idOf(mine), await idOf(theirs), await idOf(shared)];
    const list = (await aAdmin.get("/api/team/users")).body.users;
    const emails = list.map((u: any) => u.email);
    assert.ok(emails.includes("mine@alpha.test") && emails.includes("shared@both.test"));
    assert.ok(!emails.includes("theirs@beta.test") && !emails.includes("admin@tenix.test") && !emails.includes("bob@beta.test"));
    const sh = list.find((u: any) => u.email === "shared@both.test");
    assert.deepEqual(sh.tenants.map((t: any) => t.name), ["Alpha Corp"], "the other tenant's name stays hidden");
    assert.equal(sh.hiddenTenants, 1);
    assert.equal(sh.canAdminister, false);
    // other tenants' users look missing
    for (const act of [`disable`, `enable`, `reset-mfa`, `reset-password`]) assert.equal((await aAdmin.post(`/api/team/users/${theirsId}/${act}`)).status, 404, act);
    assert.equal((await aAdmin.req("DELETE", `/api/team/users/${theirsId}`, {})).status, 404);
    // a user who also belongs elsewhere can be removed from the admin's tenant but not disabled or deleted
    assert.equal((await aAdmin.post(`/api/team/users/${sharedId}/disable`)).status, 403);
    assert.equal((await aAdmin.req("DELETE", `/api/team/users/${sharedId}`, {})).status, 403);
    assert.equal((await aAdmin.req("PUT", `/api/team/users/${sharedId}/access`, { memberships: [] })).status, 200);
    assert.deepEqual((await shared.get("/api/auth/me")).body.user.tenants.map((t: any) => t.name), ["Beta Ltd"]);
    assert.equal((await aAdmin.req("PUT", `/api/team/users/${sharedId}/access`, { memberships: [] })).status, 404, "no longer theirs");
    // access edits cannot reach into other tenants
    assert.equal((await aAdmin.req("PUT", `/api/team/users/${mineId}/access`, { memberships: mem(ids.tb) })).status, 403);
    assert.equal((await aAdmin.req("PUT", `/api/team/users/${mineId}/access`, { memberships: mem(ids.ta, "admin") })).status, 200);
    assert.equal((await mine.get("/api/team/users")).status, 200, "promoted to admin");
    assert.equal((await aAdmin.req("PUT", `/api/team/users/${mineId}/access`, { memberships: mem(ids.ta), role: "super_admin" })).body.error === undefined, true);
    assert.equal((await mine.get("/api/team/users")).status, 403, "demoted back to operator; a tenant admin cannot make a super admin");
    // fully-owned users: disable signs them out, delete removes them for good
    assert.equal((await aAdmin.post(`/api/team/users/${mineId}/disable`)).status, 200);
    assert.equal((await mine.get("/api/auth/me")).status, 401);
    assert.equal((await aAdmin.req("DELETE", `/api/team/users/${mineId}`, {})).status, 200);
    assert.equal((await login("mine@alpha.test")).r.status, 401);
    assert.ok(!(await aAdmin.get("/api/team/users")).body.users.some((u: any) => u.email === "mine@alpha.test"));
    assert.equal((await aAdmin.req("DELETE", `/api/team/users/${(await idOf(aAdmin))}`, {})).status, 400, "not yourself");
  });

  test("super admin: manages every user; the last active super admin is protected; tenants can be renamed and deleted with their data", async () => {
    const adminId = (await admin.get("/api/auth/me")).body.user.id;
    assert.equal((await admin.post(`/api/team/users/${adminId}/disable`)).status, 400);
    assert.equal((await admin.req("DELETE", `/api/team/users/${adminId}`, {})).status, 400);
    assert.equal((await admin.req("PUT", `/api/team/users/${adminId}/access`, { role: "member", memberships: [] })).status, 400);
    const all_ = (await admin.get("/api/team/users")).body.users;
    assert.ok(all_.some((u: any) => u.email === "bob@beta.test") && all_.some((u: any) => u.role === "super_admin"));
    // a second super admin by promotion; now the first may be demoted
    const second = await adopt("second@tenix.test", "member", op(ids.ta));
    const secondId = (await second.get("/api/auth/me")).body.user.id;
    assert.equal((await admin.req("PUT", `/api/team/users/${secondId}/access`, { role: "super_admin", memberships: [] })).status, 200);
    assert.equal((await second.get("/api/auth/me")).status, 401, "a changed user type signs the user out");
    const again = (await login("second@tenix.test")).c;
    assert.equal((await again.get("/api/tenants")).body.tenants.length >= 3, true, "sees every tenant");
    assert.equal((await admin.req("PUT", `/api/team/users/${secondId}/access`, { role: "member", memberships: op(ids.ta) })).status, 200);

    // tenants: only super admins write; rename; delete needs the name typed and removes data and access
    const t = (await admin.post("/api/tenants", { name: "Doomed Inc" })).body.tenant;
    assert.equal((await aAdmin.post("/api/tenants", { name: "Nope" })).status, 403);
    assert.equal((await aAdmin.req("PUT", `/api/tenants/${t.id}`, { name: "x" })).status, 403);
    assert.equal((await admin.req("PUT", `/api/tenants/${t.id}`, { name: "Alpha Corp" })).status, 409);
    assert.equal((await admin.req("PUT", `/api/tenants/${t.id}`, { name: "Doomed Incorporated" })).status, 200);
    const CID_X = "9".repeat(32);
    await admin.req("PUT", `/api/tenants/${t.id}/cids`, { cids: [CID_X] });
    await dbm.run("INSERT INTO findings (cid, finding_id, aid, cve_id, severity, synced_at) VALUES (?,?,?,?,?,?)", CID_X, "f1", "a".repeat(32), "CVE-2099-1", "HIGH", 1);
    await (await import("../src/rollup.ts")).refreshRollups(CID_X); // the tenant list reads the rollups, which a sync rebuilds
    const listed = (await admin.get("/api/tenants")).body.tenants.find((x: any) => x.id === t.id);
    assert.deepEqual(listed.stats, { findings: 1, critical: 0, devices: 1, kev: 0 }, "tenant list carries headline numbers");
    assert.ok(Array.isArray(listed.detail));
    const member = await adopt("doomed@doomed.test", "member", op(t.id));
    assert.equal((await aAdmin.req("DELETE", `/api/tenants/${t.id}`, { confirmName: "Doomed Incorporated" })).status, 403);
    assert.equal((await admin.req("DELETE", `/api/tenants/${t.id}`, { confirmName: "wrong" })).status, 400);
    assert.equal((await admin.req("DELETE", `/api/tenants/${t.id}`, { confirmName: "Doomed Incorporated" })).status, 200);
    assert.equal((await dbm.get<{ n: number }>("SELECT COUNT(*) n FROM findings WHERE cid = ?", CID_X))!.n, 0, "its findings are gone");
    assert.equal((await member.get("/api/exposure/summary")).status, 403, "its users have no tenant left");
    assert.equal((await member.get("/api/auth/me")).body.user.tenants.length, 0);
  });

  test("tenant list: members see only their tenants, without CIDs; super admins see everything including CIDs and counts", async () => {
    const mine = (await a1.get("/api/tenants")).body.tenants;
    assert.deepEqual(mine.map((x: any) => x.name), ["Alpha Corp"]);
    assert.ok(!JSON.stringify(mine).includes(CID_ONE) && mine[0].cids === undefined);
    const every = (await admin.get("/api/tenants")).body.tenants;
    const alpha = every.find((x: any) => x.name === "Alpha Corp");
    assert.deepEqual(alpha.cids, [CID_ONE]);
    assert.ok(alpha.users >= 3 && alpha.admins >= 1 && alpha.state === "complete");
    assert.equal((await soc.get("/api/tenants")).body.tenants.length, 2, "an operator of two tenants sees exactly those");
  });

  test("a CID can belong to one tenant only; CIDs must be 32 hex characters", async () => {
    assert.equal((await admin.req("PUT", `/api/tenants/${ids.tx}/cids`, { cids: [CID_ONE] })).status, 409);
    assert.equal((await admin.req("PUT", `/api/tenants/${ids.tx}/cids`, { cids: ["short"] })).status, 400);
    assert.equal((await aAdmin.req("PUT", `/api/tenants/${ids.tx}/cids`, { cids: [] })).status, 403);
  });
});

describe("Falcon integration", () => {
  test("only soc_admin; the secret is never returned and is stored sealed; base URL is restricted", async () => {
    for (const c of [a1, soc, aAdmin]) assert.equal((await c.get("/api/integrations/falcon")).status, 403);
    assert.ok(!JSON.stringify((await admin.get("/api/integrations/falcon")).body).includes(MOCK_SECRET));
    const bad = await admin.post(`/api/tenants/${ids.ta}/falcon`, { baseUrl: "https://evil.example", clientId: "x", clientSecret: "y", cid: "5".repeat(32) });
    assert.equal(bad.status, 400);
    const stored = (await dbm.get<{ secret_sealed: string }>("SELECT secret_sealed FROM falcon_connections WHERE cid = ?", CID_ONE))!.secret_sealed;
    assert.ok(!stored.includes(MOCK_SECRET) && crypto.unseal(stored) === MOCK_SECRET, "secret is encrypted at rest");
    assert.equal((await admin.req("PUT", "/api/integrations/falcon", { baseUrl: mockUrl, clientId: "x", clientSecret: "y" })).status, 405, "there is no shared login to set any more");
  });

  test("connection test tells a wrong secret from a CID the client may not read", async () => {
    const t = `/api/tenants/${ids.ta}/falcon/test`, good = { baseUrl: mockUrl, clientId: MOCK_CLIENT, clientSecret: MOCK_SECRET };
    assert.equal((await admin.post(t, { ...good, cid: CID_ONE })).body.ok, true);
    const wrong = (await admin.post(t, { ...good, clientSecret: "wrong-secret" })).body;
    assert.deepEqual([wrong.ok, wrong.step, wrong.reason], [false, "login", "invalid_credentials"]);
    mock.deniedCids.add(CID_ONE);
    try {
      const denied = (await admin.post(t, { ...good, cid: CID_ONE })).body;
      assert.deepEqual([denied.ok, denied.step, denied.reason], [false, "read", "cid_not_authorized"]);
      assert.match(denied.message, /not authorized/, "Falcon's own words come back");
      const add = await admin.post(`/api/tenants/${ids.tx}/falcon`, { ...good, cid: CID_ONE });
      assert.equal(add.status, 409, "a CID of another organization is refused before anything else");
      const add2 = await admin.post(`/api/tenants/${ids.tx}/falcon`, { ...good, cid: "6".repeat(32) });
      assert.equal(add2.status, 200, "a different CID is fine");
      mock.deniedCids.add("7".repeat(32));
      const refused = await admin.post(`/api/tenants/${ids.tx}/falcon`, { ...good, cid: "7".repeat(32) });
      assert.deepEqual([refused.status, refused.body.code], [400, "cid_not_authorized"], "a connection Falcon refuses is not saved");
      assert.equal((await dbm.get<{ n: number }>("SELECT COUNT(*) n FROM falcon_connections WHERE cid = ?", "7".repeat(32)))!.n, 0);
    } finally { mock.deniedCids.clear(); }
    const mine = (await admin.get(`/api/tenants/${ids.tx}/falcon`)).body;
    await admin.req("DELETE", `/api/tenants/${ids.tx}/falcon/${mine.connections[0].id}`, { confirmCid: "6".repeat(32) });
  });

  test("the client only ever sends allowlisted read requests", () => {
    const bad = mock.requests.filter((r) => !/^(POST \/oauth2\/token|GET \/(spotlight\/(combined\/vulnerabilities\/v1|entities\/remediations\/v2)|devices\/(entities\/devices\/v2|combined\/(devices|host-groups)\/v1)|discover\/(combined\/applications|entities\/hosts)\/v1|fem\/(queries|entities)\/external-assets\/v1))/.test(r));
    assert.deepEqual(bad, []);
    assert.ok(mock.requests.some((r) => r.includes("/spotlight/combined/vulnerabilities/v1") && r.includes("after=")), "followed the pagination cursor");
    assert.ok(mock.requests.every((r) => !(r.includes("sort=updated_timestamp") && r.includes("severity") && !r.includes("exprt_rating"))), "every severity is stored: the backfill pages carry no severity filter (the fix-first slice names Critical itself)");
  });

  test("a failing page keeps the previous data and reports partial; a later run recovers", async () => {
    const before = (await a1.get("/api/exposure/summary")).body.totals.findings;
    await dbm.run("DELETE FROM cid_cursor WHERE cid = ?", CID_ONE); // a full pass again (3 pages), and Falcon fails on the second
    await dbm.run("DELETE FROM cid_sync WHERE cid = ?", CID_ONE);
    mock.fail((q) => q.includes("sort=updated_timestamp") && !q.includes("expired"), 500, 99, 1); // page 1 fine, page 2 always fails (the counts and other requests are not hit)
    await admin.post("/api/integrations/falcon/sync", { tenantId: ids.ta });
    let st = await waitSync(admin);
    const one = st.cids.find((x: any) => x.cid === CID_ONE);
    assert.equal(one.state, "partial");
    assert.match(one.detail.join(" "), /page 2: HTTP 500/);
    assert.equal(one.reason, "error");
    const mid = (await a1.get("/api/exposure/summary")).body;
    assert.equal(mid.totals.findings, before, "old data kept");
    assert.equal(mid.completeness.state, "partial");
    assert.deepEqual(mid.completeness.cids, [], "customers do not see CID detail");
    mock.clearFailures();
    await admin.post("/api/integrations/falcon/sync", { tenantId: ids.ta });
    st = await waitSync(admin);
    assert.equal(st.cids.find((x: any) => x.cid === CID_ONE).state, "complete");
  });

  test("429 is retried and the run still completes", async () => {
    mock.fail("/spotlight/combined", 429, 2);
    await admin.post("/api/integrations/falcon/sync", { tenantId: ids.tb });
    const st = await waitSync(admin);
    assert.equal(st.cids.find((x: any) => x.cid === CID_TWO).state, "complete");
  });

  test("the overview says how much is stored against what Falcon counts, and why a CID failed; customers never see the CID", async () => {
    const open = mock.data.findings.filter((f) => f.cid === CID_ONE && ["open", "reopen"].includes(f.status));
    const c = (await a1.get("/api/exposure/summary")).body.completeness;
    assert.equal(c.state, "complete");
    assert.deepEqual(c.coverage, { held: open.length, falconTotal: open.length, priorityHeld: c.coverage.priorityHeld, priorityTotal: c.coverage.priorityTotal, priorityPass: true, fullPass: true, scope: "all", keptTotal: open.length });
    assert.ok(c.coverage.priorityTotal > 0 && c.coverage.priorityTotal < open.length);
    assert.equal(c.coverage.priorityHeld, c.coverage.priorityTotal, "the whole fix-first slice is stored");
    assert.deepEqual(c.falconCounts, { total: open.length, critical: open.filter((f) => f.cve.severity === "CRITICAL").length, high: open.filter((f) => f.cve.severity === "HIGH").length,
      medium: open.filter((f) => f.cve.severity === "MEDIUM").length, low: open.filter((f) => f.cve.severity === "LOW").length, kev: 0, exprtCritical: open.filter((f) => f.cve.exprt_rating === "CRITICAL").length,
      exploited: open.filter((f) => [60, 70, 80, 90].includes(f.cve.exploit_status)).length });
    assert.ok(!JSON.stringify(c).includes(CID_ONE) && c.reason === null);
    for (const path of ["/api/exposure/vulnerabilities", "/api/exposure/hosts"]) assert.deepEqual((await a1.get(path)).body.completeness.coverage, c.coverage, `${path} carries it too`);

    mock.deniedCids.add(CID_TWO);
    try {
      await admin.post("/api/integrations/falcon/sync", { tenantId: ids.tb });
      const st = await waitSync(admin);
      const two = st.cids.find((x: any) => x.cid === CID_TWO);
      assert.deepEqual([two.state, two.reason], ["failed", "cid_not_authorized"]);
      assert.match(two.detail.join(" "), /not authorized/, "Falcon's words are kept for the admin");
      assert.equal(two.coverage.fullPass, true, "the earlier data and its counts stay");
      const b = (await b1.get("/api/exposure/summary")).body;
      assert.deepEqual([b.completeness.state, b.completeness.reason, b.completeness.cids], ["failed", "cid_not_authorized", []]);
      assert.ok(b.totals.findings > 0, "a failed run does not wipe the data");
    } finally { mock.deniedCids.clear(); }
    await admin.post("/api/integrations/falcon/sync", { tenantId: ids.tb });
    await waitSync(admin);
    assert.equal((await b1.get("/api/exposure/summary")).body.completeness.state, "complete");
  });

  test("completeness says no_cids without CIDs and no_connection when there are CIDs but no login for them", async () => {
    const t = (await admin.post("/api/tenants", { name: "Bare Co" })).body.tenant;
    assert.equal((await admin.get(`/api/exposure/summary?tenantId=${t.id}`)).body.completeness.state, "no_cids");
    assert.equal((await admin.req("PUT", `/api/tenants/${t.id}/cids`, { cids: ["4".repeat(32)] })).status, 200);
    const c = (await admin.get(`/api/exposure/summary?tenantId=${t.id}`)).body.completeness;
    assert.deepEqual([c.state, c.reason, c.coverage, c.falconCounts, c.dataAsOf], ["no_connection", null, null, null, null]);
  });

  test("a failed sync before any data exists stays failed and empty", async () => {
    const t = (await admin.post("/api/tenants", { name: "Fresh Co" })).body.tenant;
    const cid = "3".repeat(32);
    assert.equal((await admin.post(`/api/tenants/${t.id}/falcon`, { baseUrl: mockUrl, clientId: MOCK_CLIENT, clientSecret: MOCK_SECRET, cid })).status, 200);
    mock.fail("/spotlight/combined", 500, 99);
    await admin.post("/api/integrations/falcon/sync", { tenantId: t.id });
    const st = await waitSync(admin);
    mock.clearFailures();
    assert.equal(st.cids.find((x: any) => x.cid === cid).state, "failed");
    const c = await adopt("fresh@fresh.test", "member", op(t.id));
    const sum = (await c.get("/api/exposure/summary")).body;
    assert.deepEqual([sum.totals.findings, sum.completeness.state], [0, "failed"]);
  });
});

describe("tenant isolation", () => {
  const hostAidInAlpha = async () => (await dbm.get<{ aid: string }>("SELECT aid FROM findings WHERE cid = ? LIMIT 1", CID_ONE))!.aid;
  const count = async (cid: string) => (await dbm.get<{ n: number }>("SELECT COUNT(*) n FROM findings WHERE cid = ?", cid))!.n;
  const leak = (body: unknown, tenantCid: string, other: string) => {
    const s = JSON.stringify(body);
    return s.includes(other) || (s.includes(tenantCid));
  };

  test("customers see only their own data and totals match the database", async () => {
    const a = (await a1.get("/api/exposure/summary")).body;
    const b = (await b1.get("/api/exposure/summary")).body;
    assert.equal(a.totals.findings, await count(CID_ONE));
    assert.equal(b.totals.findings, await count(CID_TWO));
    assert.equal(a.tenant.name, "Alpha Corp");
    assert.ok(a.topHosts.every((h: any) => Number.isInteger(h.high) && Number.isInteger(h.medium)), "top devices carry High and Medium counts");
    assert.ok(!JSON.stringify(a).includes(CID_ONE) && !JSON.stringify(a).includes(CID_TWO), "customers never receive CIDs");
    assert.ok(Object.values(a.severity).reduce((x: number, y: any) => x + y, 0) === a.totals.findings, "every severity is counted");
    assert.ok(a.severity.LOW > 0 && a.severity.NONE > 0, "low and none severities are present");
  });

  test("overview management data agrees with the database and the summary, honours the Source filter, never leaks CIDs, and honours tenant scope", async () => {
    const a = (await a1.get("/api/exposure/executive")).body;
    const sum = (await a1.get("/api/exposure/summary")).body;
    const total = (o: Record<string, number>) => Object.values(o).reduce((x, y) => x + y, 0);
    assert.equal(a.tenant.name, "Alpha Corp");
    assert.equal(a.totals.devices, sum.totals.hosts);
    assert.equal(a.totals.critical, sum.severity.CRITICAL);
    assert.equal(a.totals.high, sum.severity.HIGH);
    assert.equal(total(a.bySource.endpoint) + total(a.bySource.external), sum.totals.findings, "every finding is in exactly one source");
    assert.equal(total(a.aging), a.totals.critical + a.totals.high, "every Critical and High finding is in exactly one age bucket");
    const kev = await dbm.get<{ n: number; d: number }>(
      "SELECT COUNT(DISTINCT f.cve_id) n, COUNT(DISTINCT f.aid) d FROM findings f JOIN cves k ON k.id = f.cve_id WHERE k.cisa_kev = 1 AND f.cid = ?", CID_ONE);
    assert.deepEqual([a.kev.cves, a.kev.devices], [kev!.n, kev!.d]);
    const net = await dbm.get<{ n: number }>(
      "SELECT COUNT(*) n FROM findings WHERE cid = ? AND (internet_exposure = 'Yes' OR provider ILIKE '%EASM%') AND severity IN ('CRITICAL','HIGH')", CID_ONE);
    assert.equal(a.totals.internetCriticalHigh, net!.n);
    assert.ok(a.totals.internetCriticalHigh >= a.bySource.external.CRITICAL + a.bySource.external.HIGH, "every external Critical or High finding is internet-facing");
    assert.ok(a.topKev.length <= 5 && a.external.top.length <= 5);
    // the Source filter narrows the totals the same way it does on the summary
    const ext = (await a1.get("/api/exposure/executive?source=external")).body;
    const extSum = (await a1.get("/api/exposure/summary?source=external")).body;
    assert.equal(ext.totals.critical, extSum.severity.CRITICAL);
    assert.equal(ext.totals.devices, extSum.totals.hosts);
    assert.deepEqual(ext.bySource, a.bySource, "the source split ignores the filter");
    assert.equal((await a1.get("/api/exposure/executive?source=nope")).status, 400);
    assert.ok(!JSON.stringify(a).includes(CID_ONE) && !JSON.stringify(a).includes(CID_TWO), "customers never receive CIDs");
    assert.equal((await admin.get("/api/exposure/executive")).status, 400, "a super admin must name a tenant");
    assert.equal((await admin.get(`/api/exposure/executive?tenantId=${ids.tb}`)).status, 200);
    assert.equal((await a1.get(`/api/exposure/executive?tenantId=${ids.tb}`)).status, 404, "another tenant looks like it does not exist");
  });

  test("a foreign tenantId is a 404 and is audited as denied; a super admin must choose a tenant", async () => {
    assert.equal((await a1.get(`/api/exposure/summary?tenantId=${ids.tb}`)).status, 404);
    assert.equal((await a1.get(`/api/exposure/vulnerabilities?tenantId=${ids.tb}`)).status, 404);
    assert.equal((await a1.get(`/api/exposure/summary?tenantId=nope`)).status, 404);
    assert.ok(await dbm.get("SELECT 1 FROM audit WHERE actor_email = 'alice@alpha.test' AND result = 'denied' AND action LIKE 'read:%'"));
    assert.equal((await a1.get(`/api/exposure/summary?tenantId=${ids.ta}`)).status, 200);
    assert.equal((await soc.get("/api/exposure/summary")).status, 400);
    const ok = await soc.get(`/api/exposure/summary?tenantId=${ids.tb}`);
    assert.equal(ok.status, 200);
    assert.equal(ok.body.totals.findings, await count(CID_TWO));
    const sup = await admin.get(`/api/exposure/summary?tenantId=${ids.tb}`);
    assert.equal(sup.status, 200);
    assert.ok(await dbm.get("SELECT 1 FROM audit WHERE actor_email = 'admin@tenix.test' AND result = 'allowed' AND tenant_id = ?", ids.tb), "a super admin's read is audited");
  });

  test("hosts: same hostname in two tenants stays two machines; foreign host looks like a missing one", async () => {
    const hostsA = (await soc.get(`/api/exposure/hosts?tenantId=${ids.ta}&pageSize=100&q=APP-`)).body.rows;
    const hostsB = (await soc.get(`/api/exposure/hosts?tenantId=${ids.tb}&pageSize=100&q=APP-`)).body.rows;
    const dupNames = hostsA.map((h: any) => h.hostname).filter((n: string) => hostsB.some((x: any) => x.hostname === n));
    assert.ok(dupNames.length > 0, "fixture has the same hostname in both tenants");
    const keysA = new Set(hostsA.map((h: any) => h.key));
    assert.ok(hostsA.every((h: any) => [h.high, h.medium, h.exploited].every((n) => typeof n === "number")), "severity split and exploited counts are returned");
    const vulnA = (await soc.get(`/api/exposure/vulnerabilities?tenantId=${ids.ta}&pageSize=5`)).body.rows;
    assert.ok(vulnA.every((v: any) => typeof v.kev === "boolean" && "published" in v && "product" in v), "CVE rows carry KEV, published date and product");
    assert.ok(hostsB.every((h: any) => !keysA.has(h.key)), "identity is CID + AID");
    const foreign = hostsB[0];
    const missing = await a1.get(`/api/exposure/hosts/${foreign.aid}`);
    const none = await a1.get(`/api/exposure/hosts/${"f".repeat(32)}`);
    assert.deepEqual([missing.status, none.status], [404, 404]);
    assert.deepEqual(missing.body, none.body);
    const own = await a1.get(`/api/exposure/hosts/${hostsA[0].aid}`);
    assert.equal(own.status, 200);
    assert.equal(own.body.cid, undefined, "customers do not get the CID back");
    assert.equal((await soc.get(`/api/exposure/hosts/${hostsA[0].aid}?tenantId=${ids.ta}`)).body.cid, hostsA[0].cid, "SOC sees the CID");
    assert.equal((await soc.get(`/api/exposure/hosts/${hostsA[0].aid}?tenantId=${ids.tb}`)).status, 404, "SOC scope is per organization too");
    const custRows = (await a1.get("/api/exposure/hosts?pageSize=100")).body.rows;
    assert.ok(!JSON.stringify(custRows).includes(CID_ONE), "no CID in any customer-facing device row");
  });

  test("graph and device tree: bounded, scoped, no CID for customers, totals match the database", async () => {
    const g = (await a1.get("/api/exposure/graph?cves=10")).body;
    assert.equal(g.cves.length, 10);
    assert.ok(g.devices.length > 0 && g.devices.length <= 60);
    assert.ok(g.links.every(([d, c]: number[]) => g.devices[d] && g.cves[c]), "every link points at a listed device and CVE");
    assert.equal(g.totals.devices, (await dbm.get<{ n: number }>("SELECT COUNT(DISTINCT aid) n FROM findings WHERE cid = ?", CID_ONE))!.n);
    assert.ok(!JSON.stringify(g).includes(CID_ONE) && !JSON.stringify(g).includes(CID_TWO), "no CID in the customer graph");
    const gb = (await soc.get(`/api/exposure/graph?tenantId=${ids.tb}`)).body;
    const aidsB = new Set((await dbm.all<{ aid: string }>("SELECT DISTINCT aid FROM findings WHERE cid = ?", CID_TWO)).map((r) => r.aid));
    assert.ok(gb.devices.every((d: any) => aidsB.has(d.aid)), "SOC graph only shows the chosen organization");
    assert.equal((await a1.get(`/api/exposure/graph?tenantId=${ids.tb}`)).status, 404, "foreign tenantId");
    assert.equal((await soc.get("/api/exposure/graph")).status, 400, "SOC must choose an organization");
    assert.equal((await a1.get("/api/exposure/graph?severity=BOGUS")).status, 400);
    const crit = (await a1.get("/api/exposure/graph?severity=CRITICAL")).body;
    assert.ok(crit.cves.every((x: any) => x.severity === "CRITICAL"));
    assert.equal((await xUser.get("/api/exposure/graph")).body.cves.length, 0, "tenant without CIDs sees an empty graph");

    const aid = (await dbm.get<{ aid: string }>("SELECT aid FROM findings WHERE cid = ? LIMIT 1", CID_ONE))!.aid;
    const h = (await a1.get(`/api/exposure/hosts/${aid}`)).body;
    assert.equal(h.total, Object.values(h.counts).reduce((a: number, b: any) => a + b, 0));
    assert.ok(h.products.length > 0 && h.products.every((p: any) => p.cves.length > 0 && p.cves.length <= 3));
    assert.ok(h.findings.length <= 300);
  });

  test("unnamed and IP-named assets are kept, not dropped", async () => {
    const rows = (await soc.get(`/api/exposure/hosts?tenantId=${ids.ta}&pageSize=100`)).body;
    const total = (await dbm.get<{ n: number }>("SELECT COUNT(DISTINCT aid) n FROM findings WHERE cid = ?", CID_ONE))!.n;
    assert.equal(rows.total, total);
    assert.ok(rows.rows.some((h: any) => !h.hostname), "an asset without a hostname is listed");
  });

  test("a tenant without CIDs sees nothing, never everything", async () => {
    const sum = (await xUser.get("/api/exposure/summary")).body;
    assert.deepEqual([sum.completeness.state, sum.totals.findings, sum.topCves.length], ["no_cids", 0, 0]);
    const v = (await xUser.get("/api/exposure/vulnerabilities")).body;
    assert.deepEqual([v.total, v.rows.length], [0, 0]);
    assert.equal((await xUser.get(`/api/exposure/hosts/${"a".repeat(32)}`)).status, 404);
    assert.equal((await xUser.get(`/api/exposure/hosts/${await hostAidInAlpha()}`)).status, 404);
  });

  test("CVE list and detail respect the scope and severity filter; zero results say 'not found' with completeness", async () => {
    const list = (await a1.get("/api/exposure/vulnerabilities?pageSize=100&sort=hosts")).body;
    assert.ok(list.rows.length > 0 && list.total >= list.rows.length);
    const some = list.rows[0].cveId;
    const detail = (await a1.get(`/api/exposure/vulnerabilities/${some}`)).body;
    assert.equal(detail.found, true);
    assert.ok(detail.hosts.every((h: any) => h.cid === undefined));
    assert.ok(!JSON.stringify(detail).includes(CID_ONE), "the CID is nowhere in a customer's CVE detail (the host key used to carry it)");
    const crit = (await a1.get("/api/exposure/vulnerabilities?severity=critical&pageSize=100")).body;
    assert.ok(crit.rows.length > 0 && crit.rows.every((r: any) => r.severity === "CRITICAL"));
    const missing = (await a1.get("/api/exposure/vulnerabilities/CVE-1999-0001")).body;
    assert.deepEqual([missing.found, missing.completeness.state], [false, "complete"]);
    assert.equal((await a1.get("/api/exposure/vulnerabilities?severity=bogus")).status, 400);
    assert.equal((await a1.get("/api/exposure/vulnerabilities/not%20an%20id!")).status, 400);
  });

  test("search input is never interpreted as SQL or wildcards", async () => {
    const all = (await a1.get("/api/exposure/vulnerabilities?pageSize=100")).body.total;
    for (const q of ["%", "_", "' OR 1=1 --", "\\"]) {
      const r = await a1.get(`/api/exposure/vulnerabilities?q=${encodeURIComponent(q)}`);
      assert.equal(r.status, 200);
      assert.ok(r.body.total < all, `q=${q} must not match everything`);
    }
  });

  test("audit log: operators denied, a tenant admin sees their own tenant only, a super admin sees all", async () => {
    assert.equal((await a1.get("/api/audit")).status, 403);
    const mine = (await aAdmin.get("/api/audit")).body.entries;
    assert.ok(mine.length > 0 && mine.every((e: any) => e.tenant_name === null || e.tenant_name === "Alpha Corp"));
    assert.ok(mine.some((e: any) => e.tenant_name === "Alpha Corp"));
    assert.ok(!JSON.stringify(mine).includes("bob@beta.test"));
    const everything = (await admin.get("/api/audit?limit=500")).body.entries;
    assert.ok(new Set(everything.map((e: any) => e.tenant_name)).size >= 2);
    assert.ok(!JSON.stringify(everything).includes(MOCK_SECRET) && !JSON.stringify(everything).includes(PW));
  });
});

describe("e-mail alerts", () => {
  const sent: { to: string; body: string }[] = [];
  // minimal SMTP server: accepts everything and records who got what
  const smtp = net.createServer((sock) => {
    let to = "", body = "", inData = false, buf = "";
    sock.write("220 test ESMTP\r\n");
    sock.on("data", (d) => {
      buf += d.toString();
      for (let i; (i = buf.indexOf("\r\n")) >= 0;) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 2);
        if (inData) {
          if (line === ".") { inData = false; sent.push({ to, body }); sock.write("250 queued\r\n"); } else body += line + "\n";
        } else if (/^RCPT TO/i.test(line)) { to = /<([^>]+)>/.exec(line)![1]; sock.write("250 ok\r\n"); }
        else if (/^DATA/i.test(line)) { inData = true; body = ""; sock.write("354 go\r\n"); }
        else if (/^QUIT/i.test(line)) { sock.end("221 bye\r\n"); }
        else sock.write("250 ok\r\n");
      }
    });
  });
  let senderId = "";
  const rid: Record<string, string> = {};
  before(async () => {
    await new Promise<void>((ok) => smtp.listen(0, "127.0.0.1", ok));
    servers.push(smtp);
  });

  test("only soc_admin; sender password is stored sealed and never returned; test mail is delivered", async () => {
    for (const c of [a1, soc, aAdmin]) assert.equal((await c.get("/api/mail")).status, 403);
    const port = (smtp.address() as AddressInfo).port;
    const bad = await admin.post("/api/mail/senders", { name: "x", host: "bad host!", port, security: "none", fromEmail: "a@b.co" });
    assert.equal(bad.status, 400);
    const r = await admin.post("/api/mail/senders", { name: "Local", host: "127.0.0.1", port, security: "none", username: "u", password: "smtp-secret-pw", fromEmail: "alerts@tenix.test", fromName: "TENIX Alerts" });
    assert.equal(r.status, 200);
    senderId = r.body.id;
    const view = (await admin.get("/api/mail")).body;
    assert.equal(view.senders[0].hasPassword, true);
    assert.equal(view.senders[0].isDefault, true);
    assert.ok(!JSON.stringify(view).includes("smtp-secret-pw"));
    const stored = (await dbm.get<{ password_sealed: string }>("SELECT password_sealed FROM mail_senders"))!.password_sealed;
    assert.equal(crypto.unseal(stored), "smtp-secret-pw");
    const t = await admin.post(`/api/mail/senders/${senderId}/test`, { to: "me@tenix.test" });
    assert.deepEqual(t.body, { ok: true });
    assert.deepEqual(sent.map((m) => m.to), ["me@tenix.test"]);
  });

  test("each alert goes only to recipients subscribed to it and allowed to see that tenant", async () => {
    const mk = async (email: string, tenantId: string | null, events: string[]) => {
      const r = await admin.post("/api/mail/recipients", { email, tenantId, events });
      assert.equal(r.status, 200, JSON.stringify(r.body));
      rid[email] = r.body.id;
    };
    await mk("soc@tenix.test", null, ["critical_new"]);
    await mk("alpha@alpha.test", ids.ta, ["critical_new", "sync_failed"]);
    await mk("beta@beta.test", ids.tb, ["critical_new"]);
    await mk("off@alpha.test", ids.ta, ["critical_new"]);
    assert.equal((await admin.req("PUT", `/api/mail/recipients/${rid["off@alpha.test"]}`, { enabled: false })).status, 200);
    assert.equal((await admin.post("/api/mail/recipients", { email: "z@z.test", events: ["nope"] })).status, 400);
    assert.equal((await admin.post("/api/mail/recipients", { email: "alpha@alpha.test", tenantId: ids.ta, events: [] })).status, 409, "duplicate");

    sent.length = 0;
    const mailm = await import("../src/mail.ts");
    await mailm.notify("critical_new", ids.ta, { subject: "s1", text: "t1", html: "<p>t1</p>" });
    assert.deepEqual(sent.map((m) => m.to).sort(), ["alpha@alpha.test", "soc@tenix.test"]);
    sent.length = 0;
    await mailm.notify("sync_failed", ids.tb, { subject: "s2", text: "t2", html: "<p>t2</p>" });
    assert.equal(sent.length, 0, "nobody subscribed for Beta sync_failed");
    // changing subscriptions takes effect
    await admin.req("PUT", `/api/mail/recipients/${rid["soc@tenix.test"]}`, { events: ["sync_failed"] });
    await mailm.notify("sync_failed", ids.tb, { subject: "s3", text: "t3", html: "<p>t3</p>" });
    assert.deepEqual(sent.map((m) => m.to), ["soc@tenix.test"]);
    assert.ok((await admin.get("/api/mail")).body.log.some((l: any) => l.state === "sent"));
  });

  test("every mail has one look, a plain-text twin, and escapes what people typed", async () => {
    const kit = await import("../src/mailkit.ts");
    const evil = `<script>alert(1)</script> "x" & <b>`;
    const all = [
      kit.composeInvite({ name: evil, inviter: evil, role: "Operator", organizations: [evil, "Beta"], link: "https://easm.example/accept-invite/abc", ttlMs: 7 * 24 * 3600_000 }),
      kit.composeReset({ name: evil, byAdmin: true, link: "https://easm.example/accept-invite/def", ttlMs: 7 * 24 * 3600_000 }),
      kit.composeSyncFailed({ organization: evil, state: "failed", link: "https://easm.example" }),
      kit.composeCritical({ organization: evil, cves: ["CVE-2026-1", ...Array.from({ length: 14 }, (_, i) => `CVE-2026-${i + 2}`)], devices: 3, link: "https://easm.example" }),
      kit.composeTest({ sender: evil }),
    ];
    for (const m of all) {
      assert.ok(m.subject.startsWith("[10CYBER Exposure]") && m.text.length > 20 && m.html.startsWith("<!doctype html>"));
      assert.ok(!m.html.includes("<script>") && !m.html.includes("<b>"), "nothing typed by a person reaches the HTML unescaped");
      assert.ok(m.html.includes("10CYBER") && m.html.includes("BY TENFORWARD") && m.html.includes("prefers-color-scheme:dark") && m.html.includes("600"), "the shared shell: wordmark, dark palette, 600 px card");
    }
    assert.ok(all[0].html.includes("https://easm.example/accept-invite/abc") && all[0].text.includes("https://easm.example/accept-invite/abc") && all[0].html.includes("Set a password and sign in"));
    assert.ok(all[3].html.includes("and 5 more") && all[3].text.includes("… and 5 more"), "a long list is cut with a count");
    assert.ok(all[1].subject.includes("Set a new password") && /ignore this email/.test(all[1].text));
  });

  test("an invitation or a reset link is e-mailed only when asked and only when a sender exists; the link is always returned", async () => {
    sent.length = 0;
    const plain = await admin.post("/api/team/invites", { email: "mailed-0@x.test", role: "member", memberships: [{ tenantId: ids.ta, role: "operator" }] });
    assert.equal(plain.status, 200); assert.equal(plain.body.emailed, "not_asked"); assert.ok(plain.body.link);
    assert.equal(sent.length, 0, "no mail unless asked");
    const asked = await admin.post("/api/team/invites", { email: "mailed-1@x.test", role: "member", memberships: [{ tenantId: ids.ta, role: "operator" }], sendEmail: true });
    assert.deepEqual([asked.status, asked.body.emailed], [200, "sent"]);
    assert.ok(asked.body.link.includes("/accept-invite/"));
    assert.deepEqual(sent.map((m) => m.to), ["mailed-1@x.test"]);
    assert.ok(/Subject: \[10CYBER Exposure\] You have been invited/.test(sent[0].body) && /multipart\/alternative/.test(sent[0].body), "subject and both parts");
    const again = await admin.req("POST", `/api/team/invites/${asked.body.invite.id}/regenerate`, { sendEmail: true });
    assert.equal(again.body.emailed, "sent");
    const u = (await admin.get("/api/team/users")).body.users.find((x: any) => x.email === "alice@alpha.test");
    sent.length = 0;
    const reset = await admin.post(`/api/team/users/${u.id}/reset-password`, { sendEmail: true });
    assert.equal(reset.body.emailed, "sent");
    assert.ok(/Set a new password/.test(sent[0].body));
    // no sender: the request still works and says so
    const only = await dbm.all<Record<string, any>>("SELECT * FROM mail_senders");
    await dbm.run("DELETE FROM mail_senders");
    try {
      const none = await admin.post("/api/team/invites", { email: "mailed-2@x.test", role: "member", memberships: [{ tenantId: ids.ta, role: "operator" }], sendEmail: true });
      assert.deepEqual([none.status, none.body.emailed, !!none.body.link], [200, "no_sender", true]);
    } finally {
      for (const r of only) await dbm.run(`INSERT INTO mail_senders (${Object.keys(r).join(",")}) VALUES (${Object.keys(r).map(() => "?").join(",")})`, ...Object.values(r));
    }
  });

  test("a sync that finds a new critical finding reports it once; the first pass and an unchanged sync report nothing", async () => {
    const run = async () => falcon.syncFindings(new falcon.FalconClient((await falcon.configFor(CID_ONE))!), CID_ONE);
    assert.deepEqual((await run()).fresh, [], "nothing new");
    const f = mock.data.findings.find((x) => x.cid === CID_ONE && x.cve.severity === "CRITICAL")!;
    await dbm.run("DELETE FROM findings WHERE cid = ? AND finding_id = ?", CID_ONE, f.id);
    mock.touch(f); // Falcon shows it as changed now
    assert.deepEqual((await run()).fresh.map((x) => x.aid), [f.aid]);
    assert.deepEqual((await run()).fresh, [], "a repeated read reports nothing again");
    assert.equal((await dbm.get<{ n: number }>("SELECT COUNT(*) n FROM findings WHERE cid = ?", CID_ONE))!.n, mock.data.findings.filter((x) => x.cid === CID_ONE && ["open", "reopen"].includes(x.status)).length, "data restored");
  });

  test("deleting the default sender promotes another one", async () => {
    const port = (smtp.address() as AddressInfo).port;
    const r2 = await admin.post("/api/mail/senders", { name: "Second", host: "127.0.0.1", port, security: "none", fromEmail: "b@tenix.test" });
    assert.equal((await admin.req("DELETE", `/api/mail/senders/${senderId}`, {})).status, 200);
    const s = (await admin.get("/api/mail")).body.senders;
    assert.deepEqual(s.map((x: any) => [x.id, x.isDefault]), [[r2.body.id, true]]);
  });
});

describe("retention settings: which severities an organization stores", () => {
  const url = (id: string) => `/api/tenants/${id}/retention`;
  const ALL = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"];

  test("super admins and the organization's own admins read and change it; operators and other organizations cannot", async () => {
    const r = await aAdmin.get(url(ids.ta));
    assert.equal(r.status, 200);
    assert.deepEqual([r.body.keep, r.body.all, r.body.graceDays, r.body.pending, r.body.rebuilding, r.body.scope], [ALL, ALL, 3, [], [], "all"]);
    assert.equal((await admin.get(url(ids.ta))).status, 200);
    assert.equal((await a1.get(url(ids.ta))).status, 403, "an operator may not");
    assert.equal((await b1.get(url(ids.tb))).status, 403);
    assert.equal((await aAdmin.get(url(ids.tb))).status, 404, "another organization looks like a missing page");
    assert.equal((await aAdmin.req("PUT", url(ids.tb), { keep: ["HIGH"] })).status, 404);
    assert.equal((await a1.req("PUT", url(ids.ta), { keep: ["HIGH"] })).status, 403);
    assert.equal((await cl().get(url(ids.ta))).status, 401);
  });

  test("validation: a list of known severities, at least one", async () => {
    for (const [keep, code] of [[[], "keep_empty"], [["HIGH", "BOGUS"], "invalid_severity"], ["HIGH", "invalid_severity"], [undefined, "invalid_severity"]] as const) {
      const r = await aAdmin.req("PUT", url(ids.ta), { keep });
      assert.deepEqual([r.status, r.body.code], [400, code], JSON.stringify(keep));
    }
    assert.deepEqual((await aAdmin.get(url(ids.ta))).body.keep, ALL, "nothing changed");
  });

  test("unticking: the answer lists what will be purged and when, the overview totals stay Falcon's exact ones, the coverage names the scope; re-ticking brings it back", async () => {
    const total = (await a1.get("/api/exposure/summary")).body.completeness.falconCounts.total;
    const put = await aAdmin.req("PUT", url(ids.ta), { keep: ["CRITICAL", "HIGH"] });
    assert.equal(put.status, 200, JSON.stringify(put.body));
    const b = put.body;
    assert.deepEqual([b.keep, b.scope, b.rebuilding], [["CRITICAL", "HIGH"], ["CRITICAL", "HIGH"], []]);
    assert.deepEqual(b.pending.map((p: any) => p.severity).sort(), ["LOW", "MEDIUM", "NONE"]);
    for (const p of b.pending) assert.ok(Math.abs(p.purgeAt - Date.now() - 3 * 86400_000) < 120_000, "a countdown of three days");
    assert.equal(b.pending[0].purgeAt <= b.pending[1].purgeAt, true);
    assert.ok(b.coverage && "scope" in b.coverage && "keptTotal" in b.coverage);
    assert.equal((await dbm.get<any>("SELECT COUNT(*) n FROM audit WHERE action = 'tenant.retention' AND tenant_id = ?", ids.ta))!.n, 1, "audited");
    await admin.post("/api/integrations/falcon/sync", { tenantId: ids.ta });
    await waitSync(admin);
    const c = (await a1.get("/api/exposure/summary")).body.completeness;
    assert.equal(c.state, "complete", "a deliberately reduced scope is not partial forever");
    assert.equal(c.falconCounts.total, total, "the totals still count every severity");
    assert.deepEqual([c.coverage.scope, c.coverage.held === c.coverage.keptTotal, c.coverage.falconTotal], [["CRITICAL", "HIGH"], true, total]);
    assert.ok(c.coverage.held < total);

    const back = await aAdmin.req("PUT", url(ids.ta), { keep: ALL });
    assert.deepEqual([back.body.pending, back.body.rebuilding.sort(), back.body.scope], [[], ["LOW", "MEDIUM", "NONE"], "all"], "re-ticked within three days: the purge is cancelled and the catch-up is queued");
    await waitSync(admin);
    await admin.post("/api/integrations/falcon/sync", { tenantId: ids.ta });
    await waitSync(admin);
    const c2 = (await a1.get("/api/exposure/summary")).body.completeness;
    assert.deepEqual([c2.state, c2.coverage.held, c2.coverage.scope], ["complete", total, "all"]);
    assert.deepEqual((await aAdmin.get(url(ids.ta))).body.rebuilding, []);
  });
});

describe("complete data collection", () => {
  const runSync = async (onProgress?: (p: any) => void) => falcon.syncFindings(new falcon.FalconClient((await falcon.configFor(CID_ONE))!), CID_ONE, onProgress);
  /** As if this CID had never been read by the sync: the next run is a first pass (the stored rows stay until it has seen what Falcon lists). */
  const restart = async () => { for (const t of ["cid_sync", "cid_cursor"]) await dbm.run(`DELETE FROM ${t} WHERE cid = ?`, CID_ONE); };
  const held = async () => (await dbm.get<{ n: number }>("SELECT COUNT(*) n FROM findings WHERE cid = ?", CID_ONE))!.n;
  const sizes = falcon.hooks.pageSizes;
  after(() => { falcon.hooks.pageSizes = sizes; mock.maxLimit = Infinity; });

  test("one big page reads everything without a cursor; progress is reported for every stage", async () => {
    falcon.hooks.pageSizes = [5000, 1000];
    await restart();
    const seen: any[] = [];
    const before = mock.requests.length;
    const r = await runSync((p) => seen.push(p));
    assert.equal(r.state, "complete");
    assert.equal(r.total, await held());
    assert.ok(mock.requests.slice(before).some((q) => q.includes("limit=5000")));
    const pages = mock.requests.slice(before).filter((q) => q.includes("sort=updated_timestamp") && !decodeURIComponent(q).includes("status:'expired'"));
    assert.equal(pages.length, 2, "one page for the fix-first slice and one for the backfill, no cursor");
    assert.ok(pages.every((q) => !q.includes("after=")));
    assert.deepEqual([...new Set(seen.map((p) => p.phase))], ["devices", "remediations", "findings"]);
    assert.equal(seen.at(-1).read, r.read);
    assert.equal(seen.at(-1).total, r.total);
  });

  test("a page size Falcon refuses falls back to the next size and says so", async () => {
    falcon.hooks.pageSizes = [5000, 1000];
    mock.maxLimit = 1000;
    await restart();
    const r = await runSync();
    mock.maxLimit = Infinity;
    assert.equal(r.state, "complete");
    assert.equal(r.total, await held());
    assert.ok(r.pages >= 2 && r.notes.some((n) => /refused 5000/.test(n)), JSON.stringify(r.notes));
  });

  test("findings that cannot be shown are counted with examples, and do not make the run partial", async () => {
    const base = { cid: CID_ONE, status: "open", cve: { id: "CVE-2099-0001", severity: "LOW" } };
    mock.add({ ...base, id: "no-aid-1", aid: "" }, { ...base, id: "no-aid-2", aid: "x".repeat(201) }, { ...base, id: "no-cve-1", aid: "a".repeat(32), cve: {} });
    try {
      falcon.hooks.pageSizes = [5000];
      await restart();
      const r = await runSync();
      assert.equal(r.state, "complete");
      assert.ok(r.notes.some((n) => /2 findings skipped: no device ID \(e\.g\. no-aid-1, no-aid-2\)/.test(n)), JSON.stringify(r.notes));
      assert.ok(r.notes.some((n) => /1 findings skipped: no CVE/.test(n)));
      assert.equal(await held(), r.total! - 3);
    } finally {
      mock.data.findings.splice(mock.data.findings.length - 3, 3);
      await restart();
      await runSync();
    }
  });

  test("notes are stored, shown to the admin and kept out of the customer's view", async () => {
    await runSync();
    await dbm.run("UPDATE cid_status SET notes_json = ? WHERE cid = ?", JSON.stringify(["example note"]), CID_ONE);
    const view = (await admin.get("/api/integrations/falcon")).body;
    assert.ok(view.cids.find((c: any) => c.cid === CID_ONE).notes.includes("example note"));
    assert.ok(!JSON.stringify((await a1.get("/api/exposure/summary")).body).includes("example note"));
  });

  test("external (EASM) assets and findings without a CVE are kept, with what they are; CVE facts are stored once", async () => {
    const easm = { cid: CID_ONE, status: "open", id: "easm-1", aid: "cid_ASxyz_AbCdEf123-45", vulnerability_id: "CS-C24-A1", data_providers: [{ provider: "Falcon EASM" }],
      host_info: { hostname: "shop.example.com", platform: "" }, apps: [{ product_name_version: "Unknown" }],
      cve: { id: "", severity: "MEDIUM", base_score: 5.3, types: ["Misconfiguration"], cwes: ["CWE-693"], description: "Missing XSS protection header", references: ["https://example.test/a", "https://example.test/a"], cisa_info: { is_cisa_kev: false } } };
    const sensor = { cid: CID_ONE, status: "open", id: "sensor-1", aid: "b".repeat(32), apps: [{ product_name_version: "Adobe Flash 21", vendor_normalized: "Adobe", evaluation_logic: { id: "ev_sensor-1" } }],
      created_timestamp: "2026-03-01T10:00:00Z", risk_score: 77, exploitability: "exploitable", host_info: { os_version: "Windows 11", internet_exposure: "Yes" },
      cve: { id: "CVE-2099-7777", severity: "CRITICAL", base_score: 9.8, types: ["Vulnerability"], cwes: ["CWE-416"], description: "Use-after-free in a media player", vendor_advisory: ["https://vendor.test/adv"], cisa_info: { is_cisa_kev: true }, exploitability_score: 2.8, impact_score: 5.9, vector: "CVSS:3.1/AV:N" } };
    const easmIp = { ...easm, id: "easm-ip", aid: "cid_ASipOnly_0123456789", host_info: { hostname: "240.0.3.57", platform: "" } };
    mock.add(easm, sensor, easmIp);
    try {
      falcon.hooks.pageSizes = [5000];
      const r = await runSync(); // a change since the last read: the incremental feed brings them
      assert.equal(r.state, "complete");
      const row = (id: string) => dbm.get<any>("SELECT * FROM findings WHERE cid = ? AND finding_id = ?", CID_ONE, id);
      const e = (await row("easm-1"))!;
      assert.deepEqual([e.cve_id, e.provider, e.kind, e.hostname, e.platform], ["CS-C24-A1", "Falcon EASM", "Misconfiguration", "shop.example.com", "External asset"]);
      const ipAsset = (await row("easm-ip"))!;
      assert.deepEqual([ipAsset.hostname, ipAsset.external_ip, ipAsset.platform], ["240.0.3.57", "240.0.3.57", "External asset"], "an EASM asset known only by its IP is named by it");
      assert.ok(r.notes.every((n) => !/no device ID/.test(n)), "an EASM asset id is a valid device id");
      assert.deepEqual(JSON.parse((await dbm.get<any>("SELECT references_json FROM cves WHERE id = 'CS-C24-A1'"))!.references_json), ["https://example.test/a"], "references are de-duplicated");
      assert.equal((await dbm.get<any>("SELECT cisa_kev FROM cves WHERE id = 'CVE-2099-7777'"))!.cisa_kev, 1);

      const d = (await a1.get("/api/exposure/vulnerabilities/CVE-2099-7777")).body;
      assert.equal(d.about.description, "Use-after-free in a media player");
      assert.deepEqual([d.about.cisaKev, d.about.cwes, d.about.advisories, d.about.vector], [true, ["CWE-416"], ["https://vendor.test/adv"], "CVSS:3.1/AV:N"]);
      assert.deepEqual(d.products.map((p: any) => p.name), ["Adobe Flash 21"]);
      assert.equal(d.devicesTotal, 1);
      assert.deepEqual([d.products[0].vendor, d.exposure.riskScore, d.exposure.internetFacing, d.exposure.exploitable], ["Adobe", 77, 1, 1], "exposure facts come from the finding");
      assert.equal(d.hosts[0].osVersion, "Windows 11");
      // how it was detected comes from Falcon on demand, for this tenant's own findings only
      const sw = (await a1.get("/api/exposure/vulnerabilities/CVE-2099-7777/software")).body;
      assert.equal(sw.state, "ok");
      assert.deepEqual([sw.fixedIn, sw.rows[0].path, sw.rows.length], [["2.0.0"], "C:\\Program Files\\Example\\app.exe", 1]);
      assert.match(sw.versions[0].version, /^1\.\d\.0$/);
      assert.equal((await b1.get("/api/exposure/vulnerabilities/CVE-2099-7777/software")).body.state, "none", "another tenant gets nothing about it");
      assert.equal((await a1.get("/api/exposure/vulnerabilities/CS-C24-A1/software")).body.state, "none", "external assets have no installed software");
      assert.equal((await a1.get("/api/exposure/vulnerabilities/bad%20id/software")).status, 400);
      const m = (await a1.get("/api/exposure/vulnerabilities/CS-C24-A1")).body;
      assert.deepEqual([m.found, m.kind, m.about.types], [true, "Misconfiguration", ["Misconfiguration"]]);
      assert.equal((await b1.get("/api/exposure/vulnerabilities/CS-C24-A1")).body.found, false, "another tenant does not see it, though the CVE facts table is shared");

      const src = async (v: string) => (await a1.get(`/api/exposure/vulnerabilities?source=${v}&pageSize=100&q=CS-C24`)).body.rows.map((x: any) => x.cveId);
      assert.deepEqual(await src("external"), ["CS-C24-A1"]);
      assert.deepEqual(await src("endpoint"), []);
      assert.equal((await a1.get("/api/exposure/vulnerabilities?source=bogus")).status, 400);
      const ext = (await a1.get("/api/exposure/hosts?source=external")).body.rows;
      assert.deepEqual(ext.map((h: any) => [h.hostname, h.provider]), [["240.0.3.57", "Falcon EASM"], ["shop.example.com", "Falcon EASM"]]);
      const total = (await a1.get("/api/exposure/summary")).body.totals.findings;
      assert.equal((await a1.get("/api/exposure/summary?source=external")).body.totals.findings, 2);
      assert.equal((await a1.get("/api/exposure/summary?source=endpoint")).body.totals.findings, total - 2);
      const host = (await a1.get(`/api/exposure/hosts/${encodeURIComponent(easm.aid)}`)).body;
      assert.deepEqual([host.hostname, host.provider, host.total], ["shop.example.com", "Falcon EASM", 1]);
    } finally {
      mock.data.findings.splice(mock.data.findings.length - 3, 3);
      await restart(); // the three are gone from Falcon: a full pass removes what it no longer lists
      await runSync();
    }
  });

  test("software inventory (Falcon Discover): grouped per tenant, unnamed entries skipped, isolation holds", async () => {
    const list = async (c: typeof a1, qs = "") => (await c.get(`/api/exposure/software?pageSize=100${qs}`)).body;
    const a = await list(a1);
    assert.equal(a.completeness?.state, "complete", JSON.stringify(a).slice(0, 300));
    assert.ok(a.rows.every((r: any) => r.name !== "-"), "entries Falcon gave no name are skipped");
    const chrome = a.rows.find((r: any) => r.name === "Google Chrome");
    assert.deepEqual([chrome.type, chrome.vendor, chrome.devices, chrome.versions], ["application", "Google", 6, 2]);
    assert.ok(a.byType.some((t: any) => t.type === "browser_extension"), "type chips cover the whole inventory");
    assert.equal(a.byType.reduce((n: number, t: any) => n + Number(t.items), 0), a.total, "the type counts add up to the products the list holds (not installs)");
    const ext = (await list(a1, "&type=browser_extension")).rows;
    assert.deepEqual(ext.map((r: any) => [r.name, r.suspicious]), [["Shady Coupons", true]]);
    assert.equal((await a1.get("/api/exposure/software?type=nope")).status, 400);
    assert.equal(JSON.stringify(a).includes(CID_ONE), false, "no CID for a customer");

    const item = (await a1.get(`/api/exposure/software/${chrome.key}`)).body;
    assert.deepEqual(item.versions.map((v: any) => [v.version, v.devices]), [["120.0.1", 3], ["121.0.2", 3]]);
    assert.equal(item.hosts.length, 6);
    const foreign = (await b1.get(`/api/exposure/software/${chrome.key}`)).body;
    assert.equal(foreign.found, true, "the same software exists in the other tenant...");
    const names = (r: any) => r.hosts.map((h: any) => h.hostname).sort().join();
    assert.notEqual(names(item) + item.hosts.map((h: any) => h.aid).join(), names(foreign) + foreign.hosts.map((h: any) => h.aid).join(), "...but with its own devices");
    assert.equal((await a1.get("/api/exposure/software/not-a-key")).status, 400);
    assert.equal((await a1.get(`/api/exposure/software?tenantId=${ids.tb}`)).status, 404, "a foreign tenant looks like a missing one");
    assert.equal((await soc.get("/api/exposure/software")).status, 400, "a super admin must name the tenant");
    assert.equal((await soc.get(`/api/exposure/software?tenantId=${ids.ta}`)).status, 200);
  });

  test("the trend range is a choice: 7, 14, 30 (default), 90, 180 or 365 days", async () => {
    assert.equal((await a1.get("/api/exposure/summary")).body.days, 30);
    for (const d of [7, 14, 90, 180, 365]) assert.equal((await a1.get(`/api/exposure/summary?days=${d}`)).body.days, d);
    assert.equal((await a1.get("/api/exposure/summary?days=5")).body.days, 30, "anything else falls back to 30");
    await dbm.run("INSERT INTO snapshots (cid, ts, critical, high, medium, low, \"none\", hosts, cves) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING", CID_ONE, Date.now() - 60 * 86400_000, 1, 1, 1, 1, 1, 1, 1);
    const within = async (d: number) => (await a1.get(`/api/exposure/summary?days=${d}`)).body.trend.length;
    assert.ok((await within(90)) > (await within(30)), "a 60 day old snapshot only shows in the 90 day view");
  });
});

describe("LINE news bot", () => {
  const SECRET = "line-channel-secret-for-tests";
  const CHAT = "Cgroup0000000000000000000000000001";
  const sign = (raw: string, secret = SECRET) => createHmac("sha256", secret).update(raw).digest("base64");
  const sent: { method: string; url: string; body: any }[] = [];
  const hit = async (events: unknown[], secret = SECRET) => {
    const raw = JSON.stringify({ destination: "U1", events });
    const r = await cl().req("POST", "/api/line/webhook", raw, { "X-Line-Signature": sign(raw, secret) });
    await Promise.all([...line.pending]);
    return r;
  };
  const msg = (id: string, text: string, chat = CHAT) => ({ type: "message", webhookEventId: id, replyToken: `rt-${id}`, source: { type: "group", groupId: chat, userId: "Uuser" }, message: { id: `m-${id}`, type: "text", text } });
  const strings = (o: any): string[] => Array.isArray(o) ? o.flatMap(strings) : o && typeof o === "object" ? Object.entries(o).flatMap(([k, v]) => k === "text" && typeof v === "string" ? [v] : strings(v)) : [];
  const textOf = (m: any): string => m.type === "text" ? m.text : [m.altText, ...strings(m.contents)].join("\n");
  const pushes = () => sent.filter((x) => x.url.endsWith("/push"));
  /** One entry per push request: the text of everything in it, Flex messages included. */
  const answers = () => pushes().map((x) => (x.body.messages as any[]).map(textOf).join("\n"));
  const newsCount = async () => (await dbm.get<{ n: number }>("SELECT COUNT(*) n FROM news_items"))!.n;
  let alphaCve = "";

  before(async () => {
    line.hooks.line = async (_t, method, url, body) => { sent.push({ method, url, body }); return { ok: true, status: 200, data: Buffer.from("png") }; };
    alphaCve = (await dbm.get<{ cve_id: string }>("SELECT cve_id FROM findings WHERE cid = ? AND cve_id LIKE 'CVE-%' LIMIT 1", CID_ONE))!.cve_id;
    const r = await admin.req("PUT", "/api/integrations/line", { channelSecret: SECRET, channelAccessToken: "line-token", allowedChats: [CHAT] });
    assert.equal(r.status, 200);
  });
  const reset = () => { sent.length = 0; };

  test("the secret and token are stored sealed and never returned; only a super admin can see or change the setup", async () => {
    const v = (await admin.get("/api/integrations/line")).body;
    assert.deepEqual([v.configured, v.hasSecret, v.hasToken, v.allowedChats], [true, true, true, [CHAT]]);
    assert.ok(!JSON.stringify(v).includes(SECRET) && !JSON.stringify(v).includes("line-token"));
    const raw = (await dbm.get<{ s: string }>("SELECT secret_sealed s FROM integrations WHERE key = 'line'"))!.s;
    assert.ok(!raw.includes(SECRET), "sealed at rest");
    assert.equal((await a1.get("/api/integrations/line")).status, 403);
    assert.equal((await admin.req("PUT", "/api/integrations/line", { allowedChats: ["bad id!"] })).status, 400);
  });

  test("a request with a wrong or missing signature is refused and stores nothing", async () => {
    reset();
    const before = await newsCount();
    const raw = JSON.stringify({ events: [msg("bad1", alphaCve)] });
    assert.equal((await cl().req("POST", "/api/line/webhook", raw, { "X-Line-Signature": sign(raw, "wrong") })).status, 401);
    assert.equal((await cl().req("POST", "/api/line/webhook", raw)).status, 401);
    assert.equal(await newsCount(), before);
    assert.equal(sent.length, 0);
  });

  test("a CVE in the message text is matched with each organization; a redelivery changes nothing", async () => {
    reset();
    PUBLISHED.set(alphaCve, cveRecord(alphaCve, { score: 9.8 }));
    await dbm.run(`INSERT INTO cves (id, description, advisories_json, updated_at) VALUES (?, 'x', ?, ?) ON CONFLICT (id) DO UPDATE SET advisories_json = excluded.advisories_json`, alphaCve, JSON.stringify([`https://vendor.example.com/security/${alphaCve}`]), Date.now());
    const before = await newsCount();
    assert.equal((await hit([msg("ev1", `ข่าวด่วน ${alphaCve} และ CVE-2023-99999`)])).status, 200);
    assert.equal(await newsCount(), before + 1);
    assert.ok(pushes().length === 1 && pushes()[0].body.messages.length === 1 && pushes()[0].body.messages[0].type === "flex", "ONE Flex message in the chat");
    const cards = pushes()[0].body.messages[0].contents;
    assert.ok(cards.type === "carousel" && cards.contents.length === 4, "per organization with devices (Alpha, Beta): the details card and, beside it, the remediation card; no summary card");
    const fixCard = JSON.stringify(cards.contents[1]);
    const fixes = (await dbm.get<{ r: string }>("SELECT remediation r FROM findings WHERE cid = ? AND cve_id = ? AND remediation IS NOT NULL LIMIT 1", CID_ONE, alphaCve))?.r.split("\n")[0].replace(/^- /, "");
    assert.ok(fixes && fixCard.includes(fixes) && fixCard.includes("วิธีแก้ไขที่ CrowdStrike Falcon แนะนำ"), "what Falcon recommends");
    assert.ok(fixCard.includes('"type":"uri"') && fixCard.includes("catalog.example"), "buttons that open pages");
    assert.ok(fixCard.includes("https://catalog.example/kb") && fixCard.includes("https://vendor.example.com/security/" + alphaCve), "each action opens its own page, and the vendor's page for the CVE is linked");
    assert.ok(!answers()[0].includes("สรุปผลการตรวจข่าว") && answers()[0].includes("CVE-2023-99999"), "what no card covers (a CVE nobody has) is at the bottom of the first card");
    const text = answers().join("\n");
    assert.ok(text.includes(alphaCve) && text.includes("Alpha Corp") && text.includes("CVE-2023-99999"), text);
    assert.ok(/Alpha Corp/.test(answers()[0]), "the card names the organization");
    assert.ok(text.includes(`Description of ${alphaCve}`) && text.includes("CVSS 9.8"), "what the CVE is, from the CVE Program");
    assert.ok(text.includes("รอข้อมูลจาก CVE Program") && text.includes("รอผลตรวจ"), "named in the news before the CVE Program has it: say so, and do not claim 'not found'");
    const dv = (await dbm.get<{ h: string; v: string }>("SELECT hostname h, product v FROM findings WHERE cid = ? AND cve_id = ? AND product IS NOT NULL AND hostname IS NOT NULL LIMIT 1", CID_ONE, alphaCve));
    assert.ok(dv && text.includes(dv.h) && text.includes(dv.v), "each device is listed with the version it runs");
    const devRow = pushes()[0].body.messages[0].contents.contents[0].body.contents.flatMap(function walk(c: any): any[] { return c.contents ? [c, ...c.contents.flatMap(walk)] : [c]; }).find((c: any) => c.type === "box" && c.layout === "horizontal" && c.contents?.length === 3 && c.contents[1].text === dv!.h);
    assert.ok(devRow && devRow.contents[0].backgroundColor && devRow.contents[2].type === "box" && devRow.contents[2].contents.some((t: any) => t.text === dv!.v && t.align === "end"), "a coloured dot, the name on the left, versions stacked and aligned to the right edge")
    assert.ok(!text.includes(CID_ONE) && !text.includes(CID_TWO), "no CIDs in the chat");
    assert.ok(!text.includes("OCR") && !text.includes("และอีก"));
    const hostnames = (await dbm.all<{ h: string }>("SELECT DISTINCT COALESCE(hostname, substr(aid, 1, 8)) h FROM findings WHERE cid = ? AND cve_id = ?", CID_ONE, alphaCve)).map((r) => r.h);
    assert.ok(hostnames.length > 0 && hostnames.every((h) => pushes().some((x) => x.body.messages.some((m: any) => m.type === "flex" && textOf(m).includes("Alpha Corp") && h && textOf(m).includes(h)))), "every device name is listed, none cut");
    const row = (await dbm.get<any>("SELECT * FROM news_items ORDER BY received_at DESC LIMIT 1"));
    assert.deepEqual([row.cve_result, row.reply_status], ["found", "sent"]);
    assert.equal((await dbm.get<{ n: number }>("SELECT COUNT(*) n FROM news_cves WHERE news_id = ?", row.id))!.n, 2);
    const n = sent.length;
    assert.equal((await hit([msg("ev1", `ข่าวด่วน ${alphaCve} และ CVE-2023-99999`)])).status, 200);
    assert.equal(await newsCount(), before + 1, "no second news item");
    assert.equal(sent.length, n, "no second answer");
  });

  test("a link to a site that needs a login is not fetched, and the answer says it could not read it instead of 'no CVE found'", async () => {
    reset();
    let fetched = 0;
    const orig = line.hooks.fetchPage; line.hooks.fetchPage = async (u: string) => { fetched++; return orig(u); };
    try {
      await hit([msg("evfb", "https://www.facebook.com/share/p/1JwMfmuMdt/")]);
    } finally { line.hooks.fetchPage = orig; }
    assert.equal(fetched, 0, "nothing is requested from a login wall");
    const said = answers().join("\n");
    assert.ok(said.includes("ตรวจไม่ได้") && said.includes("ส่งภาพหน้าจอ") && !said.includes("ไม่พบรหัส CVE"), said);
    assert.equal((await dbm.get<any>("SELECT cve_result FROM news_items ORDER BY received_at DESC LIMIT 1")).cve_result, "not_evaluated");
  });

  test("the link to a CVE in Falcon is Spotlight's page for it, in the cloud of the organization's own connection", async () => {
    const falconm = await import("../src/falcon.ts");
    assert.equal(await falconm.falconLink("CVE-2026-6460", "https://api.us-2.crowdstrike.com"),
      "https://falcon.us-2.crowdstrike.com/spotlight/vulnerabilities/group-by/vulnerability-id/instances/CVE-2026-6460?activeDetailTab=Remediations&activeTab=overview&filter=");
    assert.ok((await falconm.falconLink("CVE-2026-6460", "https://api.eu-1.crowdstrike.com"))!.startsWith("https://falcon.eu-1.crowdstrike.com/spotlight/"), "each organization's own cloud");
    assert.equal(await falconm.falconLink("CVE-2026-6460", "http://127.0.0.1:8791"), null, "no https Falcon cloud: no link");
    assert.equal(await falconm.falconLink("CVE-2026-6460"), null, "the test's shared login is a local mock");
  });

  test("a link to this portal (or to the system behind the forward URL) is conversation: nothing is fetched, stored or answered", async () => {
    reset();
    const before = await newsCount();
    let fetched = 0;
    const orig = line.hooks.fetchPage; line.hooks.fetchPage = async (u: string) => { fetched++; return orig(u); };
    try {
      const host = new URL((await admin.get("/api/integrations/line")).body.webhookUrl).origin;
      await hit([msg("evown1", `เสร็จแล้วครับ เป็น ${host}/signin แต่หน้า login ยังไม่ได้เปลี่ยน`)]);
      assert.equal(await newsCount(), before, "no news item");
      assert.equal(sent.length, 0, "and no answer in the chat");
      assert.equal(fetched, 0);
      // a CVE in the same message is still checked, and the portal link is still not fetched
      await hit([msg("evown2", `${host}/signin ${alphaCve}`)]);
      assert.equal(await newsCount(), before + 1);
      assert.ok(answers().join("\n").includes(alphaCve) && fetched === 0);
    } finally { line.hooks.fetchPage = orig; }
  });

  test("outside the allowed chats the bot is silent, except for /chatid, which gets the chat id and nothing else", async () => {
    reset();
    const OTHER = "Cother0000000000000000000000000002";
    const before = await newsCount();
    await hit([msg("ev2", alphaCve, OTHER), msg("ev2b", "hello there", OTHER)]);
    assert.equal(await newsCount(), before, "nothing is stored for a chat that was not allowed");
    assert.equal(sent.length, 0, "and nothing is said: the channel may belong to another system");
    await hit([msg("ev2c", "/chatid", OTHER)]);
    const out = sent.map((x) => textOf(x.body.messages[0]));
    assert.ok(out.length === 1 && out[0].includes(OTHER) && !out[0].includes("Alpha"));
    assert.equal(sent[0].url.endsWith("/push"), true);
  });

  test("in an allowed chat only links, CVE ids and pictures are for the bot; and no reply token is ever used", async () => {
    reset();
    const before = await newsCount();
    await hit([msg("ev2d", "ประชุมบ่ายนี้กี่โมงครับ")]);
    assert.equal(await newsCount(), before);
    assert.equal(sent.length, 0);
    line.hooks.ocr = async () => ({ status: "ok", text: "a meme with no identifiers" });
    await hit([{ type: "message", webhookEventId: "ev2e", replyToken: "rt", source: { type: "group", groupId: CHAT }, message: { id: "img0", type: "image" } }]);
    assert.equal(await newsCount(), before + 1, "the picture is kept as evidence");
    assert.equal(answers().length, 0, "a picture with no CVE gets no answer");
    assert.equal((await dbm.get<any>("SELECT cve_result, reply_status FROM news_items ORDER BY received_at DESC LIMIT 1")).cve_result, "none_found");
    await hit([msg("ev2f", `${alphaCve} please check`)]);
    assert.ok(answers().length >= 1);
    assert.ok(sent.every((x) => !x.url.endsWith("/reply")), "a reply token works once; the other system that owns the webhook may need it");
  });

  test("the answer can go to a chosen chat instead of the one the news came from, and says what it is about", async () => {
    const DEST = "Canswer0000000000000000000000000009";
    assert.equal((await admin.req("PUT", "/api/integrations/line", { allowedChats: [CHAT], answerChat: "bad id!" })).status, 400);
    assert.equal((await admin.req("PUT", "/api/integrations/line", { allowedChats: [CHAT], answerChat: DEST })).body.answerChat, DEST);
    reset();
    await hit([msg("ev7", `ดูข่าวนี้ ${alphaCve}`)]);
    assert.ok(pushes().length >= 1 && pushes().every((x) => x.body.to === DEST), "sent to the chosen chat");
    assert.ok(!sent.some((x) => x.body?.to === CHAT), "nothing goes back to the chat the news came from");
    const text = answers().join("\n");
    assert.ok(answers().at(-1)!.includes("ข่าว: ") && text.includes(alphaCve) && text.includes("Alpha Corp"), text);
    // emptied again: answers go back to the chat they were asked in
    assert.equal((await admin.req("PUT", "/api/integrations/line", { allowedChats: [CHAT], answerChat: "" })).body.answerChat, "");
    reset();
    await hit([msg("ev8", `ดูข่าวนี้ ${alphaCve}`)]);
    assert.ok(pushes().length >= 1 && pushes().every((x) => x.body.to === CHAT));
  });

  test("answers can go to several chats, each with a name; a name is for the setup page only", async () => {
    const D1 = "Cdest10000000000000000000000000001", D2 = "Cdest20000000000000000000000000002";
    assert.equal((await admin.req("PUT", "/api/integrations/line", { allowedChats: [CHAT], answerChats: [D1, "bad id!"] })).status, 400);
    assert.equal((await admin.req("PUT", "/api/integrations/line", { allowedChats: [CHAT], answerChats: [D1], chatNames: { "bad id!": "x" } })).status, 400);
    const put = (await admin.req("PUT", "/api/integrations/line", { allowedChats: [CHAT], answerChats: [D1, D2, D1], chatNames: { [D1]: "SOC TENFORWARD", [D2]: "  ลูกค้า A  ", [CHAT]: "x".repeat(200) } })).body;
    assert.deepEqual([put.answerChats, put.answerChat, put.chatNames[D1], put.chatNames[D2], put.chatNames[CHAT].length], [[D1, D2], D1, "SOC TENFORWARD", "ลูกค้า A", 60]);
    assert.deepEqual((await admin.req("PUT", "/api/integrations/line", { allowedChats: [CHAT] })).body.answerChats, [D1, D2], "left out: the list stays");
    reset();
    await hit([msg("evm1", `ดูข่าว ${alphaCve}`)]);
    const to = [...new Set(pushes().map((x) => x.body.to))].sort();
    assert.deepEqual(to, [D1, D2], "the same answer reaches every chat on the list, and not the chat it came from");
    assert.equal(answers().filter((a) => a.includes(alphaCve)).length, 2);
    assert.ok(!pushes().some((x) => x.body.to === CHAT));
    // the old one-chat form still works and replaces the list
    assert.deepEqual((await admin.req("PUT", "/api/integrations/line", { allowedChats: [CHAT], answerChat: D2 })).body.answerChats, [D2]);
    assert.deepEqual((await admin.req("PUT", "/api/integrations/line", { allowedChats: [CHAT], answerChats: [] })).body.answerChats, []);
  });

  test("each organization has its own news sources and its own destination groups, as many as it needs; a source is read for that organization only", async () => {
    const tenants = (await admin.get("/api/tenants")).body.tenants as { id: string; name: string }[];
    const alpha = tenants.find((t) => t.name === "Alpha Corp")!, beta = tenants.find((t) => t.name === "Beta Ltd")!;
    const SA = "Csrcalpha000000000000000000000001", DA1 = "Cdstalpha100000000000000000000001", DA2 = "Cdstalpha200000000000000000000002", DB = "Cdstbeta0000000000000000000000003";
    assert.equal((await a1.req("PUT", `/api/tenants/${alpha.id}/line`, { sources: [], destinations: [] })).status, 403, "super admins only");
    assert.equal((await admin.req("PUT", `/api/tenants/${alpha.id}/line`, { sources: [{ chat: "bad id!" }] })).status, 400);
    const put = await admin.req("PUT", `/api/tenants/${alpha.id}/line`, { sources: [{ chat: SA, name: "Alpha IT news" }], destinations: [{ chat: DA1, name: "Alpha SOC room" }, { chat: DA2, name: "Alpha managers" }, { chat: DA1 }] });
    assert.deepEqual([put.status, put.body.sources, put.body.destinations.map((d: any) => d.chat), put.body.destinations[1].name], [200, [{ chat: SA, name: "Alpha IT news" }], [DA1, DA2], "Alpha managers"]);
    assert.equal((await admin.req("PUT", `/api/tenants/${beta.id}/line`, { destinations: [{ chat: DA2 }] })).status, 409, "a chat belongs to one organization per role");
    assert.equal((await admin.req("PUT", `/api/tenants/${beta.id}/line`, { sources: [{ chat: CHAT }] })).status, 409, "nor to a tenant when it is the SOC's");
    assert.equal((await admin.req("PUT", `/api/tenants/${beta.id}/line`, { sources: [{ chat: DA1 }] })).status, 409, "a chat is one owner's in EVERY role: Alpha's destination is not Beta's source");
    assert.equal((await admin.req("PUT", `/api/tenants/${beta.id}/line`, { destinations: [{ chat: SA }] })).status, 409, "nor Alpha's source Beta's destination");
    assert.equal((await admin.req("PUT", `/api/tenants/${beta.id}/line`, { destinations: [{ chat: DB, name: "Beta room" }] })).status, 200);
    const list = (await admin.get("/api/tenants")).body.tenants.find((t: any) => t.id === alpha.id);
    assert.deepEqual(list.line, { sources: 1, destinations: 2 });
    assert.ok((await admin.get("/api/integrations/line")).body.tenantGroups.some((g: any) => g.chat === DA2 && g.tenant === "Alpha Corp" && g.name === "Alpha managers"));
    try {
      // news posted in Alpha's own source chat: read for Alpha only, answered to BOTH of Alpha's groups, and nobody else hears of it
      reset();
      await hit([msg("evt1", `ข่าว ${alphaCve}`, SA)]);
      const to = [...new Set(pushes().map((x) => x.body.to))].sort();
      assert.deepEqual(to, [DA1, DA2, SA], "every destination of the organization, plus a short confirmation where the news was posted; no one else (not Beta, not the SOC chat)");
      assert.ok(pushes().filter((x) => x.body.to === SA).every((x) => x.body.messages.map(textOf).join("\n").includes("ส่งเข้ากลุ่มของแต่ละองค์กรแล้ว")), "the source chat only gets the confirmation");
      const text = answers().join("\n");
      assert.ok(text.includes("Alpha Corp") || text.includes("องค์กรของคุณ"));
      assert.ok(!text.includes("Beta"), "Beta's data is not in Alpha's answer");
      // an organization with no destination is answered in the chat the news came from
      await admin.req("PUT", `/api/tenants/${alpha.id}/line`, { destinations: [] });
      reset();
      await hit([msg("evt2", `ข่าว ${alphaCve}`, SA)]);
      assert.deepEqual([...new Set(pushes().map((x) => x.body.to))], [SA], "no destination: the answer stays where the news was posted");
      await admin.req("PUT", `/api/tenants/${alpha.id}/line`, { destinations: [{ chat: DA1 }, { chat: DA2 }] });
      // news from the SOC's chat still reaches every group of every organization that has some
      reset();
      await hit([msg("evt3", `ข่าว ${alphaCve}`)]);
      const toAll = pushes().map((x) => x.body.to);
      assert.ok(toAll.includes(DA1) && toAll.includes(DA2) && toAll.includes(DB), "all destinations of all organizations");
      const aText = pushes().filter((x) => x.body.to === DA1).map((x) => x.body.messages.map(textOf).join("\n")).join("\n");
      assert.ok(!aText.includes("Beta"), "and each only its own data");
    } finally {
      for (const t of [alpha, beta]) await admin.req("PUT", `/api/tenants/${t.id}/line`, { sources: [], destinations: [] });
    }
  });

  test("each organization with its own LINE group gets its own message: its devices only, 'your organization', and 'not found' too", async () => {
    const tenants = (await admin.get("/api/tenants")).body.tenants as { id: string; name: string }[];
    const alpha = tenants.find((t) => t.name === "Alpha Corp")!, beta = tenants.find((t) => t.name === "Beta Ltd")!;
    const GA = "Calpha000000000000000000000000000a", GB = "Cbeta0000000000000000000000000000b";
    assert.equal((await a1.req("PUT", `/api/tenants/${alpha.id}/line-chat`, { lineChat: GA })).status, 403, "super admins only");
    assert.equal((await admin.req("PUT", `/api/tenants/${alpha.id}/line-chat`, { lineChat: "bad id!" })).status, 400);
    assert.equal((await admin.req("PUT", `/api/tenants/${alpha.id}/line-chat`, { lineChat: GA })).status, 200);
    assert.equal((await admin.req("PUT", `/api/tenants/${beta.id}/line-chat`, { lineChat: GA })).status, 409, "one group, one organization");
    assert.equal((await admin.req("PUT", `/api/tenants/${beta.id}/line-chat`, { lineChat: GB })).status, 200);
    assert.equal((await admin.get("/api/tenants")).body.tenants.find((t: any) => t.id === alpha.id).lineChat, GA);
    try {
      reset();
      const NOHIT = "CVE-2023-88888"; PUBLISHED.set(NOHIT, cveRecord(NOHIT)); // announced long ago, and nobody has it
      await hit([msg("evg1", `${alphaCve} และ ${NOHIT}`)]);
      const toAlpha = pushes().filter((x) => x.body.to === GA), toBeta = pushes().filter((x) => x.body.to === GB), toSoc = pushes().filter((x) => x.body.to === CHAT);
      assert.ok(toAlpha.length >= 1 && toBeta.length >= 1 && toSoc.length === 1);
      const a = toAlpha.flatMap((x) => x.body.messages.map(textOf)).join("\n"), b = toBeta.flatMap((x) => x.body.messages.map(textOf)).join("\n");
      assert.ok(a.includes("องค์กรของคุณ") && a.includes(alphaCve) && a.includes(`องค์กรของคุณไม่พบเครื่องที่เกี่ยวข้อง`), "the customer is told, also when nothing was found");
      assert.ok(!a.includes("Alpha Corp") && !a.includes("Beta") && !b.includes("Alpha") && !b.includes("Alpha Corp"), "no organization name, nobody else's data");
      const alphaHosts = (await dbm.all<{ h: string }>("SELECT DISTINCT COALESCE(hostname, substr(aid, 1, 8)) h FROM findings WHERE cid = ? AND cve_id = ?", CID_ONE, alphaCve)).map((r) => r.h);
      const betaHosts = (await dbm.all<{ h: string }>("SELECT DISTINCT COALESCE(hostname, substr(aid, 1, 8)) h FROM findings WHERE cid = ? AND cve_id = ?", CID_TWO, alphaCve)).map((r) => r.h);
      assert.ok(alphaHosts.every((h) => a.includes(h)), "all of its devices");
      assert.ok(betaHosts.filter((h) => !alphaHosts.includes(h)).every((h) => !a.includes(h)), "no device of another organization");
      assert.ok(!(await dbm.get<{ r: string }>("SELECT reply_status r FROM news_items ORDER BY received_at DESC LIMIT 1"))!.r.startsWith("failed"));
      assert.ok(answers().at(-1)!.includes("ส่งเข้ากลุ่มของแต่ละองค์กรแล้ว"), "the SOC chat gets the summary");
    } finally {
      await admin.req("PUT", `/api/tenants/${alpha.id}/line-chat`, { lineChat: "" });
      await admin.req("PUT", `/api/tenants/${beta.id}/line-chat`, { lineChat: "" });
    }
  });

  test("a long device list is sent in full, split over bubbles and messages within LINE's limits", () => {
    const names = Array.from({ length: 400 }, (_, i) => ({ name: `host-${String(i).padStart(4, "0")}.corp.example`, versions: i % 5 === 0 ? [`Product ${i % 7}.${i}.1`, `Product 9.${i}`] : [`Product ${i % 7}.${i}.1`], severity: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"][i % 5] }));
    const hit = { id: "t", tenant: "T", chats: [] as string[], devices: names.length, severity: "HIGH", names, console: null, complete: true, state: "affected" as const, asOf: Date.now(), fixes: [{ text: "Update to 9.9", devices: 400, link: "https://catalog.example/kb1", type: "recommended" }, { text: "Hotfix 9.8", devices: 20, link: null, type: "minimum" }] };
    const about = { announced: true, rejected: false, title: "Example title", description: "x".repeat(900), cvss: 9.8, cvssSeverity: "CRITICAL", publishedAt: Date.now(), kev: null };
    const { messages, truncated } = line.flexMessages("องค์กรของคุณ", [{ cve: "CVE-2024-0001", kev: true, hit, about, link: "https://falcon.us-2.crowdstrike.com/", advisory: "https://vendor.example.com/advisory/x" }], { source: "https://news.example/a" });
    assert.equal(truncated, false);
    const all = JSON.stringify(messages);
    assert.ok(names.every((n) => all.includes(n.name) && n.versions.every((v) => all.includes(v))), "every name with its version, no 'and N more'");
    for (const m of messages as any[]) {
      assert.ok(Buffer.byteLength(JSON.stringify(m)) < 50_000, "under the Flex message limit");
      const bubbles = m.contents.type === "carousel" ? m.contents.contents : [m.contents];
      assert.ok(bubbles.length <= 12 && m.altText.length <= 400);
      for (const b of bubbles) for (const c of b.body.contents) if (c.text) assert.ok(c.text.length <= 2000);
    }
    assert.ok(messages.length > 1);
    const none = line.flexMessages("องค์กรของคุณ", [{ cve: "CVE-2024-0002", kev: false, about, link: null, advisory: null, hit: { ...hit, devices: 0, names: [], severity: "", state: "not_found" as const } }], {});
    assert.ok(JSON.stringify(none.messages).includes("องค์กรของคุณไม่พบเครื่องที่เกี่ยวข้อง"));
    // the remediation card: each action opens its own page, the logo is the button to Falcon, the vendor page is a second link
    const row = { cve: "CVE-2024-0001", kev: true, hit, about, link: "https://falcon.us-2.crowdstrike.com/x", advisory: "https://vendor.example.com/advisory/x" };
    const card2 = JSON.stringify(line.fixBubble("T", row));
    assert.ok(card2.includes('"label":"ดูต่อเพิ่มเติม"') && card2.includes('"uri":"https://falcon.us-2.crowdstrike.com/x"') && !card2.includes('"type":"image"'), "one button, 'see more', to Falcon: no logo");
    assert.ok(card2.includes('"uri":"https://catalog.example/kb1"') && card2.includes("ประกาศจากผู้ผลิต") && card2.includes("แนะนำ") && card2.includes("ขั้นต่ำ"));
    const withLogo = JSON.stringify(line.fixBubble("T", row, "https://easm.example.com"));
    assert.ok(withLogo.includes('"url":"https://easm.example.com/brand/team.png"') && withLogo.includes('"aspectRatio":"480:196"') && withLogo.includes('"size":"88px"') && withLogo.includes('"uri":"https://falcon.us-2.crowdstrike.com/x"'), "the team's logo, small, in its own proportions, linking to Falcon");
    assert.ok(!JSON.stringify(line.fixBubble("T", { ...row, link: null, advisory: null })).includes('"footer"'), "nothing to link to, no footer");
    assert.ok(JSON.stringify(line.flexMessages("T", [row], {}).messages).includes('"size":"giga"'), "wide cards");
    // a device with two versions is one block with both, and blocks are separated by a rule
    const two = JSON.stringify(line.flexMessages("องค์กรของคุณ", [{ ...row, hit: { ...hit, devices: 2, names: [{ name: "HOST-A", versions: ["V 1.0", "V 2.0"], severity: "CRITICAL" }, { name: "HOST-B", versions: ["V 3.0"], severity: "LOW" }] } }], {}).messages);
    assert.ok(two.includes("CRITICAL 1") && two.includes("LOW 1") && two.includes('"backgroundColor":"#dc2626"') && two.includes('"backgroundColor":"#16a34a"'), "devices of mixed severity are split into coloured chips and each has a coloured dot");
    assert.ok(JSON.stringify(line.flexMessages("T", [{ ...row, hit: { ...hit, severity: "NONE", names: [{ name: "H", versions: ["v"], severity: "NONE" }] } }], {}).messages).includes("INFORMATIONAL"), "Informational is its own blue level");
    assert.ok(two.includes("HOST-A") && two.includes("V 1.0") && two.includes("V 2.0") && two.includes('"type":"separator","margin":"sm","color":"#d1d5db"'));
  });

  test("a verified request is passed on unchanged to the other system, a wrong signature is not, and our failures do not change the answer", async () => {
    const fwd: { url: string; raw: string; headers: Record<string, string> }[] = [];
    let status = 200;
    const orig = line.hooks.forward;
    line.hooks.forward = async (url, raw, headers) => { fwd.push({ url, raw: raw.toString("utf8"), headers }); return status; };
    const saved = { ...line.forwardTuning }; line.forwardTuning.retryMs = [0, 0];
    try {
      const URL_ = "https://other.example/api/line/webhook";
      for (const bad of ["http://other.example/x", "https://user:pw@other.example/x", "not a url", `${(await admin.get("/api/integrations/line")).body.webhookUrl}`])
        assert.equal((await admin.req("PUT", "/api/integrations/line", { forwardUrl: bad })).status, 400, bad);
      assert.equal((await admin.req("PUT", "/api/integrations/line", { allowedChats: [CHAT], answerChat: "", forwardUrl: URL_ })).body.forwardUrl, URL_);
      assert.equal((await admin.req("PUT", "/api/integrations/line", { allowedChats: [CHAT] })).body.forwardUrl, URL_, "a request without the field keeps it");

      // exact bytes, odd spacing and Thai text included: re-serialising would break the other system's signature check
      const raw = `{ "destination":"U1",  "events":[ ${JSON.stringify(msg("fw1", "สวัสดี ไม่มีข่าว"))} ] }`;
      assert.equal((await cl().req("POST", "/api/line/webhook", raw, { "X-Line-Signature": sign(raw) })).status, 200);
      await Promise.all([...line.pending]);
      assert.equal(fwd.length, 1);
      assert.equal(fwd[0].raw, raw);
      assert.equal(fwd[0].headers["X-Line-Signature"], sign(raw));
      assert.equal(fwd[0].url, URL_);
      assert.equal(line.forwardState.ok, true);

      // LINE's "Verify" button sends no events: still passed on
      const empty = '{"destination":"U1","events":[]}';
      await cl().req("POST", "/api/line/webhook", empty, { "X-Line-Signature": sign(empty) });
      await Promise.all([...line.pending]);
      assert.equal(fwd.length, 2);

      // wrong signature: refused and never passed on
      assert.equal((await cl().req("POST", "/api/line/webhook", raw, { "X-Line-Signature": sign(raw, "wrong") })).status, 401);
      await Promise.all([...line.pending]);
      assert.equal(fwd.length, 2);

      // the other system is down: LINE still gets 200, three attempts, then the page shows the failure
      status = 503;
      assert.equal((await cl().req("POST", "/api/line/webhook", raw, { "X-Line-Signature": sign(raw) })).status, 200);
      await Promise.all([...line.pending]);
      assert.equal(fwd.length, 5, "one try and two retries");
      assert.equal(line.forwardState.ok, false);
      assert.equal((await admin.get("/api/integrations/line")).body.forward.status, 503);
      // a refusal (4xx) is not retried
      status = 401; fwd.length = 0;
      await cl().req("POST", "/api/line/webhook", raw, { "X-Line-Signature": sign(raw) });
      await Promise.all([...line.pending]);
      assert.equal(fwd.length, 1);

      // switched off
      assert.equal((await admin.req("PUT", "/api/integrations/line", { allowedChats: [CHAT], forwardUrl: "" })).body.forwardUrl, "");
      fwd.length = 0;
      await cl().req("POST", "/api/line/webhook", raw, { "X-Line-Signature": sign(raw) });
      await Promise.all([...line.pending]);
      assert.equal(fwd.length, 0);
    } finally {
      line.hooks.forward = orig; line.forwardTuning.retryMs = saved.retryMs;
      await admin.req("PUT", "/api/integrations/line", { allowedChats: [CHAT], forwardUrl: "" });
    }
  });

  test("a link is read for CVEs; a link that cannot be opened is never reported as 'no CVE'", async () => {
    reset();
    line.hooks.fetchPage = async () => ({ status: "ok", finalUrl: "https://news.example/a", http: 200, contentType: "text/html", hash: "h", text: `Patch now for ${alphaCve}. Also CVE\u20112024\u20113400 is exploited.` });
    await hit([msg("ev3", "https://news.example/a")]);
    const ok = answers().join("\n");
    assert.ok(ok.includes(alphaCve) && ok.includes("CVE-2024-3400"), "dashes that look like hyphens are normalised");
    const src = await dbm.all<{ source: string }>("SELECT source FROM news_cves WHERE news_id = (SELECT id FROM news_items ORDER BY received_at DESC LIMIT 1)");
    assert.ok(src.every((x) => x.source === "article"));
    reset();
    line.hooks.fetchPage = async () => { throw new line.FetchError("timeout"); };
    await hit([msg("ev4", "https://slow.example/x")]);
    const row = await dbm.get<any>("SELECT cve_result FROM news_items ORDER BY received_at DESC LIMIT 1");
    assert.equal(row.cve_result, "not_evaluated");
    assert.ok(answers()[0].includes("ตรวจไม่ได้"));
  });

  test("a picture is read with OCR and repaired digits are checked", async () => {
    reset();
    line.hooks.ocr = async () => ({ status: "ok", text: "Security advisory\nCVE-2O23-4863 is being exploited\nCVE-1888-0001" });
    await hit([{ type: "message", webhookEventId: "ev5", replyToken: "rt5", source: { type: "group", groupId: CHAT }, message: { id: "img1", type: "image" } }]);
    assert.ok(sent.some((x) => x.method === "GET" && x.url.includes("/message/img1/content")), "the picture is fetched from LINE");
    const text = answers().join("\n");
    assert.ok(text.includes("CVE-2023-4863") && !text.includes("CVE-1888"), text);
    assert.ok(!text.includes("OCR"), "no disclaimer about how the CVE was read");
    reset();
    line.hooks.ocr = async () => ({ status: "unavailable" });
    await hit([{ type: "message", webhookEventId: "ev6", replyToken: "rt6", source: { type: "group", groupId: CHAT }, message: { id: "img2", type: "image" } }]);
    assert.ok(answers()[0].includes("ตรวจไม่ได้"));
  });

  test("the CVE reader does not guess", () => {
    assert.deepEqual(line.extractCves("cve-2024-3400, CVE-2024-3400 and CVE-2024-12"), ["CVE-2024-3400"]);
    assert.deepEqual(line.extractCves("CVE-3024-1234 CVE-1998-1234"), [], "impossible years are refused");
    assert.deepEqual(line.extractCvesFromOcr("CVE-2O24-l234"), ["CVE-2024-1234"]);
    assert.deepEqual(line.urlsIn("see https://a.example/x?y=1). and http://b.example, ok"), ["https://a.example/x?y=1", "http://b.example"]);
  });

  test("links to internal addresses are refused before any connection is made", async () => {
    for (const ip of ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "224.0.0.1", "not-an-ip"]) assert.ok(line.isBlockedAddress(ip), ip);
    for (const ip of ["8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"]) assert.ok(!line.isBlockedAddress(ip), ip);
    for (const u of ["file:///etc/passwd", "ftp://x.example/", "http://x.example:8080/", "https://user:pw@x.example/", "gopher://x.example"]) assert.throws(() => line.checkUrl(u), (e: any) => e.status === "blocked_by_policy", u);
    // a real local server must not be reachable through the fetcher
    const srv = (await import("node:http")).createServer((_q, r) => r.end("secret")).listen(0, "127.0.0.1");
    await new Promise((r) => srv.once("listening", r));
    try {
      await assert.rejects(() => line.safeFetch(`http://127.0.0.1:${(srv.address() as AddressInfo).port}/`), (e: any) => e.status === "blocked_by_policy");
      await assert.rejects(() => line.safeFetch("http://localhost/"), (e: any) => e.status === "blocked_by_policy");
    } finally { srv.close(); }
  });
});

describe("public feeds, impact status and urgent items over the API", () => {
  test("feed status is readable by every signed-in user; only a super admin changes the intervals, and they are validated", async () => {
    assert.equal((await cl().get("/api/feeds/status")).status, 401);
    const v = (await a1.get("/api/feeds/status")).body;
    assert.deepEqual([v.config.cveMinutes, v.config.kevMinutes, v.config.enabled], [10, 60, true], "defaults: the CVE List every 10 minutes, KEV hourly");
    assert.ok(v.cveList && v.kev && v.counts);
    assert.equal((await a1.req("PUT", "/api/integrations/feeds", { cveMinutes: 5 })).status, 403);
    for (const bad of [{ cveMinutes: 1 }, { cveMinutes: "x" }, { kevMinutes: 99999 }, { initialDays: 0 }])
      assert.equal((await admin.req("PUT", "/api/integrations/feeds", bad)).status, 400, JSON.stringify(bad));
    const ok = await admin.req("PUT", "/api/integrations/feeds", { cveMinutes: 15, kevMinutes: 120, enabled: true });
    assert.deepEqual([ok.status, ok.body.config.cveMinutes, ok.body.config.kevMinutes], [200, 15, 120]);
    assert.equal((await admin.req("PUT", "/api/integrations/feeds", { enabled: true })).body.config.cveMinutes, 10, "left out: back to the default");
  });

  test("a CVE that was just announced can be found and read by anyone, and adds nothing to anyone's numbers", async () => {
    const before = (await a1.get("/api/exposure/summary")).body;
    PUBLISHED.set("CVE-2026-7001", cveRecord("CVE-2026-7001", { score: 7.5, description: "A brand new flaw" }));
    await feeds.ensurePublic(["CVE-2026-7001"]);
    const found = (await a1.get("/api/public/cves?q=7001")).body.items;
    assert.deepEqual([found.length, found[0].id, found[0].cvssScore, found[0].kev], [1, "CVE-2026-7001", 7.5, false]);
    assert.ok(!JSON.stringify(found).match(/device|host|devices|tenant/i), "no organization data in the public search");
    const after = (await a1.get("/api/exposure/summary")).body;
    assert.deepEqual(after.totals, before.totals);
    const d = (await a1.get("/api/exposure/vulnerabilities/CVE-2026-7001")).body;
    assert.equal(d.found, false);
    assert.deepEqual([d.public.announced, d.public.description, d.public.cvss.score], [true, "A brand new flaw", 7.5]);
    assert.equal(d.impact.state, "not_found", "Alpha's latest read is complete and newer than the announcement");
    assert.ok(d.impact.asOf > 0);
  });

  test("the detail of an affected CVE says so, with the three things kept apart: announced, in KEV, found by Falcon", async () => {
    const cve = (await dbm.get<{ c: string }>("SELECT cve_id c FROM findings WHERE cid = ? AND cve_id LIKE 'CVE-%' LIMIT 1", CID_ONE))!.c;
    PUBLISHED.set(cve, cveRecord(cve, { score: 9.1 }));
    await feeds.ensurePublic([cve]);
    await dbm.run("INSERT INTO kev (cve_id, name, date_added, due_date, first_seen_at) VALUES (?,?,?,?,?) ON CONFLICT DO NOTHING", cve, "N", "2026-11-18", "2026-12-09", Date.now());
    const d = (await a1.get(`/api/exposure/vulnerabilities/${cve}`)).body;
    assert.deepEqual([d.found, d.impact.state, d.public.announced, d.public.kev.dueDate], [true, "affected", true, "2026-12-09"]);
    assert.ok(d.public.publishedAt && d.public.ingestedAt, "when the CVE Program published it, and when we received it");
  });

  test("the affected-devices list of a CVE has one row per device and counts its findings", async () => {
    const cve = "CVE-2099-5151";
    for (const [fid, prod] of [["dup1", "Prod A"], ["dup2", "Prod B"], ["dup3", "Prod B"]]) {
      await dbm.run("INSERT INTO findings (cid, finding_id, aid, cve_id, severity, hostname, product, synced_at) VALUES (?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING", CID_ONE, `${fid}-5151`, "dup-aid-5151", cve, "HIGH", "DUP-HOST", prod, Date.now());
    }
    const d = (await a1.get(`/api/exposure/vulnerabilities/${cve}`)).body;
    assert.equal(d.devicesTotal, 1);
    assert.deepEqual(d.hosts.map((h: any) => [h.aid, h.findings, h.products, h.severity]), [["dup-aid-5151", 3, 2, "HIGH"]]);
    assert.ok(!JSON.stringify(d.hosts).includes(CID_ONE), "an operator never sees the CID");
    await dbm.run("DELETE FROM findings WHERE cve_id = ?", cve);
  });

  test("urgent items: an organization sees only its own, another organization's id is a 404, a super admin must name one", async () => {
    const mine = (await dbm.get<{ c: string }>("SELECT cve_id c FROM findings WHERE cid = ? AND cve_id LIKE 'CVE-%' LIMIT 1", CID_ONE))!.c;
    await dbm.run("DELETE FROM alerts WHERE tenant_id = ?", ids.ta);
    await dbm.run("INSERT INTO alerts (tenant_id, cve_id, reason, created_at) VALUES (?,?,?,?)", ids.ta, mine, "first_impact", Date.now());
    await dbm.run("INSERT INTO alerts (tenant_id, cve_id, reason, created_at) VALUES (?,?,?,?)", ids.ta, mine, "kev_added", Date.now());
    const a = (await a1.get("/api/exposure/urgent")).body.items;
    assert.deepEqual([a.length, a[0].cve, a[0].reasons.sort()], [1, mine, ["first_impact", "kev_added"]], "one item per CVE, with both reasons");
    assert.ok(a[0].devices > 0);
    assert.ok((await dbm.get<{ n: number }>("SELECT COUNT(*) n FROM alerts WHERE tenant_id = ? AND reason = 'baseline'", ids.tb))!.n > 0, "the first Falcon read only recorded a baseline");
    assert.deepEqual((await b1.get("/api/exposure/urgent")).body.items, [], "Beta sees nothing of Alpha's items");
    assert.equal((await b1.get(`/api/exposure/urgent?tenantId=${ids.ta}`)).status, 404);
    assert.equal((await admin.get("/api/exposure/urgent")).status, 400);
    assert.equal((await admin.get(`/api/exposure/urgent?tenantId=${ids.ta}`)).body.items.length, 1);
    assert.equal((await cl().get("/api/exposure/urgent")).status, 401);
  });

  test("one case from end to end: LINE news first, then the official record, then Falcon's devices, then KEV: A gets one urgent item, B only what it may see", async () => {
    const x = "CVE-2026-7777"; // only Alpha has it
    await dbm.run("INSERT INTO findings (cid, finding_id, aid, cve_id, severity, hostname, local_ip, status, synced_at) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING", CID_ONE, "e2e-f1", "e2e-aid-1", x, "CRITICAL", "ALPHA-HOST-1", "10.1.2.3", "open", Date.now());
    await (await import("../src/rollup.ts")).refreshRollups(CID_ONE); // what a sync does after it stored rows
    // 1. the news names it before the CVE Program has published anything
    PUBLISHED.delete(x);
    const lineCfg = await admin.req("PUT", "/api/integrations/line", { channelSecret: "s".repeat(20), channelAccessToken: "t".repeat(20), allowedChats: ["Cend2end000000000000000000000000001"], answerChat: "" });
    assert.equal(lineCfg.status, 200);
    const sent: any[] = [];
    line.hooks.line = async (_t, method, url, body) => { sent.push({ method, url, body }); return { ok: true, status: 200, data: Buffer.from("") }; };
    const raw = JSON.stringify({ events: [{ type: "message", webhookEventId: "e2e-1", source: { type: "group", groupId: "Cend2end000000000000000000000000001" }, message: { id: "m-e2e-1", type: "text", text: `ข่าว ${x}` } }] });
    assert.equal((await cl().req("POST", "/api/line/webhook", raw, { "X-Line-Signature": createHmac("sha256", "s".repeat(20)).update(raw).digest("base64") })).status, 200);
    for (let i = 0; i < 100 && !sent.length; i++) await new Promise((ok) => setTimeout(ok, 50));
    await Promise.all([...line.pending]);
    const said = JSON.stringify(sent);
    assert.ok(said.includes("รอข้อมูลจาก CVE Program") && said.includes("Alpha Corp") && !said.includes("Beta Ltd"), "waiting for the CVE Program; the devices are Alpha's");
    // 2. the CVE Program publishes it: the next feed run fills the registry
    PUBLISHED.set(x, cveRecord(x, { score: 9.8, published: new Date().toISOString(), updated: new Date().toISOString(), description: "official text" }));
    DELTA.unshift({ fetchTime: new Date(Date.now() + 1000).toISOString(), new: [{ cveId: x }], updated: [] });
    assert.equal((await admin.post("/api/integrations/feeds/run", {})).body.cve.ingested, 1);
    assert.equal((await a1.get(`/api/exposure/vulnerabilities/${x}`)).body.public.description, "official text");
    // 3. Falcon has Alpha's devices; Beta has none and sees the public facts without Alpha's data
    const aD = (await a1.get(`/api/exposure/vulnerabilities/${x}`)).body, bD = (await b1.get(`/api/exposure/vulnerabilities/${x}`)).body;
    assert.deepEqual([aD.found, aD.impact.state], [true, "affected"]);
    assert.equal(bD.found, false);
    assert.equal(bD.public.announced, true);
    assert.ok(!JSON.stringify(bD).includes("hostname") && bD.hosts === undefined);
    // 4. it enters KEV afterwards
    KEV.etag = "k1"; KEV.list = ["CVE-2020-0001"];
    await dbm.run("DELETE FROM kev"); // so this import is the baseline
    await admin.post("/api/integrations/feeds/run", {});
    KEV.etag = "k2"; KEV.list = ["CVE-2020-0001", x];
    const run = (await admin.post("/api/integrations/feeds/run", {})).body;
    assert.deepEqual(run.kev.added, [x]);
    await admin.post("/api/integrations/feeds/run", {}); // and a repeat adds nothing
    const aU = (await a1.get("/api/exposure/urgent")).body.items.filter((i: any) => i.cve === x), bU = (await b1.get("/api/exposure/urgent")).body.items;
    assert.deepEqual([aU.length, aU[0].reasons, aU[0].kev], [1, ["kev_added"], true], "one urgent item for Alpha");
    assert.deepEqual(bU, [], "nothing for Beta");
    assert.equal(((await a1.get(`/api/exposure/vulnerabilities/${x}`)).body).public.kev.dueDate, "2026-12-09");
  });

  test("what to look at first is ordered by facts we hold (KEV, Falcon exploit status, internet exposure, severity), and says why", async () => {
    const lowCve = (await dbm.get<{ c: string }>("SELECT cve_id c FROM findings WHERE cid = ? AND severity IN ('LOW','MEDIUM') AND cve_id LIKE 'CVE-%' AND cve_id NOT IN (SELECT cve_id FROM kev) LIMIT 1", CID_ONE))!.c;
    const before = (await a1.get("/api/exposure/graph?cves=5")).body;
    assert.ok(before.cves.every((x: any) => typeof x.priority === "number" && Array.isArray(x.reasons)));
    assert.ok(before.cves.every((x: any, i: number, a: any[]) => i === 0 || a[i - 1].priority >= x.priority), "highest priority first");
        await dbm.run("INSERT INTO kev (cve_id, name, date_added, due_date, first_seen_at) VALUES (?,?,?,?,?) ON CONFLICT DO NOTHING", lowCve, "N", "2026-11-18", "2026-12-09", Date.now());
    const after = (await a1.get("/api/exposure/graph?cves=40")).body;
    const at = after.cves.findIndex((x: any) => x.id === lowCve);
    assert.ok(at >= 0 && after.cves[at].kev && after.cves[at].reasons.includes("kev"), "a Low/Medium CVE that is in CISA KEV now makes the list");
    const noKev = (await a1.get("/api/exposure/graph?cves=40")).body.cves.filter((x: any) => !x.kev && x.severity === after.cves[at].severity);
    assert.ok(noKev.every((x: any) => after.cves.findIndex((y: any) => y.id === x.id) > at || x.priority >= after.cves[at].priority), "ahead of non-KEV CVEs of the same severity");
  });

  test("system status: super admins only; shows what was read from Falcon, what the database holds and how the cache is doing; no CIDs", async () => {
    assert.equal((await a1.get("/api/system/status")).status, 403);
    await a1.get("/api/exposure/summary"); await a1.get("/api/exposure/summary");
    const v = (await admin.get("/api/system/status")).body;
    assert.ok(v.database.findings > 0 && v.falcon.organizations.length >= 2 && v.falcon.lastRunAt > 0 && v.falcon.organizations.every((o: any) => o.findings >= 0 && o.state));
    assert.ok(v.cache.entries >= 1 && v.cache.memoryHits >= 1 && v.cache.builds >= 1 && v.cache.hitRate >= 0);
    assert.ok(!JSON.stringify(v).includes(CID_ONE) && !JSON.stringify(v).includes(CID_TWO));
    assert.equal((await dbm.get<{ n: number }>("SELECT COUNT(*) n FROM result_cache"))!.n, v.cache.entries);
  });

  test("CrowdStrike connections per organization: add with cloud, client id, secret and CID; test before saving; each CID is read with its own login", async () => {
    const tenants = (await admin.get("/api/tenants")).body.tenants as { id: string; name: string }[];
    const alpha = tenants.find((t) => t.name === "Alpha Corp")!;
    const g = (await admin.post("/api/tenants", { name: "Gamma Co" })).body.tenant;
    const GCID = "9".repeat(32);
    assert.equal((await a1.post(`/api/tenants/${g.id}/falcon`, {})).status, 403, "super admins only");
    const base = { baseUrl: mockUrl, clientId: MOCK_CLIENT, clientSecret: MOCK_SECRET, cid: GCID, name: "Gamma main" };
    for (const bad of [{ cid: "xyz" }, { baseUrl: "https://evil.example.com" }, { clientId: "" }, { clientSecret: "" }]) assert.equal((await admin.post(`/api/tenants/${g.id}/falcon`, { ...base, ...bad })).status, 400, JSON.stringify(bad));
    const taken = await admin.post(`/api/tenants/${g.id}/falcon`, { ...base, cid: CID_ONE });
    assert.deepEqual([taken.status, taken.body.code], [409, "cid_taken"], "a CID of another organization is refused");
    // test before saving: wrong secret, then the right one, then a CID the client can read
    assert.deepEqual((await admin.post(`/api/tenants/${g.id}/falcon/test`, { ...base, clientSecret: "wrong-secret" })).body.reason, "invalid_credentials");
    assert.deepEqual((await admin.post(`/api/tenants/${g.id}/falcon/test`, base)).body.ok, true);
    const ok = await admin.post(`/api/tenants/${alpha.id}/falcon/test`, { ...base, cid: CID_ONE });
    assert.deepEqual([ok.body.ok, ok.body.step, ok.body.findings > 0], [true, "read", true]);
    const added = await admin.post(`/api/tenants/${g.id}/falcon`, base);
    assert.equal(added.status, 200, JSON.stringify(added.body));
    assert.deepEqual([added.body.connections.length, added.body.connections[0].cid, added.body.connections[0].hasSecret, added.body.connections[0].name], [1, GCID, true, "Gamma main"]);
    assert.ok(!JSON.stringify(added.body).includes(MOCK_SECRET), "the secret never comes back");
    assert.ok(!JSON.stringify((await dbm.get<any>("SELECT secret_sealed FROM falcon_connections WHERE cid = ?", GCID))).includes(MOCK_SECRET), "and is stored sealed");
    assert.equal((await admin.post(`/api/tenants/${g.id}/falcon`, base)).status, 409, "one connection per CID");
    // an organization's CID is read with ITS OWN login: change that secret to a wrong one and only that CID fails
    const conn = (await admin.get(`/api/tenants/${alpha.id}/falcon`)).body.connections[0];
    assert.equal((await admin.req("PUT", `/api/tenants/${alpha.id}/falcon/${conn.id}`, { clientSecret: "wrong-secret" })).status, 200);
    assert.equal((await admin.post("/api/integrations/falcon/sync", { tenantId: alpha.id })).status, 200);
    assert.equal((await waitSync(admin)).cids.find((x: any) => x.cid === CID_ONE).state, "failed", "its own login is wrong, so it fails");
    assert.equal((await admin.req("PUT", `/api/tenants/${alpha.id}/falcon/${conn.id}`, { clientId: "other-client" })).status, 400, "a new client id needs its secret");
    assert.equal((await admin.req("PUT", `/api/tenants/${alpha.id}/falcon/${conn.id}`, { clientSecret: MOCK_SECRET })).status, 200);
    assert.equal((await admin.post("/api/integrations/falcon/sync", { tenantId: alpha.id })).status, 200);
    assert.equal((await waitSync(admin)).cids.find((x: any) => x.cid === CID_ONE).state, "complete");
    // removing needs the CID typed, and removes what was read for it; the CID list of the organization keeps a connection's CID
    assert.equal((await admin.req("DELETE", `/api/tenants/${g.id}/falcon/${added.body.connections[0].id}`, {})).status, 400);
    assert.equal((await admin.req("DELETE", `/api/tenants/${g.id}/falcon/${added.body.connections[0].id}`, { confirmCid: GCID })).status, 200);
    assert.equal((await dbm.get<{ n: number }>("SELECT COUNT(*) n FROM tenant_cids WHERE cid = ?", GCID))!.n, 0);
    assert.ok((await admin.req("PUT", `/api/tenants/${alpha.id}/cids`, { cids: [] })).body.cids.includes(CID_ONE), "a connection's CID cannot be dropped through the plain CID list");
    // a CID with no connection is not read at all, and says so
    const lone = (await admin.post("/api/tenants", { name: "Lone Co" })).body.tenant, LCID = "8".repeat(32);
    await admin.req("PUT", `/api/tenants/${lone.id}/cids`, { cids: [LCID] });
    assert.equal((await admin.post("/api/integrations/falcon/sync", { tenantId: lone.id })).status, 400, "nothing to read with");
    const v = (await admin.get(`/api/tenants/${lone.id}/falcon`)).body;
    assert.deepEqual([v.connections.length, v.unconnectedCids.map((x: any) => x.cid)], [0, [LCID]]);
    assert.equal((await admin.get("/api/tenants")).body.tenants.find((t: any) => t.id === lone.id).state, "no_connection");
    // the old shared login (kept in the database) is only ever tried per CID, and only a CID it can read gets a connection
    assert.equal((await admin.post(`/api/tenants/${lone.id}/falcon/convert-shared`, {})).body.error, "There is no old shared login to try");
    await dbm.run("INSERT INTO integrations (key, config_json, secret_sealed, updated_at, updated_by) VALUES ('falcon', ?, ?, ?, NULL)", JSON.stringify({ baseUrl: mockUrl, clientId: MOCK_CLIENT }), crypto.seal(MOCK_SECRET), Date.now());
    try {
      mock.deniedCids.add(LCID);
      const no = await admin.post(`/api/tenants/${lone.id}/falcon/convert-shared`, {});
      assert.deepEqual([no.body.results[0].ok, no.body.results[0].reason, no.body.connections.length], [false, "cid_not_authorized", 0], "a login Falcon refuses for that CID is not copied");
      mock.deniedCids.clear();
      const yes = await admin.post(`/api/tenants/${lone.id}/falcon/convert-shared`, {});
      assert.deepEqual([yes.body.results[0].ok, yes.body.connections.length, yes.body.unconnectedCids.length], [true, 1, 0]);
    } finally { mock.deniedCids.clear(); await dbm.run("DELETE FROM integrations WHERE key = 'falcon'"); }
  });

  test("external attack surface: IP addresses and domains read from Falcon EASM, counted like Falcon's dashboard, per organization only", async () => {
    // the Falcon syncs of this run read the external assets with each CID's login and stored them
    assert.ok((await dbm.get<{ n: number }>("SELECT COUNT(*) n FROM external_assets WHERE cid = ?", CID_ONE))!.n > 0);
    const a = (await a1.get("/api/exposure/easm")).body, b = (await b1.get("/api/exposure/easm")).body;
    assert.deepEqual([a.assets.ips, a.assets.rootDomains, a.assets.subdomains], [40, 3, 9], "Alpha: 40 IPs, 12 domains of which every 4th is a root");
    assert.deepEqual([b.assets.ips, b.assets.rootDomains, b.assets.subdomains], [80, 6, 18], "Beta has its own, double");
    assert.equal(a.perimeter.official + a.perimeter.unofficial, 40);
    assert.deepEqual(a.reviewIps, { reviewed: 4, notReviewed: 36 }, "an empty triage status is 'not reviewed'");
    assert.deepEqual(a.reviewRootDomains, { reviewed: 0, notReviewed: 3 });
    assert.equal(a.online.online + a.online.offline, 40);
    assert.ok(a.findings.byExprt && a.findings.byType && a.findings.total >= 0 && a.state === "complete" && a.asOf > 0);
    assert.ok(!JSON.stringify(a).includes(CID_ONE) && !JSON.stringify(a).includes("203.0.113"), "no CIDs, and no individual addresses in the summary");
    assert.equal((await b1.get(`/api/exposure/easm?tenantId=${ids.ta}`)).status, 404, "another organization's id is a 404");
    assert.equal((await cl().get("/api/exposure/easm")).status, 401);
  });
});
