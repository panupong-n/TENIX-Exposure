// Starts a PREVIEW copy of the app for looking at UI changes: its own port, its own schema in the TEST database, the mock Falcon. Never the real database.
//   TENIX_TEST_DATABASE_URL=... node scripts/preview-stack.ts          (start or restart)
//   node scripts/preview-stack.ts stop                                   (stops only the PIDs this script recorded)
// The history, ages and the CISA KEV flags in the preview are synthetic so that the charts have something to show; the totals come from the mock Falcon sync.
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, openSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { join } from "node:path";
import { testDatabaseUrl } from "../test/test-db.ts";

const DIR = join(homedir(), "tenix-preview");
const PIDS = join(DIR, "pids.json");
const PORT = 8795, MOCK = 8796, SCHEMA = "preview_demo";
const PASSWORD = "Preview-Demo-12345";
const HOST = process.env.PREVIEW_HOST ?? "192.168.70.109";
mkdirSync(DIR, { recursive: true, mode: 0o700 });

if (process.argv[2] === "stop") {
  for (const pid of existsSync(PIDS) ? (JSON.parse(readFileSync(PIDS, "utf8")) as number[]) : []) { try { process.kill(pid, "SIGTERM"); } catch { /* already gone */ } }
  console.log("stopped the recorded preview processes");
  process.exit(0);
}

const dbUrl = testDatabaseUrl(); // throws unless 127.0.0.1:5433/tenix_test
const { Client } = createRequire(import.meta.url)("pg") as typeof import("pg");
const sql = async (text: string) => { const c = new Client({ connectionString: dbUrl }); await c.connect(); try { return await c.query(text); } finally { await c.end(); } };

// restart cleanly: stop what we started before, then start from an empty schema
for (const pid of existsSync(PIDS) ? (JSON.parse(readFileSync(PIDS, "utf8")) as number[]) : []) { try { process.kill(pid, "SIGTERM"); } catch { /* gone */ } }
await new Promise((r) => setTimeout(r, 800));
await sql(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);

const keyFile = join(DIR, "secret.key");
if (!existsSync(keyFile)) writeFileSync(keyFile, randomBytes(32).toString("base64"), { mode: 0o600 });
const key = readFileSync(keyFile, "utf8").trim();

const run = (args: string[], env: Record<string, string>, log: string) => {
  const fd = openSync(join(DIR, log), "w");
  const p = spawn(process.execPath, args, { cwd: join(import.meta.dirname, ".."), env: { ...process.env, ...env }, stdio: ["ignore", fd, fd], detached: true });
  p.unref();
  return p.pid!;
};
const mockPid = run(["test/mock-falcon.ts"], { MOCK_PORT: String(MOCK), MOCK_RICH: "1" }, "mock.log");
const appPid = run(["src/index.ts"], {
  TENIX_DATABASE_URL: dbUrl, TENIX_DB_SCHEMA: SCHEMA, TENIX_DEV_FALCON_URL_OK: "1", TENIX_SYNC_MINUTES: "0", PORT: String(PORT), TENIX_HOST: "0.0.0.0",
  TENIX_APP_URL: `http://${HOST}:${PORT}`, TENIX_BOOTSTRAP_EMAIL: "preview@demo.test", TENIX_SECRET_KEY: key,
  TENIX_WEB_DIST: join(DIR, "dist"), NODE_ENV: "development",
}, "app.log");
writeFileSync(PIDS, JSON.stringify([mockPid, appPid]));

const wait = async (url: string) => { for (let i = 0; i < 150; i++) { try { await fetch(url); return; } catch { await new Promise((r) => setTimeout(r, 200)); } } throw new Error(`timed out: ${url}`); };
await wait(`http://127.0.0.1:${PORT}/api/auth/me`); await wait(`http://127.0.0.1:${MOCK}/`);

class Api {
  jar = new Map<string, string>();
  async req(method: string, path: string, body?: unknown) {
    const headers: Record<string, string> = body === undefined ? {} : { "Content-Type": "application/json" };
    if (this.jar.size) headers.Cookie = [...this.jar].map(([k, v]) => `${k}=${v}`).join("; ");
    const r = await fetch(`http://127.0.0.1:${PORT}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    for (const sc of r.headers.getSetCookie()) { const [kv] = sc.split(";"), i = kv.indexOf("="); if (/Max-Age=0/.test(sc)) this.jar.delete(kv.slice(0, i)); else this.jar.set(kv.slice(0, i), kv.slice(i + 1)); }
    const json = await r.json().catch(() => null);
    if (!r.ok) throw new Error(`${method} ${path} -> ${r.status} ${JSON.stringify(json)}`);
    return json as any;
  }
}
let link = "";
for (let i = 0; i < 50 && !link; i++) { link = /accept-invite\/(\S+)/.exec(readFileSync(join(DIR, "app.log"), "utf8"))?.[1] ?? ""; if (!link) await new Promise((r) => setTimeout(r, 100)); }
if (!link) throw new Error("no bootstrap link in the app log");
await new Api().req("POST", `/api/invites/${link}/accept`, { name: "Preview Admin", password: PASSWORD });
const sa = new Api();
await sa.req("POST", "/api/auth/login", { email: "preview@demo.test", password: PASSWORD });
const CID_A = "1".repeat(31) + "a", CID_B = "2".repeat(31) + "b";
const alpha = (await sa.req("POST", "/api/tenants", { name: "Alpha Corp" })).tenant.id;
const beta = (await sa.req("POST", "/api/tenants", { name: "Beta Ltd" })).tenant.id;
await sa.req("PUT", `/api/tenants/${alpha}/cids`, { cids: [CID_A] });
await sa.req("PUT", `/api/tenants/${beta}/cids`, { cids: [CID_B] });
await sa.req("PUT", "/api/integrations/falcon", { baseUrl: `http://127.0.0.1:${MOCK}`, clientId: "mock-client", clientSecret: "mock-secret" });
await sa.req("POST", "/api/integrations/falcon/sync", {});
for (let i = 0; ; i++) {
  const f = await sa.req("GET", "/api/integrations/falcon");
  if (!f.sync.running) { if (f.cids.some((c: any) => c.state !== "complete")) throw new Error("sync not complete"); break; }
  if (i > 600) throw new Error("sync did not finish");
  await new Promise((r) => setTimeout(r, 200));
}
// a customer login, to show what a customer sees
const inv = await sa.req("POST", "/api/team/invites", { email: "exec@alpha.demo", role: "member", memberships: [{ tenantId: alpha, role: "admin" }] });
await new Api().req("POST", `/api/invites/${inv.link.split("/accept-invite/")[1]}/accept`, { name: "Alpha Executive", password: PASSWORD });

// synthetic history (60 days, improving) and ages, only so the charts have something to show
await sql(`
  INSERT INTO ${SCHEMA}.snapshots (cid, ts, critical, high, medium, low, "none", hosts, cves)
  SELECT s.cid, (extract(epoch FROM now()) * 1000)::bigint - d::bigint * 86400000,
         round(s.critical * (1 + 0.018 * d + 0.06 * sin(d))), round(s.high * (1 + 0.012 * d + 0.05 * sin(d * 1.3))),
         round(s.medium * (1 + 0.006 * d)), round(s.low * (1 + 0.004 * d)), s."none", s.hosts, s.cves
  FROM (SELECT DISTINCT ON (cid) * FROM ${SCHEMA}.snapshots ORDER BY cid, ts DESC) s, generate_series(1, 60) d
  ON CONFLICT DO NOTHING;
  UPDATE ${SCHEMA}.cves SET cisa_kev = 1 WHERE id IN (SELECT cve_id FROM ${SCHEMA}.findings WHERE cve_id LIKE 'CVE-%' GROUP BY cve_id ORDER BY COUNT(*) DESC LIMIT 7);
  UPDATE ${SCHEMA}.findings SET first_seen = (extract(epoch FROM now()) * 1000)::bigint - (abs(hashtext(finding_id)::bigint) % 260) * 86400000;
`);
console.log(JSON.stringify({ url: `http://${HOST}:${PORT}/executive`, admin: "preview@demo.test", customer: "exec@alpha.demo", password: PASSWORD, pids: [mockPid, appPid] }, null, 1));
process.exit(0);
