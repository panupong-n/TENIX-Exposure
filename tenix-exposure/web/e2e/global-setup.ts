/* eslint-disable @typescript-eslint/no-explicit-any -- test plumbing over untyped API JSON */
import { spawn, type ChildProcess } from "node:child_process";
import net from "node:net";
import { randomBytes } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { testDatabaseUrl } from "./test-db";

const here = dirname(fileURLToPath(import.meta.url));
const SERVER = join(here, "../../server");
export const AUTH_DIR = join(here, ".auth");
export const PORTS = { app: 8790, mock: 8791, smtp: 8792 };
const BASE = `http://127.0.0.1:${PORTS.app}`;
export const PASSWORD = "E2e-Password-12345";
const CID_A = "1".repeat(31) + "a", CID_B = "2".repeat(31) + "b";

// Only PIDs we start ourselves are ever signalled (see global-teardown).
const children: ChildProcess[] = [];
let smtpServer: net.Server | undefined;

function start(args: string[], env: Record<string, string>, onOut?: (s: string) => void) {
  const p = spawn(process.execPath, args, { cwd: SERVER, env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
  p.stdout!.on("data", (d) => onOut?.(String(d)));
  p.stderr!.on("data", (d) => process.stderr.write(`[e2e child ${p.pid}] ${d}`));
  children.push(p);
  return p;
}

async function waitFor(url: string, ms = 30000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    try { await fetch(url); return; } catch { await new Promise((r) => setTimeout(r, 200)); }
  }
  throw new Error(`timed out waiting for ${url}`);
}

class Api {
  jar = new Map<string, string>();
  async req(method: string, path: string, body?: unknown) {
    const headers: Record<string, string> = {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (this.jar.size) headers.Cookie = [...this.jar].map(([k, v]) => `${k}=${v}`).join("; ");
    const r = await fetch(BASE + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    for (const sc of r.headers.getSetCookie()) {
      const [kv] = sc.split(";"), i = kv.indexOf("=");
      if (/Max-Age=0/.test(sc)) this.jar.delete(kv.slice(0, i)); else this.jar.set(kv.slice(0, i), kv.slice(i + 1));
    }
    const json = await r.json().catch(() => null);
    if (!r.ok) throw new Error(`${method} ${path} -> ${r.status} ${JSON.stringify(json)}`);
    return json as any;
  }
  get = (p: string) => this.req("GET", p);
  post = (p: string, b: unknown = {}) => this.req("POST", p, b);
  put = (p: string, b: unknown = {}) => this.req("PUT", p, b);
}

function startSmtpSink() {
  smtpServer = net.createServer((sock) => {
    let inData = false, buf = "";
    sock.write("220 e2e ESMTP\r\n");
    sock.on("error", () => {});
    sock.on("data", (d) => {
      buf += d.toString();
      for (let i; (i = buf.indexOf("\r\n")) >= 0;) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 2);
        if (inData) { if (line === ".") { inData = false; sock.write("250 queued\r\n"); } }
        else if (/^DATA/i.test(line)) { inData = true; sock.write("354 go\r\n"); }
        else if (/^QUIT/i.test(line)) sock.end("221 bye\r\n");
        else sock.write("250 ok\r\n");
      }
    });
  });
  return new Promise<void>((ok) => smtpServer!.listen(PORTS.smtp, "127.0.0.1", ok));
}

export default async function globalSetup() {
  const databaseUrl = testDatabaseUrl(); // first: refuse before any file, process or schema is created
  const schema = `e2e_${Array.from(randomBytes(8), (b) => "abcdefghijklmnopqrstuvwxyz"[b % 26]).join("")}`;
  mkdirSync(AUTH_DIR, { recursive: true });
  // written first so teardown can clean up even if setup fails half-way
  const state: Record<string, unknown> = { schema, pids: [], ports: PORTS, baseURL: BASE, password: PASSWORD };
  const save = () => writeFileSync(join(AUTH_DIR, "env.json"), JSON.stringify({ ...state, pids: children.map((c) => c.pid) }, null, 2));
  save();

  try {
    await startSmtpSink();
    start(["test/mock-falcon.ts"], { MOCK_PORT: String(PORTS.mock), MOCK_RICH: "1" });
    let link = "";
    start(["src/index.ts"], {
      TENIX_DATABASE_URL: databaseUrl, TENIX_DB_SCHEMA: schema, TENIX_DEV_FALCON_URL_OK: "1", TENIX_SYNC_MINUTES: "0", TENIX_WEB_DIST: process.env.E2E_DIST ? join(here, "..", process.env.E2E_DIST) : join(here, "../dist-e2e"), // the English build; web/dist (the real one, in Thai) is never touched
      
      PORT: String(PORTS.app), TENIX_APP_URL: BASE, TENIX_BOOTSTRAP_EMAIL: "super@e2e.test", TENIX_SECRET_KEY: randomBytes(32).toString("base64"),
    }, (s) => { const m = /(https?:\/\/\S+\/accept-invite\/\S+)/.exec(s); if (m) link = m[1]; });
    save();
    await waitFor(`${BASE}/api/auth/me`);
    await waitFor(`http://127.0.0.1:${PORTS.mock}/`);
    for (let i = 0; i < 50 && !link; i++) await new Promise((r) => setTimeout(r, 100));
    if (!link) throw new Error("no bootstrap link on the server's stdout");

    const token = link.split("/accept-invite/")[1];
    const accept = (t: string, name: string) => new Api().post(`/api/invites/${t}/accept`, { name, password: PASSWORD });
    await accept(token, "Super Admin");
    const sa = new Api();
    await sa.post("/api/auth/login", { email: "super@e2e.test", password: PASSWORD });

    // each organization has its OWN Falcon login (the mock accepts one client for every CID); there is no shared login any more
    const tenant = async (name: string, cid: string | null) => {
      const t = (await sa.post("/api/tenants", { name })).tenant;
      if (cid) await sa.post(`/api/tenants/${t.id}/falcon`, { name: `${name} Falcon`, baseUrl: `http://127.0.0.1:${PORTS.mock}`, clientId: "mock-client", clientSecret: "mock-secret", cid });
      return t.id as string;
    };
    const alpha = await tenant("Alpha Corp", CID_A), beta = await tenant("Beta Ltd", CID_B), empty = await tenant("Empty Inc", null);

    await sa.post("/api/integrations/falcon/sync", {});
    for (let i = 0; ; i++) {
      const f = await sa.get("/api/integrations/falcon");
      if (!f.sync.running) { if (f.cids.some((c: any) => c.state !== "complete")) throw new Error(`sync not complete: ${JSON.stringify(f.cids)}`); break; }
      if (i > 600) throw new Error("sync did not finish");
      await new Promise((r) => setTimeout(r, 200));
    }

    const users: Record<string, { email: string; memberships: { tenantId: string; role: "admin" | "operator" }[] }> = {
      alphaAdmin: { email: "alpha-admin@e2e.test", memberships: [{ tenantId: alpha, role: "admin" }] },
      alphaOp: { email: "alpha-op@e2e.test", memberships: [{ tenantId: alpha, role: "operator" }] },
      betaOp: { email: "beta-op@e2e.test", memberships: [{ tenantId: beta, role: "operator" }] },
      multi: { email: "multi@e2e.test", memberships: [{ tenantId: alpha, role: "admin" }, { tenantId: beta, role: "operator" }] },
      emptyOp: { email: "empty-op@e2e.test", memberships: [{ tenantId: empty, role: "operator" }] },
    };
    for (const [key, u] of Object.entries(users)) {
      const { link: l } = await sa.post("/api/team/invites", { email: u.email, role: "member", memberships: u.memberships });
      await accept(l.split("/accept-invite/")[1], key);
    }

    await sa.post("/api/mail/senders", { name: "E2E sink", host: "127.0.0.1", port: PORTS.smtp, security: "none", fromEmail: "alerts@e2e.test", fromName: "TENIX E2E" });
    await sa.post("/api/mail/recipients", { email: "soc@e2e.test", tenantId: null, events: ["critical_new", "sync_failed"] });

    // storageState per user: log in once through the API and keep its cookies
    const all: Record<string, string> = { super: "super@e2e.test", ...Object.fromEntries(Object.entries(users).map(([k, u]) => [k, u.email])) };
    for (const [name, email] of Object.entries(all)) {
      const a = new Api();
      await a.post("/api/auth/login", { email, password: PASSWORD });
      const cookies = [...a.jar].map(([n, v]) => ({ name: n, value: v, domain: "127.0.0.1", path: "/", httpOnly: true, secure: false, sameSite: "Lax" as const, expires: -1 }));
      writeFileSync(join(AUTH_DIR, `${name}.json`), JSON.stringify({ cookies, origins: [] }));
    }
    Object.assign(state, {
      tenants: { alpha, beta, empty }, cids: { alpha: CID_A, beta: CID_B },
      users: { super: "super@e2e.test", ...Object.fromEntries(Object.entries(users).map(([k, u]) => [k, u.email])) },
    });
    save();
  } catch (e) {
    for (const c of children) c.kill();
    smtpServer?.close();
    throw e;
  }
  // the SMTP sink lives in this process; Playwright keeps it alive until teardown runs in the same process
  (globalThis as any).__e2eSmtp = smtpServer;
}
