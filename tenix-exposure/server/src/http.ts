import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize, resolve } from "node:path";
import { cookieSecure, webDist } from "./config.ts";
import { all, get, isManager, now, audit, type Membership, type Role, type SessionUser, type User } from "./db.ts";
import { sha256 } from "./crypto.ts";

export class HttpError extends Error {
  status: number;
  code?: string;
  extra?: Record<string, unknown>; // more for the client to show, e.g. Falcon's own reason
  constructor(status: number, message: string, code?: string, extra?: Record<string, unknown>) {
    super(message);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

export interface Ctx {
  req: IncomingMessage; res: ServerResponse; query: URLSearchParams; params: Record<string, string>;
  body: Record<string, unknown>; rawBody: Buffer; ip: string; user: SessionUser | null; sessionHash: string | null;
  setCookie: (name: string, value: string, maxAgeSec: number) => void;
  clearCookie: (name: string) => void;
}
type Auth = "none" | "mfa" | "user";
/** roles: only these user types. manager: a super admin, or a member who is admin of at least one tenant. */
interface Opts { auth?: Auth; roles?: Role[]; manager?: boolean }
type Handler = (c: Ctx) => unknown | Promise<unknown>;
const routes: { method: string; re: RegExp; keys: string[]; opts: Opts; handler: Handler }[] = [];

export function route(method: string, path: string, opts: Opts | Handler, handler?: Handler) {
  const h = typeof opts === "function" ? opts : handler!;
  const o: Opts = typeof opts === "function" ? { auth: "user" } : { auth: "user", ...opts };
  const keys: string[] = [];
  const re = new RegExp("^" + path.replace(/:(\w+)/g, (_m, k) => (keys.push(k), "([^/]+)")) + "$");
  routes.push({ method, re, keys, opts: o, handler: h });
}

export const SESSION_COOKIE = "tx_session";
export const MFA_COOKIE = "tx_mfa";

function cookies(req: IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

const MAX_BODY = 64 * 1024;
async function readBody(req: IncomingMessage): Promise<{ body: Record<string, unknown>; raw: Buffer }> {
  const none = { body: {}, raw: Buffer.alloc(0) };
  if (req.method === "GET" || req.method === "HEAD") return none;
  // A cross-site HTML form cannot send application/json, so this doubles as CSRF protection with SameSite=Lax.
  if (!/^application\/json\b/i.test(req.headers["content-type"] ?? "")) throw new HttpError(415, "Content-Type must be application/json");
  const host = req.headers.host;
  const origin = req.headers.origin;
  if (origin && new URL(origin).host !== host) throw new HttpError(403, "Cross-origin request refused");
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > MAX_BODY) throw new HttpError(413, "Body too large");
    chunks.push(c as Buffer);
  }
  if (!size) return none;
  const raw = Buffer.concat(chunks); // kept as received: a webhook signature is computed over these exact bytes
  try {
    const v = JSON.parse(raw.toString("utf8"));
    if (v === null || typeof v !== "object" || Array.isArray(v)) throw new Error();
    return { body: v as Record<string, unknown>, raw };
  } catch { throw new HttpError(400, "Invalid JSON body"); }
}

const trustProxy = process.env.TENIX_TRUST_PROXY === "1";
const clientIp = (req: IncomingMessage) =>
  (trustProxy ? String(req.headers["x-forwarded-for"] ?? "").split(",")[0].trim() : "") || req.socket.remoteAddress || "";

function sendJson(res: ServerResponse, status: number, data: unknown) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(JSON.stringify(data));
}

export async function sessionUser(hash: string, stage: "mfa" | "full"): Promise<SessionUser | null> {
  const row = await get<User & { exp: number }>(
    "SELECT u.*, s.expires_at AS exp FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = ? AND s.stage = ?", hash, stage);
  if (!row || row.exp < now() || row.disabled) return null;
  const memberships = await all<Membership>("SELECT tenant_id, role FROM user_tenants WHERE user_id = ?", row.id);
  return { ...row, memberships };
}

const CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";
const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
  ".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg", ".webp": "image/webp",
  ".woff2": "font/woff2", ".ico": "image/x-icon", ".mjs": "text/javascript; charset=utf-8",
};

async function serveStatic(url: URL, res: ServerResponse) {
  const root = resolve(webDist);
  let file = resolve(join(root, normalize(decodeURIComponent(url.pathname))));
  if (!file.startsWith(root)) { res.writeHead(403).end(); return; }
  let st = await stat(file).catch(() => null);
  if (!st?.isFile()) { file = join(root, "index.html"); st = await stat(file).catch(() => null); }
  if (!st) { res.writeHead(404).end("web build not found: run `npm run build` in web/"); return; }
  const ext = extname(file);
  const immutable = file.includes(`${root}/assets/`);
  res.writeHead(200, { "Content-Type": MIME[ext] ?? "application/octet-stream", "Cache-Control": immutable ? "public, max-age=31536000, immutable" : "no-cache" });
  res.end(await readFile(file));
}

async function handle(req: IncomingMessage, res: ServerResponse) {
  const url = new URL(req.url ?? "/", "http://x");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader("Content-Security-Policy", CSP);
  if (!url.pathname.startsWith("/api/")) {
    if (req.method !== "GET" && req.method !== "HEAD") { res.writeHead(405).end(); return; }
    return serveStatic(url, res);
  }
  const ip = clientIp(req);
  try {
    const hit = routes.find((r) => r.method === req.method && r.re.test(url.pathname));
    if (!hit) {
      if (routes.some((r) => r.re.test(url.pathname))) throw new HttpError(405, "Method not allowed");
      throw new HttpError(404, "Not found");
    }
    const m = hit.re.exec(url.pathname)!;
    const params: Record<string, string> = {};
    hit.keys.forEach((k, i) => (params[k] = decodeURIComponent(m[i + 1])));
    const jar = cookies(req);
    const out: string[] = [];
    const ctx: Ctx = {
      req, res, query: url.searchParams, params, body: {}, rawBody: Buffer.alloc(0), ip, user: null, sessionHash: null,
      setCookie: (n, v, age) => out.push(`${n}=${encodeURIComponent(v)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${age}${cookieSecure ? "; Secure" : ""}`),
      clearCookie: (n) => out.push(`${n}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${cookieSecure ? "; Secure" : ""}`),
    };
    ({ body: ctx.body, raw: ctx.rawBody } = await readBody(req));
    if (hit.opts.auth !== "none") {
      const stage = hit.opts.auth === "mfa" ? "mfa" : "full";
      const raw = jar[stage === "mfa" ? MFA_COOKIE : SESSION_COOKIE];
      const hash = raw ? sha256(raw) : null;
      const user = hash ? await sessionUser(hash, stage) : null;
      if (!user || !hash) throw new HttpError(401, "Authentication required", "unauthenticated");
      ctx.user = user;
      ctx.sessionHash = hash;
      if ((hit.opts.roles && !hit.opts.roles.includes(user.role)) || (hit.opts.manager && !isManager(user))) {
        await audit({ actor: user, action: "route", resource: `${req.method} ${url.pathname}`, result: "denied", ip });
        throw new HttpError(403, "Forbidden", "forbidden");
      }
    }
    const result = await hit.handler(ctx);
    if (res.headersSent) return; // a handler that streamed its own answer (the CSV exports) has finished it
    if (out.length) res.setHeader("Set-Cookie", out);
    sendJson(res, 200, result ?? { ok: true });
  } catch (e) {
    if (res.headersSent) { console.error("[500 while streaming]", req.method, url.pathname, e); res.destroy(); return; }
    if (e instanceof HttpError) return sendJson(res, e.status, { error: e.message, code: e.code ?? null, ...(e.extra ? { detail: e.extra } : {}) });
    // unique-constraint race (two requests creating the same thing at once)
    if ((e as { code?: string }).code === "23505") return sendJson(res, 409, { error: "Already exists", code: "exists" });
    console.error("[500]", req.method, url.pathname, e);
    sendJson(res, 500, { error: "Internal server error" });
  }
}

export function createApp(): Server {
  return createServer((req, res) => { void handle(req, res); });
}
