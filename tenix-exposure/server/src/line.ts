// LINE bot for news: someone sends a link, text or a picture; the bot finds the CVEs in it and says which devices of which organization have them.
// Flow: webhook -> signature -> dedupe -> store -> (fetch the link safely | read the picture) -> CVE ids -> match with the synced findings -> answer in LINE.
// The answer names organizations and device names, so the bot only answers in chats that a super admin has allowed.
import { createHmac, timingSafeEqual } from "node:crypto";
import { spawn } from "node:child_process";
import dns from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { str } from "./auth.ts";
import { appUrl } from "./config.ts";
import { seal, sha256, unseal, uuid } from "./crypto.ts";
import { all, audit, byName, get, nameOrder, now, run, tx } from "./db.ts";
import { HttpError, route } from "./http.ts";
import { falconLink } from "./falcon.ts";
import { ensurePublic, impactFrom, publicInfo, type ImpactState, type PublicView } from "./feeds.ts";
import type { AssetLevel, Esc, Level } from "./alertlevel.ts";
import { annotate, applyPrefs, DEFAULT_PREFS, loadPrefs, mergePrefs, notifyAccess, type Prefs } from "./notify.ts";
import { matchNews, newsHooks } from "./news.ts";

const ADMIN = { roles: ["super_admin" as const] };
const MAX_CVES = 20;       // per news item: the answer must stay readable
const MAX_URLS = 3;
const MAX_PAGE = 2 * 1024 * 1024;
const MAX_IMAGE = 8 * 1024 * 1024;

// ---------------------------------------------------------------- pure helpers (tested)
/** base64(HMAC-SHA256(channel secret, raw body)), compared in constant time. */
export function verifySignature(raw: Buffer, header: string | undefined, secret: string): boolean {
  if (!header || !secret) return false;
  const want = createHmac("sha256", secret).update(raw).digest();
  let got: Buffer;
  try { got = Buffer.from(header, "base64"); } catch { return false; }
  return got.length === want.length && timingSafeEqual(got, want);
}

const DASHES = /[‐-―−﹘﹣－]/g;
const SPACES = /[  -​ 　]/g;
const validYear = (y: number) => y >= 1999 && y <= new Date().getFullYear() + 1;

/** CVE ids in order of first appearance, upper case, no duplicates. Never guessed: only text that is a CVE id counts. */
export function extractCves(text: string): string[] {
  const t = text.replace(DASHES, "-").replace(SPACES, " ");
  const out: string[] = [];
  for (const m of t.matchAll(/\bCVE-(\d{4})-(\d{4,7})\b/gi)) {
    const id = `CVE-${m[1]}-${m[2]}`;
    if (validYear(Number(m[1])) && !out.includes(id)) out.push(id);
  }
  return out;
}

/** The same for text a picture was read into: OCR confuses O/0 and l/I/1 inside the digits, so those are repaired first. */
export function extractCvesFromOcr(text: string): string[] {
  const fix = (s: string) => s.replace(/[Oo]/g, "0").replace(/[Il|]/g, "1");
  const t = text.replace(DASHES, "-").replace(SPACES, " ");
  const out: string[] = [];
  for (const m of t.matchAll(/\bCVE\s*-\s*([12][0-9OoIl|]{3})\s*-\s*([0-9OoIl|]{4,7})\b/gi)) {
    const id = `CVE-${fix(m[1])}-${fix(m[2])}`;
    if (/^CVE-\d{4}-\d{4,7}$/.test(id) && validYear(Number(id.slice(4, 8))) && !out.includes(id)) out.push(id);
  }
  return out;
}

/** Links to this portal and to the system that shares the LINE channel are conversation, not news: they are taken out of the message before anything is read
 *  (a chat line like "the new login page is https://portal.example/signin" must not be answered with "no CVE found"). */
export function withoutOwnLinks(text: string, ownHosts: string[]): string {
  const own = new Set(ownHosts.filter(Boolean).map((h) => h.toLowerCase()));
  return text.replace(/https?:\/\/[^\s<>"'）)]+/gi, (u) => { try { return own.has(new URL(u).host.toLowerCase()) ? "" : u; } catch { return u; } });
}
export function urlsIn(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(/https?:\/\/[^\s<>"'　]+/gi)) {
    const u = m[0].replace(/[.,;:!?)\]}]+$/, "");
    if (!out.includes(u)) out.push(u);
  }
  return out.slice(0, MAX_URLS);
}

const blocked = new net.BlockList();
for (const [a, p] of [["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
  ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4]] as const) blocked.addSubnet(a, p, "ipv4");
for (const [a, p] of [["::", 128], ["::1", 128], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8], ["2001:db8::", 32], ["64:ff9b::", 96], ["2002::", 16]] as const) blocked.addSubnet(a, p, "ipv6");

/** Loopback, private, link-local, CGNAT, multicast, metadata and documentation ranges, in IPv4, IPv6 and IPv4-mapped form. */
export function isBlockedAddress(ip: string): boolean {
  const v = net.isIP(ip);
  if (!v) return true; // not an address at all: refuse
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (mapped) return blocked.check(mapped[1], "ipv4");
  return blocked.check(ip, v === 4 ? "ipv4" : "ipv6");
}

/** Scheme, port and credentials. The address is checked separately, after DNS. */
export function checkUrl(raw: string): URL {
  let u: URL;
  try { u = new URL(raw); } catch { throw new FetchError("blocked_by_policy"); }
  const port = u.port || (u.protocol === "https:" ? "443" : "80");
  if ((u.protocol !== "http:" && u.protocol !== "https:") || (port !== "80" && port !== "443") || u.username || u.password) throw new FetchError("blocked_by_policy");
  return u;
}

export class FetchError extends Error {
  status: string; http?: number;
  constructor(status: string, http?: number) { super(status); this.status = status; this.http = http; }
}
export interface Page { status: "ok"; finalUrl: string; http: number; contentType: string; hash: string; text: string }

function htmlToText(html: string): string {
  return html.replace(/<(script|style|noscript)[\s\S]*?<\/\1>/gi, " ").replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/\s+/g, " ").trim();
}

/** Opens a link the way an untrusted link must be opened: validated address, manual redirects, size and time limits, text only, no cookies. */
export async function safeFetch(start: string): Promise<Page> {
  let url = checkUrl(start);
  for (let hop = 0; hop <= 5; hop++) {
    let addrs: { address: string; family: number }[];
    try { addrs = await dns.lookup(url.hostname, { all: true }); } catch { throw new FetchError("dns_error"); }
    if (!addrs.length || addrs.some((a) => isBlockedAddress(a.address))) throw new FetchError("blocked_by_policy");
    const pinned = addrs[0]; // connect to the address that was validated, so a second DNS answer cannot change it
    const res = await new Promise<{ http: number; headers: http.IncomingHttpHeaders; body: Buffer }>((resolve, reject) => {
      const lib = url.protocol === "https:" ? https : http;
      const req = lib.request({
        hostname: url.hostname, port: url.port || undefined, path: url.pathname + url.search, method: "GET", servername: url.hostname, timeout: 8000,
        lookup: (_h, _o, cb) => (_o as { all?: boolean })?.all ? cb(null, [{ address: pinned.address, family: pinned.family }] as never, undefined as never) : cb(null, pinned.address, pinned.family),
        headers: { "User-Agent": "TENIX-Exposure-NewsBot/1.0", Accept: "text/html,text/plain", "Accept-Encoding": "identity" },
      }, (r) => {
        const type = String(r.headers["content-type"] ?? "").toLowerCase();
        const redirect = [301, 302, 303, 307, 308].includes(r.statusCode ?? 0) && r.headers.location;
        if (!redirect && !/^(text\/|application\/xhtml)/.test(type)) { r.destroy(); return reject(new FetchError("unsupported_type", r.statusCode)); }
        const chunks: Buffer[] = []; let size = 0;
        r.on("data", (c: Buffer) => { size += c.length; if (size > MAX_PAGE) { r.destroy(); reject(new FetchError("too_large")); } else chunks.push(c); });
        r.on("end", () => resolve({ http: r.statusCode ?? 0, headers: r.headers, body: Buffer.concat(chunks) }));
        r.on("error", () => reject(new FetchError("http_error", r.statusCode)));
      });
      req.on("timeout", () => { req.destroy(); reject(new FetchError("timeout")); });
      req.on("error", (e) => reject(e instanceof FetchError ? e : new FetchError("http_error")));
      req.end();
    });
    if ([301, 302, 303, 307, 308].includes(res.http) && res.headers.location) {
      if (hop === 5) throw new FetchError("redirect_limit");
      url = checkUrl(new URL(String(res.headers.location), url).toString()); // every hop is checked again
      continue;
    }
    if (res.http < 200 || res.http >= 300) throw new FetchError("http_error", res.http);
    const type = String(res.headers["content-type"] ?? "");
    const body = res.body.toString("utf8");
    return { status: "ok", finalUrl: url.toString(), http: res.http, contentType: type, hash: sha256(res.body.toString("latin1")), text: /html/i.test(type) ? htmlToText(body) : body };
  }
  throw new FetchError("redirect_limit");
}

// ---------------------------------------------------------------- outside world (replaced in tests)
export type OcrResult = { status: "ok"; text: string } | { status: "unavailable" | "error" | "too_large" };
function tesseract(img: Buffer): Promise<OcrResult> {
  if (img.length > MAX_IMAGE) return Promise.resolve({ status: "too_large" });
  return new Promise((resolve) => {
    const p = spawn("tesseract", ["stdin", "stdout", "-l", "eng+tha", "--psm", "6"], { stdio: ["pipe", "pipe", "ignore"] });
    let out = ""; const timer = setTimeout(() => { p.kill("SIGKILL"); resolve({ status: "error" }); }, 30_000);
    p.stdout.on("data", (d) => { if (out.length < 200_000) out += d; });
    p.on("error", (e) => { clearTimeout(timer); resolve({ status: (e as NodeJS.ErrnoException).code === "ENOENT" ? "unavailable" : "error" }); });
    p.on("close", (code) => { clearTimeout(timer); resolve(code === 0 ? { status: "ok", text: out } : { status: "error" }); });
    p.stdin.on("error", () => {});
    p.stdin.end(img);
  });
}
async function lineApi(token: string, method: "GET" | "POST", url: string, body?: unknown): Promise<{ ok: boolean; status: number; data?: Buffer }> {
  try {
    const r = await fetch(url, { method, headers: { Authorization: `Bearer ${token}`, ...(body ? { "Content-Type": "application/json" } : {}) }, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(15_000) });
    return { ok: r.ok, status: r.status, data: Buffer.from(await r.arrayBuffer()) };
  } catch { return { ok: false, status: 0 }; }
}
/** One POST of the unchanged request to the other system; 0 means the connection failed. Redirects are not followed. */
async function forwardOnce(url: string, raw: Buffer, headers: Record<string, string>): Promise<number> {
  try { return (await fetch(url, { method: "POST", headers, body: new Uint8Array(raw), redirect: "manual", signal: AbortSignal.timeout(5000) })).status; } catch { return 0; }
}
export const hooks = { fetchPage: safeFetch, ocr: tesseract, line: lineApi, forward: forwardOnce };

// ---------------------------------------------------------------- configuration
interface Cfg {
  secret: string; token: string;
  sources: Map<string, string | null>;      // chat -> organization it belongs to (null = the SOC's): where news is read
  allowedChats: string[];                    // the SOC's source chats
  answerChats: string[];                     // the SOC's destination chats
  tenantDests: Map<string, string[]>;        // organization -> its own destination chats
  chatNames: Record<string, string>; forwardUrl: string;
}
/** Once: what older versions kept in the LINE setup (one list of chats, one answer chat) and on each organization (one group) becomes rows of line_chats. */
async function migrateChats() {
  if (await get("SELECT 1 FROM feed_state WHERE key = 'line_chats_migrated'")) return;
  const row = await get<{ config_json: string }>("SELECT config_json FROM integrations WHERE key = 'line'");
  if (row) {
    const c = JSON.parse(row.config_json) as { allowedChats?: string[]; answerChat?: string; answerChats?: string[]; chatNames?: Record<string, string> };
    const name = (id: string) => c.chatNames?.[id] ?? null;
    for (const id of c.allowedChats ?? []) await run("INSERT INTO line_chats (chat_id, role, tenant_id, name, created_at) VALUES (?, 'source', NULL, ?, ?) ON CONFLICT DO NOTHING", id, name(id), now());
    for (const id of c.answerChats ?? (c.answerChat ? [c.answerChat] : [])) await run("INSERT INTO line_chats (chat_id, role, tenant_id, name, created_at) VALUES (?, 'destination', NULL, ?, ?) ON CONFLICT DO NOTHING", id, name(id), now());
  }
  await run("INSERT INTO line_chats (chat_id, role, tenant_id, name, created_at) SELECT line_chat, 'destination', id, NULL, ? FROM tenants WHERE line_chat IS NOT NULL AND line_chat <> '' ON CONFLICT DO NOTHING", now());
  await run("INSERT INTO feed_state (key, info_json) VALUES ('line_chats_migrated', '{}') ON CONFLICT DO NOTHING");
}
async function loadCfg(): Promise<Cfg | null> {
  const row = await get<{ config_json: string; secret_sealed: string | null }>("SELECT config_json, secret_sealed FROM integrations WHERE key = 'line'");
  if (!row?.secret_sealed) return null;
  const s = JSON.parse(unseal(row.secret_sealed)) as { secret?: string; token?: string };
  const c = JSON.parse(row.config_json) as { forwardUrl?: string };
  await migrateChats();
  const sources = new Map<string, string | null>(), tenantDests = new Map<string, string[]>(), allowedChats: string[] = [], answerChats: string[] = [], chatNames: Record<string, string> = {};
  for (const r of await all<{ chat_id: string; role: string; tenant_id: string | null; name: string | null }>("SELECT chat_id, role, tenant_id, name FROM line_chats ORDER BY created_at, chat_id")) {
    if (r.name && !chatNames[r.chat_id]) chatNames[r.chat_id] = r.name;
    if (r.role === "source") { sources.set(r.chat_id, r.tenant_id); if (!r.tenant_id) allowedChats.push(r.chat_id); }
    else if (!r.tenant_id) answerChats.push(r.chat_id);
    else tenantDests.set(r.tenant_id, [...(tenantDests.get(r.tenant_id) ?? []), r.chat_id]);
  }
  return { secret: s.secret ?? "", token: s.token ?? "", sources, allowedChats, answerChats, tenantDests, chatNames, forwardUrl: c.forwardUrl ?? "" };
}

// ---------------------------------------------------------------- matching with the synced findings
/** One affected device: its name, and the version of the affected product it runs (the product as Falcon names it, else the OS version). */
/** One remediation Falcon recommends, and how many of the organization's devices it applies to. */
export interface Fix { text: string; devices: number; link: string | null; type: string | null }
export interface Device { name: string; versions: string[]; severity: string; aid?: string; asset?: AssetLevel; level?: Level; esc?: Esc }
interface TenantHit { id: string; tenant: string; chats: string[]; devices: number; severity: string; names: Device[]; fixes: Fix[]; console: string | null; complete: boolean; state: ImpactState; asOf: number | null; note?: string; assetLevel?: AssetLevel; notifyLevel?: Level; escalated?: boolean; exploited?: boolean }
/** What the card says about the CVE itself: the CVE Program record, else what Falcon knows, else "waiting for the CVE Program". */
export interface About { announced: boolean; rejected: boolean; title: string | null; description: string | null; cvss: number | null; cvssSeverity: string | null; publishedAt: number | null; kev: PublicView["kev"] }
export interface CveMatch { cve: string; kev: boolean; known: boolean; about: About; link: string | null; advisory: string | null; tenants: TenantHit[] }
const SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"];
const thai = new Intl.Collator("th", { numeric: true });

/** The vendor's own page for the CVE (what Falcon lists as the vendor advisory), https only. */
function vendorPage(advisories: string | null | undefined, refs: string[]): string | null {
  let list: string[] = [];
  try { list = advisories ? JSON.parse(advisories) : []; } catch { /* none */ }
  return [...list, ...refs].find((u) => typeof u === "string" && /^https:\/\//i.test(u) && u.length <= 1000) ?? null;
}

/** For each CVE, every organization with its device count, the full list of devices (name and local IP) and what may be concluded when there are none. */
export async function matchCves(cves: string[], newsAt = now()): Promise<CveMatch[]> {
  if (!cves.length) return [];
  await ensurePublic(cves); // a CVE named in the news before the feed has seen it is fetched now; if the source is slow it is filled in by the next feed run
  const pub = await publicInfo(cves);
  const ph = `(${cves.map(() => "?").join(",")})`;
  const tenants = byName(await all<{ id: string; name: string }>("SELECT id, name FROM tenants"));
  const bases = new Map((await all<{ tenant_id: string; base_url: string }>("SELECT tenant_id, MIN(base_url) AS base_url FROM falcon_connections GROUP BY tenant_id")).map((r) => [r.tenant_id, r.base_url]));
  const destinations = await all<{ tenant_id: string; chat_id: string }>("SELECT tenant_id, chat_id FROM line_chats WHERE role = 'destination' AND tenant_id IS NOT NULL ORDER BY created_at, chat_id");
  const status = await all<{ tenant_id: string; state: string | null; data_as_of: number | null; slice: boolean }>("SELECT x.tenant_id, s.state, s.data_as_of, (y.scope = 'priority') AS slice FROM tenant_cids x LEFT JOIN cid_status s ON s.cid = x.cid LEFT JOIN cid_sync y ON y.cid = x.cid");
  const hits = await all<{ cve_id: string; tenant_id: string; devices: number; rank: number }>(
    `SELECT f.cve_id, x.tenant_id, COUNT(DISTINCT f.cid || f.aid) AS devices,
            MIN(CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END) AS rank
     FROM findings f JOIN tenant_cids x ON x.cid = f.cid WHERE f.cve_id IN ${ph} GROUP BY f.cve_id, x.tenant_id`, ...cves);
  const devs = await all<{ cve_id: string; tenant_id: string; cid: string; hostname: string | null; aid: string; product: string | null; os_version: string | null; severity: string }>(
    `SELECT DISTINCT f.cve_id, x.tenant_id, f.cid, f.hostname, f.aid, f.product, f.os_version, f.severity
     FROM findings f JOIN tenant_cids x ON x.cid = f.cid WHERE f.cve_id IN ${ph} ORDER BY f.cve_id, x.tenant_id, f.cid, f.aid`, ...cves);
  const rem = await all<{ cve_id: string; tenant_id: string; remediation: string; remediation_json: string | null; devices: number }>(
    `SELECT f.cve_id, x.tenant_id, f.remediation, f.remediation_json, COUNT(DISTINCT f.cid || f.aid) AS devices FROM findings f JOIN tenant_cids x ON x.cid = f.cid
     WHERE f.cve_id IN ${ph} AND f.remediation IS NOT NULL GROUP BY f.cve_id, x.tenant_id, f.remediation, f.remediation_json`, ...cves);
  const facts = await all<{ id: string; cisa_kev: number; description: string | null; published_at: string | null; advisories_json: string | null }>(`SELECT id, cisa_kev, description, published_at, advisories_json FROM cves WHERE id IN ${ph}`, ...cves);
  return Promise.all(cves.map(async (cve) => {
    const p = pub.get(cve)!, f = facts.find((x) => x.id === cve);
    // the announcement is the point in time Falcon's read has to be newer than before "not found" may be said (the CVE Program's date, else the date Falcon has);
    // a CVE nobody has announced yet is only known from the news, so the news is that point
    const since = p.publishedAt ?? (f?.published_at && Number.isFinite(Date.parse(f.published_at)) ? Date.parse(f.published_at) : newsAt);
    return {
      cve, kev: !!f?.cisa_kev || !!p.kev, known: !!f, link: await falconLink(cve), advisory: vendorPage(f?.advisories_json, p.references),
      about: { announced: p.announced, rejected: p.state === "REJECTED", title: p.title, description: p.description ?? f?.description ?? null, cvss: p.cvss.score, cvssSeverity: p.cvss.severity, publishedAt: p.publishedAt, kev: p.kev },
      tenants: tenants.map((t) => {
        const h = hits.find((x) => x.cve_id === cve && x.tenant_id === t.id);
        const mine = status.filter((s) => s.tenant_id === t.id);
        const im = impactFrom(mine, h?.devices ?? 0, since);
        // one entry per device, with EVERY version it runs (a device can have the same CVE through several installed versions)
        const byDevice = new Map<string, { name: string; aid: string; versions: Set<string>; rank: number }>();
        for (const d of devs) {
          if (d.cve_id !== cve || d.tenant_id !== t.id) continue;
          const e = byDevice.get(`${d.cid}/${d.aid}`) ?? { name: (d.hostname ?? d.aid.slice(0, 8)).slice(0, 80), aid: d.aid, versions: new Set<string>(), rank: 4 };
          e.versions.add((d.product ?? d.os_version ?? "-").slice(0, 60));
          e.rank = Math.min(e.rank, Math.max(0, SEV.indexOf(d.severity)));
          byDevice.set(`${d.cid}/${d.aid}`, e);
        }
        const names: Device[] = [...byDevice.values()].map((e) => ({ name: e.name, aid: e.aid, versions: [...e.versions].sort(thai.compare), severity: SEV[e.rank] })).sort((a, b) => thai.compare(a.name, b.name) || thai.compare(a.versions[0], b.versions[0]));
        const fixes = new Map<string, Fix>(); // the same action on several devices counts once per device
        for (const r of rem) {
          if (r.cve_id !== cve || r.tenant_id !== t.id) continue;
          let list: { action: string; link: string | null; type: string | null }[];
          try { list = r.remediation_json ? JSON.parse(r.remediation_json) : []; } catch { list = []; }
          if (!list.length) list = r.remediation.split("\n").map((l) => ({ action: l.replace(/^[-*\s]+/, "").trim(), link: null, type: null })).filter((x) => x.action); // data stored before the links were kept
          for (const x of list) { const a = fixes.get(x.action) ?? { text: x.action.slice(0, 300), devices: 0, link: x.link, type: x.type }; a.devices += r.devices; a.link ??= x.link; a.type ??= x.type; fixes.set(x.action, a); }
        }
        return { id: t.id, tenant: t.name, console: bases.get(t.id) ?? null, chats: destinations.filter((d) => d.tenant_id === t.id).map((d) => d.chat_id), devices: h?.devices ?? 0, severity: h ? SEV[h.rank] : "", names, fixes: [...fixes.values()].sort((a, b) => b.devices - a.devices || thai.compare(a.text, b.text)), complete: mine.length > 0 && im.complete === mine.length, state: im.state, asOf: im.asOf };
      }),
    };
  }));
}

// ---------------------------------------------------------------- the answer: one Flex card per organization and CVE
const COLOR: Record<string, string> = { CRITICAL: "#dc2626", HIGH: "#ea580c", MEDIUM: "#ca8a04", LOW: "#16a34a", NONE: "#2563eb" };
const sevLabel = (s: string) => (s === "NONE" ? "INFORMATIONAL" : s);
/** A level as the chips say it (Falcon's English names); "no level known" is Thai and blue like every other non-severity. */
const lvl = (s: string) => (s === "UNASSIGNED" ? "ไม่ระบุ" : s === "NONE" ? "Informational" : `${s[0]}${s.slice(1).toLowerCase()}`);
/** Which devices were raised to CRITICAL and why: the evidence is an alert Falcon raised on the machine (id kept), or the CVE itself being exploited (KEV / exploit status). */
function escalationLines(names: Device[]): object[] {
  const hit = names.filter((d) => d.esc);
  const out: object[] = [];
  const alerts = hit.filter((d) => d.esc!.type === "alert");
  if (alerts.length) out.push(txt("ยกระดับ: พบการโจมตีบนเครื่องนี้", { size: "sm", weight: "bold", color: RED }),
    ...alerts.slice(0, 3).map((d) => txt(`${d.name}: Falcon มี alert ภายใน ${d.esc!.days} วัน${d.esc!.alertId ? ` (${clip(d.esc!.alertId.split(":").pop()!, 40)})` : ""}`, { size: "xxs", color: MUTED })),
    ...(alerts.length > 3 ? [txt(`และอีก ${alerts.length - 3} เครื่อง`, { size: "xxs", color: MUTED })] : []));
  if (hit.some((d) => d.esc!.type !== "alert")) out.push(txt("ยกระดับ: CVE นี้ถูกใช้โจมตีจริง (KEV / exploit)", { size: "sm", weight: "bold", color: RED }));
  return out;
}
/** Devices (or CVEs) per severity as coloured chips, worst first: how a card or a news item divides into Critical / High / Medium / Low / Informational. */
const sevChips = (counts: Record<string, number>) => SEV.filter((k) => counts[k]).map((k) => pill(`${sevLabel(k)} ${counts[k]}`, COLOR[k] ?? BLUE));
const NAMES_PER_BUBBLE = 40, MESSAGE_BYTES = 45_000, BUBBLES_PER_MESSAGE = 12, PUSH_BATCH = 5; // LINE: a Flex message may be 50 KB (the limit we stay under), a carousel 12 cards, a push 5 messages
const MAX_MESSAGES_PER_TENANT = 40; // shortcut: a hard stop far above any real list (40 x 5 x 50 devices); the summary says when it cuts
const INK = "#111827", MUTED = "#6b7280", GREEN = "#16a34a", RED = "#dc2626", AMBER = "#b45309", PANEL = "#f3f4f6", BLUE = "#2563eb";

const txt = (text: string, o: Record<string, unknown> = {}) => ({ type: "text", text, wrap: true, ...o });
const pill = (text: string, bg: string) => ({ type: "box", layout: "vertical", flex: 0, backgroundColor: bg, cornerRadius: "12px", paddingStart: "10px", paddingEnd: "10px", paddingTop: "3px", paddingBottom: "3px", contents: [txt(text, { size: "xxs", color: "#ffffff", weight: "bold", wrap: false })] });
const pills = (items: [string, string][]) => ({ type: "box", layout: "horizontal", spacing: "sm", contents: items.map(([t, c]) => pill(t, c)) });
const eyebrow = (t: string) => txt(`10CYBER · ${t}`, { size: "xxs", color: MUTED, weight: "bold" });
/** Every message the bot sends is one of these: a white card with a coloured strip on top. */
const card = (color: string, body: object[], footer?: object) => ({
  type: "bubble", size: "giga",
  header: { type: "box", layout: "vertical", paddingAll: "0px", contents: [{ type: "box", layout: "vertical", height: "6px", backgroundColor: color, contents: [{ type: "filler" }] }] },
  body: { type: "box", layout: "vertical", spacing: "md", paddingAll: "lg", contents: body },
  ...(footer ? { footer } : {}),
});
const flex = (altText: string, contents: object) => ({ type: "flex", altText: altText.slice(0, 400), contents });
/** A short message (error, "nothing found", chat id) in the same style. */
const notice = (color: string, kind: string, title: string, lines: string[] = []) =>
  flex(`${title} ${lines.join(" ")}`, card(color, [eyebrow(kind), txt(title, { size: "lg", weight: "bold", color: INK }), ...lines.map((l) => txt(l, { size: "sm", color: MUTED }))]));

const fmt = (o: Intl.DateTimeFormatOptions) => new Intl.DateTimeFormat("th-TH-u-ca-gregory", { timeZone: "Asia/Bangkok", ...o });
const fmtTime = fmt({ day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
const fmtDay = fmt({ day: "numeric", month: "short", year: "numeric" });
const clip = (v: string, n: number) => (v.length > n ? `${v.slice(0, n - 1).trimEnd()}…` : v);

function chunkNames(names: Device[]): Device[][] {
  const out: Device[][] = [];
  for (let i = 0; i < names.length; i += NAMES_PER_BUBBLE) out.push(names.slice(i, i + NAMES_PER_BUBBLE));
  return out;
}

export interface Row { cve: string; kev: boolean; hit: TenantHit; about: About; link: string | null; advisory: string | null }
/** What an organization with no matching device may be told. */
const VERDICT: Record<Exclude<ImpactState, "affected">, { say: string; color: string; why: (at: string) => string }> = {
  not_found: { say: "ไม่พบเครื่องที่เกี่ยวข้อง", color: GREEN, why: (at) => `ตามข้อมูล Falcon ล่าสุด ${at}` },
  pending: { say: "รอผลตรวจ", color: MUTED, why: (at) => `ข้อมูล Falcon ล่าสุด ${at} ยังเก่ากว่าประกาศ CVE นี้ กำลังรอข้อมูลใหม่` },
  partial: { say: "ตรวจได้บางส่วน", color: AMBER, why: (at) => `อ่านข้อมูล Falcon ได้ไม่ครบ ผลล่าสุด ${at}` },
  unavailable: { say: "ตรวจไม่ได้", color: AMBER, why: () => "ยังอ่านข้อมูลจาก Falcon ไม่สำเร็จ" },
};
/** The CVE Program text, or the honest "waiting" line when it has not arrived. */
function aboutBlock(a: About): object[] {
  const out: object[] = [];
  if (a.title) out.push(txt(clip(a.title, 120), { size: "sm", weight: "bold", color: INK }));
  out.push(txt(a.description ? clip(a.description, 260) : a.announced ? "ยังไม่มีคำอธิบายในประกาศนี้" : "รอข้อมูลจาก CVE Program", { size: "xs", color: a.description ? "#374151" : MUTED }));
  const facts = [a.publishedAt ? `ประกาศ ${fmtDay.format(a.publishedAt)}` : "", a.kev?.dateAdded ? `เข้า KEV ${a.kev.dateAdded}` : "", a.kev?.dueDate ? `กำหนดแก้ไข ${a.kev.dueDate}` : ""].filter(Boolean);
  if (facts.length) out.push(txt(facts.join(" · "), { size: "xxs", color: MUTED }));
  return out;
}

const MAX_FIXES = 8;
/** The second card of a CVE: what CrowdStrike Falcon recommends doing (the actions of the organization's own findings), and a button to the Falcon console. */
export function fixBubble(label: string, r: Row, base: string = appUrl): object {
  const list = r.hit.fixes.slice(0, MAX_FIXES);
  const body: object[] = [eyebrow("แนวทางแก้ไข"), txt(r.cve, { size: "xl", weight: "bold", color: INK }), txt("วิธีแก้ไขที่ CrowdStrike Falcon แนะนำ", { size: "sm", weight: "bold", color: BLUE }), txt(label, { size: "xs", color: MUTED })];
  if (list.length) {
    const TYPE: Record<string, string> = { recommended: "แนะนำ", minimum: "ขั้นต่ำ" };
    body.push({ type: "box", layout: "vertical", spacing: "md", backgroundColor: PANEL, cornerRadius: "md", paddingAll: "md", contents: list.map((f, i) => ({
      type: "box", layout: "horizontal", spacing: "md", ...(f.link ? { action: { type: "uri", label: "เปิดลิงก์", uri: f.link } } : {}), contents: [
        txt(String(i + 1), { size: "sm", weight: "bold", color: BLUE, flex: 0 }),
        { type: "box", layout: "vertical", flex: 1, contents: [
          txt(clip(f.text, 240), { size: "sm", color: INK }),
          txt([`${f.devices} เครื่อง`, f.type && TYPE[f.type] ? TYPE[f.type] : "", f.link ? "แตะเพื่อเปิดลิงก์ ›" : ""].filter(Boolean).join(" · "), { size: "xxs", color: f.link ? BLUE : MUTED }),
        ] },
      ] })) });
    if (r.hit.fixes.length > MAX_FIXES) body.push(txt(`มีอีก ${r.hit.fixes.length - MAX_FIXES} แนวทาง ดูทั้งหมดใน CrowdStrike Falcon`, { size: "xxs", color: MUTED }));
  } else if (r.about.kev?.requiredAction) {
    body.push(txt("Falcon ยังไม่ได้ให้แนวทางแก้ไขสำหรับ CVE นี้", { size: "xs", color: MUTED }), { type: "box", layout: "vertical", spacing: "xs", backgroundColor: PANEL, cornerRadius: "md", paddingAll: "md", contents: [txt("CISA แนะนำ", { size: "xxs", weight: "bold", color: MUTED }), txt(clip(r.about.kev.requiredAction, 400), { size: "sm", color: INK })] });
  } else body.push(txt("Falcon ยังไม่ได้ให้แนวทางแก้ไขสำหรับ CVE นี้ ตรวจรายละเอียดเพิ่มเติมได้ใน CrowdStrike Falcon", { size: "sm", color: MUTED }));
  const links: object[] = [];
  const logo = base.startsWith("https://") ? `${base}/brand/team.png` : null; // our own picture (LINE needs https); the team's mark, small, as the link to Falcon
  if (r.link) links.push(logo
    ? { type: "box", layout: "horizontal", spacing: "md", alignItems: "center", paddingAll: "md", cornerRadius: "md", borderWidth: "1px", borderColor: "#e5e7eb", action: { type: "uri", label: "ดูต่อเพิ่มเติม", uri: r.link }, contents: [
      { type: "image", url: logo, size: "88px", aspectRatio: "480:196", aspectMode: "fit", flex: 0 },
      txt("ดูต่อเพิ่มเติมใน CrowdStrike ›", { size: "sm", weight: "bold", color: BLUE, flex: 1, align: "end" }),
    ] }
    : { type: "button", style: "primary", color: BLUE, height: "sm", action: { type: "uri", label: "ดูต่อเพิ่มเติม", uri: r.link } });
  if (r.advisory) links.push({ type: "button", style: "link", height: "sm", action: { type: "uri", label: "ประกาศจากผู้ผลิต", uri: r.advisory } });
  const footer = links.length ? { type: "box", layout: "vertical", spacing: "sm", paddingAll: "lg", paddingTop: "0px", contents: links } : undefined;
  return card(BLUE, body, footer);
}

export function flexBubbles(label: string, rows: Row[], note: { source?: string; more?: number }): { cve: string; bubble: object; alt?: string }[] {
  const bubbles: { cve: string; bubble: object; alt?: string }[] = [];
  rows.forEach((r, ri) => {
    const h = r.hit;
    const hit = h.state === "affected";
    const color = hit ? (COLOR[h.notifyLevel ?? h.severity] ?? BLUE) : VERDICT[h.state as Exclude<ImpactState, "affected">].color;
    const parts = hit && h.names.length ? chunkNames(h.names) : [[] as Device[]]; // a preference may leave no names: the count card still goes out
    parts.forEach((names, pi) => {
      const body: object[] = [eyebrow("แจ้งเตือนช่องโหว่"), txt(`${r.cve}${parts.length > 1 ? `  (${pi + 1}/${parts.length})` : ""}`, { size: "xl", weight: "bold", color: INK })];
      if (pi === 0) {
        const tags: [string, string][] = [];
        if (hit && !h.assetLevel) tags.push([sevLabel(h.severity), color]);
        if (r.about.rejected) tags.push(["REJECTED", AMBER]);
        if (r.about.cvss !== null) tags.push([`CVSS ${r.about.cvss.toFixed(1)}`, "#475569"]);
        if (r.kev) tags.push(["ถูกโจมตีจริง · CISA KEV", RED]);
        else if (h.exploited) tags.push(["ถูกโจมตีจริง · exploit", RED]);
        if (hit && h.assetLevel) { // the two levels are separate chips; the result (when the matrix is on) is the third
          body.push(pills([[`ระดับ CVE: ${lvl(h.severity)}`, COLOR[h.severity] ?? BLUE], [`ระดับเครื่อง: ${lvl(h.assetLevel)}`, COLOR[h.assetLevel] ?? BLUE]]));
          if (h.notifyLevel) body.push(pills([[`ระดับแจ้งเตือน: ${lvl(h.notifyLevel)}`, COLOR[h.notifyLevel] ?? BLUE]]));
          if (h.escalated) body.push(...escalationLines(h.names));
        }
        if (tags.length) body.push(pills(tags));
        if (hit) {
          body.push({ type: "box", layout: "horizontal", spacing: "md", alignItems: "center", margin: "sm", contents: [
            txt(String(h.devices), { size: "3xl", weight: "bold", color, flex: 0, wrap: false }),
            { type: "box", layout: "vertical", contents: [txt("เครื่องที่พบ", { size: "sm", weight: "bold", color: INK }), txt(label, { size: "xs", color: MUTED })] },
          ] });
          const per: Record<string, number> = {};
          for (const d of h.names) per[d.severity] = (per[d.severity] ?? 0) + 1;
          if (Object.keys(per).length > 1 && !h.note) body.push({ type: "box", layout: "horizontal", spacing: "sm", flex: 0, contents: sevChips(per) }); // devices of mixed severity: split and coloured
          if (h.note) body.push(txt(h.note, { size: "xs", color: AMBER }));
          if (!h.complete) body.push(txt("ข้อมูลยังไม่ครบ อาจมีเครื่องมากกว่านี้", { size: "xs", color: AMBER }));
          if (h.asOf) body.push(txt(`ข้อมูล Falcon ล่าสุด ${fmtTime.format(h.asOf)}`, { size: "xxs", color: MUTED }));
        } else {
          const v = VERDICT[h.state as Exclude<ImpactState, "affected">];
          body.push(txt(`${label}${v.say}`, { size: "md", weight: "bold", color: v.color }), txt(v.why(h.asOf ? fmtTime.format(h.asOf) : "ยังไม่มี"), { size: "xxs", color: MUTED }));
        }
        body.push({ type: "separator", margin: "sm" }, ...aboutBlock(r.about));
      }
      // two columns: the device name on the left, the version it runs on the right; each device is its own row so a long value wraps instead of shifting the others
      if (names.length) body.push({ type: "box", layout: "vertical", spacing: "sm", backgroundColor: PANEL, cornerRadius: "md", paddingAll: "md", contents: [
        { type: "box", layout: "horizontal", spacing: "md", contents: [txt(pi === 0 ? `ชื่อเครื่อง (${h.note ? h.names.length : h.devices})` : "ชื่อเครื่อง (ต่อ)", { size: "xxs", weight: "bold", color: MUTED, flex: 5 }), txt("เวอร์ชันที่ใช้อยู่", { size: "xxs", weight: "bold", color: MUTED, flex: 4, align: "end" })] },
        // one block per device, a thin rule between devices, and every version it runs stacked on the right: a device with two versions is still ONE device
        { type: "box", layout: "vertical", contents: names.flatMap((d, i) => [
          ...(i ? [{ type: "separator", margin: "sm", color: "#d1d5db" }] : []),
          { type: "box", layout: "horizontal", spacing: "sm", margin: i ? "sm" : "none", contents: [
            { type: "box", layout: "vertical", flex: 0, width: "8px", height: "8px", cornerRadius: "4px", backgroundColor: COLOR[d.severity] ?? BLUE, margin: "xs", contents: [{ type: "filler" }] },
            txt(d.name, { size: "xs", color: INK, flex: 5, weight: "bold" }),
            { type: "box", layout: "vertical", flex: 4, spacing: "xs", contents: d.versions.map((v) => txt(v, { size: "xs", color: MUTED, align: "end" })) },
          ] },
          ...(d.asset ? [{ type: "box", layout: "vertical", paddingStart: "16px", contents: [txt(`ระดับเครื่อง: ${lvl(d.asset)}${d.esc ? " · ยกระดับ" : ""}`, { size: "xxs", color: d.esc ? RED : COLOR[d.asset] ?? BLUE })] }] : []),
        ]) },
      ] });
      if (ri === 0 && pi === 0) {
        if (note.source) body.push(txt(`ที่มา: ${note.source}`, { size: "xxs", color: MUTED }));
        if (note.more) body.push(txt(`แสดง ${MAX_CVES} CVE แรกจาก ${MAX_CVES + note.more} รายการ`, { size: "xxs", color: MUTED }));
      }
      bubbles.push({ cve: r.cve, bubble: card(color, body), alt: hit && h.notifyLevel ? `ระดับแจ้งเตือน ${lvl(h.notifyLevel)}` : undefined });
      if (hit && pi === 0) bubbles.push({ cve: r.cve, bubble: fixBubble(label, r) }); // the recommendation sits right beside the details of the same CVE
    });
  });
  return bubbles;
}
/** Cards into messages (5 cards each, as a carousel); `cut` says the hard stop was hit. */
export function packBubbles(altText: string, bubbles: { cve: string; bubble: object; alt?: string }[]): { messages: object[]; truncated: boolean } {
  const messages: object[] = [];
  let group: { cve: string; bubble: object; alt?: string }[] = [], bytes = 0;
  const close = () => {
    if (!group.length) return;
    messages.push(flex(`${altText}: ${[...new Set(group.map((g) => (g.alt ? `${g.cve} (${g.alt})` : g.cve)))].join(", ")}`, group.length === 1 ? group[0].bubble : { type: "carousel", contents: group.map((g) => g.bubble) }));
    group = []; bytes = 0;
  };
  for (const b of bubbles) { // a message is closed by its size, not only by the card count: a card with 40 devices is about 8 KB
    const n = Buffer.byteLength(JSON.stringify(b.bubble));
    if (group.length && (group.length >= BUBBLES_PER_MESSAGE || bytes + n > MESSAGE_BYTES)) close();
    group.push(b); bytes += n;
  }
  close();
  return { messages: messages.slice(0, MAX_MESSAGES_PER_TENANT), truncated: messages.length > MAX_MESSAGES_PER_TENANT };
}
/** `label` is "องค์กรของคุณ" when the message goes to the organization's own group, else the organization's name. Every device name is listed. */
export const flexMessages = (label: string, rows: Row[], note: { source?: string; more?: number }) => packBubbles(label, flexBubbles(label, rows, note));
// Sites that show their content to signed-in people only: what a server gets is a login page, so "no CVE found" would be a wrong answer. Not fetched at all.
const LOGIN_WALL = /(^|\.)(facebook\.com|fb\.com|fb\.watch|fb\.me|instagram\.com)$/i;
const walled = (u: string) => { try { return LOGIN_WALL.test(new URL(u).hostname); } catch { return false; } };
const URL_REASON: Record<string, string> = { login_required: "ต้องล็อกอินจึงอ่านไม่ได้ ส่งภาพหน้าจอโพสต์หรือพิมพ์รหัส CVE แทนได้", blocked_by_policy: "ที่อยู่ไม่ปลอดภัยหรือไม่อนุญาต", dns_error: "ไม่พบชื่อโดเมน", timeout: "หมดเวลา", http_error: "เซิร์ฟเวอร์ตอบผิดปกติ", too_large: "ไฟล์ใหญ่เกินไป", unsupported_type: "ไม่ใช่หน้าข้อความ", redirect_limit: "เปลี่ยนเส้นทางมากเกินไป" };

// ---------------------------------------------------------------- one news item
// Always a push, never a reply: a reply token works once, and the webhook of this channel may belong to another system that still needs it.
async function pushAll(cfg: Cfg, to: string, messages: object[]) {
  for (let i = 0; i < messages.length; i += PUSH_BATCH) {
    const r = await hooks.line(cfg.token, "POST", "https://api.line.me/v2/bot/message/push", { to, messages: messages.slice(i, i + PUSH_BATCH) });
    if (!r.ok) return `failed:${r.status}`;
  }
  return "sent";
}
const sendCard = (cfg: Cfg, to: string, message: object) => pushAll(cfg, to, [message]);

/** Every escalation to CRITICAL that went out is on the audit trail with its reason (evidence type, alert id, window). */
async function auditEscalations(tenantId: string, rows: Row[]) {
  for (const r of rows) {
    const e = r.hit.names.filter((d) => d.esc);
    if (e.length) await audit({ tenantId, action: "notify.escalate", resource: r.cve, result: "ok", detail: e.slice(0, 5).map((d) => `${d.name} ${d.esc!.type}${d.esc!.alertId ? ` ${d.esc!.alertId.split(":").pop()}` : ""} ${d.esc!.days}d`).join("; ").slice(0, 900) });
  }
}

/** One line saying what the answer is about. Only needed when the answer goes to another chat than the one the news came from. */
function aboutLine(kind: "text" | "image", text: string): string {
  if (kind === "image") return "ข่าว: รูปภาพที่ส่งมา";
  const u = urlsIn(text)[0];
  return `ข่าว: ${(u ?? text).replace(/\s+/g, " ").trim().slice(0, 120)}`;
}

/** Each organization gets its own message with only its own devices: in its own LINE group when it has one ("องค์กรของคุณ", also when nothing was found),
 *  otherwise, only if it has matching devices, in the SOC chat under its name. The SOC chat gets ONE message: the summary first, then those cards. */
async function deliver(cfg: Cfg, dests: string[], from: string, kind: "text" | "image", text: string, matches: CveMatch[],
  x: { fails: string[]; more: number }): Promise<string> {
  const source = kind === "text" ? urlsIn(text)[0]?.slice(0, 200) : undefined;
  const own: string[] = [], viaSoc: string[] = [], failed: string[] = [], cut: string[] = [];
  const socCards: { cve: string; bubble: object }[] = [];
  let status = "sent";
  for (const t of matches[0].tenants) {
    let rows: Row[] = await Promise.all(matches.map(async (m) => ({ cve: m.cve, kev: m.kev, about: m.about, link: await falconLink(m.cve, t.console), advisory: m.advisory, hit: m.tenants.find((y) => y.id === t.id)! })));
    const prefs = await loadPrefs(t.id); // no row: exactly what was always sent
    const hits = rows.filter((r) => r.hit.devices > 0);
    if (!t.chats.length) { if (hits.length) { socCards.push(...flexBubbles(t.tenant, await annotate(t.id, hits, prefs), {})); viaSoc.push(t.tenant); } continue; } // no group of its own and nothing found: nobody to tell
    rows = prefs ? await applyPrefs(t.id, rows, prefs) : await annotate(t.id, rows, null); // no row: nothing is filtered, the levels are only shown
    if (!rows.length) continue; // the organization's settings say nothing is sent for this news
    const { messages, truncated } = flexMessages("องค์กรของคุณ", rows, { source, more: x.more });
    let status_ = "sent"; // every group of the organization gets the same cards
    for (const chat of t.chats) { const s = await pushAll(cfg, chat, messages); if (s !== "sent" && status_ === "sent") status_ = s; }
    if (truncated) cut.push(t.tenant);
    if (status_ === "sent") await auditEscalations(t.id, rows);
    if (status_ !== "sent") { failed.push(t.tenant); if (status === "sent") status = status_; } else own.push(t.tenant);
  }
  const verdict = (m: CveMatch) => {
    const hit = m.tenants.filter((t) => t.devices > 0);
    const clear = m.tenants.every((t) => t.state === "not_found");
    return { hit, text: hit.length ? `พบใน ${hit.length} องค์กร (${hit.map((t) => `${t.tenant} ${t.devices}`).join(", ")})` : clear ? "ไม่พบเครื่องที่เกี่ยวข้อง" : "ยังสรุปไม่ได้ว่าพบหรือไม่ (รอผลตรวจหรือข้อมูลยังไม่ครบ)", color: hit.length ? RED : clear ? GREEN : MUTED };
  };
  const cveRow = (m: CveMatch) => {
    const v = verdict(m);
    return { type: "box", layout: "vertical", spacing: "xs", contents: [
      { type: "box", layout: "horizontal", spacing: "sm", alignItems: "center", contents: [txt(m.cve, { size: "md", weight: "bold", color: INK, flex: 0, wrap: false }), ...(m.kev ? [pill("CISA KEV", RED)] : [])] },
      ...(m.about.title ? [txt(clip(m.about.title, 100), { size: "xs", color: MUTED })] : []),
      ...(m.about.announced || m.about.description ? [] : [txt("รอข้อมูลจาก CVE Program", { size: "xs", color: MUTED })]),
      // "nothing found" is only said when every organization's data supports it; a CVE announced after the last read, or an incomplete read, is "not yet known"
      txt(v.text, { size: "sm", color: v.color }),
    ] };
  };
  const notes: object[] = [];
  if (own.length) notes.push(txt(`ส่งเข้ากลุ่มของแต่ละองค์กรแล้ว: ${own.length} องค์กร`, { size: "xs", color: INK }));
  if (failed.length) notes.push(txt(`ส่งไม่สำเร็จ: ${failed.join(", ")}`, { size: "xs", color: RED, weight: "bold" }));
  if (cut.length) notes.push(txt(`รายชื่อเครื่องยาวเกินกำหนดต่อข้อความ ตัดบางส่วน: ${cut.join(", ")}`, { size: "xs", color: AMBER }));
  if (x.more) notes.push(txt(`แสดง ${MAX_CVES} CVE แรกจาก ${MAX_CVES + x.more} รายการ`, { size: "xs", color: MUTED }));
  for (const u of x.fails) notes.push(txt(`เปิดลิงก์ไม่ได้ (${u}) จึงไม่ได้ตรวจเนื้อหาข่าว`, { size: "xs", color: AMBER }));
  const panel = (items: object[]) => ({ type: "box", layout: "vertical", spacing: "xs", backgroundColor: PANEL, cornerRadius: "md", paddingAll: "md", contents: items });
  const clone = <T,>(v: T): T => JSON.parse(JSON.stringify(v));
  const top = Math.min(...matches.flatMap((m) => m.tenants.filter((t) => t.devices > 0).map((t) => SEV.indexOf(t.severity))), 99);
  let result = status;
  // the same answer goes to every chat on the list; the line saying what the news was is only for chats other than the one it came from
  for (const dest of dests) {
    const header: object[] = [];
    if (matches.length > 1) { // several CVEs in one news item: how they divide by severity, coloured
      const per: Record<string, number> = {};
      for (const m of matches) { const rank = Math.min(...m.tenants.filter((t) => t.devices > 0).map((t) => Math.max(0, SEV.indexOf(t.severity))), 99); if (rank < 99) per[SEV[rank]] = (per[SEV[rank]] ?? 0) + 1; }
      if (Object.keys(per).length) header.push({ type: "box", layout: "horizontal", spacing: "sm", flex: 0, contents: sevChips(per) });
    }
    if (dest !== from) header.push(txt(aboutLine(kind, text), { size: "sm", color: MUTED }));
    else if (source) header.push(txt(`ที่มา: ${source}`, { size: "xxs", color: MUTED }));
    let cards: { cve: string; bubble: object }[];
    if (socCards.length) {
      // The organizations' cards ARE the answer: no separate summary card next to them. What the summary would add (news source, CVEs nobody has,
      // what was sent elsewhere, failures) goes at the bottom of the first card.
      const rest = matches.filter((m) => !verdict(m).hit.length);
      const extra: object[] = [...header, ...rest.flatMap((m) => [{ type: "separator" }, cveRow(m)]), ...(notes.length ? [panel(notes)] : [])];
      cards = clone(socCards);
      ((cards[0].bubble as any).body.contents as object[]).push(...extra);
    } else {
      const body: object[] = [eyebrow("สรุปผลการตรวจข่าว"), ...header, ...matches.flatMap((m) => [{ type: "separator" }, cveRow(m)])];
      if (notes.length) body.push(panel(notes));
      cards = [{ cve: matches.map((m) => m.cve).join(", "), bubble: card(failed.length ? RED : top < 99 ? (COLOR[SEV[top]] ?? BLUE) : GREEN, body) }];
    }
    const s = await pushAll(cfg, dest, packBubbles("แจ้งเตือนช่องโหว่", cards).messages);
    if (s !== "sent" && result === "sent") result = s;
  }
  return result;
}

async function analyse(id: string, cfg: Cfg, from: string, kind: "text" | "image", text: string, image: Buffer | undefined, scope: string | null) {
  // news from the SOC's chats answers to the SOC's destination chats (and each organization's own); news from an organization's own chat is read for that organization only
  const dests = !scope && cfg.answerChats.length ? cfg.answerChats : [from]; // the answer goes to the chats on the setup page's list, else back to where it was asked
  const fetched: Record<string, unknown>[] = []; const fails: string[] = [];
  const found = new Map<string, { source: string; snippet: string }>();
  const add = (cve: string, source: string, from: string) => { if (!found.has(cve)) { const i = from.toUpperCase().indexOf(cve); found.set(cve, { source, snippet: from.slice(Math.max(0, i - 60), i + cve.length + 60).replace(/\s+/g, " ").trim() }); } };
  let ocrStatus: string | null = null; let anyRead = false;
  for (const c of extractCves(text)) add(c, "message", text);
  if (kind === "image" && image) {
    const r = await hooks.ocr(image);
    ocrStatus = r.status;
    if (r.status === "ok") { anyRead = true; for (const c of extractCvesFromOcr(r.text)) add(c, "image", r.text); }
  }
  for (const u of urlsIn(text)) {
    if (walled(u)) { fetched.push({ url: u, status: "login_required" }); fails.push(URL_REASON.login_required); continue; }
    try {
      const p = await hooks.fetchPage(u);
      anyRead = true;
      fetched.push({ url: u, finalUrl: p.finalUrl, status: "ok", http: p.http, contentType: p.contentType, hash: p.hash });
      for (const c of extractCves(p.text)) add(c, "article", p.text);
    } catch (e) {
      const s = e instanceof FetchError ? e.status : "http_error";
      fetched.push({ url: u, status: s, http: e instanceof FetchError ? e.http ?? null : null });
      fails.push(URL_REASON[s] ?? s);
    }
  }
  // "none found" is only said when something was actually read; a link that could not be opened never counts as "no CVE"
  const all_ = [...found.keys()]; const shown = all_.slice(0, MAX_CVES);
  const result = all_.length ? "found" : (text || anyRead) && (anyRead || !urlsIn(text).length) ? "none_found" : "not_evaluated";
  for (const [cve, v] of found) await run("INSERT INTO news_cves (news_id, cve_id, source, snippet) VALUES (?,?,?,?) ON CONFLICT DO NOTHING", id, cve, v.source, v.snippet);
  let matches = await matchCves(shown, now());
  if (scope) matches = matches.map((m) => ({ ...m, tenants: m.tenants.filter((t) => t.id === scope) })); // an organization's own news never touches another's data
  // a picture with no CVE in it is not answered (it is usually not about this bot); a picture that could not be read is
  if (!all_.length && kind === "image" && ocrStatus === "ok") {
    await run("UPDATE news_items SET fetch_json = ?, ocr_status = ?, cve_result = ?, reply_status = 'silent', done_at = ? WHERE id = ?", "[]", ocrStatus, "none_found", now(), id);
    return;
  }
  if (all_.length) {
    const status = await deliver(cfg, dests, from, kind, text, matches, { fails, more: all_.length - shown.length });
    // the organizations that were just answered now hold the state we told them: a later change in it is what gets announced
    await matchNews({ cves: shown, tenantIds: scope ? [scope] : undefined, markNotified: status === "sent" }).catch((e) => console.error("[news] match failed", e));
    return void (await run("UPDATE news_items SET fetch_json = ?, ocr_status = ?, cve_result = ?, matches_json = ?, reply_status = ?, done_at = ? WHERE id = ?",
      JSON.stringify(fetched), ocrStatus, result, JSON.stringify(matches.map(({ about: _a, ...m }) => ({ ...m, tenants: m.tenants.map(({ names, chats: _c, ...t }) => ({ ...t, names: names.length })) }))), status, now(), id));
  }
  const answerFor = (dest: string) => { const about = dest === from ? [] : [aboutLine(kind, text)]; return result === "none_found"
    ? notice(MUTED, "ผลการตรวจข่าว", "ไม่พบรหัส CVE ในข้อความ/ข่าวนี้", [...about, ...(fails.length ? [`เปิดลิงก์บางรายการไม่ได้: ${fails.join(", ")}`] : [])])
    : notice(AMBER, "ผลการตรวจข่าว", "ตรวจไม่ได้ จึงยังสรุปไม่ได้ว่ามี CVE หรือไม่", [...about, ...(fails.length ? [`เปิดลิงก์ไม่ได้ (${fails.join(", ")})`] : ocrStatus ? [`อ่านภาพไม่สำเร็จ (${ocrStatus === "unavailable" ? "ยังไม่ได้ติดตั้ง OCR" : ocrStatus})`] : [])]);
  };
  let status = "sent";
  for (const dest of dests) { const r = await sendCard(cfg, dest, answerFor(dest)); if (r !== "sent" && status === "sent") status = r; }
  await run("UPDATE news_items SET fetch_json = ?, ocr_status = ?, cve_result = ?, matches_json = ?, reply_status = ?, done_at = ? WHERE id = ?", JSON.stringify(fetched), ocrStatus, result, "[]", status, now(), id);
}

interface LineEvent { type?: string; webhookEventId?: string; replyToken?: string; source?: { type?: string; userId?: string; groupId?: string; roomId?: string }; message?: { id?: string; type?: string; text?: string } }

/** Returns the work still to do after the 200 has been sent. */
export async function handleEvents(events: LineEvent[], cfg: Cfg): Promise<Promise<void>[]> {
  const work: Promise<void>[] = [];
  for (const ev of events.slice(0, 50)) {
    if (ev.type !== "message" || !ev.message || (ev.message.type !== "text" && ev.message.type !== "image")) continue;
    const key = ev.webhookEventId ?? (ev.message.id ? `m:${ev.message.id}` : "");
    const chat = ev.source?.groupId ?? ev.source?.roomId ?? ev.source?.userId ?? "";
    if (!key || !chat) continue;
    const m = ev.message;
    const kind = m.type as "text" | "image"; // checked above
    const ownHosts = [(() => { try { return new URL(appUrl).host; } catch { return ""; } })(), (() => { try { return cfg.forwardUrl ? new URL(cfg.forwardUrl).host : ""; } catch { return ""; } })()];
    const text = kind === "text" ? withoutOwnLinks(m.text ?? "", ownHosts) : "";
    // This channel may be shared with another system that owns its webhook. Outside the allowed chats the bot says nothing, except
    // the one word that asks for the chat id (needed to allow a chat); the answer names organizations and devices.
    if (!cfg.sources.has(chat)) {
      if (kind === "text" && text.trim().toLowerCase() === "/chatid" && await fresh(key)) work.push(sendCard(cfg, chat, notice(MUTED, "รหัสห้อง", `รหัสห้องนี้: ${chat}`, ["ให้ผู้ดูแลเพิ่มรหัสนี้ที่หน้า การเชื่อมต่อ > LINE bot"])).then(() => {}));
      continue;
    }
    // In an allowed chat, only what is for this bot: a link, a CVE id, or a picture. Ordinary conversation is ignored.
    if (kind === "text" && !urlsIn(text).length && !extractCves(text).length) continue;
    if (!(await fresh(key))) continue; // LINE redelivers; the unique key makes a second delivery, or a retry after a crash, create nothing new
    const id = uuid();
    await run("INSERT INTO news_items (id, received_at, kind, message_id, chat, text, urls_json) VALUES (?,?,?,?,?,?,?)", id, now(), kind, m.id ?? null, chat, kind === "text" ? text.slice(0, 4000) : null, JSON.stringify(kind === "text" ? urlsIn(text) : []));
    work.push((async () => {
      try {
        if (kind === "text") return await analyse(id, cfg, chat, "text", text, undefined, cfg.sources.get(chat) ?? null);
        const img = await hooks.line(cfg.token, "GET", `https://api-data.line.me/v2/bot/message/${encodeURIComponent(m.id ?? "")}/content`);
        if (!img.ok || !img.data) { await run("UPDATE news_items SET ocr_status = 'error', done_at = ? WHERE id = ?", now(), id); return void (await Promise.all((!cfg.sources.get(chat) && cfg.answerChats.length ? cfg.answerChats : [chat]).map((d) => sendCard(cfg, d, notice(RED, "ผลการตรวจข่าว", "ดึงรูปจาก LINE ไม่ได้", ["กรุณาส่งใหม่"]))))); }
        await analyse(id, cfg, chat, "image", "", img.data, cfg.sources.get(chat) ?? null);
      } catch (e) { console.error("[line] analysis failed", e); await run("UPDATE news_items SET reply_status = 'error', done_at = ? WHERE id = ?", now(), id).catch(() => {}); }
    })());
  }
  return work;
}
async function fresh(key: string) {
  return !!(await get<{ event_id: string }>("INSERT INTO line_events (event_id, received_at) VALUES (?, ?) ON CONFLICT DO NOTHING RETURNING event_id", key, now()));
}

// ---------------------------------------------------------------- routes
export const pending = new Set<Promise<void>>(); // lets tests wait for the background work
const track = (w: Promise<void>) => { pending.add(w); void w.catch(() => {}).finally(() => pending.delete(w)); };

// The webhook of this channel may be the front door of another system too. When a forward URL is set, every request whose signature is
// valid is passed on byte for byte (same body, same signature), so the other system verifies it exactly as if LINE had called it.
// shortcut: the retry queue lives in memory, a restart during the 4 seconds of retries loses that delivery; use a table if that ever matters.
export const forwardTuning = { retryMs: [1000, 3000] };
export const forwardState = { at: 0, ok: true, status: 0 }; // what the setup page shows, since a failure here is otherwise silent
async function forward(url: string, raw: Buffer, headers: Record<string, string>) {
  let status = 0;
  for (let i = 0; ; i++) {
    status = await hooks.forward(url, raw, headers);
    if ((status >= 200 && status < 300) || (status >= 300 && status < 500) || i >= forwardTuning.retryMs.length) break; // a refusal does not change on retry
    await new Promise((r) => setTimeout(r, forwardTuning.retryMs[i]));
  }
  forwardState.at = now(); forwardState.status = status; forwardState.ok = status >= 200 && status < 300;
  if (!forwardState.ok) console.error(`[line] forward failed: ${status || "no connection"}`); // never the body, the signature or the URL
}

route("POST", "/api/line/webhook", { auth: "none" }, async (c) => {
  const cfg = await loadCfg();
  const sig = String(c.req.headers["x-line-signature"] ?? "");
  if (!cfg || !verifySignature(c.rawBody, sig, cfg.secret)) throw new HttpError(401, "Invalid signature");
  if (cfg.forwardUrl) {
    const ua = c.req.headers["user-agent"];
    track(forward(cfg.forwardUrl, c.rawBody, { "Content-Type": String(c.req.headers["content-type"] ?? "application/json"), "X-Line-Signature": sig, ...(ua ? { "User-Agent": ua } : {}) }));
  }
  try {
    const events = Array.isArray((c.body as { events?: unknown }).events) ? ((c.body as { events: LineEvent[] }).events) : [];
    for (const w of await handleEvents(events, cfg)) track(w);
  } catch (e) { console.error("[line] handling failed", e); } // our own failure must not change what LINE is told, the other system depends on the 200
  return { ok: true };
});

async function view() {
  const row = await get<{ config_json: string; secret_sealed: string | null; updated_at: number }>("SELECT * FROM integrations WHERE key = 'line'");
  const cfg = row?.secret_sealed ? await loadCfg() : null;
  const recent = await all<{ id: string; received_at: number; kind: string; cve_result: string; reply_status: string | null; done_at: number | null; ocr_status: string | null; n: number }>(
    `SELECT i.id, i.received_at, i.kind, i.cve_result, i.reply_status, i.done_at, i.ocr_status, (SELECT COUNT(*) FROM news_cves c WHERE c.news_id = i.id) AS n FROM news_items i ORDER BY i.received_at DESC LIMIT 20`);
  return {
    configured: !!cfg, hasSecret: !!cfg?.secret, hasToken: !!cfg?.token, allowedChats: cfg?.allowedChats ?? [], answerChats: cfg?.answerChats ?? [], answerChat: cfg?.answerChats[0] ?? "", chatNames: cfg?.chatNames ?? {},
    tenantGroups: (await all<{ tenant_id: string; tenant: string; chat_id: string; name: string | null }>(
      "SELECT l.tenant_id, t.name AS tenant, l.chat_id, l.name FROM line_chats l JOIN tenants t ON t.id = l.tenant_id WHERE l.role = 'destination' ORDER BY l.created_at")).sort((a, b) => nameOrder.compare(a.tenant, b.tenant)).map((t) => ({ tenantId: t.tenant_id, tenant: t.tenant, chat: t.chat_id, name: t.name ?? "" })),
    tenantSources: (await all<{ tenant_id: string; tenant: string; chat_id: string; name: string | null }>(
      "SELECT l.tenant_id, t.name AS tenant, l.chat_id, l.name FROM line_chats l JOIN tenants t ON t.id = l.tenant_id WHERE l.role = 'source' ORDER BY l.created_at")).sort((a, b) => nameOrder.compare(a.tenant, b.tenant)).map((t) => ({ tenantId: t.tenant_id, tenant: t.tenant, chat: t.chat_id, name: t.name ?? "" })),
    webhookUrl: `${appUrl}/api/line/webhook`, forwardUrl: cfg?.forwardUrl ?? "", forward: cfg?.forwardUrl && forwardState.at ? { ...forwardState } : null, recent,
  };
}
route("GET", "/api/integrations/line", ADMIN, async () => view());
route("PUT", "/api/integrations/line", ADMIN, async (c) => {
  const old = await get<{ secret_sealed: string | null; config_json: string }>("SELECT secret_sealed, config_json FROM integrations WHERE key = 'line'");
  const prev = old?.secret_sealed ? (JSON.parse(unseal(old.secret_sealed)) as { secret?: string; token?: string }) : {};
  const secret = (typeof c.body.channelSecret === "string" && c.body.channelSecret.trim()) || prev.secret || "";
  const token = (typeof c.body.channelAccessToken === "string" && c.body.channelAccessToken.trim()) || prev.token || "";
  if (!secret || !token) throw new HttpError(400, "Channel secret and channel access token are required", "missing_secret");
  if (secret.length > 200 || token.length > 500) throw new HttpError(400, "Invalid input");
  const isId = (x: string) => /^[A-Za-z0-9_-]{5,64}$/.test(x);
  const ids = (v: unknown) => [...new Set((v as unknown[]).map((x) => str(x, 64).trim()).filter(Boolean))];
  // The SOC's chats: where its news is read (allowedChats) and where answers go (answerChats; answerChat = one, what older clients send). A list left out stays as it is.
  const soc = async (role: "source" | "destination") => (await all<{ chat_id: string }>("SELECT chat_id FROM line_chats WHERE role = ? AND tenant_id IS NULL ORDER BY created_at", role)).map((r) => r.chat_id);
  const sources = Array.isArray(c.body.allowedChats) ? ids(c.body.allowedChats) : await soc("source");
  const destinations = Array.isArray(c.body.answerChats) ? ids(c.body.answerChats) : typeof c.body.answerChat === "string" ? (c.body.answerChat.trim() ? [c.body.answerChat.trim()] : []) : await soc("destination");
  if (sources.length > 50 || destinations.length > 50 || [...sources, ...destinations].some((x) => !isId(x))) throw new HttpError(400, "Invalid chat id", "invalid_chat");
  // a chat has ONE owner (the SOC or one organization) whatever its role: otherwise one organization's news could be answered into another's group
  for (const id of new Set([...sources, ...destinations]))
    if (await get("SELECT 1 FROM line_chats WHERE chat_id = ? AND tenant_id IS NOT NULL", id)) throw new HttpError(409, "This chat already belongs to an organization", "chat_taken");
  // a name for each chat, so the setup page can say what a chat is ("TENFORWARD SOC", "Customer A"); left out, the saved names stay
  let names: Record<string, string> = Object.fromEntries((await all<{ chat_id: string; name: string | null }>("SELECT chat_id, name FROM line_chats WHERE tenant_id IS NULL AND name IS NOT NULL")).map((r) => [r.chat_id, r.name!]));
  if (c.body.chatNames && typeof c.body.chatNames === "object" && !Array.isArray(c.body.chatNames)) {
    names = {};
    for (const [id, n] of Object.entries(c.body.chatNames as Record<string, unknown>)) {
      if (!isId(id)) throw new HttpError(400, "Invalid chat id", "invalid_chat");
      const name = typeof n === "string" ? n.trim().slice(0, 60) : "";
      if (name) names[id] = name;
    }
    if (Object.keys(names).length > 100) throw new HttpError(400, "Too many names");
  }
  // Left out of the request, the forward URL stays as it is: an older client must not stop another system's messages by saving the form.
  let forwardUrl = old ? ((JSON.parse(old.config_json) as { forwardUrl?: string }).forwardUrl ?? "") : "";
  if (typeof c.body.forwardUrl === "string") {
    forwardUrl = c.body.forwardUrl.trim();
    if (forwardUrl) {
      let u: URL | null = null;
      try { u = new URL(forwardUrl); } catch { /* refused below */ }
      if (!u || forwardUrl.length > 300 || u.protocol !== "https:" || u.username || u.password || u.host === new URL(appUrl).host) throw new HttpError(400, "Invalid forward URL", "invalid_forward");
    }
  }
  await tx(async () => {
    await run(`INSERT INTO integrations (key, config_json, secret_sealed, updated_at, updated_by) VALUES ('line', ?, ?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET config_json = excluded.config_json, secret_sealed = excluded.secret_sealed, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
      JSON.stringify({ forwardUrl }), seal(JSON.stringify({ secret, token })), now(), c.user!.id);
    await migrateChats();
    await run("DELETE FROM line_chats WHERE tenant_id IS NULL");
    for (const id of sources) await run("INSERT INTO line_chats (chat_id, role, tenant_id, name, created_at) VALUES (?, 'source', NULL, ?, ?)", id, names[id] ?? null, now());
    for (const id of destinations) await run("INSERT INTO line_chats (chat_id, role, tenant_id, name, created_at) VALUES (?, 'destination', NULL, ?, ?)", id, names[id] ?? null, now());
  });
  await audit({ actor: c.user, action: "integration.line.update", result: "ok", ip: c.ip });
  return view();
});
route("POST", "/api/integrations/line/test", ADMIN, async (c) => {
  const cfg = await loadCfg();
  if (!cfg) throw new HttpError(400, "Save the connection first", "not_configured");
  const r = await hooks.line(cfg.token, "GET", "https://api.line.me/v2/bot/info");
  await audit({ actor: c.user, action: "integration.line.test", result: r.ok ? "ok" : "fail", ip: c.ip, detail: r.ok ? null : `HTTP ${r.status}` });
  return r.ok ? { ok: true } : { ok: false, status: r.status, reason: r.status === 401 ? "invalid_token" : r.status === 0 ? "unreachable" : "error" };
});

// ---------------------------------------------------------------- per organization: where its news comes from and where its notifications go

async function tenantLine(tenantId: string) {
  const rows = await all<{ chat_id: string; role: string; name: string | null }>("SELECT chat_id, role, name FROM line_chats WHERE tenant_id = ? ORDER BY created_at, chat_id", tenantId);
  const pick = (role: string) => rows.filter((r) => r.role === role).map((r) => ({ chat: r.chat_id, name: r.name ?? "" }));
  return { sources: pick("source"), destinations: pick("destination") };
}
route("GET", "/api/tenants/:id/line", ADMIN, async (c) => {
  const t = await get<{ id: string }>("SELECT id FROM tenants WHERE id = ?", c.params.id);
  if (!t) throw new HttpError(404, "Not found");
  return tenantLine(t.id);
});
/** Replace the organization's chats. sources: news posted there is read for THIS organization only (and answered to its destinations, or in that chat when it has none).
 *  destinations: every one of them receives this organization's answers, and nobody else's. A chat belongs to one organization (or the SOC) per role. */
route("PUT", "/api/tenants/:id/line", ADMIN, async (c) => {
  const t = await get<{ id: string; name: string }>("SELECT id, name FROM tenants WHERE id = ?", c.params.id);
  if (!t) throw new HttpError(404, "Not found");
  const list = (v: unknown) => {
    if (!Array.isArray(v) || v.length > 50) throw new HttpError(400, "Invalid chat list", "invalid_chat");
    const seen = new Set<string>();
    return v.map((x: any) => {
      const chat = str(x?.chat, 64).trim();
      if (!/^[A-Za-z0-9_-]{5,64}$/.test(chat)) throw new HttpError(400, "Invalid chat id", "invalid_chat");
      return { chat, name: typeof x?.name === "string" ? x.name.trim().slice(0, 60) : "" };
    }).filter((x) => !seen.has(x.chat) && !!seen.add(x.chat));
  };
  const old = await tenantLine(t.id);
  const sources = c.body.sources === undefined ? old.sources : list(c.body.sources), destinations = c.body.destinations === undefined ? old.destinations : list(c.body.destinations);
  for (const x of [...sources, ...destinations]) // one owner per chat, whatever its role
    if (await get("SELECT 1 FROM line_chats WHERE chat_id = ? AND (tenant_id IS NULL OR tenant_id <> ?)", x.chat, t.id)) throw new HttpError(409, "This chat already belongs to another organization or to the SOC", "chat_taken");
  await tx(async () => {
    await migrateChats();
    await run("DELETE FROM line_chats WHERE tenant_id = ?", t.id);
    for (const x of sources) await run("INSERT INTO line_chats (chat_id, role, tenant_id, name, created_at) VALUES (?, 'source', ?, ?, ?)", x.chat, t.id, x.name || null, now());
    for (const x of destinations) await run("INSERT INTO line_chats (chat_id, role, tenant_id, name, created_at) VALUES (?, 'destination', ?, ?, ?)", x.chat, t.id, x.name || null, now());
  });
  await audit({ actor: c.user, tenantId: t.id, action: "tenant.line_chat", resource: `${t.name}: ${sources.length} sources, ${destinations.length} destinations`, result: "ok", ip: c.ip });
  return tenantLine(t.id);
});
/** The one-group form older clients use: this group becomes the organization's only destination. */
route("PUT", "/api/tenants/:id/line-chat", ADMIN, async (c) => {
  const chat = typeof c.body.lineChat === "string" ? c.body.lineChat.trim() : "";
  if (chat && !/^[A-Za-z0-9_-]{5,64}$/.test(chat)) throw new HttpError(400, "Invalid chat id", "invalid_chat");
  const t = await get<{ id: string }>("SELECT id FROM tenants WHERE id = ?", c.params.id);
  if (!t) throw new HttpError(404, "Not found");
  if (chat && await get("SELECT 1 FROM line_chats WHERE chat_id = ? AND (tenant_id IS NULL OR tenant_id <> ?)", chat, t.id)) throw new HttpError(409, "This group already belongs to another organization", "chat_taken");
  await tx(async () => {
    await migrateChats();
    await run("DELETE FROM line_chats WHERE tenant_id = ? AND role = 'destination'", t.id);
    if (chat) await run("INSERT INTO line_chats (chat_id, role, tenant_id, name, created_at) VALUES (?, 'destination', ?, NULL, ?)", chat, t.id, now());
  });
  await audit({ actor: c.user, tenantId: t.id, action: "tenant.line_chat", resource: chat ? "1 destination" : "none", result: "ok", ip: c.ip });
  return { lineChat: chat };
});

// ---------------------------------------------------------------- notification settings: preview, test, and the message for a news CVE that changed state
/** A card as the organization's group would get it for its own top CVE with these prefs (invented names when it has no CVE yet). Never touches another organization's data. */
route("POST", "/api/tenants/:id/notify/preview", async (c) => {
  const id = await notifyAccess(c, true);
  const prefs: Prefs = await mergePrefs(id, c.body);
  const top = await get<{ cve_id: string }>(`SELECT r.cve_id FROM roll_cve r JOIN tenant_cids x ON x.cid = r.cid WHERE x.tenant_id = ? AND r.cve_id LIKE 'CVE-%' ORDER BY r.rank, r.hosts DESC, r.cve_id LIMIT 1`, id);
  let row: Row | undefined, sample = false;
  if (top) {
    const m = (await matchCves([top.cve_id]))[0];
    const hit = m.tenants.find((t) => t.id === id);
    if (hit) row = { cve: m.cve, kev: m.kev, about: m.about, link: null, advisory: m.advisory, hit };
  }
  if (!row) {
    sample = true;
    const names: Device[] = Array.from({ length: 25 }, (_, i) => ({ name: `ตัวอย่าง-PC-${String(i + 1).padStart(2, "0")}`, aid: `sample-${i + 1}`, versions: ["1.0"], severity: i < 5 ? "CRITICAL" : "HIGH",
      asset: (i < 2 ? "CRITICAL" : i < 10 ? "HIGH" : i < 18 ? "MEDIUM" : i < 22 ? "LOW" : "UNASSIGNED") as AssetLevel, ...(i === 0 ? { esc: { type: "alert" as const, alertId: "ind:sample", days: prefs.escDays } } : {}) }));
    row = { cve: "CVE-2026-0000", kev: false, link: null, advisory: null,
      about: { announced: true, rejected: false, title: "ตัวอย่างช่องโหว่", description: "ข้อความตัวอย่างสำหรับดูหน้าตาการแจ้งเตือน", cvss: 9.8, cvssSeverity: "CRITICAL", publishedAt: now(), kev: null },
      hit: { id, tenant: "", chats: [], devices: names.length, severity: "CRITICAL", names, fixes: [], console: null, complete: true, state: "affected", asOf: now() } };
  }
  const rows = await applyPrefs(id, [row], prefs, false); // cached evidence only: every change of a setting must not become a Falcon call
  const out = rows.length ? flexMessages("องค์กรของคุณ", rows, {}) : { messages: [], truncated: false };
  return { sample, cve: sample ? null : row.cve, messages: out.messages, dropped: !rows.length, truncated: out.truncated };
});
route("POST", "/api/tenants/:id/notify/test", async (c) => {
  const id = await notifyAccess(c, true);
  const cfg = await loadCfg();
  const chats = (await all<{ chat_id: string }>("SELECT chat_id FROM line_chats WHERE role = 'destination' AND tenant_id = ?", id)).map((r) => r.chat_id);
  if (!cfg || !chats.length) throw new HttpError(400, "LINE is not set up for this organization", "no_line");
  let sent = 0;
  for (const chat of chats) if ((await sendCard(cfg, chat, notice(BLUE, "ทดสอบ", "ข้อความทดสอบการแจ้งเตือน", ["ถ้าเห็นข้อความนี้ แสดงว่ากลุ่มนี้รับการแจ้งเตือนได้"]))) === "sent") sent++;
  await audit({ actor: c.user, tenantId: id, action: "tenant.notify.test", result: sent ? "ok" : "fail", ip: c.ip });
  return { sent };
});

/** A news CVE that has just become exact (or possible) for an organization after the answer was sent: tell its LINE groups once. false = nothing was sent. */
newsHooks.notify = async (tenantId, cve, state, devices) => {
  const cfg = await loadCfg();
  const chats = (await all<{ chat_id: string }>("SELECT chat_id FROM line_chats WHERE role = 'destination' AND tenant_id = ?", tenantId)).map((r) => r.chat_id);
  if (!cfg || !chats.length) return false;
  const prefs = (await loadPrefs(tenantId)) ?? DEFAULT_PREFS;
  let messages: object[], escRows: Row[] = [];
  if (state === "exact") {
    const m = (await matchCves([cve]))[0];
    const hit = m?.tenants.find((t) => t.id === tenantId);
    if (!m || !hit) return false;
    const rows = await applyPrefs(tenantId, [{ cve, kev: m.kev, about: m.about, link: await falconLink(cve, hit.console), advisory: m.advisory, hit } as Row], (await loadPrefs(tenantId)) ?? { ...DEFAULT_PREFS, maxNames: 1000 });
    if (!rows.length) return false;
    messages = flexMessages("องค์กรของคุณ", rows, {}).messages;
    escRows = rows;
  } else {
    if (!prefs.enabled || !prefs.newsPossible) return false;
    messages = [notice(AMBER, "ข่าวช่องโหว่", `${cve} อาจกระทบองค์กรของคุณ`, [`พบซอฟต์แวร์ที่ชื่อตรงกับผลิตภัณฑ์ในข่าว ${devices} เครื่อง (ยังไม่ยืนยันจาก Falcon)`])];
  }
  let ok = true;
  for (const chat of chats) if ((await pushAll(cfg, chat, messages)) !== "sent") ok = false;
  if (ok) await auditEscalations(tenantId, escRows);
  return ok;
};
