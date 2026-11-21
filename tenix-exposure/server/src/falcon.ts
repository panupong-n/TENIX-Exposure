import { allowCustomFalconUrl, appUrl } from "./config.ts";
import { all, audit, get, insertMany, managedTenants, nameOrder, now, run, tx } from "./db.ts";
import { notify } from "./mail.ts";
import { composeCritical, composeSyncFailed } from "./mailkit.ts";
import { createHash } from "node:crypto";
import { seal, unseal, uuid } from "./crypto.ts";
import { str } from "./auth.ts";
import { HttpError, route } from "./http.ts";
import { recordImpact } from "./feeds.ts";
import { refreshRollups, rollupAt, rollupTotals } from "./rollup.ts";
import { keepForCid, keptTotal, purgeDue, retentionView, getRetention, setRetention, severityFilter, SEVERITIES as ALL_SEV, type Severity } from "./retention.ts";
import { warmAfterSync } from "./cache.ts";
import { collectHosts, storeHosts } from "./hosts.ts";
import { recordHistory, refreshSoftware } from "./rollup.ts";

// ---------- read-only client ----------
const ALLOWED = new Set([
  "POST /oauth2/token",
  "GET /spotlight/combined/vulnerabilities/v1",
  "GET /spotlight/entities/remediations/v2",
  "GET /devices/entities/devices/v2",
  "GET /devices/combined/devices/v1",
  "GET /devices/combined/host-groups/v1",
  "GET /alerts/queries/alerts/v2", // alertlevel.ts: is there an alert on this machine (ids only; the entities call is a POST and is not used)
  "GET /spotlight/entities/evaluation-logic/v1",
  "GET /discover/combined/applications/v1",
  "GET /discover/entities/hosts/v1",
  "GET /fem/queries/external-assets/v1",
  "GET /fem/entities/external-assets/v1",
]);
export const hooks = {
  sleep: (ms: number) => new Promise<void>((r) => setTimeout(r, ms)),
  /** Findings per request, tried in this order: if Falcon rejects a size (HTTP 400) the next, smaller one is used. */
  pageSizes: [5000, 1000],
  /** One CID may use this long per run (and the next run continues from the watermark), so a huge tenant cannot keep the others waiting. */
  budgetMs: (Number(process.env.TENIX_FINDINGS_BUDGET_MINUTES) || 20) * 60_000,
  /** The watermark is kept this far behind the newest change read; every write is an upsert, so reading a few rows twice is harmless. */
  marginMs: 5 * 60_000,
  reconcileDays: 7,
  /** The history of closed findings is kept row by row this long (a big tenant closes about half a million a day; the Overview only counts 7 and 30 days). */
  closedKeepDays: 35,
  /** While a run is still unfinished the rollups are rebuilt at most this often (a rebuild reads every row of the CID); a run that has caught up rebuilds them whenever something changed. */
  rollupMinMs: 20 * 60_000,
};

const CLOUD = /^https:\/\/api(\.[a-z0-9-]+)?\.crowdstrike\.com$|^https:\/\/api\.laggar\.gcw\.crowdstrike\.com$/;
export function checkBaseUrl(raw: string): string {
  const url = raw.trim().replace(/\/$/, "");
  if (CLOUD.test(url)) return url;
  if (allowCustomFalconUrl && /^http:\/\/(127\.0\.0\.1|localhost):\d+$/.test(url)) return url;
  throw new HttpError(400, "Base URL must be an official CrowdStrike API cloud, e.g. https://api.us-2.crowdstrike.com", "invalid_base_url");
}

export interface FalconConfig { baseUrl: string; clientId: string; clientSecret: string }
export type ApiResult = { ok: true; data: any } | { ok: false; status: number; message?: string };

export class FalconClient {
  private bearer: string | null = null;
  private cfg: FalconConfig;
  calls = 0;
  /** true when the last login was refused (so a 401/403 on a later request means the credentials, not a missing scope). */
  loginFailed = false;
  constructor(cfg: FalconConfig) { this.cfg = cfg; }

  private async raw(method: string, path: string, params?: Record<string, string | string[] | number>, form?: Record<string, string>): Promise<ApiResult> {
    if (!ALLOWED.has(`${method} ${path}`)) throw new Error(`Blocked: ${method} ${path} is not in the read-only allowlist`);
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(params ?? {})) (Array.isArray(v) ? v : [String(v)]).forEach((x) => q.append(k, x));
    const headers: Record<string, string> = { Accept: "application/json" };
    if (this.bearer) headers.Authorization = `Bearer ${this.bearer}`;
    let body: string | undefined;
    if (form) { body = new URLSearchParams(form).toString(); headers["Content-Type"] = "application/x-www-form-urlencoded"; }
    this.calls++;
    try {
      const r = await fetch(this.cfg.baseUrl + path + (q.size ? `?${q}` : ""), { method, headers, body, signal: AbortSignal.timeout(120_000) });
      if (!r.ok) {
        const ra = Number(r.headers.get("retry-after"));
        // Falcon explains a refusal in the body ("not authorized to use <cid> as cid filter value"); keep it so the reason can be told apart
        const message = await r.json().then((j: any) => (j?.errors ?? []).map((e: any) => String(e?.message ?? "")).filter(Boolean).join("; ").slice(0, 300)).catch(() => "");
        return { ok: false, status: r.status, ...(message ? { message } : {}), ...(ra ? { retryAfter: ra } : {}) } as ApiResult;
      }
      return { ok: true, data: await r.json() };
    } catch { return { ok: false, status: 0 }; }
  }

  private async login(): Promise<ApiResult> {
    this.bearer = null;
    const r = await this.raw("POST", "/oauth2/token", undefined, { client_id: this.cfg.clientId, client_secret: this.cfg.clientSecret });
    if (r.ok) this.bearer = String(r.data?.access_token ?? "") || null;
    this.loginFailed = !r.ok;
    return r.ok && !this.bearer ? { ok: false, status: 502 } : r;
  }
  async testLogin() { return this.login(); }

  /** GET with token refresh on 401 and backoff on 429/5xx/network errors. */
  async get(path: string, params: Record<string, string | string[] | number>): Promise<ApiResult> {
    if (!this.bearer) { const l = await this.login(); if (!l.ok) return l; }
    let refreshed = false;
    for (let attempt = 0; ; attempt++) {
      const r = await this.raw("GET", path, params);
      if (r.ok) return r;
      if (r.status === 401 && !refreshed) { refreshed = true; const l = await this.login(); if (!l.ok) return l; continue; }
      const retryable = r.status === 429 || r.status >= 500 || r.status === 0;
      if (!retryable || attempt >= 3) return r;
      const ra = (r as { retryAfter?: number }).retryAfter;
      await hooks.sleep(Math.min(ra ? ra * 1000 : 1000 * 2 ** attempt, 30_000));
    }
  }
}

// ---------- one CID: exact counts, then a watermark sync of the findings ----------
// Falcon counts every number we show (limit=1, pagination.total). Rows are stored page by page, ordered by updated_timestamp, from a persisted watermark:
// the first run is the same walk starting at the beginning, so an interrupted or time-boxed run resumes where it stopped. EVERY open finding is stored, in two phases:
// A = the fix-first slice (PRIORITY) so KEV / exploited / ExPRT-critical / Critical are usable early, B = the backfill of everything (it re-reads the slice, an upsert changes nothing).
// The state is partial ("held X of Y") until B has seen everything, then complete; from then on one incremental feed over all rows keeps it current.
const SP = "/spotlight/combined/vulnerabilities/v1";
const SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]);
const HOST_CHUNK = 100, REM_CHUNK = 400, CACHE_MAX = 100_000, FRESH_MAX = 5000;
const AID = /^[0-9a-f]{32}$/; // a Falcon sensor device id. External (EASM) assets have longer ids and are not looked up as devices.
const uniq = (v: unknown, max: number): string[] => (Array.isArray(v) ? [...new Set(v.filter((x): x is string => typeof x === "string" && !!x))].slice(0, max) : []);
/** Parentheses and the comma are an OR: without the parentheses the comma binds to the whole expression and returns a different set. `cve.cisa_info.is_cisa_kev` is refused by Falcon as a filter, `cve.is_cisa_kev` works. */
export const PRIORITY = "(cve.severity:'CRITICAL',cve.is_cisa_kev:true,cve.exploit_status:['60','70','80','90'],cve.exprt_rating:'CRITICAL')";
const COUNT_FILTERS: Record<string, string> = {
  critical: "cve.severity:'CRITICAL'", high: "cve.severity:'HIGH'", medium: "cve.severity:'MEDIUM'", low: "cve.severity:'LOW'", kev: "cve.is_cisa_kev:true",
  exprtCritical: "cve.exprt_rating:'CRITICAL'", exprtHigh: "cve.exprt_rating:'HIGH'", exploited: "cve.exploit_status:['60','70','80','90']", slice: PRIORITY,
};
/** The same numbers for sensor findings only (Falcon EASM findings live in the same feed and are not hosts or CVEs), and the three counts that give the exact tiers (design-spec 4.1):
 *  P1 = (KEV or exploited) or (Critical and ExPRT Critical) = kx + c - kxc, P1+P2 = p12 (a flat OR, no nesting), so P2 = p12 - P1 and P3 = s_total - p12.
 *  Every filter has a form Falcon already accepted for the slice or the counts (`a+(b,c)`), so no nested AND/OR is needed. */
const SENSOR = "data_providers.provider:'Falcon sensor'";
const KX = "(cve.is_cisa_kev:true,cve.exploit_status:['60','70','80','90'])", CC = "cve.severity:'CRITICAL'+cve.exprt_rating:'CRITICAL'";
const SENSOR_FILTERS: Record<string, string> = {
  s_total: SENSOR, s_critical: `${SENSOR}+cve.severity:'CRITICAL'`, s_high: `${SENSOR}+cve.severity:'HIGH'`, s_medium: `${SENSOR}+cve.severity:'MEDIUM'`, s_low: `${SENSOR}+cve.severity:'LOW'`,
  s_kev: `${SENSOR}+cve.is_cisa_kev:true`, s_exprtCritical: `${SENSOR}+cve.exprt_rating:'CRITICAL'`, s_exploited: `${SENSOR}+cve.exploit_status:['60','70','80','90']`,
  s_kx: `${SENSOR}+${KX}`, s_c: `${SENSOR}+${CC}`, s_kxc: `${SENSOR}+${CC}+${KX}`,
  s_p12: `${SENSOR}+(cve.is_cisa_kev:true,cve.exploit_status:['30','60','70','80','90'],cve.severity:'CRITICAL',cve.exprt_rating:['HIGH','CRITICAL'])`,
  easm: "data_providers.provider:'Falcon EASM'", suppressed: "suppression_info.is_suppressed:true", s_suppressed: `${SENSOR}+suppression_info.is_suppressed:true`, // Falcon's own tier totals still count suppressed sensor findings: this is how many
};
const iso = (ms: number) => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(".000Z", "Z");

export interface FindingRow {
  cid: string; finding_id: string; aid: string; cve_id: string; severity: string; base_score: number | null; exprt: string | null;
  exploit_status: number | null; hostname: string | null; platform: string | null; local_ip: string | null; external_ip: string | null;
  product: string | null; status: string | null; rem_set: number | null; provider: string | null; kind: string | null;
  vendor: string | null; eval_id: string | null; risk_score: number | null; exploitability: string | null; first_seen: number | null;
  os_version: string | null; internet_exposure: string | null; port: string | null; suppressed: number;
}
/** Public facts about a vulnerability, shared by every tenant (what it is, how bad, where to read more). */
export interface CveInfo {
  id: string; description: string | null; published_at: string | null; vector: string | null; exploitability_score: number | null; impact_score: number | null;
  cwes: string[]; types: string[]; references: string[]; advisories: string[]; cisa_kev: boolean;
}
export type FailReason = "invalid_credentials" | "cid_not_authorized" | "missing_scope" | "unreachable" | "error";
/** missing = what could not be read (makes the run partial or failed). notes = things worth knowing that do not make it partial. fresh = CRITICAL findings stored for the first time after the first pass. */
export interface FindingsRun {
  state: "complete" | "partial" | "failed"; reason: FailReason | null; pages: number; read: number; total: number | null; missing: string[]; notes: string[];
  fresh: { cve_id: string; aid: string }[];
}
export interface Progress { phase: "findings" | "devices" | "remediations" | "saving" | "software" | "hosts"; pages: number; read: number; total: number | null }

const isIp = (s: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s) || s.includes(":");
const cleanName = (v: unknown) => { const s = typeof v === "string" ? v.trim() : ""; return s && !isIp(s) ? s : null; };
/** Falcon writes "Unknown" when it cannot name something; that is the absence of a value. */
const known = (v: string | null) => (v && v !== "Unknown" ? v : null);
const text = (v: unknown, max = 500) => { const t = typeof v === "string" ? v.replace(/\0/g, "") : ""; return t ? t.slice(0, max) : null; }; // Postgres text cannot hold NUL, and Falcon sends it ("Microsoft\u0000")

/** Why Falcon refused, as one word (the same words probeFalcon uses). */
export function failureReason(r: { status: number; message?: string }, loginFailed = false): FailReason {
  if (/not authorized.*cid|only your own cid/i.test(r.message ?? "")) return "cid_not_authorized";
  if (loginFailed && (r.status === 401 || r.status === 403)) return "invalid_credentials";
  if (r.status === 401) return "invalid_credentials";
  if (r.status === 403) return "missing_scope";
  return r.status === 0 ? "unreachable" : "error";
}
const why = (r: { status: number; message?: string }) => `HTTP ${r.status || "network error"}${r.message ? ` (${r.message})` : ""}`;

interface Ctx {
  cid: string; deadline: number; pages: number; read: number; size: number; total: number | null; onProgress: (p: Progress) => void;
  missing: string[]; notes: string[]; changed: number; hosts: Map<string, any>; rem: Map<string, any>; cves: Set<string>; sets: Set<number>; alerts: boolean; fresh: { cve_id: string; aid: string }[];
  skipped: { noAid: string[]; noCve: string[]; foreign: number };
}
interface Cursor { wm: number; started: number; seen: number }
const getCursor = (cid: string, name: string) => get<Cursor>("SELECT wm, started, seen FROM cid_cursor WHERE cid = ? AND name = ?", cid, name);
const putCursor = (cid: string, name: string, c: Cursor) => run(
  "INSERT INTO cid_cursor (cid, name, wm, started, seen) VALUES (?,?,?,?,?) ON CONFLICT (cid, name) DO UPDATE SET wm = excluded.wm, started = excluded.started, seen = excluded.seen", cid, name, c.wm, c.started, c.seen);
const forget = async (cid: string) => { for (const t of ["cid_sync", "cid_cursor", "cid_counts"]) await run(`DELETE FROM ${t} WHERE cid = ?`, cid); };

/** One limit=1 request per number. Only `total` decides whether Falcon answers at all; a number that fails is left out (the older value stays). */
async function countFindings(client: FalconClient, cid: string, missing: string[], notes: string[]) {
  const base = `status:['open','reopen']+cid:'${cid}'`;
  const one = (extra: string) => client.get(SP, { filter: extra ? `${base}+${extra}` : base, limit: 1 });
  const t = await one("");
  if (!t.ok) return { ok: false as const, fail: t };
  const n: Record<string, number> = { total: Number(t.data?.meta?.pagination?.total) || 0 };
  for (const [k, f] of Object.entries({ ...COUNT_FILTERS, ...SENSOR_FILTERS })) {
    const r = await one(f);
    const v = r.ok ? r.data?.meta?.pagination?.total : null;
    if (typeof v === "number") n[k] = v;
    else if (k in SENSOR_FILTERS) notes.push(`count ${k}: ${r.ok ? "no total" : why(r)}`); // the tier and endpoint-only counts are extras: their absence shows "at least" in the UI, it does not make the run partial
    else missing.push(`count ${k}: ${r.ok ? "no total" : why(r)}`);
  }
  return { ok: true as const, n };
}
/** The key of a set of recommended actions: the first 48 bits of md5(json | text) (the same formula as the SQL that moved old rows into rem_sets). */
const remKey = (json: string | null, txt: string) => parseInt(createHash("md5").update(`${json ?? ""}|${txt}`).digest("hex").slice(0, 12), 16);

interface Walk { filter: (wm: number) => string; sort: string; facet?: string[]; wm: number; onPage: (batch: any[]) => Promise<number>; countPages?: boolean }
/** Pages through Falcon's answer. The filter only changes when the cursor is lost: then it starts again from the stored watermark (never from `after`). */
async function walk(client: FalconClient, ctx: Ctx, w: Walk): Promise<{ end: "caught_up" | "budget" | "error" | "stuck"; error?: { status: number; message?: string } }> {
  let wm = w.wm, chainWm = wm, after: string | undefined, resets = 0;
  for (;;) {
    if (now() > ctx.deadline) return { end: "budget" };
    const limit = hooks.pageSizes[ctx.size];
    const r = await client.get(SP, { filter: w.filter(chainWm), limit, sort: w.sort, ...(w.facet ? { facet: w.facet } : {}), ...(after ? { after } : {}) });
    if (!r.ok) {
      if (!ctx.pages && r.status === 400 && ctx.size + 1 < hooks.pageSizes.length) { ctx.notes.push(`Falcon refused ${limit} findings per page; using ${hooks.pageSizes[ctx.size + 1]}`); ctx.size++; continue; }
      if (after && r.status === 400 && resets++ < 3) { after = undefined; chainWm = wm; continue; } // the cursor was forgotten: resume from the watermark
      return { end: "error", error: r };
    }
    if (w.countPages !== false) ctx.pages++;
    const batch: any[] = r.data?.resources ?? [];
    if (!batch.length) return { end: "caught_up" };
    wm = Math.max(wm, await w.onPage(batch));
    const next = r.data?.meta?.pagination?.after || undefined;
    if (next && next !== after) { after = next; continue; }
    if (batch.length < limit) return { end: "caught_up" };
    if (wm <= chainWm) return { end: "stuck" }; // a full page, no cursor and no progress: stop instead of looping
    chainWm = wm; after = undefined;
  }
}

/** Device names and remediation texts for the page only; what was looked up stays in the run's cache. */
async function lookups(client: FalconClient, ctx: Ctx, page: any[]) {
  const aids = [...new Set(page.map((f) => String(f.aid ?? "")).filter((a) => AID.test(a) && !ctx.hosts.has(a)))];
  for (let i = 0; i < aids.length; i += HOST_CHUNK) {
    ctx.onProgress({ phase: "devices", pages: ctx.pages, read: ctx.read, total: ctx.total });
    const r = await client.get("/devices/entities/devices/v2", { ids: aids.slice(i, i + HOST_CHUNK) });
    if (r.ok) for (const h of r.data?.resources ?? []) ctx.hosts.set(h.device_id, h);
    else if (r.status !== 404) { const m = `host lookup: ${why(r)}; names come from the finding`; if (!ctx.notes.includes(m)) ctx.notes.push(m); break; }
    for (const a of aids.slice(i, i + HOST_CHUNK)) if (!ctx.hosts.has(a)) ctx.hosts.set(a, {}); // asked once: no second request for a device Falcon does not know
  }
  for (const f of page) for (const e of f.remediation?.entities ?? []) if (e.id) ctx.rem.set(e.id, e);
  const need = [...new Set(page.flatMap((f) => [...(f.remediation?.ids ?? [])]).filter((i): i is string => !!i && !ctx.rem.has(i)))];
  for (let i = 0; i < need.length; i += REM_CHUNK) {
    ctx.onProgress({ phase: "remediations", pages: ctx.pages, read: ctx.read, total: ctx.total });
    const r = await client.get("/spotlight/entities/remediations/v2", { ids: need.slice(i, i + REM_CHUNK) });
    if (r.ok) for (const e of r.data?.resources ?? []) ctx.rem.set(e.id, e);
    else { const m = `remediation lookup: ${why(r)}`; if (!ctx.notes.includes(m)) ctx.notes.push(m); break; }
  }
  if (ctx.hosts.size > CACHE_MAX) ctx.hosts.clear();
  if (ctx.rem.size > CACHE_MAX) ctx.rem.clear();
}

function toRows(ctx: Ctx, page: any[]) {
  const seen = new Set<string>();
  const rows: FindingRow[] = [];
  const cves = new Map<string, CveInfo>();
  const sets = new Map<number, [string, string | null]>();
  const cid = ctx.cid;
  for (const f of page) {
    if (f.cid !== cid) { ctx.skipped.foreign++; continue; }
    const aid = String(f.aid ?? "");
    const cve = f.cve ?? {};
    // an empty cve.id is normal for misconfigurations: they carry CrowdStrike's own id (CS-C24-...) in vulnerability_id
    const cveId = String(cve.id || f.vulnerability_id || "");
    if (!aid || aid.length > 200) { ctx.skipped.noAid.push(String(f.id ?? "?")); continue; }
    if (!cveId) { ctx.skipped.noCve.push(String(f.id ?? "?")); continue; }
    const product = text(f.apps?.[0]?.product_name_version, 200);
    const id = String(f.id ?? `${aid}:${cveId}:${product ?? ""}`);
    if (seen.has(id)) continue;
    seen.add(id);
    const dev = ctx.hosts.get(aid) ?? {};
    const hi = f.host_info ?? {};
    const external = /EASM/i.test(String(f.data_providers?.[0]?.provider ?? ""));
    const sev = String(cve.severity ?? "NONE").toUpperCase();
    const ids = [...(f.remediation?.ids ?? []), ...(f.remediation?.entities ?? []).map((e: any) => e.id)];
    const found = [...new Set(ids)].map((i) => ctx.rem.get(i)).filter(Boolean);
    const actions = found.map((e: any) => `- ${e.action || e.title || e.reference || e.id}`).slice(0, 8);
    // each recommended action with where to read about it (Microsoft's update catalogue for a KB, a vendor page) and whether Falcon calls it the recommended or the minimum fix
    const httpsOnly = (u: unknown) => (typeof u === "string" && /^https:\/\//i.test(u) && u.length <= 500 ? u : null);
    const detail = found.slice(0, 8)
      .map((e: any) => ({ action: String(e.action || e.title || e.reference || e.id).slice(0, 300), link: httpsOnly(e.link) ?? httpsOnly(e.vendor_url), type: typeof e.recommendation_type === "string" ? e.recommendation_type.slice(0, 20) : null }));
    let remSet: number | null = null;
    if (actions.length) {
      const body = actions.join("\n"), json = detail.length ? JSON.stringify(detail) : null;
      remSet = remKey(json, body);
      if (!ctx.sets.has(remSet)) sets.set(remSet, [body, json]);
    }
    if (!ctx.cves.has(cveId) && !cves.has(cveId) && (cve.description || cve.types)) {
      cves.set(cveId, {
        id: cveId, description: text(cve.description, 4000), published_at: text(cve.published_date, 30), vector: text(cve.vector, 100),
        exploitability_score: typeof cve.exploitability_score === "number" ? cve.exploitability_score : null,
        impact_score: typeof cve.impact_score === "number" ? cve.impact_score : null,
        cwes: uniq(cve.cwes, 10), types: uniq(cve.types, 5), references: uniq(cve.references, 10), advisories: uniq(cve.vendor_advisory, 5), cisa_kev: !!cve.cisa_info?.is_cisa_kev,
      });
    }
    rows.push({
      cid, finding_id: id, aid, cve_id: cveId, provider: text(f.data_providers?.[0]?.provider, 40), kind: text(cve.types?.[0], 40), severity: SEVERITIES.has(sev) ? sev : "NONE",
      base_score: typeof cve.base_score === "number" ? cve.base_score : null, exprt: text(cve.exprt_rating, 20),
      exploit_status: typeof cve.exploit_status === "number" ? cve.exploit_status : null,
      // An internet-facing (EASM) asset is often known only by its address, so there the IP is the name. For a sensor device a name that is just an IP is not a real name.
      hostname: cleanName(dev.hostname) ?? cleanName(hi.hostname) ?? (external ? text(hi.hostname, 253) : null),
      platform: text(dev.platform_name ?? hi.platform, 40) ?? (external ? "External asset" : null),
      local_ip: text(dev.local_ip ?? hi.local_ip, 45),
      external_ip: text(dev.external_ip ?? hi.external_ip, 45) ?? (external && isIp(String(hi.hostname ?? "")) ? text(hi.hostname, 45) : null),
      product, status: text(f.status, 20), rem_set: remSet,
      vendor: known(text(f.apps?.[0]?.vendor_normalized, 80)), eval_id: text(f.apps?.[0]?.evaluation_logic?.id, 64),
      risk_score: Number.isInteger(f.risk_score) ? f.risk_score : null, exploitability: text(f.exploitability, 30),
      first_seen: Date.parse(f.created_timestamp) || null, os_version: text(hi.os_version, 80), internet_exposure: text(hi.internet_exposure, 10),
      port: f.services?.length ? uniq(f.services.map((x: any) => `${x.port}/${x.protocol}`), 6).join(", ") : null, suppressed: f.suppression_info?.is_suppressed === true ? 1 : 0,
    });
  }
  return { rows, cves: [...cves.values()], sets };
}

const FINDING_COLS = ["cid", "finding_id", "aid", "cve_id", "severity", "base_score", "exprt", "exploit_status", "hostname", "platform", "local_ip", "external_ip", "product", "status", "rem_set", "synced_at", "provider", "kind", "vendor", "eval_id", "risk_score", "exploitability", "first_seen", "os_version", "internet_exposure", "port", "suppressed"];
const CVE_COLS = ["id", "description", "published_at", "vector", "exploitability_score", "impact_score", "cwes", "types", "references_json", "advisories_json", "cisa_kev", "updated_at"];
const UPSERT = `ON CONFLICT (cid, finding_id) DO UPDATE SET ${FINDING_COLS.slice(2).map((k) => `${k} = excluded.${k}`).join(", ")}`;

/** One page: look up names, write the rows in one short transaction (an upsert, so a repeated page changes nothing), then move the watermark. Returns the new watermark. */
async function ingest(client: FalconClient, ctx: Ctx, cur: Cursor, name: string, batch: any[]): Promise<number> {
  await lookups(client, ctx, batch);
  const { rows, cves, sets } = toRows(ctx, batch);
  const t = now();
  const done = await tx(async () => {
    await insertMany("rem_sets", ["id", "remediation", "remediation_json"], [...sets].map(([id, [body, json]]) => [id, body, json]), "ON CONFLICT DO NOTHING");
    const out = await insertMany<{ finding_id: string; inserted: boolean }>("findings_t", FINDING_COLS,
      rows.map((x) => [x.cid, x.finding_id, x.aid, x.cve_id, x.severity, x.base_score, x.exprt, x.exploit_status, x.hostname, x.platform, x.local_ip, x.external_ip, x.product, x.status, x.rem_set, t, x.provider, x.kind, x.vendor, x.eval_id, x.risk_score, x.exploitability, x.first_seen, x.os_version, x.internet_exposure, x.port, x.suppressed]),
      UPSERT, "finding_id, (xmax = 0) AS inserted");
    await insertMany("cves", CVE_COLS, cves.map((v) => [v.id, v.description, v.published_at, v.vector, v.exploitability_score, v.impact_score, JSON.stringify(v.cwes), JSON.stringify(v.types), JSON.stringify(v.references), JSON.stringify(v.advisories), v.cisa_kev ? 1 : 0, t]),
      `ON CONFLICT (id) DO UPDATE SET ${CVE_COLS.slice(1).map((k) => (k === "cisa_kev" ? "cisa_kev = GREATEST(cves.cisa_kev, excluded.cisa_kev)" : `${k} = excluded.${k}`)).join(", ")}`); // the KEV list (feeds.ts) may know more than this Falcon read
    return out;
  });
  for (const v of cves) ctx.cves.add(v.id);
  for (const id of sets.keys()) ctx.sets.add(id);
  if (ctx.sets.size > CACHE_MAX) ctx.sets.clear();
  if (ctx.alerts && ctx.fresh.length < FRESH_MAX) {
    const added = new Set(done.filter((x) => x.inserted).map((x) => x.finding_id));
    for (const x of rows) if (x.severity === "CRITICAL" && added.has(x.finding_id) && ctx.fresh.length < FRESH_MAX) ctx.fresh.push({ cve_id: x.cve_id, aid: x.aid });
  }
  let maxTs = 0;
  for (const f of batch) { const u = Date.parse(f.updated_timestamp); if (u > maxTs) maxTs = u; }
  cur.wm = Math.max(cur.wm, maxTs ? maxTs - hooks.marginMs : 0);
  cur.seen += batch.length;
  await putCursor(ctx.cid, name, cur);
  ctx.read += batch.length;
  ctx.changed += rows.length;
  ctx.onProgress({ phase: "findings", pages: ctx.pages, read: ctx.read, total: ctx.total });
  return cur.wm;
}

/** Findings Falcon has closed or let expire since the watermark: the ones we hold are written to finding_closed (with Falcon's time) and removed. Run before the feed of changes, so a finding that was closed and reopened comes back.
 *  `closed` rows carry closed_timestamp; an `expired` row has none (api-inventory section 4), so that feed walks updated_timestamp: an expired finding is treated exactly like a closed one. */
async function applyClosures(client: FalconClient, ctx: Ctx, status: "closed" | "expired" = "closed") {
  const field = status === "closed" ? "closed_timestamp" : "updated_timestamp";
  let cur = await getCursor(ctx.cid, status);
  if (!cur) { cur = { wm: now() - hooks.marginMs, started: now(), seen: 0 }; await putCursor(ctx.cid, status, cur); } // an older database has no expired cursor: start now, the reconcile removes what was missed
  const w: Walk = {
    filter: (wm) => `status:'${status}'+cid:'${ctx.cid}'+${field}:>'${iso(wm)}'`, sort: `${field}|asc`, wm: cur.wm, countPages: false,
    onPage: async (batch) => {
      const mine = batch.filter((f) => f.cid === ctx.cid && f.id);
      const ids = mine.map((f) => String(f.id)), ts = mine.map((f) => Date.parse(f[field]) || now());
      await tx(async () => {
        await run(`INSERT INTO finding_closed (cid, finding_id, aid, cve_id, severity, hostname, provider, closed_at)
                   SELECT f.cid, f.finding_id, f.aid, f.cve_id, f.severity, f.hostname, f.provider, c.ts FROM findings_t f JOIN unnest(?::text[], ?::bigint[]) AS c(id, ts) ON c.id = f.finding_id WHERE f.cid = ?
                   ON CONFLICT DO NOTHING`, ids as any, ts as any, ctx.cid);
        ctx.changed += (await get<{ n: number }>("WITH d AS (DELETE FROM findings_t WHERE cid = ? AND finding_id = ANY(?::text[]) RETURNING 1) SELECT COUNT(*) n FROM d", ctx.cid, ids as any))!.n;
      });
      let maxTs = 0;
      for (const t of ts) maxTs = Math.max(maxTs, t);
      cur.wm = Math.max(cur.wm, maxTs - hooks.marginMs);
      await putCursor(ctx.cid, status, cur);
      return cur.wm;
    },
  };
  const r = await walk(client, ctx, w);
  if (status === "closed") await run("DELETE FROM finding_closed WHERE cid = ? AND closed_at < ?", ctx.cid, now() - hooks.closedKeepDays * 86400_000);
  return r;
}

/** A pass over the whole scope is over: what it did not see is gone from Falcon's set (expired, or no longer in the slice). Only trusted when the pass saw nearly everything Falcon counts. */
async function finishScan(cid: string, name: string, expected: number | null, ctx: Ctx, keep: readonly string[]): Promise<boolean> {
  const cur = (await getCursor(cid, name))!;
  if (expected === null || cur.seen < Math.floor(expected * 0.95)) {
    ctx.missing.push(`pass read ${cur.seen} of about ${expected ?? "?"} findings; nothing was removed, it starts again`);
    await run("DELETE FROM cid_cursor WHERE cid = ? AND name = ?", cid, name);
    return false;
  }
  const gone = (await get<{ n: number }>("WITH d AS (DELETE FROM findings_t WHERE cid = ? AND synced_at < ? AND severity = ANY(?::text[]) RETURNING 1) SELECT COUNT(*) n FROM d", cid, cur.started, keep as any))!.n; // only the kept severities: the others wait for their purge date
  if (gone) { ctx.notes.push(`${gone} findings no longer in Falcon's set were removed`); ctx.changed += gone; }
  await run("DELETE FROM cid_cursor WHERE cid = ? AND name = ?", cid, name);
  return true;
}

/** Exact counts from Falcon and a watermark sync of one CID. Never removes data on a failure; stores what it read page by page, so memory stays at one page. */
export async function syncFindings(client: FalconClient, cid: string, onProgress: (p: Progress) => void = () => {}): Promise<FindingsRun> {
  const t0 = now();
  const ctx: Ctx = { cid, deadline: t0 + hooks.budgetMs, pages: 0, read: 0, size: 0, total: null, onProgress, missing: [], notes: [], changed: 0, hosts: new Map(), rem: new Map(), cves: new Set(), sets: new Set(), alerts: false, fresh: [],
    skipped: { noAid: [], noCve: [], foreign: 0 } };
  const finish = async (state: FindingsRun["state"], reason: FailReason | null, advance: boolean): Promise<FindingsRun> => {
    const missing = [...new Set(ctx.missing)];
    await tx(async () => {
      await run(`INSERT INTO cid_status (cid, state, reason, detail_json, notes_json, data_as_of, last_run_at) VALUES (?,?,?,?,?,?,?)
                 ON CONFLICT (cid) DO UPDATE SET state = excluded.state, reason = excluded.reason, detail_json = excluded.detail_json, notes_json = excluded.notes_json,
                   data_as_of = COALESCE(excluded.data_as_of, cid_status.data_as_of), last_run_at = excluded.last_run_at`,
        cid, state, reason, JSON.stringify(missing), JSON.stringify(ctx.notes), advance ? now() : null, now());
      await run('INSERT INTO sync_runs (cid, started_at, finished_at, state, pages, "read", total, detail_json) VALUES (?,?,?,?,?,?,?,?)',
        cid, t0, now(), state, ctx.pages, ctx.read, ctx.total, JSON.stringify([...missing, ...ctx.notes]));
    });
    warmAfterSync(cid);
    return { state, reason, pages: ctx.pages, read: ctx.read, total: ctx.total, missing, notes: ctx.notes, fresh: ctx.fresh };
  };

  if (!(await get("SELECT 1 FROM cid_status WHERE cid = ?", cid))) await forget(cid); // data of a removed connection must not leave a stale watermark behind
  const counted = await countFindings(client, cid, ctx.missing, ctx.notes);
  if (!counted.ok) {
    ctx.missing.push(`Falcon refused: ${why(counted.fail)}`);
    return finish("failed", failureReason(counted.fail, client.loginFailed), false); // what is stored stays as it was
  }
  const n = counted.n;
  for (const [k, v] of Object.entries(n)) await run("INSERT INTO cid_counts (cid, key, n, as_of) VALUES (?,?,?,?) ON CONFLICT (cid, key) DO UPDATE SET n = excluded.n, as_of = excluded.as_of", cid, k, v, now());

  // Every open finding is stored. Phase A (the fix-first slice) and phase B (everything) are two cursors over Falcon's answer; a first run creates both.
  let sy = await get<{ slice_done_at: number | null; first_done_at: number | null; last_scan_done_at: number | null; recon_gap: number | null }>("SELECT slice_done_at, first_done_at, last_scan_done_at, recon_gap FROM cid_sync WHERE cid = ?", cid);
  // the severities this organization stores; Falcon still counts all of them (cid_counts), so the overview totals stay true
  const keep = await keepForCid(cid);
  const sevFilter = severityFilter(keep);
  const expected = keptTotal(n, keep) ?? n.total;
  await run("INSERT INTO cid_counts (cid, key, n, as_of) VALUES (?,'keptTotal',?,?) ON CONFLICT (cid, key) DO UPDATE SET n = excluded.n, as_of = excluded.as_of", cid, expected, now());
  if (!sy) {
    await tx(async () => {
      await run("INSERT INTO cid_sync (cid) VALUES (?) ON CONFLICT (cid) DO UPDATE SET slice_done_at = NULL, first_done_at = NULL, last_scan_done_at = NULL, recon_gap = NULL", cid);
      await run("DELETE FROM cid_cursor WHERE cid = ?", cid);
      await putCursor(cid, "slice", { wm: 0, started: t0, seen: 0 });
      await putCursor(cid, "inc", { wm: 0, started: t0, seen: 0 });
      await putCursor(cid, "closed", { wm: t0 - hooks.marginMs, started: t0, seen: 0 });
    });
    sy = { slice_done_at: null, first_done_at: null, last_scan_done_at: null, recon_gap: null };
  }
  // until everything is stored, and while a re-ticked severity is collected again, what arrives is a baseline: no urgent item for a CVE that was simply not read yet
  const catchingUp = !!(await get("SELECT 1 FROM cid_cursor WHERE cid = ? AND name LIKE 'add:%' LIMIT 1", cid));
  await run("UPDATE cid_sync SET scope = ? WHERE cid = ?", keep.length < ALL_SEV.length ? "priority" : "all", cid);
  const baseline = !sy.first_done_at;
  ctx.alerts = !!sy.slice_done_at; // every CRITICAL finding is in phase A, so a new CRITICAL one after it is really new
  let failed: { status: number; message?: string } | null = null;
  let caughtUp = false;

  ctx.deadline = now() + hooks.budgetMs; // the time budget is for reading findings: the ~25 count requests and their bookkeeping come first and do not eat into it
  const closed = await applyClosures(client, ctx);
  if (closed.end === "error") { ctx.missing.push(`closed findings feed: ${why(closed.error!)}`); failed = closed.error!; }
  else if (closed.end === "stuck") ctx.missing.push("closed findings feed did not advance");
  { // expired = closed for us (Falcon stops listing the finding; without this its rows stay until the weekly reconcile)
    const expired = await applyClosures(client, ctx, "expired");
    if (expired.end === "error") ctx.missing.push(`expired findings feed: ${why(expired.error!)}`); // the run is partial, but the findings feed below still runs
    else if (expired.end === "stuck") ctx.missing.push("expired findings feed did not advance");
  }

  const cur: Record<string, Cursor> = {};
  for (const name of ["slice", "inc"]) { const c = await getCursor(cid, name); if (c) cur[name] = c; }
  let statusWritten = false;
  const firstStatus = async () => { // the first stored page makes the data visible (as partial) before the run ends
    if (statusWritten) return; statusWritten = true;
    await run(`INSERT INTO cid_status (cid, state, detail_json, notes_json, data_as_of, last_run_at) VALUES (?, 'partial', '[]', '[]', ?, ?) ON CONFLICT (cid) DO NOTHING`, cid, now(), now());
  };
  const base = `status:['open','reopen']+cid:'${cid}'`;
  const feed = (name: string, extra = ""): Walk => ({ // one walk for phase A, phase B, the incremental feed and a reconcile scan
    filter: (wm) => `${base}${extra}${wm ? `+updated_timestamp:>'${iso(wm)}'` : ""}`, sort: "updated_timestamp|asc", facet: ["cve", "host_info", "remediation"], wm: cur[name].wm,
    onPage: async (batch) => { const w = await ingest(client, ctx, cur[name], name, batch); await firstStatus(); return w; },
  });
  const step = async (name: string, extra: string, label: string) => {
    ctx.total = name === "slice" ? (n.slice ?? null) : expected;
    const r = await walk(client, ctx, feed(name, extra));
    if (r.end === "error") { ctx.missing.push(`${label} page ${ctx.pages + 1}: ${why(r.error!)}`); failed = r.error!; }
    else if (r.end === "stuck") ctx.missing.push(`${label} did not advance`);
    else if (r.end === "budget") ctx.notes.push(`time budget reached after ${ctx.read.toLocaleString("en-US")} findings; the next run continues from the watermark`);
    return r.end === "caught_up";
  };

  if (!failed) {
    if (!sy.first_done_at) {
      // phase A: the fix-first slice. It keeps running (cheaply) during phase B so the slice stays current while the backfill goes on.
      if (await step("slice", `+${PRIORITY}${sevFilter}`, "fix-first slice")) {
        if (!sy.slice_done_at) { await run("UPDATE cid_sync SET slice_done_at = ? WHERE cid = ?", now(), cid); sy.slice_done_at = now(); }
        // phase B: everything else. The walk is the incremental feed over all rows, started from the beginning.
        if (await step("inc", sevFilter, "backfill")) {
          if (await finishScan(cid, "inc", expected, ctx, keep)) {
            await run("UPDATE cid_sync SET first_done_at = ?, last_scan_done_at = ? WHERE cid = ?", now(), now(), cid);
            await run("DELETE FROM cid_cursor WHERE cid = ? AND name = 'slice'", cid);
            await putCursor(cid, "inc", { ...cur.inc, seen: 0, started: now() });
            sy.first_done_at = now(); sy.last_scan_done_at = now(); sy.recon_gap = null;
            caughtUp = true;
          } else await putCursor(cid, "inc", { wm: 0, started: now(), seen: 0 }); // the pass did not see enough: it is repeated
        }
      }
    } else caughtUp = await step("inc", sevFilter, "findings");
  }
  // a severity that was ticked again: catch up on it (from the beginning when its rows were purged); the data is partial until that is done
  let rebuilding = 0;
  if (!failed && (!baseline || caughtUp)) {
    ctx.alerts = false; // a severity that comes back is not news
    for (const row of await all<{ name: string }>("SELECT name FROM cid_cursor WHERE cid = ? AND name LIKE 'add:%' ORDER BY name", cid)) {
      const sev = row.name.slice(4) as Severity;
      if (!(ALL_SEV as readonly string[]).includes(sev) || !keep.includes(sev)) { await run("DELETE FROM cid_cursor WHERE cid = ? AND name = ?", cid, row.name); continue; }
      cur[row.name] = (await getCursor(cid, row.name))!;
      if (!(await step(row.name, severityFilter([sev]), `catch-up of ${sev}`))) rebuilding++;
      else await run("DELETE FROM cid_cursor WHERE cid = ? AND name = ?", cid, row.name);
      if (failed) break;
    }
  }
  // reconcile: a periodic or divergence-triggered re-scan over all rows removes findings Falcon no longer lists (expired) and finds the ones whose change did not move updated_timestamp
  if (caughtUp && !baseline && !failed) {
    let scan = await getCursor(cid, "scan");
    if (!scan) {
      const have = (await get<{ n: number }>("SELECT COUNT(*) n FROM findings_t WHERE cid = ?", cid))!.n;
      const gap = have - expected;
      const since = now() - (sy.last_scan_done_at ?? 0);
      const diverged = sy.recon_gap !== null && Math.abs(gap - sy.recon_gap) > Math.max(50, 0.01 * expected) && since > 86400_000;
      if (since > hooks.reconcileDays * 86400_000 || diverged) { scan = { wm: 0, started: now(), seen: 0 }; await putCursor(cid, "scan", scan); ctx.notes.push(diverged ? "reconcile started: stored and Falcon counts drifted apart" : "reconcile started: periodic re-scan"); }
    }
    if (scan) {
      cur.scan = scan;
      if (await step("scan", sevFilter, "reconcile") && (await finishScan(cid, "scan", expected, ctx, keep))) await run("UPDATE cid_sync SET last_scan_done_at = ?, recon_gap = NULL WHERE cid = ?", now(), cid);
    }
  }

  await run("UPDATE cves SET cisa_kev = 1 WHERE cisa_kev = 0 AND id IN (SELECT cve_id FROM kev)");
  // what every customer page reads: rebuilt when rows changed (an unfinished run at most every rollupMinMs: a rebuild reads all the rows of the CID)
  const lastRoll = await rollupAt(cid);
  const h = lastRoll === null || (ctx.changed > 0 && (caughtUp || now() - lastRoll >= hooks.rollupMinMs)) ? await refreshRollups(cid, keep) : await rollupTotals(cid, keep);
  const gapNow = h.held - expected;
  await run("UPDATE cid_sync SET recon_gap = COALESCE(recon_gap, ?) WHERE cid = ? AND first_done_at IS NOT NULL", gapNow, cid);
  for (const [k, v] of [["held", h.held], ["priorityHeld", h.priority]] as const) await run("INSERT INTO cid_counts (cid, key, n, as_of) VALUES (?,?,?,?) ON CONFLICT (cid, key) DO UPDATE SET n = excluded.n, as_of = excluded.as_of", cid, k, v, now());
  const sev = n.critical + n.high + n.medium + n.low;
  if (["critical", "high", "medium", "low"].every((k) => typeof n[k] === "number")) // exact numbers from Falcon, whatever part of the rows is stored so far
    await run(`INSERT INTO snapshots (cid, ts, critical, high, medium, low, "none", hosts, cves) VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT (cid, ts) DO UPDATE SET critical = excluded.critical, high = excluded.high, medium = excluded.medium, low = excluded.low, "none" = excluded."none", hosts = excluded.hosts, cves = excluded.cves`,
      cid, now(), n.critical, n.high, n.medium, n.low, Math.max(0, n.total - sev), h.hosts, h.cves);
  await recordHistory(cid).catch((e) => console.error("[history] could not write the daily row:", (e as Error).message)); // the exact counts changed every run, the rollups only sometimes
  await recordImpact(cid, baseline || catchingUp);

  const o = ctx.skipped;
  const sample = (xs: string[]) => xs.slice(0, 3).map((x) => x.slice(0, 40)).join(", ");
  if (o.noAid.length) ctx.notes.push(`${o.noAid.length} findings skipped: no device ID (e.g. ${sample(o.noAid)})`);
  if (o.noCve.length) ctx.notes.push(`${o.noCve.length} findings skipped: no CVE or vulnerability ID (e.g. ${sample(o.noCve)})`);
  if (o.foreign) ctx.missing.push(`${o.foreign} rows for another CID were ignored`);
  if (!sy.first_done_at) ctx.notes.push(`${sy.slice_done_at ? "backfill" : "fix-first slice"}: ${h.held.toLocaleString("en-US")} of ${expected.toLocaleString("en-US")} findings stored; the next run continues`);

  const reason = failed ? failureReason(failed, client.loginFailed) : null;
  if (failed && !ctx.read && !h.held) return finish("failed", reason, false); // Falcon answered the counts but no page: nothing new, nothing stored
  if (rebuilding) ctx.notes.push(`${rebuilding} re-ticked severit${rebuilding > 1 ? "ies are" : "y is"} being collected again`);
  const complete = !failed && caughtUp && !rebuilding && !!sy.first_done_at && closed.end !== "stuck" && !ctx.missing.length;
  return finish(complete ? "complete" : "partial", complete ? null : reason, caughtUp || ctx.read > 0); // "data as of" moves only when something was stored or the feed is up to date
}

/** Alert e-mails for one finished CID. What goes in the text is deliberately limited to what that tenant may see. */
async function announce(cid: string, r: FindingsRun, prevState: string | undefined) {
  const t = await get<{ id: string; name: string }>("SELECT t.id, t.name FROM tenant_cids x JOIN tenants t ON t.id = x.tenant_id WHERE x.cid = ?", cid);
  if (!t) return;
  // a first pass that is still running is not a problem; a failure, or a run that stopped on an error, is (once per change of state)
  if ((r.state === "failed" || (r.state === "partial" && r.reason)) && prevState !== r.state) await notify("sync_failed", t.id, composeSyncFailed({ organization: t.name, state: r.state, link: appUrl }));
  if (r.fresh.length) {
    await notify("critical_new", t.id, composeCritical({ organization: t.name, cves: [...new Set(r.fresh.map((x) => x.cve_id))], devices: new Set(r.fresh.map((x) => x.aid)).size, link: appUrl }));
  }
}

/** What is stored versus what Falcon counts, for the CIDs of one organization. null when a CID has not been read by this engine yet. Exact counts are summed over the CIDs. */
export async function loadCoverage(cids: string[]) {
  const none = { coverage: null, falconCounts: null };
  if (!cids.length) return none;
  const ph = `(${cids.map(() => "?").join(",")})`;
  const counts = new Map<string, number>(); // key -> sum
  const have = new Map<string, Set<string>>(); // key -> cids that have it
  for (const r of await all<{ cid: string; key: string; n: number }>(`SELECT cid, key, n FROM cid_counts WHERE cid IN ${ph}`, ...cids)) {
    counts.set(r.key, (counts.get(r.key) ?? 0) + r.n);
    have.set(r.key, (have.get(r.key) ?? new Set()).add(r.cid));
  }
  const all_ = (k: string) => have.get(k)?.size === cids.length;
  const sy = await all<{ slice_done_at: number | null; first_done_at: number | null }>(`SELECT slice_done_at, first_done_at FROM cid_sync WHERE cid IN ${ph}`, ...cids);
  const tenant = await get<{ tenant_id: string }>("SELECT tenant_id FROM tenant_cids WHERE cid = ?", cids[0]);
  const scope = tenant ? (await getRetention(tenant.tenant_id)).keep : [...ALL_SEV];
  const falconCounts = ["total", "critical", "high", "medium", "low", "kev", "exprtCritical", "exploited"].every(all_)
    ? { total: counts.get("total")!, critical: counts.get("critical")!, high: counts.get("high")!, medium: counts.get("medium")!, low: counts.get("low")!, kev: counts.get("kev")!, exprtCritical: counts.get("exprtCritical")!, exploited: counts.get("exploited")! } : null;
  const coverage = sy.length === cids.length && all_("held")
    ? { held: counts.get("held")!, falconTotal: all_("total") ? counts.get("total")! : null, priorityHeld: counts.get("priorityHeld") ?? 0, priorityTotal: all_("slice") ? counts.get("slice")! : null,
      priorityPass: sy.every((s) => !!s.slice_done_at), fullPass: sy.every((s) => !!s.first_done_at),
      scope: scope.length >= ALL_SEV.length ? ("all" as const) : scope, keptTotal: all_("keptTotal") ? counts.get("keptTotal")! : null } : null;
  return { coverage, falconCounts };
}

// ---------- testing a login, and moving the old shared login onto the organization it can read ----------
export type ProbeResult =
  | { ok: true; step: "login" | "read"; findings?: number | null }
  | { ok: false; step: "login" | "read"; reason: "invalid_credentials" | "unreachable" | "cid_not_authorized" | "missing_scope" | "error"; status: number; message?: string };

/** Log in and, when a CID is given, read one finding of it: tells a wrong secret from a CID this client may not read from a missing "Spotlight: Read" scope. */
export async function probeFalcon(cfg: FalconConfig, cid: string | null): Promise<ProbeResult> {
  const client = new FalconClient(cfg);
  const login = await client.testLogin();
  if (!login.ok) return { ok: false, step: "login", reason: login.status === 401 || login.status === 403 ? "invalid_credentials" : login.status === 0 ? "unreachable" : "error", status: login.status, message: login.message };
  if (!cid) return { ok: true, step: "login" };
  const r = await client.get("/spotlight/combined/vulnerabilities/v1", { filter: `cid:'${cid}'`, limit: 1 });
  if (!r.ok) {
    const notYours = /not authorized.*cid|only your own cid/i.test(r.message ?? ""); // Falcon says so in the body
    return { ok: false, step: "read", reason: notYours ? "cid_not_authorized" : r.status === 403 ? "missing_scope" : r.status === 0 ? "unreachable" : "error", status: r.status, message: r.message };
  }
  const total = r.data?.meta?.pagination?.total;
  return { ok: true, step: "read", findings: typeof total === "number" ? total : null };
}

/** The shared login saved before organizations had their own: give it to each CID it can actually read (probed), never to one it cannot. */
export async function convertSharedLogin(tenantId?: string): Promise<{ cid: string; tenantId: string; ok: boolean; reason?: string }[]> {
  const cfg = await loadConfig();
  if (!cfg) return [];
  const rows = await all<{ cid: string; tenant_id: string }>(
    `SELECT x.cid, x.tenant_id FROM tenant_cids x WHERE NOT EXISTS (SELECT 1 FROM falcon_connections f WHERE f.cid = x.cid)${tenantId ? " AND x.tenant_id = ?" : ""} ORDER BY x.cid`, ...(tenantId ? [tenantId] : []));
  const out: { cid: string; tenantId: string; ok: boolean; reason?: string }[] = [];
  for (const r of rows) {
    const p = await probeFalcon(cfg, r.cid);
    if (p.ok) {
      await run("INSERT INTO falcon_connections (id, tenant_id, name, base_url, client_id, secret_sealed, cid, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING",
        uuid(), r.tenant_id, null, cfg.baseUrl, cfg.clientId, seal(cfg.clientSecret), r.cid, now(), now());
      await audit({ actor: null, tenantId: r.tenant_id, action: "tenant.falcon.convert", resource: r.cid, result: "ok", ip: null });
    }
    out.push({ cid: r.cid, tenantId: r.tenant_id, ok: p.ok, ...(p.ok ? {} : { reason: p.reason }) });
  }
  return out;
}

/** Once, at start: organizations created before connections existed keep working when the old login can read them. The rest wait for their own login. */
export async function migrateSharedLogin() {
  if (await get("SELECT 1 FROM feed_state WHERE key = 'falcon_shared_converted'")) return;
  const res = await convertSharedLogin();
  if (res.every((r) => r.ok || r.reason === "cid_not_authorized")) // a network error is not an answer: try again at the next start
    await run("INSERT INTO feed_state (key, info_json) VALUES ('falcon_shared_converted', ?) ON CONFLICT DO NOTHING", JSON.stringify({ converted: res.filter((r) => r.ok).length, refused: res.filter((r) => !r.ok).length }));
}

// ---------- configuration and orchestration ----------
export async function loadConfig(): Promise<FalconConfig | null> {
  const row = await get<{ config_json: string; secret_sealed: string | null }>("SELECT config_json, secret_sealed FROM integrations WHERE key = 'falcon'");
  if (!row?.secret_sealed) return null;
  const cfg = JSON.parse(row.config_json) as { baseUrl: string; clientId: string };
  return { baseUrl: cfg.baseUrl, clientId: cfg.clientId, clientSecret: unseal(row.secret_sealed) };
}

// ---------- software inventory (Falcon Discover) ----------
export interface SoftwareRow {
  cid: string; id: string; host_id: string; type: string; name: string; vendor: string; version: string; category: string | null; first_seen: number | null;
  updated_at: number | null; suspicious: number; threat: string | null; latest: string | null; host_app: string | null; enabled: number | null; link: string | null;
}
export interface SoftwareHost { cid: string; host_id: string; aid: string | null; hostname: string | null; platform: string | null; os_version: string | null }
export interface SoftwareResult { state: "complete" | "partial" | "failed"; rows: SoftwareRow[]; hosts: SoftwareHost[]; read: number; total: number | null; missing: string[]; notes: string[] }
export const MAX_SOFTWARE = 150_000;

/** Every application, package and extension Falcon Discover has seen on the CID's hosts. A failure here never touches the vulnerability data. */
export async function collectSoftware(client: FalconClient, cid: string): Promise<SoftwareResult> {
  const missing: string[] = [], notes: string[] = [];
  const rows: SoftwareRow[] = [];
  let after: string | undefined, total: number | null = null, read = 0, pages = 0, unnamed = 0;
  while (read < MAX_SOFTWARE) {
    const r = await client.get("/discover/combined/applications/v1", { limit: 1000, ...(after ? { after } : {}) });
    if (!r.ok) { missing.push(`software page ${pages + 1}: HTTP ${r.status || "network error"}${r.status === 403 ? " (Falcon Discover read permission is missing)" : ""}`); break; }
    pages++;
    const batch: any[] = r.data?.resources ?? [];
    total = r.data?.meta?.pagination?.total ?? total;
    for (const a of batch) {
      read++;
      if (a.cid !== cid) continue;
      const name = text(a.name, 200);
      const hostId = text(a.host?.id, 200);
      if (!name || !hostId) { unnamed++; continue; }
      rows.push({
        cid, id: String(a.id), host_id: hostId, type: text(a.software_type, 30) ?? "application", name, vendor: text(a.vendor, 120) ?? "", version: text(a.version, 80) ?? "",
        category: text(a.category, 60), first_seen: Date.parse(a.first_seen_timestamp) || null, updated_at: Date.parse(a.last_updated_timestamp) || null,
        suspicious: a.is_suspicious ? 1 : 0, threat: text(a.threat_level, 40), latest: text(a.registry_latest_version_available, 80),
        host_app: text(a.host_application, 80), enabled: typeof a.browser_extension?.enabled === "boolean" ? (a.browser_extension.enabled ? 1 : 0) : null,
        link: typeof a.store_listing === "string" && /^https?:\/\//i.test(a.store_listing) ? a.store_listing.slice(0, 300) : null,
      });
    }
    const next = r.data?.meta?.pagination?.after || undefined;
    if (!batch.length || !next || next === after) break;
    after = next;
  }
  if (read >= MAX_SOFTWARE) missing.push(`stopped at the safety limit of ${MAX_SOFTWARE.toLocaleString("en-US")} entries`);
  else if (!missing.length && total !== null && read < total) missing.push(`read ${read} of ${total} entries`);
  if (unnamed) notes.push(`${unnamed} entries skipped: Falcon has no name for them`);

  // which device each entry sits on (Discover's own host id -> the Falcon device id used everywhere else)
  const hosts: SoftwareHost[] = [];
  const ids = [...new Set(rows.map((x) => x.host_id))];
  for (let i = 0; i < ids.length; i += 100) {
    const r = await client.get("/discover/entities/hosts/v1", { ids: ids.slice(i, i + 100) });
    if (!r.ok) { missing.push(`device lookup: HTTP ${r.status || "network error"}`); break; }
    for (const h of r.data?.resources ?? []) hosts.push({ cid, host_id: String(h.id), aid: text(h.aid, 200), hostname: cleanName(h.hostname), platform: text(h.platform_name, 40), os_version: text(h.os_version, 80) });
  }
  return { state: !pages ? "failed" : missing.length ? "partial" : "complete", rows, hosts, read, total, missing, notes };
}

/** Replaces the CID's inventory when the run is complete or there was nothing before; an incomplete run never overwrites a complete one. */
export async function storeSoftware(cid: string, r: SoftwareResult): Promise<void> {
  const prev = await get<{ as_of: number | null }>("SELECT as_of FROM software_sync WHERE cid = ?", cid);
  const replace = r.state === "complete" || (r.state === "partial" && !prev?.as_of);
  await tx(async () => {
    if (replace) {
      await run("DELETE FROM software WHERE cid = ?", cid);
      await run("DELETE FROM software_hosts WHERE cid = ?", cid);
      await insertMany("software", ["cid", "id", "host_id", "type", "name", "vendor", "version", "category", "first_seen", "updated_at", "suspicious", "threat", "latest", "host_app", "enabled", "link"],
        r.rows.map((x) => [x.cid, x.id, x.host_id, x.type, x.name, x.vendor, x.version, x.category, x.first_seen, x.updated_at, x.suspicious, x.threat, x.latest, x.host_app, x.enabled, x.link]), "ON CONFLICT DO NOTHING");
      await insertMany("software_hosts", ["cid", "host_id", "aid", "hostname", "platform", "os_version"], r.hosts.map((h) => [h.cid, h.host_id, h.aid, h.hostname, h.platform, h.os_version]), "ON CONFLICT DO NOTHING");
    }
    await run(`INSERT INTO software_sync (cid, state, read, total, detail_json, as_of, last_run_at) VALUES (?,?,?,?,?,?,?)
               ON CONFLICT (cid) DO UPDATE SET state = excluded.state, read = excluded.read, total = excluded.total, detail_json = excluded.detail_json, as_of = excluded.as_of, last_run_at = excluded.last_run_at`,
      cid, r.state, r.read, r.total, JSON.stringify([...r.missing, ...r.notes]), replace ? now() : (prev?.as_of ?? null), now());
  });
}

// ---------- how Falcon detected a finding (read on demand, never stored) ----------
export interface SoftwareFact { installed: string | null; path: string | null; fixedIn: string | null }
const afterColon = (xs: unknown, key: string) => {
  const hit = (Array.isArray(xs) ? xs : []).find((x) => typeof x === "string" && x.startsWith(`${key}: `)) as string | undefined;
  return hit ? hit.slice(key.length + 2, key.length + 202) : null;
};
/** Evaluation logic of one finding -> the installed version, where the software was found, and the first fixed version. */
export function parseLogic(e: any): SoftwareFact {
  const steps: any[] = Array.isArray(e?.simplified_logic) ? e.simplified_logic : [];
  const step = steps.find((x) => Array.isArray(x?.found) && x.found.length) ?? steps[0];
  const fixed = /(?:less than|is below|before)\s+([^\s)]+)/i.exec(String(step?.checks ?? step?.title ?? ""));
  return { installed: afterColon(step?.found, "version"), path: afterColon(step?.data, "filepath") ?? afterColon(step?.data, "path"), fixedIn: fixed ? fixed[1].slice(0, 80) : null };
}
let live: { key: string; client: FalconClient } | null = null;
/** One request per 100 ids. Returns null when Falcon is not set up or unreachable: callers must say "unavailable", not "none". */
export async function lookupSoftware(cid: string, evalIds: string[]): Promise<Map<string, SoftwareFact> | null> {
  const cfg = await configFor(cid);
  if (!cfg) return null;
  const key = `${cfg.baseUrl}|${cfg.clientId}|${cfg.clientSecret}`;
  if (live?.key !== key) live = { key, client: new FalconClient(cfg) };
  const out = new Map<string, SoftwareFact>();
  for (let i = 0; i < evalIds.length; i += 100) {
    const r = await live.client.get("/spotlight/entities/evaluation-logic/v1", { ids: evalIds.slice(i, i + 100) });
    if (!r.ok) return null;
    for (const e of r.data?.resources ?? []) if (e?.id) out.set(String(e.id), parseLogic(e));
  }
  return out;
}

export interface SyncProgress extends Progress { cid: string; organization: string | null; index: number; count: number }
export const syncState = { running: false, startedAt: 0, current: null as string | null, progress: null as SyncProgress | null };

// ---------- external attack surface (Falcon EASM: internet-facing IP addresses and domains) ----------
export interface ExternalAsset {
  cid: string; id: string; asset_type: string; dns_type: string | null; perimeter: string | null; review: string; criticality: string | null; status: string | null;
  internet_exposure: string | null; ip: string | null; fqdn: string | null; cloud: string | null; isp: string | null; discovered_by: string | null; first_seen: number | null; last_seen: number | null;
  country?: string | null; city?: string | null; region?: string | null; asn?: number | null; ptr?: string | null; discovery_json?: string | null; services?: ExternalService[];
}
/** One service Falcon EASM saw on an internet-facing IP, with the TLS certificate it presented. */
export interface ExternalService {
  svc: string; port: number | null; transport: string | null; protocol: string | null; status: string | null; status_code: number | null; os: string | null; first_seen: number | null; last_seen: number | null; apps_json: string | null;
  tls_version: string | null; cert_issuer: string | null; cert_subject: string | null; cert_from: number | null; cert_to: number | null; cert_sig: string | null; cert_fingerprint: string | null;
}
export interface ExternalResult { state: "complete" | "partial" | "failed"; rows: ExternalAsset[]; read: number; total: number | null; missing: string[] }
export const MAX_EXTERNAL = 50_000;
const EXT_PAGE = 100;

/** Every external asset the API client can see (all its CIDs): the list is read once per login and grouped by CID. */
export async function collectExternalAll(client: FalconClient): Promise<Map<string, ExternalResult>> {
  const missing: string[] = [];
  const ids: string[] = [];
  let offset = 0, total: number | null = null, pages = 0;
  while (ids.length < MAX_EXTERNAL) {
    const q = await client.get("/fem/queries/external-assets/v1", { limit: EXT_PAGE, offset });
    if (!q.ok) { missing.push(`asset list page ${pages + 1}: HTTP ${q.status || "network error"}${q.status === 403 ? " (the API client needs the Falcon Exposure Management external assets read scope)" : ""}`); break; }
    pages++;
    const batch: string[] = q.data?.resources ?? [];
    total = q.data?.meta?.pagination?.total ?? total;
    ids.push(...batch);
    offset += EXT_PAGE;
    if (!batch.length || (total !== null && offset >= total)) break;
  }
  const out = new Map<string, ExternalResult>();
  const ms = (v: unknown) => { const t = typeof v === "string" ? Date.parse(v) : NaN; return Number.isFinite(t) ? t : null; };
  let read = 0;
  for (let i = 0; i < ids.length; i += EXT_PAGE) {
    const e = await client.get("/fem/entities/external-assets/v1", { ids: ids.slice(i, i + EXT_PAGE) });
    if (!e.ok) { missing.push(`asset details: HTTP ${e.status || "network error"}`); break; }
    for (const a of e.data?.resources ?? []) {
      const cid = String(a.cid ?? "");
      if (!/^[0-9a-f]{32}$/i.test(cid) || !a.id) continue;
      read++;
      const r = out.get(cid.toLowerCase()) ?? { state: "complete" as const, rows: [], read: 0, total: null, missing };
      r.rows.push({
        cid: cid.toLowerCase(), id: String(a.id), asset_type: text(a.asset_type, 20) ?? "unknown", dns_type: text(a.dns_domain?.type, 20), perimeter: text(a.perimeter, 20),
        review: String(a.triage?.status ?? "").slice(0, 30), criticality: text(a.criticality, 30), status: text(a.status, 20), internet_exposure: text(a.internet_exposure, 10),
        ip: text(a.ip?.ip_address, 45), fqdn: text(a.dns_domain?.fqdn, 253), cloud: text(a.ip?.cloud_provider, 30), isp: text(a.ip?.isp, 80), discovered_by: text(a.discovered_by, 20),
        first_seen: ms(a.first_seen), last_seen: ms(a.last_seen),
        country: text(a.ip?.location?.country_code, 4), city: text(a.ip?.location?.city, 80), region: text(a.ip?.location?.region_name, 80),
        asn: Number.isFinite(Number(a.ip?.asn)) && a.ip?.asn !== null && a.ip?.asn !== "" ? Number(a.ip.asn) : null, ptr: text(a.ip?.ptr, 253),
        discovery_json: Array.isArray(a.discovery?.path?.steps) ? JSON.stringify(a.discovery.path.steps.slice(0, 20).map((x: any) => ({ entity: text(x?.entity, 253), type: text(x?.entity_type, 20), clue: text(x?.clue, 200) }))) : null,
        services: (Array.isArray(a.ip?.services) ? a.ip.services : []).slice(0, 200).map((v: any): ExternalService => {
          const cert = v?.tls?.certificate;
          const name = (o: any) => text(o?.common_name ?? o?.organization_name, 200);
          return {
            svc: text(v?.id, 80) ?? `${v?.port}/${v?.transport}`, port: Number.isInteger(v?.port) ? v.port : null, transport: text(v?.transport, 10), protocol: text(v?.protocol, 30), status: text(v?.status, 20),
            status_code: Number.isInteger(v?.status_code) ? v.status_code : null, os: text(v?.os ?? v?.platform_name, 80), first_seen: ms(v?.first_seen), last_seen: ms(v?.last_seen),
            apps_json: Array.isArray(v?.applications) && v.applications.length ? JSON.stringify(v.applications.slice(0, 10).map((x: any) => ({ vendor: text(x?.vendor, 60), name: text(x?.name, 80), category: text(x?.category, 40), version: text(x?.version, 40), cpe: text(x?.cpe, 120) }))) : null,
            tls_version: text(v?.tls?.version, 20), cert_issuer: name(cert?.issuer), cert_subject: name(cert?.subject), cert_from: ms(cert?.valid_from), cert_to: ms(cert?.valid_to), cert_sig: text(cert?.signature_algorithm, 60), cert_fingerprint: text(cert?.fingerprint_sha256, 120),
          };
        }),
      });
      out.set(cid.toLowerCase(), r);
    }
  }
  const incomplete = missing.length > 0 || (total !== null && read < total) || ids.length >= MAX_EXTERNAL;
  if (incomplete && !missing.length) missing.push(ids.length >= MAX_EXTERNAL ? `stopped at the safety limit of ${MAX_EXTERNAL.toLocaleString("en-US")} assets` : `read ${read} of ${total} assets`);
  for (const r of out.values()) { r.read = r.rows.length; r.total = r.rows.length; r.state = incomplete ? "partial" : "complete"; r.missing = missing; }
  if (!pages && !out.size) out.set("", { state: "failed", rows: [], read: 0, total, missing });
  return out;
}

export async function storeExternal(cid: string, r: ExternalResult): Promise<void> {
  const prev = await get<{ as_of: number | null }>("SELECT as_of FROM external_sync WHERE cid = ?", cid);
  const replace = r.state === "complete" || (r.state === "partial" && !prev?.as_of); // an incomplete read never replaces a complete one
  await tx(async () => {
    if (replace) {
      await run("DELETE FROM external_assets WHERE cid = ?", cid);
      await insertMany("external_assets", ["cid", "id", "asset_type", "dns_type", "perimeter", "review", "criticality", "status", "internet_exposure", "ip", "fqdn", "cloud", "isp", "discovered_by", "first_seen", "last_seen", "country", "city", "region", "asn", "ptr", "discovery_json"],
        r.rows.map((x) => [x.cid, x.id, x.asset_type, x.dns_type, x.perimeter, x.review, x.criticality, x.status, x.internet_exposure, x.ip, x.fqdn, x.cloud, x.isp, x.discovered_by, x.first_seen, x.last_seen,
          x.country ?? null, x.city ?? null, x.region ?? null, x.asn ?? null, x.ptr ?? null, x.discovery_json ?? null]), "ON CONFLICT (cid, id) DO NOTHING");
      await run("DELETE FROM external_services WHERE cid = ?", cid);
      await insertMany("external_services", ["cid", "asset_id", "svc", "port", "transport", "protocol", "status", "status_code", "os", "first_seen", "last_seen", "apps_json", "tls_version", "cert_issuer", "cert_subject", "cert_from", "cert_to", "cert_sig", "cert_fingerprint"],
        r.rows.flatMap((x) => (x.services ?? []).map((v) => [x.cid, x.id, v.svc, v.port, v.transport, v.protocol, v.status, v.status_code, v.os, v.first_seen, v.last_seen, v.apps_json, v.tls_version, v.cert_issuer, v.cert_subject, v.cert_from, v.cert_to, v.cert_sig, v.cert_fingerprint])),
        "ON CONFLICT (cid, asset_id, svc) DO NOTHING");
    }
    await run(`INSERT INTO external_sync (cid, state, read, total, detail_json, as_of, last_run_at) VALUES (?,?,?,?,?,?,?)
               ON CONFLICT (cid) DO UPDATE SET state = excluded.state, read = excluded.read, total = excluded.total, detail_json = excluded.detail_json, as_of = excluded.as_of, last_run_at = excluded.last_run_at`,
      cid, r.state, r.read, r.total, JSON.stringify(r.missing), replace ? now() : (prev?.as_of ?? null), now());
  });
}

/** The login for one CID: its own connection, set on the organization. There is no fallback: a CID without a connection is not read (the shared login can only see the CID it was created in). */
export async function configFor(cid: string): Promise<FalconConfig | null> {
  const r = await get<{ base_url: string; client_id: string; secret_sealed: string }>("SELECT base_url, client_id, secret_sealed FROM falcon_connections WHERE cid = ?", cid);
  return r ? { baseUrl: r.base_url, clientId: r.client_id, clientSecret: unseal(r.secret_sealed) } : null;
}

/** A round runs every CID once, the finished ones first (their incremental takes seconds), then each unfinished one for at most hooks.budgetMs. While a CID still has backfill to do the next round
 *  starts at once, so a 17-million-row tenant is not left waiting for the hourly tick; a round that stored nothing ends the loop (an error is retried at the next tick). */
export const MAX_ROUNDS = 200;
export async function syncCids(cids: string[]): Promise<{ started: boolean; reason?: string }> {
  if (syncState.running) return { started: false, reason: "running" };
  let jobs: { cid: string; cfg: FalconConfig }[] = [];
  for (const cid of cids) { const cfg = await configFor(cid); if (cfg) jobs.push({ cid, cfg }); } // a CID with no login at all is skipped, not allowed to stop the others
  if (!jobs.length) return { started: false, reason: "not_configured" };
  syncState.running = true;
  syncState.startedAt = now();
  void (async () => {
    try {
      const clients = new Map<string, FalconClient>(); // organizations that share one API client share its login
      const externals = new Map<string, Map<string, ExternalResult>>(); // and the external-asset list read with it
      for (let round = 0; round < MAX_ROUNDS; round++) {
        const done = new Set((await all<{ cid: string }>("SELECT cid FROM cid_sync WHERE first_done_at IS NOT NULL")).map((r) => r.cid));
        jobs = [...jobs.filter((j) => done.has(j.cid)), ...jobs.filter((j) => !done.has(j.cid))];
        const again: typeof jobs = [];
        let stored = 0;
        for (const [index, job] of jobs.entries()) {
          const { cid, cfg } = job;
          const key = `${cfg.baseUrl}|${cfg.clientId}`;
          if (!clients.has(key)) clients.set(key, new FalconClient(cfg));
          const client = clients.get(key)!;
          syncState.current = cid;
          const organization = (await get<{ name: string }>("SELECT t.name FROM tenant_cids x JOIN tenants t ON t.id = x.tenant_id WHERE x.cid = ?", cid))?.name ?? null;
          const report = (p: Progress) => { syncState.progress = { ...p, cid, organization, index: index + 1, count: jobs.length }; };
          report({ phase: "findings", pages: 0, read: 0, total: null });
          const prevState = (await get<{ state: string }>("SELECT state FROM cid_status WHERE cid = ?", cid))?.state;
          let r: FindingsRun;
          try { r = await syncFindings(client, cid, report); } catch (e) {
            console.error("[findings] sync failed:", (e as Error).message);
            r = { state: "failed", reason: "error", pages: 0, read: 0, total: null, missing: [`unexpected error: ${(e as Error).message}`], notes: [], fresh: [] };
            await run(`INSERT INTO cid_status (cid, state, reason, detail_json, notes_json, last_run_at) VALUES (?, 'failed', 'error', ?, '[]', ?)
                       ON CONFLICT (cid) DO UPDATE SET state = 'failed', reason = 'error', detail_json = excluded.detail_json, last_run_at = excluded.last_run_at`, cid, JSON.stringify(r.missing), now());
          }
          await announce(cid, r, prevState);
          stored += r.read;
          if (r.state === "partial" && !r.reason) again.push(job); // not an error, only not finished: it continues in the next round
          if (r.state === "failed" || round > 0) continue; // a refused login would only be refused again by software and external; later rounds only continue the findings
          // the device inventory (hosts, groups, tags, last seen): hourly, after the findings; a failure keeps the old inventory and never touches the vulnerability data
          try { report({ phase: "hosts", pages: 0, read: 0, total: null }); await storeHosts(cid, await collectHosts(client, cid)); } catch (e) { console.error("[hosts] sync failed:", (e as Error).message); }
          try { report({ phase: "software", pages: 0, read: 0, total: null }); await storeSoftware(cid, await collectSoftware(client, cid)); await refreshSoftware(cid); } catch (e) { console.error("[software] sync failed:", (e as Error).message); }
          // the external attack surface: one read of the client's whole list per login, shared by every CID it covers; never touches the vulnerability data
          try {
            if (!externals.has(key)) externals.set(key, await collectExternalAll(client));
            const all_ = externals.get(key)!;
            await storeExternal(cid, all_.get(cid) ?? { state: all_.has("") ? "failed" : "complete", rows: [], read: 0, total: 0, missing: all_.get("")?.missing ?? [] });
          } catch (e) { console.error("[external] sync failed:", (e as Error).message); }
        }
        if (!again.length || !stored) break;
        jobs = jobs.filter((j) => again.includes(j) || done.has(j.cid)); // finished CIDs go on with their incremental in every round
      }
    } finally { syncState.running = false; syncState.current = null; syncState.progress = null; }
  })();
  return { started: true };
}
export const allMappedCids = async () => (await all<{ cid: string }>("SELECT cid FROM tenant_cids ORDER BY cid")).map((r) => r.cid);

let timer: NodeJS.Timeout | null = null;
/** Every tick: delete what retention says may go, then sync. A start also continues a first pass that a restart interrupted (the watermarks are in the database). */
const tick = async () => {
  try { await purgeDue(); } catch (e) { console.error("[retention] purge failed:", (e as Error).message); }
  await syncCids(await allMappedCids());
};
export function startScheduler(minutes: number) {
  if (timer || minutes <= 0) return;
  timer = setInterval(() => { void tick(); }, minutes * 60_000);
  timer.unref();
  // A connected CID with no cid_sync row yet (first start after an upgrade) must not wait a whole interval.
  const resume = setTimeout(() => { void (async () => { if (await get("SELECT 1 FROM falcon_connections c LEFT JOIN cid_sync y ON y.cid = c.cid WHERE y.first_done_at IS NULL LIMIT 1")) await tick(); })().catch(() => {}); }, 15_000);
  resume.unref();
}

// ---------- routes (soc_admin only) ----------
const ADMIN = { roles: ["super_admin" as const] };
route("GET", "/api/integrations/falcon", ADMIN, async () => ({
  sync: { running: syncState.running, startedAt: syncState.startedAt || null, progress: syncState.progress },
  cids: await Promise.all((await all(`SELECT s.cid, s.state, s.reason, s.detail_json, s.notes_json, s.data_as_of, s.last_run_at, t.name AS tenant_name,
      COALESCE((SELECT n FROM cid_counts k WHERE k.cid = s.cid AND k.key = 'held'), (SELECT COUNT(*) FROM findings_t f WHERE f.cid = s.cid)) AS findings,
      (SELECT r.finished_at - r.started_at FROM sync_runs r WHERE r.cid = s.cid AND r.finished_at IS NOT NULL ORDER BY r.id DESC LIMIT 1) AS duration_ms
      FROM cid_status s LEFT JOIN tenant_cids x ON x.cid = s.cid LEFT JOIN tenants t ON t.id = x.tenant_id`))
    .sort((a: any, b: any) => nameOrder.compare(a.tenant_name ?? "", b.tenant_name ?? "") || String(a.cid).localeCompare(String(b.cid)))
    .map(async (r: any) => ({ ...r, ...(await loadCoverage([r.cid])), detail: JSON.parse(r.detail_json), notes: JSON.parse(r.notes_json), detail_json: undefined, notes_json: undefined }))),
  runs: await all('SELECT id, cid, started_at, finished_at, state, pages, "read", total FROM sync_runs ORDER BY id DESC LIMIT 20'),
}));

/** The Falcon console of the same cloud as the API: api.us-2.crowdstrike.com -> falcon.us-2.crowdstrike.com (null for anything else, e.g. a local mock). */
export function consoleRoot(baseUrl: string): string | null {
  try { const u = new URL(baseUrl); return u.protocol === "https:" && /^api\./.test(u.hostname) ? `https://falcon.${u.hostname.slice(4)}/` : null; } catch { return null; }
}
/** Where a CVE is shown in Falcon: Spotlight's page for that vulnerability id, opened on its Remediations tab (the owner's own example link, with the CVE in it). */
const CVE_PAGE = "spotlight/vulnerabilities/group-by/vulnerability-id/instances/{cve}?activeDetailTab=Remediations&activeTab=overview&filter=";
/** The link behind the "see more" button: Spotlight's page for the CVE in the Falcon cloud of the organization's connection (`baseUrl`).
 *  null when there is no https Falcon cloud to point at (a local mock). */
export async function falconLink(cve: string, baseUrl?: string | null): Promise<string | null> {
  const cloud = baseUrl ?? (await get<{ base_url: string }>("SELECT base_url FROM falcon_connections ORDER BY created_at LIMIT 1"))?.base_url; // a message for the SOC chat has no organization: any connection's cloud
  const root = consoleRoot(cloud ?? "");
  return root ? `${root}${CVE_PAGE.replaceAll("{cve}", encodeURIComponent(cve))}` : null;
}

route("POST", "/api/integrations/falcon/sync", ADMIN, async (c) => {
  const tenantId = typeof c.body.tenantId === "string" ? c.body.tenantId : null;
  const cids = tenantId ? (await all<{ cid: string }>("SELECT cid FROM tenant_cids WHERE tenant_id = ?", tenantId)).map((r) => r.cid) : await allMappedCids();
  if (!cids.length) throw new HttpError(400, "No CIDs are mapped yet", "no_cids");
  const res = await syncCids(cids);
  await audit({ actor: c.user, tenantId, action: "integration.falcon.sync", resource: `${cids.length} CIDs`, result: res.started ? "ok" : "fail", ip: c.ip, detail: res.reason ?? null });
  if (!res.started) throw new HttpError(res.reason === "running" ? 409 : 400, res.reason === "running" ? "A sync is already running" : "Save the connection first", res.reason);
  return { started: true };
});

// ---------- which severities an organization stores (super admin, or an admin of that organization) ----------
const TENANT_ADMIN = { manager: true };
async function retentionFor(c: import("./http.ts").Ctx) {
  const id = c.params.id;
  const m = managedTenants(c.user!);
  if (m !== "all" && !m.has(id)) throw new HttpError(404, "Not found"); // another organization's settings look like a missing page
  if (!(await get("SELECT 1 FROM tenants WHERE id = ?", id))) throw new HttpError(404, "Not found");
  return id;
}
const retentionAnswer = async (id: string) => {
  const cids = (await all<{ cid: string }>("SELECT cid FROM tenant_cids WHERE tenant_id = ?", id)).map((r) => r.cid);
  return { ...(await retentionView(id)), coverage: (await loadCoverage(cids)).coverage };
};
route("GET", "/api/tenants/:id/retention", TENANT_ADMIN, async (c) => retentionAnswer(await retentionFor(c)));
route("PUT", "/api/tenants/:id/retention", TENANT_ADMIN, async (c) => {
  const id = await retentionFor(c);
  const keep = c.body.keep;
  if (!Array.isArray(keep) || !keep.every((x) => typeof x === "string" && (ALL_SEV as readonly string[]).includes(x))) throw new HttpError(400, "keep must be a list of CRITICAL, HIGH, MEDIUM, LOW, NONE", "invalid_severity");
  if (!keep.length) throw new HttpError(400, "Keep at least one severity", "keep_empty");
  const { added } = await setRetention(id, [...new Set(keep as Severity[])], c.user, c.ip);
  if (added.length) void syncCids((await all<{ cid: string }>("SELECT cid FROM tenant_cids WHERE tenant_id = ?", id)).map((r) => r.cid)); // start catching up now (skipped when a sync is already running: the next round does it)
  return retentionAnswer(id);
});
