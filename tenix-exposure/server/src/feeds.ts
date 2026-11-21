// Public vulnerability facts, kept once for every organization: the CVE Program records (cvelistV5) and CISA's Known Exploited Vulnerabilities list.
// Nothing here is tenant data. What an organization is affected by comes from its own Falcon findings (falcon.ts) and is joined on the CVE id.
//
// CVE List V5 is read the way its maintainers publish it: `cves/deltaLog.json` lists, newest first, what changed in each ~7 minute run, and each changed
// record is one small file. A run reads only the start of the log (HTTP Range) back to the last checkpoint, fetches the changed records, and moves the
// checkpoint after a run's records are saved, never before. Re-running changes nothing.
import { all, audit, get, insertMany, now, run, tx } from "./db.ts";
import { HttpError, route } from "./http.ts";

const ADMIN = { roles: ["super_admin" as const] };
const LOG_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json";
const recordUrl = (id: string) => `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/${id.split("-")[1]}/${Math.floor(Number(id.split("-")[2]) / 1000)}xxx/${id}.json`;
const KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json";
const CVE_ID = /^CVE-\d{4}-\d{4,7}$/;

export const feedHooks = {
  fetch: (url: string, init: RequestInit = {}): Promise<Response> => fetch(url, { ...init, signal: AbortSignal.timeout(60_000) }),
  /** Windows of the delta log read from the top, in bytes. A gap longer than the last window reads the whole file (about 30 days of history). */
  windows: [64 * 1024, 512 * 1024, 4 * 1024 * 1024, 64 * 1024 * 1024],
  concurrency: 6,
};

// ---------------------------------------------------------------- settings
export interface FeedConfig { enabled: boolean; cveMinutes: number; kevMinutes: number; initialDays: number }
const DEFAULTS: FeedConfig = { enabled: true, cveMinutes: 10, kevMinutes: 60, initialDays: 2 };
export async function loadFeedConfig(): Promise<FeedConfig> {
  const row = await get<{ config_json: string }>("SELECT config_json FROM integrations WHERE key = 'feeds'");
  const c = row ? (JSON.parse(row.config_json) as Partial<FeedConfig>) : {};
  return { ...DEFAULTS, ...c };
}

// ---------------------------------------------------------------- CVE record
export interface PublicCve {
  id: string; state: string; title: string | null; description: string | null; published_at: number | null; modified_at: number | null;
  cvss_score: number | null; cvss_severity: string | null; cvss_vector: string | null; cwes: string[]; refs: string[]; assigner: string | null;
  affected: { vendor: string | null; product: string }[];
}
const ms = (v: unknown) => { const t = typeof v === "string" ? Date.parse(v) : NaN; return Number.isFinite(t) ? t : null; };
const clip = (v: unknown, n: number) => (typeof v === "string" && v.trim() ? v.trim().slice(0, n) : null);

/** A CVE JSON 5 record as one row. Fields the record does not have stay null: the page says "no data", never a guess. */
export function parseCve(j: any): PublicCve | null {
  const meta = j?.cveMetadata;
  const id = String(meta?.cveId ?? "").toUpperCase();
  if (!CVE_ID.test(id)) return null;
  const cna = j?.containers?.cna ?? {};
  const rejected = meta?.state === "REJECTED";
  const en = (list: any) => (Array.isArray(list) ? list.find((d: any) => /^en/i.test(d?.lang ?? "")) ?? list[0] : null)?.value;
  const description = clip(rejected ? en(cna.rejectedReasons) ?? en(cna.descriptions) : en(cna.descriptions), 4000);
  // the CNA's own score first, then the ADP containers (CISA adds one when the CNA gave none); newest CVSS version wins
  const metrics = [cna, ...(Array.isArray(j?.containers?.adp) ? j.containers.adp : [])].flatMap((c: any) => (Array.isArray(c?.metrics) ? c.metrics : []));
  let best: any = null;
  for (const v of ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]) { best = metrics.map((m: any) => m?.[v]).find((m: any) => typeof m?.baseScore === "number"); if (best) break; }
  const cwes: string[] = [...new Set<string>((Array.isArray(cna.problemTypes) ? cna.problemTypes : []).flatMap((p: any) => (p?.descriptions ?? []).map((d: any) => d?.cweId)).filter((x: unknown): x is string => typeof x === "string"))].slice(0, 10);
  const refs: string[] = [...new Set<string>((Array.isArray(cna.references) ? cna.references : []).map((r: any) => r?.url).filter((u: unknown): u is string => typeof u === "string" && /^https?:\/\//i.test(u)))].slice(0, 10);
  // the vendor/product pairs the CNA names: what a "possible" news match compares with installed software
  const affected = (Array.isArray(cna.affected) ? cna.affected : []).map((a: any) => ({ vendor: clip(a?.vendor, 80), product: clip(a?.product, 120) }))
    .filter((a: { product: string | null }): a is { vendor: string | null; product: string } => !!a.product).slice(0, 10);
  return {
    id, state: rejected ? "REJECTED" : "PUBLISHED", title: clip(cna.title, 300), description,
    published_at: ms(meta?.datePublished) ?? ms(meta?.dateReserved), modified_at: ms(meta?.dateUpdated),
    cvss_score: typeof best?.baseScore === "number" ? best.baseScore : null, cvss_severity: clip(best?.baseSeverity, 20)?.toUpperCase() ?? null, cvss_vector: clip(best?.vectorString, 120),
    cwes, refs, assigner: clip(meta?.assignerShortName, 60), affected,
  };
}

async function save(c: PublicCve) {
  // an older copy never replaces a newer one (a retry or an out-of-order delta)
  await run(`INSERT INTO cve_public (id, state, title, description, published_at, modified_at, ingested_at, cvss_score, cvss_severity, cvss_vector, cwes, refs_json, assigner, affected_json)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
             ON CONFLICT (id) DO UPDATE SET state = excluded.state, title = excluded.title, description = excluded.description, published_at = excluded.published_at,
               modified_at = excluded.modified_at, cvss_score = excluded.cvss_score, cvss_severity = excluded.cvss_severity, cvss_vector = excluded.cvss_vector,
               cwes = excluded.cwes, refs_json = excluded.refs_json, assigner = excluded.assigner, affected_json = excluded.affected_json
             WHERE cve_public.modified_at IS NULL OR excluded.modified_at IS NULL OR excluded.modified_at >= cve_public.modified_at`,
    c.id, c.state, c.title, c.description, c.published_at, c.modified_at, now(), c.cvss_score, c.cvss_severity, c.cvss_vector, JSON.stringify(c.cwes), JSON.stringify(c.refs), c.assigner, JSON.stringify(c.affected));
}

type Fetched = "ok" | "missing" | "error";
async function fetchRecord(id: string): Promise<Fetched> {
  try {
    const r = await feedHooks.fetch(recordUrl(id));
    if (r.status === 404) return "missing"; // not published (yet): the CVE Program says "waiting", we say so too
    if (!r.ok) return "error";
    const c = parseCve(await r.json());
    if (!c || c.id !== id) return "error";
    await save(c);
    return "ok";
  } catch { return "error"; }
}

/** Fetch the records that are not in the registry yet (a CVE named in a LINE message before the feed saw it). Failures are silent: it is filled in by a later run. */
export async function ensurePublic(ids: string[], waitMs = 5000): Promise<void> {
  let timer: NodeJS.Timeout | undefined;
  await Promise.race([fill(ids), new Promise<void>((ok) => { timer = setTimeout(ok, waitMs); })]); // a slow source never holds up an answer
  clearTimeout(timer);
}
async function fill(ids: string[]): Promise<void> {
  const want = [...new Set(ids.filter((i) => CVE_ID.test(i)))].slice(0, 20);
  if (!want.length) return;
  const have = new Set((await all<{ id: string }>(`SELECT id FROM cve_public WHERE id IN (${want.map(() => "?").join(",")})`, ...want)).map((r) => r.id));
  await Promise.all(want.filter((i) => !have.has(i)).map(fetchRecord));
}

// ---------------------------------------------------------------- feed state
interface State { checkpoint: string | null; etag: string | null; last_try_at: number | null; last_ok_at: number | null; error: string | null; info_json: string }
const state = (key: string) => get<State>("SELECT * FROM feed_state WHERE key = ?", key);
async function setState(key: string, p: { checkpoint?: string | null; etag?: string | null; ok?: boolean; error?: string | null; info?: object }) {
  const old = await state(key);
  const t = now();
  await run(`INSERT INTO feed_state (key, checkpoint, etag, last_try_at, last_ok_at, error, info_json) VALUES (?,?,?,?,?,?,?)
             ON CONFLICT (key) DO UPDATE SET checkpoint = excluded.checkpoint, etag = excluded.etag, last_try_at = excluded.last_try_at, last_ok_at = excluded.last_ok_at, error = excluded.error, info_json = excluded.info_json`,
    key, p.checkpoint !== undefined ? p.checkpoint : old?.checkpoint ?? null, p.etag !== undefined ? p.etag : old?.etag ?? null, t,
    p.ok ? t : old?.last_ok_at ?? null, p.ok ? null : p.error !== undefined ? p.error : old?.error ?? null, JSON.stringify(p.info ?? JSON.parse(old?.info_json ?? "{}")));
}

// ---------------------------------------------------------------- delta log
interface Delta { fetchTime: string; new?: { cveId: string }[]; updated?: { cveId: string }[] }
/** The complete top-level objects of a JSON array that may be cut off in the middle (a Range read). */
export function topObjects(text: string): Delta[] {
  const out: Delta[] = [];
  let depth = 0, start = -1, inStr = false, esc = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inStr) { if (esc) esc = false; else if (ch === "\\") esc = true; else if (ch === '"') inStr = false; continue; }
    if (ch === '"') inStr = true;
    else if (ch === "{" || ch === "[") { depth++; if (ch === "{" && depth === 2) start = i; }
    else if (ch === "}" || ch === "]") { if (ch === "}" && depth === 2 && start >= 0) { try { out.push(JSON.parse(text.slice(start, i + 1))); } catch { /* a damaged entry is skipped */ } start = -1; } depth--; }
  }
  return out;
}

/** Entries newer than `after`, newest first, and whether the log reaches back far enough to be sure nothing between was missed. */
async function deltaSince(after: string): Promise<{ entries: Delta[]; complete: boolean }> {
  for (const [i, size] of feedHooks.windows.entries()) {
    const r = await feedHooks.fetch(LOG_URL, { headers: { Range: `bytes=0-${size - 1}` } });
    if (!r.ok) throw new Error(`delta log: HTTP ${r.status}`);
    const text = await r.text();
    const all_ = topObjects(text).filter((e) => typeof e?.fetchTime === "string");
    const older = all_.findIndex((e) => e.fetchTime <= after);
    const whole = r.status === 200 || text.length < size; // the server sent everything (or ignored Range)
    if (older >= 0) return { entries: all_.slice(0, older), complete: true };
    if (whole || i === feedHooks.windows.length - 1) return { entries: all_, complete: false }; // the whole log is newer than the checkpoint: it may have a hole
  }
  return { entries: [], complete: true };
}

let cveRunning = false;
export interface CveRun { ingested: number; missing: number; remaining: number; checkpoint: string | null; gap: boolean; error?: string; skipped?: boolean }
/** One incremental run. `max` bounds the records read in one run; what is left is taken by the next run. */
export async function syncCveList(max = 500): Promise<CveRun> {
  if (cveRunning) return { ingested: 0, missing: 0, remaining: 0, checkpoint: null, gap: false, skipped: true };
  cveRunning = true;
  const st = await state("cvelist");
  let checkpoint = st?.checkpoint ?? null;
  let ingested = 0, missing = 0, remaining = 0, gap = false;
  try {
    const cfg = await loadFeedConfig();
    // first run: start a few days back (the registry fills on demand for older CVEs), not at the beginning of the CVE Program
    const after = checkpoint ?? new Date(now() - cfg.initialDays * 86_400_000).toISOString();
    const d = await deltaSince(after);
    gap = !d.complete;
    const entries = d.entries.reverse(); // oldest first, so the checkpoint only ever moves forward
    for (const [n, e] of entries.entries()) {
      if (ingested + missing >= max) { remaining = entries.length - n; break; }
      const ids = [...new Set([...(e.new ?? []), ...(e.updated ?? [])].map((x) => String(x?.cveId ?? "").toUpperCase()).filter((i) => CVE_ID.test(i)))];
      let failed = false;
      for (let i = 0; i < ids.length && !failed; i += feedHooks.concurrency) {
        for (const r of await Promise.all(ids.slice(i, i + feedHooks.concurrency).map(fetchRecord))) { if (r === "ok") ingested++; else if (r === "missing") missing++; else failed = true; }
      }
      if (failed) throw new Error("a record could not be fetched");
      checkpoint = e.fetchTime; // after every record of this entry is saved
      await setState("cvelist", { checkpoint, ok: false, info: { gap, remaining: entries.length - n - 1 } }); // a run is not finished until the end
    }
    await setState("cvelist", { checkpoint: checkpoint ?? after, ok: true, error: null, info: { gap, remaining, ingested } });
    return { ingested, missing, remaining, checkpoint: checkpoint ?? after, gap };
  } catch (e) {
    // the source is down or sent something unusable: keep what we have and when it was last good
    await setState("cvelist", { checkpoint, ok: false, error: (e as Error).message.slice(0, 200) });
    return { ingested, missing, remaining, checkpoint, gap, error: (e as Error).message };
  } finally { cveRunning = false; }
}

// ---------------------------------------------------------------- CISA KEV
let kevRunning = false;
export interface KevRun { total: number; added: string[]; notModified?: boolean; error?: string; skipped?: boolean }
export async function syncKev(): Promise<KevRun> {
  if (kevRunning) return { total: 0, added: [], skipped: true };
  kevRunning = true;
  const st = await state("kev");
  try {
    const r = await feedHooks.fetch(KEV_URL, { headers: st?.etag ? { "If-None-Match": st.etag } : {} });
    if (r.status === 304) { await setState("kev", { ok: true }); return { total: (await get<{ n: number }>("SELECT COUNT(*) n FROM kev"))!.n, added: [], notModified: true }; }
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const j: any = await r.json();
    const list: any[] = Array.isArray(j?.vulnerabilities) ? j.vulnerabilities.filter((v: any) => CVE_ID.test(String(v?.cveID ?? ""))) : [];
    if (!list.length) throw new Error("the list is empty or malformed"); // never replace a good list with a broken one
    const before = new Set((await all<{ cve_id: string }>("SELECT cve_id FROM kev")).map((x) => x.cve_id));
    const first = before.size === 0; // the first import is a baseline: nothing in it is "new"
    const t = now();
    const rows = list.map((v) => [v.cveID, clip(v.vulnerabilityName, 300), clip(v.vendorProject, 120), clip(v.product, 120), clip(v.shortDescription, 2000), clip(v.dateAdded, 10), clip(v.dueDate, 10),
      clip(v.knownRansomwareCampaignUse, 20), clip(v.requiredAction, 1000), clip(v.notes, 1000), t]);
    const added = list.map((v) => v.cveID as string).filter((i) => !before.has(i));
    await tx(async () => {
      await insertMany("kev", ["cve_id", "name", "vendor", "product", "description", "date_added", "due_date", "ransomware", "required_action", "notes", "first_seen_at"], rows,
        "ON CONFLICT (cve_id) DO UPDATE SET name = excluded.name, vendor = excluded.vendor, product = excluded.product, description = excluded.description, date_added = excluded.date_added, due_date = excluded.due_date, ransomware = excluded.ransomware, required_action = excluded.required_action, notes = excluded.notes");
      await run("UPDATE cves SET cisa_kev = 1 WHERE cisa_kev = 0 AND id IN (SELECT cve_id FROM kev)");
      if (!first && added.length) await alertKev(added);
    });
    await setState("kev", { etag: r.headers.get("etag"), ok: true, info: { total: list.length, lastAdded: added.length ? added.slice(0, 20) : undefined, release: j.catalogVersion } });
    return { total: list.length, added: first ? [] : added };
  } catch (e) {
    await setState("kev", { ok: false, error: (e as Error).message.slice(0, 200) });
    return { total: 0, added: [], error: (e as Error).message };
  } finally { kevRunning = false; }
}

// ---------------------------------------------------------------- urgent items
/** A CVE that just entered the KEV list and is open in an organization: one urgent item per organization and CVE, however often this runs. */
async function alertKev(ids: string[]) {
  for (let i = 0; i < ids.length; i += 500) {
    const part = ids.slice(i, i + 500);
    await run(`INSERT INTO alerts (tenant_id, cve_id, reason, created_at)
               SELECT DISTINCT x.tenant_id, f.cve_id, 'kev_added', ?::bigint FROM findings f JOIN tenant_cids x ON x.cid = f.cid
               WHERE f.cve_id IN (${part.map(() => "?").join(",")}) ON CONFLICT DO NOTHING`, now(), ...part);
  }
}

/** After a sync of one CID (its rollups are fresh): every CVE the organization has now and never had before is an urgent item ("first impact").
 *  The first sync of a CID, and the first start with this feature, only record what is already there (a baseline), so nothing floods. */
export async function recordImpact(cid: string, baseline: boolean) {
  await run(`INSERT INTO alerts (tenant_id, cve_id, reason, created_at)
             SELECT DISTINCT x.tenant_id, f.cve_id, ?::text, ?::bigint FROM roll_cve f JOIN tenant_cids x ON x.cid = f.cid
             WHERE x.tenant_id = (SELECT tenant_id FROM tenant_cids WHERE cid = ?) AND f.cve_id LIKE 'CVE-%'
               AND NOT EXISTS (SELECT 1 FROM alerts a WHERE a.tenant_id = x.tenant_id AND a.cve_id = f.cve_id)
             ON CONFLICT DO NOTHING`, baseline ? "baseline" : "first_impact", now(), cid);
}
/** Once, when the feature is first started on a database that already has findings. */
export async function seedAlerts() {
  if (await get("SELECT 1 FROM feed_state WHERE key = 'alerts_seed'")) return;
  await run(`INSERT INTO alerts (tenant_id, cve_id, reason, created_at)
             SELECT DISTINCT x.tenant_id, f.cve_id, 'baseline', ?::bigint FROM findings f JOIN tenant_cids x ON x.cid = f.cid WHERE f.cve_id LIKE 'CVE-%' ON CONFLICT DO NOTHING`, now());
  await setState("alerts_seed", { ok: true });
}

export interface Urgent { cve: string; reasons: ("first_impact" | "kev_added")[]; at: number; kev: boolean; severity: string; devices: number; title: string | null }
/** Open urgent items of one organization (the CVE is still on at least one of its devices), newest first. */
export async function urgentFor(tenantId: string, cids: string[]): Promise<Urgent[]> {
  if (!cids.length) return [];
  const ph = `(${cids.map(() => "?").join(",")})`;
  // the 50 newest items still open on this organization's devices first, then the facts about those 50 only (from the rollups: the findings are millions of rows)
  const rows = await all<{ cve_id: string; reasons: string; at: number; kev: number | null; severity: string; devices: number; title: string | null }>(
    `SELECT t.cve_id, t.reasons, t.at,
            (CASE WHEN EXISTS (SELECT 1 FROM kev k WHERE k.cve_id = t.cve_id) OR EXISTS (SELECT 1 FROM cves c WHERE c.id = t.cve_id AND c.cisa_kev = 1) THEN 1 ELSE 0 END) AS kev,
            (SELECT CASE MIN(r.rank) WHEN 0 THEN 'CRITICAL' WHEN 1 THEN 'HIGH' WHEN 2 THEN 'MEDIUM' WHEN 3 THEN 'LOW' ELSE 'NONE' END FROM roll_cve r WHERE r.cve_id = t.cve_id AND r.cid IN ${ph}) AS severity,
            (SELECT COALESCE(SUM(r.hosts), 0) FROM roll_cve r WHERE r.cve_id = t.cve_id AND r.cid IN ${ph}) AS devices,
            (SELECT p.title FROM cve_public p WHERE p.id = t.cve_id) AS title
     FROM (SELECT a.cve_id, STRING_AGG(DISTINCT a.reason, ',') AS reasons, MAX(a.created_at) AS at
           FROM alerts a WHERE a.tenant_id = ? AND a.reason <> 'baseline' AND EXISTS (SELECT 1 FROM roll_cve r WHERE r.cve_id = a.cve_id AND r.cid IN ${ph})
           GROUP BY a.cve_id ORDER BY MAX(a.created_at) DESC, a.cve_id LIMIT 50) t
     ORDER BY t.at DESC, t.cve_id`, ...cids, ...cids, tenantId, ...cids);
  return rows.map((r) => ({ cve: r.cve_id, reasons: r.reasons.split(",") as Urgent["reasons"], at: r.at, kev: !!r.kev, severity: r.severity, devices: r.devices, title: r.title }));
}

// ---------------------------------------------------------------- what an organization may conclude
export type ImpactState = "affected" | "pending" | "partial" | "unavailable" | "not_found";
export interface Impact { state: ImpactState; asOf: number | null; cids: number; complete: number }
/** The impact of one CVE on one organization.
 *  "not_found" is said only when every CID's latest read is complete AND it is newer than `since` (when the CVE was announced or the news arrived): older data cannot rule it out. */
export async function impactOf(tenantId: string, devices: number, since: number | null): Promise<Impact> {
  return impactFrom(await all<{ state: string | null; data_as_of: number | null; slice: boolean }>(
    `SELECT s.state, s.data_as_of, EXISTS (SELECT 1 FROM tenant_settings t WHERE t.tenant_id = x.tenant_id AND t.keep_severities <> '["CRITICAL","HIGH","MEDIUM","LOW","NONE"]') AS slice
     FROM tenant_cids x LEFT JOIN cid_status s ON s.cid = x.cid WHERE x.tenant_id = ?`, tenantId), devices, since);
}
/** `slice`: the organization stores only some severities (retention settings), so a complete read still cannot say that a CVE is not there. */
export function impactFrom(rows: { state: string | null; data_as_of: number | null; slice?: boolean | null }[], devices: number, since: number | null): Impact {
  const dated = rows.filter((r) => r.data_as_of);
  const asOf = dated.length ? Math.min(...dated.map((r) => r.data_as_of!)) : null; // the oldest read decides how fresh the whole answer is
  const complete = rows.filter((r) => r.state === "complete" && !r.slice).length;
  const base = { asOf, cids: rows.length, complete };
  if (devices > 0) return { state: "affected", ...base };
  if (!rows.length || rows.every((r) => !r.state)) return { state: "pending", ...base };               // nothing has been read from Falcon yet
  if (complete === rows.length) return { state: since !== null && asOf !== null && asOf < since ? "pending" : "not_found", ...base }; // read completely, but is the read newer than the announcement?
  if (!dated.length) return { state: "unavailable", ...base };                                           // every read failed and there is no older data
  return { state: "partial", ...base };
}

// ---------------------------------------------------------------- read models
export interface PublicView {
  id: string; announced: boolean; state: string | null; title: string | null; description: string | null; publishedAt: number | null; modifiedAt: number | null; ingestedAt: number | null;
  cvss: { score: number | null; severity: string | null; vector: string | null }; cwes: string[]; references: string[];
  kev: { dateAdded: string | null; dueDate: string | null; ransomware: string | null; requiredAction: string | null; name: string | null } | null;
}
export async function publicInfo(ids: string[]): Promise<Map<string, PublicView>> {
  const out = new Map<string, PublicView>();
  if (!ids.length) return out;
  const ph = `(${ids.map(() => "?").join(",")})`;
  const pub = new Map((await all<any>(`SELECT * FROM cve_public WHERE id IN ${ph}`, ...ids)).map((r) => [r.id, r]));
  const kev = new Map((await all<any>(`SELECT * FROM kev WHERE cve_id IN ${ph}`, ...ids)).map((r) => [r.cve_id, r]));
  for (const id of ids) {
    const p = pub.get(id), k = kev.get(id);
    out.set(id, {
      id, announced: !!p, state: p?.state ?? null, title: p?.title ?? null, description: p?.description ?? null, publishedAt: p?.published_at ?? null, modifiedAt: p?.modified_at ?? null, ingestedAt: p?.ingested_at ?? null,
      cvss: { score: p?.cvss_score ?? null, severity: p?.cvss_severity ?? null, vector: p?.cvss_vector ?? null },
      cwes: p ? JSON.parse(p.cwes) : [], references: p ? JSON.parse(p.refs_json) : [],
      kev: k ? { dateAdded: k.date_added, dueDate: k.due_date, ransomware: k.ransomware, requiredAction: k.required_action, name: k.name } : null,
    });
  }
  return out;
}

// ---------------------------------------------------------------- scheduler
/** Work that follows a feed run (the news match job registers here, so a CVE that was just announced is compared with every organization at once). */
export const afterFeedRun: (() => Promise<void>)[] = [];
async function afterRun() { for (const f of afterFeedRun) await f().catch((e) => console.error("[feeds] follow-up failed", e)); }
let timer: NodeJS.Timeout | null = null;
async function tick() {
  const cfg = await loadFeedConfig();
  if (!cfg.enabled) return;
  const due = async (key: string, minutes: number) => { const s = await state(key); return !s?.last_try_at || now() - s.last_try_at >= minutes * 60_000; };
  if (await due("cvelist", cfg.cveMinutes)) await syncCveList();
  if (await due("kev", cfg.kevMinutes)) await syncKev();
  await afterRun();
}
/** A one-minute tick that checks what is due, so the intervals can be changed in the setup page without a restart, and a restart does not reset them. */
export function startFeeds() {
  if (timer) return;
  void seedAlerts().catch((e) => console.error("[feeds] seed failed", e));
  timer = setInterval(() => { void tick().catch((e) => console.error("[feeds] tick failed", e)); }, 60_000);
  timer.unref();
  void tick().catch((e) => console.error("[feeds] tick failed", e));
}

// ---------------------------------------------------------------- routes
async function statusView() {
  const [cve, kev] = await Promise.all([state("cvelist"), state("kev")]);
  const view = (s: State | undefined) => ({ lastOkAt: s?.last_ok_at ?? null, lastTryAt: s?.last_try_at ?? null, error: s?.error ?? null, checkpoint: s?.checkpoint ?? null, info: JSON.parse(s?.info_json ?? "{}") });
  return {
    config: await loadFeedConfig(),
    cveList: view(cve), kev: view(kev),
    counts: { cves: (await get<{ n: number }>("SELECT COUNT(*) n FROM cve_public"))!.n, kev: (await get<{ n: number }>("SELECT COUNT(*) n FROM kev"))!.n },
  };
}
// Freshness of the public feeds: not tenant data, so every signed-in user may see it.
route("GET", "/api/feeds/status", async () => statusView());
route("PUT", "/api/integrations/feeds", ADMIN, async (c) => {
  const n = (v: unknown, lo: number, hi: number, d: number) => { const x = Number(v ?? d); if (!Number.isInteger(x) || x < lo || x > hi) throw new HttpError(400, "Invalid interval", "invalid_interval"); return x; };
  const cfg: FeedConfig = {
    enabled: c.body.enabled === undefined ? true : !!c.body.enabled,
    cveMinutes: n(c.body.cveMinutes, 5, 1440, 10), kevMinutes: n(c.body.kevMinutes, 15, 1440, 60), initialDays: n(c.body.initialDays, 1, 30, 2),
  };
  await run(`INSERT INTO integrations (key, config_json, secret_sealed, updated_at, updated_by) VALUES ('feeds', ?, NULL, ?, ?)
             ON CONFLICT (key) DO UPDATE SET config_json = excluded.config_json, updated_at = excluded.updated_at, updated_by = excluded.updated_by`, JSON.stringify(cfg), now(), c.user!.id);
  await audit({ actor: c.user, action: "integration.feeds.update", result: "ok", ip: c.ip });
  return statusView();
});
route("POST", "/api/integrations/feeds/run", ADMIN, async (c) => {
  const [cve, kev] = [await syncCveList(), await syncKev()];
  await afterRun();
  await audit({ actor: c.user, action: "integration.feeds.run", result: cve.error || kev.error ? "fail" : "ok", ip: c.ip });
  return { cve, kev, status: await statusView() };
});
/** Search the public registry. No organization data and no counts of what is affected, so a new CVE never changes anyone's numbers. */
route("GET", "/api/public/cves", async (c) => {
  const q = (c.query.get("q") ?? "").trim().slice(0, 100);
  const limit = Math.min(50, Math.max(1, Number(c.query.get("limit")) || 20));
  const like = `%${q.replace(/[\\%_]/g, "\\$&")}%`;
  const rows = await all<any>(
    `SELECT p.id, p.state, p.title, p.published_at, p.cvss_score, p.cvss_severity, (k.cve_id IS NOT NULL) AS kev
     FROM cve_public p LEFT JOIN kev k ON k.cve_id = p.id
     ${q ? "WHERE p.id ILIKE ? OR p.title ILIKE ? OR p.description ILIKE ?" : ""} ORDER BY COALESCE(p.published_at, 0) DESC, p.id DESC LIMIT ${limit}`, ...(q ? [like, like, like] : []));
  return { items: rows.map((r) => ({ id: r.id, state: r.state, title: r.title, publishedAt: r.published_at, cvssScore: r.cvss_score, cvssSeverity: r.cvss_severity, kev: !!r.kev })) };
});
