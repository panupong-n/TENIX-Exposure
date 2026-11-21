// What an organization's LINE messages carry: which severities, which device names (all | watched | top N), how many names. No row = exactly what the bot did before.
import { all, audit, byName, get, now, run, tx } from "./db.ts";
import { assetLevels, attackEvidence, cveLevelOf, DEFAULT_MATRIX, evidenceStatus, higher, LEVELS, lookup, parseMatrix, probeEvidence, type AssetLevel, type Esc, type Level, type Matrix } from "./alertlevel.ts";
import { HttpError, route, type Ctx } from "./http.ts";
import { managedTenants } from "./db.ts";
import { watchedSet } from "./watch.ts";

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"] as const;
export const MODES = ["all", "watched", "top"] as const;
export interface Prefs {
  enabled: boolean; severities: string[]; p1Always: boolean; devicesMode: (typeof MODES)[number]; topN: number; maxNames: number;
  newsPossible: boolean; newsHostNames: boolean; updatedAt: number | null; updatedBy: string | null;
  /** false = the old behaviour: the severities filter the CVE severity. true = they filter the notify level (matrix of CVE level x asset level, raised to CRITICAL on evidence). */
  matrixOn: boolean; matrix: Matrix; escAlert: boolean; escDays: number; escKev: boolean;
}
export const DEFAULT_PREFS: Prefs = { enabled: true, severities: [...SEVERITIES], p1Always: true, devicesMode: "all", topN: 10, maxNames: 20, newsPossible: false, newsHostNames: false, updatedAt: null, updatedBy: null,
  matrixOn: false, matrix: DEFAULT_MATRIX, escAlert: true, escDays: 7, escKev: false };

/** null = no row: delivery stays exactly as it was. */
export async function loadPrefs(tenantId: string): Promise<Prefs | null> {
  const r = await get<any>("SELECT * FROM notify_prefs WHERE tenant_id = ?", tenantId);
  if (!r) return null;
  const sev = JSON.parse(r.severities) as string[];
  return { enabled: r.enabled, severities: SEVERITIES.filter((s) => sev.includes(s)), p1Always: r.p1_always, devicesMode: r.devices_mode, topN: r.top_n, maxNames: r.max_names, newsPossible: r.news_possible, newsHostNames: r.news_host_names, updatedAt: r.updated_at, updatedBy: r.updated_by,
    matrixOn: r.matrix_on, matrix: (r.matrix_json && parseMatrix(JSON.parse(r.matrix_json))) || DEFAULT_MATRIX, escAlert: r.esc_alert, escDays: r.esc_days, escKev: r.esc_kev };
}

/** The shape of a row of a news answer that this module needs (line.ts has the full type). */
interface Dev { name: string; aid?: string; versions: string[]; severity: string; asset?: AssetLevel; level?: Level; esc?: Esc }
interface HitLike { devices: number; severity: string; names: Dev[]; note?: string; assetLevel?: AssetLevel; notifyLevel?: Level; escalated?: boolean; exploited?: boolean }
interface RowLike<H extends HitLike> { cve: string; kev: boolean; hit: H }

/** Which of these CVEs are exploited (>= 60) on the organization's devices: they count as P1 beside CISA KEV. */
async function exploited(tenantId: string, cves: string[]): Promise<Set<string>> {
  if (!cves.length) return new Set();
  return new Set((await all<{ cve_id: string }>(`SELECT DISTINCT r.cve_id FROM roll_cve r JOIN tenant_cids x ON x.cid = r.cid WHERE x.tenant_id = ? AND r.exploit_status >= 60 AND r.cve_id IN (${cves.map(() => "?").join(",")})`, tenantId, ...cves)).map((r) => r.cve_id));
}

/** Order of devices in the device list: Critical CVEs first, then CVE count, then name. */
export async function rankDevices(tenantId: string, aids: string[]): Promise<Map<string, number>> {
  const rows = aids.length ? await all<{ aid: string }>(
    `SELECT h.aid FROM roll_host h JOIN tenant_cids x ON x.cid = h.cid WHERE x.tenant_id = ? AND h.aid IN (${aids.map(() => "?").join(",")}) GROUP BY h.aid ORDER BY SUM(h.critical) DESC, SUM(h.cves) DESC, MAX(h.hostname), h.aid`, tenantId, ...aids) : [];
  return new Map(rows.map((r, i) => [r.aid, i]));
}

/** Gives every affected device its asset level (and, when the organization uses the matrix, its notify level and the reason it was raised to CRITICAL), and each row the
 *  CVE level, the highest asset level, the highest notify level and whether it is exploited on the organization's devices. Rows are copied, never changed. `fresh` false = cached evidence only. */
export async function annotate<H extends HitLike, R extends RowLike<H>>(tenantId: string, rows: R[], p: Prefs | null, fresh = true): Promise<R[]> {
  const hits = rows.filter((r) => r.hit.devices > 0);
  if (!hits.length) return rows;
  const ex = await exploited(tenantId, hits.map((r) => r.cve));
  const aids = [...new Set(hits.flatMap((r) => r.hit.names.filter((d) => !d.asset && d.aid).map((d) => d.aid!)))];
  const assets = await assetLevels(tenantId, aids);
  const on = !!p?.matrixOn;
  const order = (a: string) => LEVELS.indexOf(matrixOf(assets.get(a)?.level ?? "UNASSIGNED"));
  const evidence = on && p!.escAlert ? await attackEvidence(tenantId, [...aids].sort((a, b) => order(a) - order(b)), p!.escDays, fresh) : new Map<string, Esc>();
  return rows.map((r) => {
    if (r.hit.devices === 0) return r;
    const exploitedHere = ex.has(r.cve);
    const names = r.hit.names.map((d) => {
      const asset = d.asset ?? assets.get(d.aid ?? "")?.level ?? "UNASSIGNED";
      if (!on) return { ...d, asset, esc: undefined };
      let level = lookup(p!.matrix, cveLevelOf(d.severity), asset), esc: Esc | undefined;
      if (level !== "CRITICAL") esc = (d.esc && p!.escAlert ? d.esc : undefined) ?? evidence.get(d.aid ?? "") ?? (p!.escKev && (r.kev || exploitedHere) ? { type: r.kev ? "kev" as const : "exploited" as const, days: p!.escDays } : undefined);
      if (esc) level = "CRITICAL";
      return { ...d, asset, level, esc };
    });
    const best = names.map((d) => d.asset!).sort((x, y) => LEVELS.indexOf(matrixOf(x)) - LEVELS.indexOf(matrixOf(y)) || Number(x === "UNASSIGNED") - Number(y === "UNASSIGNED"))[0];
    return { ...r, hit: { ...r.hit, names, exploited: exploitedHere, assetLevel: best, ...(on ? { notifyLevel: names.reduce<Level>((m, d) => higher(m, d.level!), "LOW"), escalated: names.some((d) => d.esc) } : {}) } };
  });
}
const matrixOf = (a: AssetLevel): Level => (a === "UNASSIGNED" ? "MEDIUM" : a);

/** The rows of a news answer as this organization's prefs allow: severity filter (P1 may override), device names by mode, at most maxNames. [] = send nothing.
 *  With the matrix on, the severities filter the notify level of each (CVE, device) pair instead of the CVE severity. The true device count is never changed; a note says when the list is partial. */
export async function applyPrefs<H extends HitLike, R extends RowLike<H>>(tenantId: string, rows: R[], p: Prefs, fresh = true): Promise<R[]> {
  if (!p.enabled) return [];
  rows = await annotate(tenantId, rows, p, fresh);
  const watched = p.devicesMode === "watched" ? await watchedSet(tenantId) : null;
  const out: R[] = [];
  for (const r of rows) {
    if (r.hit.devices === 0) { out.push(r); continue; } // "nothing found" answers carry no severity and no names
    const p1 = p.p1Always && (r.kev || !!r.hit.exploited);
    const pass = (d: Dev) => p.severities.includes(d.level!) || (d.severity === "NONE" && d.level === "LOW" && p.severities.includes("NONE")); // informational counts as Low in the matrix
    const ok = p1 || (p.matrixOn ? r.hit.names.some(pass) : p.severities.includes(r.hit.severity));
    if (!ok) continue;
    let names = r.hit.names, note: string | undefined;
    if (p.matrixOn && !p1 && names.some((d) => !pass(d))) { names = names.filter(pass); note = `แสดงเฉพาะเครื่องที่ระดับแจ้งเตือนตรงเงื่อนไข ${names.length} จาก ${r.hit.devices} เครื่อง`; }
    const add = (x: string) => { note = note ? `${note} · ${x}` : x; };
    if (watched) {
      names = names.filter((d) => d.aid && watched.has(d.aid));
      add(names.length ? `แสดงเฉพาะเครื่องที่เฝ้าอยู่ ${names.length} จาก ${r.hit.devices} เครื่อง` : "ไม่มีเครื่องที่เฝ้าอยู่ได้รับผลกระทบ");
    } else if (p.devicesMode === "top" && names.length > p.topN) {
      const rank = await rankDevices(tenantId, names.map((d) => d.aid ?? ""));
      names = [...names].sort((a, b) => (rank.get(a.aid ?? "") ?? 1e9) - (rank.get(b.aid ?? "") ?? 1e9)).slice(0, p.topN);
      add(`แสดง ${p.topN} เครื่องสำคัญสูงสุด จาก ${r.hit.devices} เครื่อง`);
    }
    if (names.length > p.maxNames) { add(`และอีก ${names.length - p.maxNames} เครื่อง`); names = names.slice(0, p.maxNames); }
    out.push({ ...r, hit: { ...r.hit, names, note } });
  }
  return out.some((r) => r.hit.devices > 0) || rows.every((r) => r.hit.devices === 0) ? out : []; // every affected CVE was filtered out: no message at all
}

// ---------------------------------------------------------------- routes
/** Reading: any member of the tenant (and a super admin). Writing: an admin of it, or a super admin. Another organization's settings look like a missing page. */
export async function notifyAccess(c: Ctx, write: boolean): Promise<string> {
  const id = c.params.id, u = c.user!;
  const m = managedTenants(u);
  const member = u.memberships.some((x) => x.tenant_id === id);
  if (!(m === "all" || m.has(id) || (!write && member))) throw new HttpError(404, "Not found");
  if (!(await get("SELECT 1 FROM tenants WHERE id = ?", id))) throw new HttpError(404, "Not found");
  return id;
}
const int = (v: unknown, lo: number, hi: number, code: string) => { if (typeof v !== "number" || !Number.isInteger(v) || v < lo || v > hi) throw new HttpError(400, `Must be a whole number from ${lo} to ${hi}`, code); return v; };
const bool = (v: unknown, code: string) => { if (typeof v !== "boolean") throw new HttpError(400, "Must be true or false", code); return v; };

/** The saved prefs with the fields of `b` laid over them (the dialog's defaults when nothing is saved). Throws 400 on a bad value. */
export async function mergePrefs(tenantId: string, b: Record<string, unknown>): Promise<Prefs> {
  const cur = (await loadPrefs(tenantId)) ?? DEFAULT_PREFS;
  const p = { ...cur };
  if (b.enabled !== undefined) p.enabled = bool(b.enabled, "invalid_enabled");
  if (b.severities !== undefined) {
    if (!Array.isArray(b.severities) || !b.severities.every((s) => (SEVERITIES as readonly string[]).includes(s as string))) throw new HttpError(400, "severities must be a list of CRITICAL, HIGH, MEDIUM, LOW, NONE", "invalid_severity");
    if (!b.severities.length) throw new HttpError(400, "Choose at least one severity (use enabled=false to stop messages)", "severities_empty");
    p.severities = SEVERITIES.filter((s) => (b.severities as string[]).includes(s));
  }
  if (b.p1Always !== undefined) p.p1Always = bool(b.p1Always, "invalid_p1");
  if (b.devicesMode !== undefined) { if (!(MODES as readonly string[]).includes(b.devicesMode as string)) throw new HttpError(400, "devicesMode must be all, watched or top", "invalid_mode"); p.devicesMode = b.devicesMode as Prefs["devicesMode"]; }
  if (b.topN !== undefined) p.topN = int(b.topN, 1, 100, "invalid_top_n");
  if (b.maxNames !== undefined) p.maxNames = int(b.maxNames, 1, 50, "invalid_max_names");
  if (b.newsPossible !== undefined) p.newsPossible = bool(b.newsPossible, "invalid_news_possible");
  if (b.newsHostNames !== undefined) p.newsHostNames = bool(b.newsHostNames, "invalid_news_host_names");
  if (b.matrixOn !== undefined) p.matrixOn = bool(b.matrixOn, "invalid_matrix_on");
  if (b.matrix !== undefined) { const m = parseMatrix(b.matrix); if (!m) throw new HttpError(400, "matrix must give every CVE level (CRITICAL, HIGH, MEDIUM, LOW) a notify level for every asset level", "invalid_matrix"); p.matrix = m; }
  if (b.escAlert !== undefined) p.escAlert = bool(b.escAlert, "invalid_esc_alert");
  if (b.escDays !== undefined) p.escDays = int(b.escDays, 1, 30, "invalid_esc_days");
  if (b.escKev !== undefined) p.escKev = bool(b.escKev, "invalid_esc_kev");
  return p;
}

/** The host-group -> asset-level mapping of a request: undefined = keep what is saved. At most 100 groups. */
function parseGroupLevels(v: unknown): { group: string; level: Level }[] | undefined {
  if (v === undefined) return undefined;
  const bad = () => new HttpError(400, "groupLevels must be a list of at most 100 { group, level } with level CRITICAL, HIGH, MEDIUM or LOW", "invalid_group_levels");
  if (!Array.isArray(v) || v.length > 100) throw bad();
  const seen = new Map<string, { group: string; level: Level }>();
  for (const x of v) {
    const g = typeof x?.group === "string" ? x.group.replace(/\0/g, "").trim() : "";
    if (!g || g.length > 120 || !(LEVELS as readonly string[]).includes(x?.level)) throw bad();
    seen.set(g.toLowerCase(), { group: g, level: x.level });
  }
  return [...seen.values()];
}

async function view(c: Ctx, id: string, canEdit: boolean) {
  const saved = await loadPrefs(id);
  const dests = await all<{ name: string | null }>("SELECT name FROM line_chats WHERE role = 'destination' AND tenant_id = ? ORDER BY created_at, chat_id", id);
  const prefs = saved ?? DEFAULT_PREFS;
  if (canEdit && prefs.matrixOn && prefs.escAlert) await probeEvidence(id).catch(() => {}); // one cheap read-only call at most once an hour: can the API client read alerts?
  const cids = (await all<{ cid: string }>("SELECT cid FROM tenant_cids WHERE tenant_id = ?", id)).map((r) => r.cid);
  const groups = cids.length ? await all<{ name: string }>(`SELECT g AS name FROM hosts h, unnest(h.groups) g WHERE h.cid IN (${cids.map(() => "?").join(",")}) GROUP BY g ORDER BY COUNT(*) DESC LIMIT 200`, ...cids) : [];
  return {
    tenantId: id, canEdit, isDefault: !saved, prefs,
    defaultMatrix: DEFAULT_MATRIX, evidence: await evidenceStatus(id),
    groupLevels: byName(await all<{ name: string; level: string }>("SELECT group_name AS name, level FROM notify_group_levels WHERE tenant_id = ?", id)).map((g) => ({ group: g.name, level: g.level })),
    knownGroups: byName(groups).map((g) => g.name),
    watchedCount: (await get<{ n: number }>("SELECT COUNT(*) n FROM watch_hosts WHERE tenant_id = ?", id))!.n,
    destinations: { count: dests.length, names: dests.map((d) => d.name).filter((n): n is string => !!n) },
    options: { devicesModes: [...MODES], topN: [1, 100], maxNames: [1, 50] },
  };
}
const canWrite = (c: Ctx, id: string) => { const m = managedTenants(c.user!); return m === "all" || m.has(id); };

route("GET", "/api/tenants/:id/notify", async (c) => {
  const id = await notifyAccess(c, false);
  return view(c, id, canWrite(c, id));
});
route("PUT", "/api/tenants/:id/notify", async (c) => {
  const id = await notifyAccess(c, true);
  const before = await loadPrefs(id);
  const p = await mergePrefs(id, c.body);
  const gl = parseGroupLevels(c.body.groupLevels);
  await run(`INSERT INTO notify_prefs (tenant_id, enabled, severities, p1_always, devices_mode, top_n, max_names, news_possible, news_host_names, updated_by, updated_at, matrix_on, matrix_json, esc_alert, esc_days, esc_kev) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
             ON CONFLICT (tenant_id) DO UPDATE SET enabled = excluded.enabled, severities = excluded.severities, p1_always = excluded.p1_always, devices_mode = excluded.devices_mode, top_n = excluded.top_n,
               max_names = excluded.max_names, news_possible = excluded.news_possible, news_host_names = excluded.news_host_names, updated_by = excluded.updated_by, updated_at = excluded.updated_at,
               matrix_on = excluded.matrix_on, matrix_json = excluded.matrix_json, esc_alert = excluded.esc_alert, esc_days = excluded.esc_days, esc_kev = excluded.esc_kev`,
    id, p.enabled as any, JSON.stringify(p.severities), p.p1Always as any, p.devicesMode, p.topN, p.maxNames, p.newsPossible as any, p.newsHostNames as any, c.user!.name || c.user!.email, now(), p.matrixOn as any, JSON.stringify(p.matrix), p.escAlert as any, p.escDays, p.escKev as any);
  if (gl) await tx(async () => {
    await run("DELETE FROM notify_group_levels WHERE tenant_id = ?", id);
    for (const g of gl) await run("INSERT INTO notify_group_levels (tenant_id, group_name, level) VALUES (?,?,?)", id, g.group, g.level);
  });
  const brief = (x: Prefs | null) => (x ? JSON.stringify({ ...x, updatedAt: undefined, updatedBy: undefined }) : "default");
  await audit({ actor: c.user, tenantId: id, action: "tenant.notify", result: "ok", ip: c.ip, detail: `${brief(before)} -> ${brief(p)}${gl ? ` groups=${gl.length}` : ""}`.slice(0, 900) });
  return view(c, id, true);
});
