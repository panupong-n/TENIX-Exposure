// CVE news per organization. The LINE bot and the feeds store news and CVEs once for everybody (news_items, news_cves, cve_public); this module says,
// for each organization, where every news CVE stands: exact (its findings have it) | possible (an installed software name matches a product in the CVE record, 14 days)
// | wait (cannot conclude yet) | not_affected (complete, newer data, nothing). One current row per (organization, CVE) in news_match; it is recomputed after every sync of a CID,
// every feed run and every analysed news item, and the organization is told again only on a material change (notified_*).
import { all, audit, get, isSoc, now, run } from "./db.ts";
import { HttpError, route, type Ctx } from "./http.ts";
import { inList, tenantScope, type Scope } from "./scope.ts";
import { afterFeedRun, impactFrom, publicInfo } from "./feeds.ts";
import { warmers } from "./cache.ts";
import { loadPrefs } from "./notify.ts";

const DAY = 86_400_000;
export const NEWS_DAYS = 90, POSSIBLE_DAYS = 14, FRESH_MS = 2 * DAY;
export type NewsState = "exact" | "possible" | "wait" | "not_affected";
const STATES: NewsState[] = ["exact", "possible", "wait", "not_affected"];
const SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"];
export const newsHooks = { notify: async (_tenantId: string, _cve: string, _state: NewsState, _devices: number): Promise<boolean> => false };

const GENERIC = new Set(["n/a", "na", "unspecified", "unknown", "multiple", "various", "all", "none", "linux", "windows", "kernel", "product", "products", "software", "application", "applications", "server", "client", "web", "other"]);
const esc = (v: string) => v.replace(/[\\%_]/g, "\\$&");
const usable = (v: string | null | undefined, min: number) => { const x = (v ?? "").trim(); return x.length >= min && !GENERIC.has(x.toLowerCase()) ? x : null; };

/** The vendor/product pairs a CVE names (CVE record, then CISA KEV). */
async function productsOf(cve: string): Promise<{ vendor: string | null; product: string }[]> {
  const out: { vendor: string | null; product: string }[] = [];
  const p = await get<{ affected_json: string | null }>("SELECT affected_json FROM cve_public WHERE id = ?", cve);
  try { for (const a of p?.affected_json ? JSON.parse(p.affected_json) : []) { const product = usable(a.product, 4); if (product) out.push({ vendor: usable(a.vendor, 3), product }); } } catch { /* damaged: no products */ }
  const k = await get<{ vendor: string | null; product: string | null }>("SELECT vendor, product FROM kev WHERE cve_id = ?", cve);
  const kp = usable(k?.product, 4);
  if (kp) out.push({ vendor: usable(k?.vendor, 3), product: kp });
  const seen = new Set<string>();
  return out.filter((x) => !seen.has(x.product.toLowerCase()) && !!seen.add(x.product.toLowerCase())).slice(0, 5);
}

/** Installed software of the organization whose name contains a product of the CVE (and the vendor, when the record names one). */
export async function possibleHits(cids: string[], cve: string): Promise<{ products: string[]; software: { name: string; vendor: string; devices: number }[]; devices: number }> {
  const none = { products: [], software: [], devices: 0 };
  if (!cids.length) return none;
  const prods = await productsOf(cve);
  const hosts = new Set<string>(), software: { name: string; vendor: string; devices: number }[] = [];
  for (const p of prods) {
    const rows = await all<{ name: string; vendor: string; host_id: string }>(
      `SELECT name, vendor, host_id FROM software WHERE cid IN ${inList(cids)} AND name ILIKE ? ESCAPE '\\'${p.vendor ? " AND (vendor ILIKE ? ESCAPE '\\' OR name ILIKE ? ESCAPE '\\')" : ""} LIMIT 5000`,
      ...cids, `%${esc(p.product)}%`, ...(p.vendor ? [`%${esc(p.vendor)}%`, `%${esc(p.vendor)}%`] : []));
    const by = new Map<string, Set<string>>();
    for (const r of rows) { hosts.add(`${r.host_id}`); const k = `${r.name}\u0000${r.vendor}`; by.set(k, (by.get(k) ?? new Set()).add(r.host_id)); }
    for (const [k, h] of by) { const [name, vendor] = k.split("\u0000"); software.push({ name, vendor, devices: h.size }); }
  }
  software.sort((a, b) => b.devices - a.devices || a.name.localeCompare(b.name));
  return { products: prods.map((p) => p.product), software: software.slice(0, 10), devices: hosts.size };
}

export interface MatchOpts { cves?: string[]; tenantIds?: string[]; markNotified?: boolean; notify?: boolean }
let running: Promise<void> = Promise.resolve();
/** Recompute news_match. Serialized (two runs at once could tell the same organization twice). */
export function matchNews(o: MatchOpts = {}): Promise<void> {
  const next = running.then(() => doMatch(o));
  running = next.catch(() => {});
  return next;
}
async function doMatch(o: MatchOpts) {
  const t = now();
  const tenants = await all<{ id: string }>("SELECT DISTINCT t.id FROM tenants t JOIN tenant_cids x ON x.tenant_id = t.id");
  for (const { id: tenantId } of tenants) {
    if (o.tenantIds && !o.tenantIds.includes(tenantId)) continue;
    const cids = (await all<{ cid: string }>("SELECT cid FROM tenant_cids WHERE tenant_id = ? ORDER BY cid", tenantId)).map((r) => r.cid);
    // only news this organization may see: the SOC's chats and its own (another organization's chat never reaches it)
    const news = await all<{ cve: string; first: number }>(
      `SELECT nc.cve_id AS cve, MIN(n.received_at) AS first FROM news_cves nc JOIN news_items n ON n.id = nc.news_id
       JOIN line_chats l ON l.chat_id = n.chat AND l.role = 'source' AND (l.tenant_id IS NULL OR l.tenant_id = ?)
       WHERE n.received_at >= ? ${o.cves ? `AND nc.cve_id IN ${inList(o.cves)}` : ""} GROUP BY nc.cve_id`, tenantId, t - NEWS_DAYS * DAY, ...(o.cves ?? []));
    if (!news.length) continue;
    const ids = news.map((n) => n.cve);
    const devs = new Map((await all<{ cve_id: string; n: number }>(`SELECT cve_id, SUM(hosts) AS n FROM roll_cve WHERE cid IN ${inList(cids)} AND cve_id IN ${inList(ids)} GROUP BY cve_id`, ...cids, ...ids)).map((r) => [r.cve_id, r.n]));
    const status = await all<{ state: string | null; data_as_of: number | null; slice: boolean }>(
      `SELECT s.state, s.data_as_of, (y.scope = 'priority') AS slice FROM tenant_cids x LEFT JOIN cid_status s ON s.cid = x.cid LEFT JOIN cid_sync y ON y.cid = x.cid WHERE x.tenant_id = ?`, tenantId);
    const pub = await publicInfo(ids);
    const have = new Map((await all<any>(`SELECT * FROM news_match WHERE tenant_id = ? AND cve IN ${inList(ids)}`, tenantId, ...ids)).map((r) => [r.cve, r]));
    const prefs = await loadPrefs(tenantId);
    for (const n of news) {
      let state: NewsState, devices = devs.get(n.cve) ?? 0;
      if (devices > 0) state = "exact";
      else {
        const since = pub.get(n.cve)?.publishedAt ?? n.first;
        const im = impactFrom(status, 0, since);
        state = im.state === "not_found" ? "not_affected" : "wait";
        if (t - n.first < POSSIBLE_DAYS * DAY) { const p = await possibleHits(cids, n.cve); if (p.devices > 0) { state = "possible"; devices = p.devices; } }
      }
      const old = have.get(n.cve);
      const changed = !old || old.state !== state || old.devices !== devices;
      if (!old) await run("INSERT INTO news_match (tenant_id, cve, state, devices, first_seen, last_changed) VALUES (?,?,?,?,?,?) ON CONFLICT DO NOTHING", tenantId, n.cve, state, devices, n.first, t);
      else if (changed) await run("UPDATE news_match SET state = ?, devices = ?, last_changed = ?, first_seen = LEAST(first_seen, ?) WHERE tenant_id = ? AND cve = ?", state, devices, t, n.first, tenantId, n.cve);
      let ns: string | null = old?.notified_state ?? null, nd: number | null = old?.notified_devices ?? null;
      if (o.markNotified && state === "exact") { ns = state; nd = devices; await run("UPDATE news_match SET notified_state = ?, notified_devices = ?, notified_at = ? WHERE tenant_id = ? AND cve = ?", ns, nd, t, tenantId, n.cve); continue; }
      if (o.notify === false || (state !== "exact" && state !== "possible")) continue;
      if (state === "possible" && !prefs?.newsPossible) continue;
      const lastChanged = changed ? t : old.last_changed;
      const material = ns === null || (state === "exact" && ns !== "exact") || (state === "exact" && ns === "exact" && nd !== null && (devices >= nd * 2 || devices >= nd + 10));
      if (!material || t - lastChanged > FRESH_MS) continue; // old news is never announced late (a new group would get 90 days at once)
      if (await newsHooks.notify(tenantId, n.cve, state, devices).catch((e) => { console.error("[news] notify failed", e); return false; }))
        await run("UPDATE news_match SET notified_state = ?, notified_devices = ?, notified_at = ? WHERE tenant_id = ? AND cve = ?", state, devices, t, tenantId, n.cve);
    }
  }
}
warmers.push(async (cid) => {
  const t = await get<{ tenant_id: string }>("SELECT tenant_id FROM tenant_cids WHERE cid = ?", cid);
  if (t) await matchNews({ tenantIds: [t.tenant_id] });
});
afterFeedRun.push(() => matchNews());

// ---------------------------------------------------------------- read models
async function visibility(c: Ctx, s: Scope) {
  const soc = isSoc(c.user!.role);
  const p = await loadPrefs(s.tenantId);
  return { showPossible: soc || !!p?.newsPossible, showHostNames: soc || !!p?.newsHostNames };
}
const stateOk = (v: string | null): NewsState | null => { if (v && !STATES.includes(v as NewsState)) throw new HttpError(400, "Invalid state", "invalid_state"); return v as NewsState | null; };
const like = (q: string) => `%${esc(q)}%`;

const firstRef = (json: string | null) => { try { return (JSON.parse(json ?? "[]") as string[]).find((u) => /^https:\/\//.test(u)) ?? null; } catch { return null; } };
const NEWS_COUNT = `(SELECT COUNT(DISTINCT nc.news_id) FROM news_cves nc JOIN news_items n ON n.id = nc.news_id JOIN line_chats l ON l.chat_id = n.chat AND l.role = 'source' AND (l.tenant_id IS NULL OR l.tenant_id = m.tenant_id) WHERE nc.cve_id = m.cve)`;
const STATE_ORDER = "CASE m.state WHEN 'exact' THEN 0 WHEN 'possible' THEN 1 WHEN 'wait' THEN 2 ELSE 3 END";

route("GET", "/api/exposure/news", async (c) => {
  const s = await tenantScope(c, "news");
  const vis = await visibility(c, s);
  const state = stateOk(c.query.get("state"));
  const days = [7, 30, 90].includes(Number(c.query.get("days"))) ? Number(c.query.get("days")) : 90;
  const pageNo = Math.max(1, Number(c.query.get("page")) || 1), size = Math.min(500, Math.max(1, Number(c.query.get("pageSize")) || 25));
  const sev = (c.query.get("severity") ?? "").toUpperCase();
  if (sev && !SEV.includes(sev)) throw new HttpError(400, "Invalid severity");
  const rank = `(SELECT MIN(r.rank) FROM roll_cve r WHERE r.cve_id = m.cve AND r.cid IN ${inList(s.cids)})`;
  const base: string[] = ["m.tenant_id = ?", "m.first_seen >= ?"], bargs: (string | number)[] = [s.tenantId, now() - days * DAY];
  if (!vis.showPossible) base.push("m.state <> 'possible'");
  const counts = Object.fromEntries(STATES.map((x) => [x, 0])) as Record<string, number>;
  for (const r of await all<{ state: string; n: number }>(`SELECT m.state, COUNT(*) n FROM news_match m WHERE ${base.join(" AND ")} GROUP BY m.state`, ...bargs)) counts[r.state] = r.n;
  const conds = [...base], args = [...bargs];
  if (state) { conds.push("m.state = ?"); args.push(state); }
  if (c.query.get("kev") === "1") conds.push("EXISTS (SELECT 1 FROM kev k WHERE k.cve_id = m.cve)");
  const q = (c.query.get("q") ?? "").trim().slice(0, 100);
  if (q) { conds.push("(m.cve ILIKE ? ESCAPE '\\' OR p.title ILIKE ? ESCAPE '\\')"); args.push(like(q), like(q)); }
  if (sev) { conds.push(`m.state = 'exact' AND ${rank} = ?`); args.push(...s.cids, SEV.indexOf(sev)); }
  const from = `FROM news_match m LEFT JOIN cve_public p ON p.id = m.cve WHERE ${conds.join(" AND ")}`;
  const total = (await get<{ n: number }>(`SELECT COUNT(*) n ${from}`, ...args))!.n;
  const rows = await all<any>(
    `SELECT m.cve, m.state, m.devices, m.first_seen, m.last_changed, m.notified_at, p.title, p.cvss_score, p.published_at, p.refs_json,
            EXISTS (SELECT 1 FROM kev k WHERE k.cve_id = m.cve) AS kev, ${rank} AS rank, ${NEWS_COUNT} AS news
     ${from} ORDER BY ${STATE_ORDER}, m.last_changed DESC, m.cve LIMIT ? OFFSET ?`, ...s.cids, ...args, size, (pageNo - 1) * size);
  return {
    tenant: { id: s.tenantId, name: s.tenantName }, ...vis, counts, total, page: pageNo, pageSize: size,
    items: rows.map((r) => ({
      cve: r.cve, title: r.title, state: r.state, devices: r.devices, severity: r.state === "exact" && r.rank !== null ? SEV[r.rank] : null, cvss: r.cvss_score, kev: !!r.kev,
      publishedAt: r.published_at, firstSeen: r.first_seen, lastChanged: r.last_changed, notifiedAt: r.notified_at, newsCount: r.news, reference: firstRef(r.refs_json),
    })),
  };
});

route("GET", "/api/exposure/news/:cve", async (c) => {
  const s = await tenantScope(c, "news");
  const cve = c.params.cve.toUpperCase();
  const vis = await visibility(c, s);
  const m = await get<any>("SELECT * FROM news_match WHERE tenant_id = ? AND cve = ?", s.tenantId, cve);
  if (!m || (m.state === "possible" && !vis.showPossible)) throw new HttpError(404, "Not found"); // no row, or one this organization may not see, looks the same
  const pub = (await publicInfo([cve])).get(cve)!;
  const sevRow = await get<{ rank: number | null }>(`SELECT MIN(rank) AS rank FROM roll_cve WHERE cve_id = ? AND cid IN ${inList(s.cids)}`, cve, ...s.cids);
  const hosts = m.state === "exact" && vis.showHostNames
    ? (await all<{ aid: string; hostname: string | null; rank: number }>(`SELECT aid, MAX(hostname) AS hostname, MIN(CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END) AS rank
        FROM findings_t WHERE cid IN ${inList(s.cids)} AND cve_id = ? GROUP BY aid ORDER BY rank, hostname, aid LIMIT 200`, ...s.cids, cve)).map((r) => ({ aid: r.aid, hostname: r.hostname, severity: SEV[r.rank] }))
    : null;
  const poss = m.state === "possible" ? await possibleHits(s.cids, cve) : null;
  return {
    tenant: { id: s.tenantId, name: s.tenantName }, cve, state: m.state, devices: m.devices, severity: m.state === "exact" && sevRow?.rank != null ? SEV[sevRow.rank] : null,
    firstSeen: m.first_seen, lastChanged: m.last_changed, notifiedAt: m.notified_at,
    public: { title: pub.title, description: pub.description, publishedAt: pub.publishedAt, cvss: pub.cvss, references: pub.references }, kev: pub.kev,
    hostsHidden: m.state === "exact" && !vis.showHostNames, hosts,
    possible: poss ? { products: poss.products, software: poss.software.map(({ name, vendor, devices }) => ({ name, vendor, devices })) } : null,
    drawer: `/api/exposure/vulnerabilities/${encodeURIComponent(cve)}`,
  };
});

/** The SOC's view across organizations: who is hit by which news CVE. Super admin only. */
route("GET", "/api/exposure/news-soc", { roles: ["super_admin"] }, async (c) => {
  const state = stateOk(c.query.get("state"));
  const days = [7, 30, 90].includes(Number(c.query.get("days"))) ? Number(c.query.get("days")) : 90;
  const pageNo = Math.max(1, Number(c.query.get("page")) || 1), size = Math.min(200, Math.max(1, Number(c.query.get("pageSize")) || 25));
  const q = (c.query.get("q") ?? "").trim().slice(0, 100);
  await audit({ actor: c.user, action: "read:news-soc", result: "allowed", ip: c.ip });
  const conds = ["m.first_seen >= ?"], args: (string | number)[] = [now() - days * DAY];
  if (q) { conds.push("(m.cve ILIKE ? ESCAPE '\\' OR p.title ILIKE ? ESCAPE '\\')"); args.push(like(q), like(q)); }
  const rows = await all<any>(
    `SELECT m.tenant_id, t.name AS tenant, m.cve, m.state, m.devices, m.first_seen, m.notified_at, p.title, p.cvss_score, p.published_at, EXISTS (SELECT 1 FROM kev k WHERE k.cve_id = m.cve) AS kev
     FROM news_match m JOIN tenants t ON t.id = m.tenant_id LEFT JOIN cve_public p ON p.id = m.cve WHERE ${conds.join(" AND ")}`, ...args);
  const counts = Object.fromEntries(STATES.map((x) => [x, 0])) as Record<string, number>;
  const by = new Map<string, any>();
  for (const r of rows) {
    counts[r.state]++;
    if (state && r.state !== state) continue;
    const e = by.get(r.cve) ?? { cve: r.cve, title: r.title, kev: !!r.kev, cvss: r.cvss_score, publishedAt: r.published_at, firstSeen: r.first_seen, exactTenants: 0, possibleTenants: 0, totalDevices: 0, tenants: [] };
    e.firstSeen = Math.min(e.firstSeen, r.first_seen);
    if (r.state === "exact") { e.exactTenants++; e.totalDevices += r.devices; } else if (r.state === "possible") e.possibleTenants++;
    e.tenants.push({ tenantId: r.tenant_id, tenant: r.tenant, state: r.state, devices: r.devices, notifiedAt: r.notified_at });
    by.set(r.cve, e);
  }
  const items = [...by.values()].sort((a, b) => b.exactTenants - a.exactTenants || b.possibleTenants - a.possibleTenants || b.firstSeen - a.firstSeen || a.cve.localeCompare(b.cve));
  const page = items.slice((pageNo - 1) * size, pageNo * size);
  const ids = page.map((e) => e.cve);
  const src = ids.length ? await all<{ cve_id: string; urls_json: string; n: number }>(`SELECT nc.cve_id, n.urls_json, n.received_at AS n FROM news_cves nc JOIN news_items n ON n.id = nc.news_id WHERE nc.cve_id IN ${inList(ids)} ORDER BY n.received_at DESC`, ...ids) : [];
  for (const e of page) {
    const mine = src.filter((r) => r.cve_id === e.cve);
    e.newsCount = mine.length;
    e.sources = [...new Set(mine.flatMap((r) => { try { return JSON.parse(r.urls_json) as string[]; } catch { return []; } }))].slice(0, 5);
    e.tenants.sort((a: any, b: any) => STATES.indexOf(a.state) - STATES.indexOf(b.state) || b.devices - a.devices);
  }
  return { counts, total: items.length, page: pageNo, pageSize: size, items: page };
});
