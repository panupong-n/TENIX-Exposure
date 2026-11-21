/* eslint-disable @typescript-eslint/no-explicit-any -- test plumbing over untyped SQL rows and API JSON */
import { expect, type Locator, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { env } from "./fixtures";
import { testDatabaseUrl } from "./test-db";

const here = dirname(fileURLToPath(import.meta.url));
const { Client } = createRequire(join(here, "../../server/package.json"))("pg");

// ------------------------------------------------------------------ database (the source of truth for every number)
/** Runs one query in the throwaway schema the e2e server uses. COUNT(*) must be cast to ::int by the caller. */
export async function sql<T = any>(text: string, args: unknown[] = []): Promise<T[]> {
  const { schema } = JSON.parse(readFileSync(join(here, ".auth/env.json"), "utf8")) as { schema: string };
  if (!/^e2e_[a-z]+$/.test(schema)) throw new Error(`refusing to query schema ${schema}`);
  const c = new Client({ connectionString: testDatabaseUrl() });
  await c.connect();
  try {
    await c.query(`SET search_path TO ${schema}`);
    return (await c.query(text, args)).rows;
  } finally {
    await c.end();
  }
}

export type TKey = "alpha" | "beta" | "empty";
export type Source = "" | "endpoint" | "external";
export const SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"] as const;
export const SEV_LABEL: Record<string, string> = { CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low", NONE: "Informational" };
export const RANK = "CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END";
export const TENANT_NAME: Record<TKey, string> = { alpha: "Alpha Corp", beta: "Beta Ltd", empty: "Empty Inc" };
export const fmt = (n: number) => n.toLocaleString("en-US");

// "external" = internet-facing assets found by Falcon EASM, "endpoint" = everything else (devices with the sensor)
const SRC: Record<Source, string> = { "": "TRUE", endpoint: "(provider IS NULL OR provider NOT ILIKE '%EASM%')", external: "provider ILIKE '%EASM%'" };
/** SQL condition: findings of the tenant's CIDs (looked up from tenant_cids, not from the server code) and the source. */
export const where = (t: TKey, s: Source = "") => `cid IN (SELECT cid FROM tenant_cids WHERE tenant_id = '${env().tenants[t]}') AND ${SRC[s]}`;
export const tenantId = (t: TKey) => env().tenants[t];

export async function overviewTruth(t: TKey, s: Source = "", top = 10) {
  const w = where(t, s);
  const [tot] = await sql(`SELECT COUNT(*)::int findings, COUNT(DISTINCT cid||aid)::int devices, COUNT(DISTINCT cve_id)::int cves,
    COUNT(*) FILTER (WHERE severity = 'CRITICAL')::int critical, COUNT(DISTINCT CASE WHEN exploit_status >= 60 THEN cve_id END)::int exploited FROM findings WHERE ${w}`);
  const bySev = Object.fromEntries((await sql(`SELECT severity, COUNT(*)::int n FROM findings WHERE ${w} GROUP BY 1`)).map((r) => [r.severity, r.n]));
  const sev = SEV.map((x) => (bySev[x] ?? 0) as number);
  const topCves = await sql<{ cve_id: string; hosts: number }>(
    `SELECT cve_id, COUNT(DISTINCT cid||aid)::int hosts FROM findings WHERE ${w} GROUP BY cve_id ORDER BY MIN(${RANK}), hosts DESC, cve_id LIMIT ${top}`);
  const topDevices = await sql<{ aid: string; hostname: string | null; platform: string | null; cves: number; critical: number; high: number; medium: number }>(
    `SELECT aid, MAX(hostname) AS hostname, MAX(platform) AS platform, COUNT(DISTINCT cve_id)::int AS cves, COUNT(DISTINCT CASE WHEN severity = 'CRITICAL' THEN cve_id END)::int AS critical,
     COUNT(DISTINCT CASE WHEN severity = 'HIGH' THEN cve_id END)::int AS high, COUNT(DISTINCT CASE WHEN severity = 'MEDIUM' THEN cve_id END)::int AS medium
     FROM findings WHERE ${w} GROUP BY cid, aid ORDER BY critical DESC, cves DESC, hostname, aid LIMIT ${top}`);
  return { ...tot, sev, topCves, topDevices } as { findings: number; devices: number; cves: number; critical: number; exploited: number; sev: number[]; topCves: typeof topCves; topDevices: typeof topDevices };
}

export const vulnRows = (t: TKey, s: Source, page: number, extra = "") => sql<{ cve_id: string; sev: string; hosts: number; findings: number; kind: string | null; score: number | null; kev: boolean; published: string | null; product: string | null }>(
  `SELECT cve_id, (ARRAY['CRITICAL','HIGH','MEDIUM','LOW','NONE'])[MIN(${RANK}) + 1] AS sev, COUNT(DISTINCT cid||aid)::int hosts, COUNT(*)::int findings, MAX(kind) kind, MAX(base_score) score,
          COALESCE((SELECT cisa_kev = 1 FROM cves WHERE id = cve_id), false) AS kev, (SELECT published_at FROM cves WHERE id = cve_id) AS published, MAX(product) AS product
   FROM findings WHERE ${where(t, s)} ${extra} GROUP BY cve_id ORDER BY MIN(${RANK}), hosts DESC, cve_id LIMIT 25 OFFSET ${(page - 1) * 25}`);
export const vulnTotal = async (t: TKey, s: Source, extra = "") => (await sql(`SELECT COUNT(DISTINCT cve_id)::int n FROM findings WHERE ${where(t, s)} ${extra}`))[0].n as number;

export const deviceRows = (t: TKey, s: Source, page: number, extra = "") => sql<{ aid: string; hostname: string | null; platform: string | null; ip: string | null; ext: string | null; cves: number; critical: number; high: number; medium: number; exploited: number }>(
  `SELECT aid, MAX(hostname) AS hostname, MAX(platform) AS platform, MAX(local_ip) AS ip, MAX(external_ip) AS ext, COUNT(DISTINCT cve_id)::int AS cves,
          COUNT(DISTINCT CASE WHEN severity = 'CRITICAL' THEN cve_id END)::int AS critical, COUNT(DISTINCT CASE WHEN severity = 'HIGH' THEN cve_id END)::int AS high,
          COUNT(DISTINCT CASE WHEN severity = 'MEDIUM' THEN cve_id END)::int AS medium, COUNT(DISTINCT CASE WHEN exploit_status >= 60 THEN cve_id END)::int AS exploited
   FROM findings WHERE ${where(t, s)} ${extra} GROUP BY cid, aid ORDER BY critical DESC, cves DESC, hostname, aid LIMIT 25 OFFSET ${(page - 1) * 25}`);
export const deviceTotal = async (t: TKey, s: Source, extra = "") => (await sql(`SELECT COUNT(*)::int n FROM (SELECT 1 FROM findings WHERE ${where(t, s)} ${extra} GROUP BY cid, aid) x`))[0].n as number;

export async function cveTruth(t: TKey, id: string) {
  const w = `${where(t)} AND cve_id = '${id}'`;
  const [a] = await sql(`SELECT COUNT(DISTINCT cid||aid)::int devices, COUNT(*)::int findings, MAX(kind) kind, (ARRAY['CRITICAL','HIGH','MEDIUM','LOW','NONE'])[MIN(${RANK}) + 1] sev FROM findings WHERE ${w}`);
  const products = await sql<{ product: string | null; n: number }>(`SELECT product, COUNT(DISTINCT cid||aid)::int n FROM findings WHERE ${w} GROUP BY product ORDER BY n DESC, product LIMIT 8`);
  const [info] = await sql(`SELECT * FROM cves WHERE id = $1`, [id]);
  return { ...a, products, info: info as any, aids: (await sql<{ aid: string }>(`SELECT DISTINCT aid FROM findings WHERE ${w}`)).map((r) => r.aid) } as {
    devices: number; findings: number; kind: string | null; sev: string; products: { product: string | null; n: number }[]; info: any; aids: string[];
  };
}

export async function deviceTruth(t: TKey, aid: string) {
  const w = `${where(t)} AND aid = '${aid}'`;
  const bySev = Object.fromEntries((await sql(`SELECT severity, COUNT(*)::int n FROM findings WHERE ${w} GROUP BY 1`)).map((r) => [r.severity, r.n]));
  const counts = SEV.map((x) => (bySev[x] ?? 0) as number);
  const [info] = await sql(`SELECT MAX(hostname) hostname, MAX(platform) platform, MAX(local_ip) ip, MAX(external_ip) ext, MAX(cid) cid FROM findings WHERE ${w}`);
  const products = await sql<{ product: string; total: number; rank: number }>(
    `SELECT COALESCE(product, '') product, COUNT(*)::int total, MIN(${RANK}) rank FROM findings WHERE ${w} GROUP BY 1 ORDER BY rank, total DESC, product`);
  const leaves = await sql<{ product: string; cve_id: string }>(
    `SELECT product, cve_id FROM (SELECT COALESCE(product, '') product, cve_id, ROW_NUMBER() OVER (PARTITION BY COALESCE(product, '') ORDER BY ${RANK}, base_score DESC NULLS LAST, cve_id) rn
       FROM findings WHERE ${w}) x WHERE rn <= 3`);
  return { counts, total: counts.reduce((a, b) => a + b, 0), info: info as any, products, leaves };
}

// ------------------------------------------------------------------ v2 truth (endpoint findings only; EASM and suppressed rows are in no number)
// The tier rule of the API (server/src/rollup.ts), written again here in SQL on purpose: the UI is compared to the database, not to the code under test.
const KEVF = "(cve_id IN (SELECT id FROM cves WHERE cisa_kev = 1) OR cve_id IN (SELECT cve_id FROM kev))";
const TIER = `CASE WHEN ${KEVF} OR exploit_status >= 60 OR (severity = 'CRITICAL' AND exprt = 'CRITICAL') THEN 1 WHEN severity = 'CRITICAL' OR exprt IN ('HIGH', 'CRITICAL') OR exploit_status = 30 THEN 2 ELSE 3 END`;
const EXPRT_LVL = "CASE UPPER(exprt) WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END";
/** The tenant's endpoint findings with their tier (1..3) and whether the CVE is in CISA's list. */
const tiered = (t: TKey) => `(SELECT *, ${TIER} AS tier, ${KEVF} AS kevf FROM findings WHERE ${where(t)} AND (provider IS NULL OR provider NOT ILIKE '%EASM%') AND suppressed = 0) x`;
const cidsOf = (t: TKey) => `(SELECT cid FROM tenant_cids WHERE tenant_id = '${env().tenants[t]}')`;
export const EXPRT_LABEL = ["–", "Low", "Medium", "High", "Critical"];
export const EXPLOIT_LABEL: Record<string, string> = { "0": "Unproven", "30": "Medium", "60": "High", "90": "Critical" };

/** One row per host the Devices list knows: the inventory plus hosts only the findings know, with the numbers of the list. */
export const HOSTS_SQL = (t: TKey) => `SELECT COALESCE(h.cid, f.cid) cid, COALESCE(h.aid, f.aid) aid, COALESCE(h.hostname, f.hostname) hostname, COALESCE(h.os_version, h.platform, f.platform) os, COALESCE(h.platform, f.platform) platform, h.local_ip, h.external_ip, h.product_type,
    COALESCE(f.p1, 0) p1, COALESCE(f.p2, 0) p2, COALESCE(f.p3, 0) p3, COALESCE(f.critical, 0) critical, COALESCE(f.kev, 0) kev, COALESCE(f.findings, 0) findings, f.rank, COALESCE(f.inet, false) inet, h.last_seen, h.dup_group IS NOT NULL dup,
    lower(COALESCE(h.criticality, '')) = 'critical' crit
  FROM (SELECT * FROM hosts WHERE cid IN ${cidsOf(t)}) h FULL JOIN (
    SELECT cid, aid, MAX(hostname) hostname, MAX(platform) platform, (COUNT(*) FILTER (WHERE tier = 1))::int p1, (COUNT(*) FILTER (WHERE tier = 2))::int p2, (COUNT(*) FILTER (WHERE tier = 3))::int p3,
      (COUNT(DISTINCT cve_id) FILTER (WHERE severity = 'CRITICAL'))::int critical, (COUNT(DISTINCT cve_id) FILTER (WHERE kevf))::int kev, COUNT(*)::int findings,
      MIN(CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END) rank, COALESCE(BOOL_OR(internet_exposure = 'Yes'), false) inet
    FROM ${tiered(t)} GROUP BY cid, aid) f ON h.cid = f.cid AND h.aid = f.aid`;
export type HostTruth = { cid: string; aid: string; hostname: string | null; os: string | null; platform: string | null; local_ip: string | null; external_ip: string | null; product_type: string | null; p1: number; p2: number; p3: number;
  critical: number; kev: number; findings: number; rank: number | null; inet: boolean; last_seen: number | null; dup: boolean; crit: boolean };
/** Hosts in the order of the default sort (P1, Critical CVEs, business-critical, internet-facing). Ties past that are by name, so callers compare the sort keys, not the names. */
export const hostsTruth = (t: TKey, extra = "") => sql<HostTruth>(`SELECT * FROM (${HOSTS_SQL(t)}) q ${extra ? `WHERE ${extra}` : ""} ORDER BY p1 DESC, critical DESC, crit DESC, inet DESC, hostname, aid`);

export async function overviewV2(t: TKey) {
  const [h] = await sql<{ p1: number; hostsP1: number; p1Cves: number; p2: number; p3: number }>(
    `SELECT (COUNT(*) FILTER (WHERE tier = 1))::int p1, (COUNT(DISTINCT aid) FILTER (WHERE tier = 1))::int "hostsP1", (COUNT(DISTINCT cve_id) FILTER (WHERE tier = 1))::int "p1Cves",
            (COUNT(*) FILTER (WHERE tier = 2))::int p2, (COUNT(*) FILTER (WHERE tier = 3))::int p3 FROM ${tiered(t)}`);
  const inventory = (await sql(`SELECT COUNT(*)::int n FROM hosts WHERE cid IN ${cidsOf(t)}`))[0].n as number;
  const sev = Object.fromEntries((await sql(`SELECT severity, COUNT(*)::int n FROM ${tiered(t)} GROUP BY 1`)).map((r) => [r.severity, r.n])) as Record<string, number>;
  return { ...h, hostsTotal: inventory, sev: SEV.map((x) => sev[x] ?? 0) };
}

/** Fixes (one per set of recommended actions) of P1 and P2 findings with their P1 findings, most P1 first: the list "What to fix first" is ranked by it. */
export const fixTruth = (t: TKey) => sql<{ p1: number }>(
  `SELECT (COUNT(*) FILTER (WHERE tier = 1))::int p1 FROM ${tiered(t)} WHERE tier <= 2 GROUP BY COALESCE(remediation, '') || '|' || COALESCE(remediation_json, '') ORDER BY p1 DESC`);

/** What the Vulnerabilities list shows per CVE, in the order of the default "Priority" sort. `having` filters the CVEs (SQL on the aggregates), `where` the findings. */
export const vulnsTruth = (t: TKey, o: { having?: string; where?: string; limit?: number; offset?: number } = {}) => sql<{ cve_id: string; tier: number; sev: string; score: number | null; lvl: number; ex: number | null; kev: boolean; hosts: number; findings: number; kind: string | null; product: string | null }>(
  `SELECT cve_id, MIN(tier)::int tier, (ARRAY['CRITICAL','HIGH','MEDIUM','LOW','NONE'])[MIN(${RANK}) + 1] sev, MAX(base_score) score, MAX(${EXPRT_LVL})::int lvl, MAX(exploit_status) ex, BOOL_OR(kevf) kev,
          COUNT(DISTINCT cid || aid)::int hosts, COUNT(*)::int findings, MAX(kind) kind, MAX(product) product
   FROM ${tiered(t)} ${o.where ? `WHERE ${o.where}` : ""} GROUP BY cve_id ${o.having ? `HAVING ${o.having}` : ""}
   ORDER BY MIN(tier), BOOL_OR(kevf) DESC, MAX(${EXPRT_LVL}) DESC, MAX(exploit_status) DESC NULLS LAST, COALESCE(BOOL_OR(internet_exposure = 'Yes'), false) DESC, MAX(base_score) DESC NULLS LAST,
            COUNT(DISTINCT cid || aid) DESC, MIN(first_seen) ASC NULLS LAST, cve_id ${o.limit ? `LIMIT ${o.limit} OFFSET ${o.offset ?? 0}` : ""}`);
export const vulnsTotal = async (t: TKey, o: { having?: string; where?: string } = {}) => (await vulnsTruth(t, o)).length;
/** The facets of the Vulnerabilities heading: CVEs per tier and CVEs in the KEV list. */
export async function vulnFacets(t: TKey) {
  const [r] = await sql(`SELECT (COUNT(DISTINCT cve_id) FILTER (WHERE tier = 1))::int "P1", (COUNT(DISTINCT cve_id) FILTER (WHERE tier = 2))::int "P2", (COUNT(DISTINCT cve_id) FILTER (WHERE tier = 3))::int "P3", (COUNT(DISTINCT cve_id) FILTER (WHERE kevf))::int kev FROM ${tiered(t)}`);
  return r as { P1: number; P2: number; P3: number; kev: number };
}
/** One host as the device drawer shows it: findings per tier, per severity, and its CVEs (worst tier of each). */
export async function hostDetail(t: TKey, aid: string) {
  const w = `aid = '${aid}'`;
  const [c] = await sql(`SELECT (COUNT(*) FILTER (WHERE tier = 1))::int p1, (COUNT(*) FILTER (WHERE tier = 2))::int p2, (COUNT(*) FILTER (WHERE tier = 3))::int p3 FROM ${tiered(t)} WHERE ${w}`);
  const bySev = Object.fromEntries((await sql(`SELECT severity, COUNT(*)::int n FROM ${tiered(t)} WHERE ${w} GROUP BY 1`)).map((r) => [r.severity, r.n]));
  const cves = await sql<{ cve_id: string; tier: number; kev: boolean }>(`SELECT cve_id, MIN(tier)::int tier, BOOL_OR(kevf) kev FROM ${tiered(t)} WHERE ${w} GROUP BY cve_id ORDER BY MIN(tier), BOOL_OR(kevf) DESC, cve_id`);
  // a fix is one set of recommended actions; findings without any share the "no fix" entry. Only P1 and P2 findings have fixes.
  const fixes = (await sql(`SELECT COUNT(DISTINCT COALESCE(remediation, '') || '|' || COALESCE(remediation_json, ''))::int n FROM ${tiered(t)} WHERE ${w} AND tier <= 2`))[0].n as number;
  const [info] = await sql(`SELECT hostname, os, local_ip, external_ip, product_type, cid FROM (${HOSTS_SQL(t)}) q WHERE aid = '${aid}'`);
  return { fixes, tiers: [c.p1, c.p2, c.p3] as number[], counts: SEV.map((x) => (bySev[x] ?? 0) as number), cves, info: info as { hostname: string | null; os: string | null; local_ip: string | null; external_ip: string | null; product_type: string | null; cid: string } };
}
/** The public text of a CVE: what the CVE Program published, else the description Falcon sent. */
export async function cveText(id: string) {
  const [r] = await sql<{ d: string | null }>("SELECT COALESCE(NULLIF((SELECT description FROM cve_public WHERE id = $1), ''), (SELECT description FROM cves WHERE id = $1)) d", [id]);
  return r?.d ?? "";
}

// ------------------------------------------------------------------ page helpers
export const main = (page: Page) => page.locator("main");
/** The page body, or the Setting Center drawer (/settings?setting=...) that holds the old Tenants / Team / Integrations / Audit pages. */
export const pane = (page: Page) => page.locator('main, [data-slot="sheet-content"]');
/** The card (rounded box) that contains the heading. */
export const card = (page: Page, heading: string) => page.locator("h3", { hasText: heading }).locator("xpath=ancestor::*[contains(@class,'rounded-xl')][1]");
export const stat = (page: Page, title: string) => page.locator("main p", { hasText: new RegExp(`^${title}$`) }).locator("xpath=following-sibling::p[1]");
export const drawer = (page: Page) => page.getByRole("dialog");
export const num = (s: string | null) => Number((s ?? "").replace(/[^\d]/g, ""));

/** On a phone the list filters sit behind a "Filters" button; opens them (nothing to do on a wider screen or when already open). */
export async function openFilters(page: Page) {
  const b = page.locator("main").getByRole("button", { name: /^Filters/ });
  if ((await b.count()) && (await b.isVisible()) && (await b.getAttribute("aria-expanded")) !== "true") await b.click();
}
/** Clicks a combobox (Radix/Base UI select) and picks an option by its visible name. */
export async function pick(page: Page, combo: Locator, option: string | RegExp) {
  await openFilters(page);
  await combo.click();
  await page.getByRole("option", { name: option, exact: typeof option === "string" }).click();
}
export const sourceSelect = (page: Page) => page.getByRole("combobox", { name: "Source" });
export const SOURCE_LABEL: Record<Source, string> = { "": "All sources", endpoint: "Endpoints", external: "External assets" };

/** Waits for the next GET of an API path (substring match) whose query contains every given fragment. */
export const apiResponse = (page: Page, path: string, ...frags: string[]) =>
  page.waitForResponse((r) => r.request().method() === "GET" && r.url().includes(path) && frags.every((f) => r.url().includes(f)));

export type Rec = Record<string, string> & { __id: string; __text: string };
const squash = (s: string | null | undefined) => (s ?? "").replace(/\s+/g, " ").trim();
/** Rows of the first table inside the scope as { column header: cell text }; __id is the text of the first button of the first cell. */
export const tableRecords = (scope: Locator) => scope.locator("table").first().evaluate((t) => {
  const sq = (s: string | null | undefined) => (s ?? "").replace(/\s+/g, " ").trim();
  const heads = [...t.querySelectorAll("thead th")].map((x) => sq(x.textContent));
  return [...t.querySelectorAll("tbody tr")].map((tr) => {
    const tds = [...tr.querySelectorAll("td")];
    // the name button of the row (the watch star in front of it has no text)
    const name = [...tr.querySelectorAll("button")].map((b) => sq(b.textContent)).find(Boolean);
    const o: Record<string, string> = { __id: name ?? "", __text: sq(tr.textContent) };
    tds.forEach((td, i) => { o[heads[i] ?? String(i)] = sq(td.textContent); });
    return o;
  });
}) as Promise<Rec[]>;
/** What a list page (Vulnerabilities, Devices) shows right now: the table on a desktop, the card list on a phone. */
export async function listRecords(page: Page): Promise<(Rec & { mobile?: string })[]> {
  if (await main(page).locator("table").locator("visible=true").count()) return tableRecords(main(page));
  return main(page).locator("ul.divide-y > li").evaluateAll((lis) => lis.map((li) => {
    const sq = (s: string | null | undefined) => (s ?? "").replace(/\s+/g, " ").trim();
    return { __id: sq(li.querySelector("button .break-all, button .truncate")?.textContent), __text: sq(li.textContent), mobile: "1" };
  })) as Promise<Rec[]>;
}
/** The first clickable CVE, device or software name of a list page (the name button in a table row on a desktop, the card on a phone; the watch star is skipped). */
export const firstItem = (page: Page) => main(page).locator("tbody tr td button:not([aria-pressed]), ul.divide-y > li > button:not([aria-pressed])").locator("visible=true").first();
export const tableRows = (scope: Locator) => scope.locator("tbody tr");
export async function cellTexts(row: Locator) {
  return (await row.locator("td").allInnerTexts()).map((x) => x.replace(/\s+/g, " ").trim());
}

/** All apexcharts donut slice values, in series order. */
export const pieValues = (page: Page) => page.evaluate(() => [...document.querySelectorAll(".apexcharts-pie-area")].map((e) => Number(e.getAttribute("data:value"))));

/** Nodes of a drawn SVG graph: the title (full name), the visible texts, and whether the node is clickable. */
export const svgNodes = (svg: Locator) => svg.evaluate((el) =>
  [...el.querySelectorAll("g")].filter((g) => g.querySelector(":scope > rect")).map((g) => ({
    title: g.querySelector(":scope > title")?.textContent ?? "", texts: [...g.querySelectorAll(":scope > text")].map((t) => t.textContent ?? ""), link: g.getAttribute("role") === "link",
  })));

export async function expectNoCidInDom(page: Page, cids: string[]) {
  const html = await page.content();
  for (const c of cids) expect(html, `CID ${c} found in the DOM`).not.toContain(c);
}

/** Collects every API response body the page loads, so tests can assert nothing forbidden ever travelled. */
export function recordApi(page: Page) {
  const bodies: { url: string; status: number; text: string }[] = [];
  page.on("response", async (r) => {
    if (!r.url().includes("/api/")) return;
    bodies.push({ url: r.url().replace(/^https?:\/\/[^/]+/, ""), status: r.status(), text: await r.text().catch(() => "") });
  });
  return bodies;
}

/** Waits until the page has no skeleton or busy markers and the network has been quiet, so DOM reads are stable. */
export async function settle(page: Page) {
  await page.waitForLoadState("networkidle");
  await expect(page.locator('[aria-busy="true"]')).toHaveCount(0);
}

/** Makes the (super admin) viewer start on this tenant, like picking it in the header switcher would. Call before the first goto. */
export async function useTenant(page: Page, t: TKey) {
  await page.addInitScript(([k, v]) => localStorage.setItem(k, v), ["tenix.org", env().tenants[t]]);
}
