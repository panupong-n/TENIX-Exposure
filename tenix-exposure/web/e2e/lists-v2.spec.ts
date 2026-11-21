/* eslint-disable @typescript-eslint/no-explicit-any -- mock API payloads */
import { createServer, type Server } from "node:http";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { extname, join } from "node:path";
import { expect, test, type Page } from "@playwright/test";

// Lists and drawers of the v2 design (vulnerabilities, devices, software, fix drawer), against route-intercepted API mocks (contract A / B).
// Self-contained: it serves the built English UI (E2E_DIST, default dist-e2e) from its own static server and mocks the whole API, session included,
// so it runs without the e2e stack: `E2E_DIST=dist-fe2 npx playwright test -c playwright.lists.config.ts`. Screenshots go to e2e/shots/lists-v2-*.png.
const SHOTS = join(import.meta.dirname, "shots");
const now = Date.now();
const DAY = 86_400_000;
const complete = (extra: object = {}) => ({ state: "complete", dataAsOf: now - 600_000, lastRunAt: now, reason: null, coverage: { held: 1_085_590, falconTotal: 16_700_573, priorityHeld: 1_085_590, priorityTotal: 1_085_590, fullPass: true, mode: "priority" }, ...extra });

const vuln = (i: number, o: any = {}) => ({
  cveId: `CVE-2025-${1000 + i}`, tier: i < 3 ? "P1" : i < 6 ? "P2" : "P3", severity: i % 2 ? "CRITICAL" : "HIGH", baseScore: 9.8 - (i % 5) * 0.4, exprt: i % 3 ? "CRITICAL" : "HIGH", exploitStatus: i < 3 ? 90 : 30,
  kev: i < 2, kevDueDate: i < 2 ? "2026-12-09" : null, overdue: i === 0, whyTier: i < 2 ? ["kev", "exploited"] : i === 2 ? ["critical_exprt"] : i < 6 ? ["critical"] : [],
  hosts: 800 - i * 50, internetHosts: i < 2 ? 14 : 0, findings: 800, p1Findings: 800, kind: "Vulnerability", product: "Microsoft Edge 119.0",
  firstSeen: now - 40 * DAY, ageDays: 40, fix: { id: "184467440737", title: "Update Microsoft Edge to 120.0.2210.61", fixes: 2 }, published: "2025-01-10", ...o,
});
const fix = (i: number, o: any = {}) => ({
  id: String(184467440737 + i), title: i === 3 ? null : `Update Microsoft Edge to 120.0.${i}`, action: "Apply the latest cumulative update", link: "https://catalog.example/kb1", product: "Microsoft Edge 119.0", vendor: "Microsoft", noFix: i === 3,
  p1: 5210 - i * 400, p2: 120, p3: 0, findings: 5330, cves: 31, p1Cves: 30, kevCves: i < 2 ? 12 : 0, hosts: 812 - i * 30, p1Hosts: 800, internetHosts: i < 2 ? 14 : 0,
  severity: "CRITICAL", exprt: "CRITICAL", firstSeen: now - 40 * DAY, ageDays: 40, impactShare: 0.0173 - i * 0.002, ...o,
});
const host = (i: number, o: any = {}) => ({
  key: `aid${i}`, aid: `aid${i}`, inInventory: true, hostname: i === 1 ? "สมชาย-PC" : `WSR${23559 + i}`, platform: "Windows", osVersion: "Windows 11", osBuild: "22631", productType: i % 4 === 0 ? "Server" : "Workstation", criticality: "critical",
  localIp: `10.1.2.${i}`, externalIp: null, agentVersion: "8.11.21510.0", machineDomain: "corp.example.com", site: "HQ", groups: ["Servers", "Finance"], groupsMore: 0, tags: [],
  firstSeen: now - 400 * DAY, lastSeen: i === 2 ? now - 12 * DAY : now - 3_600_000, daysSinceSeen: i === 2 ? 12 : 0.1, stale: i === 2 ? "stale7" : "fresh",
  duplicate: i === 3 ? { role: "older", staleTwin: true, reason: "hostname", newerAid: "aid9" } : null, contained: false, reducedFunctionality: false, internetFacing: i % 2 === 0,
  p1: 12 - i, p2: 40, p3: 0, findings: 52, critical: 3, kevCves: 2, exploited: 4, fixes: 5, worstSeverity: i === 5 ? null : "CRITICAL", tier: "P1", watched: false, ...o,
});
const sw = (i: number, o: any = {}) => ({ key: Buffer.from(JSON.stringify(["application", "Microsoft", `Edge ${i}`])).toString("base64url"), type: "application", vendor: "Microsoft", name: `Microsoft Edge ${i}`, category: "Browser", devices: 800 - i * 10, versions: 4, firstSeen: now - 300 * DAY, suspicious: i === 2, latest: "120.0.2210.61", p1Cves: 30 - i, kevCves: i < 2 ? 4 : 0, ...o });

export interface MockOpts { total?: number; completeness?: object; empty?: boolean; huge?: boolean; delay?: number }

let server: Server;
let base = "";
test.beforeAll(async () => {
  const root = join(import.meta.dirname, "..", process.env.E2E_DIST ?? "dist-e2e");
  const types: Record<string, string> = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".woff2": "font/woff2", ".json": "application/json", ".png": "image/png" };
  server = createServer((req, res) => {
    const path = join(root, decodeURIComponent((req.url ?? "/").split("?")[0]));
    const file = path.startsWith(root) && existsSync(path) && extname(path) ? path : join(root, "index.html"); // single-page app: unknown paths get index.html
    res.writeHead(200, { "Content-Type": types[extname(file)] ?? "application/octet-stream" });
    res.end(readFileSync(file));
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});
test.afterAll(() => { server.close(); });

/** The signed-in SOC user and one organization. */
async function session(page: Page, width: number) {
  await page.setViewportSize({ width, height: 900 });
  await page.route("**/api/auth/me", (r) => r.fulfill({ json: { user: { id: "u1", email: "soc@e2e.test", name: "SOC", role: "super_admin", soc: true, manager: true, tenants: [], totpEnabled: false } } }));
  await page.route("**/api/tenants", (r) => r.fulfill({ json: { tenants: [{ id: "t1", name: "Alpha Corp", role: "super_admin", cids: ["c1"] }] } }));
  await page.route("**/api/**", (r) => (r.request().url().includes("/api/exposure/") || r.request().url().includes("/api/auth/me") || /\/api\/tenants$/.test(r.request().url()) ? r.fallback() : r.fulfill({ json: {} })));
}
/** The first element with this text that is on screen (lists render a card list for phones and a table for desktops). */
const seen = (page: Page, text: string | RegExp, exact = false) => page.getByText(text, { exact }).locator("visible=true").first();
/** A drawer never grows wider than the screen and nothing inside it scrolls sideways (tables scroll inside their own box). */
const drawerFits = async (page: Page) => {
  await expect.poll(async () => { const b = await page.getByRole("dialog").boundingBox(); return b ? b.x + b.width : 9999; }, { message: "drawer slide-in" }).toBeLessThanOrEqual(page.viewportSize()!.width + 1);
  const d = await page.getByRole("dialog").evaluate((el) => {
    const r = el.getBoundingClientRect();
    const wide = [...el.querySelectorAll("*")].filter((e) => e.getBoundingClientRect().right > r.right + 1 && !e.closest(".overflow-x-auto")).map((e) => `${e.tagName}.${(e as HTMLElement).className.toString().slice(0, 60)}`).slice(0, 3);
    return { right: r.right, left: r.left, vw: window.innerWidth, wide };
  });
  expect(d.right, `drawer right edge ${JSON.stringify(d)}`).toBeLessThanOrEqual(d.vw + 1);
};
const go = async (page: Page, path: string) => { await page.goto(base + path); };

/** One handler for the whole API of the lists; anything else answers 404 so a missing mock is visible. */
async function mockApi(page: Page, o: MockOpts = {}) {
  const comp = complete(o.completeness);
  await page.route("**/api/exposure/**", async (r) => {
    const u = new URL(r.request().url());
    const p = u.pathname.replace("/api/exposure/", "");
    const json = (body: unknown, status = 200) => r.fulfill({ status, json: body });
    if (o.delay) await new Promise((res) => setTimeout(res, o.delay));
    if (p === "v2/vulnerabilities") {
      if (o.empty) return json({ total: 0, page: 1, pageSize: 25, rows: [], facets: { P1: 0, P2: 0, P3: 0, kev: 0 }, completeness: comp });
      const q = u.searchParams.get("q");
      const rows = q?.startsWith("CVE-") ? [vuln(0)] : Array.from({ length: 12 }, (_, i) => vuln(i, o.huge ? { hosts: 16_693_578, findings: 16_693_578, internetHosts: 1_234_567 } : {}));
      return json({ total: o.total ?? 11_000, page: Number(u.searchParams.get("page") ?? 1), pageSize: 25, rows, facets: { P1: 1412, P2: 6000, P3: 3588, kev: 210 }, completeness: comp });
    }
    if (p === "v2/fixes") return json({ total: 214, page: 1, pageSize: 25, rows: Array.from({ length: 8 }, (_, i) => fix(i, o.huge ? { hosts: 16_693_578, p1: 301_274 } : {})), totals: { fixes: 214, p1: 301_274, withKev: 61 }, completeness: comp });
    if (p.startsWith("v2/fixes/") && !p.endsWith(".csv")) {
      return json({
        id: p.split("/")[2], title: "Update Microsoft Edge to 120.0.2210.61", actions: ["Update Microsoft Edge to 120.0.2210.61", "Apply KB5034123"], links: [{ action: "KB5034123", link: "https://catalog.example/kb5034123", type: "recommended" }],
        product: "Microsoft Edge 119.0", noFix: false,
        summary: { p1: 5210, p2: 120, p3: 0, cves: 31, p1Cves: 30, kevCves: 12, hosts: 812, p1Hosts: 800, internetHosts: 14, severity: "CRITICAL", exprt: "CRITICAL", firstSeen: now - 40 * DAY, ageDays: 40, impactShare: 0.0173 },
        cves: { total: 31, rows: Array.from({ length: 8 }, (_, i) => ({ cveId: `CVE-2025-${1000 + i}`, tier: i < 4 ? "P1" : "P2", severity: "CRITICAL", baseScore: 9.8, exprt: "CRITICAL", exploitStatus: 90, kev: i < 3, kevDueDate: "2026-12-09", overdue: i === 0, hosts: 800 - i, findings: 800 })) },
        hosts: { total: 812, rows: Array.from({ length: 6 }, (_, i) => ({ ...host(i + 1), fixFindings: 12, fixP1: 5 })) },
      });
    }
    if (p === "v2/hosts") {
      if (o.empty) return json({ total: 0, page: 1, pageSize: 25, rows: [], facets: { all: 0, withFindings: 0, withP1: 0, internet: 0, stale7: 0, stale30: 0, duplicates: 0, staleTwins: 0, noFindings: 0 }, completeness: comp });
      return json({ total: 7790, page: 1, pageSize: 25, rows: Array.from({ length: 10 }, (_, i) => host(i + 1, o.huge ? { p1: 16_693_578, critical: 1_234_567 } : {})), facets: { all: 7790, withFindings: 7120, withP1: 4126, internet: 311, stale7: 1696, stale30: 134, duplicates: 220, staleTwins: 107, noFindings: 670 }, completeness: comp });
    }
    if (p.startsWith("v2/hosts/")) {
      return json({
        aid: decodeURIComponent(p.split("/")[2]), host: host(1), tiers: { P1: 12, P2: 40, P3: 0 }, severity: { CRITICAL: 3, HIGH: 20, MEDIUM: 10, LOW: 2, NONE: 0 },
        fixes: Array.from({ length: 5 }, (_, i) => ({ id: String(184467440737 + i), title: `Update Microsoft Edge to 120.0.${i}`, p1: 5 - i, p2: 2, cves: 7, kevCves: i === 0 ? 1 : 0, severity: "CRITICAL" })), fixesMore: 3,
        cves: Array.from({ length: 10 }, (_, i) => ({ ...vuln(i), tier: i < 4 ? "P1" : "P2", fixId: "184467440737", product: i % 2 ? "Microsoft Edge 119.0" : "7-Zip 19.00" })), cvesTotal: 52, completeness: comp,
      });
    }
    if (p === "software") return json({ rows: Array.from({ length: 10 }, (_, i) => sw(i + 1, o.huge ? { devices: 16_693_578 } : {})), total: 120, page: 1, pageSize: 25, devices: 7790, byType: [{ type: "application", items: 100, devices: 7790 }, { type: "browser_extension", items: 20, devices: 400 }], completeness: comp });
    if (p.startsWith("software/")) return json({ found: true, key: p.split("/")[1], type: "application", vendor: "Microsoft", name: "Microsoft Edge 1", category: "Browser", suspicious: false, devices: 790, instances: 790, firstSeen: now - 300 * DAY, latest: "120.0", versions: [{ version: "119.0.1", devices: 700 }, { version: "118.0", devices: 90 }], hosts: [{ aid: "aid1", hostname: "WSR1", platform: "Windows", version: "119.0.1", firstSeen: now }], completeness: comp });
    if (p === "vulnerabilities/CVE-2025-1000") {
      return json({
        found: true, cveId: "CVE-2025-1000", severity: "CRITICAL", baseScore: 9.8, exprt: "CRITICAL", kind: "Vulnerability", exploitStatus: 90, remediation: ["- Update Microsoft Edge to 120.0.2210.61"], completeness: comp, devicesTotal: 800,
        about: { description: "A remote code execution flaw.", publishedAt: "2025-01-10", vector: "CVSS:3.1/AV:N", exploitabilityScore: 3.9, impactScore: 5.9, cwes: ["CWE-79"], types: [], references: [], advisories: [], cisaKev: true },
        products: [{ name: "Microsoft Edge 119.0", vendor: "Microsoft", devices: 800 }], exposure: { riskScore: 90, firstSeen: now - 40 * DAY, internetFacing: 14, exploitable: 5, reopened: 0, ports: [] },
        hosts: Array.from({ length: 4 }, (_, i) => ({ key: `aid${i + 1}`, aid: `aid${i + 1}`, hostname: `WSR${i + 1}`, platform: "Windows", provider: null, localIp: `10.1.2.${i}`, product: "Microsoft Edge", status: "open", severity: "CRITICAL", osVersion: "Windows 11", internetExposure: i === 0 ? "Yes" : "No", firstSeen: now - 30 * DAY })),
        public: { id: "CVE-2025-1000", announced: true, state: "PUBLISHED", title: "Edge RCE", description: null, publishedAt: now - 40 * DAY, modifiedAt: null, ingestedAt: now, cvss: { score: 9.8, severity: "CRITICAL", vector: null }, cwes: [], references: [], kev: { dateAdded: "2026-01-01", dueDate: "2026-12-09", ransomware: "Known", requiredAction: "Apply updates", name: null } },
        impact: { state: "affected", asOf: now, cids: 1, complete: 1 },
      });
    }
    if (p === "vulnerabilities/CVE-2025-1000/software") return json({ state: "ok", versions: [{ version: "119.0.1", devices: 700 }], fixedIn: ["120.0.2210.61"], rows: [{ aid: "aid1", installed: "119.0.1", path: "C:\\Edge", fixedIn: "120.0" }] });
    if (p === "news/CVE-2025-1000") return json({ state: "exact", devices: 800, lastChanged: now - 3_600_000, public: { title: "Edge RCE" } });
    if (p.startsWith("news/")) return json({ error: "Not found" }, 404);
    if (p === "watchlist") return json({ limit: 200, canEdit: true, hosts: [{ aid: "aid2", hostname: "WSR2", note: null, worstSeverity: "CRITICAL", p1: 3, critical: 1, high: 1, newP1_24h: 0, newCritical24h: 0, lastSeen: now, missing: false }], auto: [] });
    return json({ error: "not mocked" }, 404);
  });
}

const shot = async (page: Page, name: string, fullPage = true) => { mkdirSync(SHOTS, { recursive: true }); await page.screenshot({ path: join(SHOTS, `lists-v2-${name}.png`), fullPage }); };
const noSideScroll = async (page: Page) => {
  const w = await page.evaluate(() => ({ s: document.documentElement.scrollWidth, c: document.documentElement.clientWidth }));
  expect(w.s, `page scrolls sideways (${w.s} > ${w.c})`).toBeLessThanOrEqual(w.c);
};

for (const width of [1280, 390]) {
  test.describe(`lists v2 at ${width}px`, () => {
    test.beforeEach(({}, info) => test.skip(info.project.name !== "desktop", "the viewport is set by the test itself"));

    test(`vulnerabilities: tier column, default sort, filters in the URL, CSV link`, async ({ page }) => {
      await session(page, width);
      const calls: string[] = [];
      page.on("request", (q) => { if (q.url().includes("/v2/vulnerabilities?")) calls.push(q.url()); });
      await mockApi(page);
      await go(page, "/vulnerabilities");
      await expect(seen(page, "CVE-2025-1000")).toBeVisible();
      if (width > 600) {
        await expect(page.getByRole("columnheader", { name: "Tier" })).toBeVisible();
        await expect(page.locator("tbody tr").first().getByText("P1")).toBeVisible();
      }
      expect(calls[0]).toContain("sort=priority");
      await shot(page, `vulns-${width}`);
      // a filter writes the URL and the API call; the chip can remove it
      await go(page, "/vulnerabilities?tier=P1&kev=1");
      await expect(page.getByRole("button", { name: /Tier P1/ })).toBeVisible();
      await expect.poll(() => calls.at(-1)).toContain("tier=P1");
      expect(calls.at(-1)).toContain("kev=1");
      await page.getByRole("button", { name: /Tier P1/ }).click();
      await expect(page).not.toHaveURL(/tier=P1/);
      if (width > 600) await expect(page.getByRole("link", { name: "Export CSV" })).toHaveAttribute("href", /v2\/vulnerabilities\.csv/);
      await noSideScroll(page);
    });

    test(`vulnerabilities: by-fix tab and the fix drawer (links to CVE and device drawers)`, async ({ page }) => {
      await session(page, width);
      await mockApi(page);
      await go(page, "/vulnerabilities?tab=fix");
      await expect(seen(page, "Update Microsoft Edge to 120.0.0")).toBeVisible();
      await shot(page, `fixes-${width}`);
      await seen(page, "Update Microsoft Edge to 120.0.0").click();
      await expect(page).toHaveURL(/fix=/);
      const drawer = page.getByRole("dialog");
      await expect(drawer.getByText("KB5034123").first()).toBeVisible();
      await expect(drawer.getByText("Devices to fix (812)")).toBeVisible();
      await expect(drawer.getByRole("link", { name: "Export device list (CSV)" })).toHaveAttribute("href", /fixes\/\d+\/hosts\.csv/);
      await drawerFits(page);
      await shot(page, `fix-drawer-${width}`, false);
      await drawer.getByRole("button", { name: "CVE-2025-1000" }).first().click();
      await expect(page).toHaveURL(/cve=CVE-2025-1000/);
      await expect(page).not.toHaveURL(/fix=/);
    });

    test(`CVE drawer: why this tier, fix, news state, devices with stars`, async ({ page }) => {
      await session(page, width);
      await mockApi(page);
      await go(page, "/vulnerabilities?cve=CVE-2025-1000");
      const drawer = page.getByRole("dialog");
      await expect(drawer.getByText("Why this is P1")).toBeVisible();
      await expect(drawer.getByText("Listed in CISA's Known Exploited Vulnerabilities catalog")).toBeVisible();
      await expect(drawer.getByText("Affects your devices")).toBeVisible();
      await expect(drawer.getByRole("button", { name: "Update Microsoft Edge to 120.0.2210.61" })).toBeVisible();
      await expect(drawer.getByRole("button", { name: /^Watch / }).first()).toBeVisible();
      await drawerFits(page);
      await shot(page, `cve-drawer-${width}`, false);
      await drawer.getByRole("button", { name: "WSR1", exact: true }).click();
      await expect(page).toHaveURL(/device=aid1/);
    });

    test(`devices: columns, flags, stale stamp, filters, drawer checklist`, async ({ page }) => {
      await session(page, width);
      const calls: string[] = [];
      page.on("request", (q) => { if (q.url().includes("/v2/hosts?")) calls.push(q.url()); });
      await mockApi(page);
      await go(page, "/devices");
      await expect(seen(page, "สมชาย-PC")).toBeVisible(); // Thai host name as Falcon reports it
      await expect(seen(page, "Possible duplicate")).toBeVisible();
      await expect(seen(page, "Old data")).toBeVisible(); // host last seen 12 days ago
      await shot(page, `devices-${width}`);
      await go(page, "/devices?tier=P1&internet=1&seen=stale7&duplicates=1&platform=Windows");
      await expect.poll(() => calls.at(-1)).toContain("seen=stale7");
      for (const k of ["tier=P1", "internet=1", "duplicates=1", "platform=Windows"]) expect(calls.at(-1)).toContain(k);
      await noSideScroll(page);
      await go(page, "/devices?device=aid1");
      const drawer = page.getByRole("dialog");
      await expect(drawer.getByText("What to fix on this device")).toBeVisible();
      await drawer.getByRole("checkbox").first().check();
      await expect(drawer.getByText("and 3 more fixes")).toBeVisible();
      await drawerFits(page);
      await shot(page, `device-drawer-${width}`, false);
      await drawer.getByRole("button", { name: "Update Microsoft Edge to 120.0.1" }).click();
      await expect(page).toHaveURL(/fix=/);
    });

    test(`software: product list and drawer with CVEs`, async ({ page }) => {
      await session(page, width);
      await mockApi(page);
      await go(page, "/software");
      await expect(seen(page, "Microsoft Edge 1", true)).toBeVisible();
      await shot(page, `software-${width}`);
      await seen(page, "Microsoft Edge 1", true).click();
      const drawer = page.getByRole("dialog");
      await expect(drawer.getByText("CVEs of this software (found by name)")).toBeVisible();
      await expect(drawer.getByRole("button", { name: "CVE-2025-1000" })).toBeVisible();
      await drawerFits(page);
      await shot(page, `software-drawer-${width}`, false);
    });

    test(`honest states: failed read stamps old data, empty list, loading skeleton, huge numbers`, async ({ page }) => {
      await session(page, width);
      await mockApi(page, { completeness: { state: "failed", reason: "unreachable" }, delay: 400 });
      await go(page, "/vulnerabilities");
      await expect(page.locator('[data-slot="skeleton"]').first()).toBeVisible(); // skeleton while loading
      await expect(seen(page, "Old data")).toBeVisible();
      await shot(page, `vulns-failed-${width}`);
      await page.unrouteAll();
      await session(page, width);
      await mockApi(page, { empty: true });
      await go(page, "/vulnerabilities");
      await expect(page.getByText(/No vulnerabilities to show|No open vulnerabilities/)).toBeVisible();
      await page.unrouteAll();
      await session(page, width);
      await mockApi(page, { huge: true });
      for (const path of ["/vulnerabilities", "/devices", "/software", "/vulnerabilities?tab=fix"]) {
        await go(page, path);
        await expect(page.locator("main table:visible, main ul:visible").first()).toBeVisible();
        await page.waitForTimeout(300);
        // a number never overflows its cell: nothing in the table is cut by the scroll container, and the page does not scroll sideways
        await noSideScroll(page);
        const cut = await page.locator("main td").evaluateAll((els) => els.filter((e) => e.scrollWidth > e.clientWidth + 1 && getComputedStyle(e).overflow === "visible").length);
        expect(cut, `${path}: cell content wider than its cell`).toBe(0);
      }
      await go(page, "/devices");
      await shot(page, `devices-huge-${width}`);
    });
  });
}
