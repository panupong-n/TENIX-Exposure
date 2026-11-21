import { expect, test, type Page, type Route } from "@playwright/test";

// News page, EASM asset list + drawer, notification and retention settings drawers (spec 2.6a/2.6b/3.4/3.5), all against mocked API answers.
// Runs under the normal config (needs the e2e stack) or standalone: npx playwright test -c e2e/misc-v2.config.ts
const NOW = Date.now(), DAY = 86_400_000;
const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, json: body });
const SHOTS = "e2e/shots/misc-v2";

interface Opts { soc?: boolean; role?: "admin" | "operator" }
async function base(page: Page, o: Opts = {}) {
  const role = o.role ?? "admin";
  await page.route("**/api/**", (r) => json(r, { error: "not mocked", code: null }, 404));
  await page.route("**/api/auth/me", (r) => json(r, { user: { id: "u1", email: "a@x.io", name: "Alice", role: o.soc ? "super_admin" : "member", soc: !!o.soc, manager: o.soc || role === "admin", totpEnabled: true, tenants: [{ id: "t1", name: "Alpha Corp", role }] } }));
  await page.route("**/api/tenants", (r) => json(r, { tenants: [{ id: "t1", name: "Alpha Corp", role: o.soc ? "super_admin" : role }, { id: "t2", name: "Beta Ltd", role: o.soc ? "super_admin" : role }].slice(0, o.soc ? 2 : 1) }));
}

const newsItems = [
  { cve: "CVE-2026-1001", title: "Apache Tomcat remote code execution lets attackers run code", state: "exact", devices: 3, severity: "CRITICAL", cvss: 9.8, kev: true, publishedAt: NOW - 3 * DAY, firstSeen: NOW - 3 * DAY, lastChanged: NOW - 2 * 3600_000, notifiedAt: NOW - 3600_000, newsCount: 2, reference: "https://www.bleepingcomputer.com/news/x" },
  { cve: "CVE-2026-1002", title: "WinRAR path traversal", state: "possible", devices: 2, severity: null, cvss: 7.8, kev: false, publishedAt: NOW - 5 * DAY, firstSeen: NOW - 5 * DAY, lastChanged: NOW - DAY, notifiedAt: null, newsCount: 1, reference: "https://thehackernews.com/y" },
  { cve: "CVE-2026-1003", title: "Fortinet FortiOS authentication bypass", state: "wait", devices: 0, severity: null, cvss: null, kev: false, publishedAt: NOW - DAY, firstSeen: NOW - DAY, lastChanged: NOW - 5 * 3600_000, notifiedAt: null, newsCount: 1, reference: null },
  { cve: "CVE-2026-1004", title: "Chrome type confusion", state: "not_affected", devices: 0, severity: null, cvss: 8.8, kev: false, publishedAt: NOW - 9 * DAY, firstSeen: NOW - 9 * DAY, lastChanged: NOW - 4 * DAY, notifiedAt: null, newsCount: 1, reference: "javascript:alert(1)" },
];
const news = (showPossible: boolean, hosts: boolean) => ({ showPossible, showHostNames: hosts, counts: { exact: 1, ...(showPossible ? { possible: 1 } : {}), wait: 1, not_affected: 1 }, total: 4, page: 1, pageSize: 25, items: newsItems.filter((i) => showPossible || i.state !== "possible") });

test("news: states, filters, CVE drawer link, mobile fits", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop", "starts at a desktop width (tables) and switches to 390 px itself");
  await base(page);
  const calls: string[] = [];
  await page.route("**/api/exposure/news?*", (r) => { calls.push(r.request().url()); return json(r, news(false, true)); });
  await page.route("**/api/exposure/news/CVE-2026-1001*", (r) => json(r, { hostsHidden: false, hosts: [{ aid: "a1", hostname: "WEB-01", severity: "CRITICAL" }, { aid: "a2", hostname: "WEB-02", severity: "HIGH" }] }));
  await page.route("**/api/exposure/vulnerabilities/CVE-2026-1001*", (r) => json(r, { found: false, cveId: "CVE-2026-1001", completeness: { state: "complete", lastRunAt: null } }));
  await page.goto("/news");
  await expect(page.locator("main tbody tr")).toHaveCount(3);
  await expect(page.locator("main tbody").getByText("Affects 3 devices")).toBeVisible();
  await expect(page.locator("main tbody").getByText("Waiting for Falcon data")).toBeVisible();
  await expect(page.getByText("Possibly affected", { exact: true })).toHaveCount(0); // hidden for this organization, with a note
  await expect(page.getByText(/hidden for this organization/)).toBeVisible();
  await expect(page.locator('a[href^="javascript:"]')).toHaveCount(0);
  await page.getByText("Show device names").click();
  await expect(page.getByRole("button", { name: "WEB-01" })).toBeVisible();
  await page.getByTestId("news-kev").click();
  await expect(page.getByTestId("news-kev")).toBeChecked();
  await expect.poll(() => calls.at(-1)).toContain("kev=1");
  await page.screenshot({ path: `${SHOTS}-news-desktop.png` });
  await page.getByTestId("news-kev").click();
  await expect(page.getByTestId("news-kev")).not.toBeChecked();
  await page.getByRole("button", { name: "CVE-2026-1001" }).click();
  await expect(page).toHaveURL(/cve=CVE-2026-1001/);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/news");
  await expect(page.locator("main li").first()).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
  await page.screenshot({ path: `${SHOTS}-news-mobile.png` });
});

test("news: SOC sees the cross-organization view, a customer does not", async ({ page }) => {
  await base(page, { soc: true });
  await page.route("**/api/exposure/news?*", (r) => json(r, news(true, true)));
  await page.route("**/api/exposure/news-soc?*", (r) => json(r, { counts: { exact: 2 }, total: 1, items: [{ cve: "CVE-2026-1001", title: "Tomcat RCE", kev: true, cvss: 9.8, publishedAt: NOW - DAY, firstSeen: NOW - DAY, newsCount: 2, sources: ["https://thehackernews.com/z"], exactTenants: 2, possibleTenants: 1, totalDevices: 7, tenants: [{ tenantId: "t1", tenant: "Alpha Corp", state: "exact", devices: 3, notifiedAt: null }, { tenantId: "t2", tenant: "Beta Ltd", state: "possible", devices: 4, notifiedAt: null }] }] }));
  await page.goto("/news");
  await page.getByRole("tab", { name: "All organizations" }).click();
  await expect(page.locator("main tbody tr")).toHaveCount(1);
  await expect(page.getByText("Beta Ltd")).toBeVisible();
  await page.screenshot({ path: `${SHOTS}-news-soc.png` });

  const other = await page.context().newPage();
  await base(other);
  await other.route("**/api/exposure/news?*", (r) => json(r, news(false, false)));
  await other.goto("/news");
  await expect(other.getByRole("tab")).toHaveCount(0);
});

const asset = (i: number, o: object = {}) => ({ id: `as${i}`, type: i % 2 ? "ip" : "sub", dnsType: null, name: i % 2 ? `52.1.2.${i}` : `app${i}.alpha.example.com`, ip: `52.1.2.${i}`, fqdn: null, perimeter: "official", review: "", reviewed: i === 3, criticality: "Unassigned", status: "online", cloud: "AWS", isp: "AMAZON-02", asn: 16509, country: "SG", city: "Singapore", discoveredBy: "surface", firstSeen: NOW - 20 * DAY, lastSeen: NOW - DAY, isNew: i === 1, ports: [443, 80], serviceCount: 2, riskyPorts: [], expiredCerts: 0, expiringCerts: 0, nearestCertExpiry: NOW + 200 * DAY, findings: { count: 0, worstSeverity: null }, ...o });
const assets = [
  asset(1, { ports: [443, 80, 3389, 21, 8080, 8443, 9000], riskyPorts: [3389, 21], serviceCount: 7, expiredCerts: 1, nearestCertExpiry: NOW - 40 * DAY, findings: { count: 4, worstSeverity: "HIGH" } }),
  asset(2, { expiringCerts: 1, nearestCertExpiry: NOW + 9.5 * DAY }),
  asset(3, { ports: null, serviceCount: null, nearestCertExpiry: null }),
];
test("external surface: asset list, filters, drawer with services and TLS", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop", "starts at a desktop width (tables) and switches to 390 px itself");
  await base(page);
  await page.route("**/api/exposure/easm?*", (r) => json(r, { state: "complete", asOf: NOW, lastRunAt: NOW, assets: { ips: 2, rootDomains: 0, subdomains: 1 }, perimeter: { official: 3 }, reviewIps: { reviewed: 1, notReviewed: 1 }, reviewRootDomains: { reviewed: 0, notReviewed: 0 }, online: { online: 3 }, discoveredBy: { surface: 3 }, cloud: [{ k: "AWS", n: 3 }], findings: { total: 4, assets: 1, byExprt: { HIGH: 4 }, byType: { Vulnerability: 4 }, bySeverity: { HIGH: 4 } } }));
  await page.route("**/api/exposure/easm/services*", (r) => json(r, { assetsWithServices: 2, services: 9, expiredCerts: 1, expiringCerts30: 1, riskyPorts: 2, assetsWithRiskyPorts: 1, assetsWithExpiredCert: 1, newLast7d: 1 }));
  const calls: string[] = [];
  await page.route("**/api/exposure/easm/assets?*", (r) => { calls.push(r.request().url()); return json(r, { state: "complete", asOf: NOW, total: 3, page: 1, pageSize: 25, items: assets }); });
  await page.route("**/api/exposure/easm/assets/as1*", (r) => json(r, { ...assets[0], ptr: "ec2-52-1-2-1.compute.amazonaws.com", region: "Central", discovery: [{ entity: "1.2.3.4", type: "ip", clue: "IP contains a service which has SSL cert" }],
    services: [
      { port: 3389, transport: "tcp", protocol: "rdp", status: "online", statusCode: null, os: "Windows Server 2016", firstSeen: NOW - DAY, lastSeen: NOW, risky: true, applications: [{ vendor: "Microsoft", name: "RDP", category: "Remote", version: "10", cpe: "" }], tls: null },
      { port: 443, transport: "tcp", protocol: "https", status: "online", statusCode: 200, os: null, firstSeen: NOW - DAY, lastSeen: NOW, risky: false, applications: [{ vendor: "Microsoft", name: "IIS", category: "Web", version: "10.0", cpe: "" }], tls: { version: "3", issuer: "Let's Encrypt R3", subject: "alpha.example.com", validFrom: NOW - 300 * DAY, validTo: NOW - 40 * DAY, expired: true, expiresInDays: -40, signature: "sha256", fingerprint: "ab" } }],
    vulnerabilities: [{ cve: "CVE-2026-1001", severity: "HIGH", baseScore: 7.5, exprt: "HIGH", kev: true, product: "IIS" }] }));
  await page.goto("/external");
  await expect(page.locator("main tbody tr")).toHaveCount(3);
  await expect(page.locator("main tbody").getByText("Expired", { exact: true }).first()).toBeVisible();
  await expect(page.locator("main tbody").getByText("In 9 d").first()).toBeVisible();
  await expect(page.locator("main tbody").getByTitle("Risky port").first()).toBeVisible();
  expect(calls[0]).toContain("sort=triage");
  await page.getByTestId("easm-riskyPort").click();
  await expect.poll(() => calls.at(-1)).toContain("riskyPort=1");
  await page.getByTestId("easm-riskyPort").click();
  await page.locator("main tbody tr").first().click();
  await expect(page).toHaveURL(/asset=as1/);
  const dlg = page.getByTestId("asset-drawer");
  await expect(dlg.getByTestId("asset-service")).toHaveCount(2);
  await expect(dlg.getByText("Let's Encrypt R3")).toBeVisible();
  await expect(dlg.getByText("1.2.3.4")).toBeVisible();
  await page.waitForTimeout(500); // slide-in
  await page.screenshot({ path: `${SHOTS}-easm-drawer.png` });
  await page.keyboard.press("Escape");
  await expect(page).not.toHaveURL(/asset=/);
  await expect(dlg).toHaveCount(0);
  await page.screenshot({ path: `${SHOTS}-easm.png`, fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/external");
  await expect(page.locator("main ul.divide-y li").first()).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
  await page.screenshot({ path: `${SHOTS}-easm-mobile.png`, fullPage: true });
});

const prefs = { enabled: true, severities: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"], p1Always: true, devicesMode: "all", topN: 10, maxNames: 20, newsPossible: false, newsHostNames: false, updatedAt: null, updatedBy: null };
const txt = (text: string, o = {}) => ({ type: "text", text, wrap: true, ...o });
const flexMsg = { type: "flex", altText: "x", contents: { type: "bubble", header: { type: "box", layout: "vertical", paddingAll: "0px", contents: [{ type: "box", layout: "vertical", height: "6px", backgroundColor: "#dc2626", contents: [{ type: "filler" }] }] }, body: { type: "box", layout: "vertical", spacing: "md", paddingAll: "lg", contents: [txt("CVE-2026-0000", { size: "xl", weight: "bold" }), txt("เครื่องที่พบ 25", { size: "sm" }), { type: "box", layout: "horizontal", contents: [txt("ตัวอย่าง-PC-01", { size: "xs", flex: 5 }), txt("1.0", { size: "xs", flex: 4, align: "end" })] }] } } };
test("notification settings: defaults, validation, preview follows options, save errors, test", async ({ page }) => {
  await base(page);
  const bodies: Record<string, unknown>[] = [];
  let putStatus = 200;
  await page.route("**/api/tenants/t1/notify", async (r) => {
    if (r.request().method() === "PUT") { bodies.push(r.request().postDataJSON()); return putStatus === 200 ? json(r, { canEdit: true, isDefault: false, prefs, watchedCount: 3, destinations: { count: 1, names: ["Alpha managers"] } }) : json(r, { error: "x", code: "invalid_top_n" }, 400); }
    return json(r, { tenantId: "t1", canEdit: true, isDefault: true, prefs, watchedCount: 3, destinations: { count: 1, names: ["Alpha managers"] }, options: {} });
  });
  const previews: Record<string, unknown>[] = [];
  await page.route("**/api/tenants/t1/notify/preview", (r) => { previews.push(r.request().postDataJSON()); return json(r, { sample: true, cve: null, messages: [flexMsg], dropped: false, truncated: false }); });
  await page.route("**/api/tenants/t1/notify/test", (r) => json(r, { sent: 1 }));
  await page.goto("/news?settings=notify");
  const dlg = page.getByTestId("settings-notify");
  for (const s of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]) await expect(dlg.getByTestId(`notify-sev-${s}`)).toBeChecked();
  await expect(dlg.getByTestId("notify-p1")).toBeChecked();
  await expect(dlg.getByTestId("notify-mode-all")).toBeChecked();
  await expect(dlg.getByTestId("notify-maxNames")).toHaveValue("20");
  await expect(dlg.getByTestId("notify-topN")).toHaveValue("10");
  await expect(dlg.getByTestId("flex-bubble")).toBeVisible();
  await expect(dlg.getByTestId("notify-save")).toBeDisabled(); // nothing changed
  await page.waitForTimeout(500);
  await page.screenshot({ path: `${SHOTS}-notify.png` });
  await dlg.getByTestId("notify-mode-top").check();
  await expect.poll(() => previews.at(-1)?.devicesMode).toBe("top");
  await dlg.getByTestId("notify-test").click();
  await expect(dlg.getByTestId("notify-msg")).toHaveText("Test message sent to 1 group(s).");
  for (const s of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]) await dlg.getByTestId(`notify-sev-${s}`).uncheck();
  await expect(dlg.getByTestId("notify-sev-error")).toBeVisible();
  await expect(dlg.getByTestId("notify-save")).toBeDisabled();
  await dlg.getByTestId("notify-sev-CRITICAL").check();
  putStatus = 400;
  await dlg.getByTestId("notify-save").click();
  await expect(dlg.getByTestId("notify-msg")).toHaveText("The number of top devices must be 1 to 100.");
  putStatus = 200;
  await dlg.getByTestId("notify-save").click();
  await expect(dlg.getByTestId("notify-msg")).toHaveText("Saved.");
  expect(bodies.at(-1)).toMatchObject({ severities: ["CRITICAL"], devicesMode: "top", topN: 10, maxNames: 20, enabled: true });
  await page.keyboard.press("Escape");
  await expect(page).not.toHaveURL(/settings=/);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/news?settings=notify");
  await expect(page.getByTestId("settings-notify")).toBeVisible();
  await page.waitForTimeout(500);
  await page.screenshot({ path: `${SHOTS}-notify-mobile.png` });
});

test("notification settings: an operator reads but cannot change or preview", async ({ page }) => {
  await base(page, { role: "operator" });
  let previews = 0;
  await page.route("**/api/tenants/t1/notify", (r) => json(r, { tenantId: "t1", canEdit: false, isDefault: false, prefs, watchedCount: 0, destinations: { count: 0, names: [] } }));
  await page.route("**/api/tenants/t1/notify/preview", (r) => { previews++; return json(r, {}, 404); });
  await page.goto("/news?settings=notify");
  await expect(page.getByTestId("notify-sev-HIGH")).toBeDisabled();
  await expect(page.getByTestId("notify-save")).toHaveCount(0);
  expect(previews).toBe(0);
});

const retention = (o: object = {}) => ({ keep: ["CRITICAL", "HIGH", "MEDIUM", "NONE"], all: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"], graceDays: 3, pending: [{ severity: "LOW", purgeAt: NOW + 2 * DAY + 18 * 3600_000 }], rebuilding: [], scope: ["CRITICAL", "HIGH", "MEDIUM", "NONE"], coverage: { held: 1085590, falconTotal: 16700573, priorityHeld: 1085590, priorityTotal: 1085590, priorityPass: true, fullPass: true, keptTotal: 16444426 }, ...o });
const summary = { severity: { CRITICAL: 858001, HIGH: 171320, MEDIUM: 49870, LOW: 6331, NONE: 68 }, completeness: { state: "complete", lastRunAt: NOW, falconCounts: { total: 16700573, critical: 858001, high: 11116325, medium: 4469964, low: 256147, kev: 1, exprtCritical: 1, exploited: 1 } } };
test("retention settings: pending countdown, undo, un-tick with confirmation, banner", async ({ page }) => {
  await base(page);
  const puts: { keep: string[] }[] = [];
  let state = retention();
  await page.route("**/api/tenants/t1/retention", (r) => {
    if (r.request().method() === "PUT") { const b = r.request().postDataJSON(); puts.push(b); state = retention({ keep: b.keep, pending: b.keep.includes("LOW") ? [] : [{ severity: "LOW", purgeAt: NOW + 3 * DAY }] }); }
    return json(r, state);
  });
  await page.route("**/api/exposure/summary*", (r) => json(r, summary));
  await page.goto("/news?settings=retention");
  const dlg = page.getByTestId("settings-retention");
  await expect(dlg.getByTestId("retention-pending-LOW")).toContainText("Deleted in 2 d 1");
  await expect(dlg.getByTestId("retention-row-CRITICAL")).toContainText("858,001");
  await expect(dlg.getByTestId("retention-row-HIGH")).toContainText("11.1M");
  await expect(dlg.getByTestId("retention-keep-LOW")).not.toBeChecked();
  await expect(dlg.getByTestId("retention-save")).toBeDisabled();
  await page.waitForTimeout(500);
  await page.screenshot({ path: `${SHOTS}-retention.png` });
  // un-tick Medium: asks first, nothing is sent before "Yes"
  await dlg.getByTestId("retention-keep-MEDIUM").uncheck();
  await dlg.getByTestId("retention-save").click();
  await expect(dlg.getByTestId("retention-confirm")).toContainText("Falcon totals on the Overview do not change");
  expect(puts).toHaveLength(0);
  await page.screenshot({ path: `${SHOTS}-retention-confirm.png` });
  await dlg.getByTestId("retention-confirm-yes").click();
  await expect(dlg.getByTestId("retention-msg")).toHaveText("Saved.");
  expect(puts[0].keep).toEqual(["CRITICAL", "HIGH", "NONE"]);
  // undo of the pending Low deletion = tick it again, no confirmation
  await dlg.getByRole("button", { name: "Cancel deletion" }).click();
  await expect.poll(() => puts.at(-1)?.keep.includes("LOW")).toBe(true);
  // the last severity cannot be removed
  for (const s of ["CRITICAL", "HIGH", "NONE", "LOW"]) { const c = dlg.getByTestId(`retention-keep-${s}`); if (await c.isChecked()) await c.uncheck(); }
  await expect(dlg.getByText("Keep at least one severity.").first()).toBeVisible();
  await expect(dlg.getByTestId("retention-save")).toBeDisabled();
  await page.keyboard.press("Escape");

  // the banner on the Overview: countdown and undo
  state = retention();
  await page.route("**/api/exposure/**", (r) => json(r, { error: "x", code: null }, 500));
  await page.route("**/api/tenants/t1/retention", (r) => {
    if (r.request().method() === "PUT") { puts.push(r.request().postDataJSON()); state = retention({ pending: [] }); }
    return json(r, state);
  });
  await page.goto("/");
  const banner = page.getByTestId("retention-banner");
  await expect(banner).toContainText("Data for severity Low will be deleted in 2 d 1");
  await page.screenshot({ path: `${SHOTS}-banner.png` });
  await banner.getByRole("button", { name: "Cancel deletion" }).click();
  await expect(banner).toHaveCount(0);
});

test("retention settings: an operator gets no data (the API says 404) and sees a plain message", async ({ page }) => {
  await base(page, { role: "operator" });
  await page.goto("/news?settings=retention");
  await expect(page.getByTestId("retention-unavailable")).toBeVisible();
});
