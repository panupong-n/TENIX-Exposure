import { expect, expectNoHorizontalScroll, test } from "./fixtures";
import { drawer, main, tenantId, useTenant } from "./helpers";

// Regressions and recommendations from the part-2 QA (graph, CVE news, EASM, settings, devices list, CVE drawer, SOC landing).
const orgPill = (page: import("@playwright/test").Page) => page.getByRole("button", { name: /^Organization:/ });

test("CVE drawer: one row per device (findings counted), and the two scores are labelled apart", async ({ superPage: page }) => {
  await useTenant(page, "alpha");
  const rows = (await (await page.request.get(`/api/exposure/v2/vulnerabilities?tenantId=${tenantId("alpha")}&pageSize=25`)).json()).rows as { cveId: string }[];
  let seen = 0;
  for (const r of rows.slice(0, 12)) {
    const d = await (await page.request.get(`/api/exposure/vulnerabilities/${r.cveId}?tenantId=${tenantId("alpha")}`)).json();
    if (!d.found) continue;
    const aids = d.hosts.map((h: { aid: string }) => h.aid);
    expect(new Set(aids).size, `${r.cveId} lists a device twice`).toBe(aids.length);
    if (d.devicesTotal <= 200) expect(aids.length, `${r.cveId} rows = devices`).toBe(d.devicesTotal);
    expect(d.hosts.every((h: { findings: number }) => h.findings >= 1)).toBe(true);
    seen++;
  }
  expect(seen).toBeGreaterThan(0);
  await page.goto(`/vulnerabilities?cve=${rows[0].cveId}`);
  await expect(drawer(page).getByText("Falcon score", { exact: true })).toBeVisible();
  await expect(drawer(page).getByText("CVSS score", { exact: true })).toHaveCount(0);
});

test("devices list: no 'Worst severity' or 'Flags' column; the worst severity is a labelled dot; the view toggle sits in the card beside Export", async ({ superPage: page }, info) => {
  test.skip(info.project.name !== "desktop", "table is desktop only");
  await useTenant(page, "alpha");
  await page.goto("/devices");
  const head = main(page).locator("thead");
  await expect(head).toContainText("Device");
  await expect(head).not.toContainText("Worst severity");
  await expect(head).not.toContainText("Flags");
  const api = (await (await page.request.get(`/api/exposure/v2/hosts?tenantId=${tenantId("alpha")}&sort=p1&page=1&pageSize=25`)).json()).rows as { hostname: string | null; worstSeverity: string | null }[];
  const first = api.find((h) => h.worstSeverity)!;
  const label = { CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low", NONE: "Informational" }[first.worstSeverity as "HIGH"];
  await expect(main(page).locator("tbody tr").first().getByRole("img", { name: `Worst severity: ${label}` })).toBeVisible();
  const toggle = main(page).getByRole("navigation", { name: "View" });
  await expect(toggle).toBeVisible();
  expect(await toggle.evaluate((n) => !!n.closest(".rounded-xl"))).toBe(true);
  await expect(main(page).getByRole("link", { name: "Export CSV" })).toBeVisible();
});

test("phone lists: only search and a Filters button until it is opened; from a tablet up everything is in view", async ({ superPage: page }, info) => {
  await useTenant(page, "alpha");
  const phone = info.project.name === "mobile";
  for (const [url, ctl] of [["/vulnerabilities", "Priority tier"], ["/devices", "Platform"], ["/software", "Type"]] as const) {
    await page.goto(url);
    const select = main(page).getByRole("combobox", { name: ctl, exact: true });
    const btn = main(page).getByRole("button", { name: /^Filters/ });
    if (phone) {
      await expect(btn).toBeVisible();
      await expect(select).toBeHidden();
      await btn.click();
      await expect(select).toBeVisible();
      await expectNoHorizontalScroll(page);
    } else {
      await expect(btn).toBeHidden();
      await expect(select).toBeVisible();
    }
  }
});

test("SOC super admin with several organizations lands on the portfolio until an organization is picked; customers never see it", async ({ superPage: page, multiPage, operatorPage }) => {
  // the fixture starts with Alpha picked; drop that once (a later page load must keep the choice made in the test)
  await page.addInitScript(() => { try { if (!sessionStorage.getItem("fresh")) { sessionStorage.setItem("fresh", "1"); localStorage.removeItem("tenix.org"); } } catch { /* ignore */ } });
  await page.goto("/");
  await expect(main(page).getByRole("heading", { name: "Overview of all organizations" })).toBeVisible();
  await expect(orgPill(page)).toContainText("All organizations");
  await orgPill(page).click();
  await page.getByRole("listbox", { name: "Organization" }).getByRole("button", { name: "Alpha Corp" }).click();
  await expect(main(page).getByRole("heading", { name: "Overview", exact: true })).toBeVisible();
  await page.goto("/"); // the choice is remembered
  await expect(main(page).getByRole("heading", { name: "Overview", exact: true })).toBeVisible();
  await page.goto("/?view=all"); // and the portfolio is always one click away
  await expect(main(page).getByRole("heading", { name: "Overview of all organizations" })).toBeVisible();
  for (const p of [multiPage, operatorPage]) {
    await p.goto("/");
    await expect(main(p).getByRole("heading", { name: "Overview", exact: true })).toBeVisible();
    await expect(p.getByRole("button", { name: "All organizations" })).toHaveCount(0);
  }
});

test("overview phone: a long unbroken news title in the watchlist's automatic items does not widen the page", async ({ operatorPage: page }, info) => {
  test.skip(info.project.name !== "mobile", "phone layout");
  const long = "ที่ใช้งานแพร่หลายมากในองค์กรขนาดใหญ่ทั่วประเทศไทยและต่างประเทศ".repeat(3);
  await page.route("**/api/exposure/watchlist**", (r) => r.fulfill({ json: { limit: 200, canEdit: true, hosts: [], completeness: { state: "complete", dataAsOf: Date.now(), lastRunAt: Date.now(), reason: null }, auto: [{ type: "cve_news", cve: "CVE-2025-10333", title: long, devices: 26, severity: "HIGH", at: Date.now() }] } }));
  await page.goto("/");
  await expect(main(page).getByText("CVE-2025-10333").first()).toBeVisible();
  await expectNoHorizontalScroll(page);
});

test("external assets: IP addresses sort as numbers and the filter labels are not cut", async ({ superPage: page }, info) => {
  await useTenant(page, "alpha");
  const items = (await (await page.request.get(`/api/exposure/easm/assets?tenantId=${tenantId("alpha")}&sort=name&type=ip&pageSize=100`)).json()).items as { ip: string }[];
  const key = (ip: string) => ip.split(".").map(Number);
  const ips = items.map((i) => i.ip).filter(Boolean);
  expect(ips.length).toBeGreaterThan(10);
  expect(ips).toEqual([...ips].sort((a, b) => { const x = key(a), y = key(b); return x[0] - y[0] || x[1] - y[1] || x[2] - y[2] || x[3] - y[3]; }));
  if (info.project.name !== "desktop") return;
  await page.goto("/external");
  for (const name of ["Review status", "Sort"]) {
    const c = main(page).getByRole("combobox", { name: new RegExp(name, "i") }).first();
    await expect(c).toBeVisible();
    expect(await c.evaluate((e) => { const v = e.querySelector("[data-slot=select-value]") as HTMLElement | null; return v ? v.scrollWidth - v.clientWidth : 0; }), `${name} label cut`).toBeLessThanOrEqual(0);
  }
});

test("an invalid invite link says so in its heading, not 'Create your account'", async ({ browser, baseURL }) => {
  const ctx = await browser.newContext({ baseURL, viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  await page.goto("/accept-invite/not-a-real-token");
  await expect(page.getByRole("heading", { name: "Link not valid" })).toBeVisible();
  await expect(page.getByText("Create your account")).toHaveCount(0);
  await ctx.close();
});
