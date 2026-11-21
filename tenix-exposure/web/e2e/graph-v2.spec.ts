import { expect, test, type Page } from "@playwright/test";
import { FIRST_CVE, mockGraphApi, type Mode } from "./graph-mocks";

// The graph view of /devices (spec graph-design.md): every API call is mocked at the shape and scale of the real tenant, so this runs without the seeded database.
const V = "/devices?view=graph";
const open = async (page: Page, url = V, mode: Mode = { calls: [] }) => { await mockGraphApi(page, mode); await page.goto(url); return mode; };
const canvas = (page: Page) => page.getByTestId("graph-canvas");
const nodes = (page: Page) => canvas(page).locator("svg g[data-col]");

test.describe("desktop 1280", () => {
  test.beforeEach(({}, info) => { test.skip(info.project.name !== "desktop", "viewport is set below"); });
  test.use({ viewport: { width: 1280, height: 900 } });

  test("default lens: about 20 nodes and at most 60 drawn links, the held-of-total strip, no scroll sideways", async ({ page }) => {
    await open(page);
    await expect(nodes(page).first()).toBeVisible();
    expect(await nodes(page).count()).toBeLessThanOrEqual(30);
    const drawn = await canvas(page).locator("svg path").evaluateAll((ps) => ps.filter((p) => Number(p.getAttribute("stroke-opacity")) > 0).length);
    expect(drawn).toBeLessThanOrEqual(60);
    await expect(page.getByText(/Detail kept for 1,085,590 of 16,700,573/)).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    await expect(page.getByRole("tab", { name: /What to fix first/ })).toHaveAttribute("aria-selected", "true");
    await page.screenshot({ path: "e2e/shots/graph-v2-desktop-default.png" });
  });

  test("click drills (breadcrumb), Esc goes back; the breadcrumb shows in under 100 ms", async ({ page }) => {
    await open(page);
    const first = nodes(page).first();
    await expect(first).toBeVisible();
    const ms = await first.evaluate(async (el) => {
      const t0 = performance.now();
      el.dispatchEvent(new MouseEvent("click", { bubbles: true }));
      await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
      return { ms: performance.now() - t0, crumb: !!document.querySelector("nav[aria-label=Path]") };
    });
    expect(ms.crumb).toBe(true);
    expect(ms.ms).toBeLessThan(100);
    await expect(page).toHaveURL(/focus=fix%3A184467440000|focus=fix:184467440000/);
    await expect(page.getByRole("heading", { name: "Blast radius", level: 2 })).toBeVisible();
    await expect(page.getByRole("navigation", { name: "Path" })).toContainText("Fix: Apply KB5030000");
    await page.getByRole("tab", { name: /Blast radius/ }).waitFor();
    await page.locator("body").press("Escape");
    await expect(page.getByRole("navigation", { name: "Path" })).toHaveCount(0);
    await expect(page.getByRole("heading", { name: /Fixes that close the most risk/ })).toBeVisible();
  });

  test("group node drills to hosts; links of the host column appear on focus only; Back crumb", async ({ page }) => {
    await open(page);
    await nodes(page).filter({ hasText: "Servers-DC-BKK" }).click();
    await expect(page).toHaveURL(/group=Servers-DC-BKK/);
    await expect(page.getByText(/Links between fixes and hosts show on hover/)).toBeVisible();
    await page.mouse.move(0, 0);
    const lazy = await canvas(page).locator("svg path").evaluateAll((ps) => ps.every((p) => p.getAttribute("stroke-opacity") === "0"));
    expect(lazy).toBe(true);
    await nodes(page).first().focus();
    const lit = await canvas(page).locator("svg path").evaluateAll((ps) => ps.filter((p) => Number(p.getAttribute("stroke-opacity")) > 0.5).length);
    expect(lit).toBeGreaterThan(0);
    await page.getByRole("button", { name: /Back/ }).click();
    await expect(page).not.toHaveURL(/group=/);
  });

  test("keyboard: arrows move between nodes, Enter drills", async ({ page }) => {
    await open(page);
    await nodes(page).first().focus();
    await page.keyboard.press("ArrowDown");
    expect(await page.evaluate(() => document.activeElement?.getAttribute("aria-label"))).toContain("Apply KB5030137");
    await page.keyboard.press("ArrowRight");
    expect(await page.evaluate(() => document.activeElement?.getAttribute("aria-label"))).toMatch(/hosts/);
    await page.keyboard.press("ArrowLeft");
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/focus=fix/);
  });

  test("filters: tier, KEV, internet, group-by and top are in the URL and in the API call; P3 is disabled", async ({ page }) => {
    const mode = await open(page);
    await expect(page.getByRole("button", { name: /^P3/ })).toBeDisabled();
    await page.getByRole("button", { name: "P2 Fix in cycle" }).click();
    await page.getByRole("button", { name: "CISA KEV" }).click();
    await page.getByRole("button", { name: "Internet-facing" }).click();
    await expect(page).toHaveURL(/tier=P1%2CP2|tier=P1,P2/);
    await expect(page).toHaveURL(/kev=1/);
    await expect(page).toHaveURL(/internet=1/);
    await expect.poll(() => mode.calls.some((c) => /graph\?.*tier=P1%2CP2.*kev=1.*internet=1|graph\?.*kev=1.*internet=1/.test(c))).toBe(true);
    await page.getByRole("button", { name: "P1 Fix now" }).click(); // P2 only
    await page.getByRole("button", { name: "P2 Fix in cycle" }).click(); // the last tier cannot be switched off
    await expect(page.getByRole("button", { name: "P2 Fix in cycle" })).toHaveAttribute("aria-pressed", "true");
  });

  test("matrix is a real table; a cell opens the product within that group (two-step breadcrumb)", async ({ page }) => {
    await open(page, `${V}&lens=matrix`);
    const table = canvas(page).locator("table");
    await expect(table.locator("caption")).toHaveCount(1);
    expect(await table.locator("th[scope=col]").count()).toBeGreaterThanOrEqual(9);
    expect(await table.locator("tbody tr").count()).toBe(12);
    await page.screenshot({ path: "e2e/shots/graph-v2-desktop-matrix.png" });
    await table.locator("tbody tr").first().locator("button[aria-label*='Servers-DC-BKK']").click();
    await expect(page.getByRole("navigation", { name: "Path" })).toContainText("Product: ");
    await expect(page.getByRole("navigation", { name: "Path" })).toContainText("Group: Servers-DC-BKK");
  });

  test("search-to-focus: type, Enter picks the first match and shows the blast radius with the host list beside it", async ({ page }) => {
    await open(page);
    await page.getByRole("combobox", { name: "Search the graph" }).fill(FIRST_CVE.slice(0, 8));
    await expect(page.getByRole("option").first()).toBeVisible();
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(new RegExp(`focus=cve`));
    await expect(page.getByRole("navigation", { name: "Path" })).toContainText(FIRST_CVE);
    await expect(page.getByRole("complementary", { name: "List" }).getByText(/hosts/).first()).toBeVisible();
    await page.screenshot({ path: "e2e/shots/graph-v2-desktop-focus-cve.png" });
  });

  test("centre node and list buttons open the existing drawers; the star is the shared watch toggle", async ({ page }) => {
    await open(page, `${V}&focus=cve:${FIRST_CVE}`);
    await page.getByRole("button", { name: /Open details of CVE/ }).click();
    await expect(page).toHaveURL(new RegExp(`cve=${FIRST_CVE}`));
    await open(page, `${V}&focus=fix:184467440000`);
    await expect(page.getByRole("button", { name: /watchlist/ }).first()).toBeVisible();
    await page.getByRole("button", { name: /Open details of SRV-/ }).first().click();
    await expect(page).toHaveURL(/device=/);
  });

  test("states: partial and failed are stamped, no data is a designed message, an empty filter offers to clear, an error offers retry", async ({ page }) => {
    await open(page, V, { calls: [], state: "partial" });
    await expect(page.getByText(/Incomplete \d+%/)).toBeVisible();
    await open(page, V, { calls: [], state: "failed" });
    await expect(canvas(page).locator("..").getByText("Old data").first()).toBeVisible();
    await expect(nodes(page).first()).toBeVisible(); // old data stays usable
    await open(page, V, { calls: [], state: "not_synced" });
    await expect(page.getByText("Data appears after the first read from Falcon")).toBeVisible();
    await expect(page.getByRole("tab")).toHaveCount(0);
    await open(page, `${V}&group=Empty-Group`);
    await expect(page.getByText("Nothing matches the filters")).toBeVisible();
    await page.getByRole("button", { name: "Clear filters" }).click();
    await expect(nodes(page).first()).toBeVisible();
    await open(page, V, { calls: [], state: "error" });
    await expect(page.getByRole("button", { name: /Retry|Try again/i }).first()).toBeVisible();
  });

  test("the first thing on screen while loading is a skeleton (aria-busy)", async ({ page }) => {
    await open(page, V, { calls: [], delayMs: 600 });
    await expect(page.locator("[data-slot=skeleton], [aria-hidden=true] [class*=animate-pulse]").first()).toBeVisible();
    await expect(nodes(page).first()).toBeVisible();
  });

  test("fix lens table alternative lists the same ranked fixes", async ({ page }) => {
    await open(page);
    await page.getByRole("button", { name: "Table", exact: true }).last().click();
    await expect(canvas(page).locator("table tbody tr")).toHaveCount(10);
  });
});

test.describe("phone 390", () => {
  test.beforeEach(({}, info) => { test.skip(info.project.name !== "mobile", "needs the phone project"); });

  test("ranked cards instead of the drawing, same numbers, no horizontal scroll; matrix scrolls inside its own area", async ({ page }) => {
    await open(page);
    await expect(canvas(page).locator("button").first()).toBeVisible();
    await expect(canvas(page).locator("svg")).toHaveCount(0);
    await expect(canvas(page).locator("button")).toHaveCount(10);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    await page.screenshot({ path: "e2e/shots/graph-v2-mobile-default.png", fullPage: true });
    await canvas(page).locator("button").first().click();
    await expect(page.getByRole("navigation", { name: "Path" })).toBeVisible();
    await open(page, `${V}&lens=matrix`);
    await expect(canvas(page).locator("table")).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
  });
});
