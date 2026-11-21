import { env, expect, expectNoHorizontalScroll, test } from "./fixtures";
import { drawer, main, overviewV2, sql, tenantId, useTenant } from "./helpers";

// Regressions found by the part-1 human QA (Overview, SOC portfolio, Vulnerabilities, Devices, Software and their drawers).

const orgPill = (page: import("@playwright/test").Page) => page.getByRole("button", { name: /^Organization:/ });
const orgList = (page: import("@playwright/test").Page) => page.getByRole("listbox", { name: "Organization" });

test("org switcher: SOC gets 'All organizations' that opens the portfolio, and a pick returns to one organization", async ({ superPage: page }) => {
  await useTenant(page, "alpha");
  await page.goto("/");
  await expect(main(page).getByRole("heading", { name: "Overview", exact: true })).toBeVisible();
  await orgPill(page).click();
  await orgList(page).getByRole("button", { name: "All organizations" }).click();
  await expect(page).toHaveURL(/\/\?view=all$/);
  await expect(main(page).getByRole("heading", { name: "Overview of all organizations" })).toBeVisible();
  await expect(orgPill(page)).toContainText("All organizations");
  await orgPill(page).click();
  await orgList(page).getByRole("button", { name: "Beta Ltd" }).click();
  await expect(page).toHaveURL((u) => u.pathname === "/" && !u.searchParams.has("view"));
  await expect(orgPill(page)).toContainText("Beta Ltd");
  await expect(main(page).getByRole("heading", { name: "Overview", exact: true })).toBeVisible();
});

test("org switcher: customers never get 'All organizations'", async ({ multiPage: page, operatorPage }) => {
  await page.goto("/");
  await orgPill(page).click(); // multi has two organizations, so a list
  await expect(orgList(page)).toBeVisible();
  await expect(orgList(page).getByText("All organizations")).toHaveCount(0);
  await operatorPage.goto("/");
  await expect(orgPill(operatorPage)).toHaveCount(0); // one organization: a plain label, not a switcher
});

test("overview: the tier cards agree with the headline and never claim 'held' above the total", async ({ superPage: page }, info) => {
  test.skip(info.project.name !== "desktop", "same data on both projects");
  await useTenant(page, "alpha");
  const truth = await overviewV2("alpha");
  await page.goto("/");
  const p1 = page.getByTestId("p1-number");
  await expect(p1).toContainText(String(truth.p1.toLocaleString("en-US")));
  const tiers = page.locator("h3", { hasText: "Exposure by tier" }).locator("xpath=ancestor::section[1]");
  await expect(tiers.locator("a").first()).toContainText(truth.p1.toLocaleString("en-US")); // P1 row: Falcon's count equals what we hold
  await expect(tiers).toContainText(/Held [\d,]+ of [\d,]+ \(100%\)/);
  // Falcon counting less than we hold (old mock quirk, real lag): the card uses what we hold as the total and says "held in full"
  await page.route("**/api/exposure/v2/summary**", async (route) => {
    const r = await route.fetch();
    const body = await r.json();
    body.tiers.P1.total = Math.floor(body.tiers.P1.held * 0.6);
    await route.fulfill({ response: r, json: body });
  });
  await page.reload();
  await expect(tiers.locator("a").first()).toContainText(truth.p1.toLocaleString("en-US"));
  await expect(tiers.locator("a").first()).toContainText("held in full");
  await expect(tiers.locator("a").first()).not.toContainText(" of ");
});

test("overview: 'most vulnerable software' is read by risk, and an unnamed device never shows its raw id", async ({ superPage: page }, info) => {
  test.skip(info.project.name !== "desktop", "same data on both projects");
  await useTenant(page, "alpha");
  const req = page.waitForRequest((r) => /\/api\/exposure\/software\?sort=risk&pageSize=6/.test(r.url()));
  await page.goto("/");
  await req;
  await expect(main(page).getByText(/Most P1 CVEs, then KEV/)).toBeVisible();
  await expect(main(page).getByText(/\b[0-9a-f]{32}\b/)).toHaveCount(0);
});

test("portfolio: an organization with no CID is 'no data', not 'old data', and is not a connection failure", async ({ superPage: page }) => {
  await page.goto("/?view=all");
  const row = page.locator("div.grid", { hasText: "Empty Inc" }).filter({ hasText: "No CID linked" }).first();
  await expect(row).toBeVisible();
  await expect(row).not.toContainText("Old data");
  await expect(row).not.toContainText(/old data/i);
  await expect(page.getByRole("button", { name: /cannot connect/ })).toContainText(/^0/); // nothing is broken: the queue says "Nothing needs attention"
  await expect(page.getByText("Nothing needs attention")).toBeVisible();
});

test("software: the 'Software items' stat is the number of products the list holds", async ({ superPage: page }) => {
  await useTenant(page, "alpha");
  const [{ n }] = await sql<{ n: number }>(`SELECT COUNT(*)::int n FROM (SELECT 1 FROM software WHERE cid IN (SELECT cid FROM tenant_cids WHERE tenant_id = $1) GROUP BY type, vendor, name) x`, [tenantId("alpha")]);
  await page.goto("/software");
  await expect(page.getByText(`${n} items`, { exact: true })).toBeVisible();
  await expect(page.getByText("Software items").locator("xpath=../..")).toHaveText(new RegExp(`Software items\\s*${n}$`));
});

test("vulnerabilities: why-chips are not repeated under every desktop row (the columns carry KEV, exploit and ExPRT)", async ({ superPage: page }, info) => {
  test.skip(info.project.name !== "desktop", "the phone list keeps the chips");
  await useTenant(page, "alpha");
  await page.goto("/vulnerabilities?kev=1");
  const first = main(page).locator("tbody tr").first();
  await expect(first).toBeVisible();
  await expect(first).not.toContainText("Exploited");
  await expect(first).not.toContainText("ExPRT ");
});

test("CVE drawer: the KEV badge and the 'In CISA KEV' block give the same answer; the fix drawer has no NaN", async ({ superPage: page }) => {
  await useTenant(page, "alpha");
  // a KEV CVE that has a public record (the block exists only then); the bug was a badge saying KEV beside a block saying No
  const kev = (await (await page.request.get(`/api/exposure/v2/vulnerabilities?tenantId=${tenantId("alpha")}&kev=1&pageSize=25`)).json()).rows as { cveId: string }[];
  let id = "";
  for (const r of kev) if ((await (await page.request.get(`/api/exposure/vulnerabilities/${r.cveId}?tenantId=${tenantId("alpha")}`)).json()).public) { id = r.cveId; break; }
  expect(id, "a KEV CVE with a public record").not.toBe("");
  await page.goto(`/vulnerabilities?cve=${id}`);
  const d = drawer(page);
  await expect(d.getByText("Actively exploited (CISA KEV)").first()).toBeVisible();
  const block = d.locator("section").filter({ has: page.getByRole("heading", { name: "In CISA KEV" }) });
  await expect(block).toContainText("Yes");
  await expect(block).not.toContainText(/\bNo\b/);
  const fix = await page.request.get(`/api/exposure/v2/fixes?tenantId=${tenantId("alpha")}&pageSize=1`);
  const fixId = (await fix.json()).rows[0].id as string;
  await page.goto(`/vulnerabilities?fix=${fixId}`);
  await expect(drawer(page).getByText("P1 · P2 · P3")).toBeVisible();
  await expect(drawer(page)).not.toContainText("NaN");
});

test("no-data overview: the watchlist is not stamped 'Old data' when nothing was ever read", async ({ emptyPage: page }) => {
  await page.goto("/");
  await expect(page.getByText("There are no numbers to show")).toBeVisible();
  await expect(main(page).getByText("Old data")).toHaveCount(0);
  await expectNoHorizontalScroll(page);
});
