import { expect, expectNoHorizontalScroll, test } from "./fixtures";
import { useTenant } from "./helpers";
import { mockOverview, type Scenario } from "./overview-v2-mock";

// Overview v2 against a mocked API (contracts A and B): every data state, the 16.7M stress, at a desktop and a phone width.
// The page, the session and the router are real; only the data endpoints of the Overview are replaced.
const WIDTHS = [1280, 390];

const CASES: { name: string; scenario: Scenario; stress?: boolean; texts: (string | RegExp)[]; absent?: string[] }[] = [
  { name: "complete", scenario: "complete", texts: ["Fix now (P1)", "1,240", "Data is complete", "What to fix first", "Watchlist", "Exposure by tier", "By severity", "CVE news that affects you", "External attack surface (EASM)", "Data coverage and sync"] },
  { name: "slice", scenario: "slice", texts: ["301,274", /Detail kept for 1,085,590 of 16,700,573 findings/, "held 784,316 of 7,441,239 (10.5%)", "counted by Falcon only"] },
  { name: "partial", scenario: "partial", texts: ["Data is incomplete", "at least (not all read yet)"] },
  { name: "failed", scenario: "failed", texts: ["Could not read data from Falcon", /OLD data/, "1,240"] },
  { name: "no_connection", scenario: "no_connection", texts: ["No Falcon connection", "There are no numbers to show"], absent: ["Fix now (P1)"] },
  { name: "16.7M stress", scenario: "slice", stress: true, texts: ["16.7M", "16,693,578"] },
];

for (const width of WIDTHS) {
  for (const c of CASES) {
    test(`overview v2: ${c.name} at ${width}px`, async ({ superPage: page }, info) => {
      test.skip(info.project.name !== "desktop", "viewport is set by the test itself");
      await page.setViewportSize({ width, height: 900 });
      await useTenant(page, "alpha");
      await mockOverview(page, { scenario: c.scenario, stress: c.stress });
      await page.goto("/");
      await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
      await expect(page.getByText("Watchlist", { exact: true }).first()).toBeVisible();
      await page.waitForTimeout(1300); // count-up finished
      for (const t of c.texts) await expect(page.getByText(t).first()).toBeVisible();
      for (const t of c.absent ?? []) await expect(page.getByText(t, { exact: true })).toHaveCount(0);
      await expectNoHorizontalScroll(page);
      const bad = await page.locator("[data-metric]").evaluateAll((els) => els.flatMap((box) => [...box.children].map((ch) => ({ text: ch.textContent, sw: ch.scrollWidth, cw: ch.clientWidth, bw: (box as HTMLElement).clientWidth })).filter((m) => m.sw > m.cw || m.sw > m.bw)));
      expect(bad, "a number is wider than its box").toEqual([]);
      if (c.stress) await expect(page.locator("[data-testid=p1-number] [aria-label]").first()).toHaveAttribute("aria-label", "16,693,578");
      if (c.scenario === "failed") await expect(page.getByText("Old data").first()).toBeVisible();
      if (width === 390 && c.scenario === "complete") {
        // phone order: headline, fix first, watchlist, tiers, trend
        const y = async (t: string) => (await page.getByText(t, { exact: true }).first().boundingBox())!.y;
        const order = [await y("Fix now (P1)"), await y("What to fix first"), await y("Watchlist"), await y("Exposure by tier"), await y("P1 open per day")];
        expect(order).toEqual([...order].sort((a, b) => a - b));
      }
      await page.screenshot({ path: `e2e/shots/overview-v2-${c.name.replace(/\W+/g, "-")}-${width}.png`, fullPage: true });
    });
  }
}

test("overview v2: watchlist star removes with an undo toast and puts the host back", async ({ superPage: page }, info) => {
  test.skip(info.project.name !== "desktop", "viewport is set by the test itself");
  await page.setViewportSize({ width: 1280, height: 900 });
  await useTenant(page, "alpha");
  await mockOverview(page, { scenario: "complete" });
  await page.goto("/");
  const star = page.locator('button[aria-pressed][aria-label="Remove BKK-DC-01 from the watchlist"]').first();
  await expect(star).toHaveAttribute("aria-pressed", "true");
  const put = page.waitForRequest((r) => r.method() === "PUT" && r.url().includes("/api/exposure/watchlist/a0"));
  await star.click();
  await expect(page.getByRole("status").getByText("Removed BKK-DC-01 from the watchlist")).toBeVisible();
  await expect(page.locator('button[aria-pressed][aria-label="Add BKK-DC-01 to the watchlist"]').first()).toHaveAttribute("aria-pressed", "false");
  await page.getByRole("status").getByRole("button", { name: "Undo" }).click();
  expect((await put).headers()["content-type"]).toContain("application/json");
  await expect(page.locator('button[aria-pressed][aria-label="Remove BKK-DC-01 from the watchlist"]').first()).toHaveAttribute("aria-pressed", "true");
});

for (const width of WIDTHS) {
  test(`overview v2: SOC portfolio at ${width}px`, async ({ superPage: page }, info) => {
    test.skip(info.project.name !== "desktop", "viewport is set by the test itself");
    await page.setViewportSize({ width, height: 900 });
    await mockOverview(page, { scenario: "slice" });
    await page.goto("/?view=all");
    await expect(page.getByRole("heading", { name: "Overview of all organizations" })).toBeVisible();
    for (const t of ["Look at first", "CVEs hitting several organizations", "Syncs in the last 24 hours"]) await expect(page.getByText(t, { exact: true })).toBeVisible();
    await expect(page.getByText("Siam Retail Group").first()).toBeVisible();
    await expect(page.getByText("Old data").locator("visible=true").first()).toBeVisible(); // the broken tenant keeps its numbers, stamped
    await expectNoHorizontalScroll(page);
    await page.screenshot({ path: `e2e/shots/overview-v2-portfolio-${width}.png`, fullPage: true });
  });
}

test("overview v2: a customer never sees the portfolio switch or the portfolio", async ({ operatorPage: page }, info) => {
  test.skip(info.project.name !== "desktop", "viewport is set by the test itself");
  await mockOverview(page, { scenario: "complete" });
  await page.goto("/?view=all");
  await expect(page.getByRole("heading", { name: "Overview", exact: true })).toBeVisible();
  await expect(page.getByText("All organizations", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Look at first")).toHaveCount(0);
});
