import { expect, test } from "./fixtures";
import { useTenant } from "./helpers";
import { mockOverview } from "./overview-v2-mock";

// Spec 2.5: no number may be wider than its box, at any magnitude or screen width. The Overview is rendered with a mocked API that holds one number everywhere.
const VALUES = [0, 999, 7_790, 111_025, 858_001, 16_693_578];
const WIDTHS = [390, 768, 1280];

for (const width of WIDTHS) {
  for (const v of VALUES) {
    test(`numbers fit their boxes: ${v.toLocaleString("en-US")} at ${width}px`, async ({ superPage: page }, info) => {
      test.skip(info.project.name !== "desktop", "viewport is set by the test itself");
      await page.setViewportSize({ width, height: 900 });
      await useTenant(page, "alpha");
      await mockOverview(page, { scenario: "complete", value: v });
      await page.goto("/");
      const metrics = page.locator("[data-metric]");
      await expect(metrics.first()).toBeVisible();
      await page.waitForTimeout(1300); // count-up finished
      const bad = await metrics.evaluateAll((els) => els.flatMap((box) => [...box.children].map((c) => ({
        text: c.textContent, sw: c.scrollWidth, cw: c.clientWidth, bw: (box as HTMLElement).clientWidth,
      })).filter((m) => m.sw > m.cw || m.sw > m.bw)));
      expect(bad, "a number is wider than its box").toEqual([]);
      expect(await metrics.count()).toBeGreaterThanOrEqual(5); // the P1 headline and its four fact tiles
      // the table cells of the Overview lists hold the same number: none is cut by its cell
      const cut = await page.locator("main [class*=tabular-nums]").evaluateAll((els) => els.filter((e) => e.scrollWidth > e.clientWidth + 1 && getComputedStyle(e).overflow === "visible" && getComputedStyle(e).display !== "inline").length);
      expect(cut, "a number is cut by its cell").toBe(0);
      // 16.7M is short, with the full value beside it for touch and screen readers
      if (v === 16_693_578) await expect(page.locator("[data-testid=p1-number] [aria-label]").first()).toHaveAttribute("aria-label", "16,693,578");
    });
  }
}
