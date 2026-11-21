import { test as base, expect, type Page, type Browser } from "@playwright/test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const AUTH = join(dirname(fileURLToPath(import.meta.url)), ".auth");
export const env = () => JSON.parse(readFileSync(join(AUTH, "env.json"), "utf8")) as {
  tenants: { alpha: string; beta: string; empty: string }; cids: { alpha: string; beta: string };
  users: Record<string, string>; password: string; baseURL: string; ports: { app: number; mock: number; smtp: number };
};

export type UserName = "super" | "alphaAdmin" | "alphaOp" | "betaOp" | "multi" | "emptyOp";

// Console messages that are not bugs. Keep this list short and explain every entry.
const BENIGN = [
  /Failed to load resource: the server responded with a status of (401|403|404)/, // expected refusals that tests provoke on purpose
];

/** Collects console errors and uncaught page errors; call `check()` at the end of a test. */
export function watchErrors(page: Page) {
  const errors: string[] = [];
  page.on("console", (m) => { if (m.type() === "error" && !BENIGN.some((b) => b.test(m.text()))) errors.push(m.text()); });
  page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`));
  return { errors, check: () => expect(errors, "console/page errors").toEqual([]) };
}

export async function expectNoHorizontalScroll(page: Page) {
  const w = await page.evaluate(() => ({ s: document.documentElement.scrollWidth, c: document.documentElement.clientWidth }));
  expect(w.s, `page scrolls sideways (${w.s} > ${w.c})`).toBeLessThanOrEqual(w.c);
}

async function pageAs(browser: Browser, name: UserName, baseURL: string | undefined, opts: object) {
  const context = await browser.newContext({ ...opts, baseURL, storageState: join(AUTH, `${name}.json`) });
  return { context, page: await context.newPage() };
}

type Fixtures = {
  /** A page already signed in as the named seeded user (its own context; close is automatic). */
  as: (name: UserName) => Promise<Page>;
  superPage: Page; adminPage: Page; operatorPage: Page; multiPage: Page; emptyPage: Page;
  /** Fails the test at the end if the page logged console or page errors. */
  expectNoConsoleErrors: Page;
};

export const test = base.extend<Fixtures>({
  as: async ({ browser, baseURL, contextOptions, viewport, isMobile, hasTouch, deviceScaleFactor }, provide) => {
    const open: { close: () => Promise<void> }[] = [];
    await provide(async (name) => {
      const { context, page } = await pageAs(browser, name, baseURL, { ...contextOptions, viewport, isMobile, hasTouch, deviceScaleFactor });
      open.push(context);
      return page;
    });
    for (const c of open) await c.close();
  },
  // A SOC user with several organizations lands on the all-organizations portfolio until one is picked; the data tests are about one organization, so it starts with Alpha picked.
  // A test of the landing itself removes it (see part2-fixes.spec.ts).
  superPage: async ({ as }, provide) => {
    const page = await as("super");
    await page.addInitScript((id) => { try { if (!localStorage.getItem("tenix.org")) localStorage.setItem("tenix.org", id); } catch { /* ignore */ } }, env().tenants.alpha);
    await provide(page);
  },
  adminPage: ({ as }, provide) => as("alphaAdmin").then(provide),
  operatorPage: ({ as }, provide) => as("alphaOp").then(provide),
  multiPage: ({ as }, provide) => as("multi").then(provide),
  emptyPage: ({ as }, provide) => as("emptyOp").then(provide),
  expectNoConsoleErrors: async ({ page }, provide) => {
    const w = watchErrors(page);
    await provide(page);
    w.check();
  },
});

export { expect };
