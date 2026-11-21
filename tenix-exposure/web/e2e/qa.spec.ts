// QA: keyboard, skeleton-on-load and error-state checks. Writes e2e/shots/qa-<project>.json
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "./fixtures";
import { ctxAs, firstIds, settle, SHOTS } from "./qa-helpers";

let ids: Awaited<ReturnType<typeof firstIds>>;
const out: Record<string, unknown> = {};
test.beforeAll(async ({ browser }, info) => {
  const { context, page } = await ctxAs(browser, info, "super", "light");
  ids = await firstIds(page); await context.close(); mkdirSync(SHOTS, { recursive: true });
});
test.afterEach(async ({}, info) => writeFileSync(join(SHOTS, `qa-${info.project.name}-${info.title.replace(/\W+/g, "_")}.json`), JSON.stringify(out, null, 1)));

// [id, path, api pattern to delay/abort, drawer?]
const LOADS: [string, string, string, boolean?][] = [
  ["overview", "/", "**/api/exposure/summary*"], ["vulns", "/vulnerabilities", "**/api/exposure/vulnerabilities?*"],
  ["devices", "/devices", "**/api/exposure/hosts?*"], ["graph", "/graph", "**/api/exposure/graph*"],
  ["settings", "/settings", "**/api/feeds/status"],
  ["tenants", "/settings?setting=tenants", "**/api/tenants"], ["team", "/settings?setting=team", "**/api/team/users*"], ["audit", "/settings?setting=audit", "**/api/audit*"],
  ["team-admin-audit", "/team?tab=audit", "**/api/audit*"],
  ["integrations-line", "/settings?setting=line", "**/api/integrations/line"],
];

for (const [id, path, pat] of LOADS) {
  test(`skeleton + error ${id}`, async ({ browser }, info) => {
    test.setTimeout(60000);
    const r: Record<string, unknown> = {};
    // 1. delayed API: skeleton must be visible before data
    let { context, page } = await ctxAs(browser, info, "super", "light");
    await page.route(pat, async (route) => { await new Promise((s) => setTimeout(s, 2500)); await route.continue(); });
    await page.goto(path);
    r.skeletonWhileLoading = await page.locator("[data-slot=skeleton]").first().isVisible({ timeout: 2000 }).catch(() => false);
    await settle(page);
    r.skeletonGoneAfter = (await page.locator("[data-slot=skeleton]").count()) === 0;
    await context.close();
    // 2. aborted API: what does the user see?
    ({ context, page } = await ctxAs(browser, info, "super", "light"));
    await page.route(pat, (route) => route.abort());
    await page.goto(path); await page.waitForTimeout(2500);
    r.errorText = (await page.locator("main").innerText().catch(() => "")).replace(/\s+/g, " ").slice(0, 300);
    r.hasRetry = await page.getByRole("button", { name: /retry|try again/i }).count();
    await page.screenshot({ path: join(SHOTS, `${info.project.name}-light-error-${id}.png`) });
    await context.close();
    // 3. 500 response
    ({ context, page } = await ctxAs(browser, info, "super", "light"));
    await page.route(pat, (route) => route.fulfill({ status: 500, contentType: "application/json", body: '{"error":"boom"}' }));
    await page.goto(path); await page.waitForTimeout(2000);
    r.error500Text = (await page.locator("main").innerText().catch(() => "")).replace(/\s+/g, " ").slice(0, 300);
    await context.close();
    out[id] = r;
  });
}

for (const [id, pathFn, pat] of [
  ["cve-drawer", () => `/vulnerabilities?cve=${ids.cve}`, "**/api/exposure/vulnerabilities/*"],
  ["device-drawer", () => `/devices?device=${ids.aid}`, "**/api/exposure/hosts/*"],
] as [string, () => string, string][]) {
  test(`drawer skeleton + error ${id}`, async ({ browser }, info) => {
    test.setTimeout(60000);
    const r: Record<string, unknown> = {};
    let { context, page } = await ctxAs(browser, info, "super", "light");
    await page.route(pat, async (route) => { await new Promise((s) => setTimeout(s, 2500)); await route.continue(); });
    await page.goto(pathFn());
    r.skeletonWhileLoading = await page.locator("[role=dialog] [data-slot=skeleton]").first().isVisible({ timeout: 3000 }).catch(() => false);
    await context.close();
    ({ context, page } = await ctxAs(browser, info, "super", "light"));
    await page.route(pat, (route) => route.abort());
    await page.goto(pathFn()); await page.waitForTimeout(2500);
    r.errorText = (await page.locator("[role=dialog]").innerText().catch(() => "no dialog")).replace(/\s+/g, " ").slice(0, 300);
    await page.screenshot({ path: join(SHOTS, `${info.project.name}-light-error-${id}.png`) });
    await context.close();
    out[id] = r;
  });
}

test("keyboard", async ({ browser }, info) => {
  test.skip(info.project.name === "mobile", "keyboard walk-through of desktop tables");
  test.setTimeout(120000);
  const r: Record<string, unknown> = {};
  const { context, page } = await ctxAs(browser, info, "super", "light");
  // drawer open via row click, Esc, focus return
  await page.goto("/vulnerabilities"); await settle(page);
  const row = page.locator("tbody tr").first();
  r.rowFocusable = await row.evaluate((el) => el.tabIndex >= 0 || !!el.querySelector("a,button"));
  r.rowRole = await row.evaluate((el) => `${el.getAttribute("role")}|tabindex=${el.getAttribute("tabindex")}|innerLinks=${el.querySelectorAll("a,button").length}`);
  await row.locator("td").nth(2).click({ position: { x: 5, y: 5 } }); await page.waitForTimeout(400);
  r.rowCellClickOpens = (await page.locator("[role=dialog]").count()) > 0;
  if (!r.rowCellClickOpens) await row.locator("button:not([aria-pressed])").first().click();
  await page.waitForSelector("[role=dialog]");
  r.cveDrawerUrl = page.url();
  await page.keyboard.press("Escape");
  await page.waitForTimeout(600);
  r.escClosesCveDrawer = (await page.locator("[role=dialog]").count()) === 0 && !/cve=/.test(page.url());
  r.focusAfterEsc = await page.evaluate(() => { const a = document.activeElement as HTMLElement | null; return a ? `${a.tagName}|${(a.textContent ?? "").trim().slice(0, 30)}|inRow=${!!a.closest("tr")}` : "none"; });
  // device drawer + nested CVE drawer
  await page.goto("/devices"); await settle(page);
  await page.locator("tbody tr").first().locator("button:not([aria-pressed])").first().click(); await page.waitForSelector("[role=dialog]"); // the watch star in front of the name only toggles
  await page.keyboard.press("Escape"); await page.waitForTimeout(600);
  r.escClosesDeviceDrawer = (await page.locator("[role=dialog]").count()) === 0;
  r.focusAfterEscDevice = await page.evaluate(() => { const a = document.activeElement as HTMLElement | null; return a ? `${a.tagName}|inRow=${!!a.closest("tr")}` : "none"; });
  // dialogs: Team invite, Tenants new
  for (const [name, path, btn] of [["invite", "/settings?setting=team", /invite user/i], ["newTenant", "/settings?setting=tenants", /add organization/i]] as const) {
    await page.goto(path); await settle(page);
    const b = page.getByRole("button", { name: btn }); await b.focus(); await page.keyboard.press("Enter");
    await page.waitForSelector("[role=dialog]:not([data-slot=sheet-content])", { timeout: 4000 }).catch(() => {});
    const opened = (await page.locator("[role=dialog]:not([data-slot=sheet-content])").count()) > 0;
    await page.keyboard.press("Escape"); await page.waitForTimeout(500);
    r[`${name}Dialog`] = { opened, escCloses: (await page.locator("[role=dialog]:not([data-slot=sheet-content])").count()) === 0, focusBackOnTrigger: await b.evaluate((el) => el === document.activeElement, undefined, { timeout: 2000 }).catch(() => false) }; // false when the trigger is gone (the wizard replaces the Setting Center)
  }
  // icon-only controls without accessible name, and clickable non-focusables, per page
  const audit: Record<string, unknown> = {};
  for (const p of ["/", "/vulnerabilities", "/devices", "/graph", "/settings", "/settings?setting=tenants", "/settings?setting=team", "/settings?setting=line", "/settings?setting=audit", "/account"]) {
    await page.goto(p); await settle(page);
    audit[p] = await page.evaluate(() => {
      const name = (el: Element) => (el.getAttribute("aria-label") || el.getAttribute("aria-labelledby") || el.getAttribute("title") || (el as HTMLElement).innerText || "").trim();
      const unnamed = Array.from(document.querySelectorAll("button,[role=button],a,[role=tab],input,select")).filter((el) => !name(el) && !(el as HTMLInputElement).labels?.length && el.getAttribute("type") !== "hidden").map((el) => el.outerHTML.slice(0, 120));
      const clickNoFocus = Array.from(document.querySelectorAll("main *, [role=dialog] *")).filter((el) => getComputedStyle(el).cursor === "pointer" && !el.matches("a,button,input,select,label,[role=tab],[role=button],[role=combobox],[tabindex]") && !el.closest("a,button,[role=tab],[role=combobox],[tabindex]")).slice(0, 5).map((el) => el.tagName + "." + String(el.getAttribute("class")).slice(0, 60));
      const smallTargets = Array.from(document.querySelectorAll("button,a,[role=tab]")).filter((el) => { const b = el.getBoundingClientRect(); return b.width > 0 && (b.width < 24 || b.height < 24); }).length;
      return { unnamed, clickNoFocus, smallTargets };
    });
  }
  r.audit = audit;
  // Tab reach on vulnerabilities: how many tabs to reach the first row / cve link
  await page.goto("/vulnerabilities"); await settle(page);
  const seen: string[] = [];
  for (let i = 0; i < 40; i++) { await page.keyboard.press("Tab"); seen.push(await page.evaluate(() => { const a = document.activeElement as HTMLElement; return `${a.tagName}:${(a.getAttribute("aria-label") || a.textContent || "").trim().slice(0, 20)}`; })); }
  r.vulnsTabSequence = seen;
  out.keyboard = r;
  await context.close();
});

test("mobile overflow", async ({ browser }, info) => {
  test.skip(info.project.name !== "mobile");
  const { context, page } = await ctxAs(browser, info, "super", "light");
  const res: Record<string, unknown> = {};
  for (const p of ["/", "/vulnerabilities", "/devices", "/graph", "/settings", "/settings?setting=tenants", "/settings?setting=team", "/settings?setting=line", "/settings?setting=audit", "/account"]) {
    await page.goto(p); await settle(page);
    res[p] = await page.evaluate(() => {
      const doc = document.documentElement;
      const clipped = Array.from(document.querySelectorAll("table")).map((t) => {
        let el: HTMLElement | null = t.parentElement; while (el && el.scrollWidth <= el.clientWidth + 1 && el !== document.body) el = el.parentElement;
        const w = t.getBoundingClientRect().width;
        const box = t.parentElement!.getBoundingClientRect().width;
        return { tableW: Math.round(w), visibleW: Math.round(box), hiddenPct: Math.round(Math.max(0, 1 - box / w) * 100), cols: t.querySelectorAll("thead th").length, scroller: el ? getComputedStyle(el).overflowX : "none" };
      });
      const svgs = Array.from(document.querySelectorAll("main svg[role=img], main svg[width]")).filter((s) => s.getBoundingClientRect().width > 300).map((s) => ({ w: Math.round(s.getBoundingClientRect().width), parentClient: (s.parentElement as HTMLElement).clientWidth, parentScroll: (s.parentElement as HTMLElement).scrollWidth }));
      return { pageHScroll: doc.scrollWidth > doc.clientWidth, clipped, svgs };
    });
  }
  out.mobile = res; await context.close();
});
