import type { Browser, BrowserContext, Page, TestInfo } from "@playwright/test";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { UserName } from "./fixtures";

const HERE = dirname(fileURLToPath(import.meta.url));
export const SHOTS = join(HERE, "shots");
export type Theme = "light" | "dark";

/** New context signed in as `name` (null = signed out) with the theme preset in localStorage before load. */
export async function ctxAs(browser: Browser, info: TestInfo, name: UserName | null, theme: Theme): Promise<{ context: BrowserContext; page: Page }> {
  const u = info.project.use;
  const context = await browser.newContext({
    baseURL: u.baseURL, viewport: u.viewport, isMobile: u.isMobile, hasTouch: u.hasTouch, deviceScaleFactor: u.deviceScaleFactor,
    ...(name ? { storageState: join(HERE, ".auth", `${name}.json`) } : {}),
  });
  await context.addInitScript((t) => { try { localStorage.setItem("theme-mode", t); localStorage.setItem("theme", t); } catch { /* ignore */ } }, theme);
  return { context, page: await context.newPage() };
}

/** Wait until no skeleton is on screen and charts have finished animating. */
export async function settle(page: Page) {
  await page.waitForLoadState("networkidle").catch(() => {});
  await page.waitForFunction(() => document.querySelectorAll("[data-slot=skeleton]").length === 0, null, { timeout: 15000 }).catch(() => {});
  await page.waitForTimeout(1300);
}

export interface Target { id: string; user: UserName | null; path: string; prep?: (page: Page) => Promise<void>; drawer?: boolean }

/** Ids of the first CVE and device the super admin sees. */
export async function firstIds(page: Page) {
  const orgs = await (await page.request.get("/api/tenants")).json().catch(() => null);
  const tenantId: string | undefined = (Array.isArray(orgs) ? orgs : orgs?.tenants ?? orgs?.rows)?.[0]?.id;
  const q = tenantId ? `&tenantId=${tenantId}` : "";
  const v = await (await page.request.get(`/api/exposure/vulnerabilities?page=1&pageSize=1&sort=severity${q}`)).json();
  const h = await (await page.request.get(`/api/exposure/hosts?page=1&pageSize=1${q}`)).json();
  return { cve: v.rows?.[0]?.cveId as string, aid: (h.rows?.[0]?.aid ?? h.hosts?.[0]?.aid) as string, tenantId, vkeys: Object.keys(v), hkeys: Object.keys(h) };
}

export const METRICS_JS = () => {
  const vh = window.innerHeight;
  const doc = document.documentElement;
  const docH = Math.max(doc.scrollHeight, vh);
  let bottom = 0;
  const main = document.querySelector("main") ?? document.body;
  main.querySelectorAll<HTMLElement>("*").forEach((el) => {
    const cs = getComputedStyle(el);
    if (cs.position === "fixed" || cs.visibility === "hidden" || cs.display === "none") return;
    const r = el.getBoundingClientRect();
    if (r.width < 4 || r.height < 4) return;
    // only boxes that carry something visible: text, border or background
    const hasText = Array.from(el.childNodes).some((n) => n.nodeType === 3 && (n.textContent ?? "").trim());
    const visible = hasText || cs.borderTopWidth !== "0px" || (cs.backgroundColor !== "rgba(0, 0, 0, 0)") || el.tagName === "svg" || el.tagName === "CANVAS";
    if (visible) bottom = Math.max(bottom, r.bottom + window.scrollY);
  });
  const tables = Array.from(document.querySelectorAll("main table, [role=dialog] table")).map((t) => ({
    rows: t.querySelectorAll("tbody tr").length, cols: t.querySelectorAll("thead th").length || (t.querySelector("tr")?.children.length ?? 0), width: Math.round(t.getBoundingClientRect().width),
  }));
  const mr = main.getBoundingClientRect();
  const cards = Array.from(main.querySelectorAll<HTMLElement>("[class*='rounded-xl'][class*='border']"));
  return {
    viewportH: vh, docH, contentBottom: Math.round(bottom), blankBelowPx: Math.max(0, Math.round(docH - bottom)),
    blankBelowRatio: +(Math.max(0, docH - bottom) / docH).toFixed(2),
    textChars: (main as HTMLElement).innerText.length, tables, cards: cards.length,
    mainWidth: Math.round(mr.width), hScroll: doc.scrollWidth > doc.clientWidth,
    chartCount: main.querySelectorAll(".apexcharts-canvas").length,
  };
};
