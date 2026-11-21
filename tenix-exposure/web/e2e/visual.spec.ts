// QA: full-page screenshots + density metrics for every page. Output: e2e/shots/*.png and e2e/shots/metrics-<project>.json
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "./fixtures";
import { ctxAs, firstIds, METRICS_JS, settle, SHOTS, type Target, type Theme } from "./qa-helpers";

let ids: Awaited<ReturnType<typeof firstIds>>;

const targets = (): Target[] => [
  { id: "overview", user: "super", path: "/" },
  { id: "vulns", user: "super", path: "/vulnerabilities" },
  { id: "vulns-cve-drawer", user: "super", path: `/vulnerabilities?cve=${ids.cve}`, drawer: true },
  { id: "devices", user: "super", path: "/devices" },
  { id: "devices-drawer", user: "super", path: `/devices?device=${ids.aid}`, drawer: true },
  { id: "graph", user: "super", path: "/graph" },
  { id: "software", user: "super", path: "/software" },
  { id: "software-drawer", user: "super", path: "/software?q=Chrome", prep: async (p) => { await p.locator("tbody tr td:first-child button, ul.divide-y > li > button").locator("visible=true").first().click(); await p.waitForTimeout(600); } },
  { id: "settings", user: "super", path: "/settings" },
  { id: "tenants", user: "super", path: "/settings?setting=tenants", drawer: true },
  { id: "team", user: "super", path: "/settings?setting=team", drawer: true },
  { id: "integrations-line", user: "super", path: "/settings?setting=line", drawer: true },
  { id: "integrations-email", user: "super", path: "/settings?setting=email", drawer: true },
  { id: "audit", user: "super", path: "/settings?setting=audit", drawer: true },
  { id: "account", user: "super", path: "/account" },
  { id: "signin", user: null, path: "/signin" },
  { id: "op-overview", user: "alphaOp", path: "/" },
  { id: "op-vulns", user: "alphaOp", path: "/vulnerabilities" },
  { id: "admin-team", user: "alphaAdmin", path: "/team" },
  { id: "admin-team-audit", user: "alphaAdmin", path: "/team?tab=audit" },
  { id: "empty-overview", user: "emptyOp", path: "/" },
];

const ALL = ["overview", "vulns", "vulns-cve-drawer", "devices", "devices-drawer", "graph", "software", "software-drawer", "settings", "tenants", "team", "integrations-line", "integrations-email", "audit", "account", "signin", "op-overview", "op-vulns", "admin-team", "admin-team-audit", "empty-overview"];

test.describe.configure({ mode: "serial" });
test.beforeAll(async ({ browser }, info) => {
  const { context, page } = await ctxAs(browser, info, "super", "light");
  ids = await firstIds(page);
  console.log("IDS", JSON.stringify(ids));
  await context.close();
  mkdirSync(SHOTS, { recursive: true });
});

for (const id of ALL) {
  test(`shot ${id}`, async ({ browser }, info) => {
    test.setTimeout(120000);
    const t = targets().find((x) => x.id === id)!;
    const out: Record<string, unknown> = {};
    for (const theme of ["light"] as Theme[]) { // dark mode is switched off
      const { context, page } = await ctxAs(browser, info, t.user, theme);
      await page.goto(t.path);
      await settle(page);
      if (t.prep) { await t.prep(page); await settle(page); }
      const m = await page.evaluate(METRICS_JS);
      out[theme] = m;
      await page.screenshot({ path: join(SHOTS, `${info.project.name}-${theme}-${id}.png`), fullPage: !t.drawer });
      await context.close();
    }
    writeFileSync(join(SHOTS, `metrics-${info.project.name}-${id}.json`), JSON.stringify(out, null, 1));
  });
}
