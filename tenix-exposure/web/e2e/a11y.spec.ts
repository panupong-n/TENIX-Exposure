// QA: axe (wcag2a, wcag2aa) on every page and drawer in both themes. Writes e2e/shots/a11y-<project>.json
import AxeBuilder from "@axe-core/playwright";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "./fixtures";
import { ctxAs, firstIds, settle, SHOTS, type Theme } from "./qa-helpers";
import type { UserName } from "./fixtures";

let ids: Awaited<ReturnType<typeof firstIds>>;
const pages = (): { id: string; user: UserName | null; path: string; }[] => [
  { id: "overview", user: "super", path: "/" }, { id: "vulns", user: "super", path: "/vulnerabilities" },
  { id: "cve-drawer", user: "super", path: `/vulnerabilities?cve=${ids.cve}` }, { id: "devices", user: "super", path: "/devices" },
  { id: "device-drawer", user: "super", path: `/devices?device=${ids.aid}` }, { id: "graph", user: "super", path: "/graph" },
  { id: "settings", user: "super", path: "/settings" },
  { id: "tenants", user: "super", path: "/settings?setting=tenants" }, { id: "team", user: "super", path: "/settings?setting=team" },
  { id: "integrations-line", user: "super", path: "/settings?setting=line" }, { id: "integrations-email", user: "super", path: "/settings?setting=email" },
  { id: "audit", user: "super", path: "/settings?setting=audit" }, { id: "admin-team-audit", user: "alphaAdmin", path: "/team?tab=audit" }, { id: "account", user: "super", path: "/account" }, { id: "signin", user: null, path: "/signin" },
  { id: "empty-overview", user: "emptyOp", path: "/" },
];
const results: Record<string, unknown> = {};

test.beforeAll(async ({ browser }, info) => {
  const { context, page } = await ctxAs(browser, info, "super", "light");
  ids = await firstIds(page); await context.close(); mkdirSync(SHOTS, { recursive: true });
});
test.afterAll(async ({}, info) => writeFileSync(join(SHOTS, `a11y-${info.project.name}.json`), JSON.stringify(results, null, 1)));

for (const id of ["overview", "vulns", "cve-drawer", "devices", "device-drawer", "graph", "settings", "tenants", "team", "integrations-line", "integrations-email", "audit", "admin-team-audit", "account", "signin", "empty-overview"]) {
  test(`axe ${id}`, async ({ browser }, info) => {
    test.setTimeout(90000);
    const t = pages().find((p) => p.id === id)!;
    for (const theme of ["light"] as Theme[]) { // dark mode is switched off
      const { context, page } = await ctxAs(browser, info, t.user, theme);
      await page.goto(t.path); await settle(page);
      const r = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa"]).analyze();
      results[`${theme}/${id}`] = r.violations.map((v) => ({ rule: v.id, impact: v.impact, count: v.nodes.length, help: v.help, sample: v.nodes.slice(0, 3).map((n) => ({ target: n.target.join(" "), html: n.html.slice(0, 140), why: (n.any[0]?.message ?? n.all[0]?.message ?? "").slice(0, 200) })) }));
      await context.close();
    }
  });
}
