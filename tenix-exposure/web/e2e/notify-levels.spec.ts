import { expect, expectNoHorizontalScroll, test } from "./fixtures";
import { useTenant } from "./helpers";
import { mockOverview } from "./overview-v2-mock";
import type { Route } from "@playwright/test";

// Notify-level section of the LINE settings and the watchlist level picker, against mocked API answers.
// Runs under the normal config (needs the e2e stack) or standalone like misc-v2: npx playwright test -c e2e/misc-v2.config.ts notify-levels
const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, json: body });
const LV = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
const rule = (c: number, a: number) => (c === a ? LV[c] : LV[Math.max(c, a) <= 1 ? Math.min(c, a) : Math.min(3, Math.min(c, a) + 1)]);
const defaultMatrix = Object.fromEntries(LV.map((c, ci) => [c, Object.fromEntries(LV.map((a, ai) => [a, rule(ci, ai)]))]));
const prefs = { enabled: true, severities: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"], p1Always: true, devicesMode: "all", topN: 10, maxNames: 20, newsPossible: false, newsHostNames: false, updatedAt: null, updatedBy: null,
  matrixOn: false, matrix: defaultMatrix, escAlert: true, escDays: 7, escKev: false };

test("matrix: defaults, the two executive examples, edit a cell, reset, escalation, group map, save", async ({ page }) => {
  await page.route("**/api/**", (r) => json(r, { error: "not mocked", code: null }, 404));
  await page.route("**/api/auth/me", (r) => json(r, { user: { id: "u1", email: "a@x.io", name: "Alice", role: "member", soc: false, manager: true, totpEnabled: true, tenants: [{ id: "t1", name: "Alpha Corp", role: "admin" }] } }));
  await page.route("**/api/tenants", (r) => json(r, { tenants: [{ id: "t1", name: "Alpha Corp", role: "admin" }] }));
  const puts: { matrixOn: boolean; matrix: unknown; escDays: number; escKev: boolean; escAlert: boolean; groupLevels: unknown }[] = [];
  const view = (evidence: string) => ({ tenantId: "t1", canEdit: true, isDefault: true, prefs, defaultMatrix, evidence: { state: evidence, checkedAt: null }, groupLevels: [], knownGroups: ["Servers", "Kiosk"], watchedCount: 0, destinations: { count: 1, names: ["g"] } });
  const evidence = "forbidden";
  await page.route("**/api/tenants/t1/notify", (r) => { if (r.request().method() === "PUT") { puts.push(r.request().postDataJSON()); return json(r, view("ok")); } return json(r, view(evidence)); });
  await page.route("**/api/tenants/t1/notify/preview", (r) => json(r, { sample: true, cve: null, messages: [], dropped: true, truncated: false }));
  await page.goto("/news?settings=notify");
  const dlg = page.getByTestId("settings-notify");
  await expect(dlg.getByTestId("notify-matrix")).toBeVisible();
  await expect(dlg.getByTestId("notify-cell-CRITICAL-LOW")).toHaveValue("HIGH");
  await expect(dlg.getByTestId("notify-example-CRITICAL-LOW")).toContainText("High");
  await expect(dlg.getByTestId("notify-example-MEDIUM-CRITICAL")).toContainText("High");
  await expect(dlg.getByTestId("notify-esc-status")).toContainText("No permission to check evidence");
  await expect(dlg.getByTestId("notify-esc-kev")).not.toBeChecked();
  await expect(dlg.getByTestId("notify-matrix-reset")).toBeDisabled();
  await dlg.getByTestId("notify-cell-CRITICAL-LOW").selectOption("CRITICAL");
  await expect(dlg.getByTestId("notify-example-CRITICAL-LOW")).toContainText("Critical");
  await expect(dlg.getByTestId("notify-matrix-reset")).toBeEnabled();
  await dlg.getByTestId("notify-matrix-reset").click();
  await expect(dlg.getByTestId("notify-cell-CRITICAL-LOW")).toHaveValue("HIGH");
  await dlg.getByTestId("notify-matrix-on").click();
  await dlg.getByTestId("notify-esc-days").fill("3");
  await dlg.getByTestId("notify-esc-kev").check();
  await dlg.getByTestId("notify-group-add").click();
  await dlg.getByTestId("notify-group-name").fill("Kiosk");
  await dlg.getByTestId("notify-group-level").selectOption("LOW");
  await dlg.getByTestId("notify-save").click();
  await expect.poll(() => puts.length).toBe(1);
  expect(puts[0]).toMatchObject({ matrixOn: true, escDays: 3, escKev: true, escAlert: true, groupLevels: [{ group: "Kiosk", level: "LOW" }] });
  expect(puts[0].matrix).toEqual(defaultMatrix);
});

test("watchlist: pick a host's level (also on a phone)", async ({ superPage: page }) => {
  await useTenant(page, "alpha");
  await mockOverview(page, { scenario: "complete" });
  const bodies: unknown[] = [];
  await page.route("**/api/exposure/watchlist/a0*", (r) => {
    if (r.request().method() !== "PUT") return r.fallback();
    bodies.push(r.request().postDataJSON());
    return json(r, { host: { aid: "a0", hostname: "BKK-DC-01", note: null, criticality: "LOW", worstSeverity: "CRITICAL", p1: 2, critical: 2, high: 0, newP1_24h: 0, newCritical24h: 0, lastSeen: Date.now(), missing: false }, count: 1 });
  });
  await page.goto("/");
  const pick = page.getByTestId("watch-level-a0");
  await expect(pick).toBeVisible();
  await expect(pick).toHaveValue("");
  await pick.selectOption("LOW");
  await expect.poll(() => bodies.length).toBe(1);
  expect(bodies[0]).toEqual({ note: "ตัวควบคุมโดเมนหลัก รอ patch window 23 พ.ย.", criticality: "LOW" }); // the note is kept, the level changes
  await expect(pick).toHaveValue("LOW");
  await expectNoHorizontalScroll(page);
});
