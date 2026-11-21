/* eslint-disable @typescript-eslint/no-explicit-any -- API JSON */
import { randomBytes } from "node:crypto";
import type { Browser, BrowserContext, Page } from "@playwright/test";
import { env, expect, expectNoHorizontalScroll, test, watchErrors, type UserName } from "./fixtures";
import {
  cveTruth, deviceRows, drawer, fmt, hostsTruth, main, overviewTruth, overviewV2, pane, pick, recordApi, sql, tableRows, tenantId, useTenant, vulnRows, vulnsTotal, where, type TKey,
} from "./helpers";

const NAMES: Record<TKey, string> = { alpha: "Alpha Corp", beta: "Beta Ltd", empty: "Empty Inc" };
/** The header's organization control: a plain label with one organization, a button that opens the list with several. */
const orgLabel = (page: Page, name: string) => page.getByLabel(`Organization: ${name}`);
const orgSwitch = (page: Page) => page.getByRole("button", { name: /^Organization:/ });
/** The P1 headline of the Overview and the hosts line under it, checked against the database. */
async function expectOverviewOf(page: Page, tk: TKey) {
  const t = await overviewV2(tk);
  await expect(page.locator("[data-testid=p1-number] [aria-label]").first()).toHaveAttribute("aria-label", fmt(t.p1));
  await expect(main(page).getByText(`on ${fmt(t.hostsP1)} hosts (${Math.round((t.hostsP1 / t.hostsTotal) * 100)}% of ${fmt(t.hostsTotal)})`)).toBeVisible();
}
const menu = (page: Page, name: string) => page.locator("header").getByRole("link", { name, exact: true });
/** A cid/cids field that carries something (an empty list or a missing value leaks nothing). */
const hasKey = (v: unknown, keys: string[]): string | null => {
  if (Array.isArray(v)) { for (const x of v) { const r = hasKey(x, keys); if (r) return r; } return null; }
  if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) {
    // a number named cids is a count (the CVE drawer says "Checked 1 CID"), not an id
    if (keys.includes(k) && x !== undefined && x !== null && typeof x !== "number" && !(Array.isArray(x) && x.length === 0)) return k;
    const r = hasKey(x, keys); if (r) return r;
  }
  return null;
};

// =====================================================================================================================
// Isolation. Read-only: runs on desktop and mobile.
// =====================================================================================================================
const PAIRS: [UserName, TKey, TKey][] = [["alphaOp", "alpha", "beta"], ["betaOp", "beta", "alpha"]];

for (const [user, own, other] of PAIRS) {
  test.describe(`isolation: ${user} (${own}) must never see ${other}`, () => {
    test("lists and totals are the own tenant's", async ({ as }) => {
      const page = await as(user);
      const w = watchErrors(page);
      await page.goto("/");
      await expect(orgLabel(page, NAMES[own])).toBeVisible();
      await expect(orgSwitch(page)).toHaveCount(0); // one tenant, nothing to switch
      await expectOverviewOf(page, own);
      await page.goto("/vulnerabilities");
      await expect(main(page).getByText(`of ${fmt(await vulnsTotal(own))}`)).toBeVisible();
      await page.goto("/devices");
      await expect(main(page).getByText(`of ${fmt((await hostsTruth(own)).length)}`)).toBeVisible();
      w.check();
    });

    test("foreign device ids and CVE drawers show nothing of the other tenant", async ({ as }) => {
      const page = await as(user);
      const bodies = recordApi(page);
      const foreign = await sql<{ aid: string; hostname: string | null }>(`SELECT aid, MAX(hostname) hostname FROM findings WHERE ${where(other)} GROUP BY aid ORDER BY aid LIMIT 5`);
      const ownAids = new Set((await sql<{ aid: string }>(`SELECT DISTINCT aid FROM findings WHERE ${where(own)}`)).map((r) => r.aid));
      const otherAids = (await sql<{ aid: string }>(`SELECT DISTINCT aid FROM findings WHERE ${where(other)}`)).map((r) => r.aid);
      expect(foreign.length).toBeGreaterThan(0);
      for (const f of foreign) {
        await page.goto(`/devices?device=${f.aid}`);
        await expect(drawer(page).getByText(/could not|went wrong|try again/i).first()).toBeVisible();
        await expect(drawer(page).getByText(f.aid)).toHaveCount(0);
        const api = await page.request.get(`/api/exposure/hosts/${f.aid}`);
        expect(api.status(), `foreign device ${f.aid}`).toBe(404);
        expect(ownAids.has(f.aid)).toBe(false);
      }
      // a CVE that both tenants have: only the own devices are listed and counted
      const shared = await sql<{ cve_id: string }>(`SELECT cve_id FROM findings WHERE ${where(own)} INTERSECT SELECT cve_id FROM findings WHERE ${where(other)} ORDER BY 1 LIMIT 4`);
      expect(shared.length).toBeGreaterThan(0);
      for (const { cve_id } of shared) {
        const truth = await cveTruth(own, cve_id);
        const otherCount = (await cveTruth(other, cve_id)).devices;
        expect(otherCount).toBeGreaterThan(0);
        const j = await (await page.request.get(`/api/exposure/vulnerabilities/${cve_id}`)).json();
        expect(j.devicesTotal).toBe(truth.devices);
        for (const h of j.hosts) { expect(ownAids.has(h.aid), `${cve_id} host ${h.aid}`).toBe(true); expect(otherAids).not.toContain(h.aid); }
        await page.goto(`/vulnerabilities?cve=${cve_id}`);
        await expect(drawer(page).locator("dl > div").filter({ hasText: "Affected devices" }).locator("dd")).toHaveText(fmt(truth.devices));
      }
      // a CVE only the other tenant has must read as "not found"
      const only = await sql<{ cve_id: string }>(`SELECT cve_id FROM findings WHERE ${where(other)} EXCEPT SELECT cve_id FROM findings WHERE ${where(own)} LIMIT 1`);
      for (const { cve_id } of only) {
        await page.goto(`/vulnerabilities?cve=${cve_id}`);
        await expect(drawer(page).getByText(`No open findings for ${cve_id}`)).toBeVisible();
      }
      // the other tenant's hostnames are nowhere in what the browser received
      const names = (await sql<{ h: string }>(`SELECT DISTINCT hostname h FROM findings WHERE ${where(other)} AND hostname LIKE '%.example.com'`)).map((r) => r.h);
      expect(names.length).toBeGreaterThan(0);
      for (const n of names) for (const b of bodies) expect(b.text, `${n} in ${b.url}`).not.toContain(n);
      for (const a of otherAids) for (const b of bodies) expect(b.text, `${a} in ${b.url}`).not.toContain(a);
    });

    test("searching for the other tenant's devices finds nothing", async ({ as }) => {
      const page = await as(user);
      const host = (await sql<{ h: string }>(`SELECT hostname h FROM findings WHERE ${where(other)} AND hostname LIKE '%.example.com' ORDER BY 1 LIMIT 1`))[0].h;
      await page.goto("/devices");
      await page.getByRole("searchbox").fill(host);
      await expect(main(page).getByText("No devices match your filters. Remove a filter above.")).toBeVisible();
      await expect(page.getByText(host)).toHaveCount(0);
    });

    test("the API answers 404 to ?tenantId= of the other (or an unknown) tenant on every read endpoint", async ({ as }) => {
      const page = await as(user);
      const cve = (await vulnRows(own, "", 1))[0].cve_id;
      const aid = (await deviceRows(own, "", 1))[0].aid;
      for (const bad of [tenantId(other), tenantId("empty"), "00000000-0000-0000-0000-000000000000", "x' OR '1'='1"]) {
        for (const p of ["summary", "vulnerabilities", "hosts", "graph", `vulnerabilities/${cve}`, `hosts/${aid}`, "v2/summary", "v2/trend", "v2/vulnerabilities", "v2/hosts", "v2/fixes", `v2/hosts/${aid}`, "software", "easm", "news", "watchlist"]) {
          const r = await page.request.get(`/api/exposure/${p}?tenantId=${encodeURIComponent(bad)}`);
          expect(r.status(), `${p} with tenantId=${bad}`).toBe(404);
          expect(await r.text()).not.toContain(env().cids.alpha);
        }
      }
      // without tenantId the own tenant is used, never "all"
      const s = await (await page.request.get("/api/exposure/summary")).json();
      expect(s.totals.findings).toBe((await overviewTruth(own)).findings);
      expect(s.tenant.name).toBe(NAMES[own]);
      // the own tenantId explicitly is fine
      expect((await page.request.get(`/api/exposure/summary?tenantId=${tenantId(own)}`)).status()).toBe(200);
      const t = await (await page.request.get("/api/tenants")).json();
      expect(t.tenants.map((x: any) => x.name)).toEqual([NAMES[own]]);
    });

    test("management APIs are refused (403) and change nothing", async ({ as }) => {
      const page = await as(user);
      const before = await sql("SELECT (SELECT COUNT(*)::int FROM users) u, (SELECT COUNT(*)::int FROM tenants) t, (SELECT COUNT(*)::int FROM tenant_cids) c");
      for (const [m, p, body] of [
        ["GET", "/api/team/users"], ["GET", "/api/team/invites"], ["GET", "/api/audit"], ["GET", "/api/integrations/falcon"], ["GET", "/api/mail"],
        ["POST", "/api/team/invites", { email: "qa-x@e2e.test", role: "member", memberships: [{ tenantId: tenantId(own), role: "operator" }] }],
        ["POST", "/api/tenants", { name: "QA Tenant by operator" }],
        ["PUT", `/api/tenants/${tenantId(own)}/cids`, { cids: [] }],
        ["PUT", `/api/tenants/${tenantId(own)}`, { name: "hijacked" }],
        ["DELETE", `/api/tenants/${tenantId(own)}`, { confirmName: NAMES[own] }],
        ["POST", "/api/integrations/falcon/sync", {}],
      ] as [string, string, any?][]) {
        const r = await page.request.fetch(p, { method: m, data: body });
        expect(r.status(), `${m} ${p}`).toBe(403);
      }
      expect(await sql("SELECT (SELECT COUNT(*)::int FROM users) u, (SELECT COUNT(*)::int FROM tenants) t, (SELECT COUNT(*)::int FROM tenant_cids) c")).toEqual(before);
    });
  });
}

test.describe("nobody but a super admin sees a CID", () => {
  const CIDS = () => [env().cids.alpha, env().cids.beta];
  for (const user of ["alphaOp", "betaOp", "alphaAdmin", "multi"] as UserName[]) {
    test(`${user}: no CID in any page, drawer, or API response`, async ({ as }) => {
      const page = await as(user);
      const bodies = recordApi(page);
      const tenants: TKey[] = user === "betaOp" ? ["beta"] : user === "multi" ? ["alpha", "beta"] : ["alpha"];
      for (const tk of tenants) {
        await useTenant(page, tk);
        const cve = (await vulnRows(tk, "", 1))[0].cve_id;
        const dev = (await deviceRows(tk, "", 1))[0].aid;
        for (const path of ["/", "/vulnerabilities", "/devices", "/graph", `/vulnerabilities?cve=${cve}`, `/devices?device=${dev}`, "/account", ...(user === "alphaAdmin" || user === "multi" ? ["/team", "/audit"] : [])]) {
          await page.goto(path);
          await page.waitForLoadState("networkidle");
          const html = await page.content();
          for (const c of CIDS()) expect(html, `${c} in DOM of ${path}`).not.toContain(c);
          await expect(drawer(page).getByText("CID", { exact: true })).toHaveCount(0);
        }
      }
      expect(bodies.length).toBeGreaterThan(10);
      for (const b of bodies) {
        for (const c of CIDS()) expect(b.text, `${c} in ${b.url}`).not.toContain(c);
        let j: unknown = null;
        try { j = JSON.parse(b.text); } catch { /* not JSON */ }
        expect(hasKey(j, ["cid", "cids"]), `a cid field in ${b.url}`).toBeNull();
      }
    });
  }

  test("contrast: the super admin does see them", async ({ superPage: page }) => {
    const dev = (await deviceRows("alpha", "", 1))[0].aid;
    await page.goto(`/devices?device=${dev}`);
    await expect(drawer(page).locator("dl > div").filter({ hasText: /^CID/ }).locator("dd")).toHaveText(env().cids.alpha);
    await page.goto("/settings?setting=tenants");
    await pane(page).getByRole("button", { name: "Open Alpha Corp" }).click();
    const cid = env().cids.alpha;
    await expect(pane(page).getByText(`${cid.slice(0, 6)}…${cid.slice(-4)}`, { exact: true }).filter({ visible: true }).first()).toBeVisible(); // the organization's connection names its CID, shortened
  });
});

test.describe("empty tenant", () => {
  test("every page shows an empty state and says why, never an error or someone else's data", async ({ as }) => {
    const page = await as("emptyOp");
    const w = watchErrors(page);
    await page.goto("/");
    await expect(orgLabel(page, "Empty Inc")).toBeVisible();
    await expect(page.getByText("No Falcon account is linked").first()).toBeVisible();
    await expect(page.getByText("There are no numbers to show")).toBeVisible();
    await expect(page.locator("[data-testid=p1-number]")).toHaveCount(0); // no zero-filled headline that could be read as "all clear"
    for (const t of ["Fix now (P1)", "What to fix first", "Exposure by tier", "By severity"]) await expect(main(page).getByText(t, { exact: true })).toHaveCount(0);
    await expect(main(page)).not.toContainText(/Data is complete/);
    await page.goto("/vulnerabilities");
    await expect(main(page).getByText(/No vulnerabilities to show/)).toBeVisible();
    await page.goto("/devices");
    await expect(main(page).getByText(/No devices to show/)).toBeVisible();
    await page.goto("/software");
    await expect(main(page).getByText(/No software to show/)).toBeVisible();
    await page.goto("/devices?view=graph");
    await expect(main(page).getByText("Data appears after the first read from Falcon")).toBeVisible();
    for (const p of ["/", "/vulnerabilities", "/devices", "/devices?view=graph", "/software", "/external", "/news", "/vulnerabilities?tab=fix"]) {
      await page.goto(p);
      await page.waitForLoadState("networkidle");
      await expect(main(page)).not.toContainText(/could not load|something went wrong|try again/i);
      await expect(main(page).locator("tbody tr")).toHaveCount(0);
      await expectNoHorizontalScroll(page);
    }
    // drawers for things that exist elsewhere read as not found
    const cve = (await vulnRows("alpha", "", 1))[0].cve_id;
    await page.goto(`/vulnerabilities?cve=${cve}`);
    await expect(drawer(page).getByText(`No open findings for ${cve}`)).toBeVisible();
    // the API too: zero, not "all"
    const s = await (await page.request.get("/api/exposure/summary")).json();
    expect([s.totals.findings, s.totals.hosts, s.completeness.state]).toEqual([0, 0, "no_cids"]);
    const v = await (await page.request.get("/api/exposure/vulnerabilities")).json();
    expect([v.total, v.rows.length]).toEqual([0, 0]);
    for (const p of ["vulnerabilities", "hosts", "fixes"]) {
      const j = await (await page.request.get(`/api/exposure/v2/${p}`)).json();
      expect([p, j.total, j.rows.length, j.completeness.state]).toEqual([p, 0, 0, "no_cids"]);
    }
    w.check();
  });
});

test.describe("a user with two tenants", () => {
  test("the header switcher changes every page and the open drawer; the choice survives a reload", async ({ as }) => {
    const page = await as("multi");
    const w = watchErrors(page);
    const switcher = orgSwitch(page);
    await page.goto("/");
    await expect(switcher).toHaveText("Alpha Corp");
    await switcher.click();
    await expect(page.getByRole("option")).toHaveText(["Alpha Corp", "Beta Ltd"]); // Empty Inc is not theirs
    await page.keyboard.press("Escape");
    await expectOverviewOf(page, "alpha");
    await pick(page, switcher, "Beta Ltd");
    await expect(switcher).toHaveText("Beta Ltd");
    await expectOverviewOf(page, "beta");
    // client-side navigation keeps the tenant
    await menu(page, "Vulnerabilities").click();
    await expect(main(page).getByText(`of ${fmt(await vulnsTotal("beta"))}`)).toBeVisible();
    await menu(page, "Devices").click();
    await expect(main(page).getByText(`of ${fmt((await hostsTruth("beta")).length)}`)).toBeVisible();
    // an open drawer follows the switch: same CVE, the devices of the chosen tenant
    const both = await sql<{ cve_id: string; a: number; b: number }>(
      `SELECT x.cve_id, x.n a, y.n b FROM (SELECT cve_id, COUNT(DISTINCT aid)::int n FROM findings WHERE ${where("alpha")} GROUP BY 1) x
       JOIN (SELECT cve_id, COUNT(DISTINCT aid)::int n FROM findings WHERE ${where("beta")} GROUP BY 1) y USING (cve_id) WHERE x.n <> y.n ORDER BY x.cve_id LIMIT 1`);
    expect(both.length, "a CVE both tenants have with different device counts").toBe(1);
    const shared = both[0].cve_id, da = both[0].a, db = both[0].b;
    await page.goto(`/vulnerabilities?cve=${shared}`);
    const count = () => drawer(page).locator("dl > div").filter({ hasText: "Affected devices" }).locator("dd");
    await expect(count()).toHaveText(fmt(db)); // Beta was chosen and is remembered
    // the drawer is modal and covers the header: close it, switch, reopen
    await page.keyboard.press("Escape");
    await expect(drawer(page)).toHaveCount(0);
    await pick(page, switcher, "Alpha Corp");
    await page.goto(`/vulnerabilities?cve=${shared}`);
    await expect(count()).toHaveText(fmt(da));
    await page.goto("/");
    await page.reload();
    await expect(switcher).toHaveText("Alpha Corp"); // the choice is remembered
    w.check();
  });

  test("their role differs per tenant: admin of Alpha manages Alpha only, operator of Beta does not", async ({ as }) => {
    const page = await as("multi");
    // (the Team page itself is a desktop-only layout; the list it shows comes from this API)
    // Beta data is readable but Beta users are not manageable
    const r = await page.request.get("/api/team/users");
    const users = (await r.json()).users as any[];
    const emails = users.map((u) => u.email);
    expect(emails).toContain("alpha-op@e2e.test");
    for (const hidden of ["beta-op@e2e.test", "empty-op@e2e.test", "super@e2e.test"]) expect(emails).not.toContain(hidden);
    const betaOp = (await sql("SELECT id FROM users WHERE email = 'beta-op@e2e.test'"))[0].id;
    expect((await page.request.post(`/api/team/users/${betaOp}/disable`, { data: {} })).status()).toBe(404);
  });
});

// =====================================================================================================================
// Role flows through the UI. They change data, so desktop only; each test makes and removes its own users and tenants.
// =====================================================================================================================
const PASSWORD = "Qa-Password-98765";
const rand = () => randomBytes(4).toString("hex");

async function cleanup() {
  await sql("DELETE FROM users WHERE email LIKE 'qa-%@e2e.test'");
  await sql("DELETE FROM invites WHERE email LIKE 'qa-%@e2e.test'");
  await sql("DELETE FROM tenants WHERE name LIKE 'QA Tenant %'");
}
const fresh = async (browser: Browser, baseURL: string | undefined) => {
  const context = await browser.newContext({ baseURL, viewport: { width: 1440, height: 900 } });
  return { context, page: await context.newPage() };
};

/** Opens an invite link in a clean browser, creates the account through the page, returns the signed-in page. */
async function acceptInvite(browser: Browser, baseURL: string | undefined, link: string, name: string, password = PASSWORD) {
  const { context, page } = await fresh(browser, baseURL);
  await page.goto(new URL(link).pathname);
  await expect(page.getByText("Create your account")).toBeVisible();
  await page.locator('input[name="name"]').fill(name);
  await page.locator('input[name="password"]').fill(password);
  await page.locator('input[name="confirm"]').fill(password);
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page).toHaveURL(/\/$/);
  return { context, page };
}
const rowOf = (page: Page, text: string) => tableRows(pane(page)).filter({ hasText: text });
async function rowAction(page: Page, row: ReturnType<typeof rowOf>, name: string, action: string) {
  await row.getByRole("button", { name: `Actions for ${name}` }).click();
  await page.getByRole("menuitem", { name: action }).click();
}
// not the Setting Center drawer, which is a dialog too
const dialog = (page: Page) => page.locator('[role="dialog"]:not([data-slot="sheet-content"])');

test.describe("role flows", () => {
  test.skip(({ isMobile }) => isMobile, "mutating flows run on desktop only");
  test.beforeEach(cleanup);
  test.afterEach(cleanup);

  test("operators and tenant admins are bounced from pages that are not theirs", async ({ as }) => {
    for (const user of ["alphaOp", "betaOp", "emptyOp"] as UserName[]) {
      const page = await as(user);
      for (const p of ["/team", "/settings", "/tenants", "/integrations", "/audit"]) {
        await page.goto(p);
        await expect(page, `${user} ${p}`).toHaveURL(/\/$/);
        await expect(main(page).getByText("Overview", { exact: false }).first().or(page.getByRole("heading", { level: 1 }))).toBeVisible();
      }
      for (const n of ["Team", "Settings"]) await expect(menu(page, n)).toHaveCount(0);
    }
    const admin = await as("alphaAdmin");
    for (const p of ["/settings", "/tenants", "/integrations"]) { await admin.goto(p); await expect(admin, p).toHaveURL(/\/$/); }
    await admin.goto("/team");
    await expect(admin).toHaveURL(/\/team$/);
    await admin.goto("/audit"); // a tenant admin reads the audit log on the second tab of the team page
    await expect(admin).toHaveURL(/\/team\?tab=audit$/);
    await expect(menu(admin, "Team")).toBeVisible();
    await expect(menu(admin, "Settings")).toHaveCount(0);
  });

  test("tenant admin: invite an operator, copy the link, accept it in a fresh browser, edit access, reset password, disable, enable, delete", async ({ adminPage: page, browser, baseURL, as }) => {
    const w = watchErrors(page);
    await page.context().grantPermissions(["clipboard-read", "clipboard-write"]);
    const id = rand();
    const email = `qa-op-${id}@e2e.test`, name = `QA Op ${id}`;

    // invite: only the tenants the admin manages are offered
    await page.goto("/team");
    await page.getByRole("button", { name: "Invite user" }).click();
    const dlg = dialog(page);
    await expect(dlg.getByRole("checkbox")).toHaveCount(2); // the tenant, and "Also send the link by email"
    await expect(dlg.getByRole("checkbox", { name: "Alpha Corp" })).toBeVisible();
    await expect(dlg.getByRole("checkbox", { name: "Also send the link by email" })).not.toBeChecked();
    await expect(dlg.getByText("Beta Ltd")).toHaveCount(0);
    await expect(dlg.getByRole("combobox", { name: "User type" })).toHaveCount(0); // super admin invites are not offered
    await expect(dlg.getByRole("button", { name: "Create invite link" })).toBeDisabled();
    await dlg.locator('input[type="email"]').fill(email);
    await expect(dlg.getByRole("button", { name: "Create invite link" })).toBeDisabled(); // needs a tenant
    await dlg.getByRole("checkbox", { name: "Alpha Corp" }).click();
    await expect(dlg.getByRole("combobox", { name: "Role in Alpha Corp" })).toHaveText("Operator");
    await dlg.getByRole("button", { name: "Create invite link" }).click();
    await expect(page.getByText("Invite link created")).toBeVisible();
    const link = await dialog(page).getByRole("textbox").inputValue();
    expect(link).toMatch(/\/accept-invite\/[\w-]{20,}$/);
    await dialog(page).getByRole("button", { name: "Copy link" }).click();
    await expect(dialog(page).getByRole("button", { name: "Copied" })).toBeVisible();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(link);
    await dialog(page).getByRole("button", { name: "Done" }).click();
    await expect(rowOf(page, email)).toContainText("Alpha Corp · Operator");

    // accept in a fresh browser: preview names the tenant and role, then lands on the tenant
    const prev = await browser.newContext({ baseURL });
    const pp = await prev.newPage();
    await pp.goto(new URL(link).pathname);
    await expect(pp.getByText("You were invited to join Alpha Corp (Operator).")).toBeVisible();
    await prev.close();
    const { context: uc, page: user } = await acceptInvite(browser, baseURL, link, name);
    const uw = watchErrors(user);
    await expect(orgLabel(user, "Alpha Corp")).toBeVisible();
    await expectOverviewOf(user, "alpha");
    for (const n of ["Overview", "Vulnerabilities", "Devices", "Software", "External surface", "CVE news"]) await expect(menu(user, n)).toBeVisible();
    for (const n of ["Team", "Settings"]) await expect(menu(user, n)).toHaveCount(0);
    await user.goto("/team");
    await expect(user).toHaveURL(/\/$/);
    // the link works once
    const again = await browser.newContext({ baseURL });
    const ap = await again.newPage();
    await ap.goto(new URL(link).pathname);
    await expect(ap.getByText(/This link is invalid or has expired/)).toBeVisible();
    await again.close();

    // the invite left the pending list and the user is in the table
    await page.goto("/team");
    await expect(rowOf(page, email)).toContainText("Active");
    await expect(rowOf(page, email)).toContainText("Alpha Corp · Operator");

    // edit access: role in Alpha to Admin -> the user gets the Team page
    await rowAction(page, rowOf(page, email), name, "Edit access");
    await expect(dialog(page).getByRole("checkbox")).toHaveCount(1);
    await expect(dialog(page).getByRole("combobox", { name: "Role in Alpha Corp" })).toHaveText("Operator");
    await pick(page, dialog(page).getByRole("combobox", { name: "Role in Alpha Corp" }), "Admin");
    await dialog(page).getByRole("button", { name: "Save access" }).click();
    await expect(rowOf(page, email)).toContainText("Alpha Corp · Admin");
    await user.goto("/");
    await expect(menu(user, "Team")).toBeVisible();
    await user.goto("/team");
    await expect(user).toHaveURL(/\/team$/);
    await expect(tableRows(main(user)).filter({ hasText: "beta-op@e2e.test" })).toHaveCount(0);
    // ...and back to operator
    await rowAction(page, rowOf(page, email), name, "Edit access");
    await pick(page, dialog(page).getByRole("combobox", { name: "Role in Alpha Corp" }), "Operator");
    await dialog(page).getByRole("button", { name: "Save access" }).click();
    await expect(rowOf(page, email)).toContainText("Alpha Corp · Operator");
    await user.goto("/team");
    await expect(user).toHaveURL(/\/$/);

    // password reset link: the new password works, the old one stops
    await rowAction(page, rowOf(page, email), name, "Create password reset link");
    await expect(dialog(page).getByText("Create a password reset link")).toBeVisible(); // asks first, with the option to e-mail the link too
    await expect(dialog(page).getByText(`Creates a one-time link for ${email} to set a new password.`)).toBeVisible();
    await expect(dialog(page).getByRole("checkbox", { name: "Also send the link by email" })).toBeVisible();
    await dialog(page).getByRole("button", { name: "Create link" }).click();
    await expect(page.getByText("Link created")).toBeVisible();
    const resetLink = await dialog(page).getByRole("textbox").inputValue();
    await dialog(page).getByRole("button", { name: "Done" }).click();
    const rc = await browser.newContext({ baseURL });
    const rp = await rc.newPage();
    await rp.goto(new URL(resetLink).pathname);
    await expect(rp.getByText("Set a new password")).toBeVisible();
    await rp.locator('input[name="password"]').fill("Qa-Password-NEW-4321");
    await rp.locator('input[name="confirm"]').fill("Qa-Password-NEW-4321");
    await rp.getByRole("button", { name: "Save new password" }).click();
    await expect(rp.getByText("Password saved")).toBeVisible();
    const login = (pw: string) => rc.request.post("/api/auth/login", { data: { email, password: pw } });
    expect((await login(PASSWORD)).status()).toBe(401);
    expect((await login("Qa-Password-NEW-4321")).status()).toBe(200);
    await rc.close();

    // disable: signed out at once, cannot sign in; enable restores
    await rowAction(page, rowOf(page, email), name, "Disable user");
    await dialog(page).getByRole("button", { name: "Disable", exact: true }).click();
    await expect(rowOf(page, email)).toContainText("Disabled");
    await user.reload();
    await expect(user).toHaveURL(/\/signin/);
    const dc = await browser.newContext({ baseURL });
    expect((await dc.request.post("/api/auth/login", { data: { email, password: "Qa-Password-NEW-4321" } })).status()).toBeGreaterThanOrEqual(400);
    await rowAction(page, rowOf(page, email), name, "Enable user");
    await expect(rowOf(page, email)).toContainText("Active");
    expect((await dc.request.post("/api/auth/login", { data: { email, password: "Qa-Password-NEW-4321" } })).status()).toBe(200);
    await dc.close();

    // delete
    await rowAction(page, rowOf(page, email), name, "Delete user");
    await expect(dialog(page).getByText(`Delete ${name}?`)).toBeVisible();
    await dialog(page).getByRole("button", { name: "Delete user" }).click();
    await expect(rowOf(page, email)).toHaveCount(0);
    expect(await sql("SELECT 1 FROM users WHERE email = $1", [email])).toEqual([]);
    expect(await sql("SELECT 1 FROM user_tenants WHERE user_id NOT IN (SELECT id FROM users)")).toEqual([]);
    const gone = await browser.newContext({ baseURL });
    expect((await gone.request.post("/api/auth/login", { data: { email, password: "Qa-Password-NEW-4321" } })).status()).toBe(401);
    await gone.close();
    await uc.close();
    uw.errors.length = 0; // the user's own session was revoked on purpose; its 401s are expected
    w.check();
    void as;
  });

  test("tenant admin sees and manages only their own tenant's users", async ({ adminPage: page }) => {
    await page.goto("/team");
    await expect(rowOf(page, "alpha-op@e2e.test")).toBeVisible();
    const emails = await main(page).locator("tbody tr td:first-child p:nth-child(2)").allInnerTexts();
    expect(emails).toEqual(expect.arrayContaining(["alpha-admin@e2e.test", "alpha-op@e2e.test", "multi@e2e.test"]));
    for (const hidden of ["beta-op@e2e.test", "empty-op@e2e.test", "super@e2e.test"]) {
      expect(emails).not.toContain(hidden);
      await expect(page.getByText(hidden)).toHaveCount(0);
    }
    // multi also belongs to Beta: shown with what is Alpha's, the rest hidden, and cannot be disabled or deleted from here
    const multi = rowOf(page, "multi@e2e.test");
    await expect(multi).toContainText("Alpha Corp · Admin");
    await expect(multi).toContainText("+1 other organization");
    await expect(multi).not.toContainText("Beta");
    await multi.getByRole("button", { name: /Actions for/ }).click();
    for (const a of ["Disable user", "Delete user", "Create password reset link"]) await expect(page.getByRole("menuitem", { name: a })).toBeDisabled();
    await expect(page.getByRole("menuitem", { name: "Edit access" })).toBeEnabled();
    await expect(page.getByRole("menu")).toHaveAttribute("data-open", ""); // fully open before Escape, and fully closed before the next one opens
    await page.keyboard.press("Escape");
    await expect(page.getByRole("menu")).toHaveCount(0);
    // themselves: nothing destructive either
    const me = rowOf(page, "alpha-admin@e2e.test");
    await me.getByRole("button", { name: /Actions for/ }).click();
    await expect(page.getByRole("menuitem", { name: "Delete user" })).toBeDisabled();
    await expect(page.getByRole("menu")).toHaveAttribute("data-open", "");
    await page.keyboard.press("Escape");
    await expect(page.getByRole("menu")).toHaveCount(0);

    // the API agrees (ids from the database)
    const id = async (e: string) => (await sql("SELECT id FROM users WHERE email = $1", [e]))[0].id as string;
    const [betaOp, multiId, superId, alphaOp] = [await id("beta-op@e2e.test"), await id("multi@e2e.test"), await id("super@e2e.test"), await id("alpha-op@e2e.test")];
    for (const target of [betaOp, superId]) {
      for (const [m, p, body] of [["POST", `/api/team/users/${target}/disable`, {}], ["POST", `/api/team/users/${target}/reset-password`, {}], ["POST", `/api/team/users/${target}/reset-mfa`, {}],
        ["DELETE", `/api/team/users/${target}`, {}], ["PUT", `/api/team/users/${target}/access`, { memberships: [{ tenantId: tenantId("alpha"), role: "admin" }] }]] as [string, string, any][]) {
        expect((await page.request.fetch(p, { method: m, data: body })).status(), `${m} ${p}`).toBe(404);
      }
    }
    for (const [m, p] of [["POST", `/api/team/users/${multiId}/disable`], ["DELETE", `/api/team/users/${multiId}`], ["POST", `/api/team/users/${multiId}/reset-password`]]) {
      expect((await page.request.fetch(p, { method: m, data: {} })).status(), `${m} ${p}`).toBe(403);
    }
    // cannot hand out access to a tenant they do not manage, nor create super admins
    expect((await page.request.post("/api/team/invites", { data: { email: "qa-x@e2e.test", role: "member", memberships: [{ tenantId: tenantId("beta"), role: "operator" }] } })).status()).toBe(403);
    expect((await page.request.post("/api/team/invites", { data: { email: "qa-y@e2e.test", role: "super_admin" } })).status()).toBe(403);
    expect((await page.request.put(`/api/team/users/${alphaOp}/access`, { data: { memberships: [{ tenantId: tenantId("alpha"), role: "operator" }, { tenantId: tenantId("beta"), role: "operator" }] } })).status()).toBe(403);
    expect(await sql("SELECT 1 FROM user_tenants WHERE user_id = $1 AND tenant_id = $2", [alphaOp, tenantId("beta")])).toEqual([]);
    // audit shows only their tenant's events
    const audit = await (await page.request.get("/api/audit?limit=500")).json();
    expect(audit.entries.length).toBeGreaterThan(0);
    for (const e of audit.entries) expect(["Alpha Corp", null]).toContain(e.tenant_name);
  });

  test("super admin: the organizations list numbers match the database; each organization has its own connection and the CID is not shown in full", async ({ superPage: page }) => {
    await page.goto("/settings?setting=tenants");
    for (const k of ["alpha", "beta"] as TKey[]) {
      const t = await overviewTruth(k);
      const card = pane(page).getByRole("button", { name: `Open ${NAMES[k]}` });
      await expect(card).toBeVisible();
      for (const v of [t.findings, t.critical, t.devices]) await expect(card).toContainText(fmt(v));
      await expect(card).toContainText("Complete");
      await expect(card).toContainText("CrowdStrike: 1 connection");
      await expect(card).not.toContainText(env().cids[k]);
    }
    await expect(pane(page).getByRole("button", { name: "Open Empty Inc" })).toContainText("CrowdStrike not connected");
    await pane(page).getByRole("button", { name: "Open Alpha Corp" }).click();
    await expect(pane(page).getByRole("heading", { name: "CrowdStrike" })).toBeVisible();
    await expect(pane(page).getByText("mock-client")).toBeVisible();
    await expect(pane(page).getByText("mock-secret")).toHaveCount(0); // the secret is never shown
    expect(await page.content()).not.toContain("mock-secret");
  });

  test("super admin: edit access of a user across tenants, reset MFA, and see every user", async ({ superPage: page, browser, baseURL }) => {
    const id = rand();
    const email = `qa-mt-${id}@e2e.test`, name = `QA Mt ${id}`;
    const inv = await (await page.request.post("/api/team/invites", { data: { email, role: "member", memberships: [{ tenantId: tenantId("alpha"), role: "operator" }] } })).json();
    const u = await acceptInvite(browser, baseURL, inv.link, name);
    await u.context.close();

    await page.goto("/settings?setting=team");
    await expect(rowOf(page, "alpha-op@e2e.test")).toBeVisible();
    const all = await pane(page).locator("tbody tr td:first-child p:nth-child(2)").allInnerTexts();
    expect(all).toEqual(expect.arrayContaining(["super@e2e.test", "alpha-admin@e2e.test", "alpha-op@e2e.test", "beta-op@e2e.test", "multi@e2e.test", "empty-op@e2e.test", email]));
    await expect(rowOf(page, "super@e2e.test")).toContainText("Super admin");
    // the tenant filter
    await pick(page, page.getByRole("combobox", { name: "Tenant" }), "Beta Ltd");
    await expect(rowOf(page, "beta-op@e2e.test")).toBeVisible();
    await expect(rowOf(page, "alpha-op@e2e.test")).toHaveCount(0);
    await pick(page, page.getByRole("combobox", { name: "Tenant" }), "All tenants");

    // edit access: add Beta (default operator), then drop Alpha
    await rowAction(page, rowOf(page, email), name, "Edit access");
    await dialog(page).getByRole("checkbox", { name: "Beta Ltd" }).click();
    await expect(dialog(page).getByRole("combobox", { name: "Role in Beta Ltd" })).toHaveText("Operator");
    await dialog(page).getByRole("button", { name: "Save access" }).click();
    await expect(rowOf(page, email)).toContainText("Alpha Corp · Operator");
    await expect(rowOf(page, email)).toContainText("Beta Ltd · Operator");
    const login = async () => {
      const c = await browser.newContext({ baseURL });
      expect((await c.request.post("/api/auth/login", { data: { email, password: PASSWORD } })).status()).toBe(200);
      const p = await c.newPage();
      await p.goto("/");
      return { c, p };
    };
    let s = await login();
    await expect(orgSwitch(s.p)).toBeVisible();
    await s.c.close();
    await rowAction(page, rowOf(page, email), name, "Edit access");
    await dialog(page).getByRole("checkbox", { name: "Alpha Corp" }).click();
    await dialog(page).getByRole("button", { name: "Save access" }).click();
    await expect(rowOf(page, email)).not.toContainText("Alpha Corp");
    await expect(rowOf(page, email)).toContainText("Beta Ltd · Operator");
    s = await login();
    await expect(orgLabel(s.p, "Beta Ltd")).toBeVisible();
    await expect(orgSwitch(s.p)).toHaveCount(0);
    await s.c.close();
    // a member must keep one tenant: the Save button is disabled with none
    await rowAction(page, rowOf(page, email), name, "Edit access");
    await dialog(page).getByRole("checkbox", { name: "Beta Ltd" }).click();
    await expect(dialog(page).getByRole("button", { name: "Save access" })).toBeDisabled();
    await dialog(page).getByRole("button", { name: "Cancel" }).click();

    // reset MFA: disabled while off, enabled when on, then off again
    await rowAction(page, rowOf(page, email), name, "Edit access").catch(() => undefined);
    await page.keyboard.press("Escape");
    await rowOf(page, email).getByRole("button", { name: `Actions for ${name}` }).click();
    await expect(page.getByRole("menuitem", { name: "Reset MFA" })).toBeDisabled();
    await expect(page.getByRole("menu")).toHaveAttribute("data-open", ""); // fully open: an Escape while it still mounts would reach the Setting Center drawer instead
    await page.keyboard.press("Escape");
    await expect(page.getByRole("menu")).toHaveCount(0);
    await sql("UPDATE users SET totp_enabled = 1, totp_secret = 'x' WHERE email = $1", [email]);
    await page.reload();
    await expect(rowOf(page, email).getByText("On", { exact: true })).toBeVisible();
    await rowAction(page, rowOf(page, email), name, "Reset MFA");
    await dialog(page).getByRole("button", { name: "Reset MFA" }).click();
    await expect(rowOf(page, email).getByText("Off", { exact: true })).toBeVisible();
    expect((await sql("SELECT totp_enabled::int e, totp_secret FROM users WHERE email = $1", [email]))[0]).toEqual({ e: 0, totp_secret: null });
  });

  test("super admin: /integrations lands on the LINE bot card (there is no shared Falcon login any more); the old falcon address opens Organizations", async ({ superPage: page }) => {
    const w = watchErrors(page);
    await page.goto("/integrations");
    await expect(page).toHaveURL(/\/settings\?setting=line$/);
    await expect(pane(page).getByText("LINE bot (system)").first()).toBeVisible(); // the drawer title and the card heading
    await expect(pane(page).getByText("CrowdStrike Falcon")).toHaveCount(0);
    await page.goto("/integrations?tab=email");
    await expect(page).toHaveURL(/\/settings\?setting=email$/);
    await expect(pane(page).getByText("E2E sink")).toBeVisible();
    await expect(pane(page).getByText("soc@e2e.test")).toBeVisible();
    await page.goto("/settings?setting=falcon"); // an old bookmark: the card is gone, Organizations opens instead
    await expect(pane(page).getByText("Alpha Corp")).toBeVisible();
    expect((await page.request.get("/api/integrations/falcon")).status()).toBe(200); // sync status only
    expect((await page.request.fetch("/api/integrations/falcon", { method: "PUT", data: {} })).status()).toBeGreaterThanOrEqual(400);
    w.check();
  });
});

export type { BrowserContext };
