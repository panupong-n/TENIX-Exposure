import { expect, expectNoHorizontalScroll, test, watchErrors } from "./fixtures";

const OPERATOR = ["Overview", "Vulnerabilities", "Devices", "Software", "External surface", "CVE news"];
const SUPER = [...OPERATOR, "Settings"];
const menu = (page: import("@playwright/test").Page, name: string) => page.locator("header").getByRole("link", { name, exact: true });

test("sign-in page renders for a signed-out visitor", async ({ page }) => {
  const w = watchErrors(page);
  await page.goto("/signin");
  await expect(page.getByLabel(/email/i).first()).toBeVisible();
  await expect(page.locator('input[type="password"]').first()).toBeVisible();
  await expectNoHorizontalScroll(page);
  w.check();
});

test("super admin lands on the Overview and sees the flat menu (Overview, Vulnerabilities, Devices, Software, External surface, CVE news) and Settings", async ({ superPage: page }) => {
  const w = watchErrors(page);
  await page.goto("/");
  await expect(page).toHaveURL(/\/$/);
  for (const name of SUPER) await expect(menu(page, name), name).toBeVisible();
  await expect(menu(page, "Team")).toHaveCount(0); // a tenant admin's item; a super admin manages people in Settings
  await expect(menu(page, "Overview")).toHaveAttribute("aria-current", "page");
  await expectNoHorizontalScroll(page);
  w.check();
});

test("operator sees the flat menu without Settings and Team; /graph opens the graph view of Devices; /news is the CVE news page", async ({ operatorPage: page }) => {
  await page.goto("/");
  for (const name of OPERATOR) await expect(menu(page, name), name).toBeVisible();
  for (const name of ["Settings", "Team"]) await expect(menu(page, name), name).toHaveCount(0);
  await expect(page.getByRole("navigation", { name: "Vulnerability and asset views" })).toHaveCount(0); // the tab strip is gone
  await menu(page, "Devices").click();
  await expect(page).toHaveURL(/\/devices$/);
  await expect(menu(page, "Devices")).toHaveAttribute("aria-current", "page");
  await page.goto("/graph?severity=CRITICAL");
  await expect(page).toHaveURL(/\/devices\?(severity=CRITICAL&)?view=graph(&severity=CRITICAL)?$/);
  await expect(menu(page, "Devices")).toHaveAttribute("aria-current", "page");
  await menu(page, "CVE news").click();
  await expect(page).toHaveURL(/\/news$/);
  await expect(page.getByRole("heading", { name: "CVE news", level: 1 })).toBeVisible();
  await expect(menu(page, "CVE news")).toHaveAttribute("aria-current", "page");
  await expect(page.getByText("Under development")).toHaveCount(0); // not the old placeholder any more
  await expect(page.getByText("No CVE news yet")).toBeVisible(); // nothing has reached the bot in the e2e data: the empty state says so
  await expect(page.getByRole("button", { name: /^Affected\s*0$/ })).toBeVisible(); // the state counters of the page heading
});

test("a tenant admin sees Team (not Settings) and a super admin is sent from /team to the Setting Center", async ({ adminPage: admin, superPage: sa }) => {
  await admin.goto("/");
  await expect(menu(admin, "Team")).toBeVisible();
  await expect(menu(admin, "Settings")).toHaveCount(0);
  await sa.goto("/team?tenant=abc");
  await expect(sa).toHaveURL(/\/settings\?setting=team&tenant=abc$/);
  await sa.goto("/audit");
  await expect(sa).toHaveURL(/\/settings\?setting=audit$/);
  await sa.goto("/tenants");
  await expect(sa).toHaveURL(/\/settings\?setting=tenants$/);
});

test("the API refuses an operator on /api/team/users with 403", async ({ operatorPage: page }) => {
  const r = await page.request.get("/api/team/users");
  expect(r.status()).toBe(403);
});

test("light only: a saved dark preference and a dark system setting are ignored, and there is no theme switch", async ({ browser, baseURL }) => {
  const context = await browser.newContext({ colorScheme: "dark", baseURL });
  await context.addInitScript(() => { try { localStorage.setItem("theme-mode", "dark"); localStorage.setItem("theme", "dark"); } catch { /* ignore */ } });
  const page = await context.newPage();
  await page.goto("/signin");
  await expect(page.getByRole("button", { name: /sign in/i }).first()).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.classList.contains("dark"))).toBe(false);
  await expect(page.getByRole("button", { name: /theme|dark mode/i })).toHaveCount(0);
  await context.close();
});
