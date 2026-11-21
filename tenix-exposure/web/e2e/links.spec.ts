import type { Page } from "@playwright/test";
import { expect, expectNoHorizontalScroll, test, watchErrors } from "./fixtures";
import { card, drawer, firstItem, hostsTruth, main, pick, tableRows, tenantId, vulnRows, vulnsTruth } from "./helpers";

// Read-only: runs on desktop and mobile. Everything that names a CVE or a device must open a drawer in place.
type Kind = "cve" | "device" | "fix" | "software";
const DRAWER_KEYS = ["cve", "device", "fix", "software"];
/** The devices that may be first in the default order: the ones tied on the sort keys (P1, then Critical CVEs) with the top one; names inside a tie are not compared. */
async function topAids() {
  const all = await hostsTruth("alpha");
  return all.filter((h) => h.p1 === all[0].p1 && h.critical === all[0].critical).map((h) => h.aid);
}

/** Clicks, expects the drawer for `kind` in the URL on the SAME path, then Back must close it and restore the URL. */
async function opensInPlace(page: Page, kind: Kind, click: () => Promise<unknown>, expected?: string | string[]) {
  const before = new URL(page.url());
  await click();
  await expect(page).toHaveURL((u) => u.pathname === before.pathname && u.searchParams.has(kind));
  const value = new URL(page.url()).searchParams.get(kind)!;
  if (typeof expected === "string") expect(value.toUpperCase()).toBe(expected.toUpperCase());
  else if (expected) expect(expected, `opened ${value}`).toContain(value);
  await expect(drawer(page)).toBeVisible();
  await expect(drawer(page).locator('[aria-busy="true"]')).toHaveCount(0);
  await page.goBack();
  await expect(drawer(page)).toHaveCount(0);
  await expect(page).toHaveURL((u) => u.pathname === before.pathname && !DRAWER_KEYS.some((k) => u.searchParams.has(k)));
  return value;
}

const open = async (page: Page, path: string) => {
  await page.goto(path);
  await expect(main(page)).toBeVisible();
};

test("Overview: a top fix row opens that fix's drawer in place; Back closes it", async ({ superPage: page }) => {
  const w = watchErrors(page);
  await open(page, "/");
  const row = card(page, "What to fix first").locator('a[href*="fix="]').first();
  await expect(row).toBeVisible();
  await opensInPlace(page, "fix", () => row.click());
  w.check();
});

test("Overview: a riskiest-devices row opens that device's drawer in place", async ({ superPage: page }) => {
  await open(page, "/");
  const first = card(page, "Riskiest devices").locator("div.grid button:not([aria-pressed])").first();
  await expect(first).toBeVisible();
  await opensInPlace(page, "device", () => first.click(), await topAids());
});

test("Overview: a software row opens the software drawer in place", async ({ superPage: page }) => {
  await open(page, "/");
  const first = card(page, "Most vulnerable software").locator("button").first();
  await expect(first).toBeVisible();
  await opensInPlace(page, "software", () => first.click());
});

test("Overview: the headline numbers and the tier and severity bars link to the list they count", async ({ superPage: page }) => {
  await open(page, "/");
  await page.getByRole("link", { name: /KEV \(CISA known exploited\)/ }).click();
  await expect(page).toHaveURL((u) => u.pathname === "/vulnerabilities" && u.searchParams.get("kev") === "1");
  await expect(main(page).locator('[aria-label="Active filters"]')).toContainText("KEV");
  await open(page, "/");
  await card(page, "Exposure by tier").locator('a[href$="tier=P2"]').click();
  await expect(page).toHaveURL((u) => u.pathname === "/vulnerabilities" && u.searchParams.get("tier") === "P2");
  await open(page, "/");
  await card(page, "By severity").locator('a[href$="severity=CRITICAL"]').click();
  await expect(page).toHaveURL((u) => u.pathname === "/vulnerabilities" && u.searchParams.get("severity") === "CRITICAL");
});

test("Vulnerabilities: a row opens the CVE drawer in place, also on page 2", async ({ superPage: page }) => {
  const [first] = await vulnsTruth("alpha", { limit: 1 });
  await open(page, "/vulnerabilities");
  await opensInPlace(page, "cve", () => firstItem(page).click(), first.cve_id);
  const [p2] = await vulnsTruth("alpha", { limit: 1, offset: 25 });
  await open(page, "/vulnerabilities?page=2");
  await opensInPlace(page, "cve", () => firstItem(page).click(), p2.cve_id);
});

test("Devices: a row opens the device drawer in place", async ({ superPage: page }) => {
  await open(page, "/devices");
  await opensInPlace(page, "device", () => firstItem(page).click(), await topAids());
});

test("device drawer: CVE rows and fixes open their drawers; CVE drawer rows open the device drawer; Back walks the same way", async ({ superPage: page }) => {
  const w = watchErrors(page);
  const [aid] = await topAids();
  await open(page, `/devices?device=${aid}`);
  const d = drawer(page);
  await expect(d.getByRole("heading", { name: /^CVEs on this device/ })).toBeVisible();

  // a fix of the checklist opens the fix drawer; Back returns to the device
  const fixButton = d.locator("section", { hasText: "What to fix on this device" }).locator("li button").first();
  await expect(fixButton).toBeVisible();
  await fixButton.click();
  await expect(page).toHaveURL((u) => u.pathname === "/devices" && u.searchParams.has("fix") && !u.searchParams.has("device"));
  await expect(drawer(page).getByRole("button", { name: /back to device/i })).toBeVisible();
  await drawer(page).getByRole("button", { name: /back to device/i }).click();
  await expect(page).toHaveURL((u) => u.searchParams.get("device") === aid && !u.searchParams.has("fix"));

  // a CVE row of the device opens the CVE drawer
  const row = tableRows(drawer(page)).first().locator("button:not([aria-pressed])").first();
  const rowId = (await row.innerText()).trim();
  await row.click();
  await expect(page).toHaveURL((u) => u.pathname === "/devices" && u.searchParams.get("cve") === rowId && !u.searchParams.has("device"));

  // CVE drawer -> device row -> device drawer
  const dd = drawer(page);
  await expect(dd.getByRole("heading", { name: new RegExp(rowId) })).toBeVisible();
  const devButton = tableRows(dd).first().locator("button:not([aria-pressed])").first();
  await expect(devButton).toBeVisible();
  await devButton.click();
  await expect(page).toHaveURL((u) => u.pathname === "/devices" && u.searchParams.has("device") && !u.searchParams.has("cve"));

  // history: device -> cve -> device, so Back walks the same way, then the page itself
  await page.goBack();
  await expect(page).toHaveURL((u) => u.searchParams.get("cve") === rowId);
  await page.goBack();
  await expect(page).toHaveURL((u) => u.searchParams.get("device") === aid && !u.searchParams.has("cve"));
  await page.goBack();
  await expect(page).toHaveURL((u) => !DRAWER_KEYS.some((k) => u.searchParams.has(k)));
  await expect(drawer(page)).toHaveCount(0);
  w.check();
});

test("a drawer opened from a page keeps that page behind it (filters and page survive)", async ({ superPage: page }) => {
  await open(page, "/vulnerabilities?tier=P2&page=1");
  const id = ((await firstItem(page).innerText()).match(/CS-C\d+-A\d+|CVE-\d{4}-\d+/) ?? [""])[0]; // a phone card also holds severity text
  await firstItem(page).click();
  await expect(page).toHaveURL((u) => u.pathname === "/vulnerabilities" && u.searchParams.get("tier") === "P2" && u.searchParams.get("cve") === id);
  await expect(main(page).locator('[aria-label="Active filters"]')).toContainText("Tier P2"); // the drawer makes the page inert, so no role query
  await page.goBack();
  await expect(page).toHaveURL((u) => u.searchParams.get("tier") === "P2" && !u.searchParams.has("cve"));
});

test("deep links open the drawer on first load on every page", async ({ superPage: page }) => {
  const [v] = await vulnsTruth("alpha", { limit: 1 });
  const [aid] = await topAids();
  const software = (await (await page.request.get(`/api/exposure/software?pageSize=1&tenantId=${tenantId("alpha")}`)).json()).rows[0].key as string;
  const fix = (await (await page.request.get(`/api/exposure/v2/fixes?pageSize=1&tenantId=${tenantId("alpha")}`)).json()).rows[0].id as string;
  for (const path of ["/", "/vulnerabilities", "/devices", "/graph", "/software", "/news", "/external"]) {
    await open(page, `${path}?cve=${v.cve_id}`);
    await expect(drawer(page).getByRole("heading", { name: new RegExp(v.cve_id) })).toBeVisible();
    await open(page, `${path}?device=${aid}`);
    await expect(drawer(page).locator("dl > div").filter({ hasText: "Device ID (AID)" }).locator("dd")).toHaveText(aid);
    await open(page, `${path}?software=${encodeURIComponent(software)}`);
    await expect(drawer(page).getByRole("heading").first()).toBeVisible();
    await open(page, `${path}?fix=${fix}`);
    await expect(drawer(page).getByRole("heading").first()).toBeVisible();
  }
});

test("drawer closes with Escape and with its close button, leaving the page URL", async ({ superPage: page }) => {
  const [v] = await vulnsTruth("alpha", { limit: 1 });
  await open(page, `/vulnerabilities?cve=${v.cve_id}`);
  await expect(drawer(page)).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(drawer(page)).toHaveCount(0);
  await expect(page).toHaveURL((u) => u.pathname === "/vulnerabilities" && !u.searchParams.has("cve"));
  await open(page, `/vulnerabilities?cve=${v.cve_id}`);
  await drawer(page).getByRole("button", { name: /close/i }).click();
  await expect(drawer(page)).toHaveCount(0);
  await expect(page).toHaveURL((u) => !u.searchParams.has("cve"));
});

test("Back after closing a drawer with Escape does not reopen it", async ({ superPage: page }) => {
  // Closing must not leave a history entry that brings the drawer back (the user pressed Esc to leave it).
  const [v] = await vulnsTruth("alpha", { limit: 1 });
  await open(page, "/vulnerabilities");
  await firstItem(page).click();
  await expect(drawer(page)).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(drawer(page)).toHaveCount(0);
  await page.goBack();
  await expect(page).not.toHaveURL(new RegExp(`cve=${v.cve_id}`)); // would land on the drawer URL if Esc pushed an entry
});

test("drawers fit the screen: full width on a phone, no sideways scroll", async ({ superPage: page, isMobile }) => {
  const [v] = await vulnsTruth("alpha", { limit: 1 });
  const [aid] = await topAids();
  for (const q of [`cve=${v.cve_id}`, `device=${aid}`]) {
    await open(page, `/vulnerabilities?${q}`);
    const dlg = drawer(page);
    await expect(dlg.locator('[aria-busy="true"]')).toHaveCount(0);
    await expect(dlg.getByRole("heading").first()).toBeVisible();
    const box = (await dlg.boundingBox())!;
    const vp = page.viewportSize()!;
    if (isMobile) expect(box.width, "drawer width on phone").toBeGreaterThanOrEqual(vp.width - 1);
    else expect(box.width).toBeGreaterThan(vp.width * 0.5);
    await expectNoHorizontalScroll(page);
  }
});

// the one sentence the user asked for: every place that names a CVE or device is clickable
test("no CVE id or device name on a list page is plain text", async ({ superPage: page }) => {
  await open(page, "/vulnerabilities");
  await expect(firstItem(page)).toBeVisible();
  await open(page, "/devices");
  await expect(firstItem(page)).toBeVisible();
  await open(page, "/");
  const rows = card(page, "Riskiest devices").locator("div.grid:has(button)");
  await expect(rows.first()).toBeVisible();
  // one name button per row, next to the watch star (a toggle, not a name)
  for (const r of await rows.all()) expect(await r.locator("button:not([aria-pressed])").count()).toBe(1);
  expect(await rows.count()).toBeGreaterThan(0);
});

test("a drawer opened from another drawer has a Back button that returns to it", async ({ superPage: page }) => {
  const [v] = await vulnsTruth("alpha", { limit: 1 });
  await open(page, `/vulnerabilities?cve=${v.cve_id}`);
  await expect(drawer(page).getByRole("button", { name: /back to/i })).toHaveCount(0); // opened from a page: nothing to go back to
  await drawer(page).locator("tbody tr button:not([aria-pressed])").first().click(); // a device row (the star in front of it only toggles)
  await expect(page).toHaveURL((u) => u.searchParams.has("device") && !u.searchParams.has("cve"));
  await drawer(page).getByRole("button", { name: /back to cve/i }).click();
  await expect(page).toHaveURL((u) => u.searchParams.get("cve") === v.cve_id && !u.searchParams.has("device"));
  await expect(drawer(page).getByRole("heading", { name: new RegExp(v.cve_id) })).toBeVisible();
});

test("CVE drawer: software section shows vendor, installed versions and the fixed version (misconfigurations explain why there is none)", async ({ superPage: page }) => {
  const [v] = await vulnsTruth("alpha", { limit: 1 }); // the first CVE of the tenant: an endpoint vulnerability in the mock data
  await open(page, `/vulnerabilities?cve=${v.cve_id}`);
  await expect(drawer(page).getByText("Affected software")).toBeVisible();
  await expect(drawer(page).getByText(/Example Corp/).first()).toBeVisible();
  await expect(drawer(page).getByText("Installed versions")).toBeVisible();
  await expect(drawer(page).getByText("Fixed in version")).toBeVisible();
  const [mis] = await vulnRows("alpha", "external", 1); // an EASM misconfiguration: not in the (endpoint) list, its drawer opens by id
  await open(page, `/vulnerabilities?cve=${mis.cve_id}`);
  await expect(drawer(page).getByText("Affected asset")).toBeVisible();
  await expect(drawer(page).getByText(/not a flaw in installed software/)).toBeVisible();
});

test("Software: list, type filter, drawer in place with versions and devices; a device opens the device drawer and Back returns", async ({ superPage: page }) => {
  await open(page, "/software");
  await expect(main(page).getByText(/^Software items/).or(page.getByRole("button", { name: /^Software items/ }))).toBeVisible();
  await pick(page, page.getByRole("combobox", { name: "Type" }), /^Browser extension/);
  await expect(page).toHaveURL((u) => u.searchParams.get("type") === "browser_extension");
  await expect(main(page).getByText("Shady Coupons").locator("visible=true").first()).toBeVisible();
  await expect(main(page).getByText("Flagged").locator("visible=true").first()).toBeVisible();
  await open(page, "/software?q=Google%20Chrome");
  await firstItem(page).click();
  await expect(page).toHaveURL((u) => u.pathname === "/software" && u.searchParams.has("software"));
  await expect(drawer(page).getByRole("heading", { name: "Google Chrome" })).toBeVisible();
  await expect(drawer(page).getByText("Installed versions")).toBeVisible();
  await expect(drawer(page).getByText("120.0.1").first()).toBeVisible();
  await expect(drawer(page).getByText("121.0.2").first()).toBeVisible();
  await drawer(page).locator("tbody tr button:not([aria-pressed])").first().click();
  await expect(page).toHaveURL((u) => u.searchParams.has("device") && !u.searchParams.has("software"));
  await drawer(page).getByRole("button", { name: /back to software/i }).click();
  await expect(drawer(page).getByRole("heading", { name: "Google Chrome" })).toBeVisible();
});
