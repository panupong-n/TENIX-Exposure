import type { Locator, Page } from "@playwright/test";
import { expect, expectNoHorizontalScroll, test, watchErrors } from "./fixtures";
import {
  apiResponse, card, cveText, cveTruth, drawer, EXPLOIT_LABEL, EXPRT_LABEL, fixTruth, fmt, hostDetail, hostsTruth, listRecords, main, num, openFilters, overviewTruth, overviewV2, pick, RANK, SEV, SEV_LABEL,
  sql, tableRecords, tableRows, tenantId, useTenant, vulnFacets, vulnRows, vulnsTotal, vulnsTruth, where, type Source, type TKey,
} from "./helpers";

// Read-only: runs on desktop and mobile. The database is the source of truth, the UI is compared to it.
const SOURCES: Source[] = ["", "endpoint", "external"];

test.describe("seeded data is what the mock Falcon holds", () => {
  test("every CID synced completely and the row counts match the mock", async ({ superPage: page }) => {
    // 1400 + 40 EASM findings for Alpha, 500 + 6 for Beta (test/mock-falcon.ts); nothing may be dropped in the sync
    expect((await overviewTruth("alpha")).findings).toBe(1440);
    expect((await overviewTruth("beta")).findings).toBe(506);
    expect((await overviewTruth("alpha", "external")).findings).toBe(40);
    expect((await overviewTruth("beta", "external")).findings).toBe(6);
    expect((await overviewTruth("empty")).findings).toBe(0);
    const st = await sql<{ state: string }>("SELECT state FROM cid_status");
    expect(st.map((x) => x.state)).toEqual(["complete", "complete"]);
    // misconfigurations are exactly the findings with a CrowdStrike id, and CVE findings always have a description
    expect(await sql("SELECT DISTINCT cve_id FROM findings WHERE (kind = 'Misconfiguration') <> (cve_id LIKE 'CS-%')")).toEqual([]);
    expect(await sql("SELECT DISTINCT f.cve_id FROM findings f LEFT JOIN cves c ON c.id = f.cve_id WHERE COALESCE(c.description, '') = ''")).toEqual([]);
    await page.goto("/");
    await expect(page.getByText(/Data is complete/)).toBeVisible();
  });
});

// ------------------------------------------------------------------ Overview (v2: P1 headline, fixes, tiers, severity, riskiest devices)
const pct = (a: number, b: number) => `${Math.round((a / b) * 100)}%`;
/** The rows of an Overview list card as [name, numbers...]: every child of a row is one cell (hidden cells of a phone are still in the DOM). */
const overviewRows = (scope: Locator, rowSel: string) => scope.locator(rowSel).evaluateAll((rows) => rows.map((r) => [...r.children].map((c) => (c.textContent ?? "").replace(/\s+/g, " ").trim())));

for (const tenant of ["alpha", "beta"] as TKey[]) {
  test.describe(`Overview of ${tenant}`, () => {
    test("P1 headline, tiers, severity, fixes and riskiest devices match the database", async ({ superPage: page }) => {
      const w = watchErrors(page);
      await useTenant(page, tenant);
      const t = await overviewV2(tenant);
      expect(t.p1).toBeGreaterThan(0);
      await page.goto("/");
      // the headline number, who has it, and the risk level rule (share of hosts with a P1)
      await expect(page.locator("[data-testid=p1-number] [aria-label]").first()).toHaveAttribute("aria-label", fmt(t.p1));
      await expect(main(page).getByText(`on ${fmt(t.hostsP1)} hosts (${pct(t.hostsP1, t.hostsTotal)} of ${fmt(t.hostsTotal)}) · ${fmt(t.p1Cves)} CVEs`)).toBeVisible();
      const share = t.hostsP1 / t.hostsTotal;
      await expect(main(page).getByText(share >= 0.6 ? "Critical" : share >= 0.2 ? "High" : share >= 0.05 ? "Medium" : "Low", { exact: true }).first()).toBeVisible();
      // severity bars: one per level with the count of findings
      const sev = card(page, "By severity");
      for (const [i, k] of (["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"] as const).entries()) {
        const row = sev.locator(`a[href$="severity=${k}"]`);
        await expect(row, k).toContainText(SEV_LABEL[k]);
        await expect(row, k).toContainText(fmt(t.sev[i]));
      }
      // tiers: the part held in detail of P2 and P3 is what the database holds (P1 is shown as Falcon's exact total, which the headline and the list below check)
      const tiers = card(page, "Exposure by tier");
      await expect(tiers.locator('a[href$="tier=P2"]')).toContainText(new RegExp(`held in full|held ${fmt(t.p2)} of`));
      await expect(tiers.locator('a[href$="tier=P2"]')).toContainText(fmt(t.p2)); // held in full: the total shown is what we hold
      await expect(tiers.locator('a[href$="tier=P3"]')).toContainText(new RegExp(`held in full|held ${fmt(t.p3)} of`));
      await expect(tiers.locator('a[href$="tier=P3"]')).toContainText(fmt(t.p3)); // held in full: the total shown is what we hold
      // fixes: the top ones by P1 removed; the count of fixes with a P1; P1 per fix
      const fixes = await fixTruth(tenant);
      const fixCard = card(page, "What to fix first");
      await expect(fixCard.getByText(`See all ${fmt(fixes.length)} fixes`)).toBeVisible();
      const fixRows = await overviewRows(fixCard, 'a[href*="fix="]');
      expect(fixRows.length).toBe(Math.min(8, fixes.length));
      expect(fixRows.map((r) => num(r[3])), "P1 per fix, most first").toEqual(fixes.slice(0, fixRows.length).map((f) => f.p1));
      // riskiest devices: most P1, then Critical; each row is a real host with these numbers
      const hosts = await hostsTruth(tenant);
      const want = hosts.filter((h) => h.p1 > 0 || h.critical > 0).slice(0, 6);
      const rows = (await overviewRows(card(page, "Riskiest devices"), "div.grid:has(button)")).filter((r) => r.length >= 5);
      const names = await card(page, "Riskiest devices").locator("div.grid:has(button) button span[title]").evaluateAll((els) => els.map((e) => e.getAttribute("title")));
      expect(rows.length).toBe(want.length);
      expect(rows.map((r) => [num(r[2]), num(r[3])])).toEqual(want.map((h) => [h.p1, h.critical]));
      const pool = new Map<string, number>();
      for (const h of hosts) pool.set(`${h.hostname ?? h.aid}|${h.p1}|${h.critical}|${h.kev}`, (pool.get(`${h.hostname ?? h.aid}|${h.p1}|${h.critical}|${h.kev}`) ?? 0) + 1);
      for (const [i, r] of rows.entries()) {
        const k = `${names[i]}|${num(r[2])}|${num(r[3])}|${num(r[4])}`;
        expect(pool.get(k) ?? 0, `device row ${names[i]}`).toBeGreaterThan(0);
        pool.set(k, pool.get(k)! - 1);
      }
      await expect(card(page, "Riskiest devices").getByText(`All ${fmt(t.hostsP1)} devices with a P1`)).toBeVisible();
      await expectNoHorizontalScroll(page);
      w.check();
    });

    test("endpoint + external add up to the unfiltered total", async () => {
      const [all, ep, ext] = await Promise.all(SOURCES.map((s) => overviewTruth(tenant, s)));
      for (const k of ["findings", "devices", "critical", "exploited", "cves"] as const) expect(ep[k] + ext[k], k).toBe(all[k]);
      expect(ep.sev.map((v, i) => v + ext.sev[i])).toEqual(all.sev);
    });

    test("the summary API agrees with the database for every source", async ({ superPage: page }) => {
      for (const s of SOURCES) {
        const t = await overviewTruth(tenant, s);
        const r = await page.request.get(`/api/exposure/summary?tenantId=${tenantId(tenant)}${s ? `&source=${s}` : ""}`);
        const j = await r.json();
        expect([j.totals.findings, j.totals.hosts, j.totals.cves, j.totals.exploited]).toEqual([t.findings, t.devices, t.cves, t.exploited]);
        expect(SEV.map((x) => j.severity[x])).toEqual(t.sev);
      }
    });

    test("the v2 summary API agrees with the database (P1, hosts, severity, tiers held)", async ({ superPage: page }) => {
      const t = await overviewV2(tenant);
      const j = await (await page.request.get(`/api/exposure/v2/summary?tenantId=${tenantId(tenant)}`)).json();
      expect([j.headline.p1, j.headline.hostsWithP1, j.headline.hostsTotal, j.headline.p1Cves]).toEqual([t.p1, t.hostsP1, t.hostsTotal, t.p1Cves]);
      expect([j.tiers.P1.held, j.tiers.P2.held, j.tiers.P3.held]).toEqual([t.p1, t.p2, t.p3]);
      expect(SEV.map((x) => j.severity.held[x])).toEqual(t.sev);
      expect(j.external.findings).toBe((await overviewTruth(tenant, "external")).findings); // EASM findings are in no endpoint number
    });
  });
}

test.describe("trend range", () => {
  test("default is 30 days and every option sends its own days parameter", async ({ superPage: page }) => {
    await useTenant(page, "alpha");
    const first = apiResponse(page, "/api/exposure/v2/trend");
    await page.goto("/");
    expect((await first).url()).toContain("days=30");
    const range = page.getByRole("group", { name: "Period" });
    await expect(range.getByRole("button", { name: "30 d" })).toHaveAttribute("aria-pressed", "true");
    for (const d of [7, 90, 30]) {
      const r = apiResponse(page, "/api/exposure/v2/trend", `days=${d}`);
      await range.getByRole("button", { name: `${d} d` }).click();
      expect((await (await r).json()).days).toBe(d);
      await expect(range.getByRole("button", { name: `${d} d` })).toHaveAttribute("aria-pressed", "true");
    }
  });

  test("the trend holds one point per day: today equals the P1 count, and an unsupported range falls back to 30", async ({ superPage: page }) => {
    const t = await overviewV2("alpha");
    const j = await (await page.request.get(`/api/exposure/v2/trend?tenantId=${tenantId("alpha")}&days=90`)).json();
    expect(j.days).toBe(90);
    expect(j.points.at(-1).p1).toBe(t.p1);
    expect(new Set(j.points.map((p: { day: string }) => p.day)).size).toBe(j.points.length);
    expect((await (await page.request.get(`/api/exposure/v2/trend?tenantId=${tenantId("alpha")}&days=5`)).json()).days).toBe(30);
    await useTenant(page, "alpha");
    await page.goto("/");
    await expect(main(page).getByText(`P1 today: ${fmt(t.p1)}`).or(main(page).locator('svg[aria-label^="P1 findings over time"]'))).toBeVisible();
  });

  test("trend points equal the stored snapshots (one per day, last one of the day)", async ({ superPage: page }) => {
    const j = await (await page.request.get(`/api/exposure/summary?tenantId=${tenantId("alpha")}&days=365`)).json();
    const snaps = await sql(`SELECT to_char(to_timestamp(ts / 1000.0) AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS day, critical, high, medium, low FROM snapshots
      WHERE cid IN (SELECT cid FROM tenant_cids WHERE tenant_id = $1) ORDER BY ts DESC LIMIT 1`, [tenantId("alpha")]);
    const last = j.trend.at(-1);
    expect([last.day, last.critical, last.high, last.medium, last.low]).toEqual([snaps[0].day, snaps[0].critical, snaps[0].high, snaps[0].medium, snaps[0].low]);
    // the latest snapshot is the current sync: it equals the live severity counts (except Informational, which is not charted)
    const t = await overviewTruth("alpha");
    expect([last.critical, last.high, last.medium, last.low]).toEqual(t.sev.slice(0, 4));
    // an unsupported range falls back to 30
    expect((await (await page.request.get(`/api/exposure/summary?tenantId=${tenantId("alpha")}&days=5`)).json()).days).toBe(30);
  });
});

// ------------------------------------------------------------------ Vulnerabilities (v2: endpoint CVEs by priority tier)
/** Rows of the list as the page shows them, checked against the database's row for the same CVE. */
function expectVulnRow(r: Awaited<ReturnType<typeof listRecords>>[number], e: Awaited<ReturnType<typeof vulnsTruth>>[number]) {
  const kind = e.kind === "Misconfiguration";
  expect(r.__text.includes("Misconfiguration"), `${e.cve_id} misconfiguration label`).toBe(kind);
  expect(r.__text, `${e.cve_id} tier`).toContain(`P${e.tier}`);
  expect(r.__text, `${e.cve_id} severity`).toContain(SEV_LABEL[e.sev]);
  if (r.mobile) expect(r.__text.includes("KEV"), `${e.cve_id} KEV badge`).toBe(e.kev);
  if (r.mobile) expect(r.__text, e.cve_id).toContain(`${fmt(e.hosts)} ${e.hosts === 1 ? "device" : "devices"} · CVSS ${e.score ? e.score.toFixed(1) : "–"}`);
  else {
    expect(r.Tier, `${e.cve_id} tier cell`).toBe(`P${e.tier}`);
    expect(r["Severity · CVSS"], `${e.cve_id} severity and cvss`).toBe(`${SEV_LABEL[e.sev]}${e.score ? e.score.toFixed(1) : "–"}`);
    expect(r.ExPRT, `${e.cve_id} exprt`).toBe(EXPRT_LABEL[e.lvl]);
    expect(r["Exploit status"], `${e.cve_id} exploit status`).toBe(EXPLOIT_LABEL[String(e.ex)] ?? "Unknown");
    expect(r.KEV.startsWith("KEV"), `${e.cve_id} KEV cell`).toBe(e.kev);
    expect(r.Devices.startsWith(fmt(e.hosts)), `${e.cve_id} devices (${r.Devices})`).toBe(true);
    if (e.product) expect(r.CVE, `${e.cve_id} software`).toContain(e.product);
  }
}

for (const tenant of ["alpha", "beta"] as TKey[]) {
  test.describe(`Vulnerabilities of ${tenant}`, () => {
    test("count, tier facets, first page and last page match the database", async ({ superPage: page }) => {
      const w = watchErrors(page);
      await useTenant(page, tenant);
      const total = await vulnsTotal(tenant);
      const pages = Math.ceil(total / 25);
      const facets = await vulnFacets(tenant);
      expect(facets.P1 + facets.P2 + facets.P3).toBe(total);
      await page.goto("/vulnerabilities");
      for (const [k, label] of [["P1", "P1 Fix now"], ["P2", "P2 Fix in cycle"], ["P3", "P3 Plan"], ["kev", "KEV"]] as const) await expect(page.getByRole("button", { name: new RegExp(`^${label}\\s*${fmt(facets[k])}$`) }), label).toBeVisible();
      const check = async (n: number) => {
        const expected = await vulnsTruth(tenant, { limit: 25, offset: (n - 1) * 25 });
        const from = (n - 1) * 25 + 1;
        await expect(main(page).getByText(`${fmt(from)}–${fmt(Math.min(total, n * 25))} of ${fmt(total)}`)).toBeVisible();
        await expect.poll(async () => (await listRecords(page)).map((r) => r.__id), { message: `ids on page ${n}` }).toEqual(expected.map((e) => e.cve_id));
        const recs = await listRecords(page);
        for (const [i, e] of expected.entries()) expectVulnRow(recs[i], e);
      };
      await expect(main(page).getByText(`${fmt(total)} items`)).toBeVisible();
      await check(1);
      if (pages > 1) {
        await page.getByRole("button", { name: "Next" }).click();
        await expect(page).toHaveURL(/page=2/);
        await check(2);
        await page.goto(`/vulnerabilities?page=${pages}`);
        await check(pages);
        await expect(page.getByRole("button", { name: "Next" })).toBeDisabled();
      }
      w.check();
    });

    test("tier, severity, KEV and search filters narrow the list like the database does", async ({ superPage: page }) => {
      await useTenant(page, tenant);
      await page.goto("/vulnerabilities");
      const search = page.getByRole("searchbox");
      await search.fill("CVE-2025-109");
      const found = await vulnsTotal(tenant, { where: "cve_id ILIKE '%CVE-2025-109%'" });
      expect(found).toBeGreaterThan(0);
      await expect(main(page).getByText(`of ${fmt(found)}`)).toBeVisible();
      await expect.poll(async () => (await listRecords(page)).length).toBe(Math.min(25, found));
      await search.fill("");
      await expect(page).not.toHaveURL(/[?&]q=/); // the box writes the URL 300 ms after typing stops
      await pick(page, page.getByRole("combobox", { name: "Severity" }), "Critical");
      const crit = await vulnsTotal(tenant, { having: `MIN(${RANK}) = 0` });
      await expect(main(page).getByText(`of ${fmt(crit)}`)).toBeVisible();
      await expect.poll(async () => (await listRecords(page)).every((r) => (r.mobile ? r.__text.includes("Critical") : r["Severity · CVSS"].startsWith("Critical")))).toBe(true);
      await page.locator('[aria-label="Active filters"] button').click();
      await openFilters(page);
      await page.getByRole("button", { name: "KEV", exact: true }).click();
      const kev = await vulnsTotal(tenant, { having: "BOOL_OR(kevf)" });
      await expect(page).toHaveURL(/kev=1/);
      await expect(main(page).getByText(`of ${fmt(kev)}`)).toBeVisible();
      await expect.poll(async () => (await listRecords(page)).every((r) => (r.mobile ? r.__text.includes("KEV") : r.KEV.startsWith("KEV")))).toBe(true);
      await page.goto("/vulnerabilities?tier=P2");
      const p2 = await vulnsTruth(tenant, { having: "MIN(tier) = 2", limit: 25 });
      await expect(main(page).getByText(`of ${fmt((await vulnFacets(tenant)).P2)}`)).toBeVisible();
      await expect.poll(async () => (await listRecords(page)).map((r) => r.__id)).toEqual(p2.map((e) => e.cve_id));
    });
  });
}

test("Vulnerabilities: a filter chosen right after typing is not lost to the delayed search write", async ({ superPage: page }) => {
  await page.goto("/vulnerabilities");
  await page.getByRole("searchbox").fill("CVE-2025");
  await pick(page, page.getByRole("combobox", { name: "Severity" }), "Critical"); // within 300 ms of typing
  await page.waitForTimeout(800);
  await expect(page).toHaveURL(/severity=CRITICAL/);
  await expect(page).toHaveURL(/q=CVE-2025/);
});

test("Vulnerabilities list holds endpoint CVEs only: the EASM misconfigurations (CS- ids) are on External surface, and any misconfiguration row is labelled", async ({ superPage: page }) => {
  expect(await sql(`SELECT 1 FROM findings WHERE ${where("alpha", "external")} AND kind IS DISTINCT FROM 'Misconfiguration' LIMIT 1`)).toEqual([]);
  expect(await sql(`SELECT 1 FROM findings WHERE ${where("alpha", "endpoint")} AND kind = 'Misconfiguration' LIMIT 1`)).toEqual([]);
  const external = (await sql<{ n: number }>(`SELECT COUNT(DISTINCT cve_id)::int n FROM findings WHERE ${where("alpha", "external")}`))[0].n;
  expect(external).toBeGreaterThan(0);
  const j = await (await page.request.get(`/api/exposure/v2/vulnerabilities?tenantId=${tenantId("alpha")}&pageSize=100`)).json();
  expect(j.total).toBe(await vulnsTotal("alpha")); // none of the EASM findings is in the total
  for (const r of j.rows) expect(r.cveId).toMatch(/^CVE-\d{4}-\d+$/);
  await page.goto("/vulnerabilities?q=CS-C24");
  await expect(main(page).getByText(/No vulnerabilities match your filters/)).toBeVisible();
  await expect(main(page).getByText("Misconfiguration")).toHaveCount(0);
});

// ------------------------------------------------------------------ Devices (v2: the host inventory, worst first)
for (const tenant of ["alpha", "beta"] as TKey[]) {
  test.describe(`Devices of ${tenant}`, () => {
    test("count, facets, first page and last page match the database", async ({ superPage: page }) => {
      const w = watchErrors(page);
      await useTenant(page, tenant);
      const all = await hostsTruth(tenant);
      const total = all.length;
      const pages = Math.ceil(total / 25);
      const keyOf = (h: { name: string; p1: number; critical?: number; kev?: number; os?: string | null; worst?: string }) => (h.critical === undefined ? `${h.name}|${h.p1}` : `${h.name}|${h.p1}|${h.critical}|${h.kev}|${h.os ?? "–"}|${h.worst}`);
      const pool = (mobile: boolean) => {
        const m = new Map<string, number>();
        for (const h of all) {
          const k = keyOf({ name: h.hostname ?? "Unnamed device", p1: h.p1, ...(mobile ? {} : { critical: h.critical, kev: h.kev, os: h.os }) });
          m.set(k, (m.get(k) ?? 0) + 1);
        }
        return m;
      };
      await page.goto("/devices");
      // heading chips: all devices, with P1, internet-facing, unseen over 7 days
      const day = 86_400_000;
      const facets: [string, number][] = [["All devices", total], ["With P1", all.filter((h) => h.p1 > 0).length], ["Internet-facing", all.filter((h) => h.inet).length],
        ["Unseen over 7 days", all.filter((h) => h.last_seen !== null && Date.now() - Number(h.last_seen) > 7 * day).length]];
      for (const [label, n] of facets) await expect(page.getByRole("button", { name: new RegExp(`^${label}\\s*${fmt(n)}$`) }), label).toBeVisible();
      const check = async (n: number) => {
        const expected = all.slice((n - 1) * 25, n * 25);
        await expect(main(page).getByText(`${fmt((n - 1) * 25 + 1)}–${fmt(Math.min(total, n * 25))} of ${fmt(total)}`)).toBeVisible();
        await expect.poll(async () => (await listRecords(page)).length, { message: `rows on page ${n}` }).toBe(expected.length);
        const recs = await listRecords(page);
        const mobile = !!recs[0].mobile;
        // order: the sort keys (P1, then Critical CVEs) must run exactly as in the database; names inside a tie are not compared
        // (a phone card shows the P1 count only when there is one)
        const cardP1 = await main(page).locator("ul.divide-y > li").evaluateAll((lis) => lis.map((li) => Number((li.querySelector("button span.text-sm.font-semibold")?.textContent ?? "0").replace(/\D/g, ""))));
        const p1 = (r: (typeof recs)[number]) => (mobile ? cardP1[recs.indexOf(r)] : num(r.P1));
        expect(recs.map(p1), `P1 order on page ${n}`).toEqual(expected.map((h) => h.p1));
        if (!mobile) expect(recs.map((r) => num(r.Critical)), `Critical order on page ${n}`).toEqual(expected.map((h) => h.critical));
        // every row is a real device with exactly these numbers (one database device is used up per row)
        const left = pool(mobile);
        for (const r of recs) {
          const k = mobile ? keyOf({ name: r.__id, p1: p1(r) }) : keyOf({ name: r.__id, p1: num(r.P1), critical: num(r.Critical), kev: num(r.KEV), os: r.OS });
          expect(left.get(k) ?? 0, `device row ${r.__id} (${k})`).toBeGreaterThan(0);
          left.set(k, left.get(k)! - 1);
        }
      };
      await check(1);
      if (pages > 1) {
        await page.getByRole("button", { name: "Next" }).click();
        await expect(page).toHaveURL(/page=2/);
        await check(2);
        await page.goto(`/devices?page=${pages}`);
        await check(pages);
      }
      w.check();
    });

    test("filters narrow the list like the database does (P1, internet-facing, platform, last seen, duplicates)", async ({ superPage: page }) => {
      await useTenant(page, tenant);
      const day = 86_400_000;
      const cases: [string, string, string][] = [
        ["tier=P1", "p1 > 0", "Has P1"],
        ["duplicates=1", "dup", "Duplicates"],
        ["seen=stale7", `last_seen < ${Date.now() - 7 * day}`, "Unseen over 7 days"],
        ["platform=Windows", "lower(platform) = 'windows'", "Windows"],
      ];
      for (const [q, cond, chip] of cases) {
        const n = (await hostsTruth(tenant, cond)).length;
        await page.goto(`/devices?${q}`);
        await expect(page.locator('[aria-label="Active filters"]')).toContainText(chip);
        if (n === 0) await expect(main(page).getByText(/No devices match your filters/)).toBeVisible();
        else await expect(main(page).getByText(`of ${fmt(n)}`)).toBeVisible();
      }
    });
  });
}

test("Devices: search by name finds exactly the devices the database finds", async ({ superPage: page }) => {
  await page.goto("/devices");
  await page.getByRole("searchbox").fill("WEB-0");
  const hits = await hostsTruth("alpha", "hostname ILIKE '%WEB-0%' OR local_ip ILIKE '%WEB-0%' OR aid ILIKE '%WEB-0%'");
  expect(hits.length).toBeGreaterThan(0);
  await expect(main(page).getByText(`of ${fmt(hits.length)}`)).toBeVisible();
  await expect.poll(async () => (await listRecords(page)).every((r) => r.__id.includes("WEB-0"))).toBe(true);
  await page.getByRole("searchbox").fill("zz-no-such-device");
  await expect(main(page).getByText("No devices match your filters. Remove a filter above.")).toBeVisible();
});

// ------------------------------------------------------------------ drawers
const fact = (page: Page, label: string) => drawer(page).locator("dl > div").filter({ has: page.locator("dt", { hasText: new RegExp(`^${label}$`) }) }).locator("dd");

async function sampleCves(t: TKey) {
  const top = await vulnsTruth(t, { limit: 25 });
  const ext = await vulnRows(t, "external", 1); // an EASM misconfiguration: not in the list, but its drawer still opens
  const plain = await sql<{ cve_id: string }>(`SELECT cve_id FROM findings WHERE ${where(t, "endpoint")} AND product IS NULL GROUP BY cve_id LIMIT 1`);
  return [...new Set([top[0].cve_id, top[1].cve_id, top.at(-1)!.cve_id, ext[0].cve_id, ...plain.map((p) => p.cve_id)])];
}

for (const tenant of ["alpha", "beta"] as TKey[]) {
  test(`CVE drawer shows what the CVE is and the same device count as the list (${tenant})`, async ({ superPage: page }) => {
    test.setTimeout(120_000);
    const w = watchErrors(page);
    await useTenant(page, tenant);
    for (const id of await sampleCves(tenant)) {
      const t = await cveTruth(tenant, id);
      await page.goto(`/vulnerabilities?cve=${id}`);
      const d = drawer(page);
      await expect(d.getByRole("heading", { name: new RegExp(id) })).toBeVisible();
      await expect(fact(page, "Affected devices")).toHaveText(fmt(t.devices));
      // the list's Devices column for this CVE
      const listed = (await vulnsTruth(tenant)).find((r) => r.cve_id === id);
      if (listed) expect(listed.hosts).toBe(t.devices);
      const mis = id.startsWith("CS-");
      expect(t.kind).toBe(mis ? "Misconfiguration" : "Vulnerability");
      await expect(d.getByText(mis ? "Misconfiguration" : "Vulnerability", { exact: true }).first()).toBeVisible();
      await expect(d.getByText(mis ? /Security misconfiguration found/ : /Vulnerability affecting devices/)).toBeVisible();
      if (!mis) await expect(d.getByText("Misconfiguration", { exact: true })).toHaveCount(0);
      // the tier of a CVE the list shows, with the reason; a misconfiguration (not in the list) has none
      if (listed) await expect(d.getByRole("heading", { name: `Why this is P${listed.tier}` })).toBeVisible();
      else await expect(d.getByRole("heading", { name: /^Why this is P/ })).toHaveCount(0);
      // description (the public CVE record, else what Falcon sent), CWE, published date, references
      const text = await cveText(id);
      expect(text, `${id} has a description`).toBeTruthy();
      await expect(d.getByRole("heading", { name: "What it is" })).toBeVisible();
      await expect(d.locator("section", { hasText: "What it is" })).toContainText(text.slice(0, 60).replace(/\s+/g, " "));
      const cwes: string[] = JSON.parse(t.info.cwes);
      if (cwes.length) await expect(fact(page, "Weakness \\(CWE\\)")).toHaveText(cwes.join(", "));
      if (t.info.published_at) await expect(fact(page, "Published")).toHaveText(new Intl.DateTimeFormat("en-US", { dateStyle: "medium" }).format(new Date(Date.parse(t.info.published_at))));
      const refs = [...JSON.parse(t.info.advisories_json), ...JSON.parse(t.info.references_json)].filter((u: string) => /^https?:\/\//i.test(u));
      if (refs.length) {
        await expect(d.getByRole("heading", { name: "References" })).toBeVisible();
        expect(await d.locator("section", { hasText: "References" }).locator("a").evaluateAll((a) => a.map((x) => (x as HTMLAnchorElement).href))).toEqual(refs);
      }
      // affected software: vendor and product names with device counts (a misconfiguration has no software: it says why instead)
      if (mis) {
        await expect(d.getByRole("heading", { name: "Affected asset" })).toBeVisible();
        await expect(d.getByRole("heading", { name: "Affected software" })).toHaveCount(0);
      } else {
        const sw = d.locator("section", { has: page.getByRole("heading", { name: "Affected software" }) }).locator("ul").first().locator("li");
        await expect(sw).toHaveCount(t.products.length);
        for (const [i, p] of t.products.entries()) {
          const text = (await sw.nth(i).innerText()).replace(/\s+/g, " ");
          const name = p.product && p.product !== "Unknown" ? p.product : "Not identified";
          expect(text).toMatch(new RegExp(`^(.+ · )?${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} ${p.n} ${p.n === 1 ? "device" : "devices"}$`));
        }
      }
      // affected devices table: one row per device (capped at 200), every device named and clickable
      const rows = tableRows(d.locator("section", { has: page.getByRole("heading", { name: "Affected devices" }) }));
      await expect(rows).toHaveCount(Math.min(200, t.devices));
      await expect(rows.first().locator("button:not([aria-pressed])")).toBeVisible();
    }
    w.check();
  });
}

test("CVE drawer: a CVE with no findings in the tenant says so, never an error", async ({ superPage: page }) => {
  await page.goto("/vulnerabilities?cve=CVE-1999-0001");
  await expect(drawer(page).getByText("No open findings for CVE-1999-0001")).toBeVisible();
});

test("CVE drawer: lower-case ids and the old /vulnerabilities/<id> URL open the drawer", async ({ superPage: page }) => {
  const id = (await vulnsTruth("alpha", { limit: 1 }))[0].cve_id;
  await page.goto(`/vulnerabilities/${id}`);
  await expect(page).toHaveURL(new RegExp(`/vulnerabilities\\?cve=${id}$`));
  await expect(drawer(page).getByRole("heading", { name: new RegExp(id) })).toBeVisible();
  await page.goto(`/vulnerabilities?cve=${id.toLowerCase()}`);
  await expect(drawer(page).getByRole("heading", { name: new RegExp(id) })).toBeVisible();
  await expect(fact(page, "Affected devices")).toHaveText(fmt((await cveTruth("alpha", id)).devices));
});

async function sampleDevices(t: TKey) {
  const all = await hostsTruth(t);
  const named = all[0];
  const unnamed = all.find((h) => h.findings > 0 && !h.hostname);
  const bare = all.find((h) => h.findings === 0); // in the inventory, nothing found on it
  const many = [...all].sort((a, b) => b.findings - a.findings)[0];
  return [...new Set([named, unnamed, bare, many].filter((h): h is NonNullable<typeof h> => !!h).map((h) => h.aid))];
}

for (const tenant of ["alpha", "beta"] as TKey[]) {
  test(`device drawer: tier and severity counts, facts, fixes and CVEs match the database (${tenant})`, async ({ superPage: page }) => {
    test.setTimeout(120_000);
    const w = watchErrors(page);
    await useTenant(page, tenant);
    const samples = await sampleDevices(tenant);
    expect(samples.length).toBeGreaterThan(1);
    for (const aid of samples) {
      const t = await hostDetail(tenant, aid);
      await page.goto(`/devices?device=${aid}`);
      const d = drawer(page);
      await expect(d.getByRole("heading", { name: t.info.hostname ?? "Unnamed device" })).toBeVisible();
      await expect(fact(page, "Device ID \\(AID\\)")).toHaveText(aid);
      await expect(fact(page, "CID")).toHaveText(t.info.cid);
      await expect(fact(page, "Local IP")).toHaveText(t.info.local_ip || "–");
      await expect(fact(page, "External IP")).toHaveText(t.info.external_ip || "–");
      for (const part of [t.info.os, t.info.product_type]) if (part) await expect(d).toContainText(part);
      // findings per tier and per severity (only levels that have findings)
      const want = [...t.tiers.map((n, i) => `P${i + 1} ${n}`), ...SEV.flatMap((s, i) => (t.counts[i] > 0 ? [`${SEV_LABEL[s]} ${t.counts[i]}`] : []))];
      const chips = d.locator("div.flex-wrap > span.inline-flex.items-center.gap-1\\.5");
      await expect.poll(async () => (await chips.allInnerTexts()).map((x) => x.replace(/\s+/g, " ").trim())).toEqual(want);
      // fixes to apply (one per set of recommended actions, P1 and P2 only; the drawer lists the first 25) and the CVEs (worst tier of each, the first 50)
      await expect(d.locator("section", { hasText: "What to fix on this device" }).locator('input[type="checkbox"]')).toHaveCount(Math.min(25, t.fixes));
      await expect(d.getByRole("heading", { name: `CVEs on this device (${fmt(t.cves.length)})` })).toBeVisible();
      const rows = await tableRecords(d);
      expect(rows.length).toBe(Math.min(50, t.cves.length));
      for (const r of rows) {
        const e = t.cves.find((c) => c.cve_id === r.CVE);
        expect(e, `${r.CVE} is a CVE of this device`).toBeTruthy();
        expect(r.Tier, `${r.CVE} tier`).toBe(`P${e!.tier}`);
        expect(r.KEV.startsWith("KEV"), `${r.CVE} KEV`).toBe(e!.kev);
      }
      expect(new Set(rows.map((r) => r.CVE)).size).toBe(rows.length);
      await expect(d.getByRole("link", { name: "View in graph" })).toHaveAttribute("href", new RegExp(`view=graph&focus=device`));
    }
    w.check();
  });
}

test("device drawer: a device id that does not exist, and an EASM asset (not a device), show an error state, not a crash", async ({ superPage: page }) => {
  const w = watchErrors(page);
  await page.goto("/devices?device=00000000000000000000000000000000");
  await expect(drawer(page).getByText(/could not|not be loaded|went wrong|try again/i).first()).toBeVisible();
  const easm = (await sql<{ aid: string }>(`SELECT aid FROM findings WHERE ${where("alpha", "external")} LIMIT 1`))[0].aid;
  await page.goto(`/devices?device=${easm}`);
  await expect(drawer(page).getByText(/could not|not be loaded|went wrong|try again/i).first()).toBeVisible();
  w.check();
});
