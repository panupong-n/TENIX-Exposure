/* eslint-disable @typescript-eslint/no-explicit-any -- API JSON */
import { randomBytes } from "node:crypto";
import { mkdirSync } from "node:fs";
import type { Locator, Page } from "@playwright/test";
import { env, expect, test, watchErrors } from "./fixtures";
import { pane, pick, sql } from "./helpers";

// The tenant flow the owner asked for: create a tenant, give it ITS OWN CrowdStrike login, then (inside the tenant) several news sources and
// several notification groups, each list on its own. Desktop only: it creates and deletes data.
const SHOTS = process.env.TENANT_FLOW_SHOTS; // optional: a folder to drop screenshots of the flow into
const shot = async (page: Page, name: string, info: { project: { name: string } }) => {
  if (!SHOTS) return;
  mkdirSync(SHOTS, { recursive: true });
  await page.screenshot({ path: `${SHOTS}/tenant-flow-${info.project.name}-${name}.png`, fullPage: true });
};
const rand = () => randomBytes(3).toString("hex");
/** The bordered block (wizard) or section (detail) that holds this heading. */
const block = (page: Page, heading: string): Locator => page.locator("section, div.rounded-lg").filter({ has: page.getByRole("heading", { name: heading }) }).last();

async function fillConnection(page: Page, cid: string, secret = "mock-secret") {
  await pick(page, page.getByRole("combobox", { name: "Falcon cloud" }), "Custom URL");
  await page.getByLabel("API base URL").fill(`http://127.0.0.1:${env().ports.mock}`);
  await page.getByLabel("Client ID").fill("mock-client");
  await page.getByLabel("Client Secret").fill(secret);
  await page.getByLabel("CID", { exact: true }).fill(cid);
}
/** Type a room, press Add, repeat; then press this block's own Save. */
async function addRooms(b: Locator, rooms: [string, string][]) {
  for (const [chat, name] of rooms) {
    await b.getByLabel("Room ID", { exact: true }).fill(chat);
    await b.getByLabel("Room name", { exact: true }).last().fill(name);
    await b.getByRole("button", { name: "Add", exact: true }).click();
  }
}

/** The test deletes its tenants itself; this is for a run that failed half way (cid_status rows would break the data specs). */
async function cleanup() {
  const mine = "(SELECT id FROM tenants WHERE name LIKE 'QA Flow %')";
  await sql(`DELETE FROM cid_status WHERE cid IN (SELECT cid FROM tenant_cids WHERE tenant_id IN ${mine})`);
  for (const t of ["falcon_connections", "tenant_cids", "line_chats"]) await sql(`DELETE FROM ${t} WHERE tenant_id IN ${mine}`);
  await sql("DELETE FROM tenants WHERE name LIKE 'QA Flow %'");
}

test.describe("tenant flow", () => {
  test.skip(({ isMobile }) => isMobile, "creates and deletes data: desktop only");
  test.beforeEach(cleanup);
  test.afterEach(cleanup);

  test("create a tenant, add its own CrowdStrike with the mock, see the state, add 2 news sources and 2 notification groups, delete", async ({ superPage: page }, info) => {
    test.setTimeout(120_000);
    const w = watchErrors(page);
    const id = rand();
    const name = `QA Flow ${id}`, other = `QA Flow other ${id}`;
    const cid = randomBytes(16).toString("hex"), cidOther = randomBytes(16).toString("hex");
    const rooms = { s1: `Csrc1${id}aaaa`, s2: `Csrc2${id}aaaa`, g1: `Cgrp1${id}aaaa`, g2: `Cgrp2${id}aaaa`, taken: `Ctaken${id}aaaa` };
    // a second organization that owns one room and has a CID with no login of its own (the old, wrong state)
    const o = (await (await page.request.post("/api/tenants", { data: { name: other } })).json()).tenant;
    expect((await page.request.put(`/api/tenants/${o.id}/line`, { data: { sources: [{ chat: rooms.taken, name: "taken" }], destinations: [] } })).status()).toBe(200);
    expect((await page.request.put(`/api/tenants/${o.id}/cids`, { data: { cids: [cidOther] } })).status()).toBe(200);

    // 1. create: a duplicate name is explained as a NAME problem, not a CID one
    await page.goto("/settings?setting=tenants");
    await page.getByRole("button", { name: "Add organization" }).click();
    await page.getByLabel("Organization name").fill("Alpha Corp");
    await page.getByRole("button", { name: "Create and continue" }).click();
    await expect(pane(page).getByText("An organization with this name already exists.")).toBeVisible();
    await expect(pane(page).getByText(/CID already has a connection/)).toHaveCount(0);
    await page.getByLabel("Organization name").fill(name);
    await page.getByRole("button", { name: "Create and continue" }).click();
    await expect(page.getByRole("heading", { name: "Connect CrowdStrike" })).toBeVisible();

    // 2. its own CrowdStrike: a wrong secret is told apart, then the right one is tested and saved
    await fillConnection(page, cid, "wrong-secret");
    await page.getByRole("button", { name: "Test connection" }).click();
    await expect(pane(page).getByText(/Wrong Client ID or Client Secret/)).toBeVisible();
    await page.getByRole("button", { name: "Save and read data now" }).click(); // the server refuses it too and says the same
    await expect(pane(page).getByText(/Wrong Client ID or Client Secret/)).toBeVisible();
    expect(await sql("SELECT 1 FROM falcon_connections WHERE cid = $1", [cid])).toEqual([]);
    await shot(page, "1-wizard-refused", info);
    await page.getByLabel("Client Secret").fill("mock-secret");
    await page.getByRole("button", { name: "Test connection" }).click();
    await expect(pane(page).getByText(/Login works and this CID can be read/)).toBeVisible();
    await page.getByRole("button", { name: "Save and read data now" }).click();
    await expect(page.getByRole("heading", { name: "Set up LINE" })).toBeVisible();
    await expect(pane(page).getByText(/Connection saved/)).toBeVisible();
    const conn = await sql<{ tenant_id: string }>("SELECT tenant_id FROM falcon_connections WHERE cid = $1", [cid]);
    expect(conn.length).toBe(1);
    const tid = conn[0].tenant_id;

    // 3. LINE: two separate blocks, each saved on its own; a room typed but not added is added by Save; a room of another organization is refused
    const src = block(page, "News sources (several rooms)"), grp = block(page, "Notification groups (several groups)");
    await expect(src).toBeVisible();
    await expect(grp).toBeVisible();
    await addRooms(src, [[rooms.s1, "Source one"]]);
    await src.getByLabel("Room ID", { exact: true }).fill(rooms.s2); // typed, never added
    await expect(src.getByText(/Save adds it/)).toBeVisible();
    await expect(pane(page).getByRole("button", { name: "Finish" })).toBeDisabled();
    await src.getByRole("button", { name: "Save news sources" }).click();
    await expect(src.getByText("LINE settings saved.")).toBeVisible();
    await expect(src.getByText(rooms.s2)).toBeVisible();
    await addRooms(grp, [[rooms.taken, "not mine"]]);
    await grp.getByRole("button", { name: "Save notification groups" }).click();
    await expect(grp.getByText("A room can belong to only one organization, in every role.")).toBeVisible();
    await grp.getByRole("button", { name: /^Remove not mine/ }).click();
    await addRooms(grp, [[rooms.g1, "Group one"], [rooms.g2, "Group two"]]);
    await grp.getByRole("button", { name: "Save notification groups" }).click();
    await expect(grp.getByText("LINE settings saved.")).toBeVisible();
    await shot(page, "2-wizard-line", info);
    const chats = await sql<{ chat_id: string; role: string }>("SELECT chat_id, role FROM line_chats WHERE tenant_id = $1 ORDER BY chat_id", [tid]);
    expect(chats.length).toBe(4);
    expect(new Set(chats.map((c) => c.role)).size).toBe(2);
    await pane(page).getByRole("button", { name: "Finish" }).click();

    // 4. the tenant page: separate sections, chips, the state after the read
    await expect(pane(page).getByRole("heading", { name, level: 2 })).toBeVisible();
    for (const h of ["CrowdStrike", "News sources (several rooms)", "Notification groups (several groups)", "Users and data"]) await expect(pane(page).getByRole("heading", { name: h })).toBeVisible();
    await expect(pane(page).getByText("LINE: 2 news sources · 2 groups")).toBeVisible();
    await expect.poll(async () => (await sql("SELECT state FROM cid_status WHERE cid = $1", [cid])).map((r) => r.state), { timeout: 60_000 }).toEqual(["complete"]);
    await page.goto(`/settings?setting=tenants&tenant=${tid}`); // a deep link opens that tenant
    await expect(pane(page).getByRole("heading", { name, level: 2 })).toBeVisible();
    await expect(pane(page).getByText("Complete", { exact: true }).first()).toBeVisible();
    await shot(page, "3-detail", info);

    // 5. a CID with no login of its own: said plainly, never "no data", with an "add login" action; the deep link goes to the CrowdStrike section
    // the data banner on its overview says it honestly and links to THIS organization's CrowdStrike section (not to a shared login)
    await page.goto("/");
    await page.evaluate((v) => localStorage.setItem("tenix.org", v), o.id);
    await page.reload();
    await expect(page.getByText(/This organization has no CrowdStrike login of its own, so the system does not read its data|Data has not been read from Falcon yet/)).toBeVisible(); // the first once the server reports no_connection
    await shot(page, "3b-overview-no-login", info);
    await expect(page.getByRole("link", { name: "Open this organization's CrowdStrike settings" })).toHaveAttribute("href", `/settings?setting=tenants&tenant=${o.id}&section=falcon`);
    await page.getByRole("link", { name: "Open this organization's CrowdStrike settings" }).click();
    await expect(page).toHaveURL(/setting=tenants&tenant=.+&section=falcon/);
    await expect(pane(page).getByRole("heading", { name: other, level: 2 })).toBeVisible();
    await expect(pane(page).getByText("No login of its own yet")).toBeVisible();
    await expect(pane(page).getByText("No login of its own", { exact: true }).first()).toBeVisible(); // the state chip
    await expect(pane(page).getByRole("button", { name: "Try the old shared login" })).toHaveCount(0); // there is no old login
    await shot(page, "4-no-login", info);
    await pane(page).getByRole("button", { name: "Add login" }).click();
    await expect(page.getByLabel("CID", { exact: true })).toHaveValue(cidOther);
    await pick(page, page.getByRole("combobox", { name: "Falcon cloud" }), "Custom URL");
    await page.getByLabel("API base URL").fill(`http://127.0.0.1:${env().ports.mock}`);
    await page.getByLabel("Client ID").fill("mock-client");
    await page.getByLabel("Client Secret").fill("mock-secret");
    await page.getByRole("button", { name: "Save only" }).click();
    await expect(pane(page).getByText("Connection saved.")).toBeVisible();
    await expect(pane(page).getByText("No login of its own yet")).toHaveCount(0);

    // 6. delete both (name confirmation)
    await page.goto(`/settings?setting=tenants&tenant=${tid}`);
    await pane(page).getByRole("button", { name: `Actions for ${name}` }).click();
    await page.getByRole("menuitem", { name: "Delete" }).click();
    await page.locator('[role="dialog"]:not([data-slot="sheet-content"])').locator("input").fill(name);
    await page.getByRole("button", { name: "Delete tenant" }).click();
    await expect(pane(page).getByText("Tenant deleted.")).toBeVisible();
    expect(await sql("SELECT 1 FROM falcon_connections WHERE tenant_id = $1", [tid])).toEqual([]);
    expect(await sql("SELECT 1 FROM line_chats WHERE tenant_id = $1", [tid])).toEqual([]);
    expect((await page.request.fetch(`/api/tenants/${o.id}`, { method: "DELETE", data: { confirmName: other } })).status()).toBe(200);
    expect(w.errors.filter((e) => !/status of (400|409)/.test(e)), "unexpected console errors (the 400/409 refusals were provoked on purpose)").toEqual([]);
  });
});
