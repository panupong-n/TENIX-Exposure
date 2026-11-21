// QA: screenshots of the dialogs behind the "invite user" and "change access" tasks
import { join } from "node:path";
import { test } from "./fixtures";
import { ctxAs, settle, SHOTS } from "./qa-helpers";
test("task dialogs", async ({ browser }, info) => {
  test.skip(info.project.name === "mobile", "screenshot walk-through of desktop tables");
  const { context, page } = await ctxAs(browser, info, "super", "light");
  await page.goto("/settings?setting=team"); await settle(page);
  await page.getByRole("button", { name: /invite user/i }).click(); await page.waitForSelector("[role=dialog]:not([data-slot=sheet-content])"); await page.waitForTimeout(500);
  await page.screenshot({ path: join(SHOTS, `${info.project.name}-light-dialog-invite.png`) });
  await page.keyboard.press("Escape"); await page.waitForTimeout(400);
  await page.locator("tbody tr").nth(2).getByRole("button").last().click(); await page.waitForTimeout(400);
  await page.screenshot({ path: join(SHOTS, `${info.project.name}-light-team-rowmenu.png`) });
  const items = await page.getByRole("menuitem").allInnerTexts();
  console.log("MENU", JSON.stringify(items));
  await page.getByRole("menuitem").first().click(); await page.waitForTimeout(600);
  await page.screenshot({ path: join(SHOTS, `${info.project.name}-light-dialog-access.png`) });
  await context.close();
});
