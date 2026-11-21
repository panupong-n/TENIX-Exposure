---
name: tenix-exposure-frontend-qa
description: Use when checking the TENIX Exposure web app (tenix-exposure/web) for quality: dense and not empty-looking, easy to use, data correct and complete against the API/database, every page and drawer linked to the others, accessible and usable on mobile. Drives Playwright against the e2e stack. ใช้ตรวจหน้าเว็บ TENIX Exposure ว่าไม่โล่ง ใช้ง่าย ข้อมูลถูก ครบ และเชื่อมถึงกัน
---

# TENIX Exposure frontend QA

Run against the isolated e2e stack only (`cd tenix-exposure/web && npm run e2e`, see `web/e2e/README.md`): ports 8790/8791/8792, schema `e2e_*` in database `tenix_test`.
**Never** touch ports 8787/8788 or the databases `tenix_exposure` / `tenix_demo`, never `pkill`. Read `tenix-exposure/CLAUDE.md` first: its rules are the acceptance criteria.

## 1. Data is correct and complete (compare UI to the source of truth)
- For each tenant, the numbers on Overview (open findings, critical, devices, exploited, severity donut, top CVEs, top devices) equal the database (`findings` for the tenant's CIDs). Query the throwaway schema with `psql`.
- A customer-side user never sees another tenant's data in any page, drawer, export or URL (try `?tenantId=`, `?cve=`, `?device=` with foreign ids). Operators of one tenant never see CIDs.
- Misconfigurations (no CVE id, `CS-C...` ids) and external (EASM) assets appear, are labelled, and the Source filter splits them correctly; Source totals add up to the unfiltered total.
- A CVE drawer shows what the CVE is (description, CWE, published date, references), the affected software and devices, and the device count equals the list's "Devices" column.
- The trend range (7/14/30/90/180/365 days) changes the chart; default 30.
- Incomplete or failed syncs show the banner and never claim "nothing found".

## 2. Everything is connected
Starting from every place a CVE or device is named (Overview charts and tables, Vulnerabilities, Devices, Graph Tree nodes, both drawers), clicking opens the **drawer in place** (URL `?cve=` / `?device=`), without changing page, and Back closes it. From a CVE drawer a device opens the device drawer and the reverse. Old `/vulnerabilities/<id>` links redirect to the drawer.
Menu entries per role: super admin sees Tenants, Integrations, Team, Audit; a tenant admin sees Team and Audit; an operator sees neither. Direct URLs of hidden pages bounce.

## 3. Looks full, not empty (impeccable `critique`/`audit` lens)
Screenshot every page at 1440x900 and 390x844, light and dark. Flag: large blank areas below content, cards with one line of content, charts that are tiny or have lots of padding, tables with few columns stretched across the page, text that is hard to read (contrast), legends touching text, tooltips with unreadable text. Suggest concrete fixes (denser layout, more useful columns, side-by-side cards), never decoration.

## 4. Easy to use
Count clicks for the five common tasks: find the worst CVE and see which devices have it; open a device and see its CVEs; invite a user to one tenant as operator; change which tenants a user sees; switch tenant. Flag anything that takes more than 3 clicks or needs guessing. Check empty, loading (skeleton shown on **every** page and drawer), error and no-permission states for each page.

## 5. Quality bars
- Keyboard: tab order, Enter/Space on custom buttons, Esc closes drawers/dialogs, focus returns. Icon-only buttons have `aria-label`. Axe (`@axe-core/playwright`) shows no serious/critical violations on each page.
- Mobile 390px: no horizontal page scroll, drawers full width.
- No console errors or failed requests (except documented benign ones).
- Colours: Critical red, High orange, Medium yellow, Low green, Informational blue everywhere.

## Output
A table of findings: id, page, severity (blocker/major/minor), what you saw, expected, how to reproduce (Playwright step), suggested fix. Then fix only what the task asks; otherwise report. Add a Playwright test for every confirmed defect so it cannot return.
