# TENIX Exposure: rules for every change

- **Every page must show a skeleton while it loads.** Use the building blocks in `web/src/components/shared/skeletons.tsx`
  (`StatCardsSkeleton`, `ChartCardSkeleton`, `TableSkeleton`, `GraphSkeleton`, `FormSkeleton`, `PageSkeleton`).
  A file that calls `useApi()` must render one; a routed page that loads nothing needs `// skeleton-ok: <reason>`.
  `npm run lint` (in `web/`) runs `scripts/check-skeletons.mjs` and fails otherwise. This includes every new page.
- **UI text is Thai.** The language is fixed (no switcher, the browser language is ignored). Fixed text (menus, headings, buttons, messages) is Thai; data that comes from CrowdStrike stays as Falcon reports it (severity names Critical/High/Medium/Low/Informational, exploit status, ExPRT, CVE/KEV/CVSS/EASM, host names, descriptions, software names).
  Add every new string twice: Thai in `web/scripts/messages-th-*.json` and English in `web/scripts/messages-en*.json` (the English is the reference and what the e2e build shows), then `node scripts/merge-messages.mjs`. `npm run lint` runs `scripts/check-messages.mjs` and fails when a live string has no Thai text or its `{placeholders}` differ; add a new namespace to `LIVE` in that script.
  Dates use Thai month names with Gregorian years (`intlLocale()` in `web/src/utils/format.ts`). Sort names with `nameOrder` (client) or `byName()` (server), never with `ORDER BY name` or `localeCompare`, so Thai names come out in dictionary order.
- Severity colours are fixed: Critical red, High orange, Medium yellow, Low green, Informational/other blue (`web/src/lib/chart.ts`, `severity-badge.tsx`).
- Unused template pages are switched off, never deleted (`web/src/disabled-routes.tsx`).
- The menu lives in the header (`components/layout/app-layout/header`); no sidebar, no global search box.
- Keep screens dense: small card padding and gaps. Use only Tailwind classes that exist (this theme has no `text-theme-*` or `error-*` colours).
- Tenant isolation is decided in `server/src/scope.ts`; new read endpoints must go through `tenantScope()` and get a test in `server/test/api.test.ts`.
- The interface is **light only**. Dark mode is switched off (not deleted): no theme toggle is rendered and `web/src/contexts/theme-context.tsx` ignores any saved or system preference (`LIGHT_ONLY`). Do not add dark-mode work or screenshots; existing `dark:` classes stay as they are.
