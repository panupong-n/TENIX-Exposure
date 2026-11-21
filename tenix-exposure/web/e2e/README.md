# End-to-end tests (Playwright)

**Required first:** set `TENIX_TEST_DATABASE_URL` (e.g. `postgres://user:***@127.0.0.1:5433/tenix_test`). It is the only database variable the tests read (never `TENIX_DATABASE_URL`) and has no default; setup, teardown and helpers refuse anything except host `127.0.0.1`/`localhost`, port **5433**, database `tenix_test` (`e2e/test-db.ts`, checked before any schema is created or dropped). On the .109 machine 5433 is Exposure's Postgres and 5432 belongs to another system: never point tests at it.

Run: `cd web && npm run e2e` (builds the **English** UI with `VITE_LOCALE=en` into `web/dist-e2e`, which the e2e app serves, then runs both projects; `web/dist`, the real Thai build, is never touched). The tests assert English text; the Thai text is covered by `npm run lint` (`scripts/check-messages.mjs`). `npm run e2e:only` skips the build (needs `web/dist-e2e` from an earlier run), `npx playwright test --project=desktop` runs one project, `npm run e2e:report` opens the last HTML report.
Uses Playwright's own Chromium (no system Chrome needed). Once per machine: `cd web && npx playwright install chromium` (add `--with-deps` on a fresh Linux box; that needs sudo).

## What global setup does (`global-setup.ts`)
Starts, as child processes tracked by PID (teardown signals only those PIDs):
- mock Falcon on **8791** (`MOCK_RICH=1`: CVE details, KEV flags, EASM external-asset findings),
- the app on **8790** serving `web/dist`, database `tenix_test`, throwaway schema `e2e_<letters>`, no scheduled sync,
- an SMTP sink on **8792** (inside the test runner process).

Then, through the HTTP API: bootstrap super admin, tenants, Falcon connection, a finished sync, users, a mail sender and a recipient (`soc@e2e.test`).
It logs in once per user and writes `e2e/.auth/<name>.json` (Playwright storageState) plus `e2e/.auth/env.json` (ids, CIDs, ports, schema, PIDs).
Teardown stops the children, drops the schema and deletes `.auth/`. If a run is killed hard, run `npx playwright test` again with nothing else, or drop the `e2e_*` schema by hand.

## Seeded data (password for everyone: `E2e-Password-12345`)
| Fixture name | Email | Access |
|---|---|---|
| `super` (`superPage`) | super@e2e.test | super admin |
| `alphaAdmin` (`adminPage`) | alpha-admin@e2e.test | admin of Alpha Corp |
| `alphaOp` (`operatorPage`) | alpha-op@e2e.test | operator of Alpha Corp |
| `betaOp` | beta-op@e2e.test | operator of Beta Ltd |
| `multi` (`multiPage`) | multi@e2e.test | admin of Alpha, operator of Beta |
| `emptyOp` (`emptyPage`) | empty-op@e2e.test | operator of Empty Inc |

Tenants: Alpha Corp (CID `1111111111111111111111111111111a`), Beta Ltd (`2222222222222222222222222222222b`), Empty Inc (no CIDs). IDs are in `env()` from `fixtures.ts`.

## Writing tests
Import `test`, `expect`, `expectNoHorizontalScroll`, `watchErrors` from `./fixtures`. `as("betaOp")` opens a page signed in as any seeded user. Console errors: call `watchErrors(page).check()` at the end, or use the `expectNoConsoleErrors` page fixture. Benign errors (documented in `fixtures.ts`): 401/403/404 "Failed to load resource" lines.
Tests share one server and run serially. A test that changes data must create its own users or tenants with unique names and must not edit the seeded ones.

## Rules
Never use `pkill`/`killall` or kill by name. Never touch ports **8787** or **8788**, or the database `tenix_exposure`. E2E uses only 8790-8792 and `tenix_test` (on port 5433, via `TENIX_TEST_DATABASE_URL`). Never connect to Postgres 5432.
