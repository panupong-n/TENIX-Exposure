---
name: soc-portal-qa
description: Use when testing or reviewing the SOC CVE Portal end to end (LINE webhook -> news -> CVE -> Falcon -> portal) with mocks and fixtures, especially tenant isolation across two or more customers, duplicate hostnames, multi-CVE news, repeated webhooks and incomplete Falcon responses, including exports. ใช้ตรวจเส้นทางทั้งระบบด้วย mock/fixture และพิสูจน์ว่าลูกค้าเห็นข้ามองค์กรไม่ได้ทั้งหน้าจอและ API.
---

# SOC Portal QA

Goal: prove the whole chain works and that no customer can reach another customer's data. Use only mocks and fixtures. Tests must not call real LINE or real Falcon and must not contain real secrets, CIDs, hostnames or customer names (block outbound network in the test runner).

## Fixtures (build once, reuse)
- **Tenants:** `tenant-a` with `CID_A`, `tenant-b` with `CID_B` (fake 32-hex values), plus one SOC user and one customer user per tenant. Add a tenant with no CID mapping.
- **Same hostname twice:** machine `APP-01` exists in both tenants with different AIDs, and a second `APP-01` inside tenant A with another AID.
- **Unnamed machine:** one finding with no hostname.
- **LINE:** signed webhook bodies built in the test with a fake channel secret (HMAC over the exact raw bytes), a body with a bad signature, and a replay of the same `webhookEventId` (also once with `isRedelivery: true`).
- **News:** a local mock web server: article with 3 CVEs, article with none, an article that redirects to a private address, an oversized page, a timeout, and a link that returns 404.
- **Falcon mock:** serves paged Spotlight results (>=2 pages) for both CIDs, then variants: page 2 fails, host lookup returns 403, 429 then success, token 401, and a result that hits the cap.

## Scenarios and expected results
1. **Happy path:** signed LINE message with a URL -> one news item -> 3 CVE rows -> Falcon results stored per `CID + AID` -> portal shows them.
2. **Multi-CVE news:** each CVE has its own result and its own state; one failing CVE does not hide the others.
3. **Duplicate webhook:** same event twice (and a crash-retry) gives one news item, one set of CVE rows, one Falcon job.
4. **Bad signature / modified body:** rejected, nothing stored.
5. **URL states:** blocked address, timeout and 404 give `fetch_status` failures with `cve_result = not_evaluated`. Page read with no CVE gives `none_found`. The two must look different in API and UI. CVEs in message text still appear when the URL failed.
6. **Same hostname:** three separate machines appear, never merged. Unnamed machine appears with its AID.
7. **Falcon incomplete:** page failure, host-lookup 403, cap and 401 each yield `partial` or `failed` with the reason. The UI never says "no affected machines" for these. A complete run with zero findings says so with the time checked.
8. **Tenant isolation (below).**

## Tenant isolation matrix
Log in as `customer-a` and try to reach tenant B data through **every** path. Expected: 404 or empty, with no hint that the data exists.
- By-id API routes (news, CVE result, host, export, audit entry) using tenant B ids.
- List, search, filter and sort endpoints, with `cid`/`tenant` params forced to tenant B or to "all".
- Counts, totals, pagination metadata and autocomplete (no leaked numbers).
- UI routes opened directly by URL, and the browser back/refresh after switching users.
- Cache: user A loads a page, then user B loads the same URL. B must not receive A's data. Repeat for the opposite tenant.
- Exports: file contains only tenant A rows, a manipulated id list or query is rejected, cells starting with `=`, `+`, `-`, `@` are neutralized, filenames carry no other tenant name.
- Audit log: customer sees only own entries; denied attempts are recorded.
- Unmapped tenant sees nothing (not everything). SOC user must pick a tenant, and the access is audited.
- Secrets: grep responses, logs and fixtures for the fake secrets. None may appear.

## Reporting
Report as a table: scenario | layer (API/UI/export) | expected | result | evidence (test name). List what was not tested and why. A cross-tenant failure is release-blocking. Mock-only results do not prove the real Falcon field names; say so.

Related skills: `soc-portal-tenant-security`, `line-news-ingestion`, `falcon-spotlight-mapping`. For UI quality (accessibility, Thai/English, mobile) use `impeccable`.
