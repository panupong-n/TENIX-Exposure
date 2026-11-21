---
name: soc-portal-tenant-security
description: Use when designing, writing or reviewing authentication, authorization, tenant-to-CID mapping, API endpoints, caching, audit logging, exports or secret handling in the TENFORWARD SOC CVE Portal (SOC staff plus customer users). ใช้เมื่อแตะระบบล็อกอิน สิทธิ์ การแมป tenant กับ CID API cache audit log ไฟล์ส่งออก หรือ LINE/Falcon secrets. Not for UI styling.
---

# SOC Portal tenant security

One rule drives everything: **a customer must never see, count, export or infer data of another organization.** The backend enforces this. The UI hides things only for convenience.

## 1. Where the tenant comes from
- Derive tenant and allowed CIDs on the server: session -> user -> tenant membership -> CID list.
- Never trust a `cid`, `tenant`, `org` or role value from the URL, query, body, header or token claim that the client can edit. If one is sent, ignore it or check it against the allowed set and reject on mismatch.
- A tenant with no CID mapping gets **zero** data. An empty CID list must never turn into "no filter / all CIDs". (`cs_exposure_vulns.py` treats an empty CID prompt as all; that is fine for a local script and forbidden here.)

## 2. Roles
- `customer_user`: own tenant only. Read-only unless a feature says otherwise.
- `soc_analyst` / `soc_admin`: may see several tenants, but only by choosing a tenant (or CID set) explicitly per request. Every cross-tenant read is audited. Admin-only: changing membership and the tenant-to-CID mapping.
- Default deny. A new endpoint is closed until it states its required role and scope.

## 3. Enforcement points
- Put the CID scope in **one data-layer choke point** that every query goes through (repository or query builder). Do not rely on each handler remembering to filter.
- Object-level check on every by-id route (CVE result, host, news item, export, audit entry): load the object, compare its CID with the caller's allowed set. Return the same 404 for "missing" and "not yours" so ids cannot be probed.
- Aggregates, counts, search suggestions, pagination totals and error messages are data too. Compute them inside the scope.

## 4. Cache
- Every key for tenant data includes the tenant or CID set. Never cache per-tenant results under a shared key, and never reuse a CDN or HTTP cache across users (`Cache-Control: private, no-store` for authenticated tenant data).
- Public content with no tenant data (a news summary, a CVE description) may be shared.

## 5. Audit log
- Record: time, actor id, role, tenant, CIDs touched, action, resource id, result (allowed/denied), request id, source IP.
- Log denials and every SOC cross-tenant access. Append-only. Customers can read only their own tenant's entries.
- Never write secrets, tokens, full LINE payloads or full Falcon responses into logs.

## 6. Exports
- Same authorization and scoping as the API. Build the file on the server at download time from the caller's scope, not from a cached file or a client-supplied id list.
- Neutralize spreadsheet formulas in CSV/XLSX cells that start with `=`, `+`, `-`, `@`. Keep filenames and metadata free of other tenants' names.
- Audit each export.

## 7. Secrets and sessions
- LINE channel secret and access token, Falcon client id and secret: read from the environment or a secret manager. Never in the repo, fixtures, client bundle, logs, error text or screenshots. Use a read-only Falcon API client (Spotlight and Hosts read only). Plan for rotation.
- Session cookie: `HttpOnly`, `Secure`, `SameSite`. CSRF protection on state-changing routes. Rate-limit login. Require MFA for SOC roles if the identity provider supports it.
- Treat LINE user ids and customer hostnames as personal or confidential data. Store the minimum.

## Review checklist (answer each in the PR or plan)
1. Where does the tenant come from for this request?
2. What happens with an empty or unknown tenant/CID?
3. Which role is required, and what is denied by default?
4. Is the by-id object checked against the caller's CIDs?
5. Do cache keys, counts, exports and audit entries carry the scope?
6. Is there a cross-tenant test for it? (see `soc-portal-qa`)

Related skills: `falcon-spotlight-mapping` (what to query per CID), `line-news-ingestion` (webhook secrets), `soc-portal-qa` (proof).
