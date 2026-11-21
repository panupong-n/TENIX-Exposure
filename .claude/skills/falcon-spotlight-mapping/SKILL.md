---
name: falcon-spotlight-mapping
description: Use when writing or reviewing the read-only lookup that maps a CVE to affected machines through CrowdStrike Falcon Spotlight (pagination, CID and AID identity, host names, remediations, partial or failed results). References cs_exposure_vulns.py in the project root; cs_overwatch_test.py is only for understanding OverWatch alert data. ใช้เมื่อพัฒนาหรือรีวิวการจับคู่ CVE กับเครื่องผ่าน Falcon Spotlight.
---

# Falcon Spotlight mapping (read-only)

Start by reading `cs_exposure_vulns.py` in the project root. Reuse its proven parts. The portal differs from that script in the places listed under "Do not copy".

## Reuse from `cs_exposure_vulns.py`
- **Read-only allowlist** in `call()`: only the OAuth token POST and the GET paths you need (`/spotlight/combined/vulnerabilities/v1`, `/spotlight/entities/remediations/v2`, `/devices/entities/devices/v2`). Anything else is blocked. Keep this guard.
- **FQL** joined with `+`, e.g. `status:['open','reopen']+cid:'<cid>'+cve.id:'CVE-YYYY-NNNN'`, with `facet` = `cve`, `host_info`, `remediation`.
- **Cursor pagination** with `after` from `meta.pagination`, page size 1000, until no `after` or an empty page.
- **Host lookup** in chunks of 100 AIDs, remediations in chunks of 400, fixed `AID_PATTERN` validation, and the API call log with `X-Cs-Traceid`.
- Cloud base URL from `CS_BASE_URL`. Note the two scripts default to different clouds (`us-2` vs US-1), so the portal must take the cloud from configuration, never a hard-coded default.

## Do not copy (portal requirements)
1. **All severities.** The script defaults `--severity` to CRITICAL. For a named CVE, query without a severity filter. Severity is data to display, not a filter.
2. **Machine identity is `CID + AID`.** The script groups by hostname and drops assets whose name is empty or an IP. The portal must keep them: two machines with the same hostname (same or different CID) stay separate, and a machine without a name shows as `AID` with "hostname unavailable". Hostname is a display attribute only.
3. **Never an empty CID.** The script's "Enter = all CIDs" is not allowed. The CID list comes from `soc-portal-tenant-security` (tenant mapping); query once per allowed CID, or with an explicit CID set for SOC. Verify against the real API how CID filtering behaves for parent/child CIDs before relying on it.
4. **No silent caps.** The script stops at `--limit` or `SCAN_CAP` and prints a note. The portal must carry that fact in the result.

## Result states (always return one of these, with detail)
- `complete`: every page for every requested CID was read. Zero findings then means "no open findings found in these CIDs", with the time and filter used.
- `partial`: some pages, CIDs or host lookups are missing (cap reached, a page failed, host lookup 403/5xx). List what is missing and show the findings you have.
- `failed`: nothing usable (auth 401, scope 403, network, repeated 5xx). Include HTTP code and trace id, no secrets.
- `not_checked`: the CVE was never queried (for example it came from an unreadable article).

Never show an incomplete or failed run as "not affected". Retry 429/5xx a few times with backoff (honor `Retry-After`), re-authenticate once on an expired token, then degrade to `partial` or `failed`.

## Record per run
CVE, CIDs queried, FQL used, start/end time, pages read, `meta.pagination.total` vs findings read, result state and reasons, trace ids. Per finding: `cid`, `aid`, hostname (if any), platform, IPs, product, status, severity, CVSS, ExPRT, exploit status, remediation text.

## OverWatch (`cs_overwatch_test.py`)
Uses the Alerts API (detections `tactic:'Falcon Overwatch'`, leads `product:'overwatch'`, tags `ow/resolution/*`). It explains OverWatch data and API-call style only. It is a different API with different scopes, and is not part of CVE-to-machine mapping. Do not mix its results into Spotlight output.

## Limits to remember
Field names and scopes above come from the scripts, not from a live API check. Confirm them against a sandbox or a read-only key before relying on them. Do not call Falcon from tests (see `soc-portal-qa`).
