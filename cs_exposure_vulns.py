import argparse
import getpass
import ipaddress
import json
import os
import re
import sys
import textwrap
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("CS_BASE_URL", "https://api.us-2.crowdstrike.com").rstrip("/")
ALLOWED = {
    ("POST", "/oauth2/token"),
    ("GET", "/spotlight/combined/vulnerabilities/v1"),
    ("GET", "/spotlight/entities/remediations/v2"),
    ("GET", "/devices/entities/devices/v2"),
}
LOG = []
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}
EXPLOIT_STATUS = {0: "Unproven", 30: "Medium", 60: "High", 90: "Critical"}
PAGE_SIZE = 1000
SCAN_CAP = 20000
CHUNK = 400
HOST_CHUNK = 100
AID_PATTERN = re.compile(r"[0-9a-f]{32}")


def call(method, path, token=None, params=None, form=None, soft=False):
    if (method, path) not in ALLOWED:
        sys.exit(f"Blocked: {method} {path} is not in the read-only allowlist")
    url = BASE + path + ("?" + urllib.parse.urlencode(params, doseq=True) if params else "")
    data, headers = None, {"Accept": "application/json"}
    if form:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data, headers, method=method), timeout=60) as r:
            LOG.append((method, path, r.status, r.headers.get("X-Cs-Traceid", "-")))
            return json.load(r)
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        LOG.append((method, path, e.code, e.headers.get("X-Cs-Traceid", "-")))
        if soft:
            return {"_http": e.code, "_body": body}
        hint = {401: "invalid client credentials or wrong cloud base URL",
                403: "API client is missing a required read scope"}.get(e.code, "")
        sys.exit(f"HTTP {e.code} on {path} {hint}\n{body}")


def table(title, headers, rows, note="", wraps=None):
    print(f"\n{title}" + (f"  ({note})" if note else ""))
    if not rows:
        print("  No data found")
        return
    wraps = wraps or [60] * len(headers)
    grid = []
    for r in rows:
        cells = []
        for i, c in enumerate(r):
            text = "-" if c in (None, "") else str(c)
            lines = []
            for part in text.split("\n"):
                lines.extend(textwrap.wrap(part, wraps[i], break_long_words=True, break_on_hyphens=False) or [""])
            cells.append(lines)
        grid.append(cells)
    w = [max(len(h), *(len(line) for cells in grid for line in cells[i])) for i, h in enumerate(headers)]
    rule = "+-" + "-+-".join("-" * x for x in w) + "-+"
    multiline = any(len(c) > 1 for cells in grid for c in cells)

    def fmt(parts):
        return "| " + " | ".join(p.ljust(w[i]) for i, p in enumerate(parts)) + " |"

    print(rule)
    print(fmt(headers))
    print(rule)
    for cells in grid:
        for k in range(max(len(c) for c in cells)):
            print(fmt([c[k] if k < len(c) else "" for c in cells]))
        if multiline:
            print(rule)
    if not multiline:
        print(rule)


def cve_id(value):
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", value.upper()):
        raise argparse.ArgumentTypeError("expected a CVE id such as CVE-2026-111497")
    return value.upper()


def parse_args(argv):
    p = argparse.ArgumentParser(description="Read-only Falcon Exposure Management vulnerability report")
    p.add_argument("--cid", help="filter to one customer ID; if omitted, you are prompted (Enter = all)")
    p.add_argument("--cve", type=cve_id)
    p.add_argument("--severity", type=str.upper, default="CRITICAL",
                   choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "ALL"])
    p.add_argument("--exprt", type=str.upper, choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"])
    p.add_argument("--limit", type=int, default=500, help="maximum findings on named hosts to report")
    p.add_argument("--raw", action="store_true", help="print the first raw finding as JSON for field inspection")
    args = p.parse_args(argv)
    if not 1 <= args.limit <= 5000:
        p.error("--limit must be between 1 and 5000")
    return args


def resolve_cid(arg):
    value = (arg if arg is not None else input("CID (press Enter for all): ")).strip()
    if not value:
        return None
    if not re.fullmatch(r"[0-9a-fA-F]{32}", value):
        sys.exit("Invalid CID: expected 32 hexadecimal characters")
    return value.lower()


def build_filter(args, cid):
    parts = ["status:['open','reopen']"]
    if cid:
        parts.append(f"cid:'{cid}'")
    if args.cve:
        parts.append(f"cve.id:'{args.cve}'")
    if args.severity != "ALL":
        parts.append(f"cve.severity:'{args.severity}'")
    if args.exprt:
        parts.append(f"cve.exprt_rating:'{args.exprt}'")
    return "+".join(parts)


def lookup_hosts(token, findings, hosts, tried):
    aids = sorted({f["aid"] for f in findings if AID_PATTERN.fullmatch(str(f.get("aid", "")))} - tried)
    for start in range(0, len(aids), HOST_CHUNK):
        chunk = aids[start:start + HOST_CHUNK]
        r = call("GET", "/devices/entities/devices/v2", token, params={"ids": chunk}, soft=True)
        if r.get("_http") == 404:
            tried.update(chunk)
            continue
        if "_http" in r:
            return f"HTTP {r['_http']}"
        tried.update(chunk)
        for h in r.get("resources") or []:
            hosts[h.get("device_id")] = h
    return None


def host_value(finding, hosts, *names):
    for source in (hosts.get(finding.get("aid")) or {}, finding.get("host_info") or {}):
        for name in names:
            if source.get(name):
                return source[name]
    return None


def real_hostname(finding, hosts):
    name = str(host_value(finding, hosts, "hostname") or "").strip()
    if not name:
        return None
    try:
        ipaddress.ip_address(name)
        return None
    except ValueError:
        return name


def collect(token, fql, limit):
    kept, hosts, tried = [], {}, set()
    state = {"total": None, "scanned": 0, "excluded": 0, "lookup_failure": None, "capped": False}
    after = None
    while len(kept) < limit:
        if state["scanned"] >= SCAN_CAP:
            state["capped"] = True
            break
        params = {"filter": fql, "limit": PAGE_SIZE, "facet": ["cve", "host_info", "remediation"]}
        if after:
            params["after"] = after
        r = call("GET", "/spotlight/combined/vulnerabilities/v1", token, params=params)
        batch = r.get("resources") or []
        pagination = (r.get("meta") or {}).get("pagination") or {}
        state["total"] = pagination.get("total", state["total"])
        state["scanned"] += len(batch)
        if not state["lookup_failure"]:
            state["lookup_failure"] = lookup_hosts(token, batch, hosts, tried)
        for f in batch:
            if not real_hostname(f, hosts):
                state["excluded"] += 1
            elif len(kept) < limit:
                kept.append(f)
        after = pagination.get("after")
        if not batch or not after:
            break
    state["more"] = len(kept) >= limit and state["scanned"] < (state["total"] or 0)
    return kept, hosts, state


def remediation_ids(finding):
    rem = finding.get("remediation") or {}
    ids = list(rem.get("ids") or [])
    ids += [e["id"] for e in rem.get("entities") or [] if e.get("id")]
    return list(dict.fromkeys(ids))


def collect_remediations(token, findings):
    known = {}
    for f in findings:
        for e in (f.get("remediation") or {}).get("entities") or []:
            if e.get("id"):
                known[e["id"]] = e
    missing = sorted({i for f in findings for i in remediation_ids(f)} - set(known))
    for start in range(0, len(missing), CHUNK):
        r = call("GET", "/spotlight/entities/remediations/v2", token, params={"ids": missing[start:start + CHUNK]})
        for e in r.get("resources") or []:
            known[e["id"]] = e
    return known


def remediation_text(entity):
    text = entity.get("action") or entity.get("title") or entity.get("reference") or entity.get("id") or "-"
    extras = [f"{k}: {entity[k]}" for k in ("link", "vendor_url", "reference")
              if entity.get(k) and entity.get(k) != text]
    return "\n".join([f"- {text}"] + [f"  {x}" for x in extras])


def severity(cve):
    return str(cve.get("severity") or "-").upper()


def sort_key(cve_key, cve):
    return (SEVERITY_ORDER.get(severity(cve), 9), -(cve.get("base_score") or 0), cve_key)


def cve_key(finding):
    cve = finding.get("cve") or {}
    return cve.get("id") or finding.get("vulnerability_id") or "-"


def exploit_label(cve):
    value = cve.get("exploit_status")
    return EXPLOIT_STATUS.get(value, value)


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    client_id = os.environ.get("CS_CLIENT_ID") or input("Client ID: ").strip()
    secret = os.environ.get("CS_CLIENT_SECRET") or getpass.getpass("Client Secret: ").strip()
    cid = resolve_cid(args.cid)
    fql = build_filter(args, cid)
    print(f"Collecting data (read-only) from {BASE}")
    print(f"CID filter: {cid or 'none (all CIDs)'}")
    print(f"Filter: {fql}")

    token = call("POST", "/oauth2/token", form={"client_id": client_id, "client_secret": secret})["access_token"]
    findings, hosts, state = collect(token, fql, args.limit)
    if args.raw and findings:
        print("\nRaw first finding")
        print(json.dumps(findings[0], indent=2, ensure_ascii=False))
    remediations = collect_remediations(token, findings)

    by_cve, by_host, instances = {}, {}, {}
    for f in findings:
        key, cve, name = cve_key(f), f.get("cve") or {}, real_hostname(f, hosts)
        entry = by_cve.setdefault(key, {"cve": cve, "hosts": set(), "remediations": {}})
        entry["hosts"].add(name)
        for rid in remediation_ids(f):
            entry["remediations"][rid] = remediations.get(rid, {"id": rid})
        host = by_host.setdefault(name, {"platform": host_value(f, hosts, "platform_name", "platform"),
                                         "local_ip": host_value(f, hosts, "local_ip"),
                                         "external_ip": host_value(f, hosts, "external_ip"),
                                         "cid": f.get("cid"), "cves": set(), "findings": 0})
        host["cves"].add(key)
        host["findings"] += 1
        product = ((f.get("apps") or [{}])[0]).get("product_name_version")
        inst = instances.setdefault((key, name, product, f.get("status")), 0)
        instances[(key, name, product, f.get("status"))] = inst + 1

    ordered_cves = sorted(by_cve.items(), key=lambda kv: sort_key(kv[0], kv[1]["cve"]))
    cve_lookup = {k: v["cve"] for k, v in by_cve.items()}

    overview = [
        ["Findings matching filter", state["total"] if state["total"] is not None else "-"],
        ["Findings scanned", state["scanned"]],
        ["Excluded (asset has no hostname)", state["excluded"]],
        ["Reported (on named hosts)", len(findings)],
        ["Named hosts", len(by_host)],
        ["Unique CVEs", len(by_cve)],
    ]
    table("1) Overview", ["Metric", "Value"], overview)
    if state["lookup_failure"]:
        print(f"  Host lookup failed ({state['lookup_failure']}): add the Hosts: Read scope to resolve hostnames")
    if state["more"]:
        print(f"  Report limit of {args.limit} reached; raise --limit or narrow the filter for more")
    if state["capped"]:
        print(f"  Scan stopped after {SCAN_CAP} findings; narrow the filter with --cve or --cid")

    rows = []
    for key, entry in ordered_cves:
        cve = entry["cve"]
        rows.append([key, severity(cve), cve.get("base_score"), cve.get("exprt_rating"), exploit_label(cve),
                     len(entry["hosts"]), "\n".join(remediation_text(e) for e in entry["remediations"].values())
                     or "No remediation returned by the API"])
    table("2) Vulnerabilities by CVE and recommended action",
          ["CVE", "Severity", "CVSS", "ExPRT", "Exploit status", "Hosts", "Recommended action"], rows,
          wraps=[20, 10, 6, 10, 14, 6, 80])

    show_cid = not cid
    rows = []
    for name, h in sorted(by_host.items(), key=lambda kv: (-len(kv[1]["cves"]), kv[0].lower())):
        cves = sorted(h["cves"], key=lambda k: sort_key(k, cve_lookup[k]))
        rows.append([name, h["platform"], h["local_ip"], h["external_ip"], len(cves), ", ".join(cves)]
                    + ([h["cid"]] if show_cid else []))
    table("3) Affected hosts", ["Hostname", "Platform", "Local IP", "External IP", "CVEs", "CVE list"]
          + (["CID"] if show_cid else []), rows, wraps=[40, 12, 16, 16, 6, 60] + ([32] if show_cid else []))

    rows = []
    for (key, name, product, status), count in sorted(
            instances.items(), key=lambda kv: (sort_key(kv[0][0], cve_lookup[kv[0][0]]), kv[0][1].lower())):
        rows.append([f"{key} on {name}", severity(cve_lookup[key]), status, product, count])
    table("4) Findings (CVE on hostname)", ["Finding", "Severity", "Status", "Vulnerable product", "Instances"], rows,
          wraps=[70, 10, 10, 50, 9])

    table("5) API call log", ["#", "Method", "Path", "HTTP", "Trace ID"],
          [[i, m, p, s, t] for i, (m, p, s, t) in enumerate(LOG, 1)], wraps=[6, 8, 50, 6, 40])
    errors = sum(1 for _, _, s, _ in LOG if s >= 400)
    print(f"\n{len(LOG)} API calls, {errors} errors")


if __name__ == "__main__":
    main()
