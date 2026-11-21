import getpass
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

BASE = os.environ.get("CS_BASE_URL", "https://api.crowdstrike.com").rstrip("/")
LIMIT = 20
ALLOWED = {
    ("POST", "/oauth2/token"),
    ("GET", "/alerts/queries/alerts/v2"),
    ("POST", "/alerts/entities/alerts/v2"),
    ("POST", "/alerts/aggregates/alerts/v2"),
}
LOG = []

DETECTIONS = "tactic:'Falcon Overwatch'"
LEADS = "product:'overwatch'"


def call(method, path, token=None, params=None, form=None, body=None, soft=False):
    if (method, path) not in ALLOWED:
        sys.exit(f"Blocked: {method} {path} is not in the read-only allowlist")
    url = BASE + path + ("?" + urllib.parse.urlencode(params) if params else "")
    data, headers = None, {"Accept": "application/json"}
    if form:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data, headers, method=method), timeout=30) as r:
            LOG.append((method, path, r.status, r.headers.get("X-Cs-Traceid", "-")))
            return json.load(r)
    except urllib.error.HTTPError as e:
        body_txt = e.read().decode()[:500]
        LOG.append((method, path, e.code, e.headers.get("X-Cs-Traceid", "-")))
        if soft:
            return {"_http": e.code, "_body": body_txt}
        hint = {401: "invalid client credentials or wrong cloud base URL",
                403: "API client is missing the required scope"}.get(e.code, "")
        sys.exit(f"HTTP {e.code} on {path} {hint}\n{body_txt}")


def cut(v, n=60):
    s = "-" if v in (None, "") else str(v)
    return s if len(s) <= n else s[: n - 3] + "..."


def table(title, headers, rows, note=""):
    print(f"\n{title}" + (f"  ({note})" if note else ""))
    if not rows:
        print("  No data found")
        return
    rows = [["-" if c in (None, "") else str(c) for c in r] for r in rows]
    w = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    line = "+-" + "-+-".join("-" * x for x in w) + "-+"

    def fmt(r):
        return "| " + " | ".join(c.ljust(w[i]) for i, c in enumerate(r)) + " |"

    print(line)
    print(fmt(headers))
    print(line)
    for r in rows:
        print(fmt(r))
    print(line)


def main():
    cid = os.environ.get("CS_CLIENT_ID") or input("Client ID: ").strip()
    secret = os.environ.get("CS_CLIENT_SECRET") or getpass.getpass("Client Secret: ").strip()
    print("Collecting data (read-only) ...")

    token = call("POST", "/oauth2/token", form={"client_id": cid, "client_secret": secret})["access_token"]

    def ids(fql, limit=LIMIT):
        return call("GET", "/alerts/queries/alerts/v2", token,
                    params={"filter": fql, "limit": limit, "sort": "timestamp.desc"})

    def count(fql):
        return ids(fql, 1)["meta"]["pagination"]["total"]

    def entities(id_list):
        if not id_list:
            return []
        res = call("POST", "/alerts/entities/alerts/v2", token, body={"composite_ids": id_list})["resources"]
        return sorted(res, key=lambda a: a.get("timestamp", ""), reverse=True)

    def since(days):
        return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def resolution(a):
        return next((t.rsplit("/", 1)[-1] for t in a.get("tags", []) if t.startswith("ow/resolution/")), "-")

    def in30(a):
        return "Yes" if a.get("timestamp", "") >= since(30) else "No"

    rows = []
    for name, fql in (("Your OverWatch detections", DETECTIONS), ("Your leads investigated", LEADS)):
        rows.append([name, fql] + [count(f"{fql}+timestamp:>='{since(d)}'") for d in (1, 30)] + [count(fql)])
    table("1) Summary", ["Dashboard box", "API filter", "24h", "30 days", "All time"], rows)

    f30 = f"{LEADS}+timestamp:>='{since(30)}'"
    kinds = {k: count(f30 + "+tags:'ow/resolution/" + k + "'") for k in ("malicious", "testing", "benign")}
    rows = [[k.capitalize(), n] for k, n in kinds.items()] + [["Total (30 days)", count(f30)]]
    table("2) Leads investigated by resolution", ["Resolution", "Count"], rows)

    leads = entities(ids(LEADS)["resources"])
    rows = [[a.get("timestamp"), in30(a), cut(a.get("host_name"), 18), a.get("operating_system"),
             resolution(a), a.get("status"), cut(a.get("command_line"), 70)] for a in leads]
    table("3) Latest leads", ["Event time (UTC)", "30d", "Host", "OS", "Resolution", "Status", "Command line"],
          rows, f"up to {LIMIT}")

    dets = entities(ids(DETECTIONS)["resources"])
    rows = [[a.get("timestamp"), in30(a), a.get("severity_name", a.get("severity")), a.get("tactic"),
             a.get("technique"), cut(a.get("name"), 36), a.get("status"), cut(a.get("host_name"), 18)] for a in dets]
    table("4) Latest OverWatch detections (all time)",
          ["Event time (UTC)", "30d", "Severity", "Tactic", "Technique", "Name", "Status", "Host"],
          rows, f"up to {LIMIT}")

    for n, field in enumerate(("tactic", "product", "type"), start=5):
        spec = [{"name": field, "type": "terms", "field": field, "size": 50,
                 "filter": f"timestamp:>='{since(30)}'"}]
        r = call("POST", "/alerts/aggregates/alerts/v2", token, body=spec, soft=True)
        if "_http" in r:
            print(f"\n{n}) All alerts, last 30 days, by {field}: unavailable ({cut(r['_body'], 200)})")
            continue
        buckets = r["resources"][0].get("buckets", []) if r.get("resources") else []
        table(f"{n}) All alerts, last 30 days, by {field}", [field.capitalize(), "Count"],
              [[b["label"], b["count"]] for b in sorted(buckets, key=lambda b: -b["count"])])

    table("8) API call log", ["#", "Method", "Path", "HTTP", "Trace ID"],
          [[i, m, p, s, t] for i, (m, p, s, t) in enumerate(LOG, 1)], f"cloud: {BASE}")
    errors = sum(1 for _, _, s, _ in LOG if s >= 400)
    print(f"\n{len(LOG)} API calls, {errors} errors")


if __name__ == "__main__":
    main()
