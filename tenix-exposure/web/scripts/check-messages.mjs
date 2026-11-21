// Fails when a string the live pages use has no Thai text, or when the Thai text uses different {placeholders} than the English.
// Template pages that are switched off are not checked. Add a namespace to LIVE when a new page uses one.
import fs from "node:fs";
const read = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const en = read("src/messages/en.json"), th = read("src/messages/th.json");
const LIVE = ["common", "severity", "header", "tenants", "tenants2", "team", "roles", "overview", "graph", "graphView", "software", "integrations", "devices", "auth", "account", "vulns", "userDropdown", "tenantsGrid", "states", "filters", "exploit", "executive", "errors", "drawer", "cve", "app", "audit", "settings", "easm", "foundation", "news", "lists2", "watch", "ovw", "retention", "notifyPrefs", "settingsLinks", "newsPage", "easmAssets"];
const NAV = ["overview", "exposure", "external", "news", "settings", "vulnerabilities", "devices", "graph", "software", "integrations", "tenants", "team", "auditLog"];
const flat = (o, p = "") => Object.entries(o).flatMap(([k, v]) => (v && typeof v === "object" ? flat(v, `${p}${k}.`) : [[`${p}${k}`, String(v)]]));
const args = (s) => [...new Set([...s.matchAll(/\{(\w+)\s*[,}]/g)].map((m) => m[1]))].sort().join(",");
const thMap = new Map(flat(th));
const problems = [];
for (const [key, value] of flat(en)) {
  const top = key.split(".")[0];
  const live = LIVE.includes(top) || (key.startsWith("sidebar.items.") && NAV.includes(key.split(".")[2]));
  if (!live) continue;
  const t = thMap.get(key);
  if (t === undefined) problems.push(`missing in th: ${key}`);
  else if (args(t) !== args(value)) problems.push(`placeholders differ in ${key}: en {${args(value)}} th {${args(t)}}`);
}
if (problems.length) { console.error(`message check failed (${problems.length}):\n  ${problems.slice(0, 40).join("\n  ")}`); process.exit(1); }
console.log("message check: every live string has Thai text with matching placeholders");
