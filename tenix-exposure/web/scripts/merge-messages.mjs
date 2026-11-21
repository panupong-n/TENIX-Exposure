// Merges scripts/messages-en*.json into src/messages/en.json and scripts/messages-th*.json into src/messages/th.json.
// Thai is the interface language, English is the reference text (see src/i18n/routing.ts). Both must be kept in step: npm run lint checks it.
// Usage: node scripts/merge-messages.mjs   (safe to run again)
import fs from "node:fs";
const read = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const merge = (a, b) => {
  for (const k of Object.keys(b)) {
    if (b[k] && typeof b[k] === "object" && !Array.isArray(b[k])) a[k] = merge(a[k] && typeof a[k] === "object" ? a[k] : {}, b[k]);
    else a[k] = b[k];
  }
  return a;
};
const flat = (o, p = "") => Object.entries(o).flatMap(([k, v]) => (v && typeof v === "object" ? flat(v, p + k + ".") : [p + k]));
// every scripts/messages-<lang>*.json is merged (so parallel work can keep its strings in its own file)
for (const lang of ["en", "th"]) {
  const re = new RegExp(`^messages-${lang}.*\\.json$`);
  const add = fs.readdirSync("scripts").filter((f) => re.test(f)).sort().reduce((acc, f) => merge(acc, read(`scripts/${f}`)), {});
  fs.writeFileSync(`src/messages/${lang}.json`, JSON.stringify(merge(read(`src/messages/${lang}.json`), add), null, 2) + "\n");
  console.log(`${lang.toUpperCase()} ${flat(add).length} keys merged`);
}
