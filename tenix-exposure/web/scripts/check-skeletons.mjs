// Fails when a signed-in page can show nothing while it loads. Rule for every page, old and new:
//   1. a file that calls useApi() must render a skeleton (components/shared/skeletons.tsx or ui/skeleton), and
//   2. every page folder routed from src/App.tsx must use a skeleton, or say why none is needed with a comment:
//        // skeleton-ok: <reason>
// Run by `npm run lint`. See the project rules in AGENTS.md.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../src/", import.meta.url));
const app = fs.readFileSync(root + "App.tsx", "utf8");
const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : e.name.endsWith(".tsx") ? [path.join(d, e.name)] : []));
const ok = (src) => /Skeleton/.test(src) || /skeleton-ok:/.test(src);
const problems = [];
const scanned = new Set();

for (const [, rel] of app.matchAll(/from "@\/pages\/([^"]+)"/g)) {
  const asFile = [root + `pages/${rel}.tsx`, root + `pages/${rel}/index.tsx`].find((f) => fs.existsSync(f));
  if (!asFile) continue;
  const isIndex = path.basename(asFile) === "index.tsx";
  const files = isIndex ? walk(path.dirname(asFile)) : [asFile];
  const text = fs.readFileSync(asFile, "utf8");
  const barrel = /^export (\*|\{)/m.test(text) && !/<[A-Za-z]/.test(text); // a barrel only re-exports pages
  files.forEach((f) => scanned.add(f));
  if (!barrel && !files.some((f) => ok(fs.readFileSync(f, "utf8")))) {
    problems.push(`${path.relative(root, asFile)}: this page never shows a skeleton while loading. Use one from components/shared/skeletons.tsx, or add "// skeleton-ok: <reason>" if it loads nothing.`);
  }
}
for (const f of scanned) {
  const src = fs.readFileSync(f, "utf8");
  if (/\buseApi\s*[<(]/.test(src) && !ok(src)) problems.push(`${path.relative(root, f)}: calls useApi() but renders no skeleton while the data loads.`);
}
if (problems.length) {
  console.error("Skeleton rule broken:\n - " + problems.join("\n - "));
  process.exit(1);
}
console.log(`skeleton check: ${scanned.size} page files ok`);
