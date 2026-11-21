import { StaleStamp } from "@/components/shared/stale-stamp";
import { TierBadge } from "@/components/shared/tier-badge";
import { useTranslations } from "@/i18n";
import { SEVERITIES, SEVERITY_COLOR } from "@/lib/chart";
import { cn } from "@/utils";
import { BarChartIcon, ListIcon } from "@/icons";
import { Link } from "react-router";
import { NUM, useFmt } from "./parts";
import { Tile } from "./tile";
import type { SummaryV2 } from "./types";

const HATCH = "repeating-linear-gradient(45deg, rgba(0,0,0,.18) 0 1.5px, transparent 1.5px 5px)";
const TIER_COLOR = { P1: "var(--color-brand-700)", P2: "var(--color-brand-400)", P3: "var(--color-brand-200)" } as const;

/** Block D: exposure by tier. The exact Falcon total, the part we hold in detail (solid) and the part Falcon only counts (hatched), in words too. */
export function Tiers({ data, stale }: { data: SummaryV2; stale: boolean }) {
  const t = useTranslations("ovw.d");
  const f = useFmt();
  const tiers = data.tiers;
  if (!tiers) return null;
  const ft = tiers.falconTotal ?? 0;
  return (
    <Tile title={t("title")} note={t("note", { total: f.n(ft) })} icon={ListIcon} actions={stale ? <StaleStamp /> : undefined}>
      <div className="space-y-2">
        {(["P1", "P2", "P3"] as const).map((k) => {
          const r = tiers[k];
          const total = Math.max(r.total, r.held); // Falcon's count can lag what we hold: never show "held" above the total
          return (
            <Link key={k} to={`/vulnerabilities?tier=${k}`} className="block rounded-lg px-1 py-0.5 hover:bg-gray-50 focus-visible:ring-4 focus-visible:ring-brand-500/20 focus-visible:outline-none">
              <span className="flex items-center justify-between gap-2">
                <span className="flex min-w-0 items-center gap-1.5"><TierBadge tier={k} help={false} /><span className="truncate text-xs text-gray-500">{t(`name.${k}`)}</span></span>
                <span className={cn(NUM, "text-sm font-semibold", stale ? "text-gray-500" : "text-gray-900")}>{tiers.atLeast ? "≥ " : ""}{f.n(total)}</span>
              </span>
              <span className="mt-1 flex h-2 overflow-hidden rounded-full border border-gray-200 bg-white" aria-hidden="true">
                <span className="h-full" style={{ width: `${total ? Math.min(100, (r.held / total) * 100) : 0}%`, background: TIER_COLOR[k] }} />
                <span className="h-full flex-1" style={{ backgroundImage: HATCH }} />
              </span>
              <span className="block text-xs leading-4 text-gray-600 tabular-nums">{r.held >= total ? t("heldAll") : r.held <= 0 ? t("countOnly") : t("heldOf", { held: f.n(r.held), total: f.n(total), pct: f.pct(r.held / total) })}</span>
            </Link>
          );
        })}
      </div>
      <p className="mt-auto pt-2 text-xs leading-4 text-gray-500">
        <span className="me-3 inline-flex items-center gap-1"><span className="size-2 rounded-sm bg-brand-700" aria-hidden="true" />{t("legendHeld")}</span>
        <span className="inline-flex items-center gap-1"><span className="size-2 rounded-sm border border-gray-400" style={{ backgroundImage: "repeating-linear-gradient(45deg, rgba(0,0,0,.35) 0 1px, transparent 1px 3px)" }} aria-hidden="true" />{t("legendCount")}</span>
        {ft > 0 && <span className="mt-0.5 block tabular-nums">{t("total", { held: f.n(Math.min(tiers.heldTotal, ft)), total: f.n(ft), pct: f.pct(Math.min(1, tiers.heldTotal / ft)) })}</span>}
      </p>
    </Tile>
  );
}

/** Block E: severity, exact Falcon counts, one bar per level, fixed colours. */
export function Severity({ data, stale }: { data: SummaryV2; stale: boolean }) {
  const t = useTranslations("ovw.e");
  const ts = useTranslations("severity");
  const f = useFmt();
  const s = data.severity;
  if (!s) return null;
  const total = s.total || SEVERITIES.reduce((a, k) => a + (s[k] ?? 0), 0);
  const max = Math.max(1, ...SEVERITIES.map((k) => s[k] ?? 0));
  return (
    <Tile title={t("title")} note={t(s.source === "falcon" ? "noteFalcon" : "noteHeld")} icon={BarChartIcon} actions={stale ? <StaleStamp /> : undefined}>
      <ul className="space-y-1">
        {SEVERITIES.map((k) => {
          const v = s[k] ?? 0, held = s.held?.[k];
          return (
            <li key={k}>
              <Link to={`/vulnerabilities?severity=${k}`} className="grid grid-cols-[6.25rem_minmax(0,1fr)_auto] items-center gap-2 rounded px-1 text-sm leading-6 hover:bg-gray-50 focus-visible:ring-4 focus-visible:ring-brand-500/20 focus-visible:outline-none">
                <span className="flex items-center gap-1.5 text-gray-700"><span className="h-0.5 w-3" style={{ background: SEVERITY_COLOR[k] }} aria-hidden="true" />{ts(k)}</span>
                <span className="h-2 rounded-full bg-gray-100" aria-hidden="true"><span className="block h-full rounded-full" style={{ width: `${Math.max(v ? 2 : 0, (v / max) * 100)}%`, background: stale ? "#98A2B3" : SEVERITY_COLOR[k] }} /></span>
                <span className={cn(NUM, "font-medium", stale ? "text-gray-500" : "text-gray-900")}>{f.cell(v)}</span>
              </Link>
              {held != null && v > 0 && <span className="block ps-[7rem] text-xs leading-4 text-gray-500 tabular-nums">{held >= v ? t("heldAll") : held > 0 ? t("heldOf", { held: f.n(held), total: f.n(v) }) : t("countOnly")}</span>}
            </li>
          );
        })}
      </ul>
      <p className="mt-auto pt-2 text-xs leading-4 text-gray-500 tabular-nums">{SEVERITIES.filter((k) => total && s[k]).map((k) => f.pct((s[k] ?? 0) / total)).join(" · ")}</p>
    </Tile>
  );
}
