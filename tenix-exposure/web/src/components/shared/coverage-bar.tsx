import { useLocale, useTranslations } from "@/i18n";
import { cn } from "@/utils";
import { formatNumber } from "@/utils/format";

/** The part that is not held: diagonal hatching reads without colour too. */
const HATCH = "repeating-linear-gradient(45deg, rgba(0,0,0,.18) 0 1.5px, transparent 1.5px 5px)";

/** How much of `total` is held in detail: solid for the held part, hatched for what Falcon only counts. The words are always there (the bar is decoration). */
export function CoverageBar({ held, total, color = "var(--color-brand-700)", className }: { held: number; total: number | null | undefined; color?: string; className?: string }) {
  const t = useTranslations("foundation.coverage");
  const locale = useLocale();
  const share = total ? Math.min(1, Math.max(0, held / total)) : held > 0 ? 1 : 0;
  const pct = Math.round(share * 1000) / 10;
  const text = share >= 1 ? t("full") : held <= 0 ? t("countOnly") : t("part", { percent: String(pct), held: formatNumber(held, locale) });
  return (
    <span className={cn("block", className)}>
      <span className="flex h-2 overflow-hidden rounded-full border border-gray-200 bg-white" aria-hidden="true">
        <span className="h-full" style={{ width: `${pct}%`, background: color }} />
        <span className="h-full flex-1" style={{ backgroundImage: HATCH }} />
      </span>
      <span className="mt-0.5 block text-xs leading-5 text-gray-600 tabular-nums">{text}</span>
    </span>
  );
}
