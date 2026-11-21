import { useTranslations } from "@/i18n";
import { cn } from "@/utils";

export type ReasonKey = "kev" | "exprt" | "exploited" | "internet" | "critical" | "overdue";
const ORDER: ReasonKey[] = ["kev", "overdue", "exploited", "exprt", "internet", "critical"];
const STYLE: Record<ReasonKey, string> = {
  kev: "bg-red-50 text-red-700",
  overdue: "bg-red-50 text-red-700",
  exploited: "bg-gray-100 text-gray-700",
  exprt: "bg-gray-100 text-gray-700",
  internet: "bg-sky-50 text-sky-700",
  critical: "bg-gray-100 text-gray-700",
};

/** Why a row is where it is: KEV, ExPRT, exploited, internet-facing, critical asset, CISA overdue. Every chip says it in words; `max` folds the rest into "+N". */
export function ReasonChips({ reasons, max, className }: { reasons: readonly ReasonKey[]; max?: number; className?: string }) {
  const t = useTranslations("foundation.reasons");
  const list = ORDER.filter((r) => reasons.includes(r));
  const shown = max == null ? list : list.slice(0, max);
  const rest = list.length - shown.length;
  if (list.length === 0) return null;
  return (
    <span className={cn("inline-flex flex-wrap items-center gap-1", className)}>
      {shown.map((r) => <span key={r} className={cn("inline-flex max-w-full items-center rounded-md px-1.5 text-xs leading-5 font-medium whitespace-nowrap", STYLE[r])}>{t(r)}</span>)}
      {rest > 0 && <span className="inline-flex items-center rounded-md bg-gray-100 px-1.5 text-xs leading-5 font-medium text-gray-700" title={list.slice(shown.length).map((r) => t(r)).join(", ")}>+{rest}</span>}
    </span>
  );
}
