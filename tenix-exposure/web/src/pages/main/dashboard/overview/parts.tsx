import { ErrorState } from "@/components/shared/empty-state";
import { ChartCardSkeleton } from "@/components/shared/skeletons";
import { useLocale, useTranslations } from "@/i18n";
import type { ApiError } from "@/lib/api";
import { formatMetric, formatNumber, intlLocale } from "@/utils/format";
import type { ReactNode } from "react";
import { TILE } from "./tile";

/** Number text for the page: full with separators, compact from 10M in table cells (spec 2.5), "–" when the number is unknown (never 0). */
export function useFmt() {
  const locale = useLocale();
  return {
    locale,
    n: (v: number | null | undefined) => (v == null ? "–" : formatNumber(v, locale)),
    cell: (v: number | null | undefined) => (v == null ? "–" : formatMetric(v, locale, "cell").text),
    pct: (r: number | null | undefined, digits = 1) => (r == null ? "–" : `${Math.round(r * 10 ** (2 + digits)) / 10 ** digits}%`),
  };
}

/** A device's name; one Falcon has no name for reads "Unnamed device" plus the first characters of its id, never the raw 32-character id. */
export function useDeviceName() {
  const t = useTranslations("common");
  return (hostname: string | null | undefined, aid: string) => hostname || `${t("unnamedDevice")} ${aid.slice(0, 6)}`;
}

/** Clock time of a timestamp (14:52), in the interface's number style. */
export const clock = (ts: number, locale: string) => new Date(ts).toLocaleTimeString(intlLocale(locale), { hour: "2-digit", minute: "2-digit", hour12: false });

export const LINK = "font-medium text-brand-600 hover:text-brand-700 focus-visible:ring-4 focus-visible:ring-brand-500/20 focus-visible:outline-none rounded";
export const ROW = "border-t border-gray-100 first:border-t-0";
/** The right-aligned numeric cell: tabular, never wraps. */
export const NUM = "text-end tabular-nums whitespace-nowrap";

/** One block's own load state: a skeleton card while it loads, an error card with retry when it fails, the content when it is there. */
export function Slot<T>({ res, h = "h-40", children }: { res: { data: T | null; error: ApiError | null; reload: () => void }; h?: string; children: (d: T) => ReactNode }) {
  if (res.error && !res.data) return <div className={TILE}><ErrorState error={res.error} onRetry={res.reload} /></div>;
  if (!res.data) return <ChartCardSkeleton className={h} />;
  return <>{children(res.data)}</>;
}

/** A coloured dot for a data state; the words always sit beside it. */
export const DOT: Record<string, string> = { complete: "bg-green-500", partial: "bg-yellow-500", failed: "bg-red-500", no_connection: "bg-red-500", not_synced: "bg-gray-400", no_cids: "bg-gray-400", priority: "bg-sky-500" };

/** A clickable summary tile of the portfolio strip. */
export const TILE_FILTER = "min-w-0 rounded-xl border border-gray-200 bg-white px-3 py-2 text-start hover:bg-gray-50 focus-visible:ring-4 focus-visible:ring-brand-500/20 focus-visible:outline-none";
