/** Names in dictionary order, Thai included (Intl.Collator, not code-point order). */
export const nameOrder = new Intl.Collator(["th", "en"], { sensitivity: "base", numeric: true });

/** Thai text, Gregorian years: they match the years in CVE ids and in Falcon. Use "th-TH" alone for Buddhist-era years. */
export const intlLocale = (locale: string) => (locale === "th" ? "th-TH-u-ca-gregory" : locale);

const dateTime = (locale: string) =>
  new Intl.DateTimeFormat(intlLocale(locale), { dateStyle: "medium", timeStyle: "short" });

/** A calendar date without the time (e.g. when a CVE was published). */
export function formatDate(ts: number | null | undefined, locale: string): string | null {
  return ts && !Number.isNaN(ts) ? new Intl.DateTimeFormat(intlLocale(locale), { dateStyle: "medium" }).format(new Date(ts)) : null;
}

export function formatDateTime(ts: number | null | undefined, locale: string): string | null {
  return ts ? dateTime(locale).format(new Date(ts)) : null;
}

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["day", 86_400_000],
  ["hour", 3_600_000],
  ["minute", 60_000],
];

/** "5 minutes ago" in the viewer's language. */
export function formatAgo(ts: number | null | undefined, locale: string): string | null {
  if (!ts) return null;
  const diff = ts - Date.now();
  const rtf = new Intl.RelativeTimeFormat(intlLocale(locale), { numeric: "auto" });
  for (const [unit, ms] of UNITS) {
    if (Math.abs(diff) >= ms) return rtf.format(Math.round(diff / ms), unit);
  }
  return rtf.format(0, "minute");
}

export const formatNumber = (n: number, locale: string) => new Intl.NumberFormat(intlLocale(locale)).format(n);

/**
 * Short number: 999 -> 999, 34,122 -> 34.1K, 858,001 -> 858K, 16,693,578 -> 16.7M. One decimal below 100 of the unit, none from 100; rounding carries
 * to the next unit (999,999 -> 1M, never 1000K); a trailing .0 is dropped. Latin K/M/B on purpose (Falcon's console does the same).
 */
export function formatCompact(value: number): string {
  const sign = value < 0 ? "-" : "";
  let x = Math.abs(value);
  let u = 0;
  while (x >= 1000 && u < 3) { x /= 1000; u++; }
  let r = u === 0 ? Math.round(x) : x < 100 ? Math.round(x * 10) / 10 : Math.round(x);
  if (r >= 1000 && u < 3) { r /= 1000; u++; r = Math.round(r * 10) / 10; }
  return `${sign}${r}${["", "K", "M", "B"][u]}`;
}

/** Where a number is shown decides when it turns short: tiles and the hero from 1M, table cells from 10M, chips and deltas from 10K (spec 2.5). */
export type NumberContext = "tile" | "cell" | "chip";
const COMPACT_FROM: Record<NumberContext, number> = { tile: 1_000_000, cell: 10_000_000, chip: 10_000 };

/** The text for `value` in `context`: full with separators, or short once it passes the context's limit. */
export function formatMetric(value: number, locale: string, context: NumberContext = "tile"): { text: string; compact: boolean } {
  const compact = Math.abs(value) >= COMPACT_FROM[context];
  return { text: compact ? formatCompact(value) : formatNumber(value, locale), compact };
}
