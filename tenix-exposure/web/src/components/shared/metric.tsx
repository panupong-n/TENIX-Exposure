import { MaskReveal } from "@/components/shared/mask-reveal";
import { useCountUp } from "@/hooks/use-count-up";
import { useLocale } from "@/i18n";
import { cn } from "@/utils";
import { formatMetric, formatNumber, type NumberContext } from "@/utils/format";
import type { CSSProperties } from "react";

/** Design size of the digits; the real size shrinks to fit the box (spec 2.5). */
const MAX = { hero: "46px", kpi: "28px", sm: "20px" } as const;
export type MetricSize = keyof typeof MAX;

/** Width of the text in digit units: a comma or dot is about 0.45 of a digit, K/M/B about 0.9. */
const units = (s: string) => s.split("").reduce((n, c) => n + (c === "," || c === "." ? 0.45 : c === "K" || c === "M" || c === "B" ? 0.9 : 1), 0);

/**
 * The one way to show a big number. The box is a size container and the font size is min(max, 100cqi / (chars * 0.64)), so the digits can never be wider
 * than their box, at any magnitude or screen width. From 1M a tile shows 16.7M with the full value under it, in the tooltip and as the accessible name.
 * Put it in a grid of `repeat(auto-fit, minmax(9rem, 1fr))` (utility `metric-grid`, index.css) so tiles wrap instead of squeezing.
 * `reveal` plays the hero's mask animation; otherwise the number counts up. The size comes from the FINAL text, so it never jumps while counting.
 */
export function Metric({ value, size = "kpi", context = "tile", reveal, showFull = true, className, valueClassName }: {
  value: number;
  size?: MetricSize;
  context?: NumberContext;
  reveal?: boolean;
  /** write the full value under a short number (default); turn off where the full value sits right next to it */
  showFull?: boolean;
  className?: string;
  valueClassName?: string;
}) {
  const locale = useLocale();
  const animated = useCountUp(reveal ? 0 : value);
  const final = formatMetric(value, locale, context);
  const full = formatNumber(value, locale);
  const text = reveal ? final.text : formatMetric(animated, locale, context).text;
  const style = { "--max": MAX[size], "--n": Math.max(units(final.text), 2), fontSize: "min(var(--max), calc(100cqi / (var(--n) * 0.64)))" } as CSSProperties;
  const cls = cn("block font-semibold leading-tight tabular-nums whitespace-nowrap", valueClassName);
  return (
    <div data-metric="" className={cn("min-w-0 [container-type:inline-size]", className)} title={final.compact ? full : undefined}>
      {reveal ? (
        <MaskReveal by="all" as="span" label={full} className={cls} style={style}>{text}</MaskReveal>
      ) : (
        <span aria-label={full} className={cls} style={style}>{text}</span>
      )}
      {final.compact && showFull && <span className="block text-xs leading-5 whitespace-nowrap text-gray-500 tabular-nums">{full}</span>}
    </div>
  );
}
