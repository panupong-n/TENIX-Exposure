// Pure-SVG donut with an HTML legend beside (or below) it, so dot, label and count never overlap.
// <Donut title="IP by perimeter" total="1.5k" caption="IPs" slices={[{ key: "o", label: "Official", value: 10, color: "#465FFF" }]} />
import { NoDataArt } from "@/components/shared/illustrations";
import { useLocale, useTranslations } from "@/i18n";
import { cn } from "@/utils";
import { formatNumber } from "@/utils/format";

export type DonutSlice = { key: string; label: string; value: number; color: string };

const R = 40; // radius in a 100 x 100 viewBox, stroke 14 -> ring from 33 to 47
const C = 2 * Math.PI * R;

export function Donut({ slices, title, total, caption, size = 120, className }: {
  slices: DonutSlice[];
  /** Accessible name prefix (usually the tile title). */
  title: string;
  /** Centre text; defaults to the sum of the slices. */
  total?: string;
  /** Small text under the centre number. */
  caption?: string;
  size?: number;
  className?: string;
}) {
  const t = useTranslations("easm");
  const locale = useLocale();
  const shown = slices.filter((s) => s.value > 0);
  const sum = shown.reduce((a, s) => a + s.value, 0);
  if (sum === 0) {
    return (
      <div className={cn("flex flex-col items-center justify-center gap-1 py-4", className)}>
        <NoDataArt className="h-20 w-28" />
        <p className="text-sm leading-6 text-gray-500">{t("noData")}</p>
      </div>
    );
  }
  const pct = (v: number) => (v / sum > 0 && v / sum < 0.01 ? "<1%" : `${Math.round((v / sum) * 100)}%`);
  const gap = shown.length > 1 ? 1.2 : 0; // small visual gap between slices
  const arcs = shown.map((s, i) => {
    const before = shown.slice(0, i).reduce((x, y) => x + y.value, 0);
    return { s, dash: Math.max(0, (s.value / sum) * C - gap), at: (before / sum) * C };
  });
  const label = `${title}: ${shown.map((s) => `${s.label} ${formatNumber(s.value, locale)} (${pct(s.value)})`).join(", ")}`;
  return (
    <div className={cn("flex flex-wrap items-center gap-x-4 gap-y-3", className)}>
      <div className="relative shrink-0" style={{ width: size, height: size }}>
        <svg viewBox="0 0 100 100" width={size} height={size} role="img" aria-label={label} focusable="false">
          <circle cx="50" cy="50" r={R} fill="none" stroke="#F2F4F7" strokeWidth="14" />
          <g transform="rotate(-90 50 50)">
            {arcs.map(({ s, dash, at }) => (
              <circle key={s.key} cx="50" cy="50" r={R} fill="none" stroke={s.color} strokeWidth="14" strokeDasharray={`${dash} ${C - dash}`} strokeDashoffset={-at} />
            ))}
          </g>
        </svg>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center px-5 text-center" aria-hidden="true">
          <span className="text-lg leading-6 font-semibold text-gray-800 tabular-nums">{total ?? formatNumber(sum, locale)}</span>
          {caption && <span className="max-w-full truncate text-xs leading-4 text-gray-500">{caption}</span>}
        </div>
      </div>
      <ul className="min-w-40 flex-1 space-y-1">
        {shown.map((s) => (
          <li key={s.key} className="flex items-center gap-2">
            <span aria-hidden="true" className="size-2.5 shrink-0 rounded-full" style={{ backgroundColor: s.color }} />
            <span className="min-w-0 flex-1 text-sm leading-6 break-words text-gray-700">{s.label}</span>
            <span className="shrink-0 text-sm leading-6 font-medium text-gray-800 tabular-nums">{formatNumber(s.value, locale)}</span>
            <span className="w-10 shrink-0 text-end text-xs leading-6 text-gray-500 tabular-nums">{pct(s.value)}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
