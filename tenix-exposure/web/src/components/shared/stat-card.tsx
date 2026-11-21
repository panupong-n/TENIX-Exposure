import { cn } from "@/utils";
import type { ReactNode, SVGProps } from "react";

/**
 * Big, thin-line, tilted artwork that bleeds off the bottom-right corner of a stat card.
 * Each one is drawn on a 140 x 140 grid with a constant 1.5px stroke, so it stays crisp at any size.
 */
function Art(props: SVGProps<SVGSVGElement>) {
  return (
    <svg
      viewBox="0 0 140 140"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      {...props}
      className={cn("[&_*]:[vector-effect:non-scaling-stroke]", props.className)}
    />
  );
}

export const StatArt = {
  layers: (p: SVGProps<SVGSVGElement>) => (
    <Art {...p}>
      <path d="M70 18 L130 44 L70 70 L10 44 Z" />
      <path d="M10 66 L70 92 L130 66" />
      <path d="M10 88 L70 114 L130 88" />
      <path d="M70 18 V70" opacity="0.5" />
    </Art>
  ),
  alert: (p: SVGProps<SVGSVGElement>) => (
    <Art {...p}>
      <path d="M70 14 L130 118 H10 Z" />
      <path d="M70 52 V86" />
      <circle cx="70" cy="101" r="1.5" />
      <path d="M70 34 L112 108 H28 Z" opacity="0.45" />
    </Art>
  ),
  device: (p: SVGProps<SVGSVGElement>) => (
    <Art {...p}>
      <rect x="12" y="24" width="116" height="76" rx="9" />
      <path d="M48 120 H92 M70 100 V120" />
      <path d="M28 44 H78 M28 58 H62 M28 72 H88" opacity="0.5" />
    </Art>
  ),
  bolt: (p: SVGProps<SVGSVGElement>) => (
    <Art {...p}>
      <circle cx="70" cy="70" r="60" />
      <path d="M80 18 L34 80 H66 L58 124 L108 58 H74 Z" />
    </Art>
  ),
};

interface StatCardProps {
  title: string;
  value: ReactNode;
  /** Small line under the number. */
  note?: ReactNode;
  /** Change over the selected range; green when it fell, red when it rose. */
  delta?: { value: number; label: ReactNode };
  /** Colours the note as a warning. */
  alert?: boolean;
  art: (p: SVGProps<SVGSVGElement>) => ReactNode;
  className?: string;
}

export function StatCard({ title, value, note, alert, delta, art: Art, className }: StatCardProps) {
  return (
    <div
      className={cn(
        "group relative min-h-24 overflow-hidden rounded-xl border border-gray-200 bg-white px-3.5 py-3 transition-colors hover:border-gray-300 dark:border-gray-800 dark:bg-white/3 dark:hover:border-gray-700",
        className,
      )}
    >
      <Art className="pointer-events-none absolute -right-8 -bottom-12 size-32 rotate-[-14deg] text-[#0BA5EC]/40 sm:size-44 sm:text-[#0BA5EC]/55 transition-transform duration-700 ease-out group-hover:rotate-[-9deg] group-hover:scale-105 dark:text-[#0BA5EC]/45 dark:sm:text-[#0BA5EC]/60" />
      <div className="relative">
        <p className="text-sm text-gray-600 dark:text-gray-300">{title}</p>
        <p className="mt-1 text-2xl leading-8 font-semibold text-gray-800 tabular-nums dark:text-white">{value}</p>
        {delta && delta.value !== 0 && (
          <p className={cn("mt-0.5 text-xs font-medium tabular-nums", delta.value > 0 ? "text-red-600 dark:text-red-400" : "text-green-600 dark:text-green-400")}>
            {delta.value > 0 ? "▲" : "▼"} {delta.label}
          </p>
        )}
        {note && <p className={cn("mt-1 text-xs", alert ? "text-red-500 dark:text-red-400" : "text-gray-500 dark:text-gray-400")}>{note}</p>}
      </div>
    </div>
  );
}
