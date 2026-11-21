// HTML bar list: replaces Apex horizontal bars so value labels never clip.
// <BarList rows={[{ key: "CVE-1", label: "CVE-1", value: 12, color: "#F04438", onClick: () => open("CVE-1") }]} />
// Stacked (e.g. Source by severity): segments are proportional to the row total, the bar to value/max.
// <BarList rows={[{ key: "ep", label: "Endpoint", value: 30, segments: [{ color: "#F04438", value: 10, label: "Critical" }, ...] }]} />
import * as React from "react";
import { Link } from "react-router";

import { cn } from "@/utils";

export type BarSegment = { color: string; value: number; label: string };
export type BarRow = {
  key: string;
  label: React.ReactNode;
  value: number;
  color?: string;
  segments?: BarSegment[];
  onClick?: () => void;
  href?: string;
  hint?: string; // tooltip (title) of the row
};

const ROW = "grid w-full grid-cols-[minmax(0,9rem)_minmax(0,1fr)_3rem] items-center gap-2 py-1 text-start";
const INTERACTIVE =
  "rounded-md hover:bg-gray-50 focus-visible:outline-none focus-visible:ring-4 focus-visible:ring-brand-500/20";

export function BarList({
  rows,
  max,
  format = (n: number) => n.toLocaleString(),
  emptyText,
  className,
}: {
  rows: BarRow[];
  max?: number;
  format?: (n: number) => string;
  emptyText?: string;
  className?: string;
}) {
  if (rows.length === 0) return emptyText ? <p className="py-2 text-sm text-gray-500">{emptyText}</p> : null;
  const top = max ?? Math.max(0, ...rows.map((r) => r.value));
  return (
    <div role="list" className={className}>
      {rows.map((r) => {
        const pct = r.value > 0 && top > 0 ? Math.min(100, Math.max(2, (r.value / top) * 100)) : 0;
        const text = typeof r.label === "string" ? r.label : r.hint ?? r.key;
        const total = r.segments?.reduce((s, x) => s + x.value, 0) ?? 0;
        const inner = (
          <>
            <span className="min-w-0 truncate text-sm leading-6 text-gray-700" title={typeof r.label === "string" ? r.label : undefined}>
              {r.label}
            </span>
            <span
              role="img"
              aria-label={`${text}: ${format(r.value)}`}
              className="flex h-2 overflow-hidden rounded-full bg-gray-100"
            >
              <span className="flex h-full overflow-hidden rounded-full" style={{ width: `${pct}%`, backgroundColor: r.segments ? undefined : r.color ?? "#465FFF" }}>
                {r.segments?.map((s) =>
                  s.value > 0 && total > 0 ? (
                    <span key={s.label} className="h-full" title={`${s.label}: ${format(s.value)}`} style={{ width: `${(s.value / total) * 100}%`, backgroundColor: s.color }} />
                  ) : null,
                )}
              </span>
            </span>
            <span className="text-end text-sm font-medium tabular-nums text-gray-800">{format(r.value)}</span>
          </>
        );
        const cls = cn(ROW, (r.onClick || r.href) && INTERACTIVE);
        return (
          <div role="listitem" key={r.key}>
            {r.onClick ? (
              <button type="button" className={cn(cls, "cursor-pointer")} title={r.hint} onClick={r.onClick}>
                {inner}
              </button>
            ) : r.href ? (
              <Link to={r.href} className={cls} title={r.hint}>
                {inner}
              </Link>
            ) : (
              <div className={cls} title={r.hint}>
                {inner}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
