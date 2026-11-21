import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/utils";

export interface Stat {
  key: string;
  label: string;
  value: string;
  /** Fixed severity colour dot before the label. */
  dot?: string;
  /** A stat with onClick is a toggle button (used to filter the list below). */
  onClick?: () => void;
  active?: boolean;
}

const chip = "flex min-w-0 flex-col rounded-lg border px-3 py-1.5 text-start";

/** A compact row of stat chips for a page heading (fills the space beside the title). `null` = still loading: skeleton chips. */
export function PageStats({ items, count = 4 }: { items: Stat[] | null; count?: number }) {
  return (
    <div className="grid w-full grid-cols-2 gap-2 sm:w-auto sm:grid-flow-col sm:auto-cols-fr" aria-busy={items === null}>
      {items === null
        ? Array.from({ length: count }, (_, i) => <Skeleton key={i} className="h-12 w-full rounded-lg sm:w-28" aria-hidden="true" />)
        : items.map((s) => {
            const body = (
              <>
                <span className="flex items-center gap-1.5 text-xs leading-5 text-gray-600">
                  {s.dot && <span className="size-2 shrink-0 rounded-full" style={{ backgroundColor: s.dot }} aria-hidden="true" />}
                  <span className="min-w-0 truncate">{s.label}</span>
                </span>
                <span className="text-base leading-6 font-semibold text-gray-800 tabular-nums">{s.value}</span>
              </>
            );
            return s.onClick ? (
              <button
                key={s.key}
                type="button"
                onClick={s.onClick}
                aria-pressed={s.active}
                className={cn(chip, "transition-colors focus-visible:ring-4 focus-visible:ring-brand-500/20 focus-visible:outline-none", s.active ? "border-brand-500 bg-brand-50" : "border-gray-200 bg-white hover:bg-gray-50")}
              >
                {body}
              </button>
            ) : (
              <div key={s.key} className={cn(chip, "border-gray-200 bg-white")}>{body}</div>
            );
          })}
    </div>
  );
}
