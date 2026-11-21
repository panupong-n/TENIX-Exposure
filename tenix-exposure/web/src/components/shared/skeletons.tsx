import { Skeleton } from "@/components/ui/skeleton";
import { TableSkeleton } from "./empty-state";

export { TableSkeleton };

const card = "rounded-xl border border-gray-200 bg-white p-3 sm:p-4 dark:border-gray-800 dark:bg-white/3";

/** The building blocks every page uses while its data loads. A new page must use one of these (see scripts/check-skeletons.mjs). */
export function StatCardsSkeleton({ count = 4 }: { count?: number }) {
  return (
    <div className="grid grid-cols-2 gap-3 xl:grid-cols-4" aria-hidden="true">
      {Array.from({ length: count }, (_, i) => <Skeleton key={i} className="h-24 rounded-xl" />)}
    </div>
  );
}

export function ChartCardSkeleton({ className = "h-64" }: { className?: string }) {
  return (
    <div className={card} aria-hidden="true">
      <Skeleton className="h-4 w-40" />
      <Skeleton className="mt-2 h-3 w-56" />
      <Skeleton className={`mt-4 w-full ${className}`} />
    </div>
  );
}

/** The graph page while it loads: the canvas (title, two columns of nodes joined by bands) and the side list next to it, as the real page is laid out. */
export function GraphSkeleton() {
  return (
    <div className="grid items-start gap-3 lg:grid-cols-[minmax(0,1fr)_340px]" aria-hidden="true">
      <div className={`${card} min-w-0 p-3`}>
        <Skeleton className="h-4 w-44" />
        <Skeleton className="mt-1.5 h-3 w-64 max-w-full" />
        <div className="mt-4 grid grid-cols-[minmax(0,1fr)_3rem_minmax(0,1fr)] gap-x-2 sm:grid-cols-[minmax(0,1fr)_6rem_minmax(0,1fr)]">
          <div className="space-y-2">{[9, 8, 7, 6, 5, 4, 4, 3].map((w, i) => <Skeleton key={i} className="h-6 rounded-md" style={{ width: `${40 + w * 6}%` }} />)}</div>
          <div className="space-y-2">{[1, 2, 3, 4, 5, 6, 7, 8].map((i) => <Skeleton key={i} className="h-6 w-full rounded-full opacity-60" />)}</div>
          <div className="space-y-2">{[5, 7, 4, 6, 3, 5, 4, 3].map((w, i) => <Skeleton key={i} className="h-6 rounded-md" style={{ width: `${40 + w * 8}%` }} />)}</div>
        </div>
      </div>
      <div className={`${card} hidden space-y-2 p-3 lg:block`}>
        <Skeleton className="h-4 w-32" />
        {Array.from({ length: 8 }, (_, i) => (
          <div key={i} className="flex items-center gap-2"><Skeleton className="h-8 flex-1 rounded-md" /><Skeleton className="h-4 w-10" /></div>
        ))}
      </div>
    </div>
  );
}

export function FormSkeleton({ fields = 4 }: { fields?: number }) {
  return (
    <div className={`${card} space-y-4`} aria-hidden="true">
      {Array.from({ length: fields }, (_, i) => (
        <div key={i} className="space-y-1.5">
          <Skeleton className="h-3 w-24" />
          <Skeleton className="h-9 w-full max-w-md" />
        </div>
      ))}
    </div>
  );
}

/** Generic full-page placeholder: heading, a row of cards and a table. Used while the signed-in area boots. */
export function PageSkeleton() {
  return (
    <div className="space-y-3" aria-busy="true" aria-label="Loading">
      <Skeleton className="h-6 w-48" />
      <StatCardsSkeleton />
      <div className={card}><TableSkeleton rows={5} /></div>
    </div>
  );
}
