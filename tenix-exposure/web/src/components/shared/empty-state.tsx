import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useTranslations } from "@/i18n";
import type { ApiError } from "@/lib/api";
import type { ReactNode } from "react";

/** `art` is an optional illustration from shared/illustrations.tsx, drawn small above the text. */
export function EmptyState({ title, children, art }: { title?: string; children?: ReactNode; art?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-8 text-center">
      {art && <div className="mb-2">{art}</div>}
      {title && <h4 className="mb-1 text-base font-medium text-gray-800 dark:text-white/90">{title}</h4>}
      {children && <p className="max-w-md text-sm text-gray-500 dark:text-gray-400">{children}</p>}
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: ApiError; onRetry?: () => void }) {
  const t = useTranslations("errors");
  const tc = useTranslations("common");
  const msg = error.status === 0 ? t("network") : error.status === 403 ? t("forbidden") : t("loadFailed");
  return (
    <div className="flex flex-col items-center gap-3 px-6 py-8 text-center">
      <p className="max-w-md text-sm text-gray-500 dark:text-gray-400">{msg}</p>
      {onRetry && (
        <Button variant="outline" size="sm" onClick={onRetry}>
          {tc("retry")}
        </Button>
      )}
    </div>
  );
}

export function TableSkeleton({ rows = 6 }: { rows?: number }) {
  return (
    <div className="space-y-3 px-1 py-4" aria-hidden="true">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-10 w-full" />
      ))}
    </div>
  );
}
