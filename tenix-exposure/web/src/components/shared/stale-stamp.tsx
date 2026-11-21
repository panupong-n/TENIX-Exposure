import { useTranslations } from "@/i18n";
import { cn } from "@/utils";

/** Grey stamp beside a number that is old (the last read failed or there is no connection). `since` is the time of the data, shown as a tooltip. */
export function StaleStamp({ since, className }: { since?: string | null; className?: string }) {
  const t = useTranslations("foundation");
  return (
    <span title={since ?? undefined} className={cn("inline-flex items-center rounded bg-gray-100 px-1.5 text-xs leading-5 font-medium whitespace-nowrap text-gray-600", className)}>
      {t("stale")}
    </span>
  );
}
