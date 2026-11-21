import { useTranslations } from "@/i18n";

/** GET/PUT /api/tenants/:id/retention. Every field is read defensively: an older server may not send all of them. */
export interface Retention {
  keep: string[];
  all: string[];
  graceDays: number;
  pending: { severity: string; purgeAt: number }[];
  rebuilding: string[];
  scope?: "all" | string[];
  coverage?: { held: number; falconTotal: number | null; priorityHeld: number; priorityTotal: number | null; priorityPass: boolean; fullPass: boolean; keptTotal: number | null } | null;
}

/** "2 วัน 18 ชม." / "5 ชม. 10 นาที" / "7 นาที": the time until a purge, from a deadline. */
export function useRemaining() {
  const t = useTranslations("retention.time");
  return (purgeAt: number, nowMs = Date.now()) => {
    const min = Math.max(0, Math.floor((purgeAt - nowMs) / 60_000));
    const days = Math.floor(min / 1440), hours = Math.floor((min % 1440) / 60), minutes = min % 60;
    if (days > 0) return t("dh", { days, hours });
    if (hours > 0) return t("hm", { hours, minutes });
    return min > 0 ? t("m", { minutes: min }) : t("soon");
  };
}
