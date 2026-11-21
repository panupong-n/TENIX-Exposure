import { Badge } from "@/components/ui/badge";
import { useLocale, useTranslations } from "@/i18n";
import { formatNumber } from "@/utils/format";

export type NewsState = "exact" | "possible" | "wait" | "not_affected";
export const STATES: NewsState[] = ["exact", "possible", "wait", "not_affected"];
const COLOR = { exact: "error", possible: "warning", wait: "info", not_affected: "success" } as const;

export const safeUrl = (u: string) => /^https?:\/\//i.test(u);
export const host = (u: string) => { try { return new URL(u).hostname.replace(/^www\./, ""); } catch { return u; } };

/** The state is always in words ("กระทบ 3 เครื่อง"), never colour alone. */
export function StateBadge({ state, devices }: { state: NewsState; devices?: number }) {
  const t = useTranslations("newsPage.state");
  const locale = useLocale();
  return (
    <Badge variant="light" color={COLOR[state]} size="sm" data-state={state}>
      {state === "exact" && devices !== undefined ? t("exactN", { n: formatNumber(devices, locale) }) : t(state)}
    </Badge>
  );
}

export const head = "py-1.5 pe-4 text-start text-xs font-medium whitespace-nowrap text-gray-500";
export const headEnd = "py-1.5 ps-4 text-end text-xs font-medium whitespace-nowrap text-gray-500";
export const cell = "py-1.5 pe-4 text-sm text-gray-600";
