import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { useAuth } from "@/contexts/auth-context";
import { useOrg } from "@/contexts/org-context";
import { useLocale, useTranslations } from "@/i18n";
import { AlertIcon, InfoCircleIcon, OctagonAlertIcon } from "@/icons";
import { formatAgo, formatDateTime, formatNumber } from "@/utils/format";
import { Link } from "react-router";

export interface Completeness {
  state: "complete" | "partial" | "failed" | "not_synced" | "no_connection" | "no_cids";
  /** when the numbers were last read COMPLETELY (the server may send it as `asOf`) */
  dataAsOf?: number | null;
  asOf?: number | null;
  lastRunAt: number | null;
  /** why the last read failed (invalid_credentials | cid_not_authorized | missing_scope | unreachable | error) */
  reason?: string | null;
  /** how much of what Falcon counts is held in detail */
  /** `mode` "priority": the fix-first slice is held in full and the rest is counted only (big tenants, by design); absent = the whole tenant is held */
  coverage?: { held: number; falconTotal: number | null; priorityHeld: number; priorityTotal: number | null; fullPass: boolean; mode?: "full" | "priority" } | null;
  /** exact numbers from Falcon, shown on the overview instead of row counts */
  falconCounts?: { total: number; critical: number; high: number; medium: number; low: number; kev: number; exprtCritical: number; exploited: number } | null;
  cids?: { cid: string; state: string; detail: string[] }[];
}

/** The time of the last complete read, from either field name. */
export const completeAsOf = (c: Pick<Completeness, "dataAsOf" | "asOf">) => c.dataAsOf ?? c.asOf ?? null;

/** The numbers on screen are old or missing (the last read failed or there is no connection): show a StaleStamp beside each of them. */
export const isStale = (c: Pick<Completeness, "state"> | null | undefined) => c?.state === "failed" || c?.state === "no_connection" || c?.state === "no_cids";

const REASONS = ["invalid_credentials", "cid_not_authorized", "missing_scope", "unreachable", "error"];

/**
 * How far the numbers on a page can be trusted. A complete sync is one quiet line;
 * anything else is a banner, because "nothing found" only means something after a complete sync.
 * A failed read says the numbers shown are OLD (and from when), never "no data".
 */
export function DataStatus({ completeness, whyHref }: { completeness: Completeness | undefined; /** where the "why" link of the priority-slice line goes */ whyHref?: string }) {
  const t = useTranslations("states");
  const locale = useLocale();
  const { user } = useAuth();
  const { orgId } = useOrg();
  if (!completeness) return null;
  const { state, coverage, falconCounts } = completeness;
  const asOf = completeAsOf(completeness);
  const time = formatDateTime(asOf, locale) ?? t("noCompleteUpdate");

  const n = (v: number) => formatNumber(v, locale);
  const ago = formatAgo(asOf, locale);
  const when = ago ? `${time} · ${ago}` : time;
  const lastRun = user?.soc && completeness.lastRunAt ? formatDateTime(completeness.lastRunAt, locale) : null;

  if (state === "complete") {
    // complete for the priority slice: an info line (blue), not a warning
    const priority = coverage?.mode === "priority" && coverage.falconTotal != null && coverage.falconTotal > 0;
    const pct = (a: number, b: number | null) => (b ? `${Math.min(100, Math.round((a / b) * 1000) / 10)}%` : "100%");
    return (
      <p className={priority ? "flex items-start gap-2 rounded-lg bg-sky-50 px-3 py-1.5 text-sm leading-5 text-sky-800" : "flex items-start gap-2 text-sm leading-5 text-gray-500 dark:text-gray-400"}>
        <span className={priority ? "mt-1.5 size-2 shrink-0 rounded-full bg-sky-500" : "mt-1.5 size-2 shrink-0 rounded-full bg-green-500"} aria-hidden="true" />
        <span className="min-w-0">
          {priority && coverage
            ? t("priority.line", { held: n(Math.min(coverage.held, coverage.falconTotal!)), total: n(coverage.falconTotal!), percent: pct(coverage.held, coverage.falconTotal), priorityPercent: pct(coverage.priorityHeld, coverage.priorityTotal) })
            : t("complete.title")}
          {priority && whyHref && <Link to={whyHref} className="ms-2 font-medium text-brand-600 hover:text-brand-700">{t("priority.why")}</Link>}
          {" · "}{when}
          {lastRun && <span className="ms-1 text-xs">· {t("lastRun", { time: lastRun })}</span>}
        </span>
      </p>
    );
  }
  const variant = state === "partial" ? "warning" : state === "failed" ? "destructive" : "info";
  const Icon = state === "partial" ? AlertIcon : state === "failed" ? OctagonAlertIcon : InfoCircleIcon;
  const soc = !!user?.soc;
  const details = soc ? (completeness.cids ?? []).flatMap((c) => c.detail) : [];
  // customers never see a CID, a connection or Falcon's reason: only that the numbers are old or missing, and who to ask
  const body = state === "failed"
    ? t(asOf ? "failed.bodyOld" : "failed.bodyNone", { time: ago ? `${time} (${ago})` : time })
    : state === "partial" ? t("partial.body", { time }) : t(`${state}.${soc ? "bodySoc" : "body"}`);
  const reason = soc && state === "failed" && completeness.reason && REASONS.includes(completeness.reason) ? t(`reason.${completeness.reason}`) : null;
  return (
    <Alert variant={variant} className="p-4">
      <Icon className="size-5" />
      <AlertTitle>{t(`${state}.title`)}</AlertTitle>
      <AlertDescription>
        {body}
        {reason && <span className="mt-1 block text-xs">{reason}</span>}
        {state === "partial" && coverage && coverage.falconTotal != null && (
          <span className="mt-1 block">{t("coverage", { held: n(Math.min(coverage.held, coverage.falconTotal)), total: n(coverage.falconTotal) })}</span>
        )}
        {state === "partial" && coverage && !coverage.fullPass && (
          <span className="mt-1 block">{t("priorityPending", { held: n(coverage.priorityHeld), total: coverage.priorityTotal == null ? "?" : n(coverage.priorityTotal) })}</span>
        )}
        {falconCounts && state === "partial" && <span className="mt-1 block">{t("exactCounts")}</span>}
        {details.length > 0 && (
          <ul className="mt-2 list-disc ps-5 text-xs">
            {details.slice(0, 5).map((d) => (
              <li key={d}>{d}</li>
            ))}
          </ul>
        )}
        {soc && state !== "partial" && (
          <Link to={orgId ? `/settings?setting=tenants&tenant=${encodeURIComponent(orgId)}&section=falcon` : "/settings?setting=tenants"} className="mt-2 block w-fit text-sm font-medium text-brand-500 hover:text-brand-600 dark:text-brand-400">
            {t("openTenant")}
          </Link>
        )}
      </AlertDescription>
    </Alert>
  );
}

/** The Overview's name for DataStatus: one strip, every state of spec 2.1 (complete, complete for the priority slice, partial, failed, no_connection, not_synced, no_cids). */
export { DataStatus as DataStrip };
