import { ErrorState } from "@/components/shared/empty-state";
import { FormSkeleton } from "@/components/shared/skeletons";
import { Button } from "@/components/ui/button";
import { useApi } from "@/hooks/use-api";
import { useLocale, useTranslations } from "@/i18n";
import { api, ApiError } from "@/lib/api";
import { SEVERITIES, SEVERITY_COLOR } from "@/lib/chart";
import { useRemaining, type Retention } from "@/lib/retention";
import { cn } from "@/utils";
import { formatDateTime, formatMetric, formatNumber } from "@/utils/format";
import { useEffect, useState } from "react";

/** Falcon's exact counts per severity and what we hold: both come from the Overview summary (the retention answer only has totals). */
interface Summary { severity?: Record<string, number>; completeness?: { falconCounts?: { total: number; critical: number; high: number; medium: number; low: number } | null } }

export const RETENTION_CHANGED = "tenix:retention-changed";

/** Per-organization data retention (spec 2.6b): one row per severity (Falcon total, held, tick, pending purge), 3-day grace, undo. Un-ticking only asks for confirmation; nothing is deleted before the grace ends. */
export function RetentionPanel({ tenantId, canEdit, onClose }: { tenantId: string; canEdit: boolean; onClose: () => void }) {
  const t = useTranslations("retention");
  const tSev = useTranslations("severity");
  const locale = useLocale();
  const remaining = useRemaining();
  const id = encodeURIComponent(tenantId);
  const { data, error, reload } = useApi<Retention>(`/api/tenants/${id}/retention`);
  const sum = useApi<Summary>(`/api/exposure/summary?days=7&tenantId=${id}`);
  const [draft, setDraft] = useState<string[] | null>(null);
  const [confirm, setConfirm] = useState(false);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => { const i = window.setInterval(() => setNow(Date.now()), 60_000); return () => window.clearInterval(i); }, []);

  if (error) return error.status === 404 ? <p className="text-sm text-gray-500" data-testid="retention-unavailable">{t("unavailable")}</p> : <ErrorState error={error} onRetry={reload} />;
  if (!data) return <FormSkeleton fields={5} />;

  const keep = draft ?? data.keep;
  const pendingBy = new Map(data.pending.map((p) => [p.severity, p.purgeAt]));
  // ticked in the saved list, unticked in the draft
  const newly = SEVERITIES.filter((s) => data.keep.includes(s) && !keep.includes(s));
  const dirty = draft !== null && (draft.length !== data.keep.length || draft.some((s) => !data.keep.includes(s)));
  const fc = sum.data?.completeness?.falconCounts ?? null;
  const falcon = (s: string): number | null => {
    if (!fc) return null;
    return s === "NONE" ? Math.max(0, fc.total - fc.critical - fc.high - fc.medium - fc.low) : (fc[s.toLowerCase() as "critical"] ?? null);
  };
  const held = (s: string): number | null => (sum.data?.severity ? (sum.data.severity[s] ?? 0) : null);
  const cov = data.coverage;
  const sliced = cov && cov.falconTotal != null && cov.held < cov.falconTotal;
  const num = (v: number | null) => {
    if (v === null) return <span className="text-gray-400">–</span>;
    const m = formatMetric(v, locale, "cell");
    return <span title={m.compact ? formatNumber(v, locale) : undefined}>{m.text}</span>;
  };

  const toggle = (s: string) => { setMsg(null); setConfirm(false); setDraft(SEVERITIES.filter((x) => (x === s ? !keep.includes(s) : keep.includes(x)))); };
  const put = async (list: string[]) => {
    setSaving(true); setMsg(null);
    try {
      await api.put<Retention>(`/api/tenants/${id}/retention`, { keep: list });
      setDraft(null); setConfirm(false); reload(); window.dispatchEvent(new Event(RETENTION_CHANGED));
      setMsg({ ok: true, text: t("saved") });
    } catch (e) {
      const code = e instanceof ApiError ? e.code : null;
      setMsg({ ok: false, text: e instanceof ApiError && e.status === 0 ? t("error.network") : code === "keep_empty" || code === "invalid_severity" ? t(`error.${code}`) : t("error.generic") });
      setConfirm(false);
    }
    setSaving(false);
  };
  const onSave = () => { if (newly.length) setConfirm(true); else void put(keep); };
  const earliest = Date.now() + data.graceDays * 86_400_000;
  const levels = newly.map((s) => tSev(s)).join(", ");

  return (
    <div className="flex min-w-0 flex-col gap-3" data-testid="retention-panel">
      <p className="flex items-start gap-2 rounded-xl border border-sky-200 bg-sky-50 p-3 text-sm leading-6 text-sky-900">
        <span>{sliced ? t("sliced", { total: formatNumber(cov!.falconTotal!, locale), held: formatNumber(cov!.held, locale) }) : t("info", { days: data.graceDays })}</span>
      </p>
      {sliced && <p className="text-xs text-gray-500">{t("info", { days: data.graceDays })}</p>}

      <fieldset className="rounded-xl border border-gray-200 p-3">
        <legend className="px-1 text-sm font-semibold text-gray-800">{t("table.level")}</legend>
        <table className="w-full">
          <thead>
            <tr className="text-xs font-medium text-gray-500"><th className="w-8 py-1 text-start" /><th className="py-1 text-start">{t("table.level")}</th><th className="py-1 ps-2 text-end">{t("table.falcon")}</th><th className="py-1 ps-2 text-end">{t("table.held")}</th></tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {SEVERITIES.map((s) => {
              const purgeAt = pendingBy.get(s);
              const on = keep.includes(s);
              const rebuilding = data.rebuilding.includes(s);
              return (
                <tr key={s} data-testid={`retention-row-${s}`}>
                  <td className="py-2 align-top">
                    <input type="checkbox" className="size-5 accent-brand-500" checked={on} disabled={!canEdit} onChange={() => toggle(s)} aria-label={t("table.keep", { level: tSev(s) })} data-testid={`retention-keep-${s}`} />
                  </td>
                  <td className="py-2 align-top">
                    <span className="flex items-center gap-2 text-sm text-gray-800"><span className="h-0.5 w-3 rounded" style={{ backgroundColor: SEVERITY_COLOR[s as keyof typeof SEVERITY_COLOR] }} aria-hidden="true" />{tSev(s)}</span>
                    {purgeAt && !on ? (
                      <span className="mt-0.5 block text-xs font-medium text-red-700" data-testid={`retention-pending-${s}`}>
                        {t("state.pending", { time: remaining(purgeAt, now) })} {t("state.pendingAt", { date: formatDateTime(purgeAt, locale) ?? "" })}
                        {canEdit && <button type="button" className="ms-1.5 font-medium text-brand-600 underline hover:text-brand-700" onClick={() => void put([...new Set([...data.keep, s])])} disabled={saving}>{t("state.undo")}</button>}
                      </span>
                    ) : !on && !data.keep.includes(s) ? <span className="mt-0.5 block text-xs text-gray-500">{t("state.counting")}</span>
                      : rebuilding && on ? <span className="mt-0.5 block text-xs text-sky-700">{t("state.rebuilding")}</span> : null}
                  </td>
                  <td className="py-2 ps-2 text-end align-top text-sm text-gray-700 tabular-nums">{num(falcon(s))}</td>
                  <td className="py-2 ps-2 text-end align-top text-sm text-gray-700 tabular-nums">{num(held(s))}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        <p className="mt-2 border-t border-gray-100 pt-2 text-xs text-gray-500">{t("p1Note")}</p>
      </fieldset>

      <div className="rounded-xl border border-amber-200 bg-amber-50 p-3 text-sm leading-6 text-amber-900">
        <p className="font-semibold">{t("grace.title")}</p>
        <p>{t("grace.body", { days: data.graceDays })}</p>
      </div>

      {draft !== null && draft.length === 0 && <p role="alert" className="text-sm font-medium text-red-700">{t("keepOne")}</p>}
      {confirm && (
        <div role="alertdialog" aria-label={t("confirm.title", { levels })} className="rounded-xl border border-red-200 bg-red-50 p-3 text-sm leading-6 text-red-900" data-testid="retention-confirm">
          <p className="font-semibold">{t("confirm.title", { levels })}</p>
          <p>{t("confirm.body", { levels, days: data.graceDays, date: formatDateTime(earliest, locale) ?? "" })}</p>
          <div className="mt-2 flex gap-2">
            <Button size="sm" variant="destructive" disabled={saving} onClick={() => void put(keep)} data-testid="retention-confirm-yes">{t("confirm.yes")}</Button>
            <Button size="sm" variant="outline" disabled={saving} onClick={() => setConfirm(false)}>{t("confirm.no")}</Button>
          </div>
        </div>
      )}

      <div className="sticky -bottom-4 -mx-4 mt-1 flex flex-wrap items-center justify-end gap-2 border-t border-gray-200 bg-white px-4 py-2.5">
        {msg && <p role="status" className={cn("me-auto text-sm", msg.ok ? "text-green-700" : "text-red-700")} data-testid="retention-msg">{msg.text}</p>}
        <Button variant="outline" size="sm" onClick={onClose}>{t("close")}</Button>
        {canEdit && <Button size="sm" disabled={saving || !dirty || keep.length === 0 || confirm} onClick={onSave} data-testid="retention-save">{t("save")}</Button>}
      </div>
    </div>
  );
}
