import { ErrorState } from "@/components/shared/empty-state";
import { FormSkeleton } from "@/components/shared/skeletons";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { useApi } from "@/hooks/use-api";
import { useTranslations } from "@/i18n";
import { api, ApiError } from "@/lib/api";
import { SEVERITIES, SEVERITY_COLOR } from "@/lib/chart";
import { cn } from "@/utils";
import { useEffect, useRef, useState } from "react";
import { FlexMessage } from "./flex-preview";
import { NotifyLevels, type LevelPrefs, type LevelView } from "./notify-levels";

interface Prefs { enabled: boolean; severities: string[]; p1Always: boolean; devicesMode: "all" | "watched" | "top"; topN: number; maxNames: number; newsPossible: boolean; newsHostNames: boolean; updatedAt?: number | null; updatedBy?: string | null }
interface View extends Partial<LevelView> { groupLevels?: LevelPrefs["groupLevels"]; canEdit: boolean; isDefault: boolean; prefs: Prefs & Partial<LevelPrefs>; watchedCount?: number; destinations?: { count: number; names: string[] } }
type State = Prefs & LevelPrefs;
interface Preview { sample: boolean; cve: string | null; messages: object[]; dropped: boolean; truncated: boolean }

const DEFAULTS: Prefs = { enabled: true, severities: [...SEVERITIES], p1Always: true, devicesMode: "all", topN: 10, maxNames: 20, newsPossible: false, newsHostNames: false };
const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, Math.round(v) || lo));
const box = "rounded-xl border border-gray-200 p-3";
const legend = "px-1 text-sm font-semibold text-gray-800";

/** Per-organization LINE notification settings (spec 2.6a): what is sent, which device names it carries, and a live preview from the server. */
export function NotifyPanel({ tenantId, onClose }: { tenantId: string; onClose: () => void }) {
  const t = useTranslations("notifyPrefs");
  const tSev = useTranslations("severity");
  const base = `/api/tenants/${encodeURIComponent(tenantId)}/notify`;
  const { data, error, reload } = useApi<View>(base);
  const [draft, setDraft] = useState<State | null>(null);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [testing, setTesting] = useState(false);
  const [preview, setPreview] = useState<{ ok: true; p: Preview } | { ok: false } | null>(null);
  const seq = useRef(0);

  const saved = data ? ({ ...DEFAULTS, ...data.prefs, groupLevels: data.groupLevels ?? [] } as State) : null;
  const p = draft ?? saved;
  const canEdit = data?.canEdit ?? false;
  const noSev = !!p && p.severities.length === 0;
  const dirty = !!draft && JSON.stringify({ ...draft, updatedAt: 0, updatedBy: 0 }) !== JSON.stringify({ ...saved, updatedAt: 0, updatedBy: 0 });
  const patch = (x: Partial<State>) => { setMsg(null); setDraft({ ...(p as State), ...x }); };

  // the preview follows the options (debounced); a late answer for old options is dropped
  const key = p ? JSON.stringify([p.severities, p.p1Always, p.devicesMode, p.topN, p.maxNames, p.enabled, p.matrixOn, p.matrix, p.escAlert, p.escDays, p.escKev]) : "";
  useEffect(() => {
    if (!p || !canEdit || noSev) return;
    const id = ++seq.current;
    const timer = window.setTimeout(() => {
      api.post<Preview>(`${base}/preview`, { severities: p.severities, p1Always: p.p1Always, devicesMode: p.devicesMode, topN: p.topN, maxNames: p.maxNames, matrixOn: p.matrixOn, matrix: p.matrix, escAlert: p.escAlert, escDays: p.escDays, escKev: p.escKev })
        .then((r) => { if (id === seq.current) setPreview({ ok: true, p: r }); })
        .catch(() => { if (id === seq.current) setPreview({ ok: false }); });
    }, 450);
    return () => window.clearTimeout(timer);
  }, [key, canEdit, base]);

  const errText = (e: unknown) => {
    if (e instanceof ApiError) {
      if (e.status === 0) return t("error.network");
      if (e.status === 403 || e.status === 404) return t("error.forbidden");
      if (e.code && ["severities_empty", "invalid_severity", "invalid_mode", "invalid_top_n", "invalid_max_names", "invalid_matrix", "invalid_esc_days", "invalid_group_levels"].includes(e.code)) return t(`error.${e.code}`);
    }
    return t("error.generic");
  };
  const save = async () => {
    if (!p || noSev) return;
    setSaving(true); setMsg(null);
    try {
      await api.put<View>(base, { enabled: p.enabled, severities: p.severities, p1Always: p.p1Always, devicesMode: p.devicesMode, topN: p.topN, maxNames: p.maxNames, newsPossible: p.newsPossible, newsHostNames: p.newsHostNames,
        matrixOn: p.matrixOn, matrix: p.matrix, escAlert: p.escAlert, escDays: p.escDays, escKev: p.escKev, groupLevels: p.groupLevels.filter((g) => g.group.trim()).map((g) => ({ group: g.group.trim(), level: g.level })) });
      setDraft(null); reload(); setMsg({ ok: true, text: t("saved") });
    } catch (e) { setMsg({ ok: false, text: errText(e) }); }
    setSaving(false);
  };
  const test = async () => {
    setTesting(true); setMsg(null);
    try { const r = await api.post<{ sent: number }>(`${base}/test`, {}); setMsg({ ok: true, text: t("testSent", { n: r.sent }) }); }
    catch (e) { setMsg({ ok: false, text: e instanceof ApiError && e.code === "no_line" ? t("testNoLine") : t("testFailed") }); }
    setTesting(false);
  };

  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (!data || !p) return <FormSkeleton fields={5} />;
  const dis = !canEdit;
  const names = data.destinations?.names ?? [];
  const toggleSev = (s: string) => patch({ severities: SEVERITIES.filter((x) => (x === s ? !p.severities.includes(s) : p.severities.includes(x))) });
  const num = (field: "topN" | "maxNames", lo: number, hi: number, label: string) => (
    <Input type="number" inputMode="numeric" min={lo} max={hi} value={p[field]} disabled={dis} aria-label={label} className="h-8 w-16 px-2 text-center tabular-nums"
      onChange={(e) => patch({ [field]: e.target.value === "" ? lo : clamp(Number(e.target.value), lo, hi) })} data-testid={`notify-${field}`} />
  );
  const radio = (v: Prefs["devicesMode"], label: React.ReactNode, hint?: string) => (
    <label className="flex items-start gap-2 text-sm text-gray-800">
      <input type="radio" name="devicesMode" className="mt-1 size-4 accent-brand-500" checked={p.devicesMode === v} disabled={dis} onChange={() => patch({ devicesMode: v })} data-testid={`notify-mode-${v}`} />
      <span className="min-w-0"><span className="flex flex-wrap items-center gap-1.5">{label}</span>{hint && <span className="block text-xs text-gray-500">{hint}</span>}</span>
    </label>
  );

  return (
    <div className="flex min-w-0 flex-col gap-3" data-testid="notify-panel">
      {!canEdit && <p className="rounded-lg bg-sky-50 px-3 py-1.5 text-sm text-sky-800">{t("readOnly")}</p>}
      {data.isDefault && <p className="text-xs text-gray-500">{t("defaults")}</p>}

      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <label className="flex items-center gap-2 text-sm font-semibold text-gray-800">
          <Switch checked={p.enabled} disabled={dis} onCheckedChange={(v) => patch({ enabled: v })} aria-label={t("enabled")} data-testid="notify-enabled" />
          {t("enabled")}
        </label>
        <span className="min-w-0 text-xs text-gray-500">{names.length ? t("group", { names: names.join(", ") }) : data.destinations?.count ? t("group", { names: String(data.destinations.count) }) : t("groupNone")}</span>
        {canEdit && <Button size="sm" variant="outline" className="ms-auto" disabled={testing || !data.destinations?.count} onClick={() => void test()} data-testid="notify-test">{t("test")}</Button>}
      </div>
      {!p.enabled && <p className="text-sm text-amber-800">{t("enabledOff")}</p>}

      <fieldset className={cn(box, !p.enabled && "opacity-60")}>
        <legend className={legend}>{t("severities")}</legend>
        <div className="grid grid-cols-1 gap-x-4 gap-y-1.5 sm:grid-cols-2">
          {SEVERITIES.map((s) => (
            <label key={s} className="flex items-center gap-2 text-sm text-gray-800">
              <input type="checkbox" className="size-4 accent-brand-500" checked={p.severities.includes(s)} disabled={dis} onChange={() => toggleSev(s)} data-testid={`notify-sev-${s}`} />
              <span className="h-0.5 w-3 rounded" style={{ backgroundColor: SEVERITY_COLOR[s] }} aria-hidden="true" />{tSev(s)}
            </label>
          ))}
        </div>
        {noSev && <p role="alert" className="mt-1.5 text-xs font-medium text-red-700" data-testid="notify-sev-error">{t("oneRequired")}</p>}
        <label className="mt-2 flex items-start gap-2 border-t border-gray-100 pt-2 text-sm text-gray-800">
          <input type="checkbox" className="mt-1 size-4 accent-brand-500" checked={p.p1Always} disabled={dis} onChange={(e) => patch({ p1Always: e.target.checked })} data-testid="notify-p1" />
          <span>{t("p1Always")}<span className="block text-xs text-gray-500">{t("default")}</span></span>
        </label>
      </fieldset>

      {data.defaultMatrix && <NotifyLevels p={p} patch={patch} dis={dis} view={{ defaultMatrix: data.defaultMatrix, evidence: data.evidence, knownGroups: data.knownGroups }} />}

      <fieldset className={cn(box, "flex flex-col gap-2", !p.enabled && "opacity-60")}>
        <legend className={legend}>{t("devices")}</legend>
        {radio("all", t("mode.all"))}
        {radio("watched", <>{t("mode.watched")}<span className="text-xs text-gray-500">({t("watchedCount", { n: data.watchedCount ?? 0 })})</span></>, t("mode.watchedHint"))}
        {radio("top", <>{t("mode.topLabel")} {num("topN", 1, 100, t("mode.topLabel"))} {t("mode.topUnit")}</>, t("mode.topHint"))}
        <div className="flex flex-wrap items-center gap-2 border-t border-gray-100 pt-2 text-sm text-gray-800">
          {t("maxNames")} {num("maxNames", 1, 50, t("maxNames"))} <span className="min-w-0 text-xs text-gray-500">{t("maxNamesUnit")}</span>
        </div>
      </fieldset>

      <fieldset className={cn(box, "flex flex-col gap-1.5")}>
        <legend className={legend}>{t("news")}</legend>
        <label className="flex items-start gap-2 text-sm text-gray-800"><input type="checkbox" className="mt-1 size-4 accent-brand-500" checked={p.newsPossible} disabled={dis} onChange={(e) => patch({ newsPossible: e.target.checked })} data-testid="notify-news-possible" />{t("newsPossible")}</label>
        <label className="flex items-start gap-2 text-sm text-gray-800"><input type="checkbox" className="mt-1 size-4 accent-brand-500" checked={p.newsHostNames} disabled={dis} onChange={(e) => patch({ newsHostNames: e.target.checked })} data-testid="notify-news-hosts" />{t("newsHostNames")}</label>
      </fieldset>

      {canEdit && (
        <section aria-label={t("preview")} className="min-w-0" data-testid="notify-preview">
          <h3 className="mb-1 text-sm font-semibold text-gray-800">{t("preview")}</h3>
          {noSev ? null : !preview ? <div className="h-24 animate-pulse rounded-xl bg-gray-100" role="status" aria-label={t("previewLoading")} />
            : !preview.ok ? <p className="text-sm text-gray-500">{t("previewFailed")}</p>
            : (
              <div className="space-y-1.5">
                {preview.p.sample && <p className="text-xs text-gray-500">{t("previewSample")}</p>}
                {preview.p.dropped || !preview.p.messages.length ? <p className="rounded-lg bg-amber-50 px-3 py-2 text-sm text-amber-900">{t("previewDropped")}</p>
                  : <div className="max-h-96 space-y-2 overflow-y-auto rounded-xl bg-green-50 p-2">{preview.p.messages.slice(0, 3).map((m, i) => <FlexMessage key={i} message={m as Record<string, unknown>} />)}</div>}
                {preview.p.truncated && <p className="text-xs text-gray-500">{t("previewTruncated")}</p>}
              </div>
            )}
        </section>
      )}

      <div className="sticky -bottom-4 -mx-4 mt-1 flex flex-wrap items-center justify-end gap-2 border-t border-gray-200 bg-white px-4 py-2.5">
        {msg && <p role="status" className={cn("me-auto text-sm", msg.ok ? "text-green-700" : "text-red-700")} data-testid="notify-msg">{msg.text}</p>}
        <Button variant="outline" size="sm" onClick={onClose}>{t("close")}</Button>
        {canEdit && <Button size="sm" disabled={saving || noSev || !dirty} onClick={() => void save()} data-testid="notify-save">{t("save")}</Button>}
      </div>
    </div>
  );
}
