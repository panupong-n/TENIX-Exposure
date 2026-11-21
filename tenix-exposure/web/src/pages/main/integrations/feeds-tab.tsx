import { ErrorState } from "@/components/shared/empty-state";
import { FormSkeleton } from "@/components/shared/skeletons";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Spinner } from "@/components/ui/spinner";
import { Switch } from "@/components/ui/switch";
import { useApi } from "@/hooks/use-api";
import { useLocale, useTranslations } from "@/i18n";
import { api, ApiError } from "@/lib/api";
import { formatDateTime, formatNumber } from "@/utils/format";
import { useState } from "react";

interface Feed { lastOkAt: number | null; lastTryAt: number | null; error: string | null; checkpoint: string | null; info: { gap?: boolean; remaining?: number; total?: number } }
interface Config { enabled: boolean; cveMinutes: number; kevMinutes: number; initialDays: number }
interface Status { config: Config; cveList: Feed; kev: Feed; counts: { cves: number; kev: number } }
interface RunResult { cve: { ingested: number; missing: number; remaining: number; error?: string }; kev: { total: number; added: number; error?: string }; status: Status }

const card = "rounded-xl border border-gray-200 bg-white p-3 sm:p-4 dark:border-gray-800 dark:bg-white/3";
const help = "text-xs text-gray-500 dark:text-gray-400";

export default function FeedsTab() {
  const t = useTranslations("integrations.feeds");
  const locale = useLocale();
  const { data, error, reload } = useApi<Status>("/api/feeds/status");
  const [draft, setDraft] = useState<Config | null>(null);
  const [busy, setBusy] = useState<"save" | "run" | null>(null);
  const [notice, setNotice] = useState<{ kind: "success" | "destructive" | "warning"; lines: string[] } | null>(null);

  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (!data) return <FormSkeleton fields={4} />;
  const cfg = draft ?? data.config;
  const set = (patch: Partial<Config>) => setDraft({ ...cfg, ...patch });
  const num = (k: "cveMinutes" | "kevMinutes" | "initialDays") => (e: React.ChangeEvent<HTMLInputElement>) => set({ [k]: Number(e.target.value) });
  const n = (v: number) => formatNumber(v, locale);

  const save = async () => {
    setBusy("save"); setNotice(null);
    try {
      await api.put("/api/integrations/feeds", cfg);
      setDraft(null); setNotice({ kind: "success", lines: [t("saved")] }); reload();
    } catch (e) {
      const code = e instanceof ApiError ? e.code : null;
      setNotice({ kind: "destructive", lines: [code === "invalid_interval" ? t("errors.invalid_interval") : t("errors.unknown")] });
    } finally { setBusy(null); }
  };
  const runNow = async () => {
    setBusy("run"); setNotice(null);
    try {
      const r = await api.post<RunResult>("/api/integrations/feeds/run");
      const errs = [r.cve.error && t("runError", { feed: "CVE List", error: r.cve.error }), r.kev.error && t("runError", { feed: "CISA KEV", error: r.kev.error })].filter((x): x is string => !!x);
      setNotice({ kind: errs.length ? "warning" : "success", lines: [t("runCve", { ingested: n(r.cve.ingested), missing: n(r.cve.missing), remaining: n(r.cve.remaining) }), t("runKev", { total: n(r.kev.total), added: n(r.kev.added) }), ...errs] });
      reload();
    } catch { setNotice({ kind: "destructive", lines: [t("errors.unknown")] }); } finally { setBusy(null); }
  };

  const feed = (title: string, f: Feed, count: number, extra: [string, string | null][]) => (
    <div className="min-w-0 rounded-lg border border-gray-200 p-3 dark:border-gray-800">
      <h3 className="mb-1.5 text-sm font-semibold text-gray-800 dark:text-white/90">{title}</h3>
      <dl className="space-y-1 text-sm">
        {[
          [t("lastOk"), formatDateTime(f.lastOkAt, locale) ?? t("never")],
          [t("lastTry"), formatDateTime(f.lastTryAt, locale) ?? t("never")],
          [t("checkpoint"), f.checkpoint ?? "–"],
          [t("records"), n(count)],
          ...extra,
        ].filter((r): r is [string, string] => r[1] !== null).map(([k, v]) => (
          <div key={k} className="flex items-baseline justify-between gap-3">
            <dt className="shrink-0 text-xs text-gray-500 dark:text-gray-400">{k}</dt>
            <dd className="min-w-0 text-end font-medium break-all text-gray-800 tabular-nums dark:text-white/90">{v}</dd>
          </div>
        ))}
      </dl>
      {f.error && <Alert variant="warning" className="mt-2 p-2"><AlertDescription><span className="font-medium">{t("error")}:</span> <span className="break-all">{f.error}</span></AlertDescription></Alert>}
      {f.info.gap && <Alert variant="warning" className="mt-2 p-2"><AlertDescription>{t("gap")}</AlertDescription></Alert>}
    </div>
  );

  return (
    <div className="space-y-3">
      <section className={card}>
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div className="min-w-0">
            <h2 className="text-base font-semibold text-gray-800 dark:text-white/90">{t("title")}</h2>
            <p className="mt-0.5 text-sm text-gray-500 dark:text-gray-400">{t("description")}</p>
          </div>
          <Badge size="sm" color={data.config.enabled ? "success" : "gray"}>{data.config.enabled ? t("on") : t("off")}</Badge>
        </div>
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          {feed(t("cveList"), data.cveList, data.counts.cves, [[t("backlog"), data.cveList.info.remaining !== undefined ? n(data.cveList.info.remaining) : null]])}
          {feed(t("kev"), data.kev, data.counts.kev, [[t("kevTotal"), data.kev.info.total !== undefined ? n(data.kev.info.total) : null]])}
        </div>
      </section>

      <section className={card}>
        <h2 className="text-base font-semibold text-gray-800 dark:text-white/90">{t("settings")}</h2>
        <div className="mt-2 max-w-2xl space-y-3">
          <div className="flex items-center gap-2">
            <Switch size="sm" id="feeds-enabled" checked={cfg.enabled} onCheckedChange={(v) => set({ enabled: v })} />
            <Label htmlFor="feeds-enabled">{t("enabled")}</Label>
          </div>
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="space-y-1.5">
              <Label htmlFor="feeds-cve">{t("cveMinutes")}</Label>
              <Input id="feeds-cve" type="number" min={5} max={1440} value={cfg.cveMinutes} onChange={num("cveMinutes")} />
              <p className={help}>{t("cveHelp")}</p>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="feeds-kev">{t("kevMinutes")}</Label>
              <Input id="feeds-kev" type="number" min={15} max={1440} value={cfg.kevMinutes} onChange={num("kevMinutes")} />
              <p className={help}>{t("kevHelp")}</p>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="feeds-days">{t("initialDays")}</Label>
              <Input id="feeds-days" type="number" min={1} max={30} value={cfg.initialDays} onChange={num("initialDays")} />
              <p className={help}>{t("initialHelp")}</p>
            </div>
          </div>
          <p className={help}>{t("falconNote")}</p>
          {notice && <Alert variant={notice.kind}><AlertDescription>{notice.lines.map((l) => <span key={l} className="block">{l}</span>)}</AlertDescription></Alert>}
          <div className="flex flex-wrap gap-2">
            <Button type="button" onClick={save} disabled={busy !== null}>{busy === "save" && <Spinner />}{t("save")}</Button>
            <Button type="button" variant="outline" onClick={runNow} disabled={busy !== null}>{busy === "run" && <Spinner />}{t("run")}</Button>
          </div>
        </div>
      </section>
    </div>
  );
}
