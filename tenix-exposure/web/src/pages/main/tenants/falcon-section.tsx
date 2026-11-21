import { TableSkeleton } from "@/components/shared/skeletons";
import { ErrorState } from "@/components/shared/empty-state";
import { Button } from "@/components/ui/button";
import { Field, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { useApi } from "@/hooks/use-api";
import { useLocale, useTranslations } from "@/i18n";
import { PlusIcon } from "@/icons";
import { api, ApiError } from "@/lib/api";
import { formatDateTime, formatNumber } from "@/utils/format";
import { useEffect, useRef, useState } from "react";
import { CLOUDS, CopyText, NoticeBar, Section, StateChip, StateNote, cidShort, delWithBody, isReason, useErrorNotice, type Notice } from "./common";
import { FalconForm, savedKey, testNotice, type Connection, type FalconView, type SaveResult } from "./falcon-form";

interface Progress { phase: "findings" | "devices" | "remediations" | "saving" | "software"; pages: number; read: number; total: number | null; organization: string | null; index: number; count: number }

function SyncProgress({ p }: { p: Progress }) {
  const ts = useTranslations("integrations.sync");
  const locale = useLocale();
  const pct = p.total ? Math.min(100, Math.round((p.read / p.total) * 100)) : null;
  return (
    <div className="mb-3 rounded-lg bg-gray-50 p-3 dark:bg-white/3" role="status" aria-live="polite">
      <p className="text-sm leading-6 text-gray-700 dark:text-gray-300">
        {p.phase === "software" ? ts("progress.software") : ts(`progress.${p.phase}`, { read: formatNumber(p.read, locale), total: p.total === null ? "?" : formatNumber(p.total, locale), pages: p.pages })}
        {p.organization && <span className="text-gray-500 dark:text-gray-400"> · {p.organization}{p.count > 1 ? ` (${p.index}/${p.count})` : ""}</span>}
      </p>
      <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-gray-200 dark:bg-white/10" aria-hidden="true">
        <div className={pct === null ? "h-full w-1/3 animate-pulse rounded-full bg-brand-500" : "h-full rounded-full bg-brand-500 transition-[width] duration-500"} style={pct === null ? undefined : { width: `${pct}%` }} />
      </div>
    </div>
  );
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] leading-5 text-gray-500 dark:text-gray-400">{label}</dt>
      <dd className="text-sm leading-5 text-gray-700 dark:text-gray-300">{children}</dd>
    </div>
  );
}

function ConnectionRow({ tenantId, c, onChanged }: { tenantId: string; c: Connection; onChanged: (v: FalconView) => void }) {
  const t = useTranslations("tenants2.falcon");
  const tt = useTranslations("tenants2");
  const tf = useTranslations("integrations.falcon");
  const tc = useTranslations("common");
  const tg = useTranslations("tenantsGrid");
  const locale = useLocale();
  const errNotice = useErrorNotice();
  const [mode, setMode] = useState<"view" | "edit" | "remove">("view");
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState<"test" | "remove" | null>(null);
  const [notice, setNotice] = useState<Notice>(null);

  const cloud = CLOUDS.find((x) => x.url === c.baseUrl);
  const test = async () => {
    setBusy("test");
    setNotice(null);
    try {
      const r = await api.post<Parameters<typeof testNotice>[0]>(`/api/tenants/${tenantId}/falcon/test`, { connectionId: c.id, cid: c.cid });
      setNotice(testNotice(r, (k, v) => tt(k, v)));
    } catch (e) {
      setNotice(errNotice(e));
    }
    setBusy(null);
  };
  const remove = async () => {
    setBusy("remove");
    setNotice(null);
    try {
      onChanged(await delWithBody<FalconView>(`/api/tenants/${tenantId}/falcon/${c.id}`, { confirmCid: typed.trim().toLowerCase() }));
    } catch (e) {
      setNotice(errNotice(e));
      setBusy(null);
    }
  };

  return (
    <li className="rounded-lg border border-gray-200 p-3 dark:border-gray-800">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <span className="min-w-0 text-sm leading-6 font-medium wrap-break-word text-gray-800 dark:text-white/90">{c.name || t("unnamed", { cid: cidShort(c.cid) })}</span>
        <StateChip state={c.state} />
      </div>

      {mode === "edit" ? (
        <div className="mt-3">
          <FalconForm tenantId={tenantId} connection={c} onSaved={(r) => { setMode("view"); onChanged(r); }}
            footerExtra={<Button type="button" variant="ghost" onClick={() => setMode("view")}>{tc("cancel")}</Button>} />
        </div>
      ) : (
        <>
          <dl className="mt-2 grid grid-cols-1 gap-x-4 gap-y-2 @lg:grid-cols-2">
            <Fact label={t("cloud")}>{cloud ? tf(`clouds.${cloud.key}`) : c.baseUrl}</Fact>
            <Fact label={t("clientId")}><span className="font-mono text-xs break-all">{c.clientId}</span></Fact>
            <Fact label={t("cid")}><CopyText value={c.cid} shown={cidShort(c.cid)} label={t("copyCid", { cid: cidShort(c.cid) })} /></Fact>
            <Fact label={t("dataAsOf")}>{formatDateTime(c.dataAsOf, locale) ?? tc("never")}</Fact>
            <Fact label={tg("findings")}><span className="tabular-nums">{formatNumber(c.findings, locale)}</span></Fact>
            <Fact label={tg("lastSync")}>{formatDateTime(c.lastRunAt, locale) ?? tc("never")}</Fact>
          </dl>
          <StateNote className="mt-2" state={c.state} dataAsOf={c.dataAsOf} reason={c.reason} />
          {c.detail.length > 0 && <ul className="mt-2 space-y-0.5 text-xs leading-5 text-amber-600">{c.detail.slice(0, 3).map((d) => <li key={d}>{d}</li>)}</ul>}
          <NoticeBar notice={notice} className="mt-2" />
          {mode === "remove" ? (
            <div className="mt-3 rounded-lg bg-red-50 p-3">
              <p className="text-sm leading-6 text-red-700">{t("removeWarn")}</p>
              <Field className="mt-2">
                <FieldLabel className="mb-1.5 block">{t("removeConfirm", { cid: c.cid })}</FieldLabel>
                <Input value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} className="font-mono text-xs" />
              </Field>
              <div className="mt-2 flex flex-wrap gap-2">
                <Button variant="destructive" disabled={typed.trim().toLowerCase() !== c.cid || busy !== null} onClick={() => void remove()}>{busy === "remove" ? <><Spinner /> {t("removing")}</> : t("removeAction")}</Button>
                <Button variant="outline" onClick={() => { setMode("view"); setTyped(""); setNotice(null); }}>{tc("cancel")}</Button>
              </div>
            </div>
          ) : (
            <div className="mt-3 flex flex-wrap gap-2">
              <Button size="sm" variant="outline" disabled={busy !== null} onClick={() => void test()}>{busy === "test" ? <><Spinner /> {t("testing")}</> : t("test")}</Button>
              <Button size="sm" variant="outline" onClick={() => setMode("edit")}>{tc("edit")}</Button>
              <Button size="sm" variant="ghost" className="text-red-600 hover:text-red-700" onClick={() => setMode("remove")}>{t("remove")}</Button>
            </div>
          )}
        </>
      )}
    </li>
  );
}

interface ConvertResult { cid: string; ok: boolean; reason?: string }

/** CIDs of the organization that have no login of their own: not read at all. Add a login for each, or try the old shared login once. */
function Unconnected({ v, tenantId, busy, onAdd, onConverted }: { v: FalconView; tenantId: string; busy: boolean; onAdd: (cid: string) => void; onConverted: (r: FalconView, results: ConvertResult[]) => void }) {
  const t = useTranslations("tenants2.falcon");
  const tt = useTranslations("tenants2");
  const tg = useTranslations("tenantsGrid");
  const tc = useTranslations("common");
  const locale = useLocale();
  const errNotice = useErrorNotice();
  const [trying, setTrying] = useState(false);
  const [notice, setNotice] = useState<Notice>(null);
  const [results, setResults] = useState<ConvertResult[]>([]);
  const convert = async () => {
    setTrying(true);
    setNotice(null);
    try {
      const r = await api.post<FalconView & { results: ConvertResult[] }>(`/api/tenants/${tenantId}/falcon/convert-shared`);
      setResults(r.results);
      onConverted(r, r.results);
    } catch (e) {
      setNotice(errNotice(e));
    }
    setTrying(false);
  };
  return (
    <div className="rounded-lg border border-amber-200 bg-amber-50/50 p-3">
      <h4 className="text-sm leading-6 font-medium text-amber-800">{t("unconnectedTitle")}</h4>
      <p className="text-sm leading-6 text-amber-800">{t("unconnectedHelp")}</p>
      <ul className="mt-2 grid gap-2">
        {v.unconnectedCids.map((u) => {
          const res = results.find((x) => x.cid === u.cid);
          return (
            <li key={u.cid} className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg bg-white p-2">
              <CopyText value={u.cid} shown={cidShort(u.cid)} label={t("copyCid", { cid: cidShort(u.cid) })} />
              <span className="min-w-0 flex-1 text-xs leading-5 text-gray-600">
                {u.findings > 0 || u.dataAsOf ? t("oldData", { count: formatNumber(u.findings, locale), time: formatDateTime(u.dataAsOf, locale) ?? tc("never") }) : t("noData")}
                <span className="block">{tg("lastSync")}: {formatDateTime(u.lastRunAt, locale) ?? tc("never")}</span>
                {res && <span className={`block ${res.ok ? "text-green-700" : "text-red-600"}`}>{res.ok ? t("convertOk") : isReason(res.reason) ? tt(`test.${res.reason}`) : t("convertFail")}</span>}
              </span>
              <Button size="sm" variant="outline" disabled={busy} onClick={() => onAdd(u.cid)}><PlusIcon />{t("addLogin")}</Button>
            </li>
          );
        })}
      </ul>
      {v.legacyLogin && (
        <div className="mt-2">
          <Button size="sm" variant="ghost" disabled={trying} onClick={() => void convert()}>{trying ? <><Spinner /> {t("converting")}</> : t("convert")}</Button>
          <p className="text-xs leading-5 text-gray-500">{t("convertHelp")}</p>
        </div>
      )}
      <NoticeBar notice={notice} className="mt-2" />
    </div>
  );
}

/** Section A of an organization: its CrowdStrike connections (add, test, edit, remove, sync) and the CIDs that still have no login of their own. */
export function FalconSection({ tenantId, onChanged }: { tenantId: string; onChanged: () => void }) {
  const t = useTranslations("tenants2.falcon");
  const tt = useTranslations("tenants2");
  const tc = useTranslations("common");
  const errNotice = useErrorNotice();
  const { data, error, reload } = useApi<FalconView>(`/api/tenants/${tenantId}/falcon`);
  const [view, setView] = useState<FalconView | null>(null);
  const [adding, setAdding] = useState<{ cid?: string } | null>(null);
  const [notice, setNotice] = useState<Notice>(null);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [busy, setBusy] = useState(false);

  const v = view ?? data;
  const syncing = running || (v?.sync.running ?? false);
  const changed = useRef(onChanged); // the parent may pass a new function every render; the poll must not restart for that
  useEffect(() => { changed.current = onChanged; });
  const apply = (r: FalconView) => { setView(r); onChanged(); };

  // poll while a sync runs, then reload the view once it has finished
  useEffect(() => {
    if (!syncing) return;
    let live = true;
    const tick = async () => {
      try {
        const r = await api.get<{ sync: { running: boolean; progress: Progress | null } }>("/api/integrations/falcon");
        if (!live) return;
        setProgress(r.sync.progress);
        if (!r.sync.running) {
          setRunning(false);
          setProgress(null);
          setView(await api.get<FalconView>(`/api/tenants/${tenantId}/falcon`));
          changed.current();
        }
      } catch {
        /* try again on the next tick */
      }
    };
    const id = window.setInterval(() => void tick(), 3000);
    void tick();
    return () => { live = false; window.clearInterval(id); };
  }, [syncing, tenantId]);

  const sync = async () => {
    setBusy(true);
    setNotice(null);
    try {
      await api.post("/api/integrations/falcon/sync", { tenantId });
      setRunning(true);
      setNotice({ kind: "success", text: tt("notices.syncStarted") });
    } catch (e) {
      setNotice(errNotice(e));
    }
    setBusy(false);
  };
  const saved = (r: SaveResult, sync: boolean) => {
    const k = savedKey(r, sync);
    apply(r);
    setAdding(null);
    if (r.syncStarted) setRunning(true);
    setNotice({ kind: "success", text: t(k) });
  };
  const converted = (r: FalconView, results: ConvertResult[]) => {
    apply(r);
    if (results.some((x) => x.ok)) setNotice({ kind: "success", text: t("convertedSome", { count: results.filter((x) => x.ok).length }) });
  };

  return (
    <Section title={t("title")} help={t("help")} step="A" id="tenant-falcon"
      action={v && (
        <Button size="sm" variant="outline" disabled={v.connections.length === 0 || syncing || busy} onClick={() => void sync()}>
          {syncing ? <><Spinner /> {t("syncing")}</> : t("syncNow")}
        </Button>
      )}>
      {error && !v ? <ErrorState error={error as ApiError} onRetry={reload} /> : !v ? <TableSkeleton rows={3} /> : (
        <div className="grid gap-3">
          {syncing && progress && <SyncProgress p={progress} />}
          <NoticeBar notice={notice} />
          {v.connections.length === 0 && v.unconnectedCids.length === 0 && !adding && (
            <p className="rounded-lg bg-amber-50 p-3 text-sm leading-6 text-amber-700">{t("none")}</p>
          )}
          {v.connections.length > 0 && (
            <ul className="grid gap-2">{v.connections.map((c) => <ConnectionRow key={c.id} tenantId={tenantId} c={c} onChanged={apply} />)}</ul>
          )}
          {v.unconnectedCids.length > 0 && (
            <Unconnected v={v} tenantId={tenantId} busy={!!adding} onAdd={(cid) => { setAdding({ cid }); setNotice(null); }} onConverted={converted} />
          )}
          {adding ? (
            <div className="rounded-lg border border-brand-200 bg-brand-50/30 p-3">
              <h4 className="mb-3 text-sm leading-6 font-medium text-gray-800 dark:text-white/90">{t("addTitle")}</h4>
              <FalconForm key={adding.cid ?? ""} tenantId={tenantId} initialCid={adding.cid} onSaved={saved} footerExtra={<Button type="button" variant="ghost" onClick={() => setAdding(null)}>{tc("cancel")}</Button>} />
            </div>
          ) : (
            <div><Button size="sm" onClick={() => { setAdding({}); setNotice(null); }}><PlusIcon />{t("add")}</Button></div>
          )}
        </div>
      )}
    </Section>
  );
}
