import { EmptyState, ErrorState } from "@/components/shared/empty-state";
import { PageBreadcrumb } from "@/components/shared/page-breadcrumb";
import { PageMeta } from "@/components/shared/page-meta";
import { TableSkeleton } from "@/components/shared/skeletons";
import { Button } from "@/components/ui/button";
import { useOrg } from "@/contexts/org-context";
import { useApi } from "@/hooks/use-api";
import { useLocale, useTranslations } from "@/i18n";
import { ChevronRightIcon, PlusIcon } from "@/icons";
import { formatDateTime, formatNumber } from "@/utils/format";
import { useCallback, useState } from "react";
import { useNavigate, useSearchParams } from "react-router";
import { NoticeBar, type Notice } from "./common";
import { Chips } from "./chips";
import { TenantDetail } from "./detail";
import type { Tenant } from "./dialogs";
import { Wizard } from "./wizard";

type View = { kind: "list" } | { kind: "wizard" } | { kind: "detail"; id: string };

/** The organizations: a list, one organization's detail, or the create wizard, all inside this panel (used by the Setting Center drawer and by the page below). */
export function TenantsPanel() {
  const t = useTranslations("tenants2");
  const tg = useTranslations("tenantsGrid");
  const tc = useTranslations("common");
  const locale = useLocale();
  const navigate = useNavigate();
  const { reloadOrgs, setOrgId } = useOrg();
  const { data, error, reload } = useApi<{ tenants: Tenant[] }>("/api/tenants");
  // ?tenant=<id>[&section=falcon] opens that organization (the link banners and the Setting Center use)
  const [params] = useSearchParams();
  const linked = params.get("tenant");
  const [view, setView] = useState<View>(linked ? { kind: "detail", id: linked } : { kind: "list" });
  const [section, setSection] = useState<string | null>(linked ? params.get("section") : null);
  const [notice, setNotice] = useState<Notice>(null);

  const changed = useCallback(() => { reload(); reloadOrgs(); }, [reload, reloadOrgs]);
  const n = (v: number) => formatNumber(v, locale);
  const back = () => { setView({ kind: "list" }); changed(); };
  const current = view.kind === "detail" ? data?.tenants.find((x) => x.id === view.id) : undefined;

  if (view.kind === "wizard") {
    return (
      <div className="@container min-w-0">
        <Wizard onExit={() => setView({ kind: "list" })} onCreated={changed} onFinish={(id) => { setNotice({ kind: "success", text: t("wizard.done") }); setView({ kind: "detail", id }); changed(); }} />
      </div>
    );
  }

  if (view.kind === "detail") {
    return (
      <div className="@container min-w-0">
        {!data ? (error ? <ErrorState error={error} onRetry={reload} /> : <TableSkeleton rows={4} />) : !current ? (
          <EmptyState>{t("gone")}</EmptyState>
        ) : (
          <>
            <NoticeBar notice={notice} className="mb-3" />
            <TenantDetail tenant={current} section={section} onBack={() => { setNotice(null); setSection(null); back(); }} onChanged={changed}
              onOpen={() => { setOrgId(current.id); void navigate("/"); }}
              onDone={(nt, gone) => { if (gone) { setNotice(nt); setView({ kind: "list" }); changed(); } else { setNotice(nt); changed(); } }} />
          </>
        )}
      </div>
    );
  }

  return (
    <div className="@container min-w-0">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-base leading-6 font-semibold text-gray-800 dark:text-white/90">
          {t("listTitle")}{data && <span className="ms-2 rounded-md bg-gray-100 px-1.5 text-sm font-medium text-gray-600 tabular-nums">{n(data.tenants.length)}</span>}
        </h2>
        <Button onClick={() => { setNotice(null); setView({ kind: "wizard" }); }}><PlusIcon />{t("add")}</Button>
      </div>
      <NoticeBar notice={notice} className="mb-3" />
      {error ? <ErrorState error={error} onRetry={reload} /> : !data ? <TableSkeleton rows={4} /> : data.tenants.length === 0 ? <EmptyState>{t("empty")}</EmptyState> : (
        <ul className="grid gap-2">
          {data.tenants.map((x) => (
            <li key={x.id}>
              <button type="button" onClick={() => { setNotice(null); setView({ kind: "detail", id: x.id }); }} aria-label={t("openOrg", { name: x.name })}
                className="grid w-full grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-2 rounded-xl border border-gray-200 bg-white p-3 text-start transition-colors hover:border-brand-300 hover:bg-gray-50 focus-visible:ring-3 focus-visible:ring-brand-500/20 focus-visible:outline-hidden @2xl:grid-cols-[minmax(0,1fr)_auto_auto] dark:border-gray-800 dark:bg-white/3 dark:hover:bg-white/5">
                <span className="min-w-0">
                  <span className="block text-sm leading-6 font-semibold wrap-break-word text-gray-800 dark:text-white/90">{x.name}</span>
                  <span className="mt-1 block"><Chips x={x} /></span>
                  <span className="mt-1 block text-xs leading-5 text-gray-500">{tg("lastSync")}: {formatDateTime(x.lastRunAt, locale) ?? tc("never")}</span>
                </span>
                <ChevronRightIcon className="size-5 text-gray-400 @2xl:col-start-3 @2xl:row-start-1" />
                <span className="col-span-2 grid grid-cols-3 gap-2 text-center @2xl:col-span-1 @2xl:col-start-2 @2xl:row-start-1 @2xl:w-64">
                  {([["findings", x.stats.findings], ["critical", x.stats.critical], ["devices", x.stats.devices]] as const).map(([k, v]) => (
                    <span key={k} className="rounded-lg bg-gray-50 px-1 py-1.5 dark:bg-white/5">
                      <span className={`block text-sm leading-5 font-semibold tabular-nums ${k === "critical" && v ? "text-red-600" : "text-gray-800"}`}>{n(v)}</span>
                      <span className="block text-[11px] leading-4 text-gray-500">{tg(k)}</span>
                    </span>
                  ))}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default function TenantsPage() {
  const t = useTranslations("tenants");
  return (
    <>
      <PageMeta title={`${t("title")} | 10CYBER Exposure`} description={t("description")} />
      <PageBreadcrumb pageTitle={t("title")} description={t("description")} />
      <TenantsPanel />
    </>
  );
}
