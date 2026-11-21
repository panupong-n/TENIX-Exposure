// skeleton-ok: the organization comes from the list (already loaded); its sections load their own data behind skeletons
import { MaskReveal } from "@/components/shared/mask-reveal";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown";
import { useLocale, useTranslations } from "@/i18n";
import { ArrowLeftIcon, VerticalDotsIcon } from "@/icons";
import { formatDateTime, formatNumber } from "@/utils/format";
import { orgSettingLink } from "@/pages/main/settings/org-settings";
import { Link, useLocation } from "react-router";
import { Chips } from "./chips";
import { StateChip, StateNote, Section, type Notice } from "./common";
import { DeleteDialog, RenameDialog, type Tenant } from "./dialogs";
import { FalconSection } from "./falcon-section";
import { LineSection } from "./line-section";
import { useEffect, useState } from "react";

/** Section C: users and the sync facts the server already reports, shown calmly. */
function DataSection({ x }: { x: Tenant }) {
  const t = useTranslations("tenants2.data");
  const tt = useTranslations("tenants");
  const tg = useTranslations("tenantsGrid");
  const tc = useTranslations("common");
  const locale = useLocale();
  const n = (v: number) => formatNumber(v, locale);
  return (
    <Section title={t("title")} help={t("help")} step="D">
      <div className="grid gap-3 @lg:grid-cols-2">
        <div className="rounded-lg bg-gray-50 p-3 dark:bg-white/5">
          <h4 className="text-sm leading-6 font-medium text-gray-800 dark:text-white/90">{t("users")}</h4>
          <p className="mt-1 text-sm leading-6 text-gray-600">{tt("usersCount", { count: x.users })} · {tt("adminsCount", { count: x.admins })}</p>
          <Link to={`/settings?setting=team&tenant=${encodeURIComponent(x.id)}`} className="mt-1 inline-block text-sm leading-6 text-brand-500 hover:underline">{t("manageUsers")}</Link>
        </div>
        <div className="rounded-lg bg-gray-50 p-3 dark:bg-white/5">
          <h4 className="flex flex-wrap items-center gap-2 text-sm leading-6 font-medium text-gray-800 dark:text-white/90">{t("sync")} <StateChip state={x.state} /></h4>
          <StateNote className="mt-1" state={x.state} dataAsOf={x.dataAsOf} />
          <p className="text-sm leading-6 text-gray-600">{t("dataAsOf")}: {formatDateTime(x.dataAsOf, locale) ?? tc("never")}</p>
          <p className="text-sm leading-6 text-gray-600">{tg("lastSync")}: {formatDateTime(x.lastRunAt, locale) ?? tc("never")}</p>
        </div>
      </div>
      <dl className="mt-3 grid grid-cols-2 gap-2 text-center @lg:grid-cols-4">
        {([["findings", x.stats.findings], ["critical", x.stats.critical], ["devices", x.stats.devices], ["kev", x.stats.kev]] as const).map(([k, v]) => (
          <div key={k} className="rounded-lg border border-gray-100 px-1 py-1.5">
            <dd className={`text-base leading-6 font-semibold tabular-nums ${k === "critical" && v ? "text-red-600" : "text-gray-800"}`}>{n(v)}</dd>
            <dt className="text-xs leading-5 text-gray-500">{tg(k)}</dt>
          </div>
        ))}
      </dl>
      {x.detail.length > 0 && (
        <div className="mt-3">
          <h4 className="text-sm leading-6 font-medium text-gray-800">{t("messages")}</h4>
          <ul className="mt-1 space-y-0.5 text-sm leading-6 text-amber-600">{x.detail.map((d) => <li key={d}>{d}</li>)}</ul>
        </div>
      )}
    </Section>
  );
}

/** One organization: three separate sections (CrowdStrike, LINE, users and data), with rename/delete in the "..." menu. */
export function TenantDetail({ tenant: x, section, onBack, onChanged, onDone, onOpen }: {
  tenant: Tenant; section?: string | null; onBack: () => void; onChanged: () => void; onDone: (n: Notice, gone?: boolean) => void; onOpen: () => void;
}) {
  const t = useTranslations("tenants2");
  const tt = useTranslations("tenants");
  const tg = useTranslations("tenantsGrid");
  const tsl = useTranslations("settingsLinks");
  const loc = useLocation();
  const [dialog, setDialog] = useState<"rename" | "delete" | null>(null);
  const goFalcon = () => document.getElementById("tenant-falcon")?.scrollIntoView({ behavior: "smooth", block: "start" });
  // a deep link (?section=falcon) opens on that section
  useEffect(() => {
    if (section === "falcon") window.setTimeout(() => document.getElementById("tenant-falcon")?.scrollIntoView({ block: "start" }), 150);
  }, [section]);
  const noLogin = x.state === "no_cids" || x.state === "no_connection";

  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <Button variant="ghost" size="sm" onClick={onBack}><ArrowLeftIcon />{t("back")}</Button>
      </div>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <MaskReveal as="h2" className="text-xl leading-7 font-semibold wrap-break-word text-gray-800 dark:text-white/90">{x.name}</MaskReveal>
          <div className="mt-1"><Chips x={x} /></div>
          <p className="mt-1 flex flex-wrap gap-x-4 gap-y-0.5 text-sm leading-6">
            {(["notify", "retention"] as const).map((k) => <Link key={k} to={orgSettingLink(loc.pathname, loc.search, k, x.id)} className="text-brand-500 hover:underline" data-testid={`tenant-open-${k}`}>{tsl(k)}</Link>)}
          </p>
        </div>
        <DropdownMenu>
          <DropdownMenuTrigger render={<Button variant="ghost" size="icon-sm" aria-label={tt("actions.menu", { name: x.name })} />}><VerticalDotsIcon /></DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-48 p-2">
            <DropdownMenuItem onClick={onOpen}>{tg("open")}</DropdownMenuItem>
            <DropdownMenuItem onClick={() => setDialog("rename")}>{tt("actions.rename")}</DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem variant="destructive" onClick={() => setDialog("delete")}>{tt("actions.delete")}</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      {noLogin && (
        <div className="flex flex-wrap items-center gap-2 rounded-lg border border-amber-200 bg-amber-50 p-3">
          <p className="min-w-0 flex-1 basis-56 text-sm leading-6 text-amber-800">{t(`banner.${x.state as "no_cids" | "no_connection"}`)}</p>
          <Button size="sm" onClick={goFalcon}>{t("banner.action")}</Button>
        </div>
      )}
      <FalconSection tenantId={x.id} onChanged={onChanged} />
      <LineSection tenantId={x.id} onSaved={onChanged} />
      <DataSection x={x} />

      {dialog === "rename" && <RenameDialog tenant={x} onClose={() => setDialog(null)} onDone={(n) => { setDialog(null); onDone(n); }} />}
      {dialog === "delete" && <DeleteDialog tenant={x} onClose={() => setDialog(null)} onDone={(n) => { setDialog(null); onDone(n, true); }} />}
    </div>
  );
}
