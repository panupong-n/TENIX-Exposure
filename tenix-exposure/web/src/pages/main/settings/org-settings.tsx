import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { useAuth } from "@/contexts/auth-context";
import { useOrg } from "@/contexts/org-context";
import { useTranslations } from "@/i18n";
import { useState } from "react";
import { useLocation, useSearchParams } from "react-router";
import { NotifyPanel } from "./notify-panel";
import { RetentionPanel } from "./retention-panel";

export type OrgSetting = "notify" | "retention";
const isKind = (v: string | null): v is OrgSetting => v === "notify" || v === "retention";

/** Link to a per-organization settings drawer from any page: ?settings=notify|retention[&tenant=<id>] (the Setting Center also accepts &section=). */
export function orgSettingLink(pathname: string, search: string, kind: OrgSetting, tenant?: string): string {
  const p = new URLSearchParams(search);
  p.set("settings", kind);
  if (tenant) p.set("tenant", tenant);
  return `${pathname}?${p}`;
}

/** The two per-organization settings drawers, mounted once in the app layout so every page (and /settings?tenant=<id>&section=notify|retention) can open them. */
export function OrgSettingDrawers() {
  const tn = useTranslations("notifyPrefs");
  const tr = useTranslations("retention");
  const { user } = useAuth();
  const { orgs, orgId } = useOrg();
  const { pathname } = useLocation();
  const [params, setParams] = useSearchParams();
  const fromSection = pathname === "/settings" && !params.get("setting") ? params.get("section") : null;
  const raw = params.get("settings") ?? fromSection;
  const kind = isKind(raw) ? raw : null;
  const tenantId = params.get("tenant") ?? orgId;
  const [last, setLast] = useState<OrgSetting | null>(kind);
  if (kind && kind !== last) setLast(kind);
  const shown = kind ?? last;
  const org = orgs.find((o) => o.id === tenantId);
  const close = () => setParams((p) => {
    const n = new URLSearchParams(p);
    n.delete("settings");
    if (fromSection) { n.delete("section"); n.delete("tenant"); }
    return n;
  }, { replace: true });
  if (!user) return null;
  const canEdit = !!user.soc || org?.role === "admin";
  return (
    <Sheet open={kind !== null} onOpenChange={(o) => { if (!o) close(); }}>
      <SheetContent className="gap-3 overflow-y-auto p-4 data-[side=right]:w-full data-[side=right]:sm:w-[40rem] data-[side=right]:sm:max-w-none" data-testid={`settings-${shown ?? "none"}`}>
        {shown && (
          <>
            <SheetHeader className="gap-0.5 p-0 pe-8">
              <SheetTitle className="text-base leading-6">{shown === "notify" ? tn("title") : tr("title")}</SheetTitle>
              <SheetDescription className="text-xs leading-5">{(shown === "notify" ? tn : tr)("sub", { org: org?.name ?? "" })}</SheetDescription>
            </SheetHeader>
            {!tenantId ? <p className="text-sm text-gray-500">{tr("noOrg")}</p> : shown === "notify"
              ? <NotifyPanel key={tenantId} tenantId={tenantId} onClose={close} />
              : <RetentionPanel key={tenantId} tenantId={tenantId} canEdit={canEdit} onClose={close} />}
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}
