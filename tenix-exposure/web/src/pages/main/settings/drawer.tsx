import { useDrawers } from "@/components/shared/drawers-context";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { useTranslations } from "@/i18n";
import { useCallback, useState } from "react";
import { useSearchParams } from "react-router";
import { AuditPanel } from "../audit";
import EmailTab from "../integrations/email-tab";
import FeedsTab from "../integrations/feeds-tab";
import LineTab from "../integrations/line-tab";
import { TeamPanel } from "../team";
import { TenantsPanel } from "../tenants";
import { SystemPanel } from "./system-panel";
import type { SettingKey } from "./status";

const KEYS: SettingKey[] = ["feeds", "line", "email", "tenants", "team", "audit", "system"];
const isKey = (v: string | null): v is SettingKey => KEYS.includes(v as SettingKey);

// the drawer sizes used all over the app: full width on a phone, 40rem, 60vw
const MD = "data-[side=right]:w-full data-[side=right]:sm:w-[40rem] data-[side=right]:sm:max-w-none";
const LG = "data-[side=right]:w-full data-[side=right]:sm:w-[60vw] data-[side=right]:sm:max-w-none";
const WIDTH: Record<SettingKey, string> = { feeds: MD, line: LG, email: LG, tenants: LG, team: LG, audit: LG, system: LG };
const BODY: Record<SettingKey, () => React.JSX.Element> = {
  feeds: () => <FeedsTab />,
  line: () => <LineTab />,
  email: () => <EmailTab />,
  tenants: () => <TenantsPanel />,
  team: () => <TeamPanel />,
  audit: () => <AuditPanel />,
  system: () => <SystemPanel />,
};

/** Which setting is open lives in the URL (?setting=tenants|line|...), like ?cve=. Opening pushes, closing replaces, so Back closes the drawer. */
export function useSettingParam() {
  const [params, setParams] = useSearchParams();
  const raw = params.get("setting") === "falcon" ? "tenants" : params.get("setting"); // old bookmarks of the removed shared login land on Organizations
  const open = useCallback((key: SettingKey) => setParams((p) => { const n = new URLSearchParams(p); n.set("setting", key); return n; }), [setParams]);
  const close = useCallback(() => setParams((p) => { const n = new URLSearchParams(p); n.delete("setting"); n.delete("tenant"); n.delete("section"); return n; }, { replace: true }), [setParams]);
  return { key: isKey(raw) ? raw : null, open, close };
}

/** Hidden (not closed) while a CVE, device or software drawer is open on top, so closing that one returns here. */
export function SettingsDrawer({ settingKey, onClose }: { settingKey: SettingKey | null; onClose: () => void }) {
  const t = useTranslations("settings");
  const { cve, device, software } = useDrawers();
  // keep the last body while the drawer slides out
  const [last, setLast] = useState<SettingKey | null>(settingKey);
  if (settingKey && settingKey !== last) setLast(settingKey);
  const shown = settingKey ?? last;
  return (
    <Sheet open={settingKey !== null && !cve && !device && !software} onOpenChange={(o) => { if (!o) onClose(); }}>
      <SheetContent className={`gap-3 overflow-y-auto p-4 ${shown ? WIDTH[shown] : MD}`}>
        {shown && (
          <>
            <SheetHeader className="gap-0.5 p-0 pe-8">
              <SheetTitle className="text-base leading-6">{t(`cards.${shown}`)}</SheetTitle>
              <SheetDescription className="text-xs leading-5">{t(`drawer.${shown}`)}</SheetDescription>
            </SheetHeader>
            <div className="flex min-w-0 flex-col gap-3">{BODY[shown]()}</div>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}
