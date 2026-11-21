import AppHeader from "@/components/layout/app-layout/header";
import CveSheet from "@/components/shared/cve-sheet";
import FixSheet from "@/components/shared/fix-sheet";
import DeviceSheet from "@/components/shared/device-sheet";
import SoftwareSheet from "@/components/shared/software-sheet";
import { DrawersProvider, useDrawers } from "@/components/shared/drawers-context";
import { OrgSettingDrawers } from "@/pages/main/settings/org-settings";
import { ScrollToTop } from "@/components/shared/scroll-to-top";
import { useTranslations } from "@/i18n";
import React from "react";
import { Outlet, useLocation } from "react-router";

// The previous sidebar layout is kept in ./sidebar (not used): the menu now lives in the header.
/** The two drawers every page can open (a CVE or a device); which one is open is kept in the URL. */
function Drawers() {
  const { cve, device, software, fix, close } = useDrawers();
  return (
    <>
      <CveSheet id={cve} onClose={close} />
      <DeviceSheet aid={device} onClose={close} />
      <SoftwareSheet id={software} onClose={close} />
      <FixSheet id={fix} onClose={close} />
    </>
  );
}

export default function AppLayout({ children }: { children?: React.ReactNode }) {
  const { pathname } = useLocation();
  const t = useTranslations("common");
  return (
    <DrawersProvider>
    <div className="min-h-svh">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:start-2 focus:top-2 focus:z-50 focus:rounded focus:bg-white focus:px-3 focus:py-1.5 focus:text-sm focus:text-gray-900 focus:shadow">{t("skipToContent")}</a>
      <AppHeader />
      <main id="main" key={pathname} className="mx-auto w-full max-w-(--breakpoint-2xl) animate-page-in p-3 md:p-4">
        {children ?? <Outlet />}
      </main>
      <Drawers />
      <OrgSettingDrawers />
      <ScrollToTop />
    </div>
    </DrawersProvider>
  );
}
