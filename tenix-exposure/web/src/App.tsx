import AppLayout from "@/components/layout/app-layout";
import { PageSkeleton } from "@/components/shared/skeletons";
import { useAuth } from "@/contexts/auth-context";
import { RedirectIfAuthed, RequireAuth, RequireRole } from "@/components/shared/require-auth";
import AccountPage from "@/pages/main/account";
import OverviewPage from "@/pages/main/dashboard/overview";
import EasmPage from "@/pages/main/easm";
import DevicesRoute from "@/pages/main/devices/route";
import NewsPage from "@/pages/main/news";
import SoftwarePage from "@/pages/main/software";
import { Error404Page } from "@/pages/main/pages";
import TeamTabsPage from "@/pages/main/team/team-tabs";
import VulnerabilitiesPage from "@/pages/main/vulnerabilities";
import { AcceptInvitePage, AuthLayout, ForgotPasswordPage, SignInPage } from "@/pages/others/auth";
import { lazy, Suspense } from "react";
import { Navigate, Route, Routes, useParams, useSearchParams } from "react-router";

const SettingsPage = lazy(() => import("@/pages/main/settings"));

/** The Graph Tree left the menu: it is the graph view of the device list (filters in the address are kept). */
function GraphRedirect() {
  const params = new URLSearchParams(useSearchParams()[0]);
  params.set("view", "graph");
  return <Navigate to={`/devices?${params}`} replace />;
}

/** Old CVE page links now open the drawer over the vulnerability list. */
function CveRedirect() {
  const { cve = "" } = useParams();
  return <Navigate to={`/vulnerabilities?cve=${encodeURIComponent(cve)}`} replace />;
}

/** Old page addresses now open a card of the Setting Center. */
function ToSetting({ setting }: { setting: string }) {
  return <Navigate to={`/settings?setting=${setting}`} replace />;
}

/** The old integrations page had tabs (never in the address): ?tab=line|email|feeds still lands on that card; the default is the LINE bot (CrowdStrike is set per organization now). */
function IntegrationsRedirect() {
  const tab = useSearchParams()[0].get("tab");
  return <ToSetting setting={tab === "line" || tab === "email" || tab === "feeds" ? tab : "line"} />;
}

/** /team: a super admin manages people in the Setting Center (keeps ?tenant=); a tenant admin has the two-tab page. */
function TeamRoute() {
  const { user } = useAuth();
  const tenant = useSearchParams()[0].get("tenant");
  if (!user?.soc) return <TeamTabsPage />;
  return <Navigate to={`/settings?setting=team${tenant ? `&tenant=${encodeURIComponent(tenant)}` : ""}`} replace />;
}

/** /audit: the audit log is a Setting Center card for a super admin and a tab of /team for a tenant admin. */
function AuditRoute() {
  const { user } = useAuth();
  return user?.soc ? <ToSetting setting="audit" /> : <Navigate to="/team?tab=audit" replace />;
}

// Template pages that are switched off live in ./disabled-routes.tsx
export default function App() {
  return (
    <Routes>
      {/* Signed-in area */}
      <Route element={<RequireAuth />}>
        <Route element={<AppLayout />}>
          <Route index element={<OverviewPage />} />
          <Route path="/executive" element={<Navigate to="/" replace />} />
          <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
          <Route path="/devices" element={<DevicesRoute />} />
          <Route path="/software" element={<SoftwarePage />} />
          <Route path="/external" element={<EasmPage />} />
          <Route path="/news" element={<NewsPage />} />
          <Route path="/graph" element={<GraphRedirect />} />
          <Route path="/vulnerabilities/:cve" element={<CveRedirect />} />
          <Route path="/account" element={<AccountPage />} />

          <Route element={<RequireRole gate="super" />}>
            <Route path="/settings" element={<Suspense fallback={<PageSkeleton />}><SettingsPage /></Suspense>} />
            <Route path="/integrations" element={<IntegrationsRedirect />} />
            <Route path="/tenants" element={<ToSetting setting="tenants" />} />
          </Route>
          <Route element={<RequireRole gate="manager" />}>
            <Route path="/team" element={<TeamRoute />} />
            <Route path="/audit" element={<AuditRoute />} />
          </Route>
        </Route>
      </Route>

      {/* Sign-in, invites */}
      <Route element={<AuthLayout />}>
        <Route element={<RedirectIfAuthed />}>
          <Route path="/signin" element={<SignInPage />} />
          <Route path="/forgot-password" element={<ForgotPasswordPage />} />
        </Route>
        <Route path="/accept-invite/:token" element={<AcceptInvitePage />} />
      </Route>

      <Route path="/error-404" element={<Error404Page />} />
      <Route path="*" element={<Error404Page />} />
    </Routes>
  );
}
