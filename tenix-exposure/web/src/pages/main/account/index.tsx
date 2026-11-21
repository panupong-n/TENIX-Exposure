import { PageBreadcrumb } from "@/components/shared/page-breadcrumb";
import { PageMeta } from "@/components/shared/page-meta";
import { FormSkeleton } from "@/components/shared/skeletons";
import { useAuth } from "@/contexts/auth-context";
import { useTranslations } from "@/i18n";
import { useEffect } from "react";
import { useLocation } from "react-router";
import MfaCard from "./mfa-card";
import PasswordCard from "./password-card";

export default function AccountPage() {
  const t = useTranslations("account");
  const tRoles = useTranslations("roles");
  const { user } = useAuth();
  const { hash } = useLocation();

  useEffect(() => {
    if (hash === "#security") document.getElementById("security")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [hash]);

  if (!user) return <FormSkeleton fields={3} />;
  const rows: [string, string][] = [
    [t("profile.name"), user.name],
    [t("profile.email"), user.email],
    [t("profile.role"), user.soc ? tRoles("super_admin") : tRoles("member")],
    ...(user.tenants.length ? ([[t("profile.organization"), user.tenants.map((x) => `${x.name} (${tRoles(x.role)})`).join(", ")]] as [string, string][]) : []),
  ];

  return (
    <>
      <PageMeta title={`${t("title")} | 10CYBER Exposure`} description={t("description")} />
      <PageBreadcrumb pageTitle={t("title")} description={t("description")} />
      <div className="grid gap-3 lg:grid-cols-2 lg:items-start">
        <div className="space-y-3">
        <section className="rounded-xl border border-gray-200 bg-white p-3 sm:p-4 dark:border-gray-800 dark:bg-white/3">
          <h3 className="mb-3 text-lg font-semibold text-gray-800 dark:text-white/90">{t("profile.title")}</h3>
          <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2">
            {rows.map(([k, v]) => (
              <div key={k}>
                <dt className="text-xs text-gray-500 dark:text-gray-400">{k}</dt>
                <dd className="mt-1 text-sm break-all text-gray-800 dark:text-white/90">{v}</dd>
              </div>
            ))}
          </dl>
        </section>
        <section id="security" className="scroll-mt-24">
          <MfaCard />
        </section>
        </div>
        <PasswordCard />
      </div>
    </>
  );
}
