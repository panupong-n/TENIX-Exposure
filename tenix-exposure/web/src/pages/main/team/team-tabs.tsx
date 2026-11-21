// skeleton-ok: only tabs around TeamPanel and AuditPanel, which show their own skeletons
import { PageBreadcrumb } from "@/components/shared/page-breadcrumb";
import { PageMeta } from "@/components/shared/page-meta";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useTranslations } from "@/i18n";
import { useSearchParams } from "react-router";
import { AuditPanel } from "../audit";
import { TeamPanel } from ".";

/** /team for tenant admins: users, and the audit log of their tenants (the same people the server lets read /api/audit). The tab is ?tab=audit. */
export default function TeamTabsPage() {
  const t = useTranslations("team");
  const ta = useTranslations("audit");
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") === "audit" ? "audit" : "users";
  const select = (v: unknown) => setParams((p) => { const n = new URLSearchParams(p); if (v === "audit") n.set("tab", "audit"); else n.delete("tab"); return n; }, { replace: true });
  return (
    <>
      <PageMeta title={`${t("title")} | 10CYBER Exposure`} description={t("description")} />
      <PageBreadcrumb pageTitle={t("title")} description={t("description")} />
      <Tabs value={tab} onValueChange={select} className="min-w-0">
        <TabsList variant="line">
          <TabsTrigger value="users">{t("tabs.users")}</TabsTrigger>
          <TabsTrigger value="audit">{ta("title")}</TabsTrigger>
        </TabsList>
        <TabsContent value="users" className="min-w-0"><TeamPanel /></TabsContent>
        <TabsContent value="audit" className="min-w-0"><AuditPanel /></TabsContent>
      </Tabs>
    </>
  );
}
