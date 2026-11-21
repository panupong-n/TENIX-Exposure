import { Badge } from "@/components/ui/badge";
import { useTranslations } from "@/i18n";
import { StateChip } from "./common";
import type { Tenant } from "./dialogs";

/** The CrowdStrike / LINE / users chips of an organization, the same in the list and in the detail. */
export function Chips({ x }: { x: Tenant }) {
  const t = useTranslations("tenants2.chips");
  const tt = useTranslations("tenants");
  const { connections, unconnected } = x.falcon;
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {x.state === "no_cids" ? (
        <Badge size="sm" color="warning" className="[text-shadow:none]">{t("csNone")}</Badge>
      ) : (
        <>
          {connections > 0 && <Badge size="sm" color="gray" className="[text-shadow:none]">{t("cs", { count: connections })}</Badge>}
          <StateChip state={x.state} />
          {connections > 0 && unconnected > 0 && <Badge size="sm" color="warning" className="[text-shadow:none]">{t("csUnconnected", { count: unconnected })}</Badge>}
        </>
      )}
      {x.line.sources + x.line.destinations === 0
        ? <Badge size="sm" color="gray" className="[text-shadow:none]">{t("lineNone")}</Badge>
        : <Badge size="sm" color="info" className="[text-shadow:none]">{t("line", { sources: x.line.sources, groups: x.line.destinations })}</Badge>}
      <Badge size="sm" color="gray" className="[text-shadow:none]">{tt("usersCount", { count: x.users })}</Badge>
    </div>
  );
}
