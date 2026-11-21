// skeleton-ok: only switches between two pages that each show their own skeleton
import GraphPage from "@/pages/main/graph";
import { useTranslations } from "@/i18n";
import { cn } from "@/utils";
import { Link, useSearchParams } from "react-router";
import DevicesPage from ".";

/** /devices with a view toggle: table (default) or graph (`?view=graph`, the old Graph Tree page). The toggle keeps the other filters. */
export default function DevicesRoute() {
  const t = useTranslations("devices.view");
  const [params] = useSearchParams();
  const graph = params.get("view") === "graph";
  const to = (view: "table" | "graph") => {
    const next = new URLSearchParams(params);
    next.delete("page");
    if (view === "graph") next.set("view", "graph"); else next.delete("view");
    return { search: next.size ? `?${next}` : "" };
  };
  const tab = (on: boolean) => cn("rounded-md px-3 py-1 text-sm font-medium", on ? "bg-white text-gray-900 shadow-theme-xs" : "text-gray-500 hover:text-gray-800");
  // same look as the By CVE / By fix tabs of Vulnerabilities; on the table view it sits inside the card, on the graph above it
  const toggle = (
    <nav aria-label={t("label")} className="flex w-fit items-center gap-0.5 rounded-lg bg-gray-100 p-0.5">
      <Link to={to("table")} replace aria-current={graph ? undefined : "page"} className={tab(!graph)}>{t("table")}</Link>
      <Link to={to("graph")} replace aria-current={graph ? "page" : undefined} className={tab(graph)}>{t("graph")}</Link>
    </nav>
  );
  return graph ? <><div className="mb-2">{toggle}</div><GraphPage /></> : <DevicesPage toggle={toggle} />;
}
