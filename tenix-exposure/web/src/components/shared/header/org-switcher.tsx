import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { useAuth } from "@/contexts/auth-context";
import { useOrg, usePortfolioView } from "@/contexts/org-context";
import { CheckIcon, ChevronDownIcon } from "@/icons";
import { useTranslations } from "@/i18n";
import { cn } from "@/utils";
import { useState } from "react";
import { useLocation, useNavigate } from "react-router";

const pill = "inline-flex h-8 min-w-0 max-w-36 items-center gap-1.5 rounded-lg border border-gray-200 bg-white px-2 text-sm leading-5 font-medium text-gray-700 sm:max-w-48 sm:px-2.5 xl:max-w-64";

function BuildingIcon() {
  return (
    <svg aria-hidden="true" viewBox="0 0 24 24" width={16} height={16} fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" className="size-4 shrink-0 text-gray-500">
      <path d="M4 21V5a1 1 0 0 1 1-1h9a1 1 0 0 1 1 1v16M15 10h4a1 1 0 0 1 1 1v10M3 21h18M8 8h3M8 12h3M8 16h3" />
    </svg>
  );
}

/** Always shows the organization every page is about. With one it is a plain label; with several (or for SOC, who also get "All organizations" = the portfolio) it opens a list (searchable above 6). */
export default function OrgSwitcher() {
  const t = useTranslations("header");
  const { orgs, orgId, setOrgId, loading } = useOrg();
  const { user } = useAuth();
  const nav = useNavigate();
  const loc = useLocation();
  const soc = !!user?.soc;
  // the portfolio is the Overview with ?view=all; the pill says so instead of naming the last organization
  const portfolio = usePortfolioView(loc.search);
  const allView = loc.pathname === "/" && portfolio;
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const current = orgs.find((o) => o.id === orgId);
  if (loading && !orgs.length) return null;
  const name = allView ? t("allOrganizations") : current?.name ?? t("noOrganizations");

  if (orgs.length < 2 && !soc) {
    return (
      <div className={pill} title={name} aria-label={`${t("organization")}: ${name}`}>
        <BuildingIcon />
        <span className="min-w-0 truncate">{name}</span>
      </div>
    );
  }

  const shown = q.trim() ? orgs.filter((o) => o.name.toLowerCase().includes(q.trim().toLowerCase())) : orgs;
  return (
    <Popover open={open} onOpenChange={(v) => { setOpen(v); if (!v) setQ(""); }}>
      <PopoverTrigger
        title={name}
        aria-label={`${t("organization")}: ${name}`}
        className={cn(pill, "cursor-pointer hover:bg-gray-50 focus-visible:ring-4 focus-visible:ring-brand-500/20 focus-visible:outline-none")}
      >
        <BuildingIcon />
        <span className="min-w-0 truncate">{name}</span>
        <ChevronDownIcon aria-hidden="true" className="size-4 shrink-0 text-gray-500" />
      </PopoverTrigger>
      <PopoverContent align="end" sideOffset={6} className="w-72 max-w-[calc(100vw-1.5rem)] p-1.5 shadow-theme-lg ring-1 ring-gray-200">
        {orgs.length > 6 && (
          <Input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder={t("searchOrganization")} aria-label={t("searchOrganization")} className="mb-1.5 h-9" autoFocus />
        )}
        <ul role="listbox" aria-label={t("organization")} className="max-h-72 space-y-0.5 overflow-y-auto">
          {soc && !q.trim() && (
            <li role="option" aria-selected={allView}>
              <button
                type="button"
                onClick={() => { void nav("/?view=all"); setOpen(false); }}
                className={cn("flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-start text-sm leading-5 text-gray-700 hover:bg-gray-50 focus-visible:ring-4 focus-visible:ring-brand-500/20 focus-visible:outline-none", allView && "bg-brand-50 font-medium text-gray-900")}
              >
                <span className="min-w-0 flex-1 truncate">{t("allOrganizations")}</span>
                {allView && <CheckIcon aria-hidden="true" className="size-4 shrink-0 text-brand-500" />}
              </button>
            </li>
          )}
          {shown.map((o) => (
            <li key={o.id} role="option" aria-selected={o.id === orgId && !allView}>
              <button
                type="button"
                title={o.name}
                onClick={() => { setOrgId(o.id); setOpen(false); if (allView) void nav("/"); }}
                className={cn("flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-start text-sm leading-5 text-gray-700 hover:bg-gray-50 focus-visible:ring-4 focus-visible:ring-brand-500/20 focus-visible:outline-none", o.id === orgId && !allView && "bg-brand-50 font-medium text-gray-900")}
              >
                <span className="min-w-0 flex-1 truncate">{o.name}</span>
                {o.id === orgId && !allView && <CheckIcon aria-hidden="true" className="size-4 shrink-0 text-brand-500" />}
              </button>
            </li>
          ))}
          {shown.length === 0 && <li className="px-2 py-3 text-center text-sm leading-5 text-gray-500">{t("noOrganizationMatch")}</li>}
        </ul>
      </PopoverContent>
    </Popover>
  );
}
