import { useApi } from "@/hooks/use-api";
import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
import { useAuth } from "./auth-context";

export interface Org {
  id: string;
  name: string;
  /** the viewer's role in it */
  role: "super_admin" | "admin" | "operator";
  // the rest is only sent to super admins
  cids?: string[];
  users?: number;
  admins?: number;
  state?: "no_cids" | "no_connection" | "not_synced" | "complete" | "partial" | "failed";
  dataAsOf?: number | null;
}
interface OrgValue {
  orgs: Org[];
  loading: boolean;
  /** The organization every page shows: the only one the viewer has, or the one they picked. */
  orgId: string | null;
  /** True once the viewer has chosen an organization themselves (remembered in this browser). */
  picked: boolean;
  setOrgId: (id: string) => void;
  reloadOrgs: () => void;
  /** Adds the tenantId query parameter. null while the viewer has no organization (yet). */
  scoped: (path: string) => string | null;
}

const OrgContext = createContext<OrgValue | null>(null);
const STORAGE = "tenix.org";

const readStored = () => {
  try {
    return localStorage.getItem(STORAGE);
  } catch {
    return null;
  }
};

export function OrgProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  const { data, loading, reload } = useApi<{ tenants: Org[] }>(user ? "/api/tenants" : null);
  const [picked, setPicked] = useState<string | null>(readStored);
  const orgs = useMemo(() => data?.tenants ?? [], [data]);

  // A stored choice that no longer exists falls back to the first organization.
  const orgId = orgs.find((o) => o.id === picked)?.id ?? orgs[0]?.id ?? null;

  const value = useMemo<OrgValue>(
    () => ({
      orgs, loading, orgId, picked: picked !== null, reloadOrgs: reload,
      setOrgId: (id) => {
        setPicked(id);
        try {
          localStorage.setItem(STORAGE, id);
        } catch {
          /* private mode: the choice just is not remembered */
        }
      },
      scoped: (path) => {
        if (!user) return null;
        if (!orgId) return null;
        return `${path}${path.includes("?") ? "&" : "?"}tenantId=${encodeURIComponent(orgId)}`;
      },
    }),
    [orgs, loading, orgId, picked, reload, user],
  );
  return <OrgContext.Provider value={value}>{children}</OrgContext.Provider>;
}

export function useOrg(): OrgValue {
  const v = useContext(OrgContext);
  if (!v) throw new Error("useOrg must be used inside OrgProvider");
  return v;
}

/** Whether the Overview is the all-organizations portfolio: asked for with ?view=all, or (design-spec: SOC lands there) a SOC user with several organizations who has not picked one yet and did not ask for ?view=org. */
export function usePortfolioView(search: string): boolean {
  const { user } = useAuth();
  const { orgs, picked } = useOrg();
  const view = new URLSearchParams(search).get("view");
  return !!user?.soc && (view === "all" || (view === null && orgs.length >= 2 && !picked));
}
