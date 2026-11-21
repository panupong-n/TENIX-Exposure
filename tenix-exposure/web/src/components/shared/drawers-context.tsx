import { createContext, useContext, useMemo, useCallback, type ReactNode } from "react";
import { useLocation, useNavigate, useSearchParams } from "react-router";

type Kind = "cve" | "device" | "software" | "fix";

interface Drawers {
  /** Opens the CVE (or CrowdStrike vulnerability) drawer on top of the current page. */
  openCve: (id: string) => void;
  /** Opens the device drawer on top of the current page. */
  openDevice: (aid: string) => void;
  /** Opens the software drawer (the key is the one the API returns for the item). */
  openSoftware: (key: string) => void;
  /** Opens the fix drawer (one remediation: what to do, the CVEs it closes, the devices to touch). */
  openFix: (id: string) => void;
  close: () => void;
  /** Set when this drawer was opened from another drawer: goes back to that one. */
  back: (() => void) | null;
  /** What the previous drawer was ("cve" or "device"), for the button label. */
  backKind: Kind | null;
  cve: string | null;
  device: string | null;
  software: string | null;
  fix: string | null;
}

const Ctx = createContext<Drawers | null>(null);

/**
 * Which drawer is open lives in the URL (?cve=..., ?device=..., ?software=... or ?fix=...), so it can be shared, reloaded and closed with the Back button.
 * Only one is open at a time: opening one from inside the other replaces it.
 */
export function DrawersProvider({ children }: { children: ReactNode }) {
  const [params, setParams] = useSearchParams();
  const cve = params.get("cve");
  const device = params.get("device");
  const software = params.get("software");
  const fix = params.get("fix");
  const navigate = useNavigate();
  const from = (useLocation().state as { drawerFrom?: Kind } | null)?.drawerFrom ?? null;
  const open: Kind | null = cve ? "cve" : device ? "device" : software ? "software" : fix ? "fix" : null;

  const show = useCallback((key: Kind | null, value?: string) => {
    // closing replaces the entry that opened the drawer, so Back leaves the page instead of reopening it
    const replace = key === null;
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      next.delete("cve");
      next.delete("device");
      next.delete("software");
      next.delete("fix");
      if (key && value) next.set(key, value);
      return next;
    }, { replace, state: key && open ? { drawerFrom: open } : null });
  }, [setParams, open]);

  const value = useMemo<Drawers>(
    () => ({ cve, device, software, fix, openFix: (id) => show("fix", id), openSoftware: (k) => show("software", k), openCve: (id) => show("cve", id), openDevice: (aid) => show("device", aid), close: () => show(null), back: open && from ? () => void navigate(-1) : null, backKind: open ? from : null }),
    [cve, device, software, fix, show, open, from, navigate],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useDrawers(): Drawers {
  const v = useContext(Ctx);
  if (!v) throw new Error("useDrawers must be used inside DrawersProvider");
  return v;
}
