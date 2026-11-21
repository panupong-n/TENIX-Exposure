import type { Completeness } from "@/components/shared/data-status";
import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router";

export type Lens = "fix" | "matrix" | "focus";
export type Dim = "group" | "os" | "site";
export type EntityType = "fix" | "product" | "cve" | "host";
export interface Focus { type: EntityType; id: string }

export interface GraphState {
  lens: Lens;
  tiers: string[];
  kev: boolean;
  internet: boolean;
  /** "" = the server's default (group when the inventory is synced, else os) */
  by: Dim | "";
  value: { dim: Dim; name: string } | null;
  top: "10" | "20";
  focus: Focus | null;
}

const LENSES: Lens[] = ["fix", "matrix", "focus"];
const TYPES: Record<string, EntityType> = { fix: "fix", product: "product", cve: "cve", host: "host", device: "host" }; // old /graph?focus=device:<aid> links
const DIMS: Dim[] = ["group", "os", "site"];

function parse(p: URLSearchParams): GraphState {
  const lens = p.get("lens") as Lens;
  const raw = p.get("focus") ?? "";
  const cut = raw.indexOf(":");
  const type = cut > 0 ? TYPES[raw.slice(0, cut)] : undefined;
  const by = p.get("by") as Dim;
  const dim = DIMS.find((d) => p.get(d));
  const tiers = (p.get("tier") ?? "P1").split(",").filter((x) => /^P[123]$/.test(x));
  return {
    lens: LENSES.includes(lens) ? lens : "fix",
    tiers: tiers.length ? tiers : ["P1"],
    kev: p.get("kev") === "1",
    internet: p.get("internet") === "1",
    by: DIMS.includes(by) ? by : "",
    value: dim ? { dim, name: p.get(dim)! } : null,
    top: p.get("top") === "20" ? "20" : "10",
    focus: type && raw.length > cut + 1 ? { type, id: raw.slice(cut + 1) } : null,
  };
}

/** The tier / KEV / internet / dimension filters as the API takes them (the same names as the URL). */
export function filterParams(s: GraphState, top = false): URLSearchParams {
  const q = new URLSearchParams({ tier: s.tiers.join(",") });
  if (s.kev) q.set("kev", "1");
  if (s.internet) q.set("internet", "1");
  if (s.by) q.set("by", s.by);
  if (s.value) q.set(s.value.dim, s.value.name);
  if (top && s.top === "20") q.set("top", "20");
  return q;
}

/** All state lives in the URL (shareable, Back-friendly). `go` replaces the entry (filters); `push` adds one (drilling), so Back is one level up. */
export function useGraphState() {
  const [params, setParams] = useSearchParams();
  const state = useMemo(() => parse(params), [params]);
  const go = useCallback((patch: Record<string, string | null>, push = false) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      for (const [k, v] of Object.entries(patch)) { if (v === null || v === "") next.delete(k); else next.set(k, v); }
      return next;
    }, { replace: !push });
  }, [setParams]);
  return { state, go };
}

/** Patches that clear the chosen entity and dimension value. */
export const CLEAR_DIM = { group: null, os: null, site: null } as const;
export const focusParam = (type: EntityType, id: string) => `${type}:${id}`;

/** What a payload from the server may carry beyond the fields this page needs; every field is optional. */
export interface Meta {
  dims?: Partial<Record<Dim, boolean>>;
  groups?: MetaItem[]; os?: MetaItem[]; sites?: MetaItem[];
  tiers?: Partial<Record<"P1" | "P2" | "P3", boolean>>;
  held?: number; falconTotal?: number;
  completeness?: Completeness;
}
export interface MetaItem { id: string; label: string; hosts: number }
