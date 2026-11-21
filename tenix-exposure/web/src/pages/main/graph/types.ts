import type { Completeness } from "@/components/shared/data-status";
import type { Dim, EntityType } from "./state";

export interface Other { count: number; findings?: number; p1?: number; hosts?: number; total?: number; n?: number }
/** One right-hand node: a host group / OS / site (mode "dim": hosts, total) or a host (mode "host": n, inet). */
export interface RightNode { id: string; label: string; sub?: string; hosts?: number; total?: number; n?: number; inet?: boolean }
export interface FixNode { id: string; label: string; product?: string; hosts: number; findings: number; p1?: number; p2?: number; kev?: number; inet?: number }
export interface Totals { hosts?: number; findings?: number; fixes?: number; products?: number }

export interface FixData {
  lens?: "fix"; by?: Dim; mode?: "dim" | "host"; totals?: Totals;
  left: FixNode[]; leftOther?: Other | null; right?: RightNode[]; rightOther?: Other | null; links?: [number, number, number][];
  completeness?: Completeness;
}
export interface MatrixData {
  lens?: "matrix"; by?: Dim; totals?: Totals;
  cols: RightNode[]; colOther?: Other | null;
  rows: { id: string; label: string; hosts: number; findings?: number; fix?: { id: string; title?: string } | boolean | null; cells: number[] }[];
  rowsOther?: { count: number } | null;
  completeness?: Completeness;
}
export interface Part { kind: EntityType; id: string; label: string; sub?: string; n?: number; sev?: string; kev?: boolean; tier?: string }
export interface FocusData {
  lens?: "focus"; type: EntityType; mode?: "dim" | "host"; totals?: Totals;
  center: { id: string; label: string; sub?: string; hosts?: number; findings?: number; cves?: number; kev?: boolean | number; inetHosts?: number; inet?: boolean; sev?: string; exprt?: string; tier?: string };
  left?: Part[]; leftOther?: Other | null; right?: RightNode[]; rightOther?: Other | null;
  completeness?: Completeness;
}
export type GraphData = FixData | MatrixData | FocusData;

/** One row of /graph/list. Hosts: aid, name, group, os, inet, n, kev, p1, sev. Fixes and products: id, name, sub, hosts, findings. Host CVEs: id, name, sub, sev, kev, tier. */
export interface ListRow {
  id?: string; aid?: string; name?: string; label?: string; sub?: string; group?: string; os?: string; inet?: boolean;
  n?: number; kev?: number | boolean; p1?: number; sev?: string; tier?: string; hosts?: number; findings?: number;
}
export interface ListData { total: number; page?: number; rows: ListRow[] }
export interface SearchItem { kind: EntityType; id: string; label: string; sub?: string }

export const shapeOf = (d: GraphData): "fix" | "matrix" | "focus" => ("cols" in d ? "matrix" : "center" in d ? "focus" : "fix");

/** The server may send a null label (a fix without a title): fall back to the product, then the id, so a node never has an empty name. */
export function fillLabels<T extends GraphData>(d: T): T {
  const fix = (x: { label?: string | null; product?: string | null; sub?: string | null; id?: string } | undefined) => { if (x && !x.label) x.label = x.product ?? x.sub ?? x.id ?? ""; };
  if ("cols" in d) { d.cols.forEach(fix); d.rows.forEach(fix); }
  else if ("center" in d) { fix(d.center); d.left?.forEach(fix); d.right?.forEach(fix); }
  else { d.left.forEach(fix); d.right?.forEach(fix); }
  return d;
}
