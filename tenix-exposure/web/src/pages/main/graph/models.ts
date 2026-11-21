import { fit, sevColor, textW } from "@/components/shared/graph";
import type { Translator } from "@/i18n";
import type { DCol, DLink, DNode } from "./diagram";
import type { EntityType } from "./state";
import type { FixData, FixNode, FocusData, Other, Part, RightNode } from "./types";

// Tier colours are the brand steps (design-spec 4.1 / 6); hosts are neutral; severity colours appear only on CVE nodes.
export const P1 = "#2A31D8", P2 = "#7592FF", HOSTS = "#667085";

export interface Model {
  /** called with a node's entity: drills into it (dim = a host group / OS / site value) */
  go: (kind: EntityType | "dim", id: string, label: string) => void;
  other: () => void;
  noFix: () => void;
  center: () => void;
  t: Translator;
  n: (v: number) => string;
  /** "รายการ P1" or "รายการ" */
  unit: string;
  dim: string;
}

export const isNoFix = (x: { id?: string | null; none?: boolean }) => x.none === true || !x.id || x.id === "none" || x.id === "-1";
const trunc = (s: string, w: number, value?: string) => fit(s, Math.max(40, w - 30 - (value ? textW(value) : 0)));
const pct = (hosts: number, total?: number) => (total && total >= hosts ? Math.round((hosts / total) * 100) : null);

function rightNodes(m: Model, d: { mode?: "dim" | "host"; right?: RightNode[]; rightOther?: Other | null }, w: number): DNode[] {
  const { t, n } = m;
  const host = d.mode === "host";
  const right = d.right ?? [];
  const max = Math.max(1, ...right.map((r) => (host ? r.n : r.hosts) ?? 0));
  const out: DNode[] = right.map((r, i) => {
    const v = (host ? r.n : r.hosts) ?? 0;
    const value = host ? t("node.findings", { count: n(v) }) : t("node.hosts", { count: n(v) });
    const p = host ? null : pct(v, r.total);
    const sub = host ? r.sub : p !== null ? t("node.share", { percent: p, total: n(r.total!) }) : undefined;
    return {
      key: `R${i}`, label: trunc(r.label, w, value), value, sub: sub && trunc(sub, w - 20), segs: [{ v, color: HOSTS }], barMax: max, barW: host ? w - 20 : w - 20 - 100,
      aria: host ? t("node.ariaFindings", { name: r.label, findings: n(v) }) : p !== null ? t("node.ariaHosts", { name: r.label, hosts: n(v), total: n(r.total!) }) : t("node.ariaHostsOnly", { name: r.label, hosts: n(v) }),
      tip: [r.label, host ? r.sub : sub, host && r.inet ? t("node.internet") : null, host ? null : t("node.drillHosts")].filter(Boolean).join("\n"),
      onClick: () => m.go(host ? "host" : "dim", r.id, r.label),
    };
  });
  const o = d.rightOther;
  if (o && o.count > 0) {
    const v = o.hosts ?? o.n ?? 0;
    out.push({
      key: "RO", label: trunc(host ? t("node.otherHosts", { count: n(o.count) }) : t("node.otherDim", { count: n(o.count) }), w, n(v)), value: host ? t("node.findings", { count: n(v) }) : t("node.hosts", { count: n(v) }),
      dashed: true, aria: t("node.otherToast"), tip: t("node.otherToast"), onClick: m.other,
    });
  }
  return out;
}

/** Fixes (left, ranked) -> host groups or, once one group is chosen, hosts (right). */
export function fixModel(d: FixData, W: number, m: Model): { cols: DCol[]; links: DLink[]; label: string } {
  const { t, n } = m;
  const wl = Math.min(400, W * 0.4), wr = Math.min(300, W * 0.3);
  const max = Math.max(1, ...d.left.map((x) => x.findings));
  const left: DNode[] = d.left.map((x: FixNode, i) => {
    const none = isNoFix(x);
    const name = none ? t("node.noFix") : x.label;
    const value = t("node.findings", { count: n(x.findings) });
    const p1 = x.p1 ?? x.findings, p2 = x.p2 ?? Math.max(0, x.findings - p1);
    return {
      key: `L${i}`, label: trunc(name, wl, value), value, sub: t("node.hosts", { count: n(x.hosts) }), dashed: none, segs: [{ v: p1, color: P1 }, { v: p2, color: P2 }], barMax: max, barW: wl - 20 - 70,
      aria: t("node.aria", { name, hosts: n(x.hosts), findings: n(x.findings) }),
      tip: [name, x.product, t("node.tipLine", { hosts: n(x.hosts), findings: n(x.findings), p1: n(x.p1 ?? 0) }), x.kev ? t("node.tipKev", { kev: n(x.kev), inet: n(x.inet ?? 0) }) : null, none ? null : t("node.drill")].filter(Boolean).join("\n"),
      onClick: none ? m.noFix : () => m.go("fix", x.id, x.label),
    };
  });
  const o = d.leftOther;
  if (o && o.count > 0) {
    const value = t("node.findings", { count: n(o.findings ?? 0) });
    left.push({ key: "LO", label: trunc(t("node.otherFixes", { count: n(o.count) }), wl, value), value, dashed: true, aria: t("node.otherToast"), tip: t("node.otherToast"), onClick: m.other });
  }
  const right = rightNodes(m, d, wr);
  const rn = d.right?.length ?? 0;
  const key = (side: "L" | "R", i: number, len: number, hasOther: boolean) => (i < len ? `${side}${i}` : hasOther ? `${side}O` : "");
  const links = (d.links ?? []).flatMap(([li, ri, v]) => {
    const a = key("L", li, d.left.length, !!(o && o.count > 0)), b = key("R", ri, rn, !!(d.rightOther && d.rightOther.count > 0));
    return a && b ? [{ a, b, v, lazy: d.mode === "host" }] : [];
  });
  const host = d.mode === "host";
  return { cols: [{ x: 0, w: wl, nodes: left }, { x: W - wr, w: wr, nodes: right }], links, label: host ? t("svgAria.fixHost") : t("svgAria.fix", { dim: m.dim }) };
}

/** The parts of one entity (left), the entity (centre), where it is: groups or hosts (right). */
export function focusModel(d: FocusData, W: number, m: Model): { cols: DCol[]; links: DLink[]; label: string } {
  const { t, n } = m;
  const c = d.center;
  const hasRight = d.type !== "host";
  const wl = Math.min(330, W * 0.34), wc = Math.min(250, W * 0.27), wr = Math.min(270, W * 0.28);
  const parts = d.left ?? [];
  const max = Math.max(1, ...parts.map((p) => p.n ?? 0));
  const left: DNode[] = parts.map((p: Part, i) => {
    const bars = p.kind === "cve" || d.type === "host";
    const value = p.n != null && bars ? (p.kind === "cve" ? t("node.hosts", { count: n(p.n) }) : t("node.findings", { count: n(p.n) })) : undefined;
    const none = p.kind === "fix" && isNoFix(p);
    const name = none ? t("node.noFix") : p.label;
    const sub = [p.kev ? t("node.kev") : null, p.sub].filter(Boolean).join(" · ");
    return {
      key: `L${i}`, label: trunc(name, wl, value ?? (bars ? undefined : sub)), value, sub: sub ? trunc(sub, wl - 20) : undefined, dot: p.sev ? sevColor(p.sev) : undefined, dashed: none,
      segs: bars ? [{ v: p.n ?? 0, color: HOSTS }] : undefined, barMax: max, barW: wl - 20,
      aria: value ? `${name}: ${value}` : name, tip: [name, p.sub, p.sev ? `${p.sev}${p.kev ? " · CISA KEV" : ""}${p.tier ? ` · ${p.tier}` : ""}` : null, none ? null : t("node.drill")].filter(Boolean).join("\n"),
      onClick: none ? m.noFix : () => m.go(p.kind, p.id, p.label),
    };
  });
  const lo = d.leftOther;
  if (lo && lo.count > 0) left.push({ key: "LO", label: trunc(d.type === "host" ? t("node.otherFixesHost", { count: n(lo.count) }) : t("node.otherCves", { count: n(lo.count) }), wl), dashed: true, aria: t("node.otherToast"), tip: t("node.otherToast"), onClick: m.other });
  const kev = typeof c.kev === "number" ? c.kev : 0;
  const centre: DNode = {
    key: "C0", label: c.label, selected: true, dot: c.sev ? sevColor(c.sev) : undefined,
    lines: [
      { text: fit(c.label, wc - 40), bold: true }, { text: fit(c.sub ?? "", wc - 24) },
      { text: t("node.hosts", { count: n(c.hosts ?? 0) }) }, { text: `${n(c.findings ?? 0)} ${m.unit}${kev ? ` · KEV ${n(kev)}` : ""}` },
    ],
    aria: t("node.openCenter", { name: c.label }), tip: [c.label, c.sub, t("node.openCenter", { name: c.label })].filter(Boolean).join("\n"), onClick: m.center,
  };
  const cols: DCol[] = [{ x: 0, w: wl, nodes: left }, { x: hasRight ? (W - wc) / 2 : W - wc, w: wc, h: 96, nodes: [centre] }];
  const right = hasRight ? rightNodes(m, d, wr) : [];
  if (right.length) cols.push({ x: W - wr, w: wr, nodes: right });
  const links: DLink[] = [
    ...parts.map((p, i) => ({ a: `L${i}`, b: "C0", v: p.n ?? 1 })),
    ...(lo && lo.count > 0 ? [{ a: "LO", b: "C0", v: lo.n ?? 1, dashed: true }] : []),
    ...(d.right ?? []).map((r, i) => ({ a: "C0", b: `R${i}`, v: (d.mode === "host" ? r.n : r.hosts) ?? 1 })),
    ...(d.rightOther && d.rightOther.count > 0 ? [{ a: "C0", b: "RO", v: d.rightOther.hosts ?? d.rightOther.n ?? 1, dashed: true }] : []),
  ];
  return { cols, links, label: t("svgAria.focus", { name: c.label }) };
}
