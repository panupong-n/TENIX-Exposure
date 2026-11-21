import { curve } from "@/components/shared/graph";
import { useState, type KeyboardEvent } from "react";

export interface DNode {
  key: string; label: string; value?: string; sub?: string;
  /** stacked bar under the label: segment values against `barMax`, `barW` px wide */
  segs?: { v: number; color: string }[]; barMax?: number; barW?: number;
  dot?: string; dashed?: boolean; selected?: boolean;
  /** the centre node: free lines instead of label / bar */
  lines?: { text: string; bold?: boolean }[];
  aria: string; tip: string; onClick?: () => void;
}
export interface DCol { x: number; w: number; /** node height */ h?: number; nodes: DNode[] }
export interface DLink { a: string; b: string; v: number; /** drawn only while one end is hovered or focused */ lazy?: boolean; dashed?: boolean }

const NH = 42, GAP = 6, PAD = 4;
const HOVER = "#465FFF", CALM = "#98A2B3";

/** Bipartite / tripartite drawing: columns of nodes, curved links whose width is the host count. Hand-written SVG; the model (nodes, links) comes from models.ts. */
export function Diagram({ cols, links, width, label }: { cols: DCol[]; links: DLink[]; width: number; label: string }) {
  const [hover, setHover] = useState<string | null>(null);
  // a clicked node is gone after the redraw and never sends "leave": forget the hover when the drawing changes
  const sig = cols.flatMap((c) => c.nodes.map((n) => n.key + n.label)).join("|");
  const [seen, setSeen] = useState(sig);
  if (seen !== sig) { setSeen(sig); setHover(null); }
  const colH = (c: DCol) => c.nodes.length * (c.h ?? NH) + Math.max(0, c.nodes.length - 1) * GAP;
  const H = Math.max(...cols.map(colH), 0) + PAD * 2;
  const pos = new Map<string, { x: number; y: number; w: number; h: number }>();
  for (const c of cols) {
    let y = PAD + (H - PAD * 2 - colH(c)) / 2;
    for (const n of c.nodes) { pos.set(n.key, { x: c.x, y, w: c.w, h: c.h ?? NH }); y += (c.h ?? NH) + GAP; }
  }
  const maxV = Math.max(1, ...links.map((l) => l.v));
  const lw = (v: number) => 1.2 + 9 * Math.pow(v / maxV, 0.6);
  const drawn = links.filter((l) => pos.has(l.a) && pos.has(l.b));
  const near = new Set<string>();
  if (hover) { near.add(hover); for (const l of drawn) if (l.a === hover || l.b === hover) { near.add(l.a); near.add(l.b); } }

  const key = (n: DNode) => (e: KeyboardEvent<SVGGElement>) => {
    if ((e.key === "Enter" || e.key === " ") && n.onClick) { e.preventDefault(); n.onClick(); return; }
    const move = { ArrowDown: [0, 1], ArrowUp: [0, -1], ArrowRight: [1, 0], ArrowLeft: [-1, 0] }[e.key];
    if (!move) return;
    e.preventDefault();
    const svg = e.currentTarget.ownerSVGElement!;
    const ci = cols.findIndex((c) => c.nodes.includes(n));
    if (move[0]) { // next column that has nodes
      for (let j = ci + move[0]; j >= 0 && j < cols.length; j += move[0]) {
        const to = svg.querySelectorAll<SVGGElement>(`[data-col="${j}"]`);
        if (to.length) { to[Math.min(to.length - 1, cols[ci].nodes.indexOf(n))]?.focus(); break; }
      }
    } else {
      const list = svg.querySelectorAll<SVGGElement>(`[data-col="${ci}"]`);
      list[Math.max(0, Math.min(list.length - 1, cols[ci].nodes.indexOf(n) + move[1]))]?.focus();
    }
  };

  return (
    <svg width={width} height={H} viewBox={`0 0 ${width} ${H}`} role="group" aria-label={label} className="block max-w-full overflow-visible">
      {drawn.map((l) => {
        const a = pos.get(l.a)!, b = pos.get(l.b)!;
        const on = hover !== null && (l.a === hover || l.b === hover);
        const opacity = on ? 0.8 : hover !== null ? 0.07 : l.lazy ? 0 : 0.38;
        return (
          <path key={`${l.a}>${l.b}`} d={curve(a.x + a.w, a.y + a.h / 2, b.x, b.y + b.h / 2)} fill="none" stroke={on ? HOVER : CALM} strokeOpacity={opacity}
            strokeWidth={lw(l.v)} strokeDasharray={l.dashed ? "5 4" : undefined} className="transition-[stroke-opacity] duration-100 motion-reduce:transition-none" />
        );
      })}
      {cols.map((c, ci) => c.nodes.map((n) => {
        const p = pos.get(n.key)!;
        const bar = n.segs && n.barMax ? n.segs : null;
        const textX = n.dot ? 24 : 10;
        const ty = n.lines ? 0 : bar ? 16 : p.h / 2 + 4.5;
        return (
          <g
            key={n.key} data-col={ci} transform={`translate(${p.x},${p.y})`} role={n.onClick ? "button" : "group"} tabIndex={0} aria-label={n.aria}
            opacity={hover !== null && !near.has(n.key) ? 0.5 : 1} className="group/node cursor-pointer outline-none"
            onClick={n.onClick} onKeyDown={key(n)}
            onPointerEnter={(e) => { if (e.pointerType !== "touch") setHover(n.key); }} onPointerLeave={(e) => { if (e.pointerType !== "touch") setHover(null); }}
            onFocus={() => setHover(n.key)} onBlur={() => setHover(null)}
          >
            <title>{n.tip}</title>
            <rect
              width={p.w} height={p.h} rx={n.lines ? 10 : 8} strokeDasharray={n.dashed ? "4 3" : undefined}
              className={n.selected ? "fill-brand-50 stroke-brand-500 stroke-[1.5]" : `${n.dashed ? "fill-gray-50" : "fill-white"} stroke-gray-200 group-hover/node:stroke-brand-400 group-focus-visible/node:stroke-brand-500 group-focus-visible/node:stroke-2`}
            />
            {n.dot && <circle cx={n.lines ? p.w - 18 : 14} cy={n.lines ? 22 : bar ? 16 : p.h / 2} r={n.lines ? 5 : 4.5} fill={n.dot} />}
            {n.lines
              ? n.lines.map((ln, i) => (
                <text key={i} x={12} y={[22, 40, 64, 82][i] ?? 82} className={ln.bold ? "fill-gray-900 text-[13px] font-semibold" : i === 1 ? "fill-gray-500 text-[11.5px]" : "fill-gray-700 text-[12.5px] tabular-nums"}>{ln.text}</text>
              ))
              : <>
                <text x={textX} y={ty} className="fill-gray-800 text-[13px]">{n.label}</text>
                {n.value && <text x={p.w - 10} y={ty} textAnchor="end" className="fill-gray-700 text-[12.5px] font-medium tabular-nums">{n.value}</text>}
              </>}
            {bar && (() => {
              const w = n.barW ?? p.w - 20, sc = w / n.barMax!;
              let x = 10;
              return (
                <>
                  <rect x={10} y={22} width={w} height={5} rx={2.5} className="fill-gray-100" />
                  {bar.map((s, i) => { const sw = s.v > 0 ? Math.max(2, s.v * sc) : 0; const r = <rect key={i} x={x} y={22} width={sw} height={5} rx={2.5} fill={s.color} />; x += sw; return r; })}
                </>
              );
            })()}
            {n.sub && !n.lines && <text x={p.w - 10} y={bar ? 37 : ty} textAnchor="end" className="fill-gray-500 text-[11.5px] tabular-nums">{n.sub}</text>}
          </g>
        );
      }))}
    </svg>
  );
}
