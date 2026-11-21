import { useTranslations } from "@/i18n";
import { SEVERITIES, SEVERITY_COLOR, type Severity } from "@/lib/chart";
import { cn } from "@/utils";
import { useEffect, useRef, useState, type KeyboardEvent } from "react";

export const sevColor = (s: string) => SEVERITY_COLOR[(SEVERITIES as readonly string[]).includes(s) ? (s as Severity) : "NONE"];
export const curve = (x1: number, y1: number, x2: number, y2: number) => {
  const m = (x1 + x2) / 2;
  return `M${x1},${y1} C${m},${y1} ${m},${y2} ${x2},${y2}`;
};
export const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v));

// Truncate to a pixel width by measuring the real 13px text (Thai and Latin differ a lot); the full text stays in <title>.
let ctx: CanvasRenderingContext2D | null | undefined;
const widths = new Map<string, number>();
export const textW = (s: string) => {
  if (ctx === undefined) {
    try {
      ctx = document.createElement("canvas").getContext("2d");
      if (ctx) ctx.font = `13px ${getComputedStyle(document.body).fontFamily}`;
    } catch { ctx = null; }
  }
  if (!ctx) return s.length * 6.8;
  let w = widths.get(s);
  if (w === undefined) { w = ctx.measureText(s).width; widths.set(s, w); }
  return w;
};
export const fit = (s: string, max: number) => {
  if (textW(s) <= max) return s;
  let n = s.length;
  while (n > 1 && textW(`${s.slice(0, n)}…`) > max) n--;
  return `${s.slice(0, n)}…`;
};

/** Width of an element, kept up to date while the window or drawer is resized. */
export function useWidth() {
  const ref = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setWidth(Math.round(e.contentRect.width)));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, width] as const;
}

interface PillProps {
  x: number; y: number; w: number; h?: number; label: string; full?: string; sub?: string; color?: string;
  dim?: boolean; lit?: boolean; sel?: boolean; dashed?: boolean; role?: "link" | "button"; onClick?: () => void; onEnter?: () => void; onLeave?: () => void;
}
/** One node: a rounded box with a severity dot, a label and an optional count on the right. */
function Pill({ x, y, w, h = 24, label, full, sub, color, dim, lit, sel, dashed, role = "link", onClick, onEnter, onLeave }: PillProps) {
  const key = (e: KeyboardEvent) => { if (onClick && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); onClick(); } };
  // a touch tap also fires mouse-enter and no leave, which would leave a node stuck as "hovered"
  const mouse = (fn?: () => void) => (e: { pointerType: string }) => { if (e.pointerType !== "touch") fn?.(); };
  return (
    <g
      transform={`translate(${x},${y})`}
      className={cn("transition-opacity duration-200 outline-none", onClick && "cursor-pointer", dim && "opacity-25")}
      onClick={onClick} onKeyDown={key} onPointerEnter={mouse(onEnter)} onPointerLeave={mouse(onLeave)} onFocus={onEnter} onBlur={onLeave}
      role={onClick ? role : undefined} aria-pressed={onClick && role === "button" ? !!sel : undefined} tabIndex={onClick ? 0 : undefined}
    >
      <title>{full ?? label}</title>
      <rect
        width={w} height={h} rx={6} strokeWidth={sel ? 2 : lit ? 1.5 : 1} strokeDasharray={dashed ? "3 3" : undefined}
        className={cn(sel ? "fill-brand-50" : "fill-white dark:fill-gray-900", lit || sel ? "stroke-brand-500 dark:stroke-brand-400" : "stroke-gray-200 dark:stroke-gray-700")}
      />
      {color && <circle cx={10} cy={h / 2} r={3.5} fill={color} />}
      <text x={color ? 20 : 9} y={h / 2} dy=".35em" className="fill-gray-800 text-[13px] dark:fill-white/90">{label}</text>
      {sub && <text x={w - 8} y={h / 2} dy=".35em" textAnchor="end" className="fill-gray-500 text-[13px] tabular-nums dark:fill-gray-400">{sub}</text>}
    </g>
  );
}

function Link({ d, color, opacity = 0.5, width = 1.2, delay, still }: { d: string; color: string; opacity?: number; width?: number; delay?: number; still?: boolean }) {
  return <path d={d} pathLength={1} fill="none" stroke={color} strokeWidth={width} strokeOpacity={opacity} className={still ? undefined : "graph-link"} style={still ? undefined : { animationDelay: `${delay ?? 0}ms` }} />;
}

// ---------------------------------------------------------------------------------------------
// Device tree: device -> products -> worst CVEs of each product

export interface HostTreeData {
  hostname: string | null; platform: string | null; total: number;
  products: { name: string | null; total: number; severity: string; cves: { cveId: string; severity: string }[]; more: number }[];
  productsMore: number;
}

export function HostTree({ data, onOpenCve }: { data: HostTreeData; onOpenCve: (cve: string) => void }) {
  const t = useTranslations("graph");
  const tc = useTranslations("common");
  const [ref, width] = useWidth();
  const [hover, setHover] = useState<string | null>(null);
  const W = Math.max(width, 480);
  const wd = clamp(W * 0.22, 120, 180), wp = clamp(W * 0.3, 150, 270), wc = clamp(W * 0.26, 120, 190);
  const xd = 0, xp = (W - wd - wp - wc) / 2 + wd, xc = W - wc;
  const LEAF = 24, GAP = 10, PAD = 4;

  let y = PAD;
  const blocks = data.products.map((p) => {
    const leaves = p.cves.length + (p.more > 0 ? 1 : 0);
    const top = y;
    y += leaves * LEAF + GAP;
    return { p, top, leaves, mid: top + (leaves * LEAF) / 2 };
  });
  const moreY = y;
  const height = y + (data.productsMore > 0 ? LEAF : 0) + PAD - GAP;
  const mid = blocks.length ? (blocks[0].mid + blocks[blocks.length - 1].mid) / 2 : height / 2;
  const unknown = t("unknownProduct");

  return (
    <div ref={ref} className="w-full overflow-x-auto">
      {width > 0 && (
        <svg width={W} height={Math.max(height, 60)} role="group" aria-label={t("hostAria")} className="block">
          {blocks.map(({ p, top, mid: pm }, bi) => {
            const color = sevColor(p.severity);
            const pk = `p:${bi}`;
            const dimP = hover !== null && hover !== "d" && hover !== pk && !hover.startsWith(`${pk}:`);
            return (
              <g key={pk} className={cn("transition-opacity duration-200", dimP && "opacity-25")}>
                <Link d={curve(xd + wd, mid, xp, pm)} color={color} opacity={hover === pk ? 0.95 : 0.5} width={hover === pk ? 2 : 1.2} delay={bi * 60} />
                {p.cves.map((c, ci) => {
                  const ly = top + ci * LEAF + LEAF / 2;
                  return <Link key={c.cveId} d={curve(xp + wp, pm, xc, ly)} color={sevColor(c.severity)} opacity={hover === `${pk}:${ci}` ? 0.95 : 0.45} delay={200 + bi * 60 + ci * 30} />;
                })}
                {p.more > 0 && <Link d={curve(xp + wp, pm, xc, top + p.cves.length * LEAF + LEAF / 2)} color="#98A2B3" opacity={0.3} delay={300 + bi * 60} />}
              </g>
            );
          })}

          <Pill x={xd} y={mid - 17} w={wd} h={34} lit={hover === "d"} label={fit(data.hostname ?? tc("unnamedDevice"), wd - 20)} full={data.hostname ?? tc("unnamedDevice")}
            sub={undefined} onEnter={() => setHover("d")} onLeave={() => setHover(null)} />
          <text x={xd + 9} y={mid + 28} className="fill-gray-500 text-xs dark:fill-gray-400">{fit(`${data.platform ?? "–"} · ${t("findingsCount", { count: data.total })}`, wd + 20)}</text>

          {blocks.map(({ p, top, mid: pm }, bi) => {
            const pk = `p:${bi}`;
            const dimP = hover !== null && hover !== "d" && hover !== pk && !hover.startsWith(`${pk}:`);
            return (
              <g key={pk}>
                <Pill x={xp} y={pm - 12} w={wp} color={sevColor(p.severity)} lit={hover === pk} dim={dimP} label={fit(p.name ?? unknown, wp - 60)} full={p.name ?? unknown} sub={String(p.total)}
                  onEnter={() => setHover(pk)} onLeave={() => setHover(null)} />
                {p.cves.map((c, ci) => (
                  <Pill key={c.cveId} x={xc} y={top + ci * LEAF + 1} w={wc} h={LEAF - 2} color={sevColor(c.severity)} label={c.cveId} lit={hover === `${pk}:${ci}`}
                    dim={hover !== null && hover !== "d" && hover !== pk && hover !== `${pk}:${ci}`}
                    onClick={() => onOpenCve(c.cveId)} onEnter={() => setHover(`${pk}:${ci}`)} onLeave={() => setHover(null)} />
                ))}
                {p.more > 0 && <Pill x={xc} y={top + p.cves.length * LEAF + 1} w={wc} h={LEAF - 2} dashed label={t("more", { count: p.more })} dim={dimP} />}
              </g>
            );
          })}
          {data.productsMore > 0 && <Pill x={xp} y={moreY} w={wp} h={LEAF - 2} dashed label={t("moreProducts", { count: data.productsMore })} />}
        </svg>
      )}
    </div>
  );
}
