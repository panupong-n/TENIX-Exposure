import { sevColor } from "@/components/shared/graph";
import { useLocale, useTranslations } from "@/i18n";
import { formatNumber } from "@/utils/format";
import type { ReactNode } from "react";
import { isNoFix, P1, P2, type Model } from "./models";
import type { FixData, FocusData, MatrixData } from "./types";

const card = "w-full rounded-lg border border-gray-200 bg-white px-2.5 py-2 text-start hover:border-brand-300 focus-visible:ring-4 focus-visible:ring-brand-500/20 focus-visible:outline-none";
const chip = "inline-flex h-[18px] items-center rounded-md bg-gray-100 px-1.5 text-[11.5px] font-medium whitespace-nowrap text-gray-700";

function Head({ left, right }: { left: ReactNode; right?: ReactNode }) {
  return <div className="flex items-start justify-between gap-2 text-[13.5px] font-medium"><span className="min-w-0 break-words">{left}</span>{right && <span className="shrink-0 tabular-nums">{right}</span>}</div>;
}

/** Phone layout (< 760 px): the same ranked numbers as the drawn graph, as tappable cards. No SVG, no hover. */
export function Cards({ data, m }: { data: FixData | MatrixData | FocusData; m: Model }) {
  const t = useTranslations("graphView");
  const locale = useLocale();
  const n = (v: number) => formatNumber(v, locale);
  if ("cols" in data) {
    return (
      <div className="flex flex-col gap-2">
        {data.rows.map((r, i) => (
          <button key={r.id} type="button" className={card} onClick={() => m.go("product", r.id, r.label)}>
            <Head left={`${i + 1}. ${r.label}`} right={t("node.hosts", { count: n(r.hosts) })} />
            <span className="mt-1 flex flex-wrap gap-1">
              {r.cells.slice(0, 3).map((v, j) => data.cols[j] && v ? <span key={j} className={chip}>{data.cols[j].label} {n(v)}</span> : null)}
            </span>
          </button>
        ))}
        {data.rowsOther && <p className="px-0.5 text-xs text-gray-500">{t("cards.more", { count: n(data.rowsOther.count) })}</p>}
      </div>
    );
  }
  if ("center" in data) {
    const c = data.center;
    return (
      <div className="flex flex-col gap-2">
        <button type="button" className={`${card} border-brand-200 bg-brand-50`} onClick={m.center}>
          <Head left={c.label} right={t("node.hosts", { count: n(c.hosts ?? 0) })} />
          <span className="block text-xs text-gray-500">{c.sub} · {n(c.findings ?? 0)} {m.unit}</span>
        </button>
        {(data.left ?? []).map((p) => (
          <button key={`${p.kind}:${p.id}`} type="button" className={card} onClick={() => (p.kind === "fix" && isNoFix(p) ? m.noFix() : m.go(p.kind, p.id, p.label))}>
            <Head left={<>{p.sev && <span className="me-1.5 inline-block size-2 rounded-full" style={{ background: sevColor(p.sev) }} aria-hidden="true" />}{p.label}</>} right={p.kind === "cve" && p.n != null ? t("node.hosts", { count: n(p.n) }) : undefined} />
            {p.sub && <span className="block text-xs text-gray-500">{p.sub}</span>}
          </button>
        ))}
        {(data.right ?? []).map((r) => (
          <button key={r.id} type="button" className={card} onClick={() => m.go(data.mode === "host" ? "host" : "dim", r.id, r.label)}>
            <Head left={r.label} right={data.mode === "host" ? t("node.findings", { count: n(r.n ?? 0) }) : t("node.hosts", { count: n(r.hosts ?? 0) })} />
          </button>
        ))}
      </div>
    );
  }
  const max = Math.max(1, ...data.left.map((x) => x.findings));
  return (
    <div className="flex flex-col gap-2">
      {data.left.map((x, i) => {
        const p1 = x.p1 ?? x.findings, p2 = x.p2 ?? Math.max(0, x.findings - p1);
        const none = isNoFix(x);
        return (
          <button key={`${x.id}:${i}`} type="button" className={card} onClick={() => (none ? m.noFix() : m.go("fix", x.id, x.label))}>
            <Head left={`${i + 1}. ${none ? t("node.noFix") : x.label}`} right={t("node.findings", { count: n(x.findings) })} />
            <span className="my-1.5 flex h-1.5 overflow-hidden rounded-full bg-gray-100" aria-hidden="true">
              <i style={{ width: `${(p1 / max) * 100}%`, background: P1 }} /><i style={{ width: `${(p2 / max) * 100}%`, background: P2 }} />
            </span>
            <span className="flex flex-wrap gap-1">
              <span className={chip}>{t("node.hosts", { count: n(x.hosts) })}</span>
              {!!x.kev && <span className={`${chip} !bg-gray-700 !text-white`}>{t("node.kev")} {n(x.kev)}</span>}
              {!!x.inet && <span className={chip}>{t("node.internet")} {n(x.inet)}</span>}
            </span>
          </button>
        );
      })}
      {data.leftOther && data.leftOther.count > 0 && <p className="px-0.5 text-xs text-gray-500">{t("cards.more", { count: n(data.leftOther.count) })}</p>}
    </div>
  );
}

/** The graph's ranked fixes as a real table (the table alternative of the fix lens). */
export function FixTable({ data, m }: { data: FixData; m: Model }) {
  const t = useTranslations("graphView.table");
  const locale = useLocale();
  const n = (v: number) => formatNumber(v, locale);
  const th = "px-2 py-1 text-xs font-medium whitespace-nowrap text-gray-500";
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-[13px]">
        <caption className="sr-only">{t("caption")}</caption>
        <thead><tr className="border-b border-gray-200">
          <th scope="col" className={`${th} text-start`}>{t("rank")}</th><th scope="col" className={`${th} text-start`}>{t("fix")}</th>
          {(["findings", "hosts", "p1", "kev"] as const).map((k) => <th key={k} scope="col" className={`${th} text-end`}>{t(k)}</th>)}
        </tr></thead>
        <tbody>
          {data.left.map((x, i) => (
            <tr key={`${x.id}:${i}`} className="border-b border-gray-100 hover:bg-gray-50">
              <td className="px-2 py-1.5 tabular-nums">{i + 1}</td>
              <td className="px-2 py-1.5">
                <button type="button" onClick={() => (isNoFix(x) ? m.noFix() : m.go("fix", x.id, x.label))} className="text-start text-brand-600 hover:underline focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:outline-none">{isNoFix(x) ? m.t("node.noFix") : x.label}</button>
                {x.product && <div className="text-[11.5px] text-gray-500">{x.product}</div>}
              </td>
              <td className="px-2 py-1.5 text-end tabular-nums">{n(x.findings)}</td><td className="px-2 py-1.5 text-end tabular-nums">{n(x.hosts)}</td>
              <td className="px-2 py-1.5 text-end tabular-nums">{n(x.p1 ?? 0)}</td><td className="px-2 py-1.5 text-end tabular-nums">{n(x.kev ?? 0)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
