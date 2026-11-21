import { useLocale, useTranslations } from "@/i18n";
import { formatNumber } from "@/utils/format";
import { Fragment } from "react";
import type { MatrixData } from "./types";

// one hue, light to dark; the share is relative to the darkest cell of the table
const mix = (t: number) => {
  const a = [242, 246, 255], b = [42, 49, 216], k = Math.pow(Math.min(1, t), 0.6);
  return `rgb(${a.map((v, i) => Math.round(v + (b[i] - v) * k)).join(",")})`;
};

/** Products (rows) x host groups (columns): a real table with scoped headers; every cell is a button that opens the product within that group. */
export function Matrix({ data, dim, onProduct, onCell, onDim }: {
  data: MatrixData; dim: string;
  onProduct: (id: string, label: string) => void; onCell: (row: string, col: string) => void; onDim: (id: string, label: string) => void;
}) {
  const t = useTranslations("graphView");
  const locale = useLocale();
  const n = (v: number) => formatNumber(v, locale);
  const other = data.colOther && data.colOther.count > 0 ? data.colOther : null;
  // denominator of a column: its host count (group size); the "other" column uses the hosts it holds
  const den = (i: number) => data.cols[i]?.total || (i === data.cols.length ? other?.total ?? other?.hosts : 0) || 0;
  let top = 0.01;
  for (const r of data.rows) r.cells.forEach((v, i) => { const d = den(i); if (d) top = Math.max(top, v / d); });

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[640px] table-fixed border-separate border-spacing-0.5 text-[12.5px]">
        <caption className="sr-only">{t("matrix.caption", { count: data.rows.length, dim })}</caption>
        <thead>
          <tr>
            <th scope="col" className="sticky start-0 z-10 w-52 bg-white px-1 py-0.5 text-start align-bottom text-[11.5px] font-medium text-gray-600">{t("matrix.product", { count: n(data.totals?.products ?? data.rows.length) })}</th>
            {data.cols.map((c) => (
              <th key={c.id} scope="col" className="px-px py-0.5 align-bottom text-[11.5px] leading-tight font-medium text-gray-700">
                <button type="button" onClick={() => onDim(c.id, c.label)} title={`${c.label} · ${t("node.hosts", { count: n(c.hosts ?? 0) })}`} className="block w-full rounded p-0.5 text-center break-words hover:bg-brand-50 focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:outline-none">{c.label.split(/(?<=-)/).map((w, i) => <Fragment key={i}>{w}<wbr /></Fragment>)}</button>
              </th>
            ))}
            {other && <th scope="col" className="px-px py-0.5 text-center align-bottom text-[11.5px] leading-tight font-medium text-gray-500">{t("matrix.other", { count: n(other.count) })}</th>}
          </tr>
        </thead>
        <tbody>
          {data.rows.map((r) => (
            <tr key={r.id}>
              <th scope="row" className="sticky start-0 z-10 bg-white p-0 text-start font-normal">
                <button type="button" onClick={() => onProduct(r.id, r.label)} className="flex w-full flex-col rounded-md px-1 py-1 text-start hover:bg-brand-50 focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:outline-none">
                  <span className="block max-w-full truncate text-[13px] text-gray-800" title={r.label}>{r.label}</span>
                  <span className="text-[11.5px] text-gray-500">{t("node.hosts", { count: n(r.hosts) })}{r.fix ? ` · ${t("matrix.hasFix")}` : ""}</span>
                </button>
              </th>
              {r.cells.map((v, i) => {
                const c = data.cols[i], d = den(i);
                const rel = d ? v / d / top : 0;
                const name = c ? t("matrix.cell", { product: r.label, group: c.label, hosts: n(v) }) : t("matrix.cellOther", { product: r.label, hosts: n(v) });
                const share = d >= v && d > 0 ? t("matrix.cellPct", { hosts: n(v), percent: Math.round((v / d) * 100), total: n(d) }) : "";
                return (
                  <td key={i} className="p-0">
                    <button
                      type="button" disabled={!c} aria-label={name} title={share ? `${name} (${share})` : name} onClick={() => c && onCell(r.id, c.id)}
                      style={{ background: v ? mix(rel) : "#FAFBFC", color: rel > 0.5 ? "#fff" : "#344054" }}
                      className="h-9 w-full rounded-[5px] text-[12.5px] font-medium tabular-nums hover:outline-2 hover:-outline-offset-1 hover:outline-brand-500 focus-visible:outline-2 focus-visible:-outline-offset-1 focus-visible:outline-brand-500"
                    >{v ? n(v) : ""}</button>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
