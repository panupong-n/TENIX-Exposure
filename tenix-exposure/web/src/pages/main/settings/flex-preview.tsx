import type { CSSProperties, ReactNode } from "react";

/** A small renderer for the LINE Flex messages the server builds (bubble, carousel, box, text, separator, filler): what the group would get, close enough to judge the wording and the list of names. */
type Node = { type?: string; [k: string]: unknown };
const SIZE: Record<string, number> = { xxs: 10, xs: 11, sm: 12, md: 14, lg: 16, xl: 18, xxl: 22, "3xl": 28, "4xl": 34, "5xl": 40 };
const GAP: Record<string, number> = { none: 0, xs: 2, sm: 4, md: 8, lg: 12, xl: 16, xxl: 20 };
const px = (v: unknown, fallback = 0) => (typeof v === "string" ? (v.endsWith("px") ? parseFloat(v) : (GAP[v] ?? fallback)) : fallback);
const str = (v: unknown) => (typeof v === "string" ? v : undefined);

function Box({ n, parentLayout }: { n: Node; parentLayout?: string }) {
  const layout = str(n.layout) ?? "vertical";
  const style: CSSProperties = {
    display: "flex", flexDirection: layout === "vertical" ? "column" : "row", gap: px(n.spacing), backgroundColor: str(n.backgroundColor),
    borderRadius: px(n.cornerRadius), minWidth: 0, alignItems: n.alignItems === "center" ? "center" : undefined, width: n.width ? px(n.width) : undefined, height: n.height ? px(n.height) : undefined,
    flex: typeof n.flex === "number" ? `${n.flex} 1 0` : parentLayout === "horizontal" ? "1 1 0" : undefined,
    marginTop: n.margin ? px(n.margin) : undefined,
  };
  const pad = n.paddingAll !== undefined ? px(n.paddingAll) : undefined;
  style.padding = pad;
  if (n.paddingTop !== undefined) style.paddingTop = px(n.paddingTop);
  if (n.paddingBottom !== undefined) style.paddingBottom = px(n.paddingBottom);
  if (n.paddingStart !== undefined) style.paddingLeft = px(n.paddingStart);
  if (n.paddingEnd !== undefined) style.paddingRight = px(n.paddingEnd);
  if (n.flex === 0) { style.flex = "0 0 auto"; }
  return <div style={style}>{(n.contents as Node[] | undefined)?.map((c, i) => <Item key={i} n={c} parent={layout} />)}</div>;
}

function Item({ n, parent }: { n: Node; parent?: string }): ReactNode {
  switch (n.type) {
    case "box": return <Box n={n} parentLayout={parent} />;
    case "text": {
      const style: CSSProperties = {
        fontSize: SIZE[str(n.size) ?? "md"] ?? 14, fontWeight: n.weight === "bold" ? 700 : 400, color: str(n.color) ?? "#111827", textAlign: n.align === "end" ? "right" : n.align === "center" ? "center" : undefined,
        flex: typeof n.flex === "number" ? (n.flex === 0 ? "0 0 auto" : `${n.flex} 1 0`) : parent === "horizontal" ? "1 1 0" : undefined,
        whiteSpace: n.wrap === false ? "nowrap" : "pre-wrap", overflowWrap: "anywhere", minWidth: 0, marginTop: n.margin ? px(n.margin) : undefined, lineHeight: 1.35,
      };
      return <div style={style}>{str(n.text) ?? ""}</div>;
    }
    case "separator": return <hr style={{ margin: 0, marginTop: px(n.margin), borderColor: str(n.color) ?? "#e5e7eb" }} />;
    case "filler": return <div style={{ flex: 1 }} />;
    default: return null;
  }
}

function Bubble({ b }: { b: Node }) {
  const part = (k: string) => (b[k] ? <Item n={b[k] as Node} /> : null);
  return (
    <div className="w-[17rem] shrink-0 overflow-hidden rounded-xl border border-gray-200 bg-white shadow-sm sm:w-[19rem]" data-testid="flex-bubble">
      {part("header")}{part("body")}{part("footer")}
    </div>
  );
}

export function FlexMessage({ message }: { message: Node }) {
  const c = (message.contents ?? {}) as Node;
  const bubbles = c.type === "carousel" ? ((c.contents as Node[]) ?? []) : [c];
  return <div className="flex gap-2 overflow-x-auto pb-1">{bubbles.map((b, i) => <Bubble key={i} b={b} />)}</div>;
}
