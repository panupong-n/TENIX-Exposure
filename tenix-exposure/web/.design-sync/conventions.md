# TENIX Exposure UI: how to build with it

TENIX Exposure is a vulnerability portal for SOC analysts and customers (CrowdStrike Falcon data). The interface is **English only** and **light theme only**. This library is its real component set (Base UI primitives styled with Tailwind v4), bundled at `window.TenixUI`.

## Wrap once, at the root
Components read English strings, router context and tooltips from context, and every preview in this library renders inside this wrapper. Always include it.

```jsx
const { TenixProvider, Card, CardHeader, CardTitle, CardContent, Button } = window.TenixUI;
<TenixProvider>
  <Card><CardHeader><CardTitle>Alpha Corp</CardTitle></CardHeader>
    <CardContent><Button>Open overview</Button></CardContent></Card>
</TenixProvider>
```

## Styling idiom: Tailwind utility classes plus component props
- Prefer component props first: `Button variant="default|outline|ghost|destructive|link" size="xs|sm|lg|icon"`, `Badge color="primary|success|warning|error|info|gray" variant="light|solid"`, `Alert variant="info|success|warning|destructive"`.
- Your own layout glue uses Tailwind utilities. **Only classes that already exist in `styles.css` work.** The stylesheet is compiled from the classes this codebase uses, so a utility you invent may be missing: search `_ds_bundle.css` before using an unusual one, and stay with the families below.
- Tokens: brand blue `bg-brand-500` / `text-brand-500` / `hover:bg-brand-600`; neutrals `text-gray-800` (primary text), `text-gray-500` (secondary), `text-gray-400` (muted), `border-gray-200`, `bg-gray-50`, `bg-white`; radius `rounded-lg`, `rounded-xl`; elevation `shadow-theme-xs`; font `font-outfit` (applied globally); numbers use `tabular-nums`; right-align with `text-end`.
- This theme has no `text-theme-*` or `error-*` classes. Use `text-sm`, `text-xs`, `text-red-*`.
- **Severity colours are fixed:** Critical red, High orange, Medium yellow, Low green, Informational blue. Always render them with `SeverityBadge severity="CRITICAL|HIGH|MEDIUM|LOW|NONE"`, never with a hand-picked colour.

## Compound parts and unstyled primitives
- Compound components export their parts on the same global: `Dialog` + `DialogContent`, `DialogHeader`, `DialogTitle`, `DialogDescription`, `DialogFooter`; the same pattern holds for `Sheet`, `Popover`, `Select`, `Tabs`, `Accordion`, `Card`, `Pagination`. Parts only work inside their parent (a bare `AccordionItem` throws); the parent's preview and `.prompt.md` show the composition.
- `Table` is an unstyled primitive. Pass classes the way the app does: header cells `<TableCell isHeader className="py-1.5 pe-3 text-start text-xs font-medium text-gray-500">`, `<TableHeader className="border-y border-gray-100">`, `<TableBody className="divide-y divide-gray-100">`, body cells `py-1.5 text-sm`.
- `CardHeader` is a vertical flex column, so `CardAction` does not float to the right. Put badges or buttons in `CardContent` or `CardFooter`.
- `Popover`: put `PopoverFooter` inside `PopoverBody` (the body supplies the padding).
- The app has no sidebar (the menu is in the header), so sidebar components are not included.

## Where the truth lives
Read before styling: `styles.css` (imports `_ds_bundle.css`), the per-component `components/<group>/<Name>/<Name>.prompt.md` and `.d.ts`. Groups: `primitives` (generic UI) and `tenix` (SeverityBadge, StatCard, StatArt, EmptyState, PaginationBar, SearchInput, PasswordInput, skeletons).

## Show a loading state
Every page in TENIX shows a skeleton while it loads. Use `PageSkeleton`, `TableSkeleton`, `StatCardsSkeleton`, `ChartCardSkeleton`, `FormSkeleton` or `GraphSkeleton`.
