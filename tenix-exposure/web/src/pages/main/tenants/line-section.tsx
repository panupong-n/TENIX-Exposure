import { ErrorState } from "@/components/shared/empty-state";
import { FormSkeleton } from "@/components/shared/skeletons";
import { Button } from "@/components/ui/button";
import { Field, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { useApi } from "@/hooks/use-api";
import { useTranslations } from "@/i18n";
import { PlusIcon, TrashBinIcon } from "@/icons";
import { api } from "@/lib/api";
import { useCallback, useEffect, useState } from "react";
import { CHAT_RE, CopyText, NoticeBar, Section, useErrorNotice, type Notice } from "./common";

export interface Chat { chat: string; name: string }
interface LineView { sources: Chat[]; destinations: Chat[] }

type Kind = "sources" | "destinations";

/** One list of LINE rooms with its own form and its own Save button: rows (name editable in place, chat id with copy, remove) and a form to add one.
 *  A room typed but not added is added by Save, never dropped silently. `other` is the saved list of the other kind (a room in both gets answered twice). */
function ChatBlock({ kind, saved, other, tenantId, onSaved, onDirty }: { kind: Kind; saved: Chat[]; other: Chat[]; tenantId: string; onSaved: (v: LineView) => void; onDirty: (d: boolean) => void }) {
  const t = useTranslations(`tenants2.line.${kind}`);
  const tl = useTranslations("tenants2.line");
  const errNotice = useErrorNotice();
  const [items, setItems] = useState(saved);
  const [chat, setChat] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<Notice>(null);
  const clean = chat.trim();
  const pending = clean !== "";
  const dup = pending && items.some((x) => x.chat === clean);
  const bad = pending && !CHAT_RE.test(clean);
  const strip = (l: Chat[]) => l.map(({ chat: c, name: n }) => ({ chat: c, name: n.trim() }));
  const changed = JSON.stringify(strip(items)) !== JSON.stringify(strip(saved));
  const dirty = changed || pending;
  const both = [...items.map((x) => x.chat), ...(pending ? [clean] : [])].some((c) => other.some((y) => y.chat === c));
  useEffect(() => { onDirty(dirty); }, [dirty, onDirty]);
  useEffect(() => () => onDirty(false), [onDirty]);

  const add = () => {
    if (!CHAT_RE.test(clean) || dup) return;
    setItems([...items, { chat: clean, name: name.trim() }]);
    setChat("");
    setName("");
  };
  const save = async () => {
    if (bad || dup) return;
    const list = pending ? [...items, { chat: clean, name: name.trim() }] : items;
    setBusy(true);
    setNotice(null);
    try {
      // the PUT replaces both lists: this block sends its own list and the other block's saved list, so neither touches the other's unsaved edits
      const r = await api.put<LineView>(`/api/tenants/${tenantId}/line`, { sources: strip(kind === "sources" ? list : other), destinations: strip(kind === "destinations" ? list : other) });
      setItems(r[kind]);
      setChat("");
      setName("");
      setNotice({ kind: "success", text: tl("saved") });
      onSaved(r);
    } catch (e) {
      setNotice(errNotice(e));
    }
    setBusy(false);
  };

  return (
    <div className="grid gap-3">
      {items.length === 0 ? (
        <p className="rounded-lg bg-gray-50 px-3 py-2 text-sm leading-6 text-gray-500">{t("empty")}</p>
      ) : (
        <ul className="grid gap-2">
          {items.map((x, i) => (
            <li key={x.chat} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-2 rounded-lg bg-gray-50 p-2 @lg:grid-cols-[minmax(0,1fr)_minmax(0,1.3fr)_auto] dark:bg-white/5">
              <Input className="col-span-2 @lg:col-span-1" value={x.name} maxLength={60} placeholder={tl("namePlaceholder")} aria-label={tl("name")} onChange={(e) => setItems(items.map((y, j) => (j === i ? { ...y, name: e.target.value } : y)))} />
              <CopyText value={x.chat} label={tl("copyChat", { chat: x.chat.slice(0, 8) })} />
              <Button type="button" variant="ghost" size="icon-sm" className="justify-self-end text-red-600 hover:text-red-700" aria-label={tl("remove", { name: x.name || x.chat })} onClick={() => setItems(items.filter((_, j) => j !== i))}><TrashBinIcon /></Button>
            </li>
          ))}
        </ul>
      )}

      <form className="grid items-end gap-2 @lg:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)_auto]" onSubmit={(e) => { e.preventDefault(); add(); }} noValidate>
        <Field>
          <FieldLabel className="mb-1.5 block">{tl("chatId")}</FieldLabel>
          <Input value={chat} onChange={(e) => setChat(e.target.value)} maxLength={64} spellCheck={false} autoComplete="off" aria-invalid={bad || dup} placeholder="Cxxxxxxxxxxxxxxxx" className="font-mono text-xs" />
        </Field>
        <Field>
          <FieldLabel className="mb-1.5 block">{tl("name")}</FieldLabel>
          <Input value={name} onChange={(e) => setName(e.target.value)} maxLength={60} autoComplete="off" placeholder={tl("namePlaceholder")} />
        </Field>
        <Button type="submit" variant="outline" disabled={!CHAT_RE.test(clean) || dup}><PlusIcon />{tl("add")}</Button>
      </form>
      {(bad || dup) && <p className="text-xs leading-5 text-red-600">{bad ? tl("invalid") : tl("duplicate")}</p>}
      {both && <p className="text-xs leading-5 text-amber-700">{t("both")}</p>}
      <p className="text-xs leading-5 text-gray-500">{kind === "destinations" ? tl("fallback") : tl("hint")}</p>

      <NoticeBar notice={dirty && notice?.kind === "success" ? null : notice} />
      <div className="flex flex-wrap items-center gap-2 rounded-lg bg-gray-50 p-2 dark:bg-white/5">
        <Button disabled={busy || !dirty || bad || dup} onClick={() => void save()}>{busy ? <><Spinner /> {tl("saving")}</> : t("save")}</Button>
        {!busy && (changed || pending) && <span className="text-sm leading-6 text-amber-600">{[changed && tl("dirty"), pending && tl("pending")].filter(Boolean).join(" · ")}</span>}
      </div>
    </div>
  );
}

/** Sections B and C of an organization (or the two blocks of wizard step 3): news sources and notification groups, each saved on its own. */
export function LineSection({ tenantId, onSaved, onFinish, wizard }: { tenantId: string; onSaved: (v: LineView) => void; onFinish?: () => void; wizard?: boolean }) {
  const t = useTranslations("tenants2.line");
  const { data, error, reload } = useApi<LineView>(`/api/tenants/${tenantId}/line`);
  const [base, setBase] = useState<LineView | null>(null);
  const [dirty, setDirty] = useState<Record<Kind, boolean>>({ sources: false, destinations: false });
  const setSourcesDirty = useCallback((d: boolean) => setDirty((x) => ({ ...x, sources: d })), []);
  const setDestDirty = useCallback((d: boolean) => setDirty((x) => ({ ...x, destinations: d })), []);
  const anyDirty = dirty.sources || dirty.destinations;
  // closing the tab with a room typed or a change unsaved asks first
  useEffect(() => {
    if (!anyDirty) return;
    const h = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener("beforeunload", h);
    return () => window.removeEventListener("beforeunload", h);
  }, [anyDirty]);

  const v = base ?? data;
  if (error && !v) return <ErrorState error={error} onRetry={reload} />;
  if (!v) return wizard ? <FormSkeleton fields={3} /> : <><Section title={t("sources.title")} step="B"><FormSkeleton fields={3} /></Section><Section title={t("destinations.title")} step="C"><FormSkeleton fields={3} /></Section></>;
  const saved = (r: LineView) => { setBase(r); onSaved(r); };
  const blocks: [Kind, (d: boolean) => void][] = [["sources", setSourcesDirty], ["destinations", setDestDirty]];

  if (wizard) {
    return (
      <div className="grid gap-3">
        {blocks.map(([k, onDirty]) => (
          <div key={k} className="rounded-lg border border-gray-200 p-3 dark:border-gray-800">
            <h4 className="text-base leading-6 font-semibold text-gray-800 dark:text-white/90">{t(`${k}.title`)} <span className="rounded-md bg-gray-100 px-1.5 text-xs leading-5 font-medium text-gray-600 tabular-nums">{v[k].length}</span></h4>
            <p className="mb-3 text-sm leading-6 text-gray-500 dark:text-gray-400">{t(`${k}.help`)}</p>
            <ChatBlock kind={k} saved={v[k]} other={v[k === "sources" ? "destinations" : "sources"]} tenantId={tenantId} onSaved={saved} onDirty={onDirty} />
          </div>
        ))}
        <div className="flex flex-wrap items-center gap-2">
          <Button disabled={anyDirty} onClick={onFinish}>{t("finish")}</Button>
          {anyDirty && <span className="text-sm leading-6 text-amber-600">{t("finishBlocked")}</span>}
        </div>
      </div>
    );
  }
  return (
    <>
      {blocks.map(([k, onDirty], i) => (
        <Section key={k} title={t(`${k}.title`)} help={t(`${k}.help`)} step={i === 0 ? "B" : "C"} id={`tenant-${k}`}>
          <ChatBlock kind={k} saved={v[k]} other={v[k === "sources" ? "destinations" : "sources"]} tenantId={tenantId} onSaved={saved} onDirty={onDirty} />
        </Section>
      ))}
    </>
  );
}
