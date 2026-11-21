import { ErrorState } from "@/components/shared/empty-state";
import { PasswordInput } from "@/components/shared/password-input";
import { FormSkeleton } from "@/components/shared/skeletons";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Spinner } from "@/components/ui/spinner";
import { useApi } from "@/hooks/use-api";
import { ChevronDownIcon, CheckIcon, CopyIcon, PlusIcon, TrashBinIcon } from "@/icons";
import { useLocale, useTranslations } from "@/i18n";
import { api, ApiError } from "@/lib/api";
import { formatDateTime, nameOrder } from "@/utils/format";
import { useState } from "react";
import { Link } from "react-router";

interface OrgChat { tenantId: string; tenant: string; chat: string; name: string }
interface LineView {
  configured: boolean;
  hasSecret: boolean;
  hasToken: boolean;
  allowedChats: string[];
  answerChats: string[];
  chatNames: Record<string, string>;
  tenantGroups: OrgChat[]; // organizations' destinations (read-only here)
  tenantSources: OrgChat[]; // organizations' news sources (read-only here)
  webhookUrl: string;
  forwardUrl: string;
  forward: { at: number; ok: boolean; status: number } | null;
  recent: { id: string; received_at: number; kind: "text" | "image"; cve_result: "found" | "none_found" | "not_evaluated"; reply_status: string | null; done_at: number | null; ocr_status: string | null; n: number }[];
}
interface Draft { allowed: string[]; answer: string[]; names: Record<string, string> }

const CHAT_ID = /^[A-Za-z0-9_-]{5,64}$/; // the same rule as server/src/line.ts
const RESULT_COLOR = { found: "warning", none_found: "success", not_evaluated: "gray" } as const;
const card = "rounded-xl border border-gray-200 bg-white p-3";
const h3 = "text-sm leading-6 font-semibold text-gray-800";
const help = "text-xs leading-5 text-gray-500";
/** Every organization that has a chat, with its news sources and destinations, in the server's (Thai dictionary) order. */
function byOrg(sources: OrgChat[], dests: OrgChat[]) {
  const m = new Map<string, { id: string; tenant: string; sources: OrgChat[]; dests: OrgChat[] }>();
  for (const [k, list] of [["sources", sources], ["dests", dests]] as const) for (const c of list) {
    const e = m.get(c.tenantId) ?? { id: c.tenantId, tenant: c.tenant, sources: [], dests: [] };
    e[k].push(c);
    m.set(c.tenantId, e);
  }
  return [...m.values()].sort((a, b) => nameOrder.compare(a.tenant, b.tenant));
}
const sameList = (a: string[], b: string[]) => a.length === b.length && a.every((x, i) => x === b[i]);

function CopyButton({ text, label }: { text: string; label: string }) {
  const t = useTranslations("integrations.line");
  const [done, setDone] = useState(false);
  return (
    <Button
      type="button"
      variant="ghost"
      size="icon-xs"
      aria-label={done ? t("copied") : label}
      title={done ? t("copied") : label}
      onClick={() => {
        void navigator.clipboard?.writeText(text).then(() => { setDone(true); window.setTimeout(() => setDone(false), 1500); }).catch(() => {});
      }}
    >
      {done ? <CheckIcon className="size-4 text-green-600" /> : <CopyIcon className="size-4" />}
    </Button>
  );
}

/** One list of chats (name box + id + copy + remove) with its add form. Names are keyed by chat id, so a chat shows the same name in every list. */
function ChatList({ ids, names, onNames, onIds, empty, id, label }: { ids: string[]; names: Record<string, string>; onNames: (n: Record<string, string>) => void; onIds: (ids: string[]) => void; empty: string; id: string; label?: string }) {
  const t = useTranslations("integrations.line");
  const [newId, setNewId] = useState("");
  const [newName, setNewName] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const setName = (chat: string, name: string) => onNames({ ...names, [chat]: name });
  const add = () => {
    const chat = newId.trim();
    if (!CHAT_ID.test(chat)) return setErr(t("invalidId"));
    if (ids.includes(chat)) return setErr(t("duplicate"));
    onIds([...ids, chat]);
    if (newName.trim()) setName(chat, newName.trim());
    setNewId(""); setNewName(""); setErr(null);
  };
  return (
    <div>
      {ids.length === 0 ? (
        <p className="rounded-lg bg-gray-50 px-3 py-2 text-sm leading-6 text-gray-500">{empty}</p>
      ) : (
        <ul className="divide-y divide-gray-100 rounded-lg border border-gray-100">
          {ids.map((chat) => (
            <li key={chat} className="flex flex-col gap-1 px-2 py-1.5 sm:flex-row sm:items-center sm:gap-3">
              <Input
                aria-label={t("nameLabel")}
                maxLength={60}
                value={names[chat] ?? ""}
                onChange={(e) => setName(chat, e.target.value)}
                placeholder={t("unnamed")}
                className="h-8 min-w-0 sm:flex-1"
              />
              {label && <Badge size="sm" color="info" className="self-start sm:self-center">{label}</Badge>}
              <div className="flex min-w-0 items-center gap-1 sm:w-64 sm:shrink-0">
                <code className="min-w-0 flex-1 truncate font-mono text-xs leading-5 text-gray-500" title={chat}>{chat}</code>
                <CopyButton text={chat} label={t("copyId")} />
                <Button type="button" variant="ghost" size="icon-xs" aria-label={t("removeNamed", { name: names[chat] || chat })} title={t("remove")} onClick={() => onIds(ids.filter((x) => x !== chat))}>
                  <TrashBinIcon className="size-4 text-red-500" />
                </Button>
              </div>
            </li>
          ))}
        </ul>
      )}
      <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-[1fr_1fr_auto] sm:items-end">
        <div className="min-w-0 space-y-1">
          <Label htmlFor={`${id}-id`}>{t("chatIdLabel")}</Label>
          <Input id={`${id}-id`} value={newId} onChange={(e) => { setNewId(e.target.value); setErr(null); }} onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); add(); } }} placeholder="Cxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" className="font-mono" aria-invalid={err ? true : undefined} />
        </div>
        <div className="min-w-0 space-y-1">
          <Label htmlFor={`${id}-name`}>{t("nameLabel")}</Label>
          <Input id={`${id}-name`} maxLength={60} value={newName} onChange={(e) => setNewName(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); add(); } }} placeholder={t("namePlaceholder")} />
        </div>
        <Button type="button" variant="outline" onClick={add} disabled={!newId.trim()}><PlusIcon className="size-4" />{t("add")}</Button>
      </div>
      {err && <p className="mt-1 text-xs leading-5 text-red-600" role="alert">{err}</p>}
    </div>
  );
}

export default function LineTab() {
  const t = useTranslations("integrations.line");
  const locale = useLocale();
  const { data, error, reload } = useApi<LineView>("/api/integrations/line");
  const [secret, setSecret] = useState("");
  const [token, setToken] = useState("");
  const [draft, setDraft] = useState<Draft | null>(null);
  const [fwd, setFwd] = useState<string | null>(null);
  const [busy, setBusy] = useState<"save" | "test" | null>(null);
  const [notice, setNotice] = useState<{ kind: "success" | "destructive"; text: string } | null>(null);

  if (error && !data) return <ErrorState error={error} onRetry={reload} />;
  if (!data) return <FormSkeleton fields={6} />;

  const saved: Draft = { allowed: data.allowedChats, answer: data.answerChats, names: data.chatNames };
  const cur = draft ?? saved;
  const fwdText = fwd ?? data.forwardUrl;
  const patch = (p: Partial<Draft>) => setDraft({ ...cur, ...p });
  // names of chats that are in no list are dropped on save
  const used = new Set([...cur.allowed, ...cur.answer]);
  const cleanNames = () => Object.fromEntries(Object.entries(cur.names).map(([k, v]) => [k, v.trim()] as const).filter(([k, v]) => v && used.has(k)));
  const namesOf = (n: Record<string, string>) => JSON.stringify(Object.entries(n).filter(([, v]) => v.trim()).sort((a, b) => a[0].localeCompare(b[0])));
  const dirty = !!secret || !!token || (fwd !== null && fwd.trim() !== data.forwardUrl)
    || (draft !== null && (!sameList(cur.allowed, saved.allowed) || !sameList(cur.answer, saved.answer) || namesOf(cleanNames()) !== namesOf(saved.names)));
  const reset = () => { setSecret(""); setToken(""); setDraft(null); setFwd(null); setNotice(null); };
  const orgs = byOrg(data.tenantSources, data.tenantGroups);

  const save = async () => {
    setBusy("save"); setNotice(null);
    try {
      await api.put("/api/integrations/line", {
        ...(secret ? { channelSecret: secret } : {}), ...(token ? { channelAccessToken: token } : {}),
        allowedChats: cur.allowed, answerChats: cur.answer, chatNames: cleanNames(),
        ...(fwd !== null ? { forwardUrl: fwd.trim() } : {}),
      });
      setSecret(""); setToken(""); setDraft(null); setFwd(null);
      setNotice({ kind: "success", text: t("saved") });
      reload();
    } catch (e) {
      const code = e instanceof ApiError ? e.code : null;
      setNotice({ kind: "destructive", text: code === "missing_secret" ? t("errors.missing_secret") : code === "invalid_chat" ? t("errors.invalid_chat") : code === "chat_taken" ? t("errors.chat_taken") : code === "invalid_forward" ? t("errors.invalid_forward") : t("errors.unknown") });
    } finally { setBusy(null); }
  };
  const test = async () => {
    setBusy("test"); setNotice(null);
    try {
      const r = await api.post<{ ok: boolean; reason?: string }>("/api/integrations/line/test");
      setNotice(r.ok ? { kind: "success", text: t("testOk") } : { kind: "destructive", text: t(`testFail.${r.reason ?? "error"}`) });
    } catch { setNotice({ kind: "destructive", text: t("errors.unknown") }); } finally { setBusy(null); }
  };
  const time = (ts: number) => formatDateTime(ts, locale) ?? "";
  const replyText = (s: string | null) => (s === "sent" ? t("replySent") : s ? t("replyFailed") : t("replyPending"));

  return (
    <div className="space-y-3">
      <p className="text-sm leading-6 text-gray-700">
        {t("socNote")} <Link to="/settings?setting=tenants" className="text-brand-600 hover:underline">{t("tenantChange")}</Link>
      </p>
      {/* 1. connection */}
      <section className={card}>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className={h3}>{t("connection")}</h3>
          <div className="flex flex-wrap items-center gap-2">
            <Badge color={data.configured ? "success" : "gray"} size="sm">{data.configured ? t("configured") : t("notConfigured")}</Badge>
            <Button type="button" size="xs" variant="outline" onClick={test} disabled={busy !== null || !data.configured}>{busy === "test" && <Spinner />}{t("test")}</Button>
          </div>
        </div>
        <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2">
          <div className="min-w-0 space-y-1">
            <div className="flex items-center justify-between gap-2">
              <Label htmlFor="line-secret">{t("secret")}</Label>
              <Badge size="sm" color={data.hasSecret ? "success" : "gray"}>{data.hasSecret ? t("secretSaved") : t("secretMissing")}</Badge>
            </div>
            <PasswordInput id="line-secret" autoComplete="off" value={secret} onChange={(e) => setSecret(e.target.value)} placeholder={data.hasSecret ? t("keep") : ""} />
          </div>
          <div className="min-w-0 space-y-1">
            <div className="flex items-center justify-between gap-2">
              <Label htmlFor="line-token">{t("token")}</Label>
              <Badge size="sm" color={data.hasToken ? "success" : "gray"}>{data.hasToken ? t("secretSaved") : t("secretMissing")}</Badge>
            </div>
            <PasswordInput id="line-token" autoComplete="off" value={token} onChange={(e) => setToken(e.target.value)} placeholder={data.hasToken ? t("keep") : ""} />
          </div>
        </div>
        <p className={`mt-1 ${help}`}>{t("secretHelp")}</p>
        <div className="mt-2 space-y-1">
          <Label htmlFor="line-webhook">{t("webhook")}</Label>
          <div className="flex items-center gap-1">
            <Input id="line-webhook" readOnly value={data.webhookUrl} className="min-w-0 flex-1 font-mono text-xs" />
            <CopyButton text={data.webhookUrl} label={t("copy")} />
          </div>
          <p className={help}>{t("webhookHelp")}</p>
        </div>
      </section>

      {/* 2. chats the bot reads */}
      <section className={card}>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className={h3}>{t("sourceTitle")}</h3>
          <Badge size="sm" color="gray">{t("count", { count: cur.allowed.length })}</Badge>
        </div>
        <p className={`mb-2 ${help}`}>{t("sourceHelp")}</p>
        <ChatList id="line-src" ids={cur.allowed} names={cur.names} onNames={(names) => patch({ names })} onIds={(allowed) => patch({ allowed })} empty={t("sourceEmpty")} />
      </section>

      {/* 3. the SOC team's chats that receive the summaries */}
      <section className={card}>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className={h3}>{t("destTitle")}</h3>
          <Badge size="sm" color="gray">{t("count", { count: cur.answer.length })}</Badge>
        </div>
        <p className={`mb-2 ${help}`}>{t("destHelp")}</p>
        <ChatList id="line-dest" ids={cur.answer} names={cur.names} onNames={(names) => patch({ names })} onIds={(answer) => patch({ answer })} empty={t("destEmpty")} label={t("labelAll")} />
      </section>

      {/* the organizations' own chats: read-only, edited in Organizations */}
      <section className={card}>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className={h3}>{t("orgTitle")}</h3>
          <div className="flex flex-wrap items-center gap-2">
            <Badge size="sm" color="gray">{t("orgCount", { count: orgs.length })}</Badge>
            <Link to="/settings?setting=tenants" className="text-xs leading-5 text-brand-600 hover:underline">{t("tenantChange")}</Link>
          </div>
        </div>
        <p className={`mb-2 ${help}`}>{t("orgHelp")}</p>
        {orgs.length === 0 ? (
          <p className="rounded-lg bg-gray-50 px-3 py-2 text-sm leading-6 text-gray-500">{t("orgEmpty")}</p>
        ) : (
          <ul className="space-y-2">
            {orgs.map((o) => (
              <li key={o.id} className="rounded-lg border border-gray-100 p-2">
                <div className="truncate text-sm leading-6 font-semibold text-gray-800" title={o.tenant}>{o.tenant}</div>
                <div className="mt-1 grid grid-cols-1 gap-2 sm:grid-cols-2">
                  {([["sources", o.sources], ["dests", o.dests]] as const).map(([k, list]) => (
                    <div key={k} className="min-w-0">
                      <div className="text-xs leading-5 font-medium text-gray-500">{t(k === "sources" ? "orgSources" : "orgDests")}</div>
                      {list.length === 0 ? <p className="text-xs leading-5 text-gray-400">{t("orgNone")}</p> : (
                        <ul className="divide-y divide-gray-100">
                          {list.map((g) => (
                            <li key={g.chat} className="py-1">
                              <div className={`truncate text-sm leading-6 ${g.name ? "text-gray-800" : "text-gray-400"}`}>{g.name || t("unnamed")}</div>
                              <div className="flex min-w-0 items-center gap-1">
                                <code className="min-w-0 truncate font-mono text-xs leading-5 text-gray-500" title={g.chat}>{g.chat}</code>
                                <CopyButton text={g.chat} label={t("copyId")} />
                              </div>
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  ))}
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* 4. forward URL */}
      <Collapsible className={card}>
        <CollapsibleTrigger className="group/adv flex w-full items-center justify-between gap-2 text-start">
          <span className={h3}>{t("advanced")} · {t("forwardTitle")}</span>
          <ChevronDownIcon className="size-4 shrink-0 text-gray-400 transition-transform group-data-[panel-open]/adv:rotate-180" />
        </CollapsibleTrigger>
        <CollapsibleContent>
          <div className="mt-2 space-y-1">
            <Label htmlFor="line-forward">{t("forwardUrl")}</Label>
            <Input id="line-forward" value={fwdText} onChange={(e) => setFwd(e.target.value)} placeholder="https://" />
            <p className={help}>{t("forwardUrlHelp")}</p>
          </div>
        </CollapsibleContent>
        {data.forward && (
          <p className={`mt-1 text-xs leading-5 ${data.forward.ok ? "text-gray-500" : "text-red-600"}`}>
            {data.forward.ok ? t("forwardOk", { time: time(data.forward.at) })
              : data.forward.status === 0 ? t("forwardNoConn", { time: time(data.forward.at) })
              : t("forwardFail", { time: time(data.forward.at), status: String(data.forward.status) })}
          </p>
        )}
      </Collapsible>

      {notice && <Alert variant={notice.kind}><AlertDescription>{notice.text}</AlertDescription></Alert>}

      {/* unsaved-changes bar */}
      {dirty && (
        <div className="sticky bottom-0 z-10 -mx-4 -mb-4 flex flex-wrap items-center justify-between gap-2 border-t border-gray-200 bg-white px-4 py-2">
          <span className="min-w-0 text-sm leading-6 text-gray-700">{t("unsaved")}</span>
          <div className="flex gap-2">
            <Button type="button" size="sm" variant="outline" onClick={reset} disabled={busy !== null}>{t("reset")}</Button>
            <Button type="button" size="sm" onClick={save} disabled={busy !== null}>{busy === "save" && <Spinner />}{t("save")}</Button>
          </div>
        </div>
      )}

      {/* 5. recent messages: a table from 640px up, cards below (a table in a narrow drawer scrolls sideways with no cue) */}
      <section className={card}>
        <h3 className={h3}>{t("recent")}</h3>
        <p className={help}>{t("recentNote")}</p>
        {data.recent.length === 0 ? (
          <p className="mt-2 text-sm leading-6 text-gray-500">{t("empty")}</p>
        ) : (
          <>
            <table className="mt-1 hidden w-full border-collapse sm:table">
              <thead className="border-y border-gray-100">
                <tr>
                  {(["time", "kind", "cves", "result", "reply"] as const).map((c) => <th key={c} className="py-1 pe-3 text-start text-xs leading-5 font-medium whitespace-nowrap text-gray-500">{t(`columns.${c}`)}</th>)}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {data.recent.map((r) => (
                  <tr key={r.id} className="text-sm leading-6 text-gray-600">
                    <td className="py-1 pe-3 whitespace-nowrap">{time(r.received_at)}</td>
                    <td className="py-1 pe-3">{t(`kinds.${r.kind}`)}</td>
                    <td className="py-1 pe-3 tabular-nums">{r.n}</td>
                    <td className="py-1 pe-3"><Badge size="sm" color={RESULT_COLOR[r.cve_result]}>{t(`results.${r.cve_result}`)}</Badge></td>
                    <td className="py-1 pe-3">{replyText(r.reply_status)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <ul className="mt-1 space-y-1.5 sm:hidden">
              {data.recent.map((r) => (
                <li key={r.id} className="rounded-lg border border-gray-100 px-2 py-1.5">
                  <div className="flex items-start justify-between gap-2">
                    <span className="min-w-0 text-xs leading-5 text-gray-500">{time(r.received_at)}</span>
                    <Badge size="sm" color={RESULT_COLOR[r.cve_result]}>{t(`results.${r.cve_result}`)}</Badge>
                  </div>
                  <div className="text-xs leading-5 text-gray-600">{t(`kinds.${r.kind}`)} · {t("columns.cves")} {r.n} · {replyText(r.reply_status)}</div>
                </li>
              ))}
            </ul>
          </>
        )}
      </section>
    </div>
  );
}
