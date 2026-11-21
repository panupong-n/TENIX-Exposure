import { PasswordInput } from "@/components/shared/password-input";
import { Button } from "@/components/ui/button";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Spinner } from "@/components/ui/spinner";
import { useTranslations } from "@/i18n";
import { api } from "@/lib/api";
import { useState, type ReactNode } from "react";
import { CID_RE, CLOUDS, NoticeBar, isReason, useErrorNotice, type Notice, type Reason, type SyncState } from "./common";

export interface CidStatus { state: SyncState; dataAsOf: number | null; lastRunAt: number | null; findings: number; detail: string[]; reason?: string | null }
export interface Connection extends CidStatus { id: string; name: string; baseUrl: string; clientId: string; hasSecret: boolean; cid: string }
export interface FalconView {
  connections: Connection[];
  /** CIDs of the organization with no login of their own: not read at all, what is stored is old data */
  unconnectedCids: (CidStatus & { cid: string })[];
  /** an old shared login still exists, so "try the old login" can be offered */
  legacyLogin: boolean;
  sync: { running: boolean };
}
export type SaveResult = FalconView & { id?: string; syncStarted?: boolean; syncReason?: string };

const CUSTOM = "custom";
type TestReply = { ok: boolean; step: "login" | "read"; findings?: number | null; reason?: Reason; message?: string };

/** The result of "test connection" as one clear banner: login ok / wrong credentials / cannot read this CID / missing scope / unreachable. */
export function testNotice(r: TestReply, t: (k: string, v?: Record<string, string | number>) => string): Notice {
  if (r.ok) return { kind: "success", text: r.step === "read" ? t("test.okRead", { count: r.findings ?? 0 }) : t("test.okLogin") };
  return { kind: "destructive", text: t(`test.${isReason(r.reason) ? r.reason : "error"}`), extra: r.message };
}

/** What to tell after a connection was added: reading now, or waiting for the next round because another sync is running. */
export function savedKey(r: SaveResult, sync: boolean): "addedSync" | "addedLater" | "added" {
  return r.syncStarted ? "addedSync" : sync && r.syncReason === "running" ? "addedLater" : "added";
}

/**
 * One CrowdStrike connection: cloud, Client ID, Client Secret, CID, optional name. Used by wizard step 2, "add CrowdStrike" and editing.
 * Add mode needs everything; edit mode keeps the secret when it is left empty and never shows it.
 */
export function FalconForm({ tenantId, connection, initialCid, onSaved, footerExtra, wizard }: {
  tenantId: string; connection?: Connection; initialCid?: string; onSaved: (r: SaveResult, sync: boolean) => void; footerExtra?: ReactNode; wizard?: boolean;
}) {
  const t = useTranslations("tenants2.falcon");
  const tf = useTranslations("integrations.falcon");
  const tt = useTranslations("tenants2");
  const errNotice = useErrorNotice();
  const edit = !!connection;
  const [name, setName] = useState(connection?.name ?? "");
  const [baseUrl, setBaseUrl] = useState(connection?.baseUrl ?? CLOUDS[1].url);
  const [clientId, setClientId] = useState(connection?.clientId ?? "");
  const [secret, setSecret] = useState("");
  const [cid, setCid] = useState(connection?.cid ?? initialCid ?? "");
  const [busy, setBusy] = useState<"test" | "save" | "sync" | null>(null);
  const [notice, setNotice] = useState<Notice>(null);
  const [tested, setTested] = useState<Notice>(null);
  // the server runs the same check on save and refuses a connection Falcon refuses, so "Test" is a free preview, not a gate

  const isCustom = !CLOUDS.some((c) => c.url === baseUrl);
  const cloudItems = [...CLOUDS.map((c) => ({ value: c.url, label: tf(`clouds.${c.key}`) })), { value: CUSTOM, label: tf("cloudCustom") }];
  const cidClean = cid.trim().toLowerCase();
  const cidBad = !edit && cidClean !== "" && !CID_RE.test(cidClean);
  const urlOk = /^https?:\/\/[^\s/]+/i.test(baseUrl.trim()); // the server decides which addresses are allowed (official clouds only)
  const credsOk = urlOk && clientId.trim() !== "" && (edit || secret.trim() !== "");
  const canTest = credsOk && (edit ? true : CID_RE.test(cidClean)) && busy === null;
  const canSave = credsOk && (edit || CID_RE.test(cidClean)) && busy === null;

  const test = async () => {
    setBusy("test");
    setNotice(null);
    setTested(null);
    try {
      const body = edit && !secret.trim()
        ? { connectionId: connection.id, baseUrl: baseUrl.trim(), clientId: clientId.trim(), cid: connection.cid }
        : { baseUrl: baseUrl.trim(), clientId: clientId.trim(), clientSecret: secret.trim(), cid: cidClean || undefined };
      const r = await api.post<TestReply>(`/api/tenants/${tenantId}/falcon/test`, body);
      setTested(testNotice(r, (k, v) => tt(k, v)));
    } catch (e) {
      setTested(errNotice(e));
    }
    setBusy(null);
  };

  const save = async (sync: boolean) => {
    setBusy(sync ? "sync" : "save");
    setNotice(null);
    try {
      const r = edit
        ? await api.put<SaveResult>(`/api/tenants/${tenantId}/falcon/${connection.id}`, { name: name.trim(), baseUrl: baseUrl.trim(), clientId: clientId.trim(), clientSecret: secret.trim() || undefined })
        : await api.post<SaveResult>(`/api/tenants/${tenantId}/falcon`, { name: name.trim(), baseUrl: baseUrl.trim(), clientId: clientId.trim(), clientSecret: secret.trim(), cid: cidClean, sync });
      onSaved(r, sync);
    } catch (e) {
      setNotice(errNotice(e));
      setBusy(null);
    }
  };

  return (
    <form onSubmit={(e) => { e.preventDefault(); if (canSave) void save(!edit); }} className="grid gap-3" noValidate>
      <div className="grid items-start gap-3 @lg:grid-cols-2">
        <Field>
          <FieldLabel className="mb-1.5 block">{t("cloud")}</FieldLabel>
          <Select value={isCustom ? CUSTOM : baseUrl} onValueChange={(v) => v && setBaseUrl(v === CUSTOM ? "https://" : String(v))} items={cloudItems}>
            <SelectTrigger aria-label={t("cloud")}><SelectValue /></SelectTrigger>
            <SelectContent>{cloudItems.map((c) => <SelectItem key={c.value} value={c.value}>{c.label}</SelectItem>)}</SelectContent>
          </Select>
        </Field>
        <Field>
          <FieldLabel className="mb-1.5 block">{t("name")}</FieldLabel>
          <Input value={name} onChange={(e) => setName(e.target.value)} maxLength={80} placeholder={t("namePlaceholder")} autoComplete="off" />
        </Field>
        {isCustom && (
          <Field className="@lg:col-span-2">
            <FieldLabel className="mb-1.5 block">{tf("baseUrl")}</FieldLabel>
            <Input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} inputMode="url" autoComplete="off" spellCheck={false} aria-invalid={!urlOk} className="font-mono text-xs" />
            <FieldDescription className="leading-5">{t("customHelp")}</FieldDescription>
          </Field>
        )}
        <Field>
          <FieldLabel className="mb-1.5 block">{t("clientId")}</FieldLabel>
          <Input value={clientId} onChange={(e) => setClientId(e.target.value)} autoComplete="off" spellCheck={false} className="font-mono text-xs" />
        </Field>
        <Field>
          <FieldLabel className="mb-1.5 block">{t("clientSecret")}</FieldLabel>
          {/* the shared password group is 44px tall; the other inputs are 36px */}
          <div className="[&_[data-slot=input-group]]:h-9">
            <PasswordInput value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="new-password" placeholder={edit ? "••••••••" : ""} />
          </div>
          <FieldDescription className="leading-5">{edit ? t("secretKeep") : t("secretHelp")}</FieldDescription>
        </Field>
        <Field className="@lg:col-span-2">
          <FieldLabel className="mb-1.5 block">{t("cid")}</FieldLabel>
          <Input value={cid} onChange={(e) => setCid(e.target.value.toLowerCase())} disabled={edit} maxLength={32} autoComplete="off" spellCheck={false} aria-invalid={cidBad} className="font-mono text-xs" placeholder="0123456789abcdef0123456789abcdef" />
          <FieldDescription className={cidBad ? "leading-5 text-red-600" : "leading-5"}>{cidBad ? t("cidInvalid") : edit ? t("cidFixed") : t("cidHelp")}</FieldDescription>
        </Field>
      </div>

      <NoticeBar notice={tested} />
      <NoticeBar notice={notice} />
      {!tested && !notice && !edit && <p className="text-xs leading-5 text-gray-500">{t("checkOnSave")}</p>}

      <div className="flex flex-wrap items-center gap-2">
        {edit ? (
          <Button type="submit" disabled={!canSave}>{busy === "save" ? <><Spinner /> {t("saving")}</> : t("saveEdit")}</Button>
        ) : (
          <>
            <Button type="button" disabled={!canSave} onClick={() => void save(true)}>{busy === "sync" ? <><Spinner /> {t("saving")}</> : t("saveSync")}</Button>
            {!wizard && <Button type="button" variant="outline" disabled={!canSave} onClick={() => void save(false)}>{busy === "save" ? <><Spinner /> {t("saving")}</> : t("saveOnly")}</Button>}
          </>
        )}
        <Button type="button" variant="outline" disabled={!canTest} onClick={() => void test()}>{busy === "test" ? <><Spinner /> {t("testing")}</> : t("test")}</Button>
        {footerExtra}
      </div>
    </form>
  );
}
