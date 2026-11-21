import { Button } from "@/components/ui/button";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { useTranslations } from "@/i18n";
import { ArrowLeftIcon, CheckIcon } from "@/icons";
import { api } from "@/lib/api";
import { useState } from "react";
import { NoticeBar, Section, useErrorText, type Notice } from "./common";
import { FalconForm, savedKey } from "./falcon-form";
import { LineSection } from "./line-section";

const STEPS = ["org", "falcon", "line"] as const;

function Stepper({ step }: { step: number }) {
  const t = useTranslations("tenants2.wizard.steps");
  return (
    <ol className="mb-3 flex flex-wrap items-center gap-x-2 gap-y-1.5" aria-label={t("label")}>
      {STEPS.map((k, i) => {
        const done = i < step, cur = i === step;
        return (
          <li key={k} className="flex items-center gap-2" aria-current={cur ? "step" : undefined}>
            <span className={`inline-flex size-6 shrink-0 items-center justify-center rounded-full text-xs font-semibold ${done ? "bg-green-500 text-white" : cur ? "bg-brand-500 text-white" : "bg-gray-100 text-gray-500"}`}>
              {done ? <CheckIcon className="size-3.5" /> : i + 1}
            </span>
            <span className={`text-sm leading-6 ${cur ? "font-semibold text-gray-800 dark:text-white/90" : "text-gray-500"}`}>{t(k)}</span>
            {i < STEPS.length - 1 && <span className="h-px w-5 bg-gray-200" aria-hidden="true" />}
          </li>
        );
      })}
    </ol>
  );
}

/** Create an organization in three separate screens. The organization exists after step 1, so the wizard can be left at any step. */
export function Wizard({ onExit, onFinish, onCreated }: { onExit: () => void; onFinish: (tenantId: string) => void; onCreated: () => void }) {
  const t = useTranslations("tenants2.wizard");
  const tc = useTranslations("common");
  const tf = useTranslations("tenants2.falcon");
  const errText = useErrorText();
  const [step, setStep] = useState(0);
  const [tenant, setTenant] = useState<{ id: string; name: string } | null>(null);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<Notice>(null);

  const create = async (e: React.SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault();
    setBusy(true);
    setNotice(null);
    try {
      const r = await api.post<{ tenant: { id: string; name?: string } }>("/api/tenants", { name: name.trim() });
      setTenant({ id: r.tenant.id, name: name.trim() });
      onCreated();
      setStep(1);
    } catch (err) {
      setNotice({ kind: "destructive", text: errText(err) });
    }
    setBusy(false);
  };

  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Button variant="ghost" size="sm" onClick={() => (tenant ? onFinish(tenant.id) : onExit())}><ArrowLeftIcon />{tenant ? t("leave") : t("cancel")}</Button>
        {tenant && <span className="min-w-0 text-sm leading-6 wrap-break-word text-gray-500">{tc("organization")}: <span className="font-medium text-gray-800">{tenant.name}</span></span>}
      </div>
      <Stepper step={step} />
      <NoticeBar notice={notice} />

      {step === 0 && (
        <Section title={t("org.title")} help={t("org.help")} step="1">
          <form onSubmit={create} className="grid max-w-lg gap-3">
            <Field>
              <FieldLabel className="mb-1.5 block">{t("org.name")}</FieldLabel>
              <Input value={name} onChange={(e) => setName(e.target.value)} maxLength={100} autoFocus required />
              <FieldDescription className="leading-5">{t("org.nameHelp")}</FieldDescription>
            </Field>
            <div className="flex flex-wrap gap-2">
              <Button type="submit" disabled={!name.trim() || busy}>{busy ? <><Spinner /> {t("org.creating")}</> : t("org.next")}</Button>
              <Button type="button" variant="outline" onClick={onExit}>{tc("cancel")}</Button>
            </div>
          </form>
        </Section>
      )}

      {step === 1 && tenant && (
        <Section title={t("falcon.title")} help={t("falcon.help")} step="2">
          <FalconForm wizard tenantId={tenant.id}
            onSaved={(r, sync) => { onCreated(); setNotice({ kind: "success", text: tf(savedKey(r, sync)) }); setStep(2); }}
            footerExtra={<Button type="button" variant="ghost" onClick={() => { setNotice(null); setStep(2); }}>{t("falcon.skip")}</Button>} />
        </Section>
      )}

      {step === 2 && tenant && (
        <Section title={t("line.title")} help={t("line.help")} step="3">
          <LineSection wizard tenantId={tenant.id} onSaved={onCreated} onFinish={() => onFinish(tenant.id)} />
        </Section>
      )}
    </div>
  );
}
