import { FormSkeleton } from "@/components/shared/skeletons";
import { PasswordInput } from "@/components/shared/password-input";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { InputOTP, InputOTPGroup, InputOTPSlot } from "@/components/ui/input-otp";
import { useAuth } from "@/contexts/auth-context";
import { useTranslations } from "@/i18n";
import { api } from "@/lib/api";
import { REGEXP_ONLY_DIGITS } from "input-otp";
import QRCode from "qrcode";
import { useState } from "react";

type Notice = { kind: "success" | "destructive"; text: string } | null;
interface Setup { secret: string; qr: string }

const Code = ({ value, onChange, label }: { value: string; onChange: (v: string) => void; label: string }) => (
  <InputOTP maxLength={6} value={value} onChange={onChange} pattern={REGEXP_ONLY_DIGITS} inputMode="numeric" autoComplete="one-time-code" aria-label={label}>
    <InputOTPGroup className="gap-2">
      {[0, 1, 2, 3, 4, 5].map((i) => <InputOTPSlot key={i} index={i} className="size-11 rounded-lg border text-base" />)}
    </InputOTPGroup>
  </InputOTP>
);

/** MFA is optional: nothing here is required to use the app. */
export default function MfaCard() {
  const t = useTranslations("account.mfa");
  const tPassword = useTranslations("account.password");
  const { user, refresh } = useAuth();
  const [setup, setSetup] = useState<Setup | null>(null);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [notice, setNotice] = useState<Notice>(null);
  const [busy, setBusy] = useState(false);
  if (!user) return <FormSkeleton fields={2} />;
  const on = user.totpEnabled;

  const start = async () => {
    setBusy(true);
    setNotice(null);
    try {
      const r = await api.post<{ secret: string; uri: string }>("/api/account/mfa/setup");
      // the QR is drawn in the browser: the secret never goes to a third-party service
      setSetup({ secret: r.secret, qr: await QRCode.toDataURL(r.uri, { margin: 1, width: 192, color: { dark: "#101828", light: "#ffffff" } }) });
      setCode("");
    } catch {
      setNotice({ kind: "destructive", text: t("invalid") });
    }
    setBusy(false);
  };
  const enable = async () => {
    setBusy(true);
    setNotice(null);
    try {
      await api.post("/api/account/mfa/enable", { code });
      setSetup(null);
      setCode("");
      setNotice({ kind: "success", text: t("enabled") });
      await refresh();
    } catch {
      setNotice({ kind: "destructive", text: t("invalid") });
      setCode("");
    }
    setBusy(false);
  };
  const disable = async () => {
    setBusy(true);
    setNotice(null);
    try {
      await api.post("/api/account/mfa/disable", { password, code });
      setPassword("");
      setCode("");
      setNotice({ kind: "success", text: t("disabled") });
      await refresh();
    } catch {
      setNotice({ kind: "destructive", text: t("disableFailed") });
      setCode("");
    }
    setBusy(false);
  };

  return (
    <div className="rounded-xl border border-gray-200 bg-white p-3 sm:p-4 dark:border-gray-800 dark:bg-white/3">
      <div className="mb-1 flex flex-wrap items-center gap-3">
        <h3 className="text-lg font-semibold text-gray-800 dark:text-white/90">{t("title")}</h3>
        <Badge size="sm" color={on ? "success" : "gray"} className="[text-shadow:none]">{on ? t("on") : t("off")}</Badge>
      </div>
      <p className="mb-3 text-sm text-gray-500 dark:text-gray-400">{t("description")}</p>
      {notice && <Alert variant={notice.kind} className="mb-3" aria-live="polite"><AlertDescription>{notice.text}</AlertDescription></Alert>}

      {!on && !setup && <Button onClick={start} disabled={busy}>{t("setup")}</Button>}

      {!on && setup && (
        <div className="space-y-3">
          <p className="text-sm text-gray-700 dark:text-gray-300">{t("step1")}</p>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start">
            {/* a QR code must stay dark-on-white to scan, in both themes */}
            <img src={setup.qr} alt="" width={192} height={192} className="rounded-xl border border-gray-200 bg-white dark:border-gray-700" />
            <div className="min-w-0">
              <p className="mb-1 text-xs text-gray-500 dark:text-gray-400">{t("manual")}</p>
              <code className="block text-sm font-medium tracking-wider break-all text-gray-800 select-all dark:text-white/90">{setup.secret.match(/.{1,4}/g)?.join(" ")}</code>
            </div>
          </div>
          <Field>
            <FieldLabel className="mb-1.5 block">{t("step2")}</FieldLabel>
            <Code value={code} onChange={setCode} label={t("code")} />
          </Field>
          <div className="flex gap-3">
            <Button onClick={enable} disabled={busy || code.length !== 6}>{t("verify")}</Button>
            <Button variant="outline" onClick={() => setSetup(null)}>{t("cancel")}</Button>
          </div>
        </div>
      )}

      {on && (
        <div className="max-w-md space-y-3">
          <FieldDescription>{t("disableHint")}</FieldDescription>
          <Field>
            <FieldLabel className="mb-1.5 block">{tPassword("current")}</FieldLabel>
            <PasswordInput value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
          </Field>
          <Field>
            <FieldLabel className="mb-1.5 block">{t("code")}</FieldLabel>
            <Code value={code} onChange={setCode} label={t("code")} />
          </Field>
          <Button variant="destructive" onClick={disable} disabled={busy || !password || code.length !== 6}>{t("confirmDisable")}</Button>
        </div>
      )}
    </div>
  );
}
