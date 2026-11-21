import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { InputOTP, InputOTPGroup, InputOTPSlot } from "@/components/ui/input-otp";
import { useAuth } from "@/contexts/auth-context";
import { useTranslations } from "@/i18n";
import { api, ApiError, type SessionUser } from "@/lib/api";
import { REGEXP_ONLY_DIGITS } from "input-otp";
import { useState } from "react";
import { useLocation, useNavigate } from "react-router";

/** Second step: the 6-digit code from the authenticator app. Submits by itself when the sixth digit is typed. */
export default function MfaForm({ onBack }: { onBack: () => void }) {
  const t = useTranslations("auth.mfa");
  const { setUser } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const verify = async (value: string) => {
    setBusy(true);
    setError(null);
    try {
      const r = await api.post<{ user: SessionUser }>("/api/auth/login/mfa", { code: value });
      setUser(r.user);
      void navigate((location.state as { from?: string } | null)?.from ?? "/", { replace: true });
    } catch (e) {
      // 401 after the 5-minute window or after too many wrong codes: the first step must be repeated
      const gone = e instanceof ApiError && e.code === "unauthenticated";
      setError(gone ? t("expired") : t("invalid"));
      setCode("");
      setBusy(false);
      if (gone) onBack();
    }
  };

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (code.length === 6) void verify(code);
      }}
      className="space-y-6"
    >
      {error && (
        <Alert variant="destructive" aria-live="polite">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <InputOTP
        maxLength={6}
        value={code}
        onChange={setCode}
        onComplete={(v) => void verify(v)}
        pattern={REGEXP_ONLY_DIGITS}
        inputMode="numeric"
        autoComplete="one-time-code"
        autoFocus
        disabled={busy}
        aria-label={t("title")}
        containerClassName="justify-center"
      >
        <InputOTPGroup className="gap-2">
          {[0, 1, 2, 3, 4, 5].map((i) => (
            <InputOTPSlot key={i} index={i} className="size-12 rounded-lg border text-lg" />
          ))}
        </InputOTPGroup>
      </InputOTP>
      <Button className="h-12 w-full rounded-xl text-base" size="lg" type="submit" disabled={busy || code.length !== 6}>
        {busy ? t("verifying") : t("verify")}
      </Button>
      <button type="button" onClick={onBack} className="block w-full text-center text-sm text-brand-500 hover:text-brand-600 dark:text-brand-400">
        {t("back")}
      </button>
    </form>
  );
}
