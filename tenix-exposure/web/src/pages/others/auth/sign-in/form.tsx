import { PasswordInput } from "@/components/shared/password-input";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Field, FieldError, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { useAuth } from "@/contexts/auth-context";
import { useTranslations } from "@/i18n";
import { api, ApiError, type SessionUser } from "@/lib/api";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMemo, useState } from "react";
import { Controller, useForm } from "react-hook-form";
import { Link, useLocation, useNavigate } from "react-router";
import { makeSignInSchema, type SignInFormData } from "./schema";

const label = "mb-2 block text-sm font-semibold text-brand-950";
const box = "h-12 rounded-xl border-brand-200 text-base shadow-none";

export default function SignInFormFields({ onMfa }: { onMfa: (remember: boolean) => void }) {
  const t = useTranslations("auth.signIn");
  const { setUser } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [error, setError] = useState<string | null>(null);

  const schema = useMemo(() => makeSignInSchema((k) => t(`errors.${k}`)), [t]);
  const {
    register,
    handleSubmit,
    control,
    formState: { errors, isSubmitting },
  } = useForm<SignInFormData>({
    resolver: zodResolver(schema),
    defaultValues: { email: "", password: "", keepLoggedIn: false },
    mode: "onSubmit", // no error for a field the user has not had a chance to fill
  });

  const submit = async (data: SignInFormData) => {
    setError(null);
    try {
      const r = await api.post<{ status: "ok" | "mfa_required"; user?: SessionUser }>("/api/auth/login", {
        email: data.email,
        password: data.password,
        remember: data.keepLoggedIn,
      });
      if (r.status === "mfa_required") return onMfa(data.keepLoggedIn);
      setUser(r.user!);
      void navigate((location.state as { from?: string } | null)?.from ?? "/", { replace: true });
    } catch (e) {
      const code = e instanceof ApiError ? e.code : null;
      setError(code === "invalid_credentials" || code === "rate_limited" ? t(`errors.${code}`) : t("errors.generic"));
    }
  };

  return (
    <form onSubmit={handleSubmit(submit)} className="space-y-6" noValidate>
      {error && (
        <Alert variant="destructive" aria-live="polite">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <Field data-invalid={Boolean(errors.email)}>
        <FieldLabel className={label}>{t("email")}</FieldLabel>
        <Input {...register("email")} type="email" className={box} placeholder="name@company.com" autoComplete="username" autoFocus aria-invalid={errors.email ? "true" : undefined} />
        <FieldError errors={[errors.email]} />
      </Field>

      <Field data-invalid={Boolean(errors.password)}>
        <FieldLabel className={label}>{t("password")}</FieldLabel>
        <PasswordInput {...register("password")} className="text-base" groupClassName={`${box} h-12`} placeholder="••••••••" autoComplete="current-password" aria-invalid={errors.password ? "true" : undefined} />
        <FieldError errors={[errors.password]} />
      </Field>

      <div className="flex items-center justify-between">
        <Field orientation="horizontal" className="w-auto items-center gap-3">
          <Controller
            control={control}
            name="keepLoggedIn"
            render={({ field }) => (
              <Checkbox id="keep-signed-in" checked={field.value} onCheckedChange={(c) => field.onChange(Boolean(c))} />
            )}
          />
          <FieldLabel htmlFor="keep-signed-in" className="text-sm block cursor-pointer font-normal text-gray-700 dark:text-gray-400">
            {t("keep")}
          </FieldLabel>
        </Field>
        <Link to="/forgot-password" className="text-sm font-medium text-brand-500 hover:text-brand-600">
          {t("forgot")}
        </Link>
      </div>

      <Button className="h-12 w-full rounded-xl text-base" size="lg" type="submit" disabled={isSubmitting}>
        {isSubmitting ? t("submitting") : t("submit")}
      </Button>
    </form>
  );
}
