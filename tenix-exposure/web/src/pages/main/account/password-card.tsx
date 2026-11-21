import { PasswordInput } from "@/components/shared/password-input";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, FieldDescription, FieldError, FieldLabel } from "@/components/ui/field";
import { useTranslations } from "@/i18n";
import { api, ApiError } from "@/lib/api";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMemo, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

export default function PasswordCard() {
  const t = useTranslations("account.password");
  const tw = useTranslations("auth.accept");
  const [notice, setNotice] = useState<{ kind: "success" | "destructive"; text: string } | null>(null);

  const schema = useMemo(
    () =>
      z
        .object({ currentPassword: z.string().min(1), newPassword: z.string().min(12, tw("weak")), confirm: z.string() })
        .refine((v) => v.newPassword === v.confirm, { path: ["confirm"], message: t("mismatch") }),
    [t, tw],
  );
  type Form = z.infer<typeof schema>;
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<Form>({ resolver: zodResolver(schema), defaultValues: { currentPassword: "", newPassword: "", confirm: "" }, mode: "onTouched" });

  const submit = async (f: Form) => {
    setNotice(null);
    try {
      await api.post("/api/account/password", { currentPassword: f.currentPassword, newPassword: f.newPassword });
      reset();
      setNotice({ kind: "success", text: t("success") });
    } catch (e) {
      setNotice({ kind: "destructive", text: e instanceof ApiError && e.code === "weak_password" ? tw("weak") : t("wrong") });
    }
  };

  return (
    <section className="rounded-xl border border-gray-200 bg-white p-3 sm:p-4 dark:border-gray-800 dark:bg-white/3">
      <h3 className="mb-4 text-lg font-semibold text-gray-800 dark:text-white/90">{t("title")}</h3>
      <form onSubmit={handleSubmit(submit)} className="max-w-md space-y-3" noValidate>
        {notice && <Alert variant={notice.kind} aria-live="polite"><AlertDescription>{notice.text}</AlertDescription></Alert>}
        <Field data-invalid={Boolean(errors.currentPassword)}>
          <FieldLabel className="mb-1.5 block">{t("current")}</FieldLabel>
          <PasswordInput {...register("currentPassword")} autoComplete="current-password" />
        </Field>
        <Field data-invalid={Boolean(errors.newPassword)}>
          <FieldLabel className="mb-1.5 block">{t("new")}</FieldLabel>
          <PasswordInput {...register("newPassword")} autoComplete="new-password" aria-invalid={errors.newPassword ? "true" : undefined} />
          <FieldDescription>{t("help")}</FieldDescription>
          <FieldError errors={[errors.newPassword]} />
        </Field>
        <Field data-invalid={Boolean(errors.confirm)}>
          <FieldLabel className="mb-1.5 block">{t("confirm")}</FieldLabel>
          <PasswordInput {...register("confirm")} autoComplete="new-password" aria-invalid={errors.confirm ? "true" : undefined} />
          <FieldError errors={[errors.confirm]} />
        </Field>
        <Button type="submit" disabled={isSubmitting}>{isSubmitting ? t("saving") : t("submit")}</Button>
      </form>
    </section>
  );
}
