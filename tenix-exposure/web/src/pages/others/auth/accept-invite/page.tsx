import { FormSkeleton } from "@/components/shared/skeletons";
import { PageMeta } from "@/components/shared/page-meta";
import { PasswordInput } from "@/components/shared/password-input";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, FieldDescription, FieldError, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { useAuth } from "@/contexts/auth-context";
import { useApi } from "@/hooks/use-api";
import { useTranslations } from "@/i18n";
import { api, ApiError, type SessionUser } from "@/lib/api";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMemo, useState } from "react";
import { useForm } from "react-hook-form";
import { Link, useNavigate, useParams } from "react-router";
import { z } from "zod";
import SignInHeader from "../sign-in/header";

interface Preview {
  email: string;
  role: string;
  tenants: { name: string; role: string }[];
  kind: "invite" | "reset";
}

export default function AcceptInvitePage() {
  const t = useTranslations("auth.accept");
  const tRoles = useTranslations("roles");
  const tAuth = useTranslations("auth");
  const { token = "" } = useParams();
  const navigate = useNavigate();
  const { setUser } = useAuth();
  const { data, error, loading } = useApi<Preview>(`/api/invites/${encodeURIComponent(token)}`);
  const [done, setDone] = useState(false);
  const [serverError, setServerError] = useState<string | null>(null);

  const schema = useMemo(
    () =>
      z
        .object({
          name: z.string().trim(),
          password: z.string().min(12, t("weak")),
          confirm: z.string(),
        })
        .refine((v) => v.password === v.confirm, { path: ["confirm"], message: t("mismatch") })
        .refine((v) => data?.kind === "reset" || v.name.length > 0, { path: ["name"], message: t("errors.name") }),
    [t, data?.kind],
  );
  type Form = { name: string; password: string; confirm: string };
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<Form>({ resolver: zodResolver(schema), defaultValues: { name: "", password: "", confirm: "" }, mode: "onTouched" });

  const submit = async (f: Form) => {
    setServerError(null);
    try {
      const r = await api.post<{ status: "signed_in" | "reset"; user?: SessionUser }>(`/api/invites/${encodeURIComponent(token)}/accept`, {
        name: f.name,
        password: f.password,
      });
      if (r.status === "signed_in") {
        setUser(r.user!);
        void navigate("/", { replace: true });
      } else setDone(true);
    } catch (e) {
      setServerError(e instanceof ApiError && e.code === "invalid_invite" ? t("invalid") : e instanceof ApiError && e.code === "exists" ? tAuth("exists") : t("invalid"));
    }
  };

  let body;
  if (loading && !data) body = <FormSkeleton fields={3} />;
  else if (error || !data) {
    body = (
      <>
        <SignInHeader title={t("invalidTitle")} description={t("invalid")} />
        <Link to="/signin" className="text-sm font-medium text-brand-500 hover:text-brand-600">
          {t("toSignIn")}
        </Link>
      </>
    );
  } else if (done) {
    body = (
      <>
        <SignInHeader title={t("resetTitle")} description={t("resetDone")} />
        <Button render={<Link to="/signin" />} size="lg" className="h-12 w-full rounded-xl text-base">
          {t("toSignIn")}
        </Button>
      </>
    );
  } else {
    const reset = data.kind === "reset";
    const subtitle = reset
      ? t("resetSubtitle", { email: data.email })
      : data.role === "super_admin"
        ? t("inviteSubtitleSoc", { role: tRoles("super_admin") })
        : t("inviteSubtitleOrg", { organization: data.tenants.map((x) => `${x.name} (${tRoles(x.role)})`).join(", ") })
    body = (
      <>
        <SignInHeader title={reset ? t("resetTitle") : t("inviteTitle")} description={subtitle} />
        <form onSubmit={handleSubmit(submit)} className="space-y-5" noValidate>
          {serverError && (
            <Alert variant="destructive" aria-live="polite">
              <AlertDescription>{serverError}</AlertDescription>
            </Alert>
          )}
          <input type="email" value={data.email} autoComplete="username" readOnly hidden />
          {!reset && (
            <Field data-invalid={Boolean(errors.name)}>
              <FieldLabel className="mb-2 block text-sm font-semibold text-brand-950">{t("name")}</FieldLabel>
              <Input {...register("name")} className="h-12 rounded-xl border-brand-200 text-base shadow-none" autoComplete="name" autoFocus aria-invalid={errors.name ? "true" : undefined} />
              <FieldError errors={[errors.name]} />
            </Field>
          )}
          <Field data-invalid={Boolean(errors.password)}>
            <FieldLabel className="mb-2 block text-sm font-semibold text-brand-950">{t("password")}</FieldLabel>
            <PasswordInput {...register("password")} groupClassName="h-12 rounded-xl border-brand-200 shadow-none" autoComplete="new-password" aria-invalid={errors.password ? "true" : undefined} />
            <FieldDescription>{t("help")}</FieldDescription>
            <FieldError errors={[errors.password]} />
          </Field>
          <Field data-invalid={Boolean(errors.confirm)}>
            <FieldLabel className="mb-2 block text-sm font-semibold text-brand-950">{t("confirm")}</FieldLabel>
            <PasswordInput {...register("confirm")} groupClassName="h-12 rounded-xl border-brand-200 shadow-none" autoComplete="new-password" aria-invalid={errors.confirm ? "true" : undefined} />
            <FieldError errors={[errors.confirm]} />
          </Field>
          <Button className="h-12 w-full rounded-xl text-base" size="lg" type="submit" disabled={isSubmitting}>
            {isSubmitting ? t("saving") : reset ? t("submitReset") : t("submit")}
          </Button>
        </form>
      </>
    );
  }

  return (
    <>
      <PageMeta title="10CYBER Exposure" description={t("inviteTitle")} />
      {body}
    </>
  );
}
