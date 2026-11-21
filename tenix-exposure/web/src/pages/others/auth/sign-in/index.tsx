import { useTranslations } from "@/i18n";
import { useState } from "react";
import SignInFormFields from "./form";
import SignInHeader from "./header";
import MfaForm from "./mfa-form";

export default function SignIn() {
  const t = useTranslations("auth");
  const [mfa, setMfa] = useState(false);

  return mfa ? (
    <>
      <SignInHeader title={t("mfa.title")} description={t("mfa.subtitle")} />
      <MfaForm onBack={() => setMfa(false)} />
    </>
  ) : (
    <>
      <SignInHeader title={t("signIn.title")} description={t("signIn.subtitle")} />
      <SignInFormFields onMfa={() => setMfa(true)} />
    </>
  );
}
