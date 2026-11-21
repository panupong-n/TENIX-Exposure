import { PageMeta } from "@/components/shared/page-meta";
import { useTranslations } from "@/i18n";
import { ChevronLeftIcon } from "@/icons";
import { Link } from "react-router";
import SignInHeader from "../sign-in/header";

export default function ForgotPasswordPage() {
  const t = useTranslations("auth.forgot");
  return (
    <>
      <PageMeta title={`${t("title")} | 10CYBER Exposure`} description={t("body")} />
      <SignInHeader title={t("title")} description={t("body")} />
      <Link to="/signin" className="inline-flex items-center text-sm font-medium text-brand-500 hover:text-brand-600">
        <ChevronLeftIcon className="rtl:rotate-180" />
        {t("back")}
      </Link>
    </>
  );
}
