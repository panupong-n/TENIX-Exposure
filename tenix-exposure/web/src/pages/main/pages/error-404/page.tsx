import { PageMeta } from "@/components/shared/page-meta";
import { useTranslations } from "@/i18n";
import Error404 from "./index";

export default function Error404Page() {
  const t = useTranslations("errors.notFound");
  return (
    <div>
      <PageMeta title={`${t("metaTitle")} | 10CYBER Exposure`} description={t("title")} />
      <Error404 />
    </div>
  );
}
