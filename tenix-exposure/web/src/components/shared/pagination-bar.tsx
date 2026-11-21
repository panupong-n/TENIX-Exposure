import { Button } from "@/components/ui/button";
import { useLocale, useTranslations } from "@/i18n";
import { ChevronLeftIcon, ChevronRightIcon } from "@/icons";
import { formatNumber } from "@/utils/format";

interface Props {
  page: number;
  pageSize: number;
  total: number;
  onPage: (page: number) => void;
}

export function PaginationBar({ page, pageSize, total, onPage }: Props) {
  const t = useTranslations("common");
  const locale = useLocale();
  if (total <= 0) return null;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const from = (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);
  return (
    <div className="flex flex-col items-center justify-between gap-3 border-t border-gray-100 px-1 pt-4 sm:flex-row dark:border-gray-800">
      <p className="text-sm text-gray-500 tabular-nums dark:text-gray-400">
        {t("showing", { from: formatNumber(from, locale), to: formatNumber(to, locale), total: formatNumber(total, locale) })}
      </p>
      <div className="flex items-center gap-2">
        <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => onPage(page - 1)}>
          <ChevronLeftIcon className="rtl:rotate-180" />
          {t("previous")}
        </Button>
        <Button variant="outline" size="sm" disabled={page >= pages} onClick={() => onPage(page + 1)}>
          {t("next")}
          <ChevronRightIcon className="rtl:rotate-180" />
        </Button>
      </div>
    </div>
  );
}
