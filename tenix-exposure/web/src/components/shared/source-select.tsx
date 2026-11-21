import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useTranslations } from "@/i18n";

/** "" = all, otherwise the value the API takes as ?source= . Endpoints = devices with the Falcon sensor; external = internet-facing assets (EASM). */
export function SourceSelect({ value, onChange, className = "w-44" }: { value: string; onChange: (v: string) => void; className?: string }) {
  const t = useTranslations("filters");
  const items = [
    { value: "all", label: t("allSources") },
    { value: "endpoint", label: t("endpoint") },
    { value: "external", label: t("external") },
  ];
  return (
    <Select value={value || "all"} items={items} onValueChange={(v) => onChange(v === "all" ? "" : String(v))}>
      <SelectTrigger className={className} aria-label={t("source")}><SelectValue /></SelectTrigger>
      <SelectContent>{items.map((i) => <SelectItem key={i.value} value={i.value}>{i.label}</SelectItem>)}</SelectContent>
    </Select>
  );
}
