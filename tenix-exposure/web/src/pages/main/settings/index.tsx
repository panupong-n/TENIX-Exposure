import { ContourArt, ShieldOkArt } from "@/components/shared/illustrations";
import { MaskReveal } from "@/components/shared/mask-reveal";
import { PageMeta } from "@/components/shared/page-meta";
import { useTranslations } from "@/i18n";
import { useState } from "react";
import { SECTIONS, SettingCard } from "./cards";
import { SettingsDrawer, useSettingParam } from "./drawer";
import { useSettingChips } from "./status"; // the chips show skeletons while their requests load

/**
 * Card cell spans in a 12-column grid so no row ends with a hole: 1 column on a phone, 2 from sm, 3 from lg; a short last row stretches its cards
 * (5 cards: 4+4+4 / 6+6; 4 cards: 3+3+3+3; 3 cards: 4+4+4; 1 card alone: 12).
 */
function span(i: number, n: number): string {
  const sm = n % 2 === 1 && i === n - 1 ? "sm:col-span-12" : "sm:col-span-6";
  const r = n % 3;
  if (n === 4) return `col-span-12 ${sm} lg:col-span-3`;
  const lg = r !== 0 && i >= n - r ? (r === 1 ? "lg:col-span-12" : "lg:col-span-6") : "lg:col-span-4";
  return `col-span-12 ${sm} ${lg}`;
}

/** Setting Center (super admin): one card per area; a card opens its area in a drawer (?setting=). */
export default function SettingsPage() {
  const t = useTranslations("settings");
  const [tick, setTick] = useState(0);
  const chips = useSettingChips(tick);
  const { key, open, close } = useSettingParam();
  return (
    <>
      <PageMeta title={`${t("title")} | 10CYBER Exposure`} description={t("title")} />
      <section className="relative mb-4 overflow-hidden rounded-xl border border-brand-100 bg-linear-to-br from-white via-white to-brand-100/80 p-4 sm:p-6">
        <ContourArt className="pointer-events-none absolute inset-y-0 end-0 h-full w-full max-w-3xl" />
        <div className="relative flex items-center justify-between gap-4">
          <div className="min-w-0">
            <MaskReveal as="h1" className="text-3xl leading-normal font-bold text-brand-950 sm:text-4xl">{t("title")}</MaskReveal>
            <p className="max-w-2xl text-sm leading-6 text-gray-600 sm:text-base">{t("description")}</p>
          </div>
          <ShieldOkArt className="hidden h-24 w-32 shrink-0 sm:block" />
        </div>
      </section>
      <div className="space-y-5">
        {SECTIONS.map((s) => (
          <section key={s.id} aria-labelledby={`settings-${s.id}`}>
            <h2 id={`settings-${s.id}`} className="text-sm leading-6 font-semibold text-gray-800">{t(`sections.${s.id}`)}</h2>
            <p className="mb-2 text-xs leading-5 text-gray-500">{t(`sectionNotes.${s.id}`)}</p>
            <div className="grid grid-cols-12 gap-3">
              {s.cards.map((c, i) => <div key={c.key} className={span(i, s.cards.length)}><SettingCard key={c.key} name={t(`cards.${c.key}`)} icon={c.icon} chip={chips[c.key]} active={key === c.key} onOpen={() => open(c.key)} /></div>)}
            </div>
          </section>
        ))}
      </div>
      <SettingsDrawer settingKey={key} onClose={() => { close(); setTick((n) => n + 1); }} />
    </>
  );
}
