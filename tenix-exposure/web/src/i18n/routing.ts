// The interface is in Thai and there is no language switcher: the language is fixed at build time and the browser's language is ignored.
// English stays as the reference text (and as the fallback for a missing Thai string) and is what the e2e build uses (VITE_LOCALE=en).
// The ar, es and de files are kept in src/messages but switched off.
const defaultLocale: "th" | "en" = import.meta.env.VITE_LOCALE === "en" ? "en" : "th";

export const routing = {
  locales: ["th", "en"] as const,
  defaultLocale,
} as const;

export type Locale = (typeof routing.locales)[number];

export const isLocale = (v: unknown): v is Locale =>
  routing.locales.includes(v as Locale);

const RTL_LOCALES: readonly Locale[] = [];

/** Kept here (not in languages.ts) so config.ts doesn't pull in the icon barrel. */
export const isRtl = (locale: Locale): boolean => RTL_LOCALES.includes(locale);
