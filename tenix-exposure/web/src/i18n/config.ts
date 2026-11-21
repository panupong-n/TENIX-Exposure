import i18n from "i18next";
import ICU from "i18next-icu";
import resourcesToBackend from "i18next-resources-to-backend";
import { initReactI18next } from "react-i18next";

import { isLocale, isRtl, routing } from "./routing";

const syncDocument = (lng: string) => {
  const locale = isLocale(lng) ? lng : routing.defaultLocale;
  document.documentElement.lang = locale;
  document.documentElement.dir = isRtl(locale) ? "rtl" : "ltr";
};

i18n.on("languageChanged", syncDocument);

i18n
  .use(ICU)
  .use(
    // Vite code-splits one chunk per locale JSON.
    resourcesToBackend((lng: string) => import(`../messages/${lng}.json`)),
  )
  .use(initReactI18next)
  .init({
    supportedLngs: [...routing.locales],
    lng: routing.defaultLocale, // fixed: no detection from the browser or from storage
    fallbackLng: "en", // a Thai string that is missing shows the English text, never the key
    load: "languageOnly",
    ns: ["translation"],
    defaultNS: "translation",
    keySeparator: ".",
    nsSeparator: false, // keys/values may contain ":"
    returnNull: false,
    returnObjects: false,
    interpolation: { escapeValue: false }, // React already escapes
    react: { useSuspense: true },
  });

export default i18n;
