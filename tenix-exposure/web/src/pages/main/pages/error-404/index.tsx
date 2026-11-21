import GridShape from "@/components/shared/grid-shape";
import { Button } from "@/components/ui/button";
import { useTranslations } from "@/i18n";
import { Link, useNavigate } from "react-router";

const YEAR = new Date().getFullYear();

/** Shown for any address the app does not have. */
export default function Error404() {
  const t = useTranslations("errors.notFound");
  const navigate = useNavigate();
  return (
    <div className="relative z-1 flex min-h-screen flex-col items-center justify-center overflow-hidden p-6">
      <GridShape />
      <main className="mx-auto w-full max-w-lg text-center">
        <img src="/images/brand/tenforward-logo.png" alt="TENFORWARD" width={234} height={50} className="mx-auto mb-10 h-auto w-48" />
        <p className="text-7xl font-semibold tracking-tight text-brand-500 tabular-nums sm:text-8xl" aria-hidden="true">404</p>
        <h1 className="mt-4 text-2xl font-semibold text-gray-800 dark:text-white/90">{t("title")}</h1>
        <p className="mx-auto mt-3 max-w-md text-base text-gray-600 dark:text-gray-400">{t("body")}</p>
        <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
          <Button size="lg" nativeButton={false} render={<Link to="/" />}>{t("home")}</Button>
          <Button size="lg" variant="outline" className="bg-white" onClick={() => navigate(-1)}>{t("back")}</Button>
        </div>
      </main>
      <p className="absolute inset-s-1/2 bottom-6 -translate-x-1/2 text-center text-sm text-gray-500 dark:text-gray-400">
        &copy; {YEAR} 10CYBER · TENFORWARD
      </p>
    </div>
  );
}
