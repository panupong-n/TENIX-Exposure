import { TooltipProvider } from "../../src/components/ui/tooltip";
import { I18nProvider } from "../../src/i18n";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router";

/** Wrap anything built with this library once, at the root: English strings, router context and tooltips. */
export function TenixProvider({ children }: { children?: ReactNode }) {
  return (
    <MemoryRouter>
      <I18nProvider>
        <TooltipProvider>{children}</TooltipProvider>
      </I18nProvider>
    </MemoryRouter>
  );
}
