import type { ReactNode } from "react";

interface HeadingProps {
  pageTitle: string;
  description?: string;
  /** Buttons or filters aligned to the end of the heading row. */
  actions?: ReactNode;
}

/** Compact page heading. (Name kept from the template; there is no breadcrumb any more, the header menu shows the location.) */
export function PageBreadcrumb({ pageTitle, description, actions }: HeadingProps) {
  return (
    <div className="mb-3 flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
      <div className="min-w-0">
        <h1 className="text-lg font-semibold text-gray-800 dark:text-white/90">{pageTitle}</h1>
        {description && <p className="text-sm text-gray-500 dark:text-gray-400">{description}</p>}
      </div>
      {actions && <div className="flex w-full flex-wrap items-center gap-2 sm:w-auto">{actions}</div>}
    </div>
  );
}
