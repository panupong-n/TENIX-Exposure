import { cn } from "@/utils";
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";

/** Horizontal scroller that shows a soft fade on the end edge while more content is hidden there (a cue that the table scrolls sideways). */
export function ScrollFade({ children, className }: { children: ReactNode; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const [more, setMore] = useState(false);
  const measure = useCallback(() => {
    const el = ref.current;
    if (el) setMore(Math.abs(el.scrollLeft) + el.clientWidth < el.scrollWidth - 2);
  }, []);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    if (el.firstElementChild) ro.observe(el.firstElementChild);
    return () => ro.disconnect();
  }, [measure]);
  return (
    <div className="relative">
      <div ref={ref} onScroll={measure} className={cn("max-w-full overflow-x-auto", className)}>
        {children}
      </div>
      {more && <div aria-hidden="true" className="pointer-events-none absolute inset-y-0 inset-e-0 w-8 bg-linear-to-l from-white to-transparent rtl:bg-linear-to-r" />}
    </div>
  );
}
