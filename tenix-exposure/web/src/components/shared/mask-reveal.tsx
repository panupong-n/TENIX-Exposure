import { useEffect, useRef, useState, type CSSProperties, type ElementType } from "react";

/**
 * Mask reveal text: each word rises from behind an invisible mask, one after another, the first time the text scrolls into view.
 * Quiet by design: 600 ms, a small stagger, plays once, and not at all when the person asked the system for reduced motion.
 *
 *   <MaskReveal as="h1" className="text-2xl font-semibold">ภาพรวมช่องโหว่</MaskReveal>
 *   <MaskReveal by="all">12</MaskReveal>            // a number or one short label: the whole string rises at once
 *
 * `children` must be a plain string (it is also the accessible name; the animated pieces are hidden from screen readers).
 */
export function MaskReveal({
  children, label, as: Tag = "span", className, style, by = "word", delay = 0, stagger = 45, duration = 600, once = true,
}: {
  children: string;
  /** accessible name when it differs from the shown text (a short number whose full value is the name) */
  label?: string;
  as?: ElementType;
  className?: string;
  style?: CSSProperties;
  by?: "word" | "all";
  /** ms before the first piece starts */
  delay?: number;
  /** ms between pieces */
  stagger?: number;
  duration?: number;
  once?: boolean;
}) {
  const ref = useRef<HTMLElement>(null);
  const [shown, setShown] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (typeof IntersectionObserver === "undefined" || window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) {
      setShown(true);
      return;
    }
    const io = new IntersectionObserver(
      ([e]) => {
        if (e.isIntersecting) { setShown(true); if (once) io.disconnect(); }
        else if (!once) setShown(false);
      },
      { threshold: 0.2 },
    );
    io.observe(el);
    return () => io.disconnect();
  }, [once]);

  const pieces = by === "all" ? [children] : children.split(/(\s+)/);
  let n = 0;
  return (
    <Tag ref={ref} className={className} style={style} aria-label={label ?? children}>
      {pieces.map((p, i) =>
        /^\s+$/.test(p) || p === "" ? (
          <span key={i} aria-hidden="true">{p}</span>
        ) : (
          // padding + negative margin: the mask is a little taller than the line so Thai tone marks and descenders are not cut, and the layout does not move
          <span key={i} aria-hidden="true" className="inline-block overflow-hidden align-bottom py-[0.15em] -my-[0.15em]">
            <span
              className="inline-block will-change-transform"
              style={{ transform: shown ? "translateY(0)" : "translateY(115%)", transition: `transform ${duration}ms cubic-bezier(0.2, 0.7, 0.2, 1) ${delay + n++ * stagger}ms` }}
            >
              {p}
            </span>
          </span>
        ),
      )}
    </Tag>
  );
}
