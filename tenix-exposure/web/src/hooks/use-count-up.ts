import { useEffect, useRef, useState } from "react";

/** Eases a number up from its previous value (exponential ease-out). Jumps straight there under reduced motion. */
export function useCountUp(target: number, ms = 700): number {
  const [shown, setShown] = useState(0);
  const last = useRef(0);

  useEffect(() => {
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const from = last.current;
    let t0 = 0;
    let raf = 0;
    const step = (t: number) => {
      if (!t0) t0 = t;
      const p = reduce ? 1 : Math.min(1, (t - t0) / ms);
      const eased = p === 1 ? 1 : 1 - 2 ** (-10 * p);
      last.current = Math.round(from + (target - from) * eased);
      setShown(last.current);
      if (p < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [target, ms]);

  return shown;
}
