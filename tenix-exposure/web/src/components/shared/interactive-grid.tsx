import { cn } from "@/utils";
import { useEffect, useRef } from "react";

const CELL = 64;
const MAJOR = 4; // every 4th line is stronger
const GLOW = 230; // px radius of the light that follows the pointer
const BRAND = "117, 146, 255"; // brand-400

/**
 * A grid you can drag, scroll and push. Every motion is smoothed:
 * the drawn offset chases a target offset, dragging adds inertia on release, and the grid
 * slowly drifts when nobody touches it. Reduced-motion users get a still grid that follows
 * the pointer directly. Decorative only: nothing here is needed to use the page.
 * Cells are addressed by their index in the grid (not on screen), so lit cells travel with it.
 */
export function InteractiveGrid({ className }: { className?: string }) {
  const wrap = useRef<HTMLDivElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const host = wrap.current;
    const cv = canvas.current;
    const ctx = cv?.getContext("2d");
    if (!host || !cv || !ctx) return;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)");

    let w = 0, h = 0;
    // offset = what is drawn, target = where it is heading
    let ox = 0, oy = 0, tx = 0, ty = 0, vx = 0, vy = 0;
    let dragging = false, lastX = 0, lastY = 0, lastT = 0, idleSince = performance.now();
    let px = -9999, py = -9999, gx = -9999, gy = -9999, glow = 0, glowTarget = 0;
    const trail = new Map<string, number>(); // "col,row" -> light, fades out
    const pulses: { c: number; r: number; born: number }[] = [];
    const ripples: { x: number; y: number; born: number }[] = [];
    let nextPulse = 0, raf = 0, prev = performance.now();

    const resize = () => {
      const r = host.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = r.width;
      h = r.height;
      cv.width = Math.round(w * dpr);
      cv.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    const ro = new ResizeObserver(resize);
    ro.observe(host);
    resize();

    const local = (e: PointerEvent | WheelEvent) => {
      const r = host.getBoundingClientRect();
      return [e.clientX - r.left, e.clientY - r.top] as const;
    };
    const touch = () => {
      idleSince = performance.now();
    };

    const onDown = (e: PointerEvent) => {
      dragging = true;
      host.setPointerCapture(e.pointerId);
      const [x, y] = local(e);
      lastX = x;
      lastY = y;
      lastT = e.timeStamp;
      vx = vy = 0;
      ripples.push({ x, y, born: performance.now() });
      host.style.cursor = "grabbing";
      touch();
    };
    const onMove = (e: PointerEvent) => {
      const [x, y] = local(e);
      px = x;
      py = y;
      glowTarget = 1;
      if (!dragging) return;
      const dt = Math.max(1, e.timeStamp - lastT) / 1000;
      const dx = x - lastX, dy = y - lastY;
      tx += dx;
      ty += dy;
      vx = vx * 0.7 + (dx / dt) * 0.3; // smoothed release velocity
      vy = vy * 0.7 + (dy / dt) * 0.3;
      lastX = x;
      lastY = y;
      lastT = e.timeStamp;
      touch();
    };
    const onUp = (e: PointerEvent) => {
      if (!dragging) return;
      dragging = false;
      if (host.hasPointerCapture(e.pointerId)) host.releasePointerCapture(e.pointerId);
      host.style.cursor = "grab";
      if (reduce.matches) vx = vy = 0;
      touch();
    };
    const onLeave = () => {
      glowTarget = 0;
    };
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      tx -= e.deltaX * 0.8;
      ty -= e.deltaY * 0.8;
      touch();
    };
    host.addEventListener("pointerdown", onDown);
    host.addEventListener("pointermove", onMove);
    host.addEventListener("pointerup", onUp);
    host.addEventListener("pointercancel", onUp);
    host.addEventListener("pointerleave", onLeave);
    host.addEventListener("wheel", onWheel, { passive: false });

    const mod = (n: number, m: number) => ((n % m) + m) % m;

    const frame = (now: number) => {
      const dt = Math.min(0.05, (now - prev) / 1000); // clamp so a hidden tab does not make it jump
      prev = now;
      const still = reduce.matches;

      if (!dragging && !still) {
        tx += vx * dt; // inertia: velocity decays exponentially
        ty += vy * dt;
        const decay = Math.exp(-dt * 3.4);
        vx *= decay;
        vy *= decay;
        if (now - idleSince > 2500) { // slow drift once left alone, eased in
          const ease = Math.min(1, (now - idleSince - 2500) / 2500);
          tx += 7 * dt * ease;
          ty += 4 * dt * ease;
        }
      }
      const follow = (rate: number) => (still ? 1 : 1 - Math.exp(-dt * rate));
      ox += (tx - ox) * follow(16);
      oy += (ty - oy) * follow(16);
      gx += (px - gx) * follow(12);
      gy += (py - gy) * follow(12);
      glow += (glowTarget - glow) * follow(6);

      ctx.clearRect(0, 0, w, h);
      const c0 = Math.floor(-ox / CELL) - 1, c1 = Math.ceil((w - ox) / CELL) + 1;
      const r0 = Math.floor(-oy / CELL) - 1, r1 = Math.ceil((h - oy) / CELL) + 1;
      const X = (c: number) => Math.round(ox + c * CELL) + 0.5;
      const Y = (r: number) => Math.round(oy + r * CELL) + 0.5;
      const cell = (c: number, r: number, a: number) => {
        ctx.fillStyle = `rgba(${BRAND}, ${a})`;
        ctx.fillRect(ox + c * CELL + 1, oy + r * CELL + 1, CELL - 1, CELL - 1);
      };

      // the cell under the pointer lights up and fades behind it
      if (glow > 0.02) trail.set(`${Math.floor((gx - ox) / CELL)},${Math.floor((gy - oy) / CELL)}`, 1);
      for (const [key, v] of trail) {
        const nv = v - dt * 0.9;
        if (nv <= 0) { trail.delete(key); continue; }
        trail.set(key, nv);
        const [c, r] = key.split(",").map(Number);
        cell(c, r, 0.16 * nv * nv);
      }

      // ambient pulses on random cells
      if (!still && now > nextPulse) {
        pulses.push({ c: c0 + Math.floor(Math.random() * (c1 - c0)), r: r0 + Math.floor(Math.random() * (r1 - r0)), born: now });
        nextPulse = now + 500 + Math.random() * 900;
      }
      for (let i = pulses.length - 1; i >= 0; i--) {
        const p = pulses[i];
        const life = (now - p.born) / 2200;
        if (life >= 1) { pulses.splice(i, 1); continue; }
        cell(p.c, p.r, Math.sin(life * Math.PI) * 0.17);
      }

      // base lines
      ctx.lineWidth = 1;
      for (let c = c0; c <= c1; c++) {
        ctx.strokeStyle = `rgba(255,255,255,${mod(c, MAJOR) === 0 ? 0.13 : 0.07})`;
        ctx.beginPath(); ctx.moveTo(X(c), 0); ctx.lineTo(X(c), h); ctx.stroke();
      }
      for (let r = r0; r <= r1; r++) {
        ctx.strokeStyle = `rgba(255,255,255,${mod(r, MAJOR) === 0 ? 0.13 : 0.07})`;
        ctx.beginPath(); ctx.moveTo(0, Y(r)); ctx.lineTo(w, Y(r)); ctx.stroke();
      }

      // lines brighten under the pointer: a radial gradient used as the stroke colour
      if (glow > 0.02) {
        const g = ctx.createRadialGradient(gx, gy, 0, gx, gy, GLOW);
        g.addColorStop(0, `rgba(${BRAND}, ${0.75 * glow})`);
        g.addColorStop(1, `rgba(${BRAND}, 0)`);
        ctx.strokeStyle = g;
        ctx.lineWidth = 1.25;
        ctx.beginPath();
        for (let c = c0; c <= c1; c++) {
          if (Math.abs(X(c) - gx) > GLOW) continue;
          ctx.moveTo(X(c), Math.max(0, gy - GLOW)); ctx.lineTo(X(c), Math.min(h, gy + GLOW));
        }
        for (let r = r0; r <= r1; r++) {
          if (Math.abs(Y(r) - gy) > GLOW) continue;
          ctx.moveTo(Math.max(0, gx - GLOW), Y(r)); ctx.lineTo(Math.min(w, gx + GLOW), Y(r));
        }
        ctx.stroke();
        for (let c = c0; c <= c1; c++) {
          if (Math.abs(X(c) - gx) > GLOW) continue;
          for (let r = r0; r <= r1; r++) {
            const d = Math.hypot(X(c) - gx, Y(r) - gy);
            if (d > GLOW) continue;
            ctx.fillStyle = `rgba(${BRAND}, ${(1 - d / GLOW) * 0.9 * glow})`;
            ctx.beginPath(); ctx.arc(X(c), Y(r), 2, 0, Math.PI * 2); ctx.fill();
          }
        }
      }

      // click ripples
      for (let i = ripples.length - 1; i >= 0; i--) {
        const rp = ripples[i];
        const life = (now - rp.born) / 900;
        if (life >= 1) { ripples.splice(i, 1); continue; }
        ctx.strokeStyle = `rgba(${BRAND}, ${(1 - life) * 0.55})`;
        ctx.lineWidth = 1.5;
        ctx.beginPath(); ctx.arc(rp.x, rp.y, (1 - (1 - life) ** 3) * 150, 0, Math.PI * 2); ctx.stroke();
      }
      raf = requestAnimationFrame(frame);
    };
    raf = requestAnimationFrame(frame);

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      host.removeEventListener("pointerdown", onDown);
      host.removeEventListener("pointermove", onMove);
      host.removeEventListener("pointerup", onUp);
      host.removeEventListener("pointercancel", onUp);
      host.removeEventListener("pointerleave", onLeave);
      host.removeEventListener("wheel", onWheel);
    };
  }, []);

  return (
    <div ref={wrap} aria-hidden="true" className={cn("absolute inset-0 cursor-grab touch-none select-none", className)}>
      <canvas ref={canvas} className="size-full" />
    </div>
  );
}
