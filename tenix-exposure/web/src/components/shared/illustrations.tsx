// Small original illustrations for empty states and page bands. Flat shapes in the brand blue palette, drawn here (no stock art).
// <NoDataArt className="h-24 w-32" />  Each one is decorative (aria-hidden): the text next to it carries the meaning.
import type { SVGProps } from "react";

type Props = SVGProps<SVGSVGElement>;

const base = { fill: "none", "aria-hidden": true, focusable: false, viewBox: "0 0 160 120", xmlns: "http://www.w3.org/2000/svg" } as const;

/** An empty tray with a faint chart: nothing to show yet. */
export function NoDataArt(props: Props) {
  return (
    <svg {...base} {...props}>
      <ellipse cx="80" cy="104" rx="52" ry="7" fill="#ECF3FF" />
      <rect x="34" y="26" width="92" height="66" rx="10" fill="#F5F8FF" stroke="#9CB9FF" strokeWidth="2" />
      <rect x="46" y="64" width="12" height="18" rx="3" fill="#DDE9FF" />
      <rect x="66" y="52" width="12" height="30" rx="3" fill="#C2D6FF" />
      <rect x="86" y="58" width="12" height="24" rx="3" fill="#DDE9FF" />
      <rect x="106" y="44" width="10" height="38" rx="3" fill="#C2D6FF" />
      <path d="M46 44 L66 36 L86 42 L116 30" stroke="#465FFF" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" strokeDasharray="1 6" />
      <circle cx="132" cy="22" r="5" fill="#C2D6FF" />
      <circle cx="26" cy="40" r="3" fill="#C2D6FF" />
    </svg>
  );
}

/** A shield with a check mark: all clear. */
export function ShieldOkArt(props: Props) {
  return (
    <svg {...base} {...props}>
      <ellipse cx="80" cy="106" rx="40" ry="6" fill="#ECF3FF" />
      <path d="M80 12 L120 26 V58 C120 82 102 98 80 106 C58 98 40 82 40 58 V26 Z" fill="#ECF3FF" stroke="#9CB9FF" strokeWidth="2" strokeLinejoin="round" />
      <path d="M80 22 L110 33 V58 C110 76 96 89 80 96 C64 89 50 76 50 58 V33 Z" fill="#465FFF" />
      <path d="M64 58 L76 70 L98 46" stroke="#fff" strokeWidth="6" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="134" cy="30" r="4" fill="#C2D6FF" />
      <circle cx="28" cy="48" r="3" fill="#C2D6FF" />
      <path d="M28 20 v8 M24 24 h8" stroke="#9CB9FF" strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
}

/** A magnifier over an empty list: the search matched nothing. */
export function SearchEmptyArt(props: Props) {
  return (
    <svg {...base} {...props}>
      <ellipse cx="80" cy="106" rx="50" ry="6" fill="#ECF3FF" />
      <rect x="22" y="22" width="84" height="76" rx="10" fill="#F5F8FF" stroke="#C2D6FF" strokeWidth="2" />
      <rect x="34" y="36" width="40" height="6" rx="3" fill="#DDE9FF" />
      <rect x="34" y="52" width="56" height="6" rx="3" fill="#DDE9FF" />
      <rect x="34" y="68" width="32" height="6" rx="3" fill="#DDE9FF" />
      <circle cx="104" cy="66" r="22" fill="#fff" stroke="#465FFF" strokeWidth="5" />
      <path d="M94 66 h20" stroke="#9CB9FF" strokeWidth="4" strokeLinecap="round" />
      <path d="M120 82 L138 100" stroke="#465FFF" strokeWidth="7" strokeLinecap="round" />
    </svg>
  );
}

/** Faint contour lines for the corner of a page band. Fills its parent: place it absolutely, behind the content. */
export function ContourArt(props: Props) {
  return (
    <svg fill="none" aria-hidden focusable={false} viewBox="0 0 480 200" preserveAspectRatio="xMaxYMin slice" xmlns="http://www.w3.org/2000/svg" {...props}>
      <g stroke="#9CB9FF" strokeWidth="1.2" opacity="0.45">
        <path d="M200 0 C260 40 300 20 360 60 S440 110 480 90" />
        <path d="M250 0 C300 30 340 10 400 46 S460 90 480 74" />
        <path d="M300 0 C340 22 380 4 430 34 S470 66 480 58" />
        <path d="M150 0 C220 52 270 34 330 78 S430 140 480 120" />
        <path d="M100 0 C180 64 240 50 300 98 S420 170 480 150" />
      </g>
    </svg>
  );
}
