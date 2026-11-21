/** Original artwork for the sign-in screen: a bright white hall with arched windows, a glossy floor and translucent glass ribbons.
 *  Pure inline SVG (no image request); decorative, so hidden from assistive technology. The left edge fades into the white form panel. */
export function LoginArt({ className = "" }: { className?: string }) {
  return (
    <div aria-hidden="true" className={`relative overflow-hidden bg-white ${className}`}>
    <svg viewBox="0 0 800 900" preserveAspectRatio="xMidYMid slice" className="absolute inset-0 size-full">
      <defs>
        <linearGradient id="la-sky" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#d4eaff"/><stop offset="0.6" stopColor="#eef7ff"/><stop offset="1" stopColor="#ffffff"/></linearGradient>
        <linearGradient id="la-glass" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#9fd0ff"/><stop offset="0.55" stopColor="#cfe8ff"/><stop offset="1" stopColor="#eef7ff"/></linearGradient>
        <linearGradient id="la-floor" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#e3effb"/><stop offset="1" stopColor="#ffffff"/></linearGradient>
        <linearGradient id="la-wall" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#bddcfb"/><stop offset="0.45" stopColor="#e4f1ff"/><stop offset="1" stopColor="#f8fbff"/></linearGradient>
        <linearGradient id="la-rA" x1="0" y1="1" x2="1" y2="0"><stop offset="0" stopColor="#0b6ef0" stopOpacity="0.8"/><stop offset="0.55" stopColor="#4aa3ff" stopOpacity="0.6"/><stop offset="1" stopColor="#bfe0ff" stopOpacity="0.45"/></linearGradient>
        <linearGradient id="la-rB" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stopColor="#9ccfff" stopOpacity="0.55"/><stop offset="0.5" stopColor="#2f86f5" stopOpacity="0.55"/><stop offset="1" stopColor="#0a4fc4" stopOpacity="0.6"/></linearGradient>
        <linearGradient id="la-rC" x1="1" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#e6f3ff" stopOpacity="0.8"/><stop offset="0.5" stopColor="#6db6ff" stopOpacity="0.5"/><stop offset="1" stopColor="#1c7cf2" stopOpacity="0.55"/></linearGradient>
        <radialGradient id="la-sun" cx="0.5" cy="0.5" r="0.5"><stop offset="0" stopColor="#fff" stopOpacity="1"/><stop offset="0.25" stopColor="#fff" stopOpacity="0.75"/><stop offset="1" stopColor="#fff" stopOpacity="0"/></radialGradient>
        <linearGradient id="la-fadeDown" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#fff" stopOpacity="0.9"/><stop offset="1" stopColor="#fff" stopOpacity="0"/></linearGradient>
        <mask id="la-refl"><rect x="0" y="600" width="800" height="300" fill="url(#la-fadeDown)"/></mask>
        <filter id="la-blur14" x="-20%" y="-20%" width="140%" height="140%"><feGaussianBlur stdDeviation="14"/></filter>
        <filter id="la-blur4" x="-10%" y="-10%" width="120%" height="120%"><feGaussianBlur stdDeviation="3"/></filter>
        <filter id="la-soft" x="-20%" y="-20%" width="140%" height="140%"><feGaussianBlur stdDeviation="9"/></filter>
        <g id="la-wins">
          <path d="M128 600V250a82 82 0 0 1 164 0V600Z" fill="url(#la-glass)"/>
          <path d="M338 600V250a82 82 0 0 1 164 0V600Z" fill="url(#la-glass)"/>
          <path d="M548 600V250a82 82 0 0 1 164 0V600Z" fill="url(#la-glass)"/>
        </g>
      </defs>
      <rect width="800" height="900" fill="url(#la-sky)"/>
  
      <rect x="0" y="0" width="800" height="600" fill="url(#la-wall)"/>
  
      <g filter="url(#la-soft)" opacity="0.5" transform="translate(10 6)"><use href="#la-wins"/></g>
      <use href="#la-wins"/>
      <g fill="none" stroke="#fff" strokeLinecap="round">
        <path d="M128 600V250a82 82 0 0 1 164 0V600M338 600V250a82 82 0 0 1 164 0V600M548 600V250a82 82 0 0 1 164 0V600" strokeWidth="9"/>
        <path d="M210 168V600M420 168V600M630 168V600M128 360H292M338 360H502M548 360H712" strokeWidth="4" opacity="0.85"/>
      </g>
      <g fill="none" stroke="#c9ddf2" strokeWidth="1.5" opacity="0.8">
        <path d="M123 600V250a87 87 0 0 1 174 0V600M333 600V250a87 87 0 0 1 174 0V600M543 600V250a87 87 0 0 1 174 0V600"/>
      </g>
  
      <circle cx="650" cy="90" r="320" fill="url(#la-sun)" opacity="0.85"/>
      <circle cx="650" cy="90" r="110" fill="url(#la-sun)"/>
      <circle cx="650" cy="90" r="34" fill="#fff"/>
      <circle cx="540" cy="215" r="16" fill="#fff" opacity="0.5"/><circle cx="470" cy="290" r="9" fill="#fff" opacity="0.45"/><circle cx="400" cy="355" r="24" fill="#fff" opacity="0.25"/>
      <g stroke="#fff" strokeLinecap="round" opacity="0.5" fill="none">
        <path d="M650 90L420 520" strokeWidth="22" opacity="0.25"/>
        <path d="M650 90L560 560" strokeWidth="30" opacity="0.2"/>
        <path d="M650 90L760 520" strokeWidth="18" opacity="0.2"/>
      </g>
  
      <rect x="0" y="600" width="800" height="300" fill="url(#la-floor)"/>
      <g mask="url(#la-refl)" opacity="0.5"><use href="#la-wins" transform="translate(0 1200) scale(1 -1)"/></g>
      <g stroke="#fff" strokeWidth="2" opacity="0.8"><path d="M0 604H800M0 640H800M0 700H800M0 790H800" opacity="0.7"/></g>
      <rect x="0" y="596" width="800" height="14" fill="#cfe2f6" opacity="0.5" filter="url(#la-blur4)"/>
  
      <g>
        <path d="M-60 700C120 560 260 820 440 600S700 330 880 200L880 330C720 440 620 760 440 790S120 860 -60 820Z" fill="url(#la-rA)" filter="url(#la-blur14)" opacity="0.5"/>
        <path d="M-60 700C120 560 260 820 440 600S700 330 880 200L880 330C720 440 620 760 440 790S120 860 -60 820Z" fill="url(#la-rA)"/>
        <path d="M-60 700C120 560 260 820 440 600S700 330 880 200" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round" opacity="0.8"/>
        <path d="M-60 820C120 860 280 800 440 790S720 440 880 330" fill="none" stroke="#fff" strokeWidth="1.5" opacity="0.4"/>

        <path d="M880 420C700 360 640 560 480 520S220 330 -60 470L-60 580C180 450 300 600 480 640S720 480 880 540Z" fill="url(#la-rB)" filter="url(#la-blur14)" opacity="0.4"/>
        <path d="M880 420C700 360 640 560 480 520S220 330 -60 470L-60 580C180 450 300 600 480 640S720 480 880 540Z" fill="url(#la-rB)"/>
        <path d="M880 420C700 360 640 560 480 520S220 330 -60 470" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round" opacity="0.7"/>

        <path d="M120 -40C60 160 340 260 360 440S180 640 260 940L350 940C270 650 470 520 460 420S240 200 220 -40Z" fill="url(#la-rC)" filter="url(#la-blur14)" opacity="0.4"/>
        <path d="M120 -40C60 160 340 260 360 440S180 640 260 940L350 940C270 650 470 520 460 420S240 200 220 -40Z" fill="url(#la-rC)"/>
        <path d="M120 -40C60 160 340 260 360 440S180 640 260 940" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round" opacity="0.8"/>

        <path d="M560 940C600 780 760 760 820 620S780 380 880 300L880 380C800 450 880 640 770 760S660 880 640 940Z" fill="url(#la-rA)" opacity="0.75"/>
        <path d="M560 940C600 780 760 760 820 620S780 380 880 300" fill="none" stroke="#fff" strokeWidth="2.5" strokeLinecap="round" opacity="0.7"/>
      </g>
  
      <g fill="#fff"><circle cx="520" cy="470" r="3" opacity="0.9"/><circle cx="300" cy="700" r="2.5" opacity="0.9"/><circle cx="690" cy="330" r="2" opacity="0.9"/></g>
    </svg>
      <div className="absolute inset-y-0 start-0 w-1/3 bg-linear-to-r from-white to-transparent rtl:bg-linear-to-l" />
    </div>
  );
}
