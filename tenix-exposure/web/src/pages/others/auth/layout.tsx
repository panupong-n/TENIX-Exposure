import { Link, Outlet } from "react-router";
import { LoginArt } from "./login-art";

/** Two slanted slashes: the TENIX mark. */
function Mark() {
  return (
    <svg width="26" height="26" viewBox="0 0 26 26" aria-hidden="true" className="shrink-0">
      <path d="M9 2h6l-8 22H1z" className="fill-brand-500" />
      <path d="M19 2h6l-8 22h-6z" className="fill-brand-300" />
    </svg>
  );
}

/** Split screen: form panel on the left (45% from 1024 px up), artwork on the right. Below 1024 px: one clean column, no artwork. */
export default function AuthLayout() {
  return (
    <div className="min-h-dvh bg-white lg:flex">
      <div className="flex min-h-dvh w-full flex-col lg:w-[45%] lg:shrink-0">
        <header className="border-b border-brand-100 bg-linear-to-b from-brand-50 to-white px-6 py-4 sm:px-10 lg:bg-none lg:px-14 lg:py-5">
          <Link to="/" className="inline-flex items-center gap-2.5" tabIndex={-1}>
            <Mark />
            <span className="flex flex-col leading-none">
              <span className="text-xl font-extrabold tracking-tight text-brand-600">10CYBER <span className="font-bold text-brand-950">Exposure</span></span>
              <span className="mt-1 text-[10px] font-semibold tracking-[0.24em] text-gray-500">BY TENFORWARD</span>
            </span>
          </Link>
        </header>
        <main className="flex flex-1 items-center px-6 py-10 sm:px-10 lg:px-14">
          <div className="mx-auto w-full max-w-md lg:mx-0">
            <Outlet />
          </div>
        </main>
        <footer className="border-t border-gray-100 px-6 py-4 text-sm text-gray-400 sm:px-10 lg:px-14">10CYBER · by TENFORWARD</footer>
      </div>
      <LoginArt className="hidden lg:block lg:flex-1" />
    </div>
  );
}
