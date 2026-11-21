import { ChatIcon, ChevronRightIcon, DatabaseIcon, DocIcon, GlobeIcon, LayoutGridIcon, MailIcon, UsersIcon } from "@/icons";
import type { ComponentType, SVGProps } from "react";
import { StatusChip, type CardKey, type Chip } from "./status";

type Icon = ComponentType<SVGProps<SVGSVGElement>>;

/** The cards in the order they are shown, grouped in two sections. */
export const SECTIONS: { id: "data" | "system"; cards: { key: CardKey; icon: Icon }[] }[] = [
  { id: "data", cards: [{ key: "tenants", icon: LayoutGridIcon }, { key: "team", icon: UsersIcon }, { key: "system", icon: DatabaseIcon }] },
  { id: "system", cards: [{ key: "line", icon: ChatIcon }, { key: "feeds", icon: GlobeIcon }, { key: "email", icon: MailIcon }, { key: "audit", icon: DocIcon }] },
];

/** A whole-card button: icon chip, name, one status chip. No other text, so nothing can overlap. */
export function SettingCard({ name, icon: Icon, chip, active, onOpen }: { name: string; icon: Icon; chip: Chip | null; active: boolean; onOpen: () => void }) {
  return (
    <button
      type="button"
      aria-haspopup="dialog"
      aria-expanded={active}
      onClick={onOpen}
      className="group flex w-full min-w-0 items-center gap-3 rounded-xl border border-gray-200 bg-white p-3 text-start transition-colors hover:border-brand-300 hover:bg-brand-50/40 focus-visible:ring-4 focus-visible:ring-brand-500/20 focus-visible:outline-none"
    >
      <span className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-brand-50 text-brand-600"><Icon className="size-5" /></span>
      <span className="min-w-0 flex-1">
        <span className="block truncate text-sm leading-6 font-semibold text-gray-800">{name}</span>
        <StatusChip chip={chip} />
      </span>
      <ChevronRightIcon className="size-4 shrink-0 text-gray-400 group-hover:text-brand-500 rtl:rotate-180" />
    </button>
  );
}
