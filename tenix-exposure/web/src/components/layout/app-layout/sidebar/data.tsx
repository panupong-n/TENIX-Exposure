import { BoxIcon, DocIcon, GlobeIcon, LayoutGridIcon, OctagonAlertIcon, PluginIcon, SystemIcon, UsersIcon } from "@/icons";
import type { NavItem } from "./types";

// Entries are filtered by role at render time (header/index.tsx). The server enforces the same rules.
// One flat row (design spec 1.1): the old "exposure" group and its tab strip are gone; the graph is a view of /devices.
export const navItems: NavItem[] = [
  { icon: <LayoutGridIcon className="size-6" />, key: "overview", path: "/" },
  { icon: <OctagonAlertIcon className="size-6" />, key: "vulnerabilities", path: "/vulnerabilities" },
  { icon: <SystemIcon className="size-6" />, key: "devices", path: "/devices" },
  { icon: <BoxIcon className="size-6" />, key: "software", path: "/software" },
  { icon: <GlobeIcon className="size-6" />, key: "external", path: "/external" },
  { icon: <DocIcon className="size-6" />, key: "news", path: "/news" },
  { icon: <PluginIcon className="size-6" />, key: "settings", path: "/settings", gate: "super" },
  { icon: <UsersIcon className="size-6" />, key: "team", path: "/team", gate: "tenantAdmin" },
];

// Integrations, tenants, team and audit log live in the Setting Center (/settings); a tenant admin has /team.
export const othersItems: NavItem[] = [];

export const supportItems: NavItem[] = [];
