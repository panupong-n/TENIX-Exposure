import React from "react";

export type MenuType = "main" | "support" | "others";

export interface SubItem {
  key: string;
  path: string;
  pro?: boolean;
  new?: boolean;
  target?: string;
}

export interface NavItem {
  key: string;
  icon: React.ReactNode;
  path?: string;
  new?: boolean;
  target?: string;
  subItems?: SubItem[];
  /** Who sees the entry: super admins only, anyone who can manage a tenant, or tenant admins who are not super admins. Everyone when omitted. */
  gate?: "super" | "manager" | "tenantAdmin";
  /** Paths (and their sub-paths) that make the entry active; defaults to `path`. */
  match?: string[];
}
