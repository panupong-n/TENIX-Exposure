import type { Completeness } from "@/components/shared/data-status";

export interface Summary {
  tenant: { id: string; name: string };
  completeness: Completeness;
  severity: Record<string, number>;
  totals: { findings: number; hosts: number; cves: number; exploited: number };
  topCves: { cveId: string; severity: string; baseScore: number | null; exploitStatus: number | null; hosts: number }[];
  topHosts: { cid?: string; aid: string; hostname: string | null; platform: string | null; cves: number; critical: number; high: number; medium: number }[];
  days: number;
  /** Findings that disappeared from the latest complete sync within 7 / 30 days. Absent on older servers. */
  closed?: { last7: number; last30: number };
  trend: { day: string; critical: number; high: number; medium: number; low: number }[];
}

/** The management part of the Overview: KEV, internet-facing, source split, age, external surface. */
export interface Management {
  tenant: { id: string; name: string };
  completeness: Completeness;
  totals: { critical: number; high: number; devices: number; internetDevices: number; internetCriticalHigh: number };
  kev: { cves: number; devices: number };
  bySource: { endpoint: Record<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE", number>; external: Record<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE", number> };
  aging: { d30: number; d90: number; d180: number; older: number; unknown: number };
  topKev: { cveId: string; severity: string; baseScore: number | null; hosts: number }[];
  external: { assets: number; top: { aid: string; hostname: string | null; severity: string; findings: number; ports: string[] }[] };
}

// ---- API v2 (contracts A and B). Every field the server may leave out is optional or nullable: the page tolerates a missing block.
export type Tier = "P1" | "P2" | "P3";
export type LevelKey = "low" | "medium" | "high" | "critical";
export interface SummaryV2 {
  tenant: { id: string; name: string };
  completeness: Completeness;
  hostsSync?: { state: string; asOf: number | null; lastRunAt: number | null; hosts: number };
  headline?: {
    p1: number; p1Source?: string; p1Exact?: boolean; hostsWithP1: number; hostsTotal: number; hostShare: number | null; p1Cves: number; p1Fixes: number; internetP1Hosts: number | null;
    level: { key: LevelKey; base: LevelKey; escalated: boolean; share: number; reasons: string[] } | null;
    delta7: { p1: number; pct: number | null; from: number } | null;
  };
  hosts?: { total: number; source: string; withFindings: number; withP1: number; neverSeenFindings: number; stale7: number; stale30: number; duplicates: number; staleTwins: number; internetFacing: number };
  tiers?: { P1: TierRow; P2: TierRow; P3: TierRow; heldTotal: number; falconTotal: number | null; atLeast: boolean };
  severity?: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number; NONE: number; total: number; source: string; endpointOnly?: boolean; held?: Record<string, number> };
  facts?: { kev: number; exploited: number; exprtCritical: number; kevCves?: number; kevHosts?: number; internetP1?: number; kevOverdue?: number; source?: string };
  external?: { findings: number; assets: number };
  freshness?: { findings?: { state: string; asOf: number | null }; hosts?: { state: string; asOf: number | null }; rollupAt?: number | null; falconCountsAsOf?: number | null };
}
export interface TierRow { held: number; total: number; exact: boolean; source: string; hosts: number }
export interface TrendV2 {
  days: number; startedAt: string | null;
  points: { day: string; p1: number }[];
  week?: { newP1: number | null; closedP1: number | null; net: number | null };
}
export interface FixRow {
  id: string; title: string; product: string | null; noFix: boolean; p1: number; p2: number; cves: number; p1Cves: number; kevCves: number;
  hosts: number; p1Hosts: number; internetHosts: number; severity: string; exprt: string | null; impactShare: number | null;
}
export interface FixesV2 { total: number; rows: FixRow[]; totals?: { fixes: number; p1: number; withKev: number } }
export interface HostRowV2 {
  key: string; aid: string; hostname: string | null; platform: string | null; osVersion: string | null; productType: string | null; internetFacing: boolean;
  p1: number; critical: number; kevCves: number; lastSeen: number | null; stale?: string; worstSeverity: string | null; watched?: boolean | null;
}
export interface HostsV2 { total: number; rows: HostRowV2[]; facets?: { withP1?: number } }
export interface NewsItem { cve: string; title: string | null; state: "exact" | "possible" | "wait" | "not_affected"; devices: number; severity: string | null; kev: boolean; publishedAt: number | null; lastChanged: number | null }
export interface NewsV2 { total: number; counts: Record<string, number>; items: NewsItem[] }
export interface SoftwareRow { key: string; vendor: string; name: string; devices: number; versions: number; p1Cves?: number | null; kevCves?: number | null }
export interface SoftwareList { rows: SoftwareRow[]; total: number; devices: number; completeness?: Completeness }
export interface EasmV2 {
  state: string; asOf: number | null; assets: { ips: number; rootDomains: number; subdomains: number };
  online: Record<string, number>; reviewIps: { reviewed: number; notReviewed: number }; reviewRootDomains: { reviewed: number; notReviewed: number };
}
export interface EasmServices { assetsWithServices: number; services: number; expiredCerts: number; expiringCerts30: number; riskyPorts: number; assetsWithRiskyPorts: number; newLast7d: number }
export interface EasmAsset { id: string; name: string; type: string; review?: string; reviewed: boolean; isNew: boolean; ports: number[]; riskyPorts: number[]; expiredCerts: number; findings: { count: number; worstSeverity: string | null } }
export interface EasmAssets { total: number; items: EasmAsset[] }

export type AttentionReason = "broken_connection" | "kev_new" | "p1_overdue" | "partial" | "stale";
export interface PortfolioTenant {
  id: string; name: string; state: Completeness["state"]; reason: string | null; asOf: number | null; lastRunAt: number | null; ageHours: number | null; stale: boolean;
  p1: number | null; p1Delta7: number | null; p1Spark: number[] | null; hostsWithP1: number | null; hosts: number | null; hostShare: number | null; level: LevelKey | null;
  critical: number | null; kevNew7d: number; p1Overdue: number; easmPendingReview: number | null; mode: "full" | "priority" | "scoped"; heldShare: number | null;
  sync24h: { at: number; state: string; ms: number | null }[]; attention: AttentionReason[];
}
export interface Portfolio {
  generatedAt: number;
  summary: { tenants: number; byState: Record<string, number>; kevNew7d: number; p1Overdue: number; stale: number };
  tenants: PortfolioTenant[];
  attention: { tenantId: string; name: string; reasons: AttentionReason[]; detail: { kevNew7d?: number; p1Overdue?: number; ageHours?: number | null } }[];
  sharedCves: { cveId: string; kev: boolean; tenants: number; hosts: number; severity: string; exprt: string | null }[];
}
