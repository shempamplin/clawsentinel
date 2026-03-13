/**
 * ClawSentinel — Shared Types
 * New file: src/security/skill-scanner-types.ts
 *
 * Type-only exports shared between the backend scanner
 * and the frontend UI components. No runtime code here.
 */

export type SkillScanSeverity = "info" | "warn" | "critical";

export type ThreatCategory =
  | "data-exfiltration"
  | "prompt-injection"
  | "credential-theft"
  | "code-injection"
  | "filesystem-abuse"
  | "obfuscation"
  | "supply-chain"
  | "crypto-mining"
  | "inter-agent-attack"
  | "network-abuse"
  | "cost-bombing"
  | "gateway-abuse";

export type SkillScanFinding = {
  ruleId: string;
  severity: SkillScanSeverity;
  file: string;
  line: number;
  message: string;
  evidence: string;
  category: ThreatCategory;
  frameworks: string[];
  description: string;
  remediation?: string;
  remediable: boolean;
};

export type SkillScanSummary = {
  scannedFiles: number;
  critical: number;
  warn: number;
  info: number;
  findings: SkillScanFinding[];
  remediatedCount?: number;
};

export type SkillScanOptions = {
  includeFiles?: string[];
  maxFiles?: number;
  maxFileBytes?: number;
  disabledRules?: string[];
  streamTo?: SentinelStreamConfig;
  autoRemediate?: boolean;
};

export type SentinelStreamConfig = {
  url: string;
  enabled: boolean;
  categories?: ThreatCategory[];
};

export type RuleMetadata = {
  ruleId: string;
  severity: SkillScanSeverity;
  message: string;
  category: ThreatCategory;
  frameworks: string[];
  description: string;
  remediationNote?: string;
  remediable: boolean;
};