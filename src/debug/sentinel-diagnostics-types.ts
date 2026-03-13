/**
 * ClawSentinel — Shared Diagnostics Types
 * New file: src/debug/sentinel-diagnostics-types.ts
 *
 * Shared type definitions consumed by both the diagnostic engine
 * (sentinel-diagnostics.ts) and the UI view (ui/src/ui/views/diagnostics.ts).
 * Kept in a separate file to avoid importing the full Node.js diagnostic
 * engine into the browser-side Lit UI bundle.
 */

// ─── Core Event Types ─────────────────────────────────────────────────────────

export type DiagnosticLevel = "trace" | "debug" | "info" | "warn" | "error" | "fatal";

export type DiagnosticEvent = {
  id: string;
  timestamp: number;
  level: DiagnosticLevel;
  subsystem: string;
  message: string;
  meta?: Record<string, unknown>;
  stack?: string;
  durationMs?: number;
};

// ─── Performance Profiling Types ──────────────────────────────────────────────

export type RuleProfile = {
  ruleId: string;
  severity: "critical" | "warn" | "info";
  timeMs: number;
  matchCount: number;
  filesChecked: number;
};

export type FileProfile = {
  filePath: string;
  timeMs: number;
  bytes: number;
  findingCount: number;
  skipped: boolean;
};

export type ScanProfile = {
  id: string;
  directory: string;
  startedAt: number;
  completedAt?: number;
  totalTimeMs: number;
  filesScanned: number;
  filesSkipped: number;
  totalFindings: number;
  peakMemoryMb: number;
  ruleProfiles: RuleProfile[];
  fileProfiles: FileProfile[];
};

// ─── Rule Tester Types ────────────────────────────────────────────────────────

export type RuleTestResult = {
  ruleId: string;
  matched: boolean;
  findings: Array<{
    ruleId: string;
    severity: string;
    line: number;
    message: string;
    evidence: string;
  }>;
  matchedLines: number[];
  highlightedSource: string;
  timeMs: number;
  error?: string;
};

// ─── Self-Test Types ──────────────────────────────────────────────────────────

export type SelfTestCase = {
  id: string;
  ruleId: string;
  description: string;
  input: string;
  expectMatch: boolean;
  context?: Record<string, string>;
};

export type SelfTestResult = SelfTestCase & {
  passed: boolean;
  actual: boolean;
  error?: string;
  timeMs: number;
};

export type SelfTestReport = {
  totalCases: number;
  passed: number;
  failed: number;
  errors: number;
  rulesCovered: string[];
  rulesNotCovered: string[];
  results: SelfTestResult[];
  totalTimeMs: number;
};

// ─── Bug Report Types ─────────────────────────────────────────────────────────

export type SystemHealthCheck = {
  scannerLoaded: boolean;
  filesystemReadable: boolean;
  logServerReachable: boolean;
  nodeVersion: string;
  heapUsedMb: number;
  heapTotalMb: number;
  uptime: number;
  platform: string;
};

export type SentinelBugReport = {
  reportVersion: "1";
  generatedAt: string;
  environment: {
    nodeVersion: string;
    platform: string;
    arch: string;
    uptime: number;
    heapUsedMb: number;
  };
  recentErrors: DiagnosticEvent[];
  lastScanProfile?: ScanProfile;
  selfTestReport?: SelfTestReport;
  ruleInventory: Array<{ ruleId: string; severity: string; enabled: boolean }>;
  systemHealth: SystemHealthCheck;
  reproductionSteps: string[];
};