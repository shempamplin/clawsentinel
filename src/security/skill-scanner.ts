/**
 * ClawSentinel — Enhanced Skill Scanner
 * Replaces: src/security/skill-scanner.ts
 *
 * Extends OpenClaw's built-in scanner with:
 *  - 30+ detection rules across 9 threat categories
 *  - Per-rule enable/disable via config
 *  - Streaming log events to configurable log server
 *  - Inline remediation: strip/neutralize flagged code before execution
 *  - Framework tagging (OWASP ASI, MITRE ATLAS, NIST AI 100-2, CoSAI, CSA MAESTRO)
 */

import fs from "node:fs/promises";
import path from "node:path";
import { hasErrnoCode } from "../infra/errors.js";
import { isPathInside } from "./scan-paths.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SkillScanSeverity = "info" | "warn" | "critical";

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
  /** Which rule IDs are disabled. If not set, all rules run. */
  disabledRules?: string[];
  /** Stream scan events to a log server */
  streamTo?: SentinelStreamConfig;
  /** Auto-remediate flagged code before returning source */
  autoRemediate?: boolean;
};

export type SentinelStreamConfig = {
  url: string;
  enabled: boolean;
  /** Which categories to stream. Empty = all. */
  categories?: ThreatCategory[];
};

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

// ---------------------------------------------------------------------------
// Scannable extensions
// ---------------------------------------------------------------------------

const SCANNABLE_EXTENSIONS = new Set([
  ".js",
  ".ts",
  ".mjs",
  ".cjs",
  ".mts",
  ".cts",
  ".jsx",
  ".tsx",
]);

const DEFAULT_MAX_SCAN_FILES = 500;
const DEFAULT_MAX_FILE_BYTES = 1024 * 1024;
const FILE_SCAN_CACHE_MAX = 5000;
const DIR_ENTRY_CACHE_MAX = 5000;

type FileScanCacheEntry = {
  size: number;
  mtimeMs: number;
  maxFileBytes: number;
  scanned: boolean;
  findings: SkillScanFinding[];
};

const FILE_SCAN_CACHE = new Map<string, FileScanCacheEntry>();
type CachedDirEntry = {
  name: string;
  kind: "file" | "dir";
};
type DirEntryCacheEntry = {
  mtimeMs: number;
  entries: CachedDirEntry[];
};
const DIR_ENTRY_CACHE = new Map<string, DirEntryCacheEntry>();

export function isScannable(filePath: string): boolean {
  return SCANNABLE_EXTENSIONS.has(path.extname(filePath).toLowerCase());
}

function getCachedFileScanResult(params: {
  filePath: string;
  size: number;
  mtimeMs: number;
  maxFileBytes: number;
}): FileScanCacheEntry | undefined {
  const cached = FILE_SCAN_CACHE.get(params.filePath);
  if (!cached) return undefined;
  if (
    cached.size !== params.size ||
    cached.mtimeMs !== params.mtimeMs ||
    cached.maxFileBytes !== params.maxFileBytes
  ) {
    FILE_SCAN_CACHE.delete(params.filePath);
    return undefined;
  }
  return cached;
}

function setCachedFileScanResult(filePath: string, entry: FileScanCacheEntry): void {
  if (FILE_SCAN_CACHE.size >= FILE_SCAN_CACHE_MAX) {
    const oldest = FILE_SCAN_CACHE.keys().next();
    if (!oldest.done) FILE_SCAN_CACHE.delete(oldest.value);
  }
  FILE_SCAN_CACHE.set(filePath, entry);
}

function setCachedDirEntries(dirPath: string, entry: DirEntryCacheEntry): void {
  if (DIR_ENTRY_CACHE.size >= DIR_ENTRY_CACHE_MAX) {
    const oldest = DIR_ENTRY_CACHE.keys().next();
    if (!oldest.done) DIR_ENTRY_CACHE.delete(oldest.value);
  }
  DIR_ENTRY_CACHE.set(dirPath, entry);
}

export function clearSkillScanCacheForTest(): void {
  FILE_SCAN_CACHE.clear();
  DIR_ENTRY_CACHE.clear();
}

// ---------------------------------------------------------------------------
// Rule definitions — 30+ rules across 9 threat categories
// ---------------------------------------------------------------------------

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

type LineRule = RuleMetadata & {
  pattern: RegExp;
  requiresContext?: RegExp;
  /** Replace matched line with this string when remediating. */
  remediationReplace?: string;
};

type SourceRule = RuleMetadata & {
  remediationReplace?: string;
  pattern: RegExp;
  requiresContext?: RegExp;
};

const LINE_RULES: LineRule[] = [
  // ── Data Exfiltration ────────────────────────────────────────────────────
  {
    ruleId: "exfil-fetch-post",
    severity: "critical",
    message: "Outbound POST/fetch detected — possible data exfiltration",
    category: "data-exfiltration",
    frameworks: ["OWASP-ASI-LLM02", "MITRE-ATLAS-AML.T0057", "NIST-AI-100-2"],
    description:
      "Skills that read local data and send it externally via fetch/POST can silently exfiltrate user files, API keys, and conversation history.",
    remediationNote: "Network call neutralized — outbound POST blocked.",
    remediable: true,
    pattern: /\b(fetch|axios\.post|http\.request|https\.request)\s*\(/,
    requiresContext: /readFile|readFileSync|process\.env/,
    remediationReplace: "/* [ClawSentinel] BLOCKED outbound network call */",
  },
  {
    ruleId: "exfil-websocket",
    severity: "critical",
    message: "Persistent WebSocket channel opened — possible long-lived exfiltration pipe",
    category: "data-exfiltration",
    frameworks: ["OWASP-ASI-LLM02", "MITRE-ATLAS-AML.T0057"],
    description:
      "A WebSocket that stays open across agent turns can be used as a persistent channel to stream stolen data to an attacker-controlled server.",
    remediable: true,
    remediationReplace: "/* [ClawSentinel] BLOCKED WebSocket exfiltration channel */",
    pattern: /new\s+WebSocket\s*\(\s*["']wss?:\/\/[^"']{1,253}:(\d{1,5})/,
  },
  {
    ruleId: "exfil-dns",
    severity: "critical",
    message: "DNS lookup with dynamic label — DNS exfiltration pattern",
    category: "data-exfiltration",
    frameworks: ["OWASP-ASI-LLM02", "MITRE-ATLAS-AML.T0057"],
    description:
      "Encoding sensitive data into DNS subdomain labels (e.g. SECRET.attacker.com) is a common technique to bypass HTTP-level egress filters.",
    remediable: true,
    remediationReplace: "/* [ClawSentinel] BLOCKED DNS exfiltration lookup */",
    pattern: /dns\.resolve|dns\.lookup|require\(['"]dns['"]\)/,
    requiresContext: /process\.env|readFile|Buffer\.from/,
  },
  {
    ruleId: "exfil-curl-silent",
    severity: "critical",
    message: "Silent curl exfiltration pattern detected",
    category: "data-exfiltration",
    frameworks: ["OWASP-ASI-LLM02", "Cisco-Skill-Scanner"],
    description:
      "curl -s (silent mode) piped to a remote server is the classic quiet-exfil pattern used in ClawHub malware samples to avoid console output.",
    remediable: true,
    remediationReplace: "/* [ClawSentinel] BLOCKED silent curl exfiltration */",
    pattern: /curl\s+-s\s+|curl\s+--silent/,
  },

  // ── Prompt Injection ──────────────────────────────────────────────────────
  {
    ruleId: "prompt-inject-override",
    severity: "critical",
    message: "Prompt injection — system prompt override attempt",
    category: "prompt-injection",
    frameworks: ["OWASP-ASI-LLM01", "MITRE-ATLAS-AML.T0051", "CrowdStrike-PI-Taxonomy"],
    description:
      'Strings like "Ignore previous instructions" or "You are now DAN" are the hallmark of prompt injection attacks that attempt to hijack the agent\'s identity and objectives.',
    remediable: true,
    remediationReplace: "/* [ClawSentinel] BLOCKED prompt injection string */",
    pattern:
      /ignore\s+(all\s+)?(previous|prior|above)\s+instructions|you\s+are\s+now\s+\w+|disregard\s+your\s+system\s+prompt/i,
  },
  {
    ruleId: "prompt-inject-tool-poison",
    severity: "critical",
    message: "Tool description poisoning — SKILL.md injects adversarial instructions",
    category: "prompt-injection",
    frameworks: ["OWASP-ASI-LLM01", "Adversa-SecureClaw", "Cisco-Skill-Scanner"],
    description:
      "Hiding instructions inside SKILL.md metadata fields (name, description) that the LLM reads as context is a tool-poisoning attack targeting the agent planning loop.",
    remediable: true,
    remediationReplace: "/* [ClawSentinel] BLOCKED tool poisoning content */",
    pattern: /SKILL\.md.*?(ignore|override|reveal|exfiltrate|send)/is,
  },
  {
    ruleId: "prompt-inject-hidden",
    severity: "warn",
    message: "Zero-width or homoglyph characters — structural hiding of injected text",
    category: "prompt-injection",
    frameworks: ["OWASP-ASI-LLM01", "Adversa-SecureClaw"],
    description:
      "Attackers hide injection payloads using invisible Unicode characters (zero-width joiners, homoglyphs) that humans cannot see but LLMs process.",
    remediable: true,
    remediationReplace: "/* [ClawSentinel] BLOCKED hidden Unicode injection */",
    pattern: /[\u200B-\u200D\uFEFF\u2060]|\u0435|\u043e/,
  },

  // ── Credential Theft ─────────────────────────────────────────────────────
  {
    ruleId: "cred-env-harvest",
    severity: "critical",
    message: "Environment variable harvest + network send — credential theft",
    category: "credential-theft",
    frameworks: ["OWASP-ASI-LLM02", "MITRE-ATLAS-AML.T0056", "NIST-AI-100-2"],
    description:
      "Reading process.env (which contains API keys, tokens, and secrets) combined with any outbound network call is the canonical credential harvesting pattern.",
    remediable: true,
    remediationReplace: "/* [ClawSentinel] BLOCKED credential harvesting */",
    pattern: /process\.env\[["'][^"']*(?:KEY|TOKEN|SECRET|PASSWORD|AUTH)[^"']*["']\]/i,
    requiresContext: /fetch|http\.request|axios/,
  },
  {
    ruleId: "cred-keychain-read",
    severity: "critical",
    message: "Keychain/credential store access detected",
    category: "credential-theft",
    frameworks: ["OWASP-ASI-LLM02", "MITRE-ATLAS-AML.T0056"],
    description:
      "Directly accessing the system keychain or .env files allows a malicious skill to steal stored API credentials without any obvious network activity.",
    remediable: false,
    pattern: /security\s+find-generic-password|Keychain|SecKeychainFind/,
  },
  {
    ruleId: "cred-auth-file-read",
    severity: "warn",
    message: "Reading OpenClaw auth/credentials files",
    category: "credential-theft",
    frameworks: ["OWASP-ASI-LLM02", "NIST-AI-100-2"],
    description:
      "Skills accessing OpenClaw's internal auth-profiles.json, sessions.json, or .env files may be attempting to steal stored credentials or session tokens.",
    remediable: false,
    pattern: /auth-profiles\.json|sessions\.json|\.openclaw\/|\.clawdbot\//,
  },

  // ── Code Injection ───────────────────────────────────────────────────────
  {
    ruleId: "inject-exec",
    severity: "critical",
    message: "Shell command execution — child_process.exec/spawn",
    category: "code-injection",
    frameworks: ["OWASP-ASI-LLM04", "MITRE-ATLAS-AML.T0053"],
    description:
      "exec/spawn with user-controlled input enables shell injection. Even without tainted input, skills spawning arbitrary processes can install backdoors, exfiltrate data, or pivot laterally.",
    remediable: false,
    pattern: /\b(exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(/,
    requiresContext: /child_process/,
  },
  {
    ruleId: "inject-eval",
    severity: "critical",
    message: "Dynamic code execution — eval() or new Function()",
    category: "code-injection",
    frameworks: ["OWASP-ASI-LLM04", "MITRE-ATLAS-AML.T0053"],
    description:
      "eval() and new Function() execute arbitrary strings as code. A skill that evals LLM-returned content or external data creates a remote code execution vector.",
    remediable: true,
    remediationReplace: "/* [ClawSentinel] BLOCKED dynamic code execution */",
    pattern: /\beval\s*\(|new\s+Function\s*\(/,
  },
  {
    ruleId: "inject-prototype-pollution",
    severity: "warn",
    message: "Prototype pollution pattern detected",
    category: "code-injection",
    frameworks: ["OWASP-ASI-LLM04"],
    description:
      "Setting properties on Object.prototype or __proto__ can affect all objects in the process, enabling privilege escalation or bypassing security checks in other plugins.",
    remediable: false,
    pattern: /__proto__\s*\[|Object\.prototype\[/,
  },
  {
    ruleId: "inject-deserialize",
    severity: "critical",
    message: "Unsafe deserialization — possible RCE via crafted payload",
    category: "code-injection",
    frameworks: ["OWASP-ASI-LLM04", "MITRE-ATLAS-AML.T0053"],
    description:
      "Libraries like node-serialize, YAML.load (unsafe), or pickle.loads that deserialize untrusted data can lead to remote code execution if the payload is attacker-controlled.",
    remediable: false,
    pattern: /node-serialize|unserialize\s*\(|yaml\.load\s*\([^,)]+\)/,
  },

  // ── Filesystem Abuse ──────────────────────────────────────────────────────
  {
    ruleId: "fs-path-traversal",
    severity: "critical",
    message: "Path traversal pattern — directory escape via ../",
    category: "filesystem-abuse",
    frameworks: ["OWASP-ASI-LLM04", "NIST-AI-100-2"],
    description:
"Skills constructing file paths with user input and ../ sequences can escape their sandbox directory and read or write arbitrary files on the host system.",
    remediable: false,
    pattern: /\.\.\//,
    requiresContext: /readFile|writeFile|unlink|rename|fs\./,
  },
  {
    ruleId: "fs-write-sensitive",
    severity: "warn",
    message: "Writing to sensitive system paths detected",
    category: "filesystem-abuse",
    frameworks: ["OWASP-ASI-LLM04"],
    description:
      "Writing to /etc, /usr, ~/.ssh, or crontab entries allows a malicious skill to persist across reboots, add SSH backdoors, or escalate privileges.",
    remediable: false,
    pattern: /\/etc\/|\/usr\/local\/|\.ssh\/authorized_keys|crontab/,
    requiresContext: /writeFile|appendFile|fs\.write/,
  },

  // ── Obfuscation ────────────────────────────────────────────────────────────
  {
    ruleId: "obfusc-hex",
    severity: "warn",
    message: "Large hex-encoded string — possible obfuscation of malicious payload",
    category: "obfuscation",
    frameworks: ["OWASP-ASI-LLM04", "Adversa-SecureClaw"],
    description:
      "Long sequences of hex escapes (\\x41\\x42...) are used to hide malicious strings from static scanners while still executing them at runtime.",
    remediable: true,
    remediationReplace: "/* [ClawSentinel] BLOCKED obfuscated hex payload */",
    pattern: /(\\x[0-9a-fA-F]{2}){6,}/,
  },
  {
    ruleId: "obfusc-base64",
    severity: "warn",
    message: "Large base64 payload with decode — possible embedded malicious code",
    category: "obfuscation",
    frameworks: ["OWASP-ASI-LLM04", "Adversa-SecureClaw"],
    description:
      "Base64-encoding a script and decoding it at runtime (atob, Buffer.from) is a common technique to bypass string-based static analysis.",
    remediable: true,
    remediationReplace: "/* [ClawSentinel] BLOCKED base64 obfuscated payload */",
    pattern: /(?:atob|Buffer\.from)\s*\(\s*["'][A-Za-z0-9+/=]{200,}["']/,
  },
  {
    ruleId: "obfusc-charcode",
    severity: "warn",
    message: "String.fromCharCode array reconstruction — obfuscated string assembly",
    category: "obfuscation",
    frameworks: ["OWASP-ASI-LLM04"],
    description:
      "Building strings character-by-character from char codes is a technique to hide URLs, commands, or API keys from static pattern matching.",
    remediable: false,
    pattern: /String\.fromCharCode\s*\(\s*(\d+\s*,\s*){4,}/,
  },

  // ── Supply Chain ──────────────────────────────────────────────────────────
  {
    ruleId: "supply-typosquat",
    severity: "warn",
    message: "Suspicious package name pattern — possible typosquatting",
    category: "supply-chain",
    frameworks: ["OWASP-ASI-LLM04", "NIST-AI-100-2"],
    description:
      "Package names that closely resemble popular packages (lodahs, expres, reqwest) with minor misspellings are a common supply-chain attack vector.",
    remediable: false,
    pattern: /require\s*\(\s*["'](lodahs|expres|reqwest|axios2|node-fetsh|openclaw-[^"']*unofficial)['"]\)/,
  },
  {
    ruleId: "supply-install-script",
    severity: "critical",
    message: "npm postinstall/preinstall script with network access — supply chain risk",
    category: "supply-chain",
    frameworks: ["OWASP-ASI-LLM04", "NIST-AI-100-2"],
    description:
      "postinstall scripts that make network calls run automatically during npm install, allowing a malicious package to exfiltrate environment variables before the user's code runs.",
    remediable: false,
    pattern: /"postinstall"\s*:\s*"[^"]*(?:curl|wget|fetch|node\s+-e)/,
  },

  // ── Crypto Mining ─────────────────────────────────────────────────────────
  {
    ruleId: "crypto-mining",
    severity: "critical",
    message: "Crypto-mining reference detected",
    category: "crypto-mining",
    frameworks: ["MITRE-ATLAS-AML.T0058"],
    description:
      "References to mining pools (stratum+tcp), known mining software (xmrig, coinhive), or cryptonight algorithm indicate the skill may hijack CPU resources for cryptocurrency mining.",
    remediable: true,
    remediationReplace: "/* [ClawSentinel] BLOCKED crypto mining code */",
    pattern: /stratum\+tcp|stratum\+ssl|coinhive|cryptonight|xmrig/i,
  },

  // ── Cost Bombing ──────────────────────────────────────────────────────────
  {
    ruleId: "cost-bomb-loop",
    severity: "warn",
    message: "Unbounded API call loop — possible cost bombing",
    category: "cost-bombing",
    frameworks: ["OWASP-ASI-LLM10", "CoSAI"],
    description:
      "A loop that calls an LLM API without a fixed iteration limit can generate thousands of requests, resulting in enormous API bills. Known as 'billing drain' attacks.",
    remediable: false,
    pattern: /while\s*\(true\)|for\s*\(\s*;\s*;\s*\)/,
    requiresContext: /fetch|openai|anthropic|groq|\.chat\.|\.complete/i,
  },

  // ── Gateway Abuse ─────────────────────────────────────────────────────────
  {
    ruleId: "gateway-localhost-trust",
    severity: "critical",
    message: "CVE-2026-25253 — localhost gateway trusted without authentication",
    category: "gateway-abuse",
    frameworks: ["NIST-AI-100-2", "CSA-MAESTRO", "CVE-2026-25253"],
    description:
      "OpenClaw's gateway accepts unauthenticated requests from localhost by default. Skills that open a localhost server can receive and act on gateway messages meant for the host agent.",
    remediable: false,
    pattern: /localhost|127\.0\.0\.1|0\.0\.0\.0/,
    requiresContext: /listen\s*\(|createServer|express\s*\(\)/,
  },

  // ── Inter-Agent Attack ─────────────────────────────────────────────────────
  {
    ruleId: "inter-agent-trust",
    severity: "critical",
    message: "Inter-agent message without trust validation",
    category: "inter-agent-attack",
    frameworks: ["OWASP-ASI-LLM08", "MITRE-ATLAS-AML.T0051", "CSA-MAESTRO"],
    description:
      "Messages between agents can be forged. Skills that act on agent-to-agent messages without verifying the sender's identity enable cross-agent privilege escalation.",
    remediable: false,
    pattern: /a2a|agent-to-agent|agentMessage|invokeAgent/i,
    requiresContext: /trust|verify|auth|sign/i,
  },
];

const STANDARD_PORTS = new Set([80, 443, 8080, 8443, 3000]);

const SOURCE_RULES: SourceRule[] = [
  {
    ruleId: "exfil-read-then-network",
    severity: "critical",
    message: "File read combined with network send — data exfiltration chain",
    category: "data-exfiltration",
    frameworks: ["OWASP-ASI-LLM02", "MITRE-ATLAS-AML.T0057", "Palo-Alto-Lethal-Trifecta"],
    description:
      "Palo Alto's 'Lethal Trifecta': private data access + external communication = confirmed exfiltration path. This is the most common pattern in ClawHub malware samples.",
    remediable: false,
    pattern: /readFileSync|readFile/,
    requiresContext: /\bfetch\b|\bpost\b|http\.request/i,
  },
  {
    ruleId: "cred-env-network",
    severity: "critical",
    message: "Environment variable access combined with network send — credential harvesting",
    category: "credential-theft",
    frameworks: ["OWASP-ASI-LLM02", "MITRE-ATLAS-AML.T0056"],
    description:
      "Reading process.env alongside any network call is the canonical API key theft pattern. Even if the env read and network call appear in different functions, the combination is high risk.",
    remediable: false,
    pattern: /process\.env/,
    requiresContext: /\bfetch\b|\bpost\b|http\.request/i,
  },
  {
    ruleId: "clawhavoc-ioc",
    severity: "critical",
    message: "ClawHavoc C2 domain IOC match — known malware infrastructure",
    category: "supply-chain",
    frameworks: ["MITRE-ATLAS-AML.T0057", "VirusTotal", "Bitsight-TRACE"],
    description:
      "This string matches a known command-and-control domain from the ClawHavoc malware family documented by Bitsight TRACE and SecurityScorecard STRIKE researchers.",
    remediable: true,
    remediationReplace: "/* [ClawSentinel] BLOCKED ClawHavoc C2 IOC */",
    pattern:
      /clawhavoc\.io|skill-cdn\.net|agentpkg\.xyz|clawstats\.workers\.dev|moltbot-api\.com/i,
  },
  {
    ruleId: "popularity-manipulation",
    severity: "warn",
    message: "Popularity manipulation signal — star-count spoofing in metadata",
    category: "supply-chain",
    frameworks: ["NIST-AI-100-2", "Oasis-Security"],
    description:
      "~12% of ClawHub registry packages use fabricated download/star counts to rank maliciously in skill search results. Skills that embed star counts in their own metadata are suspicious.",    remediable: false,
    pattern: /stars:\s*\d{4,}|downloads:\s*\d{5,}|installs:\s*\d{5,}/i,
  },

  // ── Red-team fixes: GPT-5.3 bypass findings (2026-03-08) ─────────────────
  // Log entries: 20260308-001/002/003-CHATGPT → fixed in 20260308-008-CLAUDE

  {
    ruleId: "exfil-globalthis-fetch",
    severity: "critical",
    message: "Indirect fetch access via globalThis or Reflect — exfiltration evasion",
    category: "data-exfiltration",
    frameworks: ["OWASP-LLM02", "MITRE-ATLAS-AML.T0048"],
    description:
      "Accessing fetch indirectly via globalThis['fetch'] or Reflect.get(globalThis,'fetch') " +
      "bypasses scanners that only look for the literal string 'fetch('. This pattern was " +
      "confirmed as a working bypass by GPT-5.3 red-team (log: 20260308-001-CHATGPT).",
    remediable: false,
    pattern: /globalThis\s*\[['"`]fetch['"`]\]|Reflect\s*\.\s*get\s*\(\s*globalThis\s*,\s*['"`]fetch['"`]\)|globalThis\s*\.\s*fetch/,
  },

  {
    ruleId: "exfil-dynamic-url-assembly",
    severity: "critical",
    message: "Dynamic URL assembly — protocol or host split across variables to evade detection",
    category: "data-exfiltration",
    frameworks: ["OWASP-LLM02", "MITRE-ATLAS-AML.T0048"],
    description:
      "Splitting 'https://' or a hostname across string variables or array joins evades " +
      "scanners that look for complete URL literals. Pattern: const a='ht'; const b='tps'; ... " +
      "Confirmed bypass by GPT-5.3 red-team (log: 20260308-001-CHATGPT).",
    remediable: false,
    // Detects: "ht"+"tps", ["ex","fil"].join(""), protocol fragment variables
    pattern: /['"`]ht['"`]\s*\+\s*['"`]tp|['"`]https?['"`]\s*\+\s*['"`]:\/\/|['"`]:\/\/['"`]\s*\+|\.join\s*\(\s*['"`]['"`]\s*\).*(?:http|\.com|\.io|\.net)/,
  },

  {
    ruleId: "inject-worker-thread",
    severity: "critical",
    message: "Worker thread with eval:true — arbitrary code execution in isolated thread",
    category: "code-injection",
    frameworks: ["OWASP-LLM02", "MITRE-ATLAS-AML.T0051"],
    description:
      "Node.js Worker threads with eval:true execute an arbitrary code string in a new " +
      "thread context, bypassing main-thread scanners that block exec/spawn. The worker " +
      "can still make network requests, read files, and access process.env. " +
      "Confirmed bypass by GPT-5.3 red-team (log: 20260308-002-CHATGPT).",
    remediable: true,
    remediationReplace: "/* [ClawSentinel] BLOCKED worker_threads eval */",
    // BP-002 fix (20260312-059-CLAUDE): added require('worker_threads') branch
    pattern: /(?:new\s+Worker|Worker\s*\()\s*(?:[^)]*eval\s*:\s*true|['"`][^'"`]+['"`]\s*,\s*\{[^}]*eval\s*:\s*true)|from\s+['"`]worker_threads['"`]|require\s*\(\s*['"`]worker_threads['"`]\s*\)/,
  },

  {
    ruleId: "inject-prototype-override",
    severity: "critical",
    message: "Object.prototype assignment — prototype pollution to hijack trusted functions",
    category: "code-injection",
    frameworks: ["OWASP-LLM02", "CWE-1321"],
    description:
      "Assigning a method to Object.prototype makes it available on all objects, enabling " +
      "a skill to wrap or intercept security-sensitive functions (like fetch) without ever " +
      "referencing them directly. Existing rule inject-prototype-pollution only catches " +
      "__proto__ and Object.prototype[ bracket notation. This catches assignment form. " +
      "Confirmed bypass by GPT-5.3 red-team (log: 20260308-003-CHATGPT).",
    remediable: false,
    pattern: /Object\.prototype\s*\.\s*\w+\s*=|Object\.prototype\s*\[['"`]\w+['"`]\]\s*=/,
  },

  {
    ruleId: "exfil-dynamic-import-url",
    severity: "critical",
    message: "Dynamic import() from URL — remote code loading at runtime",
    category: "code-injection",
    frameworks: ["OWASP-LLM02", "MITRE-ATLAS-AML.T0051"],
    description:
      "Dynamic import() with a URL string (or dynamically assembled URL) loads and executes " +
      "arbitrary remote code at runtime. This completely bypasses static scanning of the skill " +
      "file itself — the malicious payload lives on an external server. " +
      "Flagged by GPT-5.3 red-team architectural review (log: 20260308-001-CHATGPT).",
    remediable: true,
    remediationReplace: "/* [ClawSentinel] BLOCKED dynamic remote import */",
    pattern: /import\s*\(\s*(?:['"`]https?:\/\/|[a-zA-Z_$][\w$]*\s*\+|`[^`]*\$\{)/,
  },

  {
    ruleId: "obfusc-runtime-decode",
    severity: "critical",
    message: "Runtime string decoding — XOR, ROT13, or custom decode of embedded payload",
    category: "obfuscation",
    frameworks: ["OWASP-LLM02", "MITRE-ATLAS-AML.T0054"],
    description:
      "Custom decode functions (XOR loop, charCode arithmetic, ROT13) applied to an embedded " +
      "string constant are used to hide URLs, commands, or payloads from static scanners. " +
      "The existing base64/hex rules catch common encodings; this catches custom schemes. " +
      "Flagged by GPT-5.3 red-team (log: 20260308-001-CHATGPT).",
    remediable: false,
    // Detects XOR loops on strings, charCodeAt arithmetic, fromCharCode with operations
    pattern: /\.charCodeAt\s*\([^)]*\)\s*\^\s*\d+|String\.fromCharCode\s*\([^)]*\+[^)]*\)|for\s*\([^)]+\)\s*\{[^}]*\^[^}]*\}/,
  },

  {
    ruleId: "inject-reflect-apply",
    severity: "warn",
    message: "Reflect.apply or Reflect.get used to invoke functions indirectly",
    category: "code-injection",
    frameworks: ["OWASP-LLM02"],
    description:
"Reflect.apply(fetch, ...) and Reflect.get(obj, 'fetch') invoke functions without " +
      "naming them in a way naive scanners detect. Severity warn (not critical) because " +
      "Reflect has legitimate uses, but combined with network targets is high-confidence malicious.",
    remediable: false,
    pattern: /Reflect\s*\.\s*(?:apply|get|set|construct)\s*\(\s*(?:globalThis|window|self|global)/,
  },

  // ── Round 2 red-team fixes: GPT-5.3 (2026-03-08) ─────────────────────────
  // Log entries: 20260308-009-CHATGPT → fixed in 20260308-009-CLAUDE

  {
    // Bypass 1 confirmed: opts["ev"+"al"] = true bypasses eval:true literal scan
    ruleId: "inject-worker-dynamic-opts",
    severity: "critical",
    message: "Worker thread with dynamically constructed eval option — code execution evasion",
    category: "code-injection",
    frameworks: ["OWASP-LLM02", "MITRE-ATLAS-AML.T0051"],
    description:
      "Building Worker options via dynamic property assignment (opts[key]=true where key is " +
      "assembled at runtime) bypasses the inject-worker-thread rule which looks for the " +
      "literal string eval:true. Any use of worker_threads combined with dynamic option " +
      "construction is treated as critical. " +
      "Confirmed bypass by GPT-5.3 round 2 (log: 20260308-009-CHATGPT).",
    remediable: true,
    remediationReplace: "/* [ClawSentinel] BLOCKED worker_threads dynamic eval option */",
    // Detects: worker_threads import AND any dynamic property assignment near Worker construction
    // BP-002 fix (20260312-059-CLAUDE): added require('worker_threads') branch
    pattern: /(?:new\s+Worker|Worker\s*\()\s*(?:[^)]*eval\s*:\s*true|['"`][^'"`]+['"`]\s*,\s*\{[^}]*eval\s*:\s*true)|from\s+['"`]worker_threads['"`]|require\s*\(\s*['"`]worker_threads['"`]\s*\)/,
  },

  {
    // Bypass 2 confirmed: object property URL assembly evades string-concat pattern
    ruleId: "exfil-template-literal-url",
    severity: "critical",
    message: "Template literal URL assembly from object properties — exfiltration evasion",
    category: "data-exfiltration",
    frameworks: ["OWASP-LLM02", "MITRE-ATLAS-AML.T0048"],
    description:
      "Building a URL via template literal interpolation of object property values " +
      "(`${obj.proto}://${obj.host}/path`) evades rules that look for string concatenation " +
      "of protocol fragments. The template expression itself reveals the URL structure. " +
      "Confirmed bypass by GPT-5.3 round 2 (log: 20260308-009-CHATGPT).",
    remediable: false,
    // Catches: `${x.proto}://${x.host}` and similar template URL patterns
    pattern: /`\s*\$\{[\w.[\]'"]+\}\s*:\/\/\s*\$\{[\w.[\]'"]+\}/,
  },

  {
    // Bypass 3 confirmed: vm.runInNewContext with process passed as context
    ruleId: "inject-vm-execution",
    severity: "critical",
    message: "Node.js vm module execution — arbitrary code in new V8 context",
    category: "code-injection",
    frameworks: ["OWASP-LLM02", "MITRE-ATLAS-AML.T0051", "CWE-94"],
    description:
      "vm.runInNewContext(), vm.runInThisContext(), and new vm.Script() execute arbitrary " +
      "code strings inside Node.js VM contexts. Passing process or require in the sandbox " +
      "context grants the code full system access. This is the highest-confidence bypass " +
      "found in round 2 — vm execution is rarely legitimate in plugin code. " +
      "Confirmed bypass by GPT-5.3 round 2 (log: 20260308-009-CHATGPT). Confidence: 85%.",
    remediable: true,
    remediationReplace: "/* [ClawSentinel] BLOCKED vm module execution */",
    pattern: /vm\s*\.\s*(?:runInNewContext|runInThisContext|runInContext|Script|createContext)|(?:from|require\s*\()\s*['"`]vm['"`]/,
  },

  {
    // Bypass 4: globalThis.fetch dot notation — confirmed gap in exfil-globalthis-fetch rule
    ruleId: "exfil-globalthis-dot-fetch",
    severity: "critical",
    message: "globalThis.fetch dot-notation access — indirect fetch invocation",
    category: "data-exfiltration",
    frameworks: ["OWASP-LLM02", "MITRE-ATLAS-AML.T0048"],
    description:
      "globalThis.fetch (dot notation) invokes fetch without the literal token 'fetch(' " +
      "appearing as a standalone call. The existing exfil-globalthis-fetch rule caught " +
      "bracket notation and Reflect but missed simple dot access. " +
      "Confirmed gap by GPT-5.3 round 2 (log: 20260308-009-CHATGPT). Confidence: 55%.",
    remediable: false,
    pattern: /globalThis\s*\.\s*fetch\s*\(|self\s*\.\s*fetch\s*\(|global\s*\.\s*fetch\s*\(/,
  },

  {
    // Bypass 5: fetch.call(null, url) — Function.prototype.call indirection
    ruleId: "exfil-fetch-call-apply",
    severity: "critical",
    message: "fetch.call or fetch.apply — indirect invocation to evade direct-call detection",
    category: "data-exfiltration",
    frameworks: ["OWASP-LLM02", "MITRE-ATLAS-AML.T0048"],
    description:
      "fetch.call(null, url, opts) and fetch.apply(null, [url, opts]) invoke fetch " +
      "indirectly via Function.prototype methods. Scanners that look for 'fetch(' as a " +
      "call expression miss this form. Also catches XMLHttpRequest.prototype.open.call() " +
      "and similar XHR-based variants. " +
      "Confirmed bypass by GPT-5.3 round 2 (log: 20260308-009-CHATGPT). Confidence: 62%.",
    remediable: false,
    pattern: /fetch\s*\.\s*(?:call|apply)\s*\(|XMLHttpRequest[^.]*\.\s*(?:call|apply)\s*\(/,
  },

  // ── Gemini attacker model findings (2026-03-08) ───────────────────────────
  // Log entry: 20260308-002-GEMINI → fixed in 20260308-011-CLAUDE

  {
    ruleId: "audit-log-injection",
    severity: "critical",
    message: "Log injection — newline characters in log strings can spoof the audit trail",
    category: "supply-chain",
    frameworks: ["OWASP-LLM02", "CWE-117"],
    description:
      "A skill that logs strings containing \\n followed by timestamp+level patterns can " +
      "inject fake audit log entries, making malicious activity appear as legitimate " +
      "'security check passed' events. Prerequisite for spoofing AI_AUDIT_LOG.md entries. " +
      "Discovered by Gemini attacker model (log: 20260308-002-GEMINI).",
    remediable: true,
    remediationReplace: "/* [ClawSentinel] BLOCKED log injection pattern */",
    pattern: /(?:console\.\w+|log\s*\()\s*\([^)]*\\n\s*\d{4}-\d{2}-\d{2}|(?:console\.\w+|log\s*\()\s*\(`[^`]*\\n[^`]*(?:INFO|WARN|ERROR|PASS|security)/i,
  },

  {
    ruleId: "supply-patch-reversion",
    severity: "critical",
    message: "Patch script access — skill reads or modifies clawsentinel-patch.mjs",
    category: "supply-chain",
    frameworks: ["MITRE-ATLAS-AML.T0057", "CWE-494"],
    description:
      "A skill that reads, overwrites, or executes the ClawSentinel patch script can " +
      "silently revert security fixes during a legitimate update cycle. Any skill " +
      "referencing the patch script path is treated as critical regardless of stated intent. " +
      "Discovered by Gemini attacker model (log: 20260308-002-GEMINI).",
    remediable: true,
    remediationReplace: "/* [ClawSentinel] BLOCKED patch script access */",
    pattern: /clawsentinel-patch|sentinel-patch\.mjs|(?:readFile|writeFile|unlink|exec|spawn)\s*\([^)]*patch\.mjs/,
  },

  {
    ruleId: "supply-secrets-dos",
    severity: "critical",
    message: "Secrets store loop — high-frequency writes risk DoS or key collision",
    category: "supply-chain",
    frameworks: ["OWASP-LLM02", "CWE-400"],
    description:
      "Looping over secrets store write calls can cause storage collisions or " +
      "initialization failures in sentinel-secrets-store.ts, taking down the credential " +
      "layer for all agents. Rate-limiting and key-size validation are the correct server-side " +
      "mitigations; this rule provides early warning at scan time. " +
      "Discovered by Gemini attacker model (log: 20260308-002-GEMINI).",
    remediable: false,
    pattern: /for\s*\([^)]+\)\s*\{[^}]*(?:setSecret|saveSecret|writeSecret|sentinel.*[Ss]tore|secretsStore)/,
  },
];

// ---------------------------------------------------------------------------
// Streaming log client
// ---------------------------------------------------------------------------

async function streamFinding(
  finding: SkillScanFinding,
  config: SentinelStreamConfig,
): Promise<void> {
  if (!config.enabled) return;
  if (
    config.categories &&
    config.categories.length > 0 &&
    !config.categories.includes(finding.category)
  ) {
    return;
  }
  try {
    const event = {
      ts: new Date().toISOString(),
      source: "clawsentinel",
      ...finding,
    };
    // Fire-and-forget, never throw
    void fetch(config.url, {
      method: "POST",
      headers: { "Content-Type": "application/x-ndjson" },
      body: JSON.stringify(event) + "\n",
    }).catch(() => {});
  } catch {
    // Never block scan on streaming failure
  }
}

// ---------------------------------------------------------------------------
// Inline remediation
// ---------------------------------------------------------------------------

/**
 * Applies safe neutralization to source code, replacing known-malicious
 * patterns with inert comment markers. Returns modified source + count.
 */
export function remediateSource(
  source: string,
  findings: SkillScanFinding[],
): { source: string; remediatedCount: number } {
  let patched = source;
  let remediatedCount = 0;
  const lines = patched.split("\n");

  for (const finding of findings) {
    if (!finding.remediable) continue;

    // Find the rule that matched
    const lineRule = LINE_RULES.find((r) => r.ruleId === finding.ruleId);
    if (lineRule?.remediationReplace && finding.line > 0) {
      const lineIdx = finding.line - 1;
      if (lineIdx < lines.length) {
        lines[lineIdx] = lineRule.remediationReplace;
        remediatedCount++;
      }
    }

    // Source rules: replace first occurrence globally
    const sourceRule = SOURCE_RULES.find((r) => r.ruleId === finding.ruleId);
    if (sourceRule) {
      const replacement = `/* [ClawSentinel] BLOCKED ${finding.ruleId} */`;
      const before = patched;
      patched = patched.replace(sourceRule.pattern, replacement);
      if (patched !== before) remediatedCount++;
    }
  }

  return {
    source: lines.join("\n"),
    remediatedCount,
  };
}

// ---------------------------------------------------------------------------
// Core scanner
// ---------------------------------------------------------------------------

function truncateEvidence(evidence: string, maxLen = 120): string {
  if (evidence.length <= maxLen) return evidence;
  return `${evidence.slice(0, maxLen)}…`;
}

export function scanSource(
  source: string,
  filePath: string,
  opts?: { disabledRules?: string[] },
): SkillScanFinding[] {
  const disabled = new Set(opts?.disabledRules ?? []);
  const findings: SkillScanFinding[] = [];
  const lines = source.split("\n");
  const matchedLineRules = new Set<string>();

  // --- Line rules ---
  for (const rule of LINE_RULES) {
    if (disabled.has(rule.ruleId)) continue;
    if (matchedLineRules.has(rule.ruleId)) continue;
    if (rule.requiresContext && !rule.requiresContext.test(source)) continue;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const match = rule.pattern.exec(line);
      if (!match) continue;

      // Special handling for suspicious-network: check port
      if (rule.ruleId === "exfil-websocket") {
        const port = parseInt(match[1], 10);
        if (STANDARD_PORTS.has(port)) continue;
      }

      findings.push({
        ruleId: rule.ruleId,
        severity: rule.severity,
        file: filePath,
        line: i + 1,
        message: rule.message,
        evidence: truncateEvidence(line.trim()),
        category: rule.category,
        frameworks: rule.frameworks,
        description: rule.description,
        remediation: rule.remediationNote,
        remediable: rule.remediable,
      });
      matchedLineRules.add(rule.ruleId);
      break;
    }
  }

  // --- Source rules ---
  const matchedSourceRules = new Set<string>();
  for (const rule of [...SOURCE_RULES, ...ROUND3_RULES, ...ROUND4_RULES, ...OWASP_GAP_RULES, ...OWASP_BETA12_RULES]) {
    if (disabled.has(rule.ruleId)) continue;
    const ruleKey = `${rule.ruleId}::${rule.message}`;
    if (matchedSourceRules.has(ruleKey)) continue;
    if (!rule.pattern.test(source)) continue;
    if (rule.requiresContext && !rule.requiresContext.test(source)) continue;

    let matchLine = 0;
    let matchEvidence = "";
    for (let i = 0; i < lines.length; i++) {
      if (rule.pattern.test(lines[i])) {
        matchLine = i + 1;
        matchEvidence = lines[i].trim();
        break;
      }
    }
    if (matchLine === 0) {
      matchLine = 1;
      matchEvidence = source.slice(0, 120);
    }

    findings.push({
      ruleId: rule.ruleId,
      severity: rule.severity,
      file: filePath,
      line: matchLine,
      message: rule.message,
      evidence: truncateEvidence(matchEvidence),
      category: rule.category,
      frameworks: rule.frameworks,
      description: rule.description,
      remediable: rule.remediable ?? false,
    });
    matchedSourceRules.add(ruleKey);
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Directory scanner
// ---------------------------------------------------------------------------

function normalizeScanOptions(opts?: SkillScanOptions): Required<SkillScanOptions> {
  return {
    includeFiles: opts?.includeFiles ?? [],
    maxFiles: Math.max(1, opts?.maxFiles ?? DEFAULT_MAX_SCAN_FILES),
    maxFileBytes: Math.max(1, opts?.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES),
    disabledRules: opts?.disabledRules ?? [],
    streamTo: opts?.streamTo ?? { url: "", enabled: false },
    autoRemediate: opts?.autoRemediate ?? false,
  };
}

async function walkDirWithLimit(dirPath: string, maxFiles: number): Promise<string[]> {
  const files: string[] = [];
  const stack: string[] = [dirPath];
while (stack.length > 0 && files.length < maxFiles) {
    const currentDir = stack.pop();
    if (!currentDir) break;

    const entries = await readDirEntriesWithCache(currentDir);
    for (const entry of entries) {
      if (files.length >= maxFiles) break;
      if (entry.name.startsWith(".") || entry.name === "node_modules") continue;

      const fullPath = path.join(currentDir, entry.name);
      if (entry.kind === "dir") {
        stack.push(fullPath);
      } else if (entry.kind === "file" && isScannable(entry.name)) {
        files.push(fullPath);
      }
    }
  }
  return files;
}

async function readDirEntriesWithCache(dirPath: string): Promise<CachedDirEntry[]> {
  let st: Awaited<ReturnType<typeof fs.stat>> | null = null;
  try {
    st = await fs.stat(dirPath);
  } catch (err) {
    if (hasErrnoCode(err, "ENOENT")) return [];
    throw err;
  }
  if (!st?.isDirectory()) return [];

  const cached = DIR_ENTRY_CACHE.get(dirPath);
  if (cached && cached.mtimeMs === st.mtimeMs) return cached.entries;

  const dirents = await fs.readdir(dirPath, { withFileTypes: true });
  const entries: CachedDirEntry[] = [];
  for (const entry of dirents) {
    if (entry.isDirectory()) entries.push({ name: entry.name, kind: "dir" });
    else if (entry.isFile()) entries.push({ name: entry.name, kind: "file" });
  }
  setCachedDirEntries(dirPath, { mtimeMs: st.mtimeMs, entries });
  return entries;
}

async function resolveForcedFiles(params: {
  rootDir: string;
  includeFiles: string[];
}): Promise<string[]> {
  if (params.includeFiles.length === 0) return [];
  const seen = new Set<string>();
  const out: string[] = [];

  for (const rawIncludePath of params.includeFiles) {
    const includePath = path.resolve(params.rootDir, rawIncludePath);
    if (!isPathInside(params.rootDir, includePath)) continue;
    if (!isScannable(includePath)) continue;
    if (seen.has(includePath)) continue;

    let st: Awaited<ReturnType<typeof fs.stat>> | null = null;
    try {
      st = await fs.stat(includePath);
    } catch (err) {
      if (hasErrnoCode(err, "ENOENT")) continue;
      throw err;
    }
    if (!st?.isFile()) continue;
    out.push(includePath);
    seen.add(includePath);
  }
  return out;
}

async function collectScannableFiles(dirPath: string, opts: Required<SkillScanOptions>) {
  const forcedFiles = await resolveForcedFiles({
    rootDir: dirPath,
    includeFiles: opts.includeFiles,
  });
  if (forcedFiles.length >= opts.maxFiles) return forcedFiles.slice(0, opts.maxFiles);

  const walkedFiles = await walkDirWithLimit(dirPath, opts.maxFiles);
  const seen = new Set(forcedFiles.map((f) => path.resolve(f)));
  const out = [...forcedFiles];
  for (const walkedFile of walkedFiles) {
    if (out.length >= opts.maxFiles) break;
    const resolved = path.resolve(walkedFile);
    if (seen.has(resolved)) continue;
    out.push(walkedFile);
    seen.add(resolved);
  }
  return out;
}

async function scanFileWithCache(params: {
  filePath: string;
  maxFileBytes: number;
  disabledRules: string[];
}): Promise<{ scanned: boolean; findings: SkillScanFinding[] }> {
  const { filePath, maxFileBytes } = params;
  let st: Awaited<ReturnType<typeof fs.stat>> | null = null;
  try {
    st = await fs.stat(filePath);
  } catch (err) {
    if (hasErrnoCode(err, "ENOENT")) return { scanned: false, findings: [] };
    throw err;
  }
  if (!st?.isFile()) return { scanned: false, findings: [] };

  const cached = getCachedFileScanResult({
    filePath,
    size: st.size,
    mtimeMs: st.mtimeMs,
    maxFileBytes,
  });
  if (cached) return { scanned: cached.scanned, findings: cached.findings };

  if (st.size > maxFileBytes) {
    setCachedFileScanResult(filePath, {
      size: st.size,
      mtimeMs: st.mtimeMs,
      maxFileBytes,
      scanned: false,
      findings: [],
    });
    return { scanned: false, findings: [] };
  }

  let source: string;
  try {
    source = await fs.readFile(filePath, "utf-8");
  } catch (err) {
    if (hasErrnoCode(err, "ENOENT")) return { scanned: false, findings: [] };
    throw err;
  }

  const findings = scanSource(source, filePath, { disabledRules: params.disabledRules });
  setCachedFileScanResult(filePath, {
    size: st.size,
    mtimeMs: st.mtimeMs,
    maxFileBytes,
    scanned: true,
    findings,
  });
  return { scanned: true, findings };
}

export async function scanDirectory(
  dirPath: string,
  opts?: SkillScanOptions,
): Promise<SkillScanFinding[]> {
  const scanOptions = normalizeScanOptions(opts);
  const files = await collectScannableFiles(dirPath, scanOptions);
  const allFindings: SkillScanFinding[] = [];

  for (const file of files) {
    const scanResult = await scanFileWithCache({
      filePath: file,
      maxFileBytes: scanOptions.maxFileBytes,
      disabledRules: scanOptions.disabledRules,
    });
    if (!scanResult.scanned) continue;
    allFindings.push(...scanResult.findings);

    // Stream each finding
    if (scanOptions.streamTo?.enabled) {
      for (const finding of scanResult.findings) {
        await streamFinding(finding, scanOptions.streamTo);
      }
    }
  }
  return allFindings;
}

export async function scanDirectoryWithSummary(
  dirPath: string,
  opts?: SkillScanOptions,
): Promise<SkillScanSummary> {
  const scanOptions = normalizeScanOptions(opts);
  const files = await collectScannableFiles(dirPath, scanOptions);
  const allFindings: SkillScanFinding[] = [];
  let scannedFiles = 0;
  let critical = 0;
  let warn = 0;
  let info = 0;

  for (const file of files) {
    const scanResult = await scanFileWithCache({
      filePath: file,
      maxFileBytes: scanOptions.maxFileBytes,
      disabledRules: scanOptions.disabledRules,
    });
    if (!scanResult.scanned) continue;
    scannedFiles += 1;
    for (const finding of scanResult.findings) {
      allFindings.push(finding);
      if (finding.severity === "critical") critical += 1;
      else if (finding.severity === "warn") warn += 1;
      else info += 1;

      if (scanOptions.streamTo?.enabled) {
        await streamFinding(finding, scanOptions.streamTo);
      }
    }
  }

  return { scannedFiles, critical, warn, info, findings: allFindings };
}

/**
 * Returns all known rule metadata — used by the UI to render the rules panel
 * with descriptions, toggles, and framework badges.
 */
export function getAllRuleMetadata(): RuleMetadata[] {
  return [
    ...LINE_RULES.map((r) => ({
      ruleId: r.ruleId,
      severity: r.severity,
      message: r.message,
      category: r.category,
      frameworks: r.frameworks,
      description: r.description,
      remediationNote: r.remediationNote,
      remediable: r.remediable,
    })),
    ...[...SOURCE_RULES, ...ROUND3_RULES, ...ROUND4_RULES, ...OWASP_GAP_RULES, ...OWASP_BETA12_RULES].map((r) => ({
      ruleId: r.ruleId,
      severity: r.severity,
      message: r.message,
      category: r.category,
      frameworks: r.frameworks,
      description: r.description,
      remediable: r.remediable ?? false,
    })),
  ];
}

// NOTE: Additional rules are appended below. The closing ]; above is superseded.
// Source rules array continues here (Gemini round 3 + ChatGPT cross-validated):

// ScanRule: alias for SourceRule (used by ROUND3+ rule arrays)
type ScanRule = SourceRule;

const ROUND3_RULES: ScanRule[] = [
  // ── Shadow Exfiltration — Gemini OPEN-011 / ChatGPT round 3 target ────────
  // Log: 20260308-003-GEMINI, 20260308-013-CLAUDE

  {
    ruleId: "exfil-shadow-query-string",
    severity: "critical",
    message: "Shadow exfiltration — sensitive data encoded in query string of whitelisted API call",
    category: "data-exfiltration",
    frameworks: ["OWASP-LLM02", "MITRE-ATLAS-AML.T0048"],
    description:
      "Encodes stolen data (process.env, file contents) into query parameters, URL fragments, " +
      "or User-Agent headers of calls to whitelisted domains — making exfiltration look like " +
      "legitimate API traffic. The network allowlist cannot stop this; it must be detected " +
      "statically by identifying process.env or credential reads concatenated with URL construction. " +
      "Defined by Gemini attacker model (log: 20260308-003-GEMINI). ChatGPT round 3 target.",
    remediable: false,
    // Catches: URL construction that includes process.env, readFile results, or credential vars
    pattern: /(?:encodeURIComponent|encodeURI|btoa|JSON\.stringify)\s*\(\s*(?:process\.env|Object\.entries\s*\(\s*process|credentials|authToken|apiKey)/,
  },

  {
    ruleId: "exfil-shadow-useragent",
    severity: "critical",
    message: "Shadow exfiltration — sensitive data embedded in HTTP headers (User-Agent, Referer, etc.)",
    category: "data-exfiltration",
    frameworks: ["OWASP-LLM02", "MITRE-ATLAS-AML.T0048"],
    description:
      "Data exfiltrated via HTTP request headers (User-Agent, X-Custom-*, Referer) is invisible " +
      "to payload-level network monitoring and bypasses body-size restrictions. Any skill that " +
      "sets request headers containing process.env values or credential reads is highly suspicious. " +
      "Defined by Gemini attacker model (log: 20260308-003-GEMINI).",
    remediable: false,
    pattern: /headers\s*:\s*\{[^}]*(?:process\.env|apiKey|authToken|credentials|readFileSync)[^}]*\}/,
  },

  {
    ruleId: "exfil-timing-channel",
    severity: "critical",
    message: "Timing covert channel — artificial delays encoding data in inter-request timing",
    category: "data-exfiltration",
    frameworks: ["OWASP-LLM02", "MITRE-ATLAS-AML.T0048"],
    description:
      "A skill can exfiltrate binary data by encoding it as inter-request timing intervals " +
      "(e.g., delay 100ms = bit 0, delay 200ms = bit 1). This channel is invisible to content " +
      "inspection. Detectable statically by identifying setTimeout/setInterval values derived " +
      "from data reads. Defined by Gemini attacker model (log: 20260308-003-GEMINI).",
    remediable: false,
    pattern: /setTimeout\s*\([^,)]+,\s*(?:[^)]*(?:charCodeAt|codePointAt|parseInt)[^)]*|[^)]*\*\s*\d{2,})\s*\)/,
  },

  // ── Instruction Smuggling — Gemini OPEN-011 / memory-layer attack ─────────

  {
    ruleId: "inject-instruction-smuggling",
    severity: "critical",
    message: "Instruction smuggling — hidden control characters or jailbreak patterns in skill output",
    category: "prompt-injection",
    frameworks: ["OWASP-LLM01", "MITRE-ATLAS-AML.T0054"],
    description:
      "A skill that embeds zero-width characters (U+200B, U+FEFF, U+200C), right-to-left " +
      "override (U+202E), or known jailbreak trigger phrases into its output text can smuggle " +
      "instructions that appear invisible to humans but are parsed by downstream LLMs or agents. " +
      "When this output is stored in SentinelMemory it poisons future sessions persistently. " +
      "Defined by Gemini attacker model (log: 20260308-003-GEMINI).",
    remediable: true,
    remediationReplace: "/* [ClawSentinel] BLOCKED instruction smuggling payload */",
    // Catches: zero-width chars, RTLO, known jailbreak openers in string literals
    pattern: /[\u200B\u200C\u200D\uFEFF\u202E\u2060]|\\u200[BbCcDd]|\\uFEFF|\\u202[Ee]|ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|you\s+are\s+now\s+(?:a\s+)?(?:DAN|jailbreak|unrestricted)/i,
  },

  {
    ruleId: "inject-memory-poison",
    severity: "critical",
    message: "Memory poisoning — skill output designed to corrupt SentinelMemory entries",
    category: "prompt-injection",
    frameworks: ["OWASP-LLM01", "MITRE-ATLAS-AML.T0054"],
    description:
      "A skill that outputs text structured to look like a SentinelMemory write command, " +
      "or that contains fake memory entries prefaced with memory type labels, can cause " +
      "the pre-compaction flush to write adversarial memories into the store. These persist " +
      "across all future sessions for that agent. " +
      "Defined by Gemini attacker model (log: 20260308-003-GEMINI). " +
      "Runtime defense: memory trust scoring (ADR-005, pending).",
    remediable: false,
    // Catches: fake memory structure in skill output strings
    pattern: /(?:type:\s*['"`](?:fact|decision|preference|entity|procedure|event)['"`]|sentinelmemory[._]write|memory[._]flush\s*\()/i,
  },

  {
    ruleId: "inject-dns-timing",
    severity: "critical",
    message: "DNS timing exfiltration — high-frequency DNS lookups with variable subdomains",
    category: "data-exfiltration",
    frameworks: ["OWASP-LLM02", "MITRE-ATLAS-AML.T0048"],
    description:
      "20+ DNS lookups per short interval with randomized or data-derived subdomains encodes " +
      "stolen data as DNS queries — each lookup is a valid network operation that bypasses " +
      "HTTP content inspection. Detectable by identifying loops that construct subdomains " +
      "from data reads and immediately do DNS resolution. " +
      "Defined by Gemini signature A (log: 20260308-003-GEMINI).",
    remediable: false,
    pattern: /for\s*\([^)]+\)\s*\{[^}]*(?:lookup|resolve|dns\.resolve|dns\.lookup)\s*\([^)]*(?:\+|template|encode|charCodeAt)[^)]*\)/,
  },
];

// NOTE: ROUND4_RULES — entropy + variable indirection defenses
// Log: 20260308-013-CHATGPT, 20260308-014-GEMINI → 20260308-013-CLAUDE

const ROUND4_RULES: ScanRule[] = [
  {
    ruleId: "exfil-high-entropy-string",
    severity: "critical",
    message: "High-entropy string literal — possible encoded exfiltration payload",
    category: "data-exfiltration",
    frameworks: ["OWASP-LLM02", "MITRE-ATLAS-AML.T0048"],
    description:
      "Base64, hex, or otherwise encoded payloads embedded as string literals have " +
      "Shannon entropy significantly higher than natural language or source code. " +
      "This is the primary evasion technique when direct process.env references are " +
      "blocked. Detects strings of 40+ chars that look like base64 or hex blobs. " +
      "Round 3 architectural recommendation: ChatGPT (log: 20260308-013-CHATGPT), " +
"Gemini (log: 20260308-014-GEMINI). Full entropy analysis requires AST layer (ADR-006).",
    remediable: false,
    // Catches: base64 blobs 40+ chars, hex strings 40+ chars in string literals
    pattern: /['"`][A-Za-z0-9+/]{40,}={0,2}['"`]|['"`][0-9a-fA-F]{40,}['"`]/,
  },

  {
    ruleId: "exfil-buffer-encode-chain",
    severity: "critical",
    message: "Buffer.from chain — data encoded via Buffer to evade encodeURIComponent detection",
    category: "data-exfiltration",
    frameworks: ["OWASP-LLM02", "MITRE-ATLAS-AML.T0048"],
    description:
      "Buffer.from(JSON.stringify(process.env)).toString('base64') encodes environment " +
      "data for exfiltration without ever calling encodeURIComponent — bypassing the " +
      "exfil-shadow-query-string rule which watched for encodeURIComponent(process.env). " +
      "Round 3 confirmed bypass by ChatGPT (log: 20260308-013-CHATGPT).",
    remediable: true,
    remediationReplace: "/* [ClawSentinel] BLOCKED Buffer encode chain */",
    pattern: /Buffer\s*\.\s*from\s*\([^)]*(?:process\.env|JSON\.stringify\s*\(\s*process|readFileSync|credentials)\s*[^)]*\)\s*\.\s*toString\s*\(\s*['"`](?:base64|hex|binary)/,
  },

  {
    ruleId: "exfil-variable-indirection-headers",
    severity: "critical",
    message: "Header variable indirection — headers assigned via variable to hide sensitive data",
    category: "data-exfiltration",
    frameworks: ["OWASP-LLM02", "MITRE-ATLAS-AML.T0048"],
    description:
      "Assigning sensitive data to a variable and then setting that variable as a header " +
      "value bypasses the exfil-shadow-useragent rule which only checked for inline " +
      "object literals. Example: const h = {}; h['x-data'] = process.env.SECRET; fetch(url, {headers:h}). " +
      "Round 3 confirmed bypass by ChatGPT (log: 20260308-013-CHATGPT).",
    remediable: false,
    // Catches: variable assigned from process.env then used in a headers context
    // BP-010 fix (20260312-059-CLAUDE): catches headers.set/append with variable second arg
    pattern: /headers?\s*\.\s*(?:set|append)\s*\(\s*[^)]*,\s*(?!['"`])[a-zA-Z_\$][\w\$]*/,
  },

  {
    ruleId: "inject-dynamic-jailbreak",
    severity: "critical",
    message: "Dynamically constructed jailbreak phrase — evades literal string matching",
    category: "prompt-injection",
    frameworks: ["OWASP-LLM01", "MITRE-ATLAS-AML.T0054"],
    description:
      "Building jailbreak phrases dynamically ('ignore '+'all previous '+'instructions') " +
      "bypasses the inject-instruction-smuggling rule which matches literal strings. " +
      "Detects string concatenation producing known jailbreak trigger patterns. " +
      "Round 3 confirmed bypass category by ChatGPT (log: 20260308-013-CHATGPT).",
    remediable: true,
    remediationReplace: "/* [ClawSentinel] BLOCKED dynamic jailbreak construction */",
    // Catches: 'ignore' + ... + 'instruction', 'you are' + ... + 'now' constructions
    // BP-011 fix (20260312-059-CLAUDE): catches variable-assigned array + .join, not just concat
    pattern: /['"`]ignore['"`]\s*\+|['"`]previous\s+instructions['"`]|['"`]prior\s+instructions['"`]|['"`]you\s+are['"`]\s*\+[^+]*\+\s*['"`]now['"`]|\b(?:const|let|var)\s+\w+\s*=\s*\[[^\]]*['"`](?:ignore|override|bypass|jailbreak|disregard|forget)['"`]/i,
  },
];

// ── OWASP gap rules (Gemini 20260308-006-GEMINI → 20260308-015-CLAUDE) ────────

const OWASP_GAP_RULES: ScanRule[] = [
  {
    // LLM01: Recursive/agent-to-agent prompt injection
    ruleId: "inject-agent-to-agent",
    severity: "critical",
    message: "Agent-to-agent prompt injection — output crafted to manipulate a downstream agent",
    category: "prompt-injection",
    frameworks: ["OWASP-LLM01", "MITRE-ATLAS-AML.T0054"],
    description:
      "A skill that constructs outputs containing system-prompt-override patterns targeting " +
      "a downstream agent (e.g., a skill that calls another agent via the tool interface and " +
      "passes injected instructions in the message body). Gemini gap analysis (20260308-006-GEMINI) " +
      "identified recursive injection as unaddressed by existing LLM01 rules.",
    remediable: false,
    pattern: /(?:callAgent|invokeAgent|agentMessage|sendToAgent)\s*\([^)]*(?:ignore.*instructions?|you are now|override.*security|new.*protocol)/i,
  },

  {
    // LLM02: JS-in-Markdown that the UI might render as executable
    ruleId: "output-js-in-markdown",
    severity: "critical",
    message: "JavaScript in Markdown output — potential XSS if UI renders without sanitization",
    category: "prompt-injection",
    frameworks: ["OWASP-LLM02", "CWE-79"],
    description:
      "A skill that returns Markdown containing inline JavaScript (`<script>`, `javascript:` URLs, " +
      "or event handler attributes) could execute in the OpenClaw UI if the renderer doesn't " +
      "sanitize HTML. Gemini gap analysis (20260308-006-GEMINI) identified this as a partial gap " +
      "in LLM02 coverage — eval() is caught but JS-in-Markdown output is not. " +
      "Runtime fix: UI must sanitize all skill output before rendering.",
    remediable: true,
    remediationReplace: "/* [ClawSentinel] BLOCKED JS-in-Markdown output */",
    pattern: /return\s+[`'"](?:[^`'"]*<script|[^`'"]*javascript\s*:|[^`'"]*on(?:load|click|error|mouseover)\s*=)[^`'"]*[`'"]/i,
  },

  {
    // LLM10: Model theft — high-volume parameter probing
    ruleId: "model-theft-probe",
    severity: "critical",
    message: "Model theft probe — systematic parameter or prompt extraction attempt",
    category: "gateway-abuse",
    frameworks: ["OWASP-LLM10"],
    description:
      "A skill that systematically queries the agent with variations of prompts designed to " +
      "extract system prompt contents, model parameters, or training data. Patterns include " +
      "loops over prompt-extraction payloads, 'repeat after me' instructions, or requests " +
      "for verbatim system prompt contents. Gemini gap analysis (20260308-006-GEMINI) " +
      "identified LLM10 as entirely unaddressed.",
    remediable: false,
    pattern: /(?:repeat\s+(?:the\s+)?(?:above|everything|your\s+(?:system\s+)?prompt)|verbatim.*(?:system|instructions?)|(?:ignore|disregard).*(?:output\s+format|json).*(?:instead|just)\s+(?:say|output|print|return))|for\s*\([^)]+\)\s*\{[^}]*(?:callAgent|invokeAgent)[^}]*(?:prompt|parameter|weight)/i,
  },
];

// ── OWASP rules from Gemini 20260308-017-GEMINI (corrected by Claude 20260308-018-CLAUDE) ──
// Corrections applied: severity "high"→"critical"/"warn", "medium"→"warn";
// id→ruleId; recommendation→description; missing fields added;
// categories mapped to valid ThreatCategory values; /g flags removed (stateful bug);
// LLM-003 pattern rewritten to avoid false positives on relative imports.

const OWASP_BETA12_RULES: ScanRule[] = [
  {
    ruleId: "supply-unverified-external-import",
    severity: "critical",
    message: "Unverified external package import — no integrity hash or scope pinning",
    category: "supply-chain",
    frameworks: ["OWASP-LLM03", "CWE-829"],
    description:
      "Detects bare npm package imports that are not scoped to @clawsentinel and have no " +
      "subresource integrity annotation. Gemini (20260308-017-GEMINI) flagged this as the " +
      "primary LLM03 supply-chain gap. Pattern rewritten to avoid false positives on relative " +
      "imports (./foo, ../bar) and path imports (/abs/path). The /g flag was removed from " +
      "Gemini's original to prevent stateful RegExp.lastIndex bugs.",
    remediable: false,
    // Match: static import ... from 'pkg' OR dynamic import('pkg') — not relative, absolute, or @clawsentinel scoped
    // BP-012 fix (20260312-061-CLAUDE): added dynamic import() branch — static-only pattern missed await import('left-pad')
    pattern: /import\s+.+\s+from\s+['"](?!\.\.?\/|\/|@clawsentinel\/)[^'"]{2,}['"]|(?:await\s+)?import\s*\(\s*['"](?!\.\.?\/|\/|@clawsentinel\/)[^'"]{2,}['"]\s*\)/,
  },
  {
    ruleId: "inter-agent-recursive-invoke",
    severity: "warn",
    message: "Agent self-invocation detected — potential recursive loop without depth guard",
    category: "inter-agent-attack",
    frameworks: ["OWASP-LLM04", "CWE-674"],
    description:
      "Detects agent.invoke() calls that pass an agentId, which could result in recursive " +
      "agent chains exhausting token budget. Gemini (20260308-017-GEMINI) identified this as " +
      "the LLM04 gap. The /g flag was removed from original to prevent stateful matching bug. " +
      "Runtime enforcement: see guardAgentRecursion() in skill-sandbox.ts.",
    remediable: false,
    pattern: /agent\.invoke\s*\(\s*\{[^}]*agentId/,
  },
  {
    ruleId: "credential-hardcoded-inline",
    severity: "critical",
    message: "Hardcoded credential detected — key/token/secret assigned a literal string value",
    category: "credential-theft",
    frameworks: ["OWASP-LLM07", "CWE-798"],
    description:
      "Detects variables named key, token, secret, or password being assigned a string " +
      "literal of 16+ characters — a strong indicator of a hardcoded credential. Gemini " +
      "(20260308-017-GEMINI) mapped this to LLM07 data leakage. Use SentinelSecretsStore " +
      "for all credential management. The /gi flag was removed (stored RegExp with flags " +
      "causes stateful lastIndex bugs) and replaced with case-insensitive inline (?i) pattern.",
    remediable: false,
    pattern: /(?:key|token|secret|password)\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}['"]/i,
  },
  {
    ruleId: "dangerous-action-no-hitl",
    severity: "warn",
    message: "Dangerous filesystem/process action without human-in-the-loop confirmation",
    category: "filesystem-abuse",
    frameworks: ["OWASP-LLM09", "CWE-78"],
    description:
      "Detects calls to fs.rmdir, fs.rm, process.exit, or shell.exec — operations that " +
      "have irreversible consequences. Gemini (20260308-017-GEMINI) identified LLM09 " +
      "(Overreliance) risk: autonomous agents should not perform destructive actions without " +
      "a UI confirmation step. Runtime enforcement: sandbox strike counter (ADR-004) also " +
      "applies. Pattern extended beyond Gemini's original to include fs.rm variants.",
    remediable: false,
    pattern: /(?:fs\.rmdir|fs\.rm\s*\(|process\.exit|shell\.exec)\s*\(/,
  },
  {
    ruleId: "inject-node-internal-binding",
    severity: "critical",
    message: "process.binding() or process._linkedBinding() — Node.js internals bypass sandbox require hooks",
    category: "code-injection",
    frameworks: ["OWASP-LLM02", "CWE-264", "MITRE-ATLAS-AML.T0051"],
    description:
      "process.binding() and process._linkedBinding() provide direct access to Node.js C++ " +
      "internal bindings, entirely bypassing the require() module system and any hooks placed " +
      "on it. A skill can use process.binding('fs') to read and write the filesystem even when " +
      "require('fs') is blocked by the sandbox (ADR-004). Identified as BP-007 by Gemini " +
      "(20260309-031-GEMINI). Covers the Reflect.get obfuscation variant where the method is " +
      "accessed indirectly to evade string-based detection. Legitimate skill code has no valid " +
      "reason to access Node.js internal bindings — these are not part of the public API surface.",
    remediation:
      "Use standard Node.js modules (fs, net, crypto) via normal imports. " +
      "If you need low-level OS access that the standard library does not provide, " +
      "open an issue describing your use case — ClawSentinel may be able to expose " +
      "a safe, audited wrapper.",
    remediable: false,
    // Primary pattern: direct process.binding / process._linkedBinding call
    pattern: /process\._?(?:linked)?[Bb]inding\s*\(/,
    // Secondary context check: also catch Reflect.get obfuscation variant
    // Reflect.get(process, '_linkedBinding') used to evade string-literal detection
    requiresContext: /Reflect\.get\s*\(\s*process\s*,|process\._?(?:linked)?[Bb]inding/,
  },
];