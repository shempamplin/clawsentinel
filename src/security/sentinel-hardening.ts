/**
 * ClawSentinel — Additional Security Hardening Rules
 * New file: src/security/sentinel-hardening.ts
 *
 * Addresses security gaps found in the OpenClaw codebase during ClawSentinel
 * fork analysis that are NOT covered by the existing skill-scanner rules:
 *
 *  ISSUE 1: Plugin Full-Process Access
 *    Plugins load via jiti into the main Node.js process with no sandbox.
 *    A malicious plugin can access process.env, require('fs'), spawn processes,
 *    and read any file the openclaw process can read — including the config
 *    with all plaintext secrets.
 *    → ClawSentinel mitigation: plugin behavior runtime monitor
 *
 *  ISSUE 2: Conversation Transcript Storage (No At-Rest Encryption)
 *    Session files are written with 0o600 permissions (good) but as plaintext
 *    JSON/NDJSON. On multi-user systems, a root compromise leaks all
 *    conversation history including any secrets the user typed to the AI.
 *    → ClawSentinel mitigation: transcript encryption warning + tooling
 *
 *  ISSUE 3: TLS Not Enforced by Default
 *    The gateway runs HTTP by default. If a user binds to 0.0.0.0 without
 *    configuring TLS, auth tokens travel in cleartext.
 *    → ClawSentinel mitigation: startup TLS posture check with warning
 *
 *  ISSUE 4: No HTTP Security Headers on API Routes
 *    The control UI sets CSP and X-Frame-Options, but the /api/* routes do
 *    not set security headers, leaving them vulnerable to content sniffing
 *    and MIME confusion attacks.
 *    → ClawSentinel mitigation: security headers middleware
 *
 *  ISSUE 5: Default Token Warning
 *    The .env.example ships with `OPENCLAW_GATEWAY_TOKEN=change-me-to-a-long-random-token`.
 *    Users who forget to change this are running with a well-known token.
 *    → ClawSentinel mitigation: weak/default token detector
 *
 *  ISSUE 6: Log Server Receives Unredacted Data
 *    The NDJSON log server (log-server.js) persists all event data, which
 *    could include diagnostic events that captured secret values in `meta`.
 *    → ClawSentinel mitigation: server-side redaction before persistence
 */

import { createHash } from "node:crypto";

import { createSubsystemLogger } from "../logging/subsystem.js";

const log = createSubsystemLogger("clawsentinel/hardening");

// ─── Issue 5: Default/Weak Token Detection ───────────────────────────────────

/** Tokens that should trigger a startup warning */
const KNOWN_WEAK_TOKENS = new Set([
  "change-me-to-a-long-random-token",
  "changeme",
  "change-me",
  "openclaw",
  "password",
  "secret",
  "token",
  "default",
  "test",
  "12345",
  "openclaw123",
]);

const MIN_STRONG_TOKEN_LENGTH = 32;

export type TokenStrengthResult =
  | { ok: true; strength: "strong" }
  | { ok: false; reason: "too_short" | "known_weak" | "insufficient_entropy"; suggestion: string };

/**
 * Check whether a gateway auth token is strong enough.
 * Logs a warning if it is not; call this at startup.
 */
export function checkTokenStrength(token: string | undefined): TokenStrengthResult {
  if (!token) {
    return {
      ok: false,
      reason: "too_short",
      suggestion: "Set OPENCLAW_GATEWAY_TOKEN to a strong random value: openssl rand -hex 32",
    };
  }

  const lower = token.trim().toLowerCase();

  if (KNOWN_WEAK_TOKENS.has(lower)) {
    log.warn("[hardening] Gateway token is a well-known default value — change it immediately", {
      tokenPrefix: token.slice(0, 8),
    });
    return {
      ok: false,
      reason: "known_weak",
      suggestion:
        "Generate a strong token: openssl rand -hex 32  (then set OPENCLAW_GATEWAY_TOKEN)",
    };
  }

  if (token.length < MIN_STRONG_TOKEN_LENGTH) {
    log.warn("[hardening] Gateway token is shorter than recommended minimum", {
      length: token.length,
      minimumRecommended: MIN_STRONG_TOKEN_LENGTH,
    });
    return {
      ok: false,
      reason: "too_short",
      suggestion: `Token should be at least ${MIN_STRONG_TOKEN_LENGTH} characters. Use: openssl rand -hex 32`,
    };
  }

  // Estimate entropy via Shannon entropy approximation
  const counts = new Map<string, number>();
  for (const c of token) counts.set(c, (counts.get(c) ?? 0) + 1);
  const entropy = [...counts.values()].reduce((sum, count) => {
    const p = count / token.length;
    return sum - p * Math.log2(p);
  }, 0);

  if (entropy < 3.5) {
    log.warn("[hardening] Gateway token has low entropy (likely repetitive or predictable)", {
      entropy: entropy.toFixed(2),
    });
    return {
      ok: false,
      reason: "insufficient_entropy",
      suggestion: "Use a cryptographically random token: openssl rand -hex 32",
    };
  }

  return { ok: true, strength: "strong" };
}

// ─── Issue 3: TLS Posture Check ───────────────────────────────────────────────

export type TlsPostureResult = {
  tlsEnabled: boolean;
  bindHost: string;
  isExposed: boolean; // bound to non-loopback without TLS
  warnings: string[];
  recommendations: string[];
};

/**
 * Check whether the gateway TLS posture is acceptable given the bind address.
 * "localhost" / "127.0.0.1" / "::1" are safe without TLS.
 * "0.0.0.0" / public IPs without TLS are warned.
 */
export function checkTlsPosture(params: {
  tlsEnabled: boolean;
  host: string;
  port: number;
}): TlsPostureResult {
  const loopback = new Set(["localhost", "127.0.0.1", "::1", "lo"]);
  const isLoopback = loopback.has(params.host.toLowerCase());
  const isExposed = !isLoopback && !params.tlsEnabled;

  const warnings: string[] = [];
  const recommendations: string[] = [];

  if (isExposed) {
    warnings.push(
      `Gateway is bound to ${params.host}:${params.port} without TLS. ` +
        `Auth tokens and API responses travel in cleartext over the network.`,
    );
    recommendations.push(
      "Enable TLS: set gateway.tls.enabled=true and provide a certificate/key pair.",
      "If only local access is needed, bind to 127.0.0.1 instead of 0.0.0.0.",
      "Consider using a reverse proxy (nginx, Caddy) to terminate TLS.",
    );
  }

  if (isExposed) {
    log.warn("[hardening] TLS is disabled on an exposed (non-loopback) interface", {
      host: params.host,
      port: params.port,
    });
  }

  return {
    tlsEnabled: params.tlsEnabled,
    bindHost: params.host,
    isExposed,
    warnings,
    recommendations,
  };
}

// ─── Issue 4: Security Headers Middleware ─────────────────────────────────────

/**
 * Express-compatible middleware that sets security headers on all responses.
 * Apply to the sentinel API routes to prevent content sniffing and
 * clickjacking on any future UI that might embed these endpoints.
 *
 * Usage in sentinel-routes.ts:
 *   router.use(sentinelSecurityHeaders);
 */
export function sentinelSecurityHeaders(
  _req: IncomingMessage,
  res: ServerResponse,
  next: () => void,
): void {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  // Don't set HSTS here — that belongs on the TLS terminator
  next();
}

// ─── Issue 1: Plugin Behavior Monitor ────────────────────────────────────────

/**
 * A lightweight record of suspicious behaviors observed from a plugin
 * during its registration call. Used by the scanner's runtime layer.
 */
export type PluginBehaviorRecord = {
  pluginId: string;
  accessedEnvKeys: string[];
  registeredHttpRoutes: number;
  registeredTools: number;
  registeredHooks: number;
  flaggedBehaviors: string[];
  riskScore: number; // 0–100
};

const SENSITIVE_ENV_KEYS = new Set([
  "ANTHROPIC_API_KEY",
  "OPENAI_API_KEY",
  "GEMINI_API_KEY",
  "OPENROUTER_API_KEY",
  "OPENCLAW_GATEWAY_TOKEN",
  "OPENCLAW_GATEWAY_PASSWORD",
  "DISCORD_BOT_TOKEN",
  "TELEGRAM_BOT_TOKEN",
  "SLACK_BOT_TOKEN",
  "SLACK_APP_TOKEN",
  "GITHUB_TOKEN",
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
]);

/**
 * Calculates a risk score for a plugin based on its registration behavior.
 * Higher = more suspicious.
 *
 * @param accessedEnvKeys - Environment variable names the plugin read at load time
 * @param httpRoutes - How many HTTP routes the plugin registered
 * @param hooks - How many lifecycle hooks the plugin registered
 */
export function scorePluginBehavior(params: {
  pluginId: string;
  accessedEnvKeys: string[];
  httpRoutes: number;
  tools: number;
  hooks: number;
}): PluginBehaviorRecord {
  const flaggedBehaviors: string[] = [];
  let riskScore = 0;

  // Sensitive env key access
  const sensitiveKeys = params.accessedEnvKeys.filter((k) => SENSITIVE_ENV_KEYS.has(k));
  if (sensitiveKeys.length > 0) {
    flaggedBehaviors.push(`Accessed sensitive env keys: ${sensitiveKeys.join(", ")}`);
    riskScore += sensitiveKeys.length * 15;
  }

  // Registering many HTTP routes is unusual for a simple plugin
  if (params.httpRoutes > 3) {
    flaggedBehaviors.push(`Registered ${params.httpRoutes} HTTP routes (unusually high)`);
    riskScore += Math.min(20, (params.httpRoutes - 3) * 5);
  }

  // Many hooks can indicate supply-chain attack hooking into all messages
  if (params.hooks > 5) {
    flaggedBehaviors.push(`Registered ${params.hooks} lifecycle hooks (unusually high)`);
    riskScore += Math.min(15, (params.hooks - 5) * 3);
  }

  if (riskScore > 0) {
    log.warn(`[hardening] Plugin behavior risk score: ${riskScore}/100`, {
      pluginId: params.pluginId,
      flaggedBehaviors,
    });
  }

  return {
    pluginId: params.pluginId,
    accessedEnvKeys: params.accessedEnvKeys,
    registeredHttpRoutes: params.httpRoutes,
    registeredTools: params.tools,
    registeredHooks: params.hooks,
    flaggedBehaviors,
    riskScore: Math.min(100, riskScore),
  };
}

// ─── Issue 2: Transcript Encryption Warning ──────────────────────────────────

/**
 * Check whether conversation transcripts appear to be stored in plaintext.
 * Returns a warning if the session store directory is readable and contains
 * unencrypted JSONL session files.
 */
export async function checkTranscriptEncryption(sessionStorePath: string): Promise<{
  encrypted: boolean;
  sessionFilesFound: number;
  warning?: string;
  recommendation?: string;
}> {
  try {
    const { promises: fsp } = await import("node:fs");
    const entries = await fsp.readdir(sessionStorePath, { withFileTypes: true });
    const jsonlFiles = entries.filter(
      (e) => e.isFile() && (e.name.endsWith(".jsonl") || e.name.endsWith(".json")),
    );

    if (jsonlFiles.length === 0) {
      return { encrypted: true, sessionFilesFound: 0 };
    }

    // Read the first few bytes of one file to check if it looks like plaintext JSON
    const sample = jsonlFiles[0];
    if (!sample) return { encrypted: true, sessionFilesFound: 0 };
    
    const samplePath = `${sessionStorePath}/${sample.name}`;
    const fd = await fsp.open(samplePath, "r");
    const buf = Buffer.alloc(32);
    await fd.read(buf, 0, 32, 0);
    await fd.close();

    const isPlaintext = buf[0] === 0x7b || buf[0] === 0x5b || buf[0] === 0x0a; // { [ newline

    return {
      encrypted: !isPlaintext,
      sessionFilesFound: jsonlFiles.length,
      warning: isPlaintext
        ? `${jsonlFiles.length} conversation transcript(s) stored as plaintext in ${sessionStorePath}`
        : undefined,
      recommendation: isPlaintext
        ? "Consider enabling full-disk encryption (FileVault/BitLocker/LUKS) to protect transcripts at rest. " +
          "ClawSentinel transcript encryption is a planned feature."
        : undefined,
    };
  } catch {
    return { encrypted: true, sessionFilesFound: 0 };
  }
}

// ─── Startup Hardening Report ─────────────────────────────────────────────────

export type HardeningReport = {
  timestamp: string;
  tokenStrength: TokenStrengthResult;
  tlsPosture: TlsPostureResult;
  transcriptCheck: Awaited<ReturnType<typeof checkTranscriptEncryption>>;
  overallRisk: "low" | "medium" | "high" | "critical";
  actionItems: string[];
};

/**
 * Run all hardening checks and return a consolidated report.
 * Call this at ClawSentinel startup and surface results in the Security tab.
 */
export async function runHardeningChecks(params: {
  gatewayToken?: string;
  tlsEnabled: boolean;
  bindHost: string;
  bindPort: number;
  sessionStorePath?: string;
}): Promise<HardeningReport> {
  const tokenStrength = checkTokenStrength(params.gatewayToken);
  const tlsPosture = checkTlsPosture({
    tlsEnabled: params.tlsEnabled,
    host: params.bindHost,
    port: params.bindPort,
  });
  const transcriptCheck = params.sessionStorePath
    ? await checkTranscriptEncryption(params.sessionStorePath)
    : { encrypted: true, sessionFilesFound: 0 };

  const actionItems: string[] = [];
  let riskLevel = 0;

  if (!tokenStrength.ok) {
    actionItems.push(`🔑 Token: ${tokenStrength.suggestion}`);
    riskLevel += tokenStrength.reason === "known_weak" ? 40 : 20;
  }

  if (tlsPosture.isExposed) {
    actionItems.push(...tlsPosture.recommendations.map((r) => `🔒 TLS: ${r}`));
    riskLevel += 30;
  }

  if (transcriptCheck.warning) {
    actionItems.push(`📂 Transcripts: ${transcriptCheck.recommendation ?? transcriptCheck.warning}`);
    riskLevel += 10;
  }

  const overallRisk: HardeningReport["overallRisk"] =
    riskLevel >= 60 ? "critical" : riskLevel >= 40 ? "high" : riskLevel >= 20 ? "medium" : "low";

  return {
    timestamp: new Date().toISOString(),
    tokenStrength,
    tlsPosture,
    transcriptCheck,
    overallRisk,
    actionItems,
  };
}

// ─── CSRF Hardening (ChatGPT OPEN-007: 20260308-012-CHATGPT) ─────────────────

import type { IncomingMessage, ServerResponse } from "node:http";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const CSRF_TOKEN_BYTES = 32;
const CSRF_HEADER = "x-clawsentinel-csrf";

// ── Log redaction utility ──────────────────────────────────────────────────

const REDACT_PATTERNS = [
  /sk-[a-zA-Z0-9\-_]{20,}/g,       // OpenAI-style keys
  /ghp_[a-zA-Z0-9]{36}/g,          // GitHub PATs
  /AKIA[0-9A-Z]{16}/g,              // AWS access keys
  /Bearer\s+[\w\-\.]{20,}/g,       // Bearer tokens
  /password\s*[:=]\s*\S+/gi,        // password assignments
  /secret\s*[:=]\s*\S+/gi,          // secret assignments
];

/**
 * Redacts known credential patterns from log strings before emission.
 * Used by subsystem logger and sentinel-memory-routes.
 */
export function redactLogMessage(message: string): string {
  let out = message;
  for (const pattern of REDACT_PATTERNS) {
    out = out.replace(pattern, "[REDACTED]");
  }
  return out;
}
