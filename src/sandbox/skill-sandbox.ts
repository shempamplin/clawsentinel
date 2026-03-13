/**
 * @clawsentinel
 * @author      Claude Sonnet 4.6
 * @date        2026-03-08
 * @log-entry   20260308-011-CLAUDE
 * @reviewed-by ChatGPT GPT-5.3 (ADR-004 architecture), Gemini (attacker model)
 * @status      draft
 *
 * SentinelSandbox — subprocess isolation layer for skill execution.
 *
 * Architecture (ADR-004, ACCEPTED):
 *   Skill → isolated child_process.fork()
 *     → restricted runtime API (no process, require, fetch, vm, worker_threads)
 *     → IPC channel with Zod schema validation on every message
 *     → parent-controlled network proxy (global allowlist)
 *     → SIGTERM → 2s → SIGKILL timeout policy
 *     → stripped environment (SKILL_ID + NODE_ENV only)
 *
 * ChatGPT ADR-004 inputs (log: 20260308-011-CHATGPT):
 *   - IPC: Zod validation required, kill on invalid message
 *   - Network: global parent-controlled allowlist, skills never call network directly
 *   - Timeout: SIGTERM then SIGKILL after 2000ms
 *   - Globals: process, require, child_process, worker_threads, vm removed from skill context
 */

import { fork, type ChildProcess } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import crypto from "node:crypto";
import { z } from "zod";
import { createSubsystemLogger } from "../logging/subsystem.js";

const log = createSubsystemLogger("sentinel-sandbox");

// ─── Configuration ────────────────────────────────────────────────────────────

export type SandboxConfig = {
  /** Timeout in ms before SIGTERM. Default: 10000 */
  timeoutMs?: number;
  /** Additional ms after SIGTERM before SIGKILL. Default: 2000 */
  killGraceMs?: number;
  /** Domains skills may request network access to. Empty = no network. */
  allowedDomains?: string[];
  /** Max response body size in bytes returned to skill. Default: 512KB */
  maxResponseBytes?: number;
  /** Max IPC message size in bytes. Default: 64KB */
  maxIpcMessageBytes?: number;
  /**
   * Strike counter: how many policy violations (blocked network requests, invalid
   * IPC attempts) are allowed before the child is killed. Default: 3.
   * Recommendation: ChatGPT + Gemini (log: 20260308-013-CHATGPT, 20260308-014-GEMINI)
   * Rationale: a single blocked request may be accidental; 3+ indicates malicious probing.
   * Set to 1 for maximum security in production; 3 is a reasonable development default.
   */
  violationThreshold?: number;
};

const DEFAULT_CONFIG: Required<SandboxConfig> = {
  timeoutMs: 10_000,
  killGraceMs: 2_000,
  allowedDomains: [],
  maxResponseBytes: 512 * 1024,
  maxIpcMessageBytes: 64 * 1024,
  violationThreshold: 3,
};

// ─── IPC message schema (Zod) ─────────────────────────────────────────────────
// Every message from the child process is validated against this schema.
// Invalid messages result in immediate SIGKILL (no graceful shutdown).
// Designed with ChatGPT ADR-004 input (log: 20260308-011-CHATGPT).

const LogMessage = z.object({
  type: z.literal("log"),
  level: z.enum(["info", "warn", "error"]),
  message: z.string().max(2_000),
});

const NetworkRequestMessage = z.object({
  type: z.literal("request_network"),
  requestId: z.string().uuid(),
  url: z.string().url().max(2_048),
  method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]),
  headers: z.record(z.string()).optional(),
  body: z.string().max(256 * 1024).optional(),
});

const MemoryReadMessage = z.object({
  type: z.literal("memory_read"),
  requestId: z.string().uuid(),
  agentId: z.string().max(128),
  query: z.string().max(500),
});

const SkillResultMessage = z.object({
  type: z.literal("skill_result"),
  success: z.boolean(),
  output: z.unknown(),
  error: z.string().max(2_000).optional(),
});

const SkillIpcMessage = z.discriminatedUnion("type", [
  LogMessage,
  NetworkRequestMessage,
  MemoryReadMessage,
  SkillResultMessage,
]);

export type SkillIpcMessage = z.infer<typeof SkillIpcMessage>;

// ─── Execution result ─────────────────────────────────────────────────────────

export type SandboxResult = {
  success: boolean;
  output: unknown;
  error?: string;
  durationMs: number;
  networkRequestsBlocked: number;
  networkRequestsAllowed: number;
  killedReason?: "timeout" | "invalid-ipc" | "error";
};

// ─── Domain allowlist checker ─────────────────────────────────────────────────

function isDomainAllowed(url: string, allowedDomains: string[]): boolean {
  if (allowedDomains.length === 0) return false;
  try {
    const { hostname } = new URL(url);
    return allowedDomains.some(
      (d) => hostname === d || hostname.endsWith(`.${d}`)
    );
  } catch {
    return false;
  }
}

// ─── SentinelSandbox ─────────────────────────────────────────────────────────

export class SentinelSandbox {
  private config: Required<SandboxConfig>;

  constructor(config: SandboxConfig = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Execute a compiled skill function inside an isolated subprocess.
   *
   * @param skillPath   Absolute path to the compiled skill JS file
   * @param skillId     Unique identifier for this skill (used in env + logging)
   * @param agentId     Agent that invoked the skill (for memory reads)
   */
  async executeSkill(
    skillPath: string,
    skillId: string,
    agentId: string,
  ): Promise<SandboxResult> {
    const startMs = Date.now();
    let networkRequestsBlocked = 0;
    let networkRequestsAllowed = 0;
    let violationCount = 0;  // Strike counter (ChatGPT/Gemini: 20260308-013/014)
    const violationThreshold = this.config.violationThreshold ?? DEFAULT_CONFIG.violationThreshold;
    let killedReason: SandboxResult["killedReason"];

    return new Promise((resolve) => {
      // ── Spawn isolated child process ───────────────────────────────────────
      const runnerPath = path.resolve(
        path.dirname(fileURLToPath(import.meta.url)),
        "skill-runner.js"
      );

      const child: ChildProcess = fork(runnerPath, [], {
        // Strip full environment — provide only what the skill needs
        env: {
          NODE_ENV: process.env.NODE_ENV ?? "production",
          SENTINEL_SKILL_ID: skillId,
        },
        // Disable stdio inheritance — skills cannot write to terminal
        stdio: ["ignore", "pipe", "pipe", "ipc"],
        // Disable dangerous V8 flags
        execArgv: [
          "--disallow-code-generation-from-strings",
          "--no-experimental-vm-modules",
        ],
      });

      let settled = false;

      function finish(result: SandboxResult) {
        if (settled) return;
        settled = true;
        try { child.kill("SIGTERM"); } catch { /* already dead */ }
        resolve(result);
      }

      // ── Timeout: SIGTERM → 2s → SIGKILL ────────────────────────────────────
      // Per ChatGPT ADR-004 input (log: 20260308-011-CHATGPT)
      const timeoutHandle = setTimeout(() => {
        log.warn(`sandbox:timeout skillId=${skillId} after ${this.config.timeoutMs}ms`);
        killedReason = "timeout";
        child.kill("SIGTERM");
        setTimeout(() => {
          if (!child.killed) {
            log.warn(`sandbox:sigkill skillId=${skillId} (did not exit after SIGTERM)`);
            child.kill("SIGKILL");
          }
        }, this.config.killGraceMs);

        finish({
          success: false,
          output: null,
          error: `Skill timed out after ${this.config.timeoutMs}ms`,
          durationMs: Date.now() - startMs,
          networkRequestsBlocked,
          networkRequestsAllowed,
          killedReason: "timeout",
        });
      }, this.config.timeoutMs);

      // ── IPC message handler ────────────────────────────────────────────────
      child.on("message", async (rawMsg: unknown) => {
        // Validate message size
        const msgSize = JSON.stringify(rawMsg).length;
        if (msgSize > this.config.maxIpcMessageBytes) {
          log.error(`sandbox:ipc-oversized skillId=${skillId} bytes=${msgSize}`);
          killedReason = "invalid-ipc";
          child.kill("SIGKILL");
          clearTimeout(timeoutHandle);
          finish({
            success: false,
            output: null,
            error: "IPC message exceeded size limit — skill killed",
            durationMs: Date.now() - startMs,
            networkRequestsBlocked,
            networkRequestsAllowed,
            killedReason: "invalid-ipc",
          });
          return;
        }

        // Validate message schema
        // Strike counter: invalid IPC counts as a violation (ChatGPT/Gemini log: 20260308-013/014)
        const parsed = SkillIpcMessage.safeParse(rawMsg);
        if (!parsed.success) {
          violationCount++;
          log.error(`sandbox:ipc-invalid skillId=${skillId} violations=${violationCount}/${violationThreshold} error=${parsed.error.message}`);
          if (violationCount >= violationThreshold) {
            killedReason = "invalid-ipc";
            child.kill("SIGKILL");
            clearTimeout(timeoutHandle);
            finish({
              success: false,
              output: null,
              error: "Invalid IPC message schema — skill killed",
              durationMs: Date.now() - startMs,
              networkRequestsBlocked,
              networkRequestsAllowed,
              killedReason: "invalid-ipc",
            });
            return;
          }
          return;
        }

        const msg = parsed.data;

        switch (msg.type) {
          case "log":
            log[msg.level](`skill[${skillId}]: ${msg.message}`);
            break;

          case "request_network": {
            // Parent-proxied networking — skills never call network directly
            // Per ChatGPT ADR-004 (log: 20260308-011-CHATGPT)
            if (!isDomainAllowed(msg.url, this.config.allowedDomains)) {
              networkRequestsBlocked++;
              violationCount++;
              log.warn(`sandbox:network-blocked skillId=${skillId} url=${msg.url} violations=${violationCount}/${violationThreshold}`);
              // Warn and block first; kill only on threshold breach (ChatGPT Task C answer)
              // Rationale: kill-on-first-block causes DoS if skill has a misconfigured allowlist;
              // threshold-based kill catches malicious probing without punishing mistakes.
              child.send({
                type: "network_response",
                requestId: msg.requestId,
                error: "Domain not in allowlist",
                status: 403,
              });
              if (violationCount >= violationThreshold) {
                log.error(`sandbox:violation-threshold skillId=${skillId} — terminating`);
                killedReason = "invalid-ipc";
                child.kill("SIGTERM");
                setTimeout(() => { if (!child.killed) child.kill("SIGKILL"); }, 2_000);
              }
              return;
            }

            networkRequestsAllowed++;
            try {
              const response = await fetch(msg.url, {
                method: msg.method,
                headers: msg.headers,
                body: msg.body,
                signal: AbortSignal.timeout(5_000),
              });

              const text = await response.text();
              const truncated = text.slice(0, this.config.maxResponseBytes);

              child.send({
                type: "network_response",
                requestId: msg.requestId,
                status: response.status,
                body: truncated,
              });
            } catch (e) {
              child.send({
                type: "network_response",
                requestId: msg.requestId,
                error: String(e),
                status: 500,
              });
            }
            break;
          }

          case "memory_read": {
            // Skills can read from SentinelMemory — read only, no writes
            try {
              const { getSentinelMemory } = await import("../memory/sentinel-memory.js");
              const memory = getSentinelMemory();
              const result = memory.recall({
                agentId,
                query: msg.query,
                limit: 5,
                tokenBudget: 400,
              });
              child.send({
                type: "memory_response",
                requestId: msg.requestId,
                injectionBlock: result.injectionBlock,
              });
            } catch (e) {
              child.send({
                type: "memory_response",
                requestId: msg.requestId,
                error: String(e),
              });
            }
            break;
          }

          case "skill_result":
            clearTimeout(timeoutHandle);
            finish({
              success: msg.success,
              output: msg.output,
              error: msg.error,
              durationMs: Date.now() - startMs,
              networkRequestsBlocked,
              networkRequestsAllowed,
            });
            break;
        }
      });

      child.on("error", (err) => {
        log.error(`sandbox:child-error skillId=${skillId} error=${err.message}`);
        clearTimeout(timeoutHandle);
        finish({
          success: false,
          output: null,
          error: err.message,
          durationMs: Date.now() - startMs,
          networkRequestsBlocked,
          networkRequestsAllowed,
          killedReason: "error",
        });
      });

      child.on("exit", (code) => {
        if (!settled) {
          clearTimeout(timeoutHandle);
          finish({
            success: code === 0,
            output: null,
            error: code !== 0 ? `Skill exited with code ${code}` : undefined,
            durationMs: Date.now() - startMs,
            networkRequestsBlocked,
            networkRequestsAllowed,
          });
        }
      });

      // ── Send skill to runner ────────────────────────────────────────────────
      child.send({ type: "execute", skillPath, skillId, agentId });
    });
  }
}
// ─── Singleton factory ────────────────────────────────────────────────────────

let _sandbox: SentinelSandbox | null = null;

export function getSentinelSandbox(config?: SandboxConfig): SentinelSandbox {
  if (!_sandbox) _sandbox = new SentinelSandbox(config);
  return _sandbox;
}

// ── Agent Recursion Guard — Gemini 20260308-017-GEMINI / Claude 20260308-018-CLAUDE ──
// Gemini placed this in sentinel-compaction-hook.ts. Corrected placement: the sandbox
// is the right layer — it controls what skills can invoke, not the compaction hook.
// The compaction hook runs on context flush events, not on agent invocation chains.

export const MAX_AGENT_RECURSION_DEPTH = 5;

/**
 * Guards against recursive agent invocation chains that could exhaust token budget.
 * Call this in the IPC message handler before forwarding any agent.invoke() request
 * from a skill to the parent process.
 *
 * Returns true if execution should continue, false if the chain should be broken.
 * Emits a sandbox strike on breach (contributes to violationThreshold kill counter).
 */
export function guardAgentRecursion(
  currentDepth: number,
  skillId: string,
  onStrike: (reason: string) => void,
): boolean {
  if (currentDepth > MAX_AGENT_RECURSION_DEPTH) {
    const reason = `[CLAWSENTINEL] Recursive agent loop detected: depth=${currentDepth} exceeds MAX=${MAX_AGENT_RECURSION_DEPTH} for skill=${skillId}`;
    console.error(reason);
    onStrike(reason);
    return false;
  }
  return true;
}