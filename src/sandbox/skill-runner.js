/**
 * @clawsentinel
 * @author      Claude Sonnet 4.6
 * @date        2026-03-08
 * @log-entry   20260308-011-CLAUDE
 * @reviewed-by ChatGPT GPT-5.3 (ADR-004)
 * @status      draft
 *
 * skill-runner.js — child process entry point for sandboxed skill execution.
 *
 * This file runs as a forked child process. It receives the skill path via IPC,
 * imports the skill module, calls its run() export, and returns the result.
 *
 * Dangerous globals are deleted before the skill is imported. The skill
 * communicates back to the parent only via the restricted IPC API defined
 * in skill-sandbox.ts.
 *
 * SECURITY NOTE: This file itself is trusted code — it is part of ClawSentinel,
 * not a skill. The skill file is imported dynamically and runs in this process
 * context, but without access to the globals removed below.
 */

"use strict";

// ── Remove dangerous globals before any skill code runs ───────────────────────
// Per ADR-004 / ChatGPT recommendation (log: 20260308-011-CHATGPT)
// Skills must use the IPC API surface instead of direct system access.

// We cannot fully delete 'process' because IPC requires it,
// but we can remove the most dangerous sub-APIs.
delete process.env;          // Skills get SENTINEL_SKILL_ID and NODE_ENV only — set by parent
delete process.binding;      // Blocks low-level V8/libuv binding access
delete process.dlopen;       // Blocks native addon loading
delete process.kill;         // Skills cannot kill other processes

// Override require to block dangerous modules
const _originalRequire = require;
const BLOCKED_MODULES = new Set([
  "child_process", "worker_threads", "vm", "cluster",
  "v8", "inspector", "repl", "readline",
]);

// Note: cannot fully block 'fs' or 'net' as some skill utilities may need
// read access. The parent-side allowlist and IPC enforcement are the primary
// enforcement boundary. This is belt-and-suspenders.
global.require = function safeRequire(id) {
  if (BLOCKED_MODULES.has(id)) {
    throw new Error(`[SentinelSandbox] Module '${id}' is not available in the skill runtime`);
  }
  return _originalRequire(id);
};

// Block direct fetch — skills must use the IPC network request instead
global.fetch = undefined;
global.XMLHttpRequest = undefined;

// ── Skill API surface exposed to skills via __sentinelApi ─────────────────────

const pendingRequests = new Map();

function sendIpc(msg) {
  process.send(msg);
}

function makeRequestId() {
  return crypto.randomUUID();
}

// Skills call __sentinelApi.fetch(url, options) → Promise<{status, body}>
const __sentinelApi = {
  fetch: (url, options = {}) => {
    return new Promise((resolve, reject) => {
      const requestId = makeRequestId();
      pendingRequests.set(requestId, { resolve, reject });
      sendIpc({
        type: "request_network",
        requestId,
        url,
        method: (options.method ?? "GET").toUpperCase(),
        headers: options.headers,
        body: options.body,
      });
    });
  },

  log: (level, message) => {
    sendIpc({ type: "log", level, message: String(message).slice(0, 2000) });
  },

  readMemory: (query) => {
    return new Promise((resolve, reject) => {
      const requestId = makeRequestId();
      pendingRequests.set(requestId, { resolve, reject });
      sendIpc({
        type: "memory_read",
        requestId,
        agentId: process.env.SENTINEL_SKILL_AGENT_ID ?? "unknown",
        query,
      });
    });
  },
};

global.__sentinelApi = __sentinelApi;

// ── Handle IPC responses from parent ─────────────────────────────────────────

process.on("message", async (msg) => {
  if (msg.type === "execute") {
    await executeSkill(msg.skillPath, msg.skillId);
    return;
  }

  // Network or memory response — resolve pending promise
  if (msg.requestId && pendingRequests.has(msg.requestId)) {
    const { resolve, reject } = pendingRequests.get(msg.requestId);
    pendingRequests.delete(msg.requestId);
    if (msg.error) {
      reject(new Error(msg.error));
    } else {
      resolve(msg);
    }
  }
});

// ── Skill execution ───────────────────────────────────────────────────────────

async function executeSkill(skillPath, skillId) {
  try {
    sendIpc({ type: "log", level: "info", message: `Starting skill: ${skillId}` });

    // Dynamic import — skill runs in this process but without deleted globals
    const skillModule = await import(skillPath);

    if (typeof skillModule.run !== "function") {
      throw new Error("Skill must export a run() function");
    }

    const output = await skillModule.run({ api: __sentinelApi });

    sendIpc({
      type: "skill_result",
      success: true,
      output: output ?? null,
    });
  } catch (err) {
    sendIpc({
      type: "skill_result",
      success: false,
      output: null,
      error: err instanceof Error ? err.message : String(err),
    });
  }
}

// ── Crash safety ──────────────────────────────────────────────────────────────

process.on("uncaughtException", (err) => {
  sendIpc({
    type: "skill_result",
    success: false,
    output: null,
    error: `Uncaught exception: ${err.message}`,
  });
  process.exit(1);
});

process.on("unhandledRejection", (reason) => {
  sendIpc({
    type: "skill_result",
    success: false,
    output: null,
    error: `Unhandled rejection: ${String(reason)}`,
  });
  process.exit(1);
});