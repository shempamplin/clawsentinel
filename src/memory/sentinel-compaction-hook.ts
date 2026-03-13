/**
 * @clawsentinel
 * @author      Claude Sonnet 4.6
 * @date        2026-03-08
 * @log-entry   20260308-010-CLAUDE
 * @reviewed-by Gemini 3 Flash (finding: 20260308-001-GEMINI)
 * @status      approved
 *
 * SentinelMemory — Compaction Hook Integration
 *
 * Gemini's integration audit (20260308-001-GEMINI) confirmed that OpenClaw does NOT
 * expose an `agent:compaction-pre` event. The actual hook is `context_threshold_reached`,
 * emitted by OpenClaw's logic-server when token count reaches ~85% of MAX_CONTEXT_WINDOW.
 *
 * This fires BEFORE the hard compaction limit, giving SentinelMemory a window to:
 *   1. Ask the agent to distill the current session into durable memories
 *   2. Write those memories to SQLite
 *   3. Allow compaction to proceed — nothing is lost
 *
 * Integration pattern:
 *   Import and call `registerCompactionHook(agentEventBus, memory)` from your
 *   OpenClaw gateway server entry point after the agent event bus is initialized.
 *
 * Modification history:
 *   2026-03-08  Claude Sonnet 4.6  20260308-010-CLAUDE  — initial implementation
 *                                                          based on Gemini finding
 */

import { EventEmitter } from "node:events";
import crypto from "node:crypto";
import { createSubsystemLogger } from "../logging/subsystem.js";
import { getSentinelMemory } from "./sentinel-memory.js";
import type { WriteMemoryParams, MemoryType } from "./sentinel-memory.js";

const log = createSubsystemLogger("sentinel-compaction-hook");

// ─── Types ────────────────────────────────────────────────────────────────────

/**
 * Shape of the event payload OpenClaw emits on context_threshold_reached.
 * Field names based on Gemini's inspection of the OpenClaw logic-server.
 * Treat as best-effort — OpenClaw may change this shape across versions.
 */
export type ContextThresholdEvent = {
  agentId: string;
  userId?: string;
  conversationId: string;
  tokenCount: number;
  maxTokens: number;
  thresholdPercent: number;   // typically 0.85
  messages?: Array<{          // recent messages if provided
    role: "user" | "assistant" | "system";
    content: string;
  }>;
};

/**
 * Shape of what the LLM returns when asked to flush memories.
 * We request JSON from the agent; this is the expected schema.
 */
type FlushResponse = {
  memories: Array<{
    type: MemoryType;
    content: string;
    importance: number;
    tags?: string[];
    sensitive?: boolean;
  }>;
  summary?: string;   // optional session summary for logging
};

// ─── Hook registration ────────────────────────────────────────────────────────

/**
 * Register SentinelMemory's pre-compaction flush on OpenClaw's event bus.
 *
 * Call this once during gateway server initialization:
 *
 *   import { registerCompactionHook } from "./memory/sentinel-compaction-hook.js";
 *   registerCompactionHook(agentEventBus);
 *
 * @param eventBus  The OpenClaw agent EventEmitter (or compatible emitter)
 * @param invokeAgentFn  Function that sends a message to the agent and returns its reply.
 *                       Signature matches OpenClaw's internal agent invocation API.
 */
export function registerCompactionHook(
  eventBus: EventEmitter,
  invokeAgentFn: (agentId: string, prompt: string, conversationId: string) => Promise<string>,
): void {
  eventBus.on("context_threshold_reached", async (event: ContextThresholdEvent) => {
    const { agentId, userId, conversationId, tokenCount, maxTokens, thresholdPercent } = event;

    log.info(
      `compaction-hook:triggered agent=${agentId} tokens=${tokenCount}/${maxTokens} ` +
      `(${Math.round(thresholdPercent * 100)}% of limit)`
    );

    const memory = getSentinelMemory();
    const sessionId = `compaction-${conversationId}-${Date.now()}`;

    // Build the flush prompt
    const flushPrompt = memory.buildFlushPrompt(agentId, sessionId);

    let agentResponse: string;
    try {
      agentResponse = await invokeAgentFn(agentId, flushPrompt, conversationId);
    } catch (err) {
      log.error(`compaction-hook:invoke-failed agent=${agentId} error=${String(err)}`);
      return; // Do not block compaction if flush fails
    }

    // NO_FLUSH signal — agent says nothing worth storing
    if (agentResponse.trim() === "NO_FLUSH") {
      log.info(`compaction-hook:no-flush agent=${agentId}`);
      return;
    }

    // Parse the agent's memory extraction
    let parsed: FlushResponse;
    try {
      const clean = agentResponse
        .replace(/```json\n?/g, "")
        .replace(/```\n?/g, "")
        .trim();
      parsed = JSON.parse(clean) as FlushResponse;
    } catch {
      log.warn(
        `compaction-hook:parse-failed agent=${agentId} ` +
        `response="${agentResponse.slice(0, 100)}..."`
      );
      return;
    }

    if (!Array.isArray(parsed.memories) || parsed.memories.length === 0) {
      log.info(`compaction-hook:empty-flush agent=${agentId}`);
      return;
    }

    // Validate and write each memory
    const VALID_TYPES: MemoryType[] = [
      "fact", "decision", "preference", "entity", "procedure", "event",
    ];

    const toWrite: WriteMemoryParams[] = parsed.memories
      .filter((m) => {
        if (!VALID_TYPES.includes(m.type)) {
          log.warn(`compaction-hook:invalid-type type=${m.type} — skipping`);
          return false;
        }
        if (!m.content || m.content.trim().length < 10) {
          log.warn("compaction-hook:too-short — skipping");
          return false;
        }
        return true;
      })
      .map((m) => ({
        agentId,
        userId,
        type: m.type,
        content: m.content.trim(),
        importance: Math.min(10, Math.max(1, Math.round(m.importance ?? 5))),
        tags: Array.isArray(m.tags) ? m.tags : [],
        sessionId,
        sensitive: m.sensitive === true,
      }));

    const { written, skipped } = memory.bulkWrite(toWrite);

    if (parsed.summary) {
      log.info(`compaction-hook:summary agent=${agentId} "${parsed.summary.slice(0, 80)}"`);
    }

    log.info(
      `compaction-hook:complete agent=${agentId} ` +
      `written=${written} skipped=${skipped} session=${sessionId}`
    );
  });

  log.info("compaction-hook:registered — listening for context_threshold_reached");
}

// ─── Manual flush (for UI "Flush" button) ────────────────────────────────────

/**
 * Manually trigger a memory flush for a given agent.
 * Used by the Memory tab's "Generate Flush Prompt" button.
 * Returns the prompt text for the user to copy into their session.
 */
export function buildManualFlushPrompt(agentId: string): string {
  const memory = getSentinelMemory();
  const sessionId = `manual-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
  return memory.buildFlushPrompt(agentId, sessionId);
}

// ─── Patch note for clawsentinel-patch.mjs ───────────────────────────────────
//
// The patch script must add this to the gateway server entry point:
//
//   import { registerCompactionHook } from "./src/memory/sentinel-compaction-hook.js";
//   registerCompactionHook(agentEventBus, invokeAgent);
//
// Where `agentEventBus` is OpenClaw's agent EventEmitter and `invokeAgent` is
// the function that sends a message to an agent and returns its response.
// Both are available in OpenClaw's gateway/server.ts after initialization.