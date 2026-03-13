/**
 * @clawsentinel
 * @author      Claude Sonnet 4.6
 * @date        2026-03-08
 * @log-entry   20260308-012-CLAUDE
 * @reviewed-by Gemini 3 Flash (finding: 20260308-003-GEMINI)
 * @status      approved
 *
 * SentinelMemory — Core Runtime Context Threshold Emitter
 *
 * CRITICAL FINDING (Gemini 20260308-003-GEMINI):
 *   `context_threshold_reached` is present in log-server.js but NOT confirmed
 *   in OpenClaw's core agent runtime. If the core runtime doesn't emit this event,
 *   the compaction hook (sentinel-compaction-hook.ts) never fires — silently.
 *
 * This module provides a defensive shim:
 *   1. Polls the agent's reported token count (via OpenClaw's agent status API)
 *   2. Emits `context_threshold_reached` on the shared event bus when threshold is hit
 *   3. Also emits `SYSTEM_CONTEXT_CRITICAL` at 90% (Gemini's recommended signal)
 *   4. Backs off automatically once flush has been triggered for this conversation
 *
 * Integration (in OpenClaw gateway entry point, AFTER agentEventBus is initialized):
 *
 *   import { registerContextThresholdEmitter } from
 *     "./memory/sentinel-context-threshold-emitter.js";
 *
 *   registerContextThresholdEmitter({
 *     eventBus: agentEventBus,
 *     getTokenUsage: () => agent.getContextUsage(),  // adapt to OpenClaw's actual API
 *     maxTokens: process.env.MAX_CONTEXT_TOKENS ? parseInt(process.env.MAX_CONTEXT_TOKENS) : 200000,
 *   });
 *
 * Modification history:
 *   2026-03-08  Claude Sonnet 4.6  20260308-012-CLAUDE  — initial implementation
 *                                                          based on Gemini OPEN-001 followup
 */

import { EventEmitter } from "node:events";
import { createSubsystemLogger } from "../logging/subsystem.js";

const log = createSubsystemLogger("sentinel-ctx-emitter");

// ─── Configuration ────────────────────────────────────────────────────────────

export type ContextThresholdEmitterOptions = {
  /** The shared OpenClaw agent event bus */
  eventBus: EventEmitter;

  /**
   * Function that returns current token usage for the active conversation.
   * Adapt this to whatever OpenClaw exposes — e.g. agent.getContextUsage(),
   * conversation.tokenCount, etc.
   */
  getTokenUsage: () => Promise<{
    conversationId: string;
    agentId: string;
    userId?: string;
    tokenCount: number;
  } | null>;

  /** Maximum context window size. Default: 200000 */
  maxTokens?: number;

  /**
   * Fraction at which to emit context_threshold_reached. Default: 0.85
   * Matches what Gemini observed in log-server.js.
   */
  warningThreshold?: number;

  /**
   * Fraction at which to emit SYSTEM_CONTEXT_CRITICAL. Default: 0.90
   * Gemini's recommended signal — fires slightly later as a hard warning.
   */
  criticalThreshold?: number;

  /** Poll interval in ms. Default: 5000 (5 seconds) */
  pollIntervalMs?: number;
};

// ─── State ────────────────────────────────────────────────────────────────────

/** Track which conversations have already triggered a flush this cycle */
const flushedConversations = new Set<string>();

/** Track which conversations have emitted CRITICAL this cycle */
const criticalFiredConversations = new Set<string>();

// ─── Emitter ──────────────────────────────────────────────────────────────────

/**
 * Register the context threshold polling emitter.
 *
 * If OpenClaw's core runtime already emits `context_threshold_reached`, this
 * shim is harmless — the event bus will have two emitters for the same event,
 * and the compaction hook will deduplicate by conversation ID.
 *
 * If OpenClaw does NOT emit it (Gemini's finding: unconfirmed in core runtime),
 * this shim is the only thing keeping the memory flush alive.
 */
export function registerContextThresholdEmitter(
  opts: ContextThresholdEmitterOptions,
): () => void {
  const {
    eventBus,
    getTokenUsage,
    maxTokens = 200_000,
    warningThreshold = 0.85,
    criticalThreshold = 0.90,
    pollIntervalMs = 5_000,
  } = opts;

  log.info(
    `sentinel-ctx-emitter:start ` +
    `maxTokens=${maxTokens} warning=${warningThreshold * 100}% ` +
    `critical=${criticalThreshold * 100}% poll=${pollIntervalMs}ms`,
  );

  const intervalHandle = setInterval(async () => {
    let usage: Awaited<ReturnType<typeof getTokenUsage>>;
    try {
      usage = await getTokenUsage();
    } catch (err) {
      log.warn(`sentinel-ctx-emitter:poll-error ${String(err)}`);
      return;
    }

    if (!usage) return;

    const { conversationId, agentId, userId, tokenCount } = usage;
    const ratio = tokenCount / maxTokens;

    // ── SYSTEM_CONTEXT_CRITICAL (90%) ──────────────────────────────────────
    if (ratio >= criticalThreshold && !criticalFiredConversations.has(conversationId)) {
      criticalFiredConversations.add(conversationId);
      log.warn(
        `sentinel-ctx-emitter:critical ` +
        `agent=${agentId} tokens=${tokenCount}/${maxTokens} (${Math.round(ratio * 100)}%)`,
      );
      eventBus.emit("SYSTEM_CONTEXT_CRITICAL", {
        agentId,
        userId,
        conversationId,
        tokenCount,
        maxTokens,
        thresholdPercent: ratio,
      });
    }

    // ── context_threshold_reached (85%) ────────────────────────────────────
    if (ratio >= warningThreshold && !flushedConversations.has(conversationId)) {
      flushedConversations.add(conversationId);
      log.info(
        `sentinel-ctx-emitter:threshold-reached ` +
        `agent=${agentId} tokens=${tokenCount}/${maxTokens} (${Math.round(ratio * 100)}%)`,
      );
      eventBus.emit("context_threshold_reached", {
        agentId,
        userId,
        conversationId,
        tokenCount,
        maxTokens,
        thresholdPercent: ratio,
      });
    }
  }, pollIntervalMs);

  // ── Conversation reset — clear flushed state when new conversation starts ──
  const onNewConversation = (event: { conversationId: string }) => {
    flushedConversations.delete(event.conversationId);
    criticalFiredConversations.delete(event.conversationId);
    log.info(`sentinel-ctx-emitter:reset conversationId=${event.conversationId}`);
  };

  // Listen for whatever event OpenClaw uses to signal a new conversation.
  // Common candidates — adjust to match actual OpenClaw event name:
  for (const newConvEvent of ["conversation:start", "conversation:new", "agent:reset", "session:new"]) {
    eventBus.on(newConvEvent, onNewConversation);
  }

  // ── Optional: listen for agent:token_usage_update ────────────────────────
  // Gemini (20260308-006-GEMINI) recommends this event as a direct hook.
  // CAUTION: "agent:token_usage_update" was NOT found in the OpenClaw source files
  // we have access to. It may exist in a newer version or be inferred architecture.
  // The polling shim above remains the confirmed fallback. This handler fires first
  // if the event exists; if it does not exist, the shim handles it silently.
  // When OpenClaw confirms or denies this event, remove whichever path is incorrect.
  const onTokenUsageUpdate = (stats: {
    conversationId?: string;
    agentId?: string;
    userId?: string;
    usagePercent?: number;   // Gemini's observed payload shape
    prompt_tokens?: number;  // alternative payload key
    completion_tokens?: number;
    total_tokens?: number;
    max_tokens?: number;
  }) => {
    const conversationId = stats.conversationId ?? "unknown";
    const agentId = stats.agentId ?? "unknown";

    // Normalize usagePercent from either payload shape
    let usagePercent = stats.usagePercent;
    if (usagePercent === undefined && stats.total_tokens && stats.max_tokens) {
      usagePercent = stats.total_tokens / stats.max_tokens;
    }
    if (usagePercent === undefined) return;

    log.info(`sentinel-ctx-emitter:token-usage-update agent=${agentId} usage=${Math.round(usagePercent * 100)}%`);

    if (usagePercent >= criticalThreshold && !criticalFiredConversations.has(conversationId)) {
      criticalFiredConversations.add(conversationId);
      eventBus.emit("SYSTEM_CONTEXT_CRITICAL", { agentId, userId: stats.userId, conversationId, thresholdPercent: usagePercent });
    }
    if (usagePercent >= warningThreshold && !flushedConversations.has(conversationId)) {
      flushedConversations.add(conversationId);
      eventBus.emit("context_threshold_reached", { agentId, userId: stats.userId, conversationId, thresholdPercent: usagePercent });
    }
  };

  eventBus.on("agent:token_usage_update", onTokenUsageUpdate);
  log.info("sentinel-ctx-emitter:listening-for agent:token_usage_update (unverified — polling shim also active)");

  // Return a cleanup function
  return () => {
    clearInterval(intervalHandle);
    eventBus.off("agent:token_usage_update", onTokenUsageUpdate);
    for (const newConvEvent of ["conversation:start", "conversation:new", "agent:reset", "session:new"]) {
      eventBus.off(newConvEvent, onNewConversation);
    }
    log.info("sentinel-ctx-emitter:stopped");
  };
}