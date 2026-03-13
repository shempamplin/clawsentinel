/**
 * ClawSentinel — SentinelMemory Relevance Weights
 * OPEN-008 implementation
 *
 * Prevents "Context Displacement" attacks — where low-trust skill data
 * accumulates in memory and displaces high-trust system safety instructions
 * during RAG retrieval. Addresses the "Memory Staging" / "Sleeper" threat
 * class identified by Gemini (20260309-031-GEMINI).
 *
 * Schema designed by Gemini 3 Flash. TypeScript implementation by Claude
 * Sonnet 4.6, reconciled against existing TrustSource type system in
 * sentinel-memory.ts to avoid a parallel type hierarchy.
 *
 * INTEGRATION POINT (sentinel-memory.ts — recall()):
 *   Stage 2 scoring must be updated from:
 *     score: computeScore(row.fts_rank, row)
 *   To:
 *     score: computeScore(row.fts_rank, row) *
 *            getTrustRelevanceMultiplier(row.trust_source as TrustSource) +
 *            getSystemAnchorBoost(row.trust_source as TrustSource)
 */

import type { TrustSource } from "./sentinel-memory";

// ─── Scoring formula ──────────────────────────────────────────────────────────
//
//   FinalScore = (BaseScore × TrustMultiplier) + SystemAnchorBoost
//
//   Where BaseScore is the existing computeScore() result:
//     (fts_rank × 0.45) + (importance/10 × 0.25) +
//     (recency_decay × 0.25) + (access_freq × 0.05)
//
//   TrustMultiplier: scales the entire base score up or down based on source
//   SystemAnchorBoost: additive constant that prevents system memories from
//     being displaced even when their FTS rank is low (e.g., a safety rule
//     that uses different vocabulary than the query still surfaces)

// ─── Trust multipliers (by TrustSource) ──────────────────────────────────────
//
// Gemini's MemorySource → our TrustSource mapping:
//   system           → system (1.0 trust)
//   user_verified    → manual (1.0 trust)
//   agent_internal   → agent-auto, flush-verified (0.7–0.8 trust)
//   external_tool    → flush-unverified, migrated (0.5 trust)
//   skill_api        → skill-api (0.3 trust)

export const TRUST_RELEVANCE_MULTIPLIERS: Record<TrustSource, number> = {
  // Gemini schema: system → 1.5x (highest priority, never displaced)
  system:             1.5,

  // Gemini schema: user_verified → 1.2x (explicit human approval)
  manual:             1.2,

  // Gemini schema: agent_internal → 1.0x (agent's own reasoning, standard weight)
  "agent-auto":       1.0,
  "flush-verified":   1.0,

  // Gemini schema: external_tool → 0.7x (external data, potentially tainted)
  "flush-unverified": 0.7,
  migrated:           0.7,

  // Gemini schema: skill_api → 0.3x (CRITICAL: heavy penalty, BP-008 defense)
  // This is the primary Context Displacement mitigation — a malicious skill
  // that floods memory with high-importance entries still loses to system
  // memories at retrieval time because the multiplier penalizes it heavily.
  "skill-api":        0.3,
};

// ─── System anchor boost ──────────────────────────────────────────────────────
//
// Additive constant applied AFTER the trust multiplier.
// Ensures system-sourced safety instructions remain retrievable even when
// their FTS5 rank is low (vocabulary mismatch with the query).
//
// Gemini's schema: systemAnchorBoost = 0.5
// Only applied to source=system memories (ClawSentinel internals).

export const SYSTEM_ANCHOR_BOOST = 0.5;

// ─── Recency decay factor ─────────────────────────────────────────────────────
//
// Gemini's schema: recencyDecay = 0.98 (slow decay)
// Rationale: safety triggers should not "time out" due to age alone.
// This is a global modifier on the recency component, not a replacement
// for the existing exponential decay in computeScore().
//
// Integration note: multiply the recencyScore() result by this factor
// only for non-system sources. System memories use the anchor boost
// instead — applying both would double-count the protection.

export const SLOW_RECENCY_DECAY_FACTOR = 0.98;

// ─── Helper functions ─────────────────────────────────────────────────────────

/**
 * Returns the trust-based relevance multiplier for a given memory source.
 * Apply this to the result of computeScore() before sorting recall results.
 */
export function getTrustRelevanceMultiplier(source: TrustSource): number {
  return TRUST_RELEVANCE_MULTIPLIERS[source] ?? 0.5; // unknown source → conservative
}

/**
 * Returns the additive system anchor boost for a given source.
 * Only non-zero for source="system" — ClawSentinel's own safety instructions.
 */
export function getSystemAnchorBoost(source: TrustSource): number {
  return source === "system" ? SYSTEM_ANCHOR_BOOST : 0;
}

/**
 * Computes the final trust-weighted relevance score for a memory entry.
 * Drop-in wrapper around the existing computeScore() result.
 *
 * @param baseScore  Result of existing computeScore(ftsRank, memory)
 * @param source     TrustSource of the memory entry (from trust_source column)
 * @returns          Final score for recall ranking
 */
export function applyTrustWeighting(
  baseScore: number,
  source: TrustSource,
): number {
  return (
    baseScore * getTrustRelevanceMultiplier(source) +
    getSystemAnchorBoost(source)
  );
}

// ─── Context displacement detection threshold ─────────────────────────────────
//
// If the top-ranked recalled memory comes from skill-api or a source with
// multiplier < 0.5, this is a potential Context Displacement attempt.
// The recall() function should log a diagnostic warning at this threshold.

export const DISPLACEMENT_ALERT_THRESHOLD: TrustSource[] = [
  "skill-api",
  "flush-unverified",
  "migrated",
];

export function isDisplacementRisk(topSource: TrustSource): boolean {
  return DISPLACEMENT_ALERT_THRESHOLD.includes(topSource);
}