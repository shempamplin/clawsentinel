================================================================================
CLAWSENTINEL — GDPR COMPLIANCE DOCUMENTATION
SentinelMemory: Personal Data Processing Record
Author: Gemini 3.1 Pro (20260312-057-GEMINI), reviewed by Claude Sonnet 4.6
Closes: OPEN-009
Date: 2026-03-12
================================================================================

## What Personal Data Is Stored

| Field            | Type                   | Notes |
|------------------|------------------------|-------|
| userId           | Direct identifier      | Identifies the human user |
| sessionId        | Pseudonymous identifier| Rotates per session |
| content          | Free-text string       | May contain PII (names, emails, preferences) extracted from conversation |
| createdAt        | Timestamp              | |
| lastAccessedAt   | Timestamp              | |
| expiresAt        | Timestamp              | Governs automatic decay |

## Legal Basis for Processing

- **Article 6(1)(f) Legitimate Interests** — providing contextual memory continuity
  for the AI agent on behalf of the deploying entity, OR
- **Article 6(1)(a) Consent** — if the OpenClaw host explicitly gathers user
  consent during skill onboarding (recommended for consumer-facing deployments).

## Retention Policy and Deletion Mechanisms

- **Automatic decay:** `expiresAt` field + `RECENCY_HALF_LIFE_DAYS` scoring decay
  cause stale memories to fall below recall threshold and be pruned on compaction.
- **Hard deletion (API):**
  - `DELETE /agent/:agentId` → `memory.clearAgent(agentId)` — drops all rows for agent
  - `DELETE /:id?agentId=...` → `memory.delete(id)` — drops a single memory entry
- **Right to Erasure (GDPR Art. 17):** Satisfied by `DELETE /agent/:agentId`.
  Confirmed: SQLite WAL database rows are permanently removed, not flagged inactive.

## Right to Access (GDPR Art. 15)

Satisfied via:
- `GET /stats?agentId=...` — returns structured memory summary
- Recall query API — returns formatted JSON memory objects

## Data Processor / Controller Determination

| Deployment       | Data Controller        | ClawSentinel role |
|------------------|------------------------|-------------------|
| Self-hosted      | Deploying entity       | Part of on-premise application; no independent controller role |
| External sync    | Deploying entity       | External sync service becomes Data Processor; DPA required |

## OPEN-020 Log Streaming — GDPR Addendum (RISK)

**Risk:** `streamFinding()` sends real-time NDJSON logs to an external
`config.url`. If a scanner rule triggers on code containing PII (e.g., a name
or email in a string literal caught as evidence), that PII is transmitted off-host.

**Current mitigation:** `redactLogMessage()` redacts credential patterns.
Standard PII (names, emails, phone numbers) is **NOT currently redacted**.

**Required action before OPEN-020 ships:**
Log streams must either:
1. Be routed exclusively to GDPR-compliant endpoints, OR
2. Have a PII scrubbing pass added to `streamFinding()` prior to transmission.

This is a blocking requirement for OPEN-020. Document in its ADR.

================================================================================
END GDPR DOCUMENTATION — SentinelMemory
================================================================================
