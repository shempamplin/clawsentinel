# ClawSentinel — Daily Context Sync
# Generated: 2026-03-22 18:15 UTC
# Upload this file to your Claude.ai project knowledge to sync chat Claude.

## REPO STATE
Branch: main
Last commit: 85774c4 beta14: remove .bak files, add .bak to gitignore

## RECENT AUDIT LOG (last 3 entries)
- AUDIT-20260319-034 [high]: 74 tests/skill-scanner.test.ts failures: 30 describe blocks with samples not matching real rule patt
  Resolution: All 30 describe blocks replaced with pattern-verified samples. Rule IDs and seve
- AUDIT-20260319-035 [medium]: SCRYPT_N=131072 causes RangeError in test environment — ~128MB per scryptSync call exceeds worker me
  Resolution: SCRYPT_N conditional: 2^14 when NODE_ENV=test, 2^17 in production. ADR-001 prese
- AUDIT-20260319-036 [low]: Vitest config running all 1756 OpenClaw monorepo tests. audit.test.ts and dm-policy-channel-smoke.te
  Resolution: Created clawsentinel.vitest.config.ts scoped to ClawSentinel tests only with exp

## BYPASS WORKBENCH
Total: 14 | Verified fixed: 6 | Open: 8
Unverified:
  BP-005 [?] credential-hardcoded-inline — Partial fix — full variable-concat chain may still evade. ChatGPT round 4 to ver
  BP-006 [?] inter-agent-recursive-invoke — Awaiting ChatGPT round 4 verification.
  BP-007 [?] sandbox — Rule added beta13. ADR-007 test added. Reflect.get variant caught via requiresCo
  BP-008 [?] sandbox — IPC flood doesn't trigger 3-strike kill because it doesn't fail Zod validation —
  BP-009 [critical] exfil-buffer-encode-chain — Reproduced with scanSource(); target rule missed while broader exfil rules fired
  BP-010 [critical] exfil-variable-indirection-headers — Round 4 ChatGPT confirmed Bearer+concat variant evades fix. Reopened 20260319.
  BP-013 [critical] credential-hardcoded-inline — BP-005 remains reproducible via concat. Source: 20260312-053-CHATGPT
  BP-014 [high] inter-agent-recursive-invoke — BP-006 remains reproducible at static-scan level. Runtime guardAgentRecursion() 

## OPEN ITEMS
  M4-BLOCKERS:    OPEN-005, OPEN-012, OPEN-015, OPEN-018
  M4-BLOCKERS:    [OPEN-IDs blocking v1.0.0]
  OPEN-005  Unit tests — 17/62 rules (25%)           Grok                M4 BLOCKER
  OPEN-012  skill-runner.js sandbox red-team         ChatGPT round 4     M4 BLOCKER
  OPEN-015  ADR-006 AST scanner Phase 1              Claude              M4 BLOCKER
  OPEN-018  computeDangerScore() implementation      Claude              M4 BLOCKER
  OPEN-019  Runtime behavioral audit log             Needs ADR-009       high
  OPEN-021  Hardware requirements spec (per-instance)      Claude+Grok         M6/v1.0.0
  OPEN-023  NemoClaw conflict audit (sandbox coexistence)     Claude              M6/v1.0.0
  Next open item ID: OPEN-030

## RECENT SESSION LOG (last 10 lines)
  - `21:08:47 UTC` Session started — task: chatgpt-round4, dry_run: False
  - `21:08:47 UTC` Repo context loaded
    16486 chars from 3 files
  - `21:08:47 UTC` Safety review requested
  - `21:09:14 UTC` chatgpt responded
    2856 chars
  - `21:09:14 UTC` Response saved to relay/chatgpt-round4-response.txt
  - `21:09:39 UTC` Claude review complete
    3922 chars
  - `21:09:39 UTC` Review saved to relay/chatgpt-round4-claude-review.txt

## PENDING RELAY REVIEWS (awaiting implementation)
  chatgpt-round4-claude-review.txt

## HOW TO RESTORE FULL CONTEXT
Also upload these files to project knowledge:
  relay/ONBOARDING-CONTINUITY-v3.4.md
  relay/BYPASS-WORKBENCH.json
  relay/LIVING-AUDIT-ERROR-LOG.json

## SESSION STARTUP CHECKLIST
1. git pull origin main ✓ (done by hey-claude)
2. Upload this file to Claude.ai project knowledge
3. Tell chat Claude: 'New session. Context file uploaded.'
4. Chat Claude reads it and confirms project state
5. Begin work