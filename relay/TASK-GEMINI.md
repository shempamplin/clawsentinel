================================================================================
CLAWSENTINEL — TASK ASSIGNMENT
Cycle: beta14  |  Date: 2026-03-12
Assigned to: Gemini 3.1 Pro (Integration Auditor)
Task: ADR-006 Phase 1 scope confirmation + OPEN-015 AST scanner input
Prepared by: Claude Sonnet 4.6  |  Log-ref: 20260312-060-CLAUDE
================================================================================

SVT-REQUIRED: SVT:beta14|fc7adc254a99c97c|20260312-060-CLAUDE|OPEN-012,OPEN-015,OPEN-018
TASK-NONCE:   F2C8

── SHARED CONTEXT ──────────────────────────────────────────────────────────────
COMPLETED THIS CYCLE (your prior tasks):
  OPEN-017  Patch script hardening — confirmed and implemented. CLOSED.
  OPEN-009  GDPR docs — delivered and accepted. CLOSED.
  ADR-008   OWASP multipliers — reviewed and updated. CLOSED.
  CONTRIBUTING.md schema — corrected and applied. CLOSED.

REMAINING OPEN ITEMS:
  OPEN-012  skill-runner.js sandbox child process
  OPEN-015  ADR-006 Phase 1 AST scanner — not yet built
  OPEN-018  Danger scoring (computeDangerScore) — not yet built

CURRENT PACKAGE: v7
────────────────────────────────────────────────────────────────────────────────

Acknowledge shared context: "SHARED CONTEXT RECEIVED — [any conflict or question]"

CONTEXT

Your prior tasks this cycle are complete. Two items remain that need your
integration audit perspective before Claude can build them: ADR-006 Phase 1
scope and a specific sandbox escape risk (OPEN-015).

TASK 1 — ADR-006 PHASE 1 SCOPE CONFIRMATION (OPEN-015)

ADR-006 is the AST (Abstract Syntax Tree) scanner proposal. It is split into:
  Phase 1: AST-based detection for patterns that regex cannot reliably catch
  Phase 2: Full AST pipeline (longer term)

Claude proposed the following Phase 1 scope — confirm or refine:

  Phase 1 targets (3 rules that are weak as regex):
    A. inject-dynamic-jailbreak — array variable assigned then .join() called
       in a separate statement. Regex cannot span statements reliably.
    B. exfil-variable-indirection-headers — header name/value split across
       statements. Same problem.
    C. exfil-buffer-encode-chain — Buffer.from() with env var, result stored
       in variable, then passed to fetch() later. Multi-statement chain.

  Question for Gemini: Are these the right 3 to prioritize for Phase 1?
  Are there other rules in the scanner that would benefit more from AST
  analysis? Reference specific rule IDs from skill-scanner.ts.

TASK 2 — OPEN-015 SANDBOX ESCAPE REVIEW

The following sandbox escape was confirmed but not yet fixed:

  Vector: import('vm') in skill-runner.js
  Issue:  skill-runner.js wraps global.require to block BLOCKED_MODULES,
          but ESM dynamic import() bypasses this wrapper entirely.
          A skill can call import('vm') and get unrestricted vm module access.
  Status: OPEN-015, high priority, blocking M4.

  Question for Gemini: Review the skill-runner.js sandbox implementation
  (parts 08 and 09 of the relay). What is the safest way to intercept
  dynamic import() in a Node.js child process? Options to evaluate:
    A. Override globalThis[Symbol.for('nodejs.rejection')] hooks
    B. Use --experimental-vm-modules flag restrictions
    C. Add an import() wrapper in the child process bootstrap
    D. Use worker_threads instead of fork() (architectural change)

  Provide a recommendation with confidence rating and any OWASP mapping.

OUTPUT FORMAT

Respond in Part 10 format (single flat text response, no attachments).
Mark all findings READ FROM SOURCE or INFERRED FROM DESCRIPTION.
Use NNN for log entry number — never self-assign.
Echo TASK-NONCE F2C8 in NONCE-ECHO field.

LOG ENTRY DRAFT AT END

Date: 2026-03-12
Author: Gemini 3.1 Pro
Type: REVIEW
Status: PROPOSED
Changes Made: None — review and recommendation only
Uncertainties: [list anything not verifiable from provided source]

╔══════════════════════════════════════════════════════════════════════════════╗
END TASK — GEMINI
◀◀◀ SHEM: COPY EVERYTHING FROM TOP LINE TO THIS LINE, PASTE TO GEMINI
╚══════════════════════════════════════════════════════════════════════════════╝
