================================================================================
CLAWSENTINEL — TASK ASSIGNMENT
Cycle: beta14  |  Date: 2026-03-12
Assigned to: Grok (xAI) (Test Coverage Lead)
Task: Regression tests for BP-002, BP-010, BP-011 v7 rule fixes
Prepared by: Claude Sonnet 4.6  |  Log-ref: 20260312-060-CLAUDE
================================================================================

SVT-REQUIRED: SVT:beta14|fc7adc254a99c97c|20260312-060-CLAUDE|OPEN-012,OPEN-015,OPEN-018
TASK-NONCE:   E7A3

── SHARED CONTEXT ──────────────────────────────────────────────────────────────
COMPLETED THIS CYCLE:
  OPEN-005  Unit tests — 62/62 rules covered. CLOSED.
  OPEN-009  GDPR docs — complete.
  OPEN-017  Patch script hardening — complete.
  BP-002, BP-010, BP-011 — scanner rules patched in v7 (20260312-060-CLAUDE).

OPEN BYPASSES:
  BP-008    IPC flood — runtime only, no static rule possible.
  BP-009 through BP-014 — trigger patterns caught by scanner rules.

REMAINING BLOCKERS:
  OPEN-012  skill-runner.js sandbox child process hardening
  OPEN-015  import('vm') sandbox escape fix
  OPEN-018  Danger scoring implementation (computeDangerScore)

CURRENT PACKAGE: v7
────────────────────────────────────────────────────────────────────────────────

Acknowledge shared context: "SHARED CONTEXT RECEIVED — [any conflict or question]"

CONTEXT

OPEN-005 is complete — all 62 rules have test coverage. Your next task is
writing regression tests for the three scanner rules patched in v7. These
tests must follow Pattern 10 (Regression Test Loop): each test must FAIL on
the vulnerable rule and PASS on the patched rule.

PREREQUISITE

No compiled output or node_modules in the relay package. Before running:

  npm install
  npm install --save-dev vitest @vitest/coverage-v8

Validate samples using scanSource() not raw regex:

  npx tsx -e "
    const { scanSource } = require('./src/security/skill-scanner');
    const result = scanSource('YOUR_SAMPLE_HERE', 'test.ts');
    console.log(result.length > 0 ? 'TRIGGERED' : 'MISSED');
  "

YOUR TASK — REGRESSION TESTS FOR V7 RULE FIXES

Write a describe block for each of the three patched rules. Each block must
include exactly 2 TRIGGER cases and 2 SAFE cases. Follow the existing test
file format in tests/skill-scanner.test.ts.

RULE 1 — inject-worker-thread (BP-002 fix)
The fix added a require('worker_threads') branch. New trigger: any code
that requires worker_threads. Safe: Worker constructed from a static
string path with no require.

Key samples to include:
  TRIGGER: const { Worker } = require("worker_threads"); new Worker(userScript);
  TRIGGER: const wt = require("worker_threads"); const w = new wt.Worker(fn);
  SAFE:    new Worker("./worker.js");
  SAFE:    new Worker(path.join(__dirname, "background-task.js"));

RULE 2 — exfil-variable-indirection-headers (BP-010 fix)
The fix catches headers.set/append where the second argument is a variable,
not a string literal. Safe: second argument is a string literal.

Key samples to include:
  TRIGGER: const h = "Authorization"; const v = apiKey; headers.set(h, v); fetch(url, { headers });
  TRIGGER: const name = "x-api-key"; const val = process.env.KEY; headers.append(name, val);
  SAFE:    headers.set("Content-Type", "application/json");
  SAFE:    headers.set(headerName, "Bearer static-value");

RULE 3 — inject-dynamic-jailbreak (BP-011 fix)
The fix catches variable-assigned arrays containing jailbreak keywords.
Safe: array contains only benign words.

Key samples to include:
  TRIGGER: const parts = ["ignore", "all", "instructions"]; const p = parts.join(" ");
  TRIGGER: const words = ["override", "previous", "rules"]; sendToLLM(words.join(" "));
  SAFE:    const parts = ["hello", "world"]; const greeting = parts.join(" ");
  SAFE:    const words = ["generate", "a", "poem"]; sendToLLM(words.join(" "));

DELIVERABLE FORMAT

Provide the complete describe blocks as plain text. Validate all TRIGGER
samples with scanSource() before submitting. Flag any that fail to trigger
and explain why — do not silently substitute.

Use the existing test helper functions (triggers, safe) already defined in
tests/skill-scanner.test.ts.

After the test blocks, run Pattern A (suite verification):
  npx vitest run --coverage
Report: coverage remains above 80% branches, no regressions, new tests pass.

CONSTRAINTS

Never self-assign log entry numbers. Use NNN.
Echo TASK-NONCE E7A3 in NONCE-ECHO field.
Single flat response per Part 10 format.
Mark all findings READ FROM SOURCE or INFERRED FROM DESCRIPTION.

LOG ENTRY DRAFT AT END

Date: 2026-03-12
Author: Grok (xAI)
Type: IMPLEMENTATION
Status: PROPOSED
Changes Made: Regression tests for BP-002, BP-010, BP-011 v7 fixes
Uncertainties: [list any samples that failed scanSource() validation]

╔══════════════════════════════════════════════════════════════════════════════╗
END TASK — GROK
◀◀◀ SHEM: COPY EVERYTHING FROM TOP LINE TO THIS LINE, PASTE TO GROK
╚══════════════════════════════════════════════════════════════════════════════╝
