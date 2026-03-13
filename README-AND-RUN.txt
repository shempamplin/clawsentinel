================================================================================
CLAWSENTINEL beta14 — README AND RUN
================================================================================
This file is your single entry point. Follow these steps IN ORDER.
Do not skip steps. Log every error to LIVING-AUDIT-ERROR-LOG.json
(in this package root) before continuing past any failure.

SVT (Session Verification Token):
  SVT:beta14|fc7adc254a99c97c|20260309-052-CLAUDE|OPEN-005,OPEN-012,OPEN-015,OPEN-018

Your role in this package:
  ROLE-ID: CHATGPT-ADVERSARIAL-REVIEWER
  Cycle:   beta14
  Log ref: Next entry is 20260310-053-CHATGPT

================================================================================
STEP 1 — VERIFY THE PACKAGE (do this before reading any content)
================================================================================

1a. Confirm you received all 25 source parts:
    A-source-packages/ must contain:
    clawsentinel-beta14-SCR-part01of25.txt through part25of25.txt
    If any are missing: log error class MANIFEST_MISSING_PART and stop.

1b. Verify file integrity against MANIFEST.sha256:
    For each file in MANIFEST.sha256, confirm SHA-256 hash and byte count match.
    If any file fails: log error class MANIFEST_HASH_MISMATCH and stop.

1c. Confirm expected folder structure:
    A-source-packages/   — 23 .txt files
    B-continuity/        — 5 files (ADR-007, ADR-008, BYPASS-WORKBENCH.json,
                           EXECUTIVE-SUMMARY, RELAY-COVER)
    C-onboarding/        — 2 files (ONBOARDING-CONTINUITY-v3.4,
                           NEW-CYCLE-INIT-PROMPT)
    D-task-assignments/  — 3 files (TASK-CHATGPT, TASK-GEMINI, TASK-GROK)
    MANIFEST.sha256
    README-AND-RUN.txt
    LIVING-AUDIT-ERROR-LOG.json

================================================================================
STEP 2 — READ ONBOARDING AND CONTINUITY
================================================================================

2a. Read in this order:
    1. C-onboarding/clawsentinel-beta14-ONBOARDING-CONTINUITY-v3.4_2026-03-10.md
    2. B-continuity/clawsentinel-beta14-EXECUTIVE-SUMMARY_2026-03-10.md
    3. B-continuity/clawsentinel-beta14-ADR-007_2026-03-10.md
    4. B-continuity/clawsentinel-beta14-ADR-008_2026-03-10.md
    5. B-continuity/clawsentinel-beta14-BYPASS-WORKBENCH_2026-03-10.json

2b. After reading, confirm these facts back (do not proceed until verified):
    - Current rule count in skill-scanner.ts (from continuity doc)
    - Number of open bypass classes in BYPASS-WORKBENCH.json
    - Status of OPEN-005, OPEN-012, OPEN-015
    - Last log entry ID (should be 20260309-052-CLAUDE)

================================================================================
STEP 3 — REASSEMBLE SOURCE CODE
================================================================================

3a. Each part in A-source-packages/ contains one or more file chunks.
    Each chunk is wrapped in:
      <file path="relative/path/to/file.ts" chunk="NofM">
      [file contents]
      </file>

3b. Reassembly rules:
    - Create the file at the path shown (relative to clawsentinel-fork/)
    - If a file has multiple chunks (NofM where M > 1), collect all chunks
      IN ORDER and concatenate
    - Do NOT insert any content between chunks — direct concatenation only
    - Confirm ALL 25 parts received before using any content

3c. Expected output: 21 files at these paths:
    src/security/skill-scanner.ts          (chunks across parts 01-03)
    src/security/skill-scanner-types.ts    (part 21)
    src/security/sentinel-hardening.ts     (part 22)
    src/security/sentinel-routes.ts        (part 23)
    CONTRIBUTING.md                        (part 24)
    clawsentinel-patch.mjs                 (part 25)
    src/security/sentinel-secrets-store.ts
    src/security/sentinel-hardening.ts     (part 22)
    src/security/sentinel-routes.ts        (part 23)
    src/memory/sentinel-memory.ts          (chunks across parts 05-06)
    src/memory/sentinel-memory-routes.ts
    src/memory/sentinel-relevance-weights.ts
    src/memory/sentinel-compaction-hook.ts
    src/memory/sentinel-context-threshold-emitter.ts
    src/sandbox/skill-sandbox.ts
    src/sandbox/skill-runner.js
    src/debug/sentinel-diagnostics.ts
    src/debug/sentinel-diagnostics-types.ts
    src/debug/sentinel-diagnostic-routes.ts
    tests/skill-scanner.test.ts            (chunks across parts 17-18)
    tests/sentinel-memory.test.ts
    tests/sentinel-secrets-store.test.ts
    tests/vitest.config.ts


> IMPORTANT — COMPILE CONSTRAINT:
> The relay is source-only and does NOT include node_modules, package.json, or
> local support modules (logging/subsystem.js, infra/errors.js, etc.).
> Running tsc --noEmit against the raw relay will report missing-module errors
> for every file that imports these dependencies. This is expected and is NOT
> a source bug. All exports that tsc reports as missing (getAllRuleMetadata,
> encrypt/decrypt, redactLogMessage, etc.) ARE present in the relay source.
> Report tsc failures as BUILD_REGRESSION only if a syntax or type error
> is confirmed in the relay source itself — not for missing node_modules.
> Full compilation must be verified against the actual repo with npm install.

3d. Run build/parse checks on the reassembled source:
    - node --check src/sandbox/skill-runner.js
    - tsc --noEmit (with a tsconfig pointing at src/)
    Log any parse errors as error class SOURCE_PARSE_ERROR before continuing.

================================================================================
STEP 4 — PRE-FLIGHT: VALIDATE ALL THREE TASK FILES
================================================================================

Before executing your own task, validate the other AIs' task files.
This is a cross-AI pre-flight check to catch issues before relay.

4a. Read D-task-assignments/clawsentinel-beta14-TASK-GEMINI_2026-03-10.md
    Check for:
    - Part count references (should say 01-23, not 01-20 or 01-26)
    - File paths that reference files not present in the relay
    - Task instructions that depend on source files that failed parse checks
    - Any instruction that contradicts the onboarding continuity doc
    Report: TASK_GEMINI_PREFLIGHT — PASS or list of TASK_CROSSREF_ERROR entries

4b. Read D-task-assignments/clawsentinel-beta14-TASK-GROK_2026-03-10.md
    Check for:
    - Part count references (should say 01-23)
    - scanSource() validation instructions present (required per Pattern 7)
    - vitest not in package.json warning — confirm this is flagged in the task
    - Bypass workbench items assigned to Grok that are already fixed
    Report: TASK_GROK_PREFLIGHT — PASS or list of TASK_CROSSREF_ERROR entries

================================================================================
STEP 5 — EXECUTE YOUR TASK
================================================================================

Read D-task-assignments/clawsentinel-beta14-TASK-CHATGPT_2026-03-10.md
and execute it fully.

Context from prior session:
  Your Round 4 red-team response was truncated after "Example attack:"
  in Q1 during beta13. Resume from that exact point — provide the attack
  code for Q1, then continue through Q2-Q5 and all six Round 4 bypass targets.
  Use Pattern 8 (Exploit Reproduction) from the onboarding doc for each bypass.

For each bypass finding, log it to BYPASS-WORKBENCH.json before proposing a fix.

================================================================================
STEP 6 — PRODUCE AUDIT OUTPUT
================================================================================

Produce a single flat text response using the format in Part 10 of the
onboarding doc. Your response must include:

6a. SECTION 1 — MANIFEST VERIFICATION RESULT
    Pass/fail per file with any hash mismatches named explicitly.

6b. SECTION 2 — SOURCE BUILD STATUS
    Parse/compile results for all 21 files. Name any errors with file + line.

6c. SECTION 3 — PRE-FLIGHT TASK REVIEW
    Gemini task: PASS or list of issues found.
    Grok task:   PASS or list of issues found.

6d. SECTION 4 — ROUND 4 BYPASS FINDINGS
    All six bypass targets with:
    - Exact TypeScript bypass code
    - Confidence rating (0-100)
    - Proposed fix
    - BYPASS-WORKBENCH.json entry (full JSON)

6e. SECTION 5 — SANDBOX QUESTIONS (Q-A through Q-D)
    Your answers to the four sandbox architecture questions.

6f. SECTION 6 — LIVING AUDIT LOG ENTRIES
    New entries to append to LIVING-AUDIT-ERROR-LOG.json.
    Use the schema defined in that file.
    Include one entry per distinct error found across all steps.

6g. SECTION 7 — LOG ENTRY DRAFT
    Use NNN as your log entry number. Claude assigns the real ID on receipt.

================================================================================
IMPORTANT RULES (from Part 13 of onboarding)
================================================================================

- Never self-assign log entry numbers. Use NNN.
- Mark all findings: READ FROM SOURCE or INFERRED FROM DESCRIPTION.
- Confidence rating required on all security findings.
- Bypass code must be logged to BYPASS-WORKBENCH.json BEFORE proposing a fix.
- One response file only. No split messages. No attachments.
- Do not auto-block skill installs. ClawSentinel flags, user decides.

================================================================================
END README-AND-RUN
================================================================================
