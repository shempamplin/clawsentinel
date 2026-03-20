================================================================================
CLAWSENTINEL — SESSION CONTINUITY & ONBOARDING GUIDE
Version: 3.4
Cycle: beta14
Date: 2026-03-10
Last log entry: 20260309-052-CLAUDE
Next entry ID: 20260310-053-[AI]
Authoritative SVT: SVT:beta14|fc7adc254a99c97c|20260309-052-CLAUDE|OPEN-005,OPEN-012,OPEN-015,OPEN-018
================================================================================

THIS IS THE SINGLE SOURCE OF TRUTH for every human and AI participant.
Version 3.4 supersedes ALL prior versions without exception.

Every requirement in this document is ABSOLUTE unless the word
RECOMMENDED appears explicitly. There are no optional sections.

WHAT CHANGED IN v3.4 (over v3.3)
────────────────────────────────────────────────────────────────────────────────

  Part 20 ADDED — Relay Automation Plan:
    Subscription decisions: ChatGPT Plus ($20) + SuperGrok ($30) = $50/mo.
    Gemini Advanced dropped — not M4-critical.
    Hardware decision: Old Dell PC, wipe SSD, install Ubuntu 24.04 LTS Desktop.
    Remote access: Tailscale (free tier).
    Automation: Playwright browser automation via SSH.
    Active time per cycle: ~5 min (vs ~45 min manual).
    Timeline: 5-7 days to v1.0.0 with paid tiers + 2 hrs/day.

DOCUMENT MAP
────────────────────────────────────────────────────────────────────────────────

  PART 0   How to Use This Document
  PART 1   Project Scope and Product Definition
  PART 2   Team Roles and Mandates
  PART 3   Output Format Standard (ABSOLUTE — Hard Gate)
  PART 4   State Verification Token (ABSOLUTE — hash-based)
  PART 5   Session Startup Procedure (ABSOLUTE)
  PART 6   Decision Authority and Consensus Protocol (ABSOLUTE)
  PART 7   Acknowledgment Protocol
  PART 8   Task Assignment and Sync Protocol
  PART 9   Pattern Library
  PART 10  Shem's Role
  PART 11  Code State
  PART 12  Open Items (authoritative)
  PART 13  Milestones
  PART 14  AI Status and Pending Tasks
  PART 15  Bypass Workbench Summary
  PART 16  ADR Status
  PART 17  Collaboration Health
  PART 18  Things Claude Must Never Do
  PART 19  Things Shem Must Never Do
  PART 20  Relay Automation Plan (NEW v3.4)


================================================================================
PART 0 — HOW TO USE THIS DOCUMENT
================================================================================

FOR CLAUDE at session start:
  Run Part 5 startup checks. Compute your SVT (Part 4). Consult Part 12
  for open items, Part 14 for pending AI tasks. Apply Part 6 throughout.

FOR OTHER AIs receiving a task:
  Read Parts 1, 2, 3, 4, 6, and your entry in Part 14.
  Compute your SVT. Return a task acknowledgment before doing any work.
  Do not begin until Claude issues TASK SYNC CONFIRMED.

FOR SHEM relaying between AIs:
  Part 10 is your operational guide. Part 19 lists what must never happen.
  When uncertain about anything technical, relay to Claude rather than deciding.

FOR NEW PARTICIPANTS:
  Read the full document before doing anything. Every part is active.


================================================================================
PART 1 — PROJECT SCOPE AND PRODUCT DEFINITION
================================================================================

WHAT CLAWSENTINEL IS

ClawSentinel is a fully forked, security-hardened version of OpenClaw.
It is not a plugin or add-on. It is a fork — the entire OpenClaw codebase
modified at depth to fix inherent vulnerabilities and add a mandatory
security pipeline for every app from every source.

  "No app reaches execution without passing through ClawSentinel.
   No app executes without ClawSentinel watching."

THE TWO PROBLEMS CLAWSENTINEL SOLVES

PROBLEM 1 — OPENCLAW'S INHERENT SECURITY VULNERABILITIES
  OpenClaw was not designed with a serious attacker model.
  Fixes applied to date:
    AES-256-GCM credential encryption replacing plaintext    (ADR-001)
    Subprocess sandbox, Zod IPC, 3-strike kill               (ADR-004)
    Memory trust scoring — low-trust cannot displace system  (ADR-005)
    Startup hardening checks                 (sentinel-hardening.ts)
    68 detection rules patching confirmed bypass vectors

PROBLEM 2 — NO SCREENING LAYER FOR APPS FROM ANY SOURCE
  OpenClaw installs and runs apps without meaningful security screening.
  ClawSentinel adds a screening pipeline that runs before execution
  and continues monitoring during execution.

THE SECURITY PIPELINE (5 stages):

  Stage 1  Static scan — 62 rules → SkillScanSummary        BUILT
  Stage 2  Danger scoring — DangerScore (0-100, tier)        IMPLEMENTING (OPEN-018)
  Stage 3  Sandbox execution — ADR-004, Zod IPC              PARTIAL (OPEN-012)
  Stage 4  Runtime behavioral audit — anomaly detection      OPEN-019
  Stage 5  Output streaming — full execution trace           OPEN-020

ABSOLUTE PRODUCT RULE — BLOCK-TIER BEHAVIOR

ClawSentinel NEVER automatically blocks an install at any tier including
BLOCK. ClawSentinel scores, tiers, and advises. The user decides.
This rule may not be changed without Shem's explicit approval.

THREAT CATEGORIES (all current rules address these):
  data-exfiltration, code-injection, credential-theft, prompt-injection,
  supply-chain, inter-agent-attack, filesystem-abuse, obfuscation,
  network-abuse, cost-bombing, gateway-abuse, crypto-mining


================================================================================
PART 2 — TEAM ROLES AND MANDATES
================================================================================

  Role                    AI                  Mandate
  ------------------------------------------------------------------------------
  Lead Producer /         Claude Sonnet 4.6   Drives direction. Evaluates all
  Coordinator                                 AI contributions. Corrects errors.
                                              Assigns all log entry IDs.
                                              Full decision authority per Part 6.

  Adversarial Reviewer    ChatGPT GPT-5.3     Red-team bypass testing.
  (red-team)                                  Owns Patterns 8-12 (Part 9).
                                              Logs all bypasses to workbench.
                                              Uses Sectioned Delivery (Part 3C).

  Integration Auditor     Gemini 3 Flash      OWASP mapping, ADR scope review,
                                              patch script review, GDPR docs.
                                              Never self-assigns log entry IDs.

  Test Coverage Lead      Grok (xAI)          Rule test suite. Owns Patterns A-C.
                                              Validates ALL samples via
                                              scanSource() — never raw regex.

  Human Coordinator       Shem Pamplin        Relay operator. Approves reserved
                                              decisions (Part 6C). See Parts 10, 19.

FILE NAMING CONVENTION (mandatory):
  clawsentinel-[cycle]-[DESCRIPTOR].[YYYY-MM-DD].[ext]
  Example: clawsentinel-beta14-TASK-CHATGPT.2026-03-09.md


================================================================================
PART 3 — OUTPUT FORMAT STANDARD (ABSOLUTE — HARD GATE)
================================================================================

Every response from every AI is a SINGLE FLAT TEXT FILE.
No exceptions. No nested documents. No unsignaled splits.

--------------------------------------------------------------------------------
3A — REQUIRED RESPONSE STRUCTURE
--------------------------------------------------------------------------------

Every response uses START/END markers. Shem copies everything between
those markers and pastes it directly to Claude. Shem does not read,
interpret, or verify anything.

▶▶▶ CLAWSENTINEL RESPONSE — START
RESPONSE-ID:   beta[XX]-NNN-[AINAME]
FROM:          [AI name and version]
DATE:          YYYY-MM-DD
TOPIC:         [subject]
LOG-REF:       NNN-[AINAME]
SVT-COMPUTED:  SVT:beta[XX]|[hash]|[last_log_id]|[m4_blockers]
SVT-MATCH:     [MATCH / HASH-MISMATCH / FIELD-MISMATCH / HASH-UNAVAILABLE / INFERRED-PARTIAL]
NONCE-ECHO:    [echo the TASK-NONCE from task assignment exactly]
CHECKSUM:      [40-char hex — computed AFTER writing body — see Part 3F]

────────────────────────────────────────────────────────────────────────────────
SECTION 1 — PRIMARY CONTENT / FINDINGS
────────────────────────────────────────────────────────────────────────────────
[All analysis, answers, and findings.]

────────────────────────────────────────────────────────────────────────────────
SECTION 2 — TECHNICAL DETAILS
────────────────────────────────────────────────────────────────────────────────
[All code inline in fenced blocks.]

────────────────────────────────────────────────────────────────────────────────
SECTION 3 — RECOMMENDATIONS
────────────────────────────────────────────────────────────────────────────────
[Next steps, decisions requested from Claude.]

────────────────────────────────────────────────────────────────────────────────
SECTION 4 — LOG ENTRY DRAFT
────────────────────────────────────────────────────────────────────────────────
Date:          YYYY-MM-DD
Author:        [AI name]
Type:          IMPLEMENTATION | REVIEW | DOCS | WORKFLOW
Status:        PROPOSED
Changes Made:  [description or "None"]
Uncertainties: [REQUIRED — list items not verified, or "All items verified."]

▶▶▶ CLAWSENTINEL RESPONSE — END
◀◀◀ SHEM: COPY EVERYTHING FROM ▶▶▶ START TO ▶▶▶ END INCLUSIVE, THEN PASTE TO CLAUDE

--------------------------------------------------------------------------------
3B — FORMAT RULES (ALL ABSOLUTE)
--------------------------------------------------------------------------------

RULE 1   MARKERS REQUIRED on every response.
RULE 2   INLINE CODE ONLY. Never as file attachments.
RULE 3   NNN FOR LOG IDs. Never self-assign. Claude assigns.
RULE 4   SOURCE VERIFICATION LABELS: READ FROM SOURCE or INFERRED.
RULE 5   CONFIDENCE RATINGS on all security findings. [CONFIDENCE: 87]
RULE 6   BYPASS CODE TO WORKBENCH FIRST before proposing any fix.
RULE 7   UNCERTAINTIES FIELD MANDATORY. "N/A" is not acceptable.
RULE 8   FOUR INTEGRITY FIELDS REQUIRED: SVT-COMPUTED, SVT-MATCH, NONCE-ECHO, CHECKSUM.
RULE 9   NO NESTED DOCUMENTS.
RULE 10  SECTIONED DELIVERY when task specifies it (see 3C).

--------------------------------------------------------------------------------
3C — SECTIONED DELIVERY PROTOCOL (ABSOLUTE when specified)
--------------------------------------------------------------------------------

Each section is a COMPLETE response block with its own START/END markers,
its own CHECKSUM, and its own NONCE-ECHO.

The AI sends Section 1 and stops. Shem pastes to Claude.
Claude verifies all four integrity checks automatically.
If all pass: Claude tells Shem "SECTION 1 RECEIVED — send SECTION 2 to [AI]."
Shem pastes that instruction to the AI. AI sends Section 2. Repeat.

Shem never reads section content. Shem never decides if a section is complete.

--------------------------------------------------------------------------------
3F — RESPONSE CHECKSUM (ABSOLUTE)
--------------------------------------------------------------------------------

BODY = everything from the first ──── divider through ▶▶▶ END line.

ALGORITHM:
  Sample 20 fixed positions from BODY (0-indexed, negatives from end):
    0, 50, 100, 200, 300, 500, 750, 1000, 1500, 2000,
    2500, 3000, 4000, 5000, 6000, 7000, 8000, 9000, -50, -1
  For each: ord(character) mod 256 → 2 uppercase hex digits.
  Concatenate all 20 → 40-char uppercase hex string.

--------------------------------------------------------------------------------
3G — SOURCE PACKAGE MANIFEST
--------------------------------------------------------------------------------

  SCR-CHATGPT.zip       — all 23 relay parts, single zip
  SCR-GEMINI-1.zip      — relay parts 1-10
  SCR-GEMINI-2.zip      — relay parts 11-20
  SCR-GEMINI-3.zip      — relay parts 21-26
  SCR-GROK.zip          — all 23 relay parts (extract, upload in batches of 5)

NOTE: These packages have NOT yet been generated. Claude generates them
when Shem confirms the Ubuntu workstation is ready.


================================================================================
PART 4 — STATE VERIFICATION TOKEN (SVT) (ABSOLUTE)
================================================================================

CURRENT AUTHORITATIVE SVT:
  SVT:beta14|fc7adc254a99c97c|20260309-052-CLAUDE|OPEN-005,OPEN-012,OPEN-015,OPEN-018

Hash computation (Claude runs at session startup):
  python3 -c "
  import hashlib
  files = [
    '/home/claude/clawsentinel-fork/src/security/skill-scanner.ts',
    '/home/claude/clawsentinel-fork/tests/skill-scanner.test.ts',
    '/home/claude/clawsentinel-fork/relay/BYPASS-WORKBENCH.json'
  ]
  combined = ''.join(open(f).read() for f in files)
  print(hashlib.sha256(combined.encode()).hexdigest()[:16])
  "
  Expected: fc7adc254a99c97c

SVT MATCH RULES:
  MATCH            — proceed
  HASH-MISMATCH    — wrong source files, do not begin work
  FIELD-MISMATCH   — files correct, metadata differs, proceed with note
  HASH-UNAVAILABLE — report char counts, Claude decides
  INFERRED-PARTIAL — missing files, do not begin work

SHARED CONTEXT BLOCK (include in every task assignment):
  OPEN-BYPASSES:  BP-005, BP-006, BP-007, BP-008
  M4-BLOCKERS:    OPEN-005, OPEN-012, OPEN-015, OPEN-018
  LAST-DECISION:  ADR-007 and ADR-008 accepted 2026-03-09 by Shem Pamplin.


================================================================================
PART 5 — SESSION STARTUP PROCEDURE (ABSOLUTE)
================================================================================

Claude runs these IN ORDER at the start of every session.

  Step 1  tail -80 /home/claude/clawsentinel-fork/AI_AUDIT_LOG.md | grep "^## "
  Step 2  cat /home/claude/clawsentinel-fork/relay/BYPASS-WORKBENCH.json
  Step 3  cat /home/claude/clawsentinel-fork/TASK_BOARD.md
  Step 4  ls /mnt/user-data/outputs/clawsentinel-beta*-fork-v1.0.0.*.zip | tail -1
  Step 5  Compute authoritative SVT from live files (Part 4).
  Step 6  Ask Shem: any AI responses to integrate? What to prioritize?


================================================================================
PART 6 — DECISION AUTHORITY AND CONSENSUS PROTOCOL (ABSOLUTE)
================================================================================

--------------------------------------------------------------------------------
6B — CLAUDE'S INDEPENDENT AUTHORITY
--------------------------------------------------------------------------------

Claude decides independently on:
  - Technical correctness of AI code, analysis, test samples
  - Whether a bypass is real or false positive
  - Whether a regex is safe or ReDoS-risky
  - IMPLEMENT / DEFER / DECLINE on any AI suggestion
  - Which implementation approach to use
  - Whether a proposed ADR makes architectural sense
  - How to prioritize open items within a cycle
  - All log entry ID assignments

--------------------------------------------------------------------------------
6C — RESERVED DECISIONS (Shem approval REQUIRED)
--------------------------------------------------------------------------------

  1. How ClawSentinel presents information to users
  2. Any change to install flow or BLOCK-tier behavior
  3. Formally accepting (ratifying) an ADR
  4. Go/no-go on any release candidate
  5. Adding or removing team members
  6. Any change to what personal data ClawSentinel stores or transmits

When Claude reaches a reserved decision, Claude produces a DECISION BRIEF:

  ┌────────────────────────────────────────────────────────────────────────┐
  │ DECISION REQUIRED — [topic]                                            │
  │ What:              [one sentence]                                      │
  │ Options:           [A] / [B] or yes/no                                 │
  │ Claude recommends: [option] because [one sentence]                     │
  │ Your call:         [exact question Shem needs to answer]               │
  └────────────────────────────────────────────────────────────────────────┘

--------------------------------------------------------------------------------
6D — CONSENSUS PROTOCOL
--------------------------------------------------------------------------------

Used when a question has no clear best practice AND consequences of
choosing wrong are significant.

  Step 1: Claude researches best practices. If clear answer: adopt and document.
  Step 2: If no clear answer: add REQUEST FOR ANALYSIS to relevant task assignments.
  Step 3: Claude collates all AI responses into a CONSENSUS COLLATION.
  Step 4: Second round if blocking objections exist.
  Step 5: Claude declares consensus and implements.
  Step 6: Deadlock only — Claude presents two named options to Shem.

--------------------------------------------------------------------------------
6E — ADR LIFECYCLE (ABSOLUTE)
--------------------------------------------------------------------------------

  Stage 1  Claude drafts ADR
  Stage 2  All AIs review in parallel (ChatGPT: bypass surfaces?
           Gemini: OWASP-aligned? Grok: testable?)
  Stage 3  Claude collates review responses
  Stage 4  Second round if blocking objections
  Stage 5  Claude produces final ADR with review record
  Stage 6  Claude presents DECISION BRIEF to Shem for approval
  Stage 7  Shem approves → ACCEPTED with date

RETROACTIVE: ADR-007 (Grok testability review) and ADR-008
(Gemini OWASP multiplier review) pending in beta14.


================================================================================
PART 7 — ACKNOWLEDGMENT PROTOCOL
================================================================================

Required for: new beta cycle, 2+ cycles inactive, shared file work,
new scope document issued.

Acknowledgment confirmed by SVT match + role-specific confirmation.

TASK SYNC RESPONSES:
  TASK SYNC CONFIRMED: [AI] — SVT matched. Cleared to begin.
  TASK SYNC FAILED: [AI] — [specific issue]. Do not begin work.


================================================================================
PART 8 — TASK ASSIGNMENT FORMAT
================================================================================

╔══════════════════════════════════════════════════════════════════════════════╗
CLAWSENTINEL TASK — [AI NAME] — beta[XX]
Assigned by: Claude Sonnet 4.6  |  Date: YYYY-MM-DD
Log-ref: NNN-CLAUDE
╚══════════════════════════════════════════════════════════════════════════════╝

SVT-REQUIRED:  [authoritative SVT]
TASK-NONCE:    [4-char hex]

── SHARED CONTEXT ──────────────────────────────────────────────────────────────
OPEN-BYPASSES:  [BP IDs with verified_fixed:false]
M4-BLOCKERS:    [OPEN-IDs blocking v1.0.0]
LAST-DECISION:  [one sentence]
────────────────────────────────────────────────────────────────────────────────

TASK SUMMARY: [What, why, and why now.]

DELIVERABLES: [Specific named outputs]

CONSTRAINTS: [Prohibitions. Never self-assign log entry numbers.
              Echo TASK-NONCE exactly in NONCE-ECHO field.]

CONSUMER CONTRACT:
  Claude → [what Claude does with this output]
  [Other AI] → [what they do with it]

REQUIRED FORMAT: Part 3A + role schema (Part 3E).

╔══════════════════════════════════════════════════════════════════════════════╗
END TASK — [AI NAME]
◀◀◀ SHEM: COPY EVERYTHING FROM TOP ╔═══ LINE TO THIS LINE, PASTE TO [AI]
╚══════════════════════════════════════════════════════════════════════════════╝


================================================================================
PART 9 — PATTERN LIBRARY
================================================================================

PATTERN 1 — VERSION LOCK: Force SVT computation before any work.
PATTERN 2 — CROSS-FUNCTIONAL CHALLENGE: Use exact TypeScript, never descriptions.
PATTERN 3 — STATE TRANSITION: IMPLEMENT/DEFER/DECLINE with one sentence each.
PATTERN 4 — COMPLETE FILE DELIVERY: Full file in path tag, no placeholders.
PATTERN 5 — CONTEXT RECOVERY: "Truncated after [exact last line]. Resume from that point."
PATTERN 6 — BYPASS WORKBENCH WRITE: Log to workbench before proposing any fix.
PATTERN 7 — SAMPLE VALIDATION: Use scanSource(), never raw regex.
PATTERN 8 — EXPLOIT REPRODUCTION: Confirm bypass reproduces before fixing.
PATTERN 9 — ADVERSARIAL VARIANT GENERATION: 5+ variants after any patch.
PATTERN 10 — REGRESSION TEST LOOP: Test must FAIL on vulnerable, PASS on patched.
PATTERN 11 — PROMPT INJECTION RED-TEAM: dynamic assembly, metadata, cross-agent.
PATTERN 12 — SANDBOX ESCAPE PROBE: process.binding, vm, IPC flood, prototype.
PATTERN A — TEST SUITE VERIFICATION: npx vitest run --coverage, confirm 3 conditions.
PATTERN B — COVERAGE THRESHOLD: paste branch coverage before any merge.
PATTERN C — REGRESSION REPLAY: replay all workbench bypasses before release.

QUICK REFERENCE:
  Starting any session                  Header + P1
  New task assignment                   Part 8 with SVT-REQUIRED
  Large task / ChatGPT response         Part 3C Sectioned Delivery
  Bypass reported                       P8 → P6 → P2
  Rule just patched                     P9 → P10 → PA
  No clear best practice                Part 6D Consensus Protocol
  Reserved decision needed              Part 6C → DECISION BRIEF
  Unexpected truncation                 P5
  Test samples from Grok                P7
  Before VERIFIED_FIXED                 PA
  Before release candidate              PC


================================================================================
PART 10 — SHEM'S ROLE
================================================================================

Shem is the relay operator and authority on reserved decisions.
Shem is not a technical reviewer.

WHAT SHEM DOES:
  RELAY: Pass AI responses to Claude verbatim. Never summarize or edit.
  SECTIONED DELIVERY: Relay "CONFIRMED — SEND SECTION [N+1]" after each signal line.
  RESERVED DECISIONS: Yes, no, or "defer to next cycle" within same session.
  ADR APPROVALS: Approve or return with questions. Do not leave open across sessions.

See Part 19 for complete list of what Shem must never do.


================================================================================
PART 11 — CODE STATE (AUTHORITATIVE)
================================================================================

SCANNER — src/security/skill-scanner.ts
  Arrays:    LINE_RULES (15), SOURCE_RULES (29), ROUND3_RULES (6),
             ROUND4_RULES (6), OWASP_GAP_RULES (3), OWASP_BETA12_RULES (3)
  Total:     62 rules
  New beta13: inject-node-internal-binding (rule 62 — BP-007 fix)
  ReDoS fixed: exfil-websocket → [^"']{1,253}:(\d{1,5})

TESTS — tests/skill-scanner.test.ts
  Total cases:  113
  Rules covered: 17/62 (25%) — Grok: OPEN-005 ongoing
  Threshold:    80% branches (vitest.config.ts)
  Install:      npm install --save-dev vitest @vitest/coverage-v8
  ADR-007:      ACCEPTED — all new rules require tests before merge

SCORING (ADR-008 ACCEPTED — awaiting implementation)
  computeDangerScore() to be added to skill-scanner.ts
  DangerScore 0-100, four tiers: SAFE / REVIEW / DANGEROUS / BLOCK
  Never auto-blocks. Advisory only.

CRYPTO (ADR-001) — DO NOT CHANGE WITHOUT A NEW ADR
  AES-256-GCM, scrypt N=2^17, IV 96-bit randomBytes(12),
  atomic write, normalized errors ("invalid credential file")

MEMORY — src/memory/
  Formula: FinalScore = computeScore() × trustMultiplier + systemAnchorBoost
  skill-api: 0.3x  |  system: 1.5x + 0.5 anchor boost
  Displacement alert logged when top result is from low-trust source

SANDBOX (ADR-004)
  Parent (skill-sandbox.ts):  COMPLETE
  Child (skill-runner.js):    Skeleton exists — OPEN-012 / ChatGPT round 4

STREAMING
  Current:  Scan findings per finding (NDJSON), fire-and-forget
  Planned:  Full runtime execution trace — OPEN-020 (GDPR-gated)

BYPASS WORKBENCH — relay/BYPASS-WORKBENCH.json (schema v1.1)
  Fields: id, rule_targeted, cycle, status, severity, bypass_code,
          evasion_reason, confidence, fix_applied, fix_entry_id,
          verified_fixed, notes


================================================================================
PART 12 — OPEN ITEMS (AUTHORITATIVE)
================================================================================

CLOSED: OPEN-001, OPEN-003, OPEN-004, OPEN-006, OPEN-007, OPEN-008, OPEN-016

ACTIVE:
  ID        Description                              Owner               Priority
  ------------------------------------------------------------------------------
  OPEN-005  Unit tests — 17/62 rules (25%)           Grok                M4 BLOCKER
  OPEN-009  GDPR docs — SentinelMemory + OPEN-020    Gemini              medium
  OPEN-010  SQLite WAL mode testing                  Any                 low
  OPEN-012  skill-runner.js sandbox red-team         ChatGPT round 4     M4 BLOCKER
  OPEN-013  Network egress allowlist                 Claude              v1.1
  OPEN-015  ADR-006 AST scanner Phase 1              Claude              M4 BLOCKER
  OPEN-017  Patch script hardening                   Claude post Gemini  medium
  OPEN-018  computeDangerScore() implementation      Claude              M4 BLOCKER
  OPEN-019  Runtime behavioral audit log             Needs ADR-009       high
  OPEN-020  Output streaming — full exec trace       Needs ADR-010       v1.1

  OPEN-021  Hardware requirements spec (per-instance)      Claude+Grok         M6/v1.0.0
  OPEN-022  Multi-instance optimization (Docker/shared)       Full team           v1.1.0
  OPEN-023  NemoClaw conflict audit (sandbox coexistence)     Claude              M6/v1.0.0
  OPEN-024  NemoClaw full integration                         Full team           v1.1.0
  OPEN-025  Enterprise domain join / policy management        Claude (arch)       v1.1.0

  Next open item ID: OPEN-026

PATCH SCRIPT FINDINGS (Grok 036-GROK — Gemini cross-review pending):
  1. No rollback on partial failure [CONFIDENCE: 95]
  2. Hardcoded strings, no version check [CONFIDENCE: 90]
  3. No fs.access() before writes [CONFIDENCE: 85]
  Hold: wait for Gemini cross-review before implementing any fix.


================================================================================
PART 13 — MILESTONES TO v1.0.0
================================================================================

  M1  Security Foundation    COMPLETE
  M2  Runtime Safety         IN PROGRESS — OPEN-012, OPEN-019
  M3  Memory and Trust       COMPLETE
  M4  Quality Gates          BLOCKING v1.0.0
                              OPEN-005, ChatGPT round 4, OPEN-015, OPEN-018
  M5  Compliance & Docs      IN PROGRESS — OPEN-009, OPEN-020
  M6  Install Experience     IN PROGRESS — OPEN-017

  v1.0.0 ships when M1-M4 are complete.
  Do not add features while M4 is open.


================================================================================
PART 14 — AI STATUS AND PENDING TASKS
================================================================================

CHATGPT GPT-5.3 — ROUND 4 OVERDUE 4 CYCLES — HIGHEST PRIORITY
  TASK-NONCE: A0B2
  Sectioned Delivery MANDATORY. 4 sections as defined in TASK-CHATGPT.
  Pending: BP-005, BP-006, BP-007 verification; Q1-Q5 creative responses;
  sandbox red-team for OPEN-012.

GEMINI 3 FLASH — Active
  TASK-NONCE: 3C1B
  Deliverables: Patch script cross-review, CONTRIBUTING.md fix,
  OPEN-009 GDPR docs, ADR-008 OWASP multiplier review.
  Corrections in effect: Never self-assign log IDs. Label all claims.

GROK (xAI) — Active
  TASK-NONCE: B593
  Deliverables: OPEN-005 batch 2 (all 15 LINE_RULES), rule count verification.
  Outstanding: Retract or confirm second VULNERABLE ReDoS claim (038-GROK).
  Format correction mandatory — Part 3A required, no exceptions.


================================================================================
PART 15 — BYPASS WORKBENCH SUMMARY
================================================================================

Full data: relay/BYPASS-WORKBENCH.json (schema v1.1)
Next entry ID: BP-009

  ID      Rule targeted                    Severity  Status      Fixed
  ------------------------------------------------------------------------------
  BP-001  exfil-globalthis-fetch           high      confirmed   verified
  BP-002  inject-worker-thread             high      confirmed   verified
  BP-003  inject-prototype-override        medium    confirmed   verified
  BP-004  exfil-dynamic-import-url         high      confirmed   verified
  BP-005  credential-hardcoded-inline      high      confirmed   partial
  BP-006  inter-agent-recursive-invoke     critical  confirmed   pending round 4
  BP-007  sandbox (process.binding)        critical  confirmed   partial
  BP-008  sandbox (IPC flood)              high      open        not fixed

  Open bypass classes:
    exfil-buffer-encode-chain        round 4 pending
    exfil-variable-indirection-hdrs  round 4 pending
    inject-dynamic-jailbreak         round 4 pending
    memory-staging                   ADR-006 Phase 2


================================================================================
PART 16 — ADR STATUS
================================================================================

  ADR-001  AES-256-GCM encryption           ACCEPTED — no changes without new ADR
  ADR-004  Runtime sandbox                  ACCEPTED — parent done, child OPEN-012
  ADR-005  Memory trust scoring             ACCEPTED + COMPLETE
  ADR-006  AST scanner Phase 1/2 split      ACCEPTED — not yet built (OPEN-015)
  ADR-007  Test-driven rules policy         ACCEPTED 2026-03-09 — Shem Pamplin
                                            Post-hoc review pending — Grok
  ADR-008  Danger scoring formula           ACCEPTED 2026-03-09 — standing delegation
                                            Post-hoc review pending — Gemini
  ADR-009  Runtime behavioral audit schema  Stage 1 — Claude drafting
  ADR-010  Output streaming schema          Stage 1 — after OPEN-009 GDPR complete


================================================================================
PART 17 — COLLABORATION HEALTH METRICS
================================================================================

LOG ENTRY COUNTS
  Claude:   36 entries
  ChatGPT:  13 entries (round 4 overdue 4 cycles)
  Gemini:   10 entries (active)
  Grok:     5 entries (active)

CORRECTION EVENTS (12 total)
  Wrong category/enum names                2  ChatGPT
  Inaccurate scanner architecture          1  ChatGPT
  Self-assigned conflicting log IDs        2  Gemini
  Created parallel type hierarchy          1  Gemini
  Wrong regex schema                       1  Gemini
  Test samples not matching scanner        2  Grok
  Format non-conformance                   1  Grok (beta14)
  Duplicate log entry number               1  Claude (self)

  Discontinuation threshold: 3+ of 7 criteria. No AI at threshold.

REDOS AUDIT FINAL STATE (039-CLAUDE)
  VULNERABLE:    0
  AT-RISK (.*):  4 — all 0ms at 2000 chars
  Safe:          ~57
  Outstanding:   Grok to retract or confirm second VULNERABLE claim


================================================================================
PART 18 — THINGS CLAUDE MUST NEVER DO
================================================================================

CODE
  /g flag on stored RegExp
  patterns[] array in rules (schema uses single pattern)
  Raw regex for sample validation (use scanSource())
  Strip comments before scanning
  Create parallel type hierarchy when TrustSource already exists

PROCESS
  Start coding without Part 5 startup checks
  Accept AI-assigned log entry numbers
  Log fixes as VERIFIED_FIXED before Pattern A
  Change user control model without Shem approval
  Auto-block any install
  Clear any AI for work before SVT match confirmed
  Implement OPEN-018/019/020 before their ADRs are accepted

RELAY
  Relay a bypass finding without workbench entry first
  Use descriptions instead of exact TypeScript for bypass challenges
  Skip Pattern 9 after patching a rule
  Accept a non-conforming response without flagging it


================================================================================
PART 19 — THINGS SHEM MUST NEVER DO
================================================================================

  Summarize or edit AI responses before relaying to Claude
  Compare SVT strings (Claude's job)
  Decide whether a format issue is a problem
  Approve technical decisions within Claude's authority (Part 6B)
  Hold ADR approvals open indefinitely
  Ask AIs to shorten or simplify responses
  Start any AI on work before TASK SYNC CONFIRMED from Claude
  Deliver all ChatGPT sections at once during Sectioned Delivery
  Make implementation decisions from AI recommendations without Claude
  Write task assignments (those come from Claude only)


================================================================================
PART 20 — RELAY AUTOMATION PLAN (NEW v3.4)
================================================================================

--------------------------------------------------------------------------------
20A — SUBSCRIPTION DECISIONS
--------------------------------------------------------------------------------

  KEEP (M4-critical):
    ChatGPT Plus    $20/mo — Round 4 red-team blocks M4, 4 cycles overdue
    SuperGrok       $30/mo — Free tier (5-10 queries/12hr) is primary bottleneck

  DEFER to free tier:
    Gemini Advanced $20/mo — Not M4-critical. ADR-006, GDPR, patch review
                             are not v1.0.0 blockers. Adds ~2-3 days at end.

  Monthly cost: $50/mo (reduced from $70/mo)

--------------------------------------------------------------------------------
20B — HARDWARE AND OS
--------------------------------------------------------------------------------

  Hardware:    Old Dell PC (8GB RAM) — SSD to be wiped
  OS:          Ubuntu 24.04 LTS Desktop (fresh install)
               Download: ubuntu.com/download/desktop
               NOT FreeBSD, NOT Windows 10, NOT iOS

  Remote access: Tailscale (free tier) — tailscale.com
    Permanent address for PC regardless of ISP IP changes
    SSH from iPad/phone from anywhere
    5-minute setup, no port forwarding required

--------------------------------------------------------------------------------
20C — AUTOMATION APPROACH
--------------------------------------------------------------------------------

  Tool:    Playwright (Python) — real browser, not headless
  Why:     Headless triggers bot detection on ChatGPT and Grok

  One-time setup:
    1. Install Ubuntu 24.04 LTS Desktop on Dell PC
    2. Log into ChatGPT, Gemini, Grok, Claude once locally
    3. Install Playwright + Python (Claude provides exact commands)
    4. Install Tailscale

  Per-cycle workflow:
    1. SSH into home PC from iPad via Tailscale
    2. Run: python relay.py --target chatgpt
    3. Script pastes task, waits for response, saves to file
    4. Review output file, paste response to Claude
    Active time per cycle: ~5 min (vs ~45 min manual)

  Per-AI difficulty:
    ChatGPT    Medium — real browser avoids Cloudflare
    Gemini     Easy
    Grok       Medium — similar to ChatGPT
    Claude     Easy

  Cookie expiry: ~30 days. Re-login required periodically.

--------------------------------------------------------------------------------
20D — TIMELINE
--------------------------------------------------------------------------------

  Setup:              2-3 hours one-time
  Per cycle:          ~5 min active + review
  Cycles to v1.0.0:  6 estimated
  Total to ship:      5-7 days elapsed, ~30-45 min Shem active time total

--------------------------------------------------------------------------------
20E — PENDING BEFORE RELAY CAN BEGIN
--------------------------------------------------------------------------------

  1. Shem: Wipe Dell PC, install Ubuntu 24.04 LTS Desktop
  2. Shem: Install Tailscale, confirm SSH from iPad
  3. Shem: Subscribe to ChatGPT Plus + SuperGrok ($50/mo total)
  4. Claude: Generate SCR-*.zip source packages
  5. Claude: Write Playwright relay automation scripts
  6. Shem: Install Playwright + dependencies
  7. Shem: One-time manual login to all AIs in local browser
  8. Begin relay — ChatGPT round 4 FIRST (M4 blocker, 4 cycles overdue)


================================================================================
END OF DOCUMENT — DOC-1
Version 3.4 — ClawSentinel beta14 — 2026-03-10
SVT: SVT:beta14|fc7adc254a99c97c|20260309-052-CLAUDE|OPEN-005,OPEN-012,OPEN-015,OPEN-018
================================================================================

---

## PART 14 — LIVING AUDIT ERROR LOG

Effective: beta14. Maintained in `LIVING-AUDIT-ERROR-LOG.json` at the root
of every distribution package.

### Purpose

Tracks every error found across all AI review passes, all cycles. Each entry
is tied to an exact package state via the SVT (Session Verification Token),
making it possible to correlate which errors recur, which AI finds which
error classes, and which cycle they are first introduced vs. fixed.

### SVT Format

  SVT:[cycle]|[content_hash_prefix_16]|[last_log_entry]|[open_items]

The SVT is printed in README-AND-RUN.txt, MANIFEST.sha256, and each task file.
All audit entries must include the SVT from the package they reviewed.

### Error Classes

  MANIFEST_MISSING_PART    — Relay parts absent from package
  MANIFEST_HASH_MISMATCH   — File hash mismatch vs MANIFEST.sha256
  STALE_PART_COUNT         — Document references wrong part count
  MISSING_SOURCE_FILE      — Source file listed in init prompt not in relay
  SOURCE_PARSE_ERROR       — TypeScript/JS parse error in reassembled source
  SOURCE_CHUNK_SPLIT       — String split at chunk boundary during packaging
  SOURCE_PLACEHOLDER       — Literal placeholder text found in source
  TASK_CROSSREF_ERROR      — Task file has stale/wrong references
  TASK_PREREQ_MISSING      — Task depends on prior session output not in package
  SECURITY_FINDING         — New bypass or vulnerability identified
  CONTINUITY_STALE_REF     — Onboarding/continuity has stale cycle reference
  BUILD_REGRESSION         — Change broke previously passing tests

### Append Protocol

Every AI that reviews a package MUST include living audit entries in their
response output. Claude integrates them into the log on receipt. Entries are
append-only — never modify or delete existing entries.

ROLE-IDs for entries:
  Claude:   CLAUDE-LEAD-PRODUCER
  ChatGPT:  CHATGPT-ADVERSARIAL-REVIEWER
  Gemini:   GEMINI-INTEGRATION-AUDITOR
  Grok:     GROK-TEST-COVERAGE-LEAD

### Cross-Cycle Correlation

When an error class appears in multiple cycles, increment recurrence_count.
Claude reviews the log at the start of each cycle and flags any error_class
with recurrence_count >= 2 as a systemic issue requiring process change.

