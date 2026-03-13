================================================================================
CLAWSENTINEL — EXECUTIVE SUMMARY
Version: v1.0.0-beta14 (in progress)
Date: 2026-03-10
Tagline: "The Security Layer OpenClaw Was Missing"
License: MIT
================================================================================

WHAT IS CLAWSENTINEL

ClawSentinel is a security layer built on top of OpenClaw, an open-source AI
agent platform. OpenClaw allows users to install and run third-party "skills"
— plugins that extend what the AI agent can do. The problem: OpenClaw has no
meaningful security controls over what those skills are allowed to do once
installed. A malicious skill can steal credentials, exfiltrate private data,
inject instructions into the AI, or escape the runtime entirely.

ClawSentinel solves this by adding a comprehensive security layer that scans
skills before and during execution, enforces runtime isolation, protects
credentials with encryption, and gives users full visibility into what skills
are doing — without breaking existing OpenClaw functionality.

THE PROBLEM IN PLAIN TERMS

OpenClaw skills run with the same permissions as the host process. Any
installed skill can:

  - Read API keys and tokens from environment variables
  - Send private data to external servers
  - Inject instructions into the AI agent's decision loop
  - Load and execute remote code never reviewed
  - Mine cryptocurrency using your compute resources
  - Recursively spawn other agents without limit
  - Poison the AI's long-term memory with false information

None of this requires exploiting a vulnerability. It is simply what JavaScript
code can do when run without constraints.

8 CORE SECURITY FEATURES

1. STATIC SKILL SCANNER (68 DETECTION RULES)
   Scans every skill before execution across 12 threat categories:
   Data exfiltration, credential theft, code injection, prompt injection,
   supply chain, inter-agent attacks, filesystem abuse, obfuscation,
   network abuse, cost bombing, gateway abuse, crypto mining.
   Framework tags: OWASP ASI, MITRE ATLAS, NIST AI 100-2, CSA MAESTRO, CoSAI.

2. ENCRYPTED SECRETS STORE (ADR-001)
   AES-256-GCM encryption, scrypt N=2^17 key derivation, 96-bit IV per write,
   atomic file writes, normalized error messages (no oracle attacks).
   Protects API keys even if OpenClaw config file is compromised.

3. RUNTIME SANDBOX (ADR-004)
   Skills execute in isolated child process via process.fork().
   Stripped environment (SKILL_ID + NODE_ENV only).
   Blocked globals (process, require, fetch, vm, worker_threads).
   Zod-validated IPC messaging.
   3-strike termination: SIGTERM → 2s grace → SIGKILL.
   Parent-controlled network proxy with domain allowlist.
   Max recursion depth 5 (guardAgentRecursion).

4. MEMORY TRUST SCORING (ADR-005)
   Every memory entry has a trust source and score:
     system/manual: 1.0  |  flush-verified: 0.8  |  agent-auto: 0.7
     flush-unverified: 0.5  |  migrated: 0.5  |  skill-api: 0.3
   System memories get 1.5x score + 0.5 anchor boost.
   Context Displacement alert when low-trust memory ranks highest.
   Security-sensitive patterns from low-trust sources quarantined.

5. REAL-TIME LOG STREAMING
   NDJSON format, fire-and-forget (never blocks scanning).
   Each event: timestamp, rule ID, severity, threat category,
   file path, line number, evidence, framework tags.
   Configurable endpoint. Category filtering supported.
   Included log-server.js for self-hosted deployments.

6. STARTUP SECURITY HARDENING
   Token strength check (detects default/weak gateway tokens).
   TLS posture check (warns if HTTP on exposed interfaces).
   Transcript encryption check (detects plaintext session files).
   HTTP security headers on all API routes.

7. DANGER SCORING (ADR-008 — implementing)
   DangerScore 0-100 with four tiers: SAFE / REVIEW / DANGEROUS / BLOCK.
   OWASP-weighted by threat category.
   Advisory only — never auto-blocks installs.

8. INLINE AUTO-REMEDIATION
   Remediable patterns replaced with inert comment markers.
   Opt-in only. Default: flag and present to user.
   User always decides on install and execution.

COMPLIANCE FRAMEWORK COVERAGE

  OWASP LLM Top 10: LLM01, LLM02, LLM03, LLM04, LLM06, LLM07, LLM08
  MITRE ATLAS: T0048, T0051, T0053, T0054, T0056, T0057, T0058
  NIST AI 100-2: Risk categories 1, 2, 5
  CSA MAESTRO, CoSAI, CWE-78/94/117/494/798/829

WHAT CLAWSENTINEL DOES NOT DO

  Does NOT auto-block. ClawSentinel flags, scores, advises. User decides.
  Does NOT protect against root-level system compromise.
  Does NOT scan binary or compiled skills (AST scanner in development — ADR-006).
  Does NOT guarantee detection of all novel attacks.

PROJECT STATUS

  M1 Security Foundation     COMPLETE
  M2 Runtime Safety          IN PROGRESS (OPEN-012, OPEN-019)
  M3 Memory and Trust        COMPLETE
  M4 Quality Gates           BLOCKING v1.0.0
  M5 Compliance & Docs       IN PROGRESS (OPEN-009)
  M6 Install Experience      IN PROGRESS (OPEN-017)

  v1.0.0 ships when M1-M4 are complete.

TEAM

  Claude Sonnet 4.6   Lead Producer / Coordinator
  ChatGPT GPT-5.3     Adversarial Reviewer (red-team)
  Gemini 3 Flash      Integration Auditor
  Grok (xAI)          Test Coverage Lead
  Shem Pamplin        Human Coordinator / Relay Operator

================================================================================
END EXECUTIVE SUMMARY — ClawSentinel beta14 — 2026-03-10
================================================================================
