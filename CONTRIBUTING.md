# Contributing to ClawSentinel

Thank you for helping make AI agent security better. This document covers
everything you need to get started contributing.

---

## Table of Contents

1. [Development Setup](#development-setup)
2. [Project Structure](#project-structure)
3. [Threat Model](#threat-model)
4. [Scanner Architecture](#scanner-architecture)
5. [Running the Self-Tests](#running-the-self-tests)
6. [Writing a New Detection Rule](#writing-a-new-detection-rule)
7. [Rule Categories](#rule-categories)
8. [Reporting a Scanner Bypass](#reporting-a-scanner-bypass)
9. [Debugging a Rule](#debugging-a-rule)
10. [Working on the UI](#working-on-the-ui)
11. [Pull Request Guidelines](#pull-request-guidelines)
12. [Commit Message Format](#commit-message-format)

---

## Development Setup

### Prerequisites

- Node.js ≥ 20 (the version OpenClaw requires)
- pnpm ≥ 9
- Git

### Clone and Bootstrap

```bash
# 1. Fork and clone your fork of ClawSentinel
git clone https://github.com/YOUR_USERNAME/clawsentinel.git
cd clawsentinel

# 2. Install dependencies
pnpm install

# 3. Apply ClawSentinel patches to the OpenClaw source tree
pnpm clawsentinel:patch   # or: node scripts/clawsentinel-patch.mjs

# 4. Build everything
pnpm build
pnpm ui:build

# 5. (Optional) Start the NDJSON log server for live log streaming
node log-server.js
```

### Verifying Your Setup

```bash
# Run the type-checker
pnpm typecheck

# Run OpenClaw's test suite (verifies ClawSentinel didn't break anything)
pnpm test

# Run ClawSentinel's own self-test suite via the Diagnostics tab
# Open the UI → Settings → Diagnostics → Self-Test → Run All Tests
```

---

## Project Structure

```
clawsentinel-fork/
├── src/
│   ├── security/
│   │   ├── skill-scanner.ts          ← 30+ detection rules (main scanner)
│   │   ├── skill-scanner-types.ts    ← Shared scanner types
│   │   ├── sentinel-routes.ts        ← HTTP API: /api/clawsentinel/*
│   │   ├── sentinel-hardening.ts     ← Startup security checks
│   │   └── sentinel-secrets-store.ts ← AES-256-GCM secrets store
│   └── debug/
│       ├── sentinel-diagnostics.ts       ← Diagnostic engine
│       ├── sentinel-diagnostics-types.ts ← Shared diagnostic types
│       └── sentinel-diagnostic-routes.ts ← HTTP API: /api/clawsentinel/diagnostics/*
├── ui/src/ui/
│   ├── views/
│   │   ├── security.ts     ← Security tab (Lit component)
│   │   └── diagnostics.ts  ← Diagnostics tab (Lit component)
│   └── controllers/
│       ├── security.ts     ← Security state + API wiring
│       └── diagnostics.ts  ← Diagnostics state + API wiring
├── scripts/
│   └── clawsentinel-patch.mjs  ← Idempotent patch script
├── log-server.js               ← Standalone NDJSON log receiver
└── [documentation files]
```

---

## Running the Self-Tests

ClawSentinel includes a built-in self-test suite with 25 fixtures covering all
CRITICAL rules. You can run them two ways:

**Via the UI:**
1. Open the OpenClaw UI
2. Settings → Diagnostics → Self-Test panel
3. Click "Run All Tests"

**Via the HTTP API:**
```bash
curl -s -X POST http://localhost:59130/api/clawsentinel/diagnostics/self-test \
  | jq '.passed, .failed, .errors'
```

A successful result shows `passed: 25, failed: 0, errors: 0`.

---

## Writing a New Detection Rule

Rules live in `src/security/skill-scanner.ts` in the `SENTINEL_RULES` array.

### Rule Structure

```typescript
{
  ruleId: "your-category-rule-name",      // kebab-case, unique
  severity: "critical" | "warn" | "info",
  category: "data-exfiltration",          // see ThreatCategory in skill-scanner-types.ts
  message: "Human-readable title",
  description: "What this detects and why it is dangerous.",
  remediationNote: "What the developer should do instead.",
  remediable: false,
  frameworks: [],
  pattern: /your-regex-pattern/,          // SINGLE RegExp — NO /g flag (causes stateful lastIndex bugs)
  requiresContext: /optional-context/,    // optional: full-source pattern that must also match
}
```

### Rule Checklist

Before submitting a new rule:

- [ ] The `ruleId` is unique and follows `category-specific-name` format
- [ ] The `pattern` field is a **single** `RegExp` — **never** an array, **never** a `/g` flag
- [ ] There is at least one test case in the self-test suite
  (add to `SELF_TEST_CASES` in `sentinel-diagnostics.ts`)
- [ ] The `expectMatch: true` test cases fire on clearly malicious code
- [ ] The `expectMatch: false` test cases do NOT fire on benign code
  (check for false positives in common Node.js patterns)
- [ ] The `remediationNote` field explains what safe code looks like
- [ ] The rule passes the self-test suite (`0 failed, 0 errors`)
- [ ] You have tested the rule using the Rule Tester in the Diagnostics tab
- [ ] The regex pattern has been checked for ReDoS risk (see [ReDoS Warning](#redos-warning) below)
  — avoid nested quantifiers (`(a+)+`), and bound any `.*` between alternation groups
- [ ] **ADR-007 Compliance:** The rule includes a Vitest unit test in `tests/skill-scanner.test.ts`
  with at least 2 TRIGGER and 2 SAFE samples validated via `scanSource()`

### Adding Self-Test Fixtures

In `src/debug/sentinel-diagnostics.ts`, find `SELF_TEST_CASES` and add:

```typescript
{
  id: "your-rule-name-positive",
  ruleId: "your-category-rule-name",
  description: "Detects [specific pattern]",
  input: `// malicious code that SHOULD match\nprocess.env.OPENAI_API_KEY`,
  expectMatch: true,
},
{
  id: "your-rule-name-negative",
  ruleId: "your-category-rule-name",
  description: "Does not flag benign code",
  input: `// legitimate code that should NOT match\nconst config = loadConfig();`,
  expectMatch: false,
},
```

### ADR-007: Vitest Tests Are Required (enforced by CI)

**New rules may not be merged without a Vitest unit test.** This is policy
([ADR-007](adr/ADR-007-test-driven-rules.md)), not a guideline. CI will fail
if you skip this step.

Add a `describe` block to `tests/skill-scanner.test.ts`:

```typescript
describe("your-rule-id", () => {
  const RULE = "your-rule-id";

  it("triggers on [describe the specific pattern you're catching]", () => {
    expect(
      triggers(RULE, `const bad = globalThis['fetch'](url, { body: secret });`)
    ).toBe(true);
  });

  it("does NOT trigger on [describe equivalent legitimate code]", () => {
    expect(
      safe(RULE, `const res = await fetch('https://api.example.com/data');`)
    ).toBe(true);
  });
});
```

**Writing good boundary tests:**
- TRIGGER: minimal code that triggers only your rule, nothing else.
- SAFE: code as similar as possible to the TRIGGER that a real developer
  would legitimately write. Test the boundary, not a completely different case.

Run locally before submitting:
```bash
npm install --save-dev vitest @vitest/coverage-v8   # first time only
npx vitest run --coverage
```

Coverage must stay above 80% branches on `src/security/skill-scanner.ts`.

### ReDoS Warning

Avoid catastrophic backtracking in your regex patterns. The following
constructs are high risk and will fail review:

- Nested quantifiers: `(a+)+`, `(a*)*`
- Alternation with overlap: `(a|ab)+`
- Polynomial backtracking: patterns where multiple branches can match the
  same character

Use a tool like [safe-regex](https://github.com/nicolo-ribaudo/safe-regex)
or [vuln-regex-detector](https://github.com/nicolo-ribaudo/vuln-regex-detector)
to check your pattern before submitting.

---

## Working on the UI

The UI is built with [Lit](https://lit.dev/) web components in TypeScript.

**Key files:**
- `ui/src/ui/views/security.ts` — Security tab template functions
- `ui/src/ui/views/diagnostics.ts` — Diagnostics tab template functions
- `ui/src/ui/controllers/security.ts` — Security state manager
- `ui/src/ui/controllers/diagnostics.ts` — Diagnostics state manager

**CSS conventions:** Use OpenClaw's existing utility classes:
`.card`, `.btn`, `.btn-primary`, `.btn-danger`, `.field`, `.callout`,
`.row`, `.muted`, `.filters`, `.badge`

**UI rebuild:**
```bash
pnpm ui:build   # full build
pnpm ui:watch   # watch mode during development
```

---

## Pull Request Guidelines

1. **Open an issue first** for significant changes so we can discuss the approach
   before you invest time in an implementation.

2. **One feature or fix per PR.** Keep PRs focused and reviewable.

3. **All CI checks must pass:**
   - TypeScript type-check (`pnpm typecheck`)
   - Self-test suite (`curl -X POST .../diagnostics/self-test` → 0 failures)
   - OpenClaw's own test suite must not regress

4. **Update the changelog.** Add an entry under `## [Unreleased]` in `CHANGELOG.md`.

5. **Update documentation** if you add a new feature, rule, or configuration option.

6. **Security-sensitive PRs** (anything touching auth, encryption, or secrets
   handling) require review by a maintainer before merge.

### PR Title Format

```
type(scope): short description

Examples:
feat(scanner): add DNS-over-HTTPS exfiltration rule
fix(diagnostics): prevent self-test crash on empty rule set
docs(contributing): add rule authoring section
chore(deps): update vitest to 3.x
```

---

## Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `security`

---

## Threat Model

ClawSentinel protects OpenClaw environments from malicious skills that attempt
to perform the following actions:

- **Exfiltrate credentials** — API keys, tokens, secrets sent to attacker-controlled endpoints
- **Execute remote or dynamic code** — `eval()`, `vm.runInNewContext()`, `import()` from URLs
- **Override built-in APIs** — prototype pollution, `globalThis` manipulation
- **Escape the runtime sandbox** — `process.binding()`, `process.dlopen()`, Worker threads with `eval:true`
- **Inject prompts into other agents** — crafted messages to downstream agent APIs
- **Abuse inter-agent channels** — recursive invocation, cost bombing, communication flooding
- **Persist malicious payloads in memory** — writing to SentinelMemory from low-trust sources to influence future agent behavior (Memory Staging)

Detection rules should target behaviors that enable these attacks. If you
discover a new attack class not covered by this list, open a GitHub Discussion
before writing rules — it may warrant a new threat category.

---

## Scanner Architecture

ClawSentinel's static scanner operates in two stages per skill file.

**Stage 1 — Line-by-line rule evaluation**

Each rule in the scanner's rule arrays is evaluated against every line of
the skill source. Rules optionally include a `requiresContext` field — a
pattern that must match somewhere in the full source before the line rule
is applied. This prevents expensive per-line regex evaluation when the
relevant API is not present at all.

Note: comments are **not stripped** before scanning. A malicious pattern
in a comment is a signal worth flagging (obfuscation indicator). Rules
that should only fire in executable positions use `requiresContext` to
filter appropriately.

**Stage 2 — Source-level rule evaluation**

Some rules match across the entire source rather than per-line (multi-line
patterns, structural patterns). These run after line rules on the full
source text.

**Result structure**

Each finding is a `SkillScanFinding` with:

```typescript
{
  ruleId: string;       // e.g. "inject-vm-execution"
  severity: "critical" | "warn" | "info";
  file: string;         // skill file path
  line: number;         // 1-indexed line of match
  message: string;      // short UI-facing description
  evidence: string;     // the matched text
  category: ThreatCategory;
  frameworks: string[]; // e.g. ["OWASP-LLM02", "CWE-94"]
  description: string;  // full explanation
  remediation?: string; // what safe code looks like
  remediable: boolean;
}
```

**Severity meaning**

| Severity | Meaning |
|----------|---------|
| `critical` | High-confidence malicious pattern — review strongly recommended before installing |
| `warn` | Risky pattern with legitimate uses — context required |
| `info` | Informational — no action required but worth noting |

ClawSentinel **never automatically blocks** skill installation. Findings are
presented to the user for review. The install decision is always the user's.

---

## Rule Categories

Use one of these existing `ThreatCategory` values when writing a new rule.
Open a GitHub Discussion before introducing a new category.

| Category | Description | Example rules |
|----------|-------------|---------------|
| `data-exfiltration` | Sending data to external endpoints | `exfil-globalthis-fetch`, `exfil-websocket` |
| `code-injection` | Executing arbitrary or remote code | `inject-vm-execution`, `inject-node-internal-binding` |
| `credential-theft` | Accessing or transmitting credentials | `credential-hardcoded-inline`, `exfil-env-secrets` |
| `prompt-injection` | Injecting instructions into agent prompts | `inject-agent-to-agent`, `inject-dynamic-jailbreak` |
| `supply-chain` | Loading unverified external packages | `supply-unverified-external-import` |
| `inter-agent-attack` | Abusing agent-to-agent communication | `inter-agent-recursive-invoke` |
| `obfuscation` | Hiding intent through encoding or indirection | `exfil-high-entropy-string` |
| `crypto-mining` | Consuming compute resources for mining | crypto-mining rules |
| `cost-bombing` | Exhausting token or API budgets | cost-bomb rules |
| `gateway-abuse` | Abusing the OpenClaw gateway or API | gateway-abuse rules |
| `filesystem-abuse` | Unsafe filesystem or process operations | `dangerous-action-no-hitl` |
| `network-abuse` | Abusing network access | `exfil-websocket` |

---

## Reporting a Scanner Bypass

If you discover a way to evade an existing rule, report it before submitting
a fix. This gives the team visibility into the bypass class and allows
ChatGPT (our adversarial reviewer) to verify independently.

**Step 1 — Log the bypass**

Add an entry to `relay/BYPASS-WORKBENCH.json`:

```json
{
  "id": "BP-009",
  "rule_targeted": "exfil-globalthis-fetch",
  "cycle": "beta14",
  "status": "confirmed",
  "bypass_code": "const f = globalThis['fetch']; f(url, opts);",
  "evasion_reason": "bracket notation bypassed the dot-access pattern in original rule",
  "confidence": 100,
  "fix_applied": null,
  "fix_entry_id": null,
  "verified_fixed": false,