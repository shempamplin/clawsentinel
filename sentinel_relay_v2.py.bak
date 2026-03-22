"""
ClawSentinel AI Relay — Stage 1
================================
SAFEGUARDS:
  - Dry-run by default. Nothing commits without --execute flag.
  - Hard limit: 10 API calls per run maximum.
  - Relay directory only. Source code is never touched.
  - Plain English action summary + YES confirmation before any action.
  - API Claude reads repo context files before every review.
  - Session log written to relay/SESSION-LOG.md on every run.

USAGE:
  python3 sentinel_relay_v2.py --task chatgpt-round4           # dry run
  python3 sentinel_relay_v2.py --task chatgpt-round4 --execute # run for real
  python3 sentinel_relay_v2.py --list                          # show available tasks
"""

import asyncio
import argparse
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from pydantic_ai import Agent
from pydantic_ai.models.openrouter import OpenRouterModel
from pydantic_ai.providers.openrouter import OpenRouterProvider

# ── Config ────────────────────────────────────────────────────────────────────

REPO_DIR = Path('/home/shem/clawsentinel-repo')
RELAY_DIR = REPO_DIR / 'relay'
ENV_PATH  = REPO_DIR / '.env'

MAX_API_CALLS = 10       # hard ceiling per run
call_count    = 0        # global counter

# ── Model strings ─────────────────────────────────────────────────────────────

MODELS = {
    'claude':  'anthropic/claude-sonnet-4-6',
    'chatgpt': 'openai/gpt-4o',
    'gemini':  'google/gemini-2.0-flash-001',
    'grok':    'x-ai/grok-3-beta',
}

# ── Key loading ───────────────────────────────────────────────────────────────

def load_key() -> str:
    with open(ENV_PATH) as f:
        for line in f:
            line = line.strip()
            if line.startswith('OPENROUTER_API_KEY='):
                return line.split('=', 1)[1]
    raise ValueError(f"OPENROUTER_API_KEY not found in {ENV_PATH}")

def make_agent(model_id: str, system_prompt: str) -> Agent:
    provider = OpenRouterProvider(api_key=load_key())
    return Agent(OpenRouterModel(model_id, provider=provider),
                 system_prompt=system_prompt)

# ── API call with hard limit ──────────────────────────────────────────────────

async def call_ai(agent: Agent, prompt: str, label: str) -> str:
    global call_count
    if call_count >= MAX_API_CALLS:
        raise RuntimeError(
            f"SAFETY STOP: Hit the {MAX_API_CALLS} API call limit. "
            "No further calls will be made this run."
        )
    call_count += 1
    print(f"  [API call {call_count}/{MAX_API_CALLS}] {label}...")
    result = await agent.run(prompt)
    return result.output

# ── Repo context loader ───────────────────────────────────────────────────────

def load_repo_context() -> str:
    """Read the three context files that give Claude project state."""
    context_parts = []

    files = [
        ('ONBOARDING-CONTINUITY-v3.4.md', 'PROJECT CONTINUITY DOC'),
        ('LIVING-AUDIT-ERROR-LOG.json',    'RECENT AUDIT LOG (last 5 entries)'),
        ('BYPASS-WORKBENCH.json',          'BYPASS WORKBENCH'),
    ]

    for filename, label in files:
        path = RELAY_DIR / filename
        if not path.exists():
            context_parts.append(f"[{label}: file not found — {filename}]")
            continue

        content = path.read_text()

        # For JSON files, summarise rather than dump everything
        if filename.endswith('.json'):
            try:
                data = json.loads(content)
                if filename == 'LIVING-AUDIT-ERROR-LOG.json':
                    entries = data if isinstance(data, list) else next(
                        v for v in data.values() if isinstance(v, list))
                    last5 = entries[-5:]
                    content = json.dumps(last5, indent=2)
                elif filename == 'BYPASS-WORKBENCH.json':
                    # Just the attempts summary
                    attempts = data.get('attempts', data)
                    content = json.dumps(attempts, indent=2)
            except Exception:
                content = content[:2000] + '\n[truncated]'
        else:
            # Truncate large docs to first 4000 chars
            if len(content) > 4000:
                content = content[:4000] + '\n\n[...truncated for context window...]'

        context_parts.append(f"=== {label} ===\n{content}")

    return '\n\n'.join(context_parts)

# ── Session logger ────────────────────────────────────────────────────────────

class SessionLog:
    def __init__(self):
        self.entries = []
        self.path = RELAY_DIR / 'SESSION-LOG.md'
        self.start = datetime.now(timezone.utc)

    def log(self, action: str, detail: str = ''):
        ts = datetime.now(timezone.utc).strftime('%H:%M:%S UTC')
        self.entries.append(f"- `{ts}` {action}" + (f"\n  {detail}" if detail else ''))
        print(f"  LOG: {action}")

    def write(self, task: str, dry_run: bool, outcome: str):
        date = self.start.strftime('%Y-%m-%d')
        header = f"\n\n## {date} — {task} ({'DRY RUN' if dry_run else 'EXECUTED'})\n"
        header += f"API calls used: {call_count}/{MAX_API_CALLS}\n"
        header += f"Outcome: {outcome}\n\n"
        body = '\n'.join(self.entries)

        existing = self.path.read_text() if self.path.exists() else ''
        self.path.write_text(existing + header + body + '\n')

# ── Safety reviewer (Claude reviewing the plan) ───────────────────────────────

async def safety_review(plan: dict, reviewer: Agent, log: SessionLog) -> tuple[bool, str]:
    """Ask Claude to review the planned actions in plain English."""
    plan_text = json.dumps(plan, indent=2)
    prompt = f"""You are a safety reviewer for an automated AI relay system.
Review this planned action and respond in plain English.

PLANNED ACTION:
{plan_text}

Respond with exactly this format:

RESULT: SAFE  (or UNSAFE)

WHAT THIS WILL DO:
- [bullet list of exactly what will happen, in plain English]

ESTIMATED COST: [rough estimate]

CONCERNS: [None, or list any concerns]

Be direct. No jargon. The person reading this is not a developer."""

    log.log("Safety review requested")
    review = await call_ai(reviewer, prompt, "Safety review")
    is_safe = 'RESULT: SAFE' in review.upper() and 'RESULT: UNSAFE' not in review.upper()
    return is_safe, review

# ── Git commit helper ─────────────────────────────────────────────────────────

def git_commit(files: list[str], message: str, log: SessionLog):
    """Stage specific files and commit. Never touches src/ or tests/."""
    # Safety check — only relay/ files allowed
    for f in files:
        p = Path(f)
        if not str(p).startswith(str(RELAY_DIR)):
            raise ValueError(f"SAFETY BLOCK: {f} is outside relay/ directory. Aborting.")

    subprocess.run(['git', 'add'] + files, cwd=REPO_DIR, check=True)
    subprocess.run(['git', 'commit', '-m', message], cwd=REPO_DIR, check=True)
    subprocess.run(['git', 'push', 'origin', 'main'], cwd=REPO_DIR, check=True)
    log.log(f"Committed and pushed: {message}")

# ── Tasks ─────────────────────────────────────────────────────────────────────

TASKS = {
    'chatgpt-round4': {
        'description': 'Send ChatGPT Round 4 red-team prompt and get Claude review',
        'target_ai':   'chatgpt',
        'output_file': 'relay/chatgpt-round4-response.txt',
    },
    'gemini-patch-review': {
        'description': 'Ask Gemini to cross-review Grok patch script findings (OPEN-017)',
        'target_ai':   'gemini',
        'output_file': 'relay/gemini-patch-review-response.txt',
    },
    'grok-open005': {
        'description': 'Ask Grok for next batch of OPEN-005 test coverage',
        'target_ai':   'grok',
        'output_file': 'relay/grok-open005-response.txt',
    },
}

PROMPTS = {
    'chatgpt-round4': lambda ctx: f"""PROJECT: ClawSentinel | CYCLE: beta14 | ROLE: Adversarial Reviewer
LAST LOG ENTRY: 20260319-066-CLAUDE

PROJECT CONTEXT:
{ctx}

---

Your Round 4 red-team response was truncated after 'Example attack:' in Q1 in beta13.
Resume from that point — provide the example attack code for Q1, then continue through
Q2-Q5 and the full Round 4 bypass attempts for all six targets:

1. exfil-buffer-encode-chain
2. exfil-variable-indirection-headers
3. inject-dynamic-jailbreak
4. supply-unverified-external-import
5. credential-hardcoded-inline
6. inter-agent-recursive-invoke

For each bypass:
- Exact TypeScript that evades the current scanner
- Confidence rating (0-100)
- Proposed fix

Additional question: does knowing the 3-strike sandbox threshold (ADR-004) create
an exploitable timing attack pattern?

Format: single flat text response, standard relay format (Part 10 of continuity doc).""",

    'gemini-patch-review': lambda ctx: f"""PROJECT: ClawSentinel | CYCLE: beta14 | ROLE: Integration Auditor
LAST LOG ENTRY: 20260319-066-CLAUDE

PROJECT CONTEXT:
{ctx}

---

Grok identified three findings on the ClawSentinel patch script (clawsentinel-patch.mjs):
1. No rollback on partial failure [CONFIDENCE: 95]
2. Hardcoded strings, no version precondition [CONFIDENCE: 90]
3. No fs.access() permissions check before writes [CONFIDENCE: 85]

Please cross-review these findings. For each:
- Do you agree with the finding? (READ FROM SOURCE or INFERRED)
- Severity assessment
- Recommended fix

Use NNN for log entry number. Standard relay format.""",

    'grok-open005': lambda ctx: f"""PROJECT: ClawSentinel | CYCLE: beta14 | ROLE: Test Coverage Lead
LAST LOG ENTRY: 20260319-066-CLAUDE

PROJECT CONTEXT:
{ctx}

---

OPEN-005: Unit test coverage is at 17/62 rules (25%). 45 rules still need tests.

Priority order: rules listed in open_bypass_classes in BYPASS-WORKBENCH.json first.

For each rule, provide:
- At least 2 TRIGGER samples (code that SHOULD fire the rule)
- At least 1 SAFE sample (code that should NOT fire the rule)

CRITICAL: Validate every sample against the actual pattern before delivery.
Use this validation approach: test the regex pattern directly against your sample.
Flag any sample you cannot validate — do not silently substitute.

Deliver tests in the describe() block format matching tests/skill-scanner.test.ts.
Use NNN for log entry number. Standard relay format.""",
}

CLAUDE_REVIEW_PROMPT = lambda ctx, task, response: f"""You are Claude, Lead Producer for ClawSentinel.

PROJECT CONTEXT:
{ctx}

---

You just received this response from the {task} relay:

{response}

Review this response using Pattern 3 (State Transition) from the continuity doc.
For each suggestion or finding, state IMPLEMENT, DEFER, or DECLINE with one sentence of reasoning.

Then provide:
1. DECISIONS: list of IMPLEMENT/DEFER/DECLINE with reasoning
2. NEXT ACTIONS: what should happen next (max 3 items)
3. FLAGS: anything requiring Shem's explicit approval (ADR changes, user control model, etc.)

Be concise. This output will be saved to the repo and committed automatically."""

# ── Main task runner ──────────────────────────────────────────────────────────

async def run_task(task_name: str, dry_run: bool):
    if task_name not in TASKS:
        print(f"Unknown task: {task_name}")
        print(f"Available: {', '.join(TASKS.keys())}")
        return

    task = TASKS[task_name]
    log  = SessionLog()
    log.log(f"Session started — task: {task_name}, dry_run: {dry_run}")

    # Build agents
    reviewer = make_agent(MODELS['claude'],
        "You are Claude, Lead Producer for ClawSentinel. "
        "Review AI responses and make IMPLEMENT/DEFER/DECLINE decisions. "
        "Flag anything requiring human approval. Be concise and direct.")

    safety_agent = make_agent(MODELS['claude'],
        "You are a safety reviewer. Assess planned actions for risk. Plain English only.")

    target_agent = make_agent(
        MODELS[task['target_ai']],
        f"You are the {task['target_ai'].upper()} AI working on ClawSentinel. "
        "Follow the relay format specified in the prompt."
    )

    # Load repo context
    print("\nLoading repo context...")
    ctx = load_repo_context()
    log.log("Repo context loaded", f"{len(ctx)} chars from 3 files")

    # Plan
    output_path = REPO_DIR / task['output_file']
    review_path = RELAY_DIR / f"{task_name}-claude-review.txt"

    plan = {
        "task": task_name,
        "description": task['description'],
        "api_calls_planned": 3,
        "files_to_write": [
            str(output_path),
            str(review_path),
            str(log.path),
        ],
        "will_commit": not dry_run,
        "branches_touched": ["main"] if not dry_run else [],
        "source_code_modified": False,
        "estimated_cost_usd": "~$0.05-0.15",
    }

    # Safety review
    print("\n── Safety Review ────────────────────────────────────")
    is_safe, review_text = await safety_review(plan, safety_agent, log)
    print(review_text)

    if not is_safe:
        print("\n⛔  SAFETY REVIEWER FLAGGED THIS AS UNSAFE. Stopping.")
        log.log("Stopped by safety reviewer")
        log.write(task_name, dry_run, "STOPPED — safety review failed")
        log.path.parent.mkdir(parents=True, exist_ok=True)
        log.write(task_name, dry_run, "STOPPED — safety review failed")
        return

    # Confirmation
    print("\n── Confirmation ─────────────────────────────────────")
    if dry_run:
        print("DRY RUN MODE — nothing will be committed.")
        print("Run with --execute to apply for real.\n")
    else:
        print("EXECUTE MODE — this will commit and push to GitHub.\n")

    answer = input("Type YES to proceed, anything else to cancel: ").strip()
    if answer != "YES":
        print("Cancelled.")
        log.log("Cancelled by user")
        log.write(task_name, dry_run, "CANCELLED by user")
        return

    # Send to target AI
    print(f"\n── Calling {task['target_ai'].upper()} ──────────────────────────────")
    prompt = PROMPTS[task_name](ctx)
    ai_response = await call_ai(target_agent, prompt, task['target_ai'])
    log.log(f"{task['target_ai']} responded", f"{len(ai_response)} chars")

    # Save AI response
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(ai_response)
    log.log(f"Response saved to {task['output_file']}")

    # Claude review
    print(f"\n── Claude Review ────────────────────────────────────")
    review_prompt = CLAUDE_REVIEW_PROMPT(ctx, task_name, ai_response)
    claude_review = await call_ai(reviewer, review_prompt, "Claude review")
    log.log("Claude review complete", f"{len(claude_review)} chars")

    review_path.write_text(claude_review)
    log.log(f"Review saved to relay/{task_name}-claude-review.txt")

    # Print review
    print("\n── Claude's Review ──────────────────────────────────")
    print(claude_review)

    # Write session log
    log.write(task_name, dry_run, "COMPLETED")

    # Commit if executing
    if not dry_run:
        print("\n── Committing to GitHub ─────────────────────────────")
        files_to_commit = [
            str(output_path),
            str(review_path),
            str(log.path),
        ]
        commit_msg = f"beta14: {task_name} relay — automated via sentinel_relay_v2"
        git_commit(files_to_commit, commit_msg, log)
        print("✓ Committed and pushed.")
    else:
        print("\n── DRY RUN COMPLETE ─────────────────────────────────")
        print("Files written locally but NOT committed.")
        print("Run with --execute to commit and push.")

    print(f"\n✓ Done. API calls used: {call_count}/{MAX_API_CALLS}")

# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='ClawSentinel AI Relay — Stage 1')
    parser.add_argument('--task',    help='Task to run')
    parser.add_argument('--execute', action='store_true',
                        help='Actually commit and push (default is dry-run)')
    parser.add_argument('--list',    action='store_true',
                        help='List available tasks')
    args = parser.parse_args()

    if args.list or not args.task:
        print("\nAvailable tasks:")
        for name, t in TASKS.items():
            print(f"  {name:<30} {t['description']}")
        print("\nUsage:")
        print("  python3 sentinel_relay_v2.py --task chatgpt-round4           # dry run")
        print("  python3 sentinel_relay_v2.py --task chatgpt-round4 --execute # commit")
        return

    asyncio.run(run_task(args.task, dry_run=not args.execute))

if __name__ == '__main__':
    main()
