#!/usr/bin/env python3
"""
ClawSentinel Session Sync
=========================
Keeps chat Claude and API Claude in sync via a context file.

hey-claude  → pulls repo, generates context file for upload to chat Claude
claude-end  → commits changes, pushes, generates updated context file
"""

import sys, json, subprocess, os
from pathlib import Path
from datetime import datetime, timezone

REPO  = Path.home() / 'clawsentinel-repo'
RELAY = REPO / 'relay'
VENV  = REPO / '.venv'

CONTEXT_OUT = REPO / 'relay' / 'CLAUDE-CONTEXT-TODAY.md'

def git(cmd, check=True):
    r = subprocess.run(['git'] + cmd, cwd=REPO,
                       capture_output=True, text=True)
    if check and r.returncode != 0:
        print(f"  git warning: {r.stderr.strip()}")
    return r.stdout.strip()

def read_json(path):
    try:
        return json.loads(Path(path).read_text())
    except Exception:
        return {}

def generate_context_file():
    """Generate the file to upload to chat Claude."""
    date = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    lines = []

    lines.append(f"# ClawSentinel — Daily Context Sync")
    lines.append(f"# Generated: {date}")
    lines.append(f"# Upload this file to your Claude.ai project knowledge to sync chat Claude.")
    lines.append("")

    # ── Git state ──
    last_commit = git(['log', '--oneline', '-1'])
    branch = git(['branch', '--show-current'])
    lines.append(f"## REPO STATE")
    lines.append(f"Branch: {branch}")
    lines.append(f"Last commit: {last_commit}")
    lines.append("")

    # ── Audit log — last 3 entries ──
    log_path = RELAY / 'LIVING-AUDIT-ERROR-LOG.json'
    if log_path.exists():
        data = read_json(log_path)
        entries = data if isinstance(data, list) else next(
            (v for v in data.values() if isinstance(v, list)), [])
        lines.append("## RECENT AUDIT LOG (last 3 entries)")
        for e in entries[-3:]:
            lines.append(f"- {e.get('id')} [{e.get('severity','?')}]: {e.get('description','')[:100]}")
            lines.append(f"  Resolution: {e.get('resolution','')[:80]}")
        lines.append("")

    # ── Bypass workbench summary ──
    wb_path = RELAY / 'BYPASS-WORKBENCH.json'
    if wb_path.exists():
        wb = read_json(wb_path)
        attempts = wb.get('attempts', [])
        unverified = [b for b in attempts if not b.get('verified_fixed')]
        verified   = [b for b in attempts if b.get('verified_fixed')]
        lines.append("## BYPASS WORKBENCH")
        lines.append(f"Total: {len(attempts)} | Verified fixed: {len(verified)} | Open: {len(unverified)}")
        if unverified:
            lines.append("Unverified:")
            for b in unverified:
                lines.append(f"  {b['id']} [{b.get('severity','?')}] {b['rule_targeted']} — {b.get('notes','')[:80]}")
        lines.append("")

    # ── Open items ──
    cont_path = RELAY / 'ONBOARDING-CONTINUITY-v3.4.md'
    if cont_path.exists():
        content = cont_path.read_text()
        lines.append("## OPEN ITEMS")
        in_open = False
        for line in content.splitlines():
            if 'OPEN-' in line and ('BLOCKER' in line or 'M4' in line or
                                     'M6' in line or 'high' in line.lower()):
                lines.append(f"  {line.strip()}")
            if 'Next open item ID' in line:
                lines.append(f"  {line.strip()}")
                break
        lines.append("")

    # ── Session log — last 5 entries ──
    session_log = RELAY / 'SESSION-LOG.md'
    if session_log.exists():
        log_content = session_log.read_text().splitlines()
        lines.append("## RECENT SESSION LOG (last 10 lines)")
        for l in log_content[-10:]:
            lines.append(f"  {l}")
        lines.append("")

    # ── Pending relay tasks ──
    pending = []
    for f in sorted(RELAY.glob('*-claude-review.txt')):
        pending.append(f.name)
    if pending:
        lines.append("## PENDING RELAY REVIEWS (awaiting implementation)")
        for p in pending:
            lines.append(f"  {p}")
        lines.append("")

    # ── Key decisions and context ──
    lines.append("## HOW TO RESTORE FULL CONTEXT")
    lines.append("Also upload these files to project knowledge:")
    lines.append("  relay/ONBOARDING-CONTINUITY-v3.4.md")
    lines.append("  relay/BYPASS-WORKBENCH.json")
    lines.append("  relay/LIVING-AUDIT-ERROR-LOG.json")
    lines.append("")
    lines.append("## SESSION STARTUP CHECKLIST")
    lines.append("1. git pull origin main ✓ (done by hey-claude)")
    lines.append("2. Upload this file to Claude.ai project knowledge")
    lines.append("3. Tell chat Claude: 'New session. Context file uploaded.'")
    lines.append("4. Chat Claude reads it and confirms project state")
    lines.append("5. Begin work")

    CONTEXT_OUT.write_text('\n'.join(lines))
    return CONTEXT_OUT

def session_start():
    print("\n── hey-claude: Session Start ────────────────────────────────")

    # Pull latest
    print("Pulling latest from GitHub...")
    result = git(['pull', 'origin', 'main'], check=False)
    print(f"  {result or 'Already up to date'}")

    # Check for uncommitted changes
    status = git(['status', '--short'])
    if status:
        print(f"\nNote — uncommitted local changes:\n{status}")

    # Generate context file
    print("\nGenerating context file for chat Claude...")
    out = generate_context_file()
    print(f"  Saved: {out}")

    # Summary
    wb_path = RELAY / 'BYPASS-WORKBENCH.json'
    if wb_path.exists():
        wb = read_json(wb_path)
        attempts = wb.get('attempts', [])
        unverified = [b for b in attempts if not b.get('verified_fixed')]
        print(f"\nBypass workbench: {len(unverified)} unverified items")

    print(f"\n{'='*60}")
    print("NEXT STEP: Upload this file to Claude.ai project knowledge:")
    print(f"  {out}")
    print("Then tell chat Claude: 'New session. Context file uploaded.'")
    print(f"{'='*60}\n")

def session_end():
    print("\n── claude-end: Session End ──────────────────────────────────")

    status = git(['status', '--short'])

    if not status:
        print("Repo clean — nothing to commit")
    else:
        print(f"Uncommitted changes:\n{status}\n")
        answer = input("Commit and push all changes? (YES/no): ").strip()
        if answer == 'YES':
            ts = datetime.now(timezone.utc).strftime('%Y-%m-%d')
            # Stage safe files only
            safe_patterns = [
                'relay/', 'sentinel_relay_v2.py', 'sentinel_sync.py',
                'clawsentinel.vitest.config.ts', 'tests/skill-scanner.test.ts',
                'src/security/skill-scanner.test.ts',
                'src/security/sentinel-secrets-store.ts'
            ]
            for p in safe_patterns:
                full = REPO / p
                if full.exists():
                    git(['add', str(full)], check=False)

            msg = f"beta14: session close {ts}"
            result = git(['commit', '-m', msg], check=False)
            if 'nothing to commit' not in result:
                git(['push', 'origin', 'main'])
                print(f"  Pushed: {msg}")
            else:
                print("  Nothing new to commit")
        else:
            print("  Skipped — changes remain local")

    # Always generate updated context file
    print("\nGenerating updated context file...")
    out = generate_context_file()

    # Commit the context file itself
    git(['add', str(out)], check=False)
    git(['commit', '-m', f"sync: update CLAUDE-CONTEXT-TODAY.md"], check=False)
    git(['push', 'origin', 'main'], check=False)

    print(f"\n{'='*60}")
    print("SESSION CLOSED. Upload this file to Claude.ai project knowledge:")
    print(f"  {out}")
    print("This keeps chat Claude in sync for next session.")
    print(f"{'='*60}\n")

if __name__ == '__main__':
    if '--start' in sys.argv:
        session_start()
    elif '--end' in sys.argv:
        session_end()
    else:
        print("Usage:")
        print("  hey-claude   (or: python3 sentinel_sync.py --start)")
        print("  claude-end   (or: python3 sentinel_sync.py --end)")
