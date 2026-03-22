"""
adr_manager.py — ADR template validation and staleness detection
Part of ClawSentinel relay automation (OPEN-028, OPEN-029)
"""

import re
from pathlib import Path
from datetime import datetime, timezone, timedelta

RELAY_DIR = Path('/home/shem/clawsentinel-repo/relay')

# Required sections in every ADR file
REQUIRED_SECTIONS = [
    'CONTEXT',
    'DECISION',
    'ENFORCEMENT',
    'RATIONALE',
    'CONSEQUENCES',
    'ALTERNATIVES CONSIDERED',
    'POST-HOC REVIEW REQUIRED',
]

REQUIRED_HEADER_FIELDS = [
    'Status:',
    'Date:',
    'Author:',
]

VALID_STATUSES = {'PROPOSED', 'ACCEPTED', 'SUPERSEDED', 'DEPRECATED'}
STALENESS_DAYS = 14


def validate_adr(content: str, filename: str) -> list[str]:
    """
    Validate an ADR file against the standard template.
    Returns list of error strings. Empty list = valid.
    """
    errors = []

    # Check required header fields
    for field in REQUIRED_HEADER_FIELDS:
        if field not in content:
            errors.append(f"Missing required header field: {field}")

    # Check status is valid
    status_match = re.search(r'Status:\s*(\w+)', content)
    if status_match:
        status = status_match.group(1).upper()
        if status not in VALID_STATUSES:
            errors.append(
                f"Invalid Status '{status}'. Must be one of: {', '.join(VALID_STATUSES)}"
            )
    else:
        errors.append("Cannot parse Status field")

    # Check date format
    date_match = re.search(r'Date:\s*(\d{4}-\d{2}-\d{2})', content)
    if not date_match:
        errors.append("Missing or invalid Date field (expected YYYY-MM-DD)")

    # Check required sections
    for section in REQUIRED_SECTIONS:
        if section not in content:
            errors.append(f"Missing required section: {section}")

    # Check alternatives — need at least 2
    if 'ALTERNATIVES CONSIDERED' in content:
        alt_section_match = re.search(
            r'ALTERNATIVES CONSIDERED\s*\n+(.*?)(?:\n[A-Z]{3,}|\Z)',
            content, re.DOTALL
        )
        if alt_section_match:
            alt_text = alt_section_match.group(1)
            # Count alternatives by looking for "Rejected" or numbered items
            alt_count = len(re.findall(r'Rejected', alt_text, re.IGNORECASE))
            if alt_count < 2:
                errors.append(
                    "ALTERNATIVES CONSIDERED must include at least 2 rejected alternatives"
                )

    return errors


def check_staleness() -> list[dict]:
    """
    Check all ADR files for staleness.
    Returns list of stale ADR dicts with id, date, days_stale, filename.
    """
    stale = []

    adr_files = sorted(RELAY_DIR.glob('ADR-*.md'))
    now = datetime.now(timezone.utc)

    for adr_file in adr_files:
        # Skip drafts and template
        if 'DRAFT' in adr_file.name or 'TEMPLATE' in adr_file.name:
            continue

        content = adr_file.read_text()

        # Check status
        status_match = re.search(r'Status:\s*(\w+)', content)
        if not status_match:
            continue
        status = status_match.group(1).upper()

        if status != 'PROPOSED':
            continue

        # Check for staleness override
        if 'Staleness-Override: DEFER-INDEFINITELY' in content:
            continue

        # Parse date
        date_match = re.search(r'Date:\s*(\d{4}-\d{2}-\d{2})', content)
        if not date_match:
            continue

        try:
            adr_date = datetime.strptime(
                date_match.group(1), '%Y-%m-%d'
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            continue

        days_old = (now - adr_date).days

        if days_old >= STALENESS_DAYS:
            # Get ADR number and title
            adr_id_match = re.search(r'ADR-(\d+):', content)
            title_match = re.search(r'ADR-\d+:\s*(.+)', content)
            stale.append({
                'filename': adr_file.name,
                'id': f"ADR-{adr_id_match.group(1)}" if adr_id_match else adr_file.stem,
                'title': title_match.group(1).strip() if title_match else 'Unknown',
                'date': date_match.group(1),
                'days_stale': days_old,
            })

    return stale


def print_staleness_warnings(stale: list[dict]):
    """Print staleness warnings in plain English."""
    if not stale:
        return

    print(f"\n{'='*60}")
    print(f"⚠  STALE ADR WARNING — {len(stale)} ADR(s) need attention")
    print(f"{'='*60}")
    for s in stale:
        print(f"\n  {s['id']}: {s['title']}")
        print(f"  Proposed: {s['date']} ({s['days_stale']} days ago)")
        print(f"  File: relay/{s['filename']}")
        print(f"  Action: Tell Claude to APPROVE, DECLINE, or add")
        print(f"          'Staleness-Override: DEFER-INDEFINITELY' to the file")
    print(f"\n{'='*60}")


def get_next_adr_number() -> int:
    """Find the next available ADR number."""
    existing = []
    for f in RELAY_DIR.glob('ADR-*.md'):
        if 'DRAFT' in f.name or 'TEMPLATE' in f.name:
            continue
        match = re.search(r'ADR-(\d+)', f.name)
        if match:
            existing.append(int(match.group(1)))
    return max(existing) + 1 if existing else 1


def finalize_adr_draft(draft_path: Path, approved_by: str) -> Path:
    """
    Finalize an ADR draft — assign number, update status, rename file.
    Returns the new file path.
    """
    content = draft_path.read_text()

    # Assign number
    next_num = get_next_adr_number()
    adr_id = f"ADR-{next_num:03d}"

    # Update status and approval
    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    content = re.sub(r'Status:\s*PROPOSED', f'Status: ACCEPTED', content)
    content = re.sub(
        r'Approved by:\s*PENDING.*',
        f'Approved by: {approved_by} ({today})',
        content
    )
    content = re.sub(r'ADR-XXX', adr_id, content)

    # Validate before finalizing
    errors = validate_adr(content, draft_path.name)
    if errors:
        raise ValueError(f"ADR validation failed:\n" + '\n'.join(f"  - {e}" for e in errors))

    # Write to final location
    final_path = RELAY_DIR / f"{adr_id}.md"
    final_path.write_text(content)

    # Remove draft
    draft_path.unlink()

    return final_path


if __name__ == '__main__':
    # Quick test
    print("Checking for stale ADRs...")
    stale = check_staleness()
    print_staleness_warnings(stale)
    if not stale:
        print("No stale ADRs found.")

    print(f"\nNext ADR number: ADR-{get_next_adr_number():03d}")
