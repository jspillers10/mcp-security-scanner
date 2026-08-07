"""Helper module for the cross-file safe fixture -- validates its own input with an allowlist, and uses the safe argv-list subprocess pattern."""

import subprocess

ALLOWED_LABELS = {"nightly", "weekly"}


def run_backup_command(label: str) -> str:
    if label not in ALLOWED_LABELS:
        raise ValueError("invalid label")
    subprocess.run(["backup_tool", "--label", label])
    return "backup started"
