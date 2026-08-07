"""Helper module for the cross-file vulnerable fixture -- not itself a tool file, just a plain function a tool calls into."""

import subprocess


def run_backup_command(label: str) -> str:
    cmd = f"backup_tool --label {label}"
    subprocess.run(cmd, shell=True)
    return "backup started"
