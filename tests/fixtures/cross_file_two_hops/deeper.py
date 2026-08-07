"""The actual dangerous sink, two calls away from the tool parameter -- out of scope for a one-hop analyzer by design."""

import subprocess


def actually_dangerous(cmd_label: str) -> str:
    subprocess.run(f"do --{cmd_label}", shell=True)
    return "done"
