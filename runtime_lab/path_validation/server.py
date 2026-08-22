import os
from pathlib import Path

from fastmcp import FastMCP

LAB_ROOT = Path("/lab")
ALLOWED_DIR = (LAB_ROOT / "allowed").resolve()

mcp = FastMCP("Path Validation Lab")


@mcp.tool()
def vulnerable_read(report_path: str) -> str:
    """Read any existing file selected by the caller."""
    if not os.path.exists(report_path):
        return "NOT_FOUND"

    with open(report_path, encoding="utf-8") as handle:
        return handle.read()


@mcp.tool()
def safe_read(report_name: str) -> str:
    """Read a report only when it resolves inside the approved directory."""
    candidate = (ALLOWED_DIR / report_name).resolve()

    if not candidate.is_relative_to(ALLOWED_DIR):
        return "BLOCKED"

    with open(candidate, encoding="utf-8") as handle:
        return handle.read()


if __name__ == "__main__":
    mcp.run()
