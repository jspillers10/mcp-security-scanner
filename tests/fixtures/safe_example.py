"""A small MCP server fixture written defensively, used to check for false positives."""

import subprocess
from pathlib import Path

from fastmcp import FastMCP

mcp = FastMCP("demo-safe-server")

ALLOWED_STATUSES = {"open", "closed", "pending"}
REPORTS_DIR = Path("/var/data/reports").resolve()


@mcp.tool()
def export_report(status_filter: str, export_format: str) -> str:
    """Export a report using an allowlist and argv-based subprocess (no shell)."""
    if status_filter not in ALLOWED_STATUSES:
        raise ValueError("invalid status filter")
    if export_format not in {"csv", "json"}:
        raise ValueError("invalid format")
    subprocess.run(["legacy_export", "--status", status_filter, "--format", export_format], shell=False)
    return "export started"


@mcp.tool()
def read_report(report_name: str) -> str:
    """Read a report file, constrained to the reports directory."""
    candidate = (REPORTS_DIR / report_name).resolve()
    if REPORTS_DIR not in candidate.parents and candidate != REPORTS_DIR:
        raise ValueError("path escapes reports directory")
    with open(candidate) as f:
        return f.read()


@mcp.resource("reports://summary")
def summary() -> str:
    """Non-sensitive aggregate resource."""
    return "reports: 42 open, 10 closed"
