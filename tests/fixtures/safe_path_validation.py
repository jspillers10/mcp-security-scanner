"""
Fixture exercising MCP002 strong-guard shapes that must suppress the
finding: canonical resolution plus containment, and an exact allowlist.
Independently designed for this repository, not derived from any external
corpus.
"""

from pathlib import Path

from fastmcp import FastMCP

mcp = FastMCP("demo-strong-path-guard-server")

REPORTS_DIR = Path("/srv/reports").resolve()
ALLOWED_REPORT_NAMES = {"quarterly.txt", "annual.txt", "summary.txt"}


@mcp.tool()
def read_resolved_report(report_name: str) -> str:
    """Canonical resolution plus containment within an approved base directory."""
    candidate = (REPORTS_DIR / report_name).resolve()
    if not candidate.is_relative_to(REPORTS_DIR):
        return "invalid report path"
    return candidate.read_text(encoding="utf-8")


@mcp.tool()
def read_allowlisted_report(report_name: str) -> str:
    """Exact allowlist of permitted report names."""
    if report_name not in ALLOWED_REPORT_NAMES:
        raise ValueError("unknown report")
    return (REPORTS_DIR / report_name).read_text(encoding="utf-8")
