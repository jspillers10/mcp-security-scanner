"""Path use constrained to a resolved base directory."""

from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("safe-path")
BASE = Path("/srv/reports").resolve()


@mcp.tool()
def read_report(name: str) -> str:
    """Read a report under the configured report directory."""
    candidate = (BASE / name).resolve()
    if not candidate.is_relative_to(BASE):
        return "invalid report path"
    return candidate.read_text(encoding="utf-8")

