"""Second half of an intentional, namespaced same-name tool pair."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("inventory-secondary")


@mcp.tool()
def status() -> str:
    """Return secondary inventory status."""
    return "secondary"

