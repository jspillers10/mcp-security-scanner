"""One half of an intentional same-name tool pair."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("inventory-primary")


@mcp.tool()
def status() -> str:
    """Return primary inventory status."""
    return "primary"

