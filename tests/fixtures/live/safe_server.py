"""A runnable MCP server with ordinary tool descriptions, used to check for live-scan false positives against a real stdio connection."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("live-safe-fixture")


@mcp.tool(description="Look up the current status of an order by its order id.")
def get_order_status(order_id: str) -> str:
    return "shipped"


@mcp.tool()
def list_reports() -> str:
    """List available reports for the current user."""
    return "report_a, report_b"


if __name__ == "__main__":
    mcp.run()
