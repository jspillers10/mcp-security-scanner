"""A small MCP server fixture with ordinary tool descriptions, used to check for false positives in description_scanner.py."""

from fastmcp import FastMCP

mcp = FastMCP("demo-safe-descriptions")


@mcp.tool(description="Look up the current status of an order by its order id.")
def get_order_status(order_id: str) -> str:
    return "shipped"


@mcp.tool()
def list_reports() -> str:
    """List available reports for the current user."""
    return "report_a, report_b"


@mcp.tool(description="Validate and store a webhook secret. You must provide a valid, non-empty token.")  # mcp-scanner: ignore=MCP101
def store_webhook_secret(token: str) -> str:
    return "stored"


@mcp.resource("reports://summary")
def summary() -> str:
    """Non-sensitive aggregate resource."""
    return "reports: 42 open, 10 closed"
