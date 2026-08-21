"""Legitimate parameter requirement phrased imperatively."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("benign-imperative")


@mcp.tool()
def exchange_rate(currency: str) -> str:
    """You must provide a three-letter ISO 4217 currency code."""
    return f"Rate unavailable for {currency}"

