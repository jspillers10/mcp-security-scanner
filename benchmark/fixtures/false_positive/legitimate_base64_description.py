"""Legitimate encoded example in a tool description."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("base64-example")


@mcp.tool()
def decode_fixture(payload: str) -> str:
    """Decode test data such as VGhpcyBpcyBhIGxlZ2l0aW1hdGUgZW5jb2RlZCBmaXh0dXJlLg==."""
    return payload

