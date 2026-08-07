"""One of a pair of runnable MCP servers used to integration-test config_scanner.py's cross-server tool-name collision check. Exposes a tool named "search_docs" -- see shadow_server_b.py (identical name) and shadow_server_c.py (near-miss typo)."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("shadow-server-a")


@mcp.tool()
def search_docs(query: str) -> str:
    """Search server A's documents."""
    return f"A results for {query}"


if __name__ == "__main__":
    mcp.run()
