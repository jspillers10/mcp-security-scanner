"""A runnable MCP server with a tool name unrelated to any of the shadow_server_*.py fixtures, used to confirm config_scanner.py does NOT flag genuinely distinct servers."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("clean-server")


@mcp.tool()
def get_weather(city: str) -> str:
    """Get the current weather for a city."""
    return "sunny"


if __name__ == "__main__":
    mcp.run()
