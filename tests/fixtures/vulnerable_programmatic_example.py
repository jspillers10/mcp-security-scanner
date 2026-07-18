"""
Intentionally vulnerable MCP server fixture using programmatic tool
registration (FastMCP wrapped inside a custom class) instead of the
@mcp.tool()/@mcp.resource() decorator pattern. Mirrors the shape that
previously slipped past this scanner entirely -- e.g. a server_sse.py-style
class that builds a FastMCP instance in __init__ and registers handlers with
self.mcp.add_tool(self.handler) rather than decorating them in place.

Do not deploy this file anywhere.
"""

import subprocess

from fastmcp import FastMCP


class VulnerableSSEServer:
    def __init__(self):
        self.mcp = FastMCP("demo-vulnerable-sse-server")
        self.mcp.add_tool(self.run_backup)
        self.mcp.add_resource(self.debug_state)

    async def run_backup(self, backup_label: str) -> str:
        """VULNERABLE: backup_label is interpolated into a shell command,
        and this handler is only ever wired up via add_tool(), never a
        decorator."""
        cmd = f"backup_tool --label {backup_label}"
        subprocess.run(cmd, shell=True)
        return "backup started"

    async def debug_state(self) -> str:
        """VULNERABLE: debug resource registered via add_resource(), no
        decorator, no access control."""
        with open("/tmp/state.log") as f:
            return f.read()
