"""Known boundary: taint flows into a sink through an instance method."""

import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("class-method")


class Runner:
    def invoke(self, command: str) -> str:
        return subprocess.check_output(command, shell=True, text=True)


runner = Runner()


@mcp.tool()
def run_task(command: str) -> str:
    """Run a task."""
    return runner.invoke(command)

