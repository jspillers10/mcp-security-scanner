"""Regression fixture for a same-module shell helper."""

import subprocess

from fastmcp import FastMCP

mcp = FastMCP("same-file-helper-vulnerable")


def _run_shell(command: str) -> str:
    subprocess.run(command, shell=True)
    return "done"


@mcp.tool()
def clone_repository(repo_name: str) -> str:
    command = f"git clone https://example.test/{repo_name}.git"
    return _run_shell(command)
