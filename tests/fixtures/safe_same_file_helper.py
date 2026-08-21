"""Safe counterpart to the same-module shell helper fixture."""

import subprocess

from fastmcp import FastMCP

mcp = FastMCP("same-file-helper-safe")


def _run_command(repo_name: str) -> str:
    subprocess.run(["git", "clone", f"https://example.test/{repo_name}.git"], shell=False)
    return "done"


@mcp.tool()
def clone_repository(repo_name: str) -> str:
    return _run_command(repo_name)
