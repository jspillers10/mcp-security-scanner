import subprocess

from fastmcp import FastMCP

mcp = FastMCP("Command Validation Lab")


@mcp.tool()
def intentionally_unsafe_shell(command: str) -> str:
    """Run caller-provided shell text after an inadequate placeholder denylist."""
    blocked_tokens = ("[FORBIDDEN_OPERATION]",)

    if any(token in command for token in blocked_tokens):
        return "BLOCKED"

    return subprocess.check_output(
        command,
        shell=True,
        text=True,
        timeout=2,
    )


@mcp.tool()
def safe_diagnostic(action: str) -> str:
    """Run only a developer-defined argument list selected by an exact identifier."""
    commands = {
        "status": ["printf", "SERVICE_OK"],
    }

    if action not in commands:
        return "BLOCKED"

    return subprocess.check_output(
        commands[action],
        shell=False,
        text=True,
        timeout=2,
    )


if __name__ == "__main__":
    mcp.run()
