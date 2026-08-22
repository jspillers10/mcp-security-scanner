"""
Fixture exercising MCP001 guard-strength boundaries: a denylist guard that
touches the tainted command parameter and exits early, but does not
constrain the final shell string to a known-safe value. Independently
designed for this repository, not derived from any external corpus.
"""

import subprocess

from fastmcp import FastMCP

mcp = FastMCP("demo-weak-command-guard-server")

_BLOCKED_SUBSTRINGS = ("rm ", "shutdown", "reboot")
ALLOWED_ACTIONS = {"status", "restart", "health"}


def load_allowed_actions():
    """Pretend to load an allowlist at runtime -- e.g. from a config file or database."""
    return {"status", "restart"}


@mcp.tool()
def run_diagnostic_command(command: str) -> str:
    """VULNERABLE: a partial denylist blocks a few known-bad substrings but not the rest of the shell grammar."""
    if any(bad in command for bad in _BLOCKED_SUBSTRINGS):
        return "blocked: command not permitted"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


@mcp.tool()
def run_guard_after_sink(action: str) -> str:
    """VULNERABLE: the allowlist check runs after the shell command has already executed."""
    result = subprocess.run(f"service demo-app {action}", shell=True, capture_output=True, text=True)
    if action not in ALLOWED_ACTIONS:
        raise ValueError("invalid action")
    return result.stdout


@mcp.tool()
def run_inverted_allowlist(action: str) -> str:
    """VULNERABLE: returns early when the action IS allowed, falling through to the sink exactly when it is not."""
    if action in ALLOWED_ACTIONS:
        return "action looks fine, refusing for no good reason"
    result = subprocess.run(f"service demo-app {action}", shell=True, capture_output=True, text=True)
    return result.stdout


@mcp.tool()
def run_user_controlled_allowlist(action: str, allowed_actions: str) -> str:
    """VULNERABLE: the allowlist itself comes from a tool parameter, so it isn't trusted."""
    allowed = allowed_actions.split(",")
    if action not in allowed:
        raise ValueError("invalid action")
    result = subprocess.run(f"service demo-app {action}", shell=True, capture_output=True, text=True)
    return result.stdout


@mcp.tool()
def run_dynamic_allowlist(action: str) -> str:
    """VULNERABLE: the allowlist is loaded at call time, not a fixed developer-controlled literal."""
    allowed = load_allowed_actions()
    if action not in allowed:
        raise ValueError("invalid action")
    result = subprocess.run(f"service demo-app {action}", shell=True, capture_output=True, text=True)
    return result.stdout


@mcp.tool()
def run_character_filter_still_dangerous(action: str) -> str:
    """VULNERABLE: rejecting only whitespace still allows shell metacharacters like ; | & through untouched."""
    if " " in action:
        return "no spaces allowed"
    result = subprocess.run(f"service demo-app {action}", shell=True, capture_output=True, text=True)
    return result.stdout


@mcp.tool()
def run_mixed_safe_and_vulnerable(safe_action: str, other_command: str) -> str:
    """One properly allowlisted command alongside one that is never guarded at all, in the same function."""
    if safe_action not in ALLOWED_ACTIONS:
        raise ValueError("invalid action")
    safe_result = subprocess.run(f"service demo-app {safe_action}", shell=True, capture_output=True, text=True)
    unsafe_result = subprocess.run(other_command, shell=True, capture_output=True, text=True)  # VULNERABLE
    return safe_result.stdout + unsafe_result.stdout


@mcp.tool()
def run_guard_nested_in_condition(action: str, debug_mode: bool) -> str:
    if debug_mode:
        if action not in ALLOWED_ACTIONS:
            return "invalid"
    return subprocess.run(f"service demo-app {action}", shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def run_guard_with_conditional_exit(action: str, log_only: bool) -> str:
    if action not in ALLOWED_ACTIONS:
        if log_only:
            return "invalid"
    return subprocess.run(f"service demo-app {action}", shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def run_guard_inside_try(action: str) -> str:
    try:
        if action not in ALLOWED_ACTIONS:
            return "invalid"
    except Exception:
        pass
    return subprocess.run(f"service demo-app {action}", shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def run_nonterminating_guard(action: str) -> str:
    if action not in ALLOWED_ACTIONS:
        print("invalid")
    return subprocess.run(f"service demo-app {action}", shell=True, capture_output=True, text=True).stdout
