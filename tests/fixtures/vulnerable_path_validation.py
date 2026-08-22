"""
Fixture exercising MCP002 guard-strength boundaries: checks that touch the
tainted path parameter and exit early, but do not actually constrain it to
a safe location. Independently designed for this repository, not derived
from any external corpus.
"""

import os
from pathlib import Path

from fastmcp import FastMCP

mcp = FastMCP("demo-weak-path-guard-server")

BASE = Path("/srv/reports").resolve()


def load_allowed_report_names():
    """Pretend to load an allowlist at runtime -- e.g. from a config file or database."""
    return {"quarterly.txt", "annual.txt"}


@mcp.tool()
def read_by_existence_check(report_path: str) -> str:
    """VULNERABLE: an existence check proves the file is there, not that it's in an allowed location."""
    if not os.path.exists(report_path):
        return "not found"
    with open(report_path) as f:
        return f.read()


@mcp.tool()
def read_by_extension_check(report_path: str) -> str:
    """VULNERABLE: an extension check doesn't constrain which directory the file lives in."""
    if not report_path.endswith(".txt"):
        return "unsupported file type"
    with open(report_path) as f:
        return f.read()


@mcp.tool()
def read_by_prefix_check(report_path: str) -> str:
    """VULNERABLE: a raw string prefix check is defeated by '../' before resolution."""
    if not report_path.startswith("/srv/reports/"):
        return "outside reports directory"
    with open(report_path) as f:
        return f.read()


@mcp.tool()
def read_by_denylist_check(report_path: str) -> str:
    """VULNERABLE: blocking '..' alone misses an absolute path outside the reports directory."""
    if ".." in report_path:
        return "invalid path"
    with open(report_path) as f:
        return f.read()


@mcp.tool()
def read_guard_after_sink(report_name: str) -> str:
    """VULNERABLE: the containment check runs after the file is already opened, too late to matter."""
    candidate = (BASE / report_name).resolve()
    with open(candidate) as f:
        data = f.read()
    if not candidate.is_relative_to(BASE):
        raise ValueError("invalid report path")
    return data


@mcp.tool()
def read_inverted_guard(report_name: str) -> str:
    """VULNERABLE: returns early when the path IS safe, falling through to the sink exactly when it is not."""
    candidate = (BASE / report_name).resolve()
    if candidate.is_relative_to(BASE):
        return "path looks fine, refusing to read for no good reason"
    with open(candidate) as f:
        return f.read()


@mcp.tool()
def read_unresolved_is_relative_to(report_name: str) -> str:
    """VULNERABLE: is_relative_to() on an unresolved candidate can still be fooled by literal '..' segments."""
    candidate = BASE / report_name
    if not candidate.is_relative_to(BASE):
        raise ValueError("invalid report path")
    with open(candidate) as f:
        return f.read()


@mcp.tool()
def read_unresolved_parents(report_name: str) -> str:
    """VULNERABLE: a .parents membership check on an unresolved candidate has the same weakness."""
    candidate = BASE / report_name
    if BASE not in candidate.parents:
        raise ValueError("invalid report path")
    with open(candidate) as f:
        return f.read()


@mcp.tool()
def read_user_controlled_allowlist(report_name: str, allowed_names: str) -> str:
    """VULNERABLE: the allowlist itself comes from a tool parameter, so it isn't trusted."""
    allowed = allowed_names.split(",")
    if report_name not in allowed:
        raise ValueError("invalid report name")
    with open(BASE / report_name) as f:
        return f.read()


@mcp.tool()
def read_dynamic_allowlist(report_name: str) -> str:
    """VULNERABLE: the allowlist is loaded at call time, not a fixed developer-controlled literal."""
    allowed = load_allowed_report_names()
    if report_name not in allowed:
        raise ValueError("invalid report name")
    with open(BASE / report_name) as f:
        return f.read()


@mcp.tool()
def read_mixed_safe_and_vulnerable(safe_name: str, other_path: str) -> str:
    """One properly guarded read alongside one that is never guarded at all, in the same function."""
    candidate = (BASE / safe_name).resolve()
    if not candidate.is_relative_to(BASE):
        raise ValueError("invalid report path")
    with open(candidate) as f:
        safe_data = f.read()
    with open(other_path) as f:  # VULNERABLE: never guarded
        unsafe_data = f.read()
    return safe_data + unsafe_data


@mcp.tool()
def read_guard_nested_in_condition(report_name: str, debug_mode: bool) -> str:
    candidate = (BASE / report_name).resolve()
    if debug_mode:
        if not candidate.is_relative_to(BASE):
            return "invalid"
    with open(candidate) as f:
        return f.read()


@mcp.tool()
def read_guard_with_conditional_exit(report_name: str, log_only: bool) -> str:
    candidate = (BASE / report_name).resolve()
    if not candidate.is_relative_to(BASE):
        if log_only:
            return "invalid"
    with open(candidate) as f:
        return f.read()


@mcp.tool()
def read_guard_inside_try(report_name: str) -> str:
    candidate = (BASE / report_name).resolve()
    try:
        if not candidate.is_relative_to(BASE):
            return "invalid"
    except Exception:
        pass
    with open(candidate) as f:
        return f.read()


@mcp.tool()
def read_nonterminating_guard(report_name: str) -> str:
    candidate = (BASE / report_name).resolve()
    if not candidate.is_relative_to(BASE):
        print("invalid")
    with open(candidate) as f:
        return f.read()


@mcp.tool()
def read_abspath_only(report_name: str) -> str:
    base = os.path.abspath("/srv/reports")
    candidate = os.path.abspath(os.path.join(base, report_name))
    if not Path(candidate).is_relative_to(Path(base)):
        return "invalid"
    with open(candidate) as f:
        return f.read()


@mcp.tool()
def read_normpath_only(report_name: str) -> str:
    base = os.path.normpath("/srv/reports")
    candidate = os.path.normpath(os.path.join(base, report_name))
    if not Path(candidate).is_relative_to(Path(base)):
        return "invalid"
    with open(candidate) as f:
        return f.read()
