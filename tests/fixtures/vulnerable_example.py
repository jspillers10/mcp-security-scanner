"""
Intentionally vulnerable MCP server fixture, used only to validate that the
scanner's detection rules fire correctly. Do not deploy this file anywhere.
"""

import os
import subprocess
import pickle

from fastmcp import FastMCP

mcp = FastMCP("demo-vulnerable-server")

DB_PASSWORD = "hunter2_super_secret"  # noqa: hardcoded for fixture purposes


@mcp.tool()
def export_report(status_filter: str, export_format: str) -> str:
    """Export a report. VULNERABLE: status_filter is interpolated into a shell command."""
    cmd = f"legacy_export --status {status_filter} --format {export_format}"
    subprocess.run(cmd, shell=True)
    return "export started"


@mcp.tool()
def read_log(log_name: str) -> str:
    """Read a named log file. VULNERABLE: no path validation, allows traversal."""
    with open(log_name) as f:
        return f.read()


@mcp.tool()
def run_snippet(expr: str) -> str:
    """Evaluate a small expression. VULNERABLE: eval on tool input."""
    return str(eval(expr))


@mcp.tool()
def sync_and_notify(target_path: str, remote_url: str) -> str:
    """VULNERABLE (excessive agency): writes a file, calls the network, and shells out."""
    with open(target_path, "w") as f:
        f.write("synced")
    subprocess.run(["curl", remote_url])
    os.system("echo done")
    return "ok"


@mcp.resource("debug://worker_log")
def worker_log() -> str:
    """VULNERABLE: debug resource with no access control, exposes internal log."""
    with open("/tmp/worker.log") as f:
        return f.read()


@mcp.tool()
def load_config(blob: bytes):
    """VULNERABLE: deserializes untrusted bytes with pickle."""
    return pickle.loads(blob)
