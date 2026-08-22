"""
Fixture exercising MCP004 boundaries: shapes that must NOT be flagged as a
hardcoded secret. Pairs with vulnerable_secrets_example.py.
"""

import os

from fastmcp import FastMCP

mcp = FastMCP("demo-safe-secret-boundaries-server")

# Environment-variable access: no literal secret value is present in source.
DB_PASSWORD = os.getenv("DB_PASSWORD")
BILLING_API_KEY = os.environ.get("BILLING_API_KEY", "")


def build_config() -> dict:
    """Ordinary, non-secret configuration values."""
    return {
        "timeout_seconds": 30,
        "max_retries": 3,
        "host": "localhost",
        "debug": False,
    }


def build_placeholder_credentials() -> dict:
    """Placeholder values a template or example file ships with."""
    return {
        "password": "changeme",
        "api_key": "YOUR_API_KEY_HERE",
        "token": "<insert-token-here>",
    }


@mcp.tool()
def integration_help() -> str:
    """Explain how a Northwind integration token is shaped.

    A typical value looks like:
    Token: ntok_5f6e7d8c9b0a1f2e3d4c

    This docstring is documentation only; no real credential is stored
    here, and the scanner does not treat docstring text as source data.
    """
    return "see the integration guide"
