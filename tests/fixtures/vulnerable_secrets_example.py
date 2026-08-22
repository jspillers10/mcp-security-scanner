"""
Fixture exercising MCP004 detection beyond a single-line `KEY = "value"`
assignment: multiline credential text, dictionary values keyed by a
secret-shaped name, and nested literal containers. All values below are
fabricated for this fixture and are not derived from any external corpus.
"""

from fastmcp import FastMCP

mcp = FastMCP("demo-secret-bundle-server")


@mcp.tool()
def write_ops_notes() -> str:
    """Write an internal ops memo to disk.

    VULNERABLE: the credentials below are embedded directly in a multiline
    string, not in a `key = "value"` assignment, so a line-oriented
    single-assignment regex never sees them.
    """
    with open("/tmp/ops_notes.txt", "w") as f:
        f.write(
            """
INTERNAL OPS NOTES - DO NOT SHARE
----------------------------------
Database Host: db.northwind.internal
Database Password: Nw-Prod-8f3k2m9x
Backup Service API Key: bsvc_live_7h2j9k4m1p6q3r8t
"""
        )
    return "written"


@mcp.tool()
def register_integrations() -> str:
    """Register third-party integration credentials.

    VULNERABLE: secrets live as dictionary values under secret-shaped keys,
    including one level of nesting (a dict of per-service credential dicts).
    """
    integrations = {
        "billing_service": {
            "service_name": "Northwind Billing",
            "api_key": "nwb_live_9d8c7b6a5e4f3g2h1i",
            "access_token": "ntok_9f8e7d6c5b4a3f2e1d0c",
        },
        "shipping_service": {
            "service_name": "Northwind Shipping",
            "api_key": "nws_live_1a2b3c4d5e6f7g8h9i",
        },
    }
    return f"registered {len(integrations)} integrations"


def build_admin_bundle() -> dict:
    """One logical credential bundle with several secret-shaped fields.

    VULNERABLE: expected to produce exactly one MCP004 finding for this
    dict literal, not one per field -- see docs/benchmark.md's counting
    rule for a logical credential bundle.
    """
    return {
        "password": "Nw-Admin-6q1w2e3r",
        "api_key": "nwa_live_4t5y6u7i8o9p0a1s",
        "secret": "nws_live_2d3f4g5h6j7k8l9z",
    }
