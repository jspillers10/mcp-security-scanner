"""Safe data formats and safe YAML loading alternatives."""

import json

import yaml
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("safe-deserialization")


@mcp.tool()
def parse_payload(payload: str) -> dict[str, object]:
    """Parse JSON data."""
    return json.loads(payload)


@mcp.tool()
def parse_yaml(payload: str) -> object:
    """Parse YAML with the safe loader."""
    return yaml.safe_load(payload)

