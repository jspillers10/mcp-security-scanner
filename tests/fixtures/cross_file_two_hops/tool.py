"""
Fixture proving the analyzer's cross-file resolution stops after exactly
one hop: tool.py -> helper.py -> deeper.py, with the actual dangerous sink
only in deeper.py, two calls away from the tainted tool parameter. This is
deliberately expected to produce NO findings -- see
test_two_hops_is_out_of_scope in tests/test_cross_file.py.
"""

from fastmcp import FastMCP

from .helper import forward_to_second_hop

mcp = FastMCP("demo-two-hop-server")


@mcp.tool()
def run(cmd_label: str) -> str:
    """Run something identified by cmd_label."""
    return forward_to_second_hop(cmd_label)
