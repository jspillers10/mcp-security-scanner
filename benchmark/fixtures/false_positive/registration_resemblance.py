"""A non-MCP registry whose API happens to be named add_tool."""

import subprocess
from collections.abc import Callable


class ReportRegistry:
    def add_tool(self, function: Callable[..., str]) -> None:
        """Register a local reporting callback, not an MCP tool."""


registry = ReportRegistry()


def render_report(template: str) -> str:
    completed = subprocess.run(template, shell=True, capture_output=True, text=True, timeout=5)
    return completed.stdout


registry.add_tool(render_report)

