"""First hop from tool.py -- itself calls into a second local file (deeper.py), which is out of scope for a one-hop analyzer."""

from .deeper import actually_dangerous


def forward_to_second_hop(cmd_label: str) -> str:
    return actually_dangerous(cmd_label)
