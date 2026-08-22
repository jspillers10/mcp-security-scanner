"""
MCP003 duplicate-finding suppression: the same physical sink call site
must not be reported twice just because a direct scan and a one-hop
cross-call resolution both reach it. Genuinely distinct sinks -- separate
tools, or two calls on the same line -- must not be collapsed.

Fixtures are independently designed for this repository, not copied from
DVMCP -- see vulnerable_duplicate_sink.py / vulnerable_distinct_sinks.py.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp_scanner.analyzer import scan_file

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _mcp003(findings):
    return [f for f in findings if f.rule_id == "MCP003"]


def test_same_sink_reached_two_ways_is_reported_once():
    findings, errors = scan_file(os.path.join(FIXTURES, "vulnerable_duplicate_sink.py"))
    assert errors == []
    hits = _mcp003(findings)
    assert len(hits) == 1, f"expected exactly one MCP003 finding, got {len(hits)}: {[(f.line, f.detail) for f in hits]}"


def test_duplicate_finding_keeps_the_direct_detail_not_only_the_one_hop_copy():
    # Whichever copy survives, it must still point at the real sink line
    # inside risky_server's compute(), not some other location.
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_duplicate_sink.py"))
    hits = _mcp003(findings)
    assert hits[0].function_name == "compute"


def test_distinct_tools_each_keep_their_own_finding():
    findings, errors = scan_file(os.path.join(FIXTURES, "vulnerable_distinct_sinks.py"))
    assert errors == []
    hits = _mcp003(findings)
    function_names = {f.function_name for f in hits}
    assert "run_math" in function_names
    assert "run_formula" in function_names


def test_two_sinks_on_the_same_line_are_both_kept():
    # run_pair_same_line has two eval() calls sharing one lineno; only
    # column offset distinguishes them. Both must survive dedup.
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_distinct_sinks.py"))
    hits = [f for f in _mcp003(findings) if f.function_name == "run_pair_same_line"]
    assert len(hits) == 2, f"expected both same-line eval() calls kept, got {len(hits)}: {hits}"
    assert hits[0].line == hits[1].line
    assert hits[0].col_offset != hits[1].col_offset


def test_full_fixture_finding_count_matches_distinct_sink_count():
    # Sanity check on the whole file: 2 (run_math, run_formula) + 2
    # (run_pair_same_line) = 4 distinct eval() sinks, no more, no fewer.
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_distinct_sinks.py"))
    assert len(_mcp003(findings)) == 4
