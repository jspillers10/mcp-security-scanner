"""
MCP001 command-validation reasoning: a partial denylist must not suppress
a command-injection finding. A fixed command allowlist, or a fixed lookup
table where the tainted parameter only selects among fixed literal
commands, must still suppress it.

Fixtures are independently designed for this repository, not copied from
DVMCP -- see vulnerable_command_validation.py / safe_command_validation.py.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp_scanner.analyzer import scan_file

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
BENCHMARK_FIXTURES = os.path.join(os.path.dirname(__file__), "..", "benchmark", "fixtures")


def _mcp001(findings):
    return {f.function_name for f in findings if f.rule_id == "MCP001"}


def test_partial_denylist_does_not_suppress_finding():
    findings, errors = scan_file(os.path.join(FIXTURES, "vulnerable_command_validation.py"))
    assert errors == []
    assert "run_diagnostic_command" in _mcp001(findings)


def test_exact_command_allowlist_suppresses_finding():
    findings, errors = scan_file(os.path.join(FIXTURES, "safe_command_validation.py"))
    assert errors == []
    assert "service_action" not in _mcp001(findings)


def test_fixed_command_lookup_table_suppresses_finding():
    # The tainted parameter only ever selects among fixed literal command
    # strings in the dict -- its own content never reaches the shell sink.
    findings, _ = scan_file(os.path.join(FIXTURES, "safe_command_validation.py"))
    assert "run_named_diagnostic" not in _mcp001(findings)


def test_safe_fixture_has_no_command_findings():
    findings, _ = scan_file(os.path.join(FIXTURES, "safe_command_validation.py"))
    assert _mcp001(findings) == set(), f"expected no MCP001 findings, got: {_mcp001(findings)}"


def test_fixed_argv_list_still_not_flagged():
    # Regression: the pre-existing shell=False argv-list case must still
    # be safe after narrowing the guard classifier.
    findings, _ = scan_file(os.path.join(BENCHMARK_FIXTURES, "false_positive", "safe_subprocess_args.py"))
    assert _mcp001(findings) == set()


# -- Control-flow correctness: ordering, polarity, trust --


def test_guard_after_the_shell_sink_does_not_suppress_finding():
    findings, errors = scan_file(os.path.join(FIXTURES, "vulnerable_command_validation.py"))
    assert errors == []
    assert "run_guard_after_sink" in _mcp001(findings), "an allowlist check after the sink must not suppress it"


def test_inverted_allowlist_logic_does_not_suppress_finding():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_command_validation.py"))
    assert "run_inverted_allowlist" in _mcp001(findings), (
        "a guard that returns on the ALLOWED branch and falls through to the sink otherwise must be flagged"
    )


def test_user_controlled_allowlist_does_not_suppress_finding():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_command_validation.py"))
    assert "run_user_controlled_allowlist" in _mcp001(findings), (
        "an allowlist built from a tool parameter must not be treated as trusted"
    )


def test_dynamic_allowlist_does_not_suppress_finding():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_command_validation.py"))
    assert "run_dynamic_allowlist" in _mcp001(findings), (
        "an allowlist loaded at call time is not a fixed developer-controlled literal"
    )


def test_character_filtering_that_still_permits_dangerous_shell_behavior_is_flagged():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_command_validation.py"))
    assert "run_character_filter_still_dangerous" in _mcp001(findings), (
        "rejecting only whitespace still leaves shell metacharacters unfiltered"
    )


def test_mixed_function_flags_only_the_unguarded_sink():
    # One function with a properly allowlisted call and a never-guarded
    # call: exactly one MCP001 finding, for the unguarded sink.
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_command_validation.py"))
    hits = [f for f in findings if f.rule_id == "MCP001" and f.function_name == "run_mixed_safe_and_vulnerable"]
    assert len(hits) == 1, f"expected exactly one finding for the unguarded sink, got {len(hits)}: {hits}"


def test_nested_allowlist_guard_does_not_suppress_finding():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_command_validation.py"))
    assert "run_guard_nested_in_condition" in _mcp001(findings)


def test_conditionally_terminating_allowlist_guard_does_not_suppress_finding():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_command_validation.py"))
    assert "run_guard_with_conditional_exit" in _mcp001(findings)


def test_exception_handled_allowlist_guard_does_not_suppress_finding():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_command_validation.py"))
    assert "run_guard_inside_try" in _mcp001(findings)


def test_nonterminating_allowlist_guard_does_not_suppress_finding():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_command_validation.py"))
    assert "run_nonterminating_guard" in _mcp001(findings)
