"""
MCP002 path-validation reasoning: an existence check, extension check,
string-prefix check, or denylist must not by itself suppress an
arbitrary-path finding. Canonical resolution combined with containment
(Path.is_relative_to / parents), or an exact allowlist, must still
suppress it.

Fixtures are independently designed for this repository, not copied from
DVMCP -- see vulnerable_path_validation.py / safe_path_validation.py.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp_scanner.analyzer import scan_file

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _mcp002(findings):
    return {f.function_name for f in findings if f.rule_id == "MCP002"}


def test_existence_check_alone_does_not_suppress_finding():
    findings, errors = scan_file(os.path.join(FIXTURES, "vulnerable_path_validation.py"))
    assert errors == []
    assert "read_by_existence_check" in _mcp002(findings)


def test_extension_check_alone_does_not_suppress_finding():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_path_validation.py"))
    assert "read_by_extension_check" in _mcp002(findings)


def test_raw_prefix_check_does_not_suppress_finding():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_path_validation.py"))
    assert "read_by_prefix_check" in _mcp002(findings)


def test_denylist_check_does_not_suppress_finding():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_path_validation.py"))
    assert "read_by_denylist_check" in _mcp002(findings)


def test_all_weak_and_unsound_guards_are_flagged():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_path_validation.py"))
    hits = _mcp002(findings)
    expected = {
        "read_by_existence_check",
        "read_by_extension_check",
        "read_by_prefix_check",
        "read_by_denylist_check",
        "read_guard_after_sink",
        "read_inverted_guard",
        "read_unresolved_is_relative_to",
        "read_unresolved_parents",
        "read_user_controlled_allowlist",
        "read_dynamic_allowlist",
        "read_mixed_safe_and_vulnerable",
        "read_guard_nested_in_condition",
        "read_guard_with_conditional_exit",
        "read_guard_inside_try",
        "read_nonterminating_guard",
        "read_abspath_only",
        "read_normpath_only",
    }
    assert hits == expected, f"expected {expected}, got: {hits}"


def test_canonical_resolution_and_containment_suppresses_finding():
    findings, errors = scan_file(os.path.join(FIXTURES, "safe_path_validation.py"))
    assert errors == []
    assert "read_resolved_report" not in _mcp002(findings)


def test_exact_allowlist_suppresses_finding():
    findings, _ = scan_file(os.path.join(FIXTURES, "safe_path_validation.py"))
    assert "read_allowlisted_report" not in _mcp002(findings)


def test_safe_fixture_has_no_path_findings():
    findings, _ = scan_file(os.path.join(FIXTURES, "safe_path_validation.py"))
    assert _mcp002(findings) == set(), f"expected no MCP002 findings, got: {_mcp002(findings)}"


def test_existing_strong_guard_regressions_still_pass():
    # Regression: the two strong shapes already relied on elsewhere in the
    # test suite (parents-based containment, exact set membership) must
    # still suppress after narrowing the guard classifier.
    findings, _ = scan_file(os.path.join(FIXTURES, "safe_example.py"))
    assert "read_report" not in _mcp002(findings)


# -- Control-flow correctness: ordering, polarity, canonicalization, trust --


def test_guard_placed_after_the_sink_does_not_suppress_finding():
    findings, errors = scan_file(os.path.join(FIXTURES, "vulnerable_path_validation.py"))
    assert errors == []
    assert "read_guard_after_sink" in _mcp002(findings), "a guard after the sink must not suppress the finding"


def test_inverted_guard_that_returns_when_safe_does_not_suppress_finding():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_path_validation.py"))
    assert "read_inverted_guard" in _mcp002(findings), (
        "a guard that returns on the SAFE branch and falls through to the sink on the unsafe branch must be flagged"
    )


def test_unresolved_is_relative_to_does_not_suppress_finding():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_path_validation.py"))
    assert "read_unresolved_is_relative_to" in _mcp002(findings), (
        "is_relative_to() on an uncanonicalized candidate must not suppress the finding"
    )


def test_unresolved_parents_membership_does_not_suppress_finding():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_path_validation.py"))
    assert "read_unresolved_parents" in _mcp002(findings), (
        "a .parents membership check on an uncanonicalized candidate must not suppress the finding"
    )


def test_user_controlled_allowlist_does_not_suppress_finding():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_path_validation.py"))
    assert "read_user_controlled_allowlist" in _mcp002(findings), (
        "an allowlist built from a tool parameter must not be treated as trusted"
    )


def test_dynamic_allowlist_does_not_suppress_finding():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_path_validation.py"))
    assert "read_dynamic_allowlist" in _mcp002(findings), (
        "an allowlist loaded at call time is not a fixed developer-controlled literal"
    )


def test_mixed_function_flags_only_the_unguarded_sink():
    # One function with a properly guarded read and a never-guarded read:
    # exactly one MCP002 finding, for the unguarded sink specifically.
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_path_validation.py"))
    hits = [f for f in findings if f.rule_id == "MCP002" and f.function_name == "read_mixed_safe_and_vulnerable"]
    assert len(hits) == 1, f"expected exactly one finding for the unguarded sink, got {len(hits)}: {hits}"


def test_nested_guard_does_not_suppress_finding():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_path_validation.py"))
    assert "read_guard_nested_in_condition" in _mcp002(findings)


def test_conditionally_terminating_guard_does_not_suppress_finding():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_path_validation.py"))
    assert "read_guard_with_conditional_exit" in _mcp002(findings)


def test_exception_handled_guard_does_not_suppress_finding():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_path_validation.py"))
    assert "read_guard_inside_try" in _mcp002(findings)


def test_nonterminating_guard_does_not_suppress_finding():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_path_validation.py"))
    assert "read_nonterminating_guard" in _mcp002(findings)


def test_abspath_only_containment_does_not_suppress_finding():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_path_validation.py"))
    assert "read_abspath_only" in _mcp002(findings)


def test_normpath_only_containment_does_not_suppress_finding():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_path_validation.py"))
    assert "read_normpath_only" in _mcp002(findings)
