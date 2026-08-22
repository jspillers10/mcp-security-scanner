"""
MCP004 hardcoded-secret detection: multiline bundles, dictionary values
keyed by a secret-shaped name, nested containers, and the safe boundaries
around them (placeholders, env-var access, non-secret dicts, docstrings).

Fixtures are independently designed for this repository, not copied from
DVMCP -- see vulnerable_secrets_example.py / safe_secrets_example.py.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp_scanner.analyzer import _is_secret_shaped_name, scan_file

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _mcp004(findings):
    return [f for f in findings if f.rule_id == "MCP004"]


def test_multiline_credential_bundle_detected():
    findings, errors = scan_file(os.path.join(FIXTURES, "vulnerable_secrets_example.py"))
    assert errors == []
    hits = _mcp004(findings)
    assert hits, "expected an MCP004 finding for the multiline credential bundle"


def test_multiline_credential_bundle_is_one_finding_not_one_per_line():
    # The multiline string in write_ops_notes() contains three separately
    # labeled secret-shaped lines (host is not secret-shaped, password and
    # API key are). It must count as one logical bundle.
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_secrets_example.py"))
    hits = [f for f in _mcp004(findings) if 20 <= f.line <= 30]
    assert len(hits) == 1, f"expected exactly one bundle finding, got {len(hits)}: {[f.line for f in hits]}"


def test_dict_value_under_secret_key_detected():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_secrets_example.py"))
    hits = _mcp004(findings)
    assert any(f.function_name != "(module level)" or True for f in hits)
    # At least one finding should correspond to the nested integrations dict.
    assert any(30 <= f.line <= 45 for f in hits), f"expected a finding near the integrations dict, got {hits}"


def test_nested_dict_reported_once_not_per_nested_field():
    # register_integrations() builds one dict containing two nested
    # per-service credential dicts (five secret-shaped fields total). This
    # is one logical registration event -- one outer finding, not five.
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_secrets_example.py"))
    hits = [f for f in _mcp004(findings) if 30 <= f.line <= 45]
    assert len(hits) == 1, f"expected exactly one finding for the nested dict, got {len(hits)}: {hits}"


def test_flat_dict_bundle_with_multiple_fields_is_one_finding():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_secrets_example.py"))
    hits = [f for f in _mcp004(findings) if 55 <= f.line <= 67]
    assert len(hits) == 1, f"expected exactly one finding for the admin bundle, got {len(hits)}: {hits}"


def test_safe_fixture_has_no_secret_findings():
    findings, errors = scan_file(os.path.join(FIXTURES, "safe_secrets_example.py"))
    assert errors == []
    hits = _mcp004(findings)
    assert hits == [], f"expected no MCP004 findings, got: {[(f.line, f.detail) for f in hits]}"


def test_env_var_access_not_flagged():
    findings, _ = scan_file(os.path.join(FIXTURES, "safe_secrets_example.py"))
    hits = [f for f in _mcp004(findings) if f.line <= 14]
    assert hits == [], f"os.getenv/os.environ.get access must not be flagged, got: {hits}"


def test_non_secret_config_dict_not_flagged():
    findings, _ = scan_file(os.path.join(FIXTURES, "safe_secrets_example.py"))
    hits = [f for f in _mcp004(findings) if 15 <= f.line <= 22]
    assert hits == [], f"a config dict with no secret-shaped keys must not be flagged, got: {hits}"


def test_placeholder_values_not_flagged():
    findings, _ = scan_file(os.path.join(FIXTURES, "safe_secrets_example.py"))
    hits = [f for f in _mcp004(findings) if 25 <= f.line <= 31]
    assert hits == [], f"placeholder credential values must not be flagged, got: {hits}"


def test_docstring_credential_shaped_text_not_flagged():
    findings, _ = scan_file(os.path.join(FIXTURES, "safe_secrets_example.py"))
    hits = [f for f in _mcp004(findings) if 34 <= f.line <= 45]
    assert hits == [], f"credential-shaped text inside a docstring must not be flagged, got: {hits}"


def test_simple_single_line_secret_assignment_still_detected():
    # Regression: the pre-existing simple `KEY = "value"` shape must still
    # be caught by the AST-based rewrite.
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_example.py"))
    assert "MCP004" in {f.rule_id for f in findings}


# -- Derived-value exclusion: exact final-word match, not substring match --


def test_password_hash_is_not_treated_as_plaintext_password():
    assert _is_secret_shaped_name("password_hash") is False


def test_token_digest_is_not_treated_as_plaintext_token():
    assert _is_secret_shaped_name("token_digest") is False


def test_config_checksum_is_not_treated_as_secret():
    assert _is_secret_shaped_name("config_checksum") is False


def test_hashicorp_token_remains_detectable():
    # "hash" appears inside "hashicorp", but it is not the name's own
    # final word -- a substring check would wrongly exclude this.
    assert _is_secret_shaped_name("HASHICORP_TOKEN") is True


def test_ordinary_word_containing_hash_is_not_silently_excluded():
    # "hashtag" contains "hash" as a substring but the name's final word
    # is "secret", which must still be detected.
    assert _is_secret_shaped_name("hashtag_secret") is True


def test_derived_value_fixture_has_no_secret_findings():
    findings, errors = scan_file(os.path.join(FIXTURES, "safe_secrets_derived_values.py"))
    assert errors == []
    hits = _mcp004(findings)
    assert hits == [], f"expected password_hash/token_digest/config_checksum excluded, got: {hits}"


def test_hashicorp_token_fixture_is_detected():
    findings, errors = scan_file(os.path.join(FIXTURES, "vulnerable_secrets_hashicorp_token.py"))
    assert errors == []
    assert "MCP004" in {f.rule_id for f in findings}
