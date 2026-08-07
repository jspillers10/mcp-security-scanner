import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp_scanner import cli
from mcp_scanner.readiness import check_security_md, scan_file

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _check_ids(findings):
    return {f.check_id for f in findings}


def test_safe_fixture_has_no_readiness_findings():
    findings, errors = scan_file(os.path.join(FIXTURES, "safe_readiness_example.py"))
    assert errors == []
    assert findings == [], f"expected no readiness findings, got: {[f.check_id for f in findings]}"


def test_vulnerable_fixture_detects_zero_bind():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_readiness_example.py"))
    assert "RDY001" in _check_ids(findings)


def test_vulnerable_fixture_detects_missing_auth():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_readiness_example.py"))
    assert "RDY002" in _check_ids(findings)


def test_vulnerable_fixture_detects_privileged_port():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_readiness_example.py"))
    assert "RDY004" in _check_ids(findings)


def test_vulnerable_fixture_detects_debug_enabled():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_readiness_example.py"))
    assert "RDY005" in _check_ids(findings)


def test_vulnerable_fixture_detects_reload_enabled():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_readiness_example.py"))
    assert "RDY006" in _check_ids(findings)


def test_readiness_findings_have_no_saif_fields():
    # Structural guard: ReadinessFinding must stay a distinct shape from
    # analyzer.Finding (no rule_id/saif_category/function_name), so it can
    # never be silently merged into the vulnerability-findings list.
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_readiness_example.py"))
    assert findings
    assert not hasattr(findings[0], "saif_category")
    assert not hasattr(findings[0], "rule_id")


def test_check_security_md_absent(tmp_path):
    finding = check_security_md(str(tmp_path))
    assert finding is not None
    assert finding.check_id == "RDY003"


def test_check_security_md_present(tmp_path):
    (tmp_path / "SECURITY.md").write_text("# Security Policy\n")
    finding = check_security_md(str(tmp_path))
    assert finding is None


def test_check_security_md_case_insensitive(tmp_path):
    (tmp_path / "security.md").write_text("# Security Policy\n")
    finding = check_security_md(str(tmp_path))
    assert finding is None


def test_check_security_md_returns_none_for_a_file_path(tmp_path):
    single_file = tmp_path / "server.py"
    single_file.write_text("x = 1\n")
    assert check_security_md(str(single_file)) is None


def test_cli_runs_security_md_check_once_per_directory_not_per_file(tmp_path, capsys):
    # Two source files, neither vulnerable to anything, no SECURITY.md.
    (tmp_path / "server_a.py").write_text("x = 1\n")
    (tmp_path / "server_b.py").write_text("y = 2\n")

    try:
        cli.main([str(tmp_path)])
    except SystemExit:
        pass

    output = capsys.readouterr().out
    assert output.count("RDY003") == 1, f"expected exactly one RDY003 mention, got output:\n{output}"


def test_cli_omits_security_md_finding_when_present(tmp_path, capsys):
    (tmp_path / "SECURITY.md").write_text("# Security Policy\n")
    (tmp_path / "server_a.py").write_text("x = 1\n")

    try:
        cli.main([str(tmp_path)])
    except SystemExit:
        pass

    output = capsys.readouterr().out
    assert "RDY003" not in output


def test_report_separates_readiness_section_from_findings():
    from mcp_scanner.analyzer import scan_file as scan_vulnerabilities
    from mcp_scanner.report import format_text

    path = os.path.join(FIXTURES, "vulnerable_readiness_example.py")
    findings, errors = scan_vulnerabilities(path)
    readiness, _ = scan_file(path)
    text = format_text(path, findings, errors, readiness)
    assert "Readiness (risky defaults" in text
    # The severity summary line is derived only from `findings`, not
    # readiness -- confirm the two never get merged into one count.
    readiness_section_index = text.index("Readiness (risky defaults")
    assert "RDY001" not in text[:readiness_section_index]
