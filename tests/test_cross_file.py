import ast
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp_scanner.analyzer import MCPAnalyzer, _collect_local_imports, scan_file

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _rule_ids(findings):
    return {f.rule_id for f in findings}


def test_one_hop_detects_command_injection_in_imported_helper():
    path = os.path.join(FIXTURES, "cross_file_vulnerable", "tool_server.py")
    findings, errors = scan_file(path)
    assert errors == []
    hits = [f for f in findings if f.rule_id == "MCP001"]
    assert hits, f"expected a one-hop MCP001 finding, got: {[f.rule_id for f in findings]}"


def test_one_hop_finding_points_at_the_callee_file_and_function():
    path = os.path.join(FIXTURES, "cross_file_vulnerable", "tool_server.py")
    findings, _ = scan_file(path)
    hit = next(f for f in findings if f.rule_id == "MCP001")
    assert hit.function_name == "run_backup_command"
    assert hit.file is not None
    assert os.path.basename(hit.file) == "helper.py"
    assert "one-hop" in hit.detail
    assert "backup()" in hit.detail  # names the originating tool


def test_one_hop_finding_line_number_is_within_the_helper_file():
    path = os.path.join(FIXTURES, "cross_file_vulnerable", "tool_server.py")
    helper_path = os.path.join(FIXTURES, "cross_file_vulnerable", "helper.py")
    findings, _ = scan_file(path)
    hit = next(f for f in findings if f.rule_id == "MCP001")
    with open(helper_path, encoding="utf-8") as f:
        helper_lines = f.read().splitlines()
    assert "subprocess.run" in helper_lines[hit.line - 1]


def test_safe_cross_file_fixture_has_no_findings():
    # Regression-style guard: the helper validates label with an allowlist
    # and uses the safe argv-list subprocess pattern -- the one-hop check
    # must reuse the same guard-clause logic a single-file tool gets.
    path = os.path.join(FIXTURES, "cross_file_safe", "tool_server.py")
    findings, errors = scan_file(path)
    assert errors == []
    assert findings == [], f"expected no findings, got: {[f.rule_id for f in findings]}"


def test_two_hops_is_out_of_scope():
    # The real sink lives in deeper.py, two calls away from the tainted
    # tool parameter (tool.py -> helper.py -> deeper.py). A one-hop
    # analyzer must NOT find it -- this is the explicitly documented scope
    # boundary, not a bug.
    path = os.path.join(FIXTURES, "cross_file_two_hops", "tool.py")
    findings, errors = scan_file(path)
    assert errors == []
    assert findings == [], f"expected no findings (sink is two hops away), got: {[f.rule_id for f in findings]}"


def test_scan_file_without_file_path_does_not_attempt_resolution():
    # MCPAnalyzer used directly on an inline AST (no real file on disk, as
    # several tests elsewhere in this suite do) has no directory to resolve
    # imports against -- cross-file resolution must no-op, not crash.
    src = '''
from fastmcp import FastMCP
from .helper import run_backup_command

mcp = FastMCP("x")

@mcp.tool()
def backup(label: str) -> str:
    """Run a backup."""
    return run_backup_command(label)
'''
    tree = ast.parse(src)
    analyzer = MCPAnalyzer(src)  # no file_path
    analyzer.visit(tree)
    assert analyzer.findings == []


def test_collect_local_imports_plain_import(tmp_path):
    (tmp_path / "helper.py").write_text("def f(x): pass\n")
    tree = ast.parse("import helper\n")
    module_map, name_map = _collect_local_imports(tree, str(tmp_path))
    assert module_map == {"helper": str(tmp_path / "helper.py")}
    assert name_map == {}


def test_collect_local_imports_from_dot_import(tmp_path):
    (tmp_path / "helper.py").write_text("def f(x): pass\n")
    tree = ast.parse("from . import helper\n")
    module_map, name_map = _collect_local_imports(tree, str(tmp_path))
    assert module_map == {"helper": str(tmp_path / "helper.py")}


def test_collect_local_imports_from_dot_module_import_name(tmp_path):
    (tmp_path / "helper.py").write_text("def f(x): pass\n")
    tree = ast.parse("from .helper import f\n")
    module_map, name_map = _collect_local_imports(tree, str(tmp_path))
    assert name_map == {"f": (str(tmp_path / "helper.py"), "f")}


def test_collect_local_imports_flat_non_relative(tmp_path):
    (tmp_path / "helper.py").write_text("def f(x): pass\n")
    tree = ast.parse("from helper import f\n")
    module_map, name_map = _collect_local_imports(tree, str(tmp_path))
    assert name_map == {"f": (str(tmp_path / "helper.py"), "f")}


def test_collect_local_imports_ignores_nonexistent_module(tmp_path):
    # No helper.py on disk -- must not guess. Also covers the common case
    # of importing a real third-party/stdlib package that happens to share
    # a name with nothing local.
    tree = ast.parse("from helper import f\nimport os\n")
    module_map, name_map = _collect_local_imports(tree, str(tmp_path))
    assert module_map == {}
    assert name_map == {}


def test_collect_local_imports_respects_aliases(tmp_path):
    (tmp_path / "helper.py").write_text("def f(x): pass\n")
    tree = ast.parse("from .helper import f as run_it\n")
    module_map, name_map = _collect_local_imports(tree, str(tmp_path))
    assert name_map == {"run_it": (str(tmp_path / "helper.py"), "f")}
