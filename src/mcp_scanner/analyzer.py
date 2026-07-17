"""
AST-based static analyzer for MCP server source files.

Approach
--------
1. Find functions decorated with a recognized MCP tool/resource decorator
   (e.g. @mcp.tool(), @tool(), @server.resource(...)).
2. For tool functions, track their parameter names as "tainted" inputs.
3. Walk the function body looking for dangerous sink calls (subprocess,
   os.system, eval/exec, open, pickle.loads, yaml.load) and check whether a
   tainted parameter name reaches the sink's arguments -- directly, through
   an f-string / JoinedStr, through string concatenation, or through
   str.format().
4. For resource functions, flag names that look like debug/log/admin
   endpoints regardless of taint, since the risk is exposure of the
   resource itself.

This is a lightweight, best-effort static analysis -- it favors clear,
explainable findings over exhaustive dataflow precision. False negatives are
expected on heavily obfuscated code; false positives are expected on code
that re-implements sanitization in a way the analyzer doesn't recognize.
"""

import ast
from dataclasses import dataclass, field

from .rules import RULES

TOOL_DECORATOR_NAMES = {"tool"}
RESOURCE_DECORATOR_NAMES = {"resource"}

SHELL_SINKS = {
    ("subprocess", "run"),
    ("subprocess", "call"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
    ("subprocess", "Popen"),
    ("os", "system"),
    ("os", "popen"),
}
EVAL_SINKS = {("__builtin__", "eval"), ("__builtin__", "exec")}
FILE_SINKS = {("__builtin__", "open")}
DESERIALIZE_SINKS = {
    ("pickle", "loads"),
    ("pickle", "load"),
    ("yaml", "load"),
    ("marshal", "loads"),
}

SENSITIVE_RESOURCE_KEYWORDS = ("debug", "log", "admin", "internal", "secret", "config", "token", "auth", "credential", "confidential", "private")

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key"),
    (r"(?i)(api[_-]?key|apikey)\s*=\s*['\"][A-Za-z0-9_\-]{12,}['\"]", "API key"),
    (r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]", "hardcoded password"),
    (r"(?i)(secret|token)\s*=\s*['\"][A-Za-z0-9_\-\.]{8,}['\"]", "secret/token"),
    (r"[a-zA-Z0-9_.+-]+://[^:\s]+:[^@\s]+@[^\s'\"]+", "credential in connection string"),
]


@dataclass
class Finding:
    rule_id: str
    line: int
    function_name: str
    detail: str
    severity: str = field(init=False)
    saif_category: str = field(init=False)
    saif_code: str = field(init=False)
    title: str = field(init=False)

    def __post_init__(self):
        rule = RULES[self.rule_id]
        self.severity = rule.severity
        self.saif_category = rule.saif_category
        self.saif_code = rule.saif_code
        self.title = rule.title


def _decorator_names(node):
    names = []
    for dec in node.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(target, ast.Attribute):
            names.append(target.attr)
        elif isinstance(target, ast.Name):
            names.append(target.id)
    return names


def _decorator_string_args(node):
    """Collect string literal arguments passed to decorators, e.g. @mcp.resource('debug://x')."""
    args = []
    for dec in node.decorator_list:
        if isinstance(dec, ast.Call):
            for a in dec.args:
                if isinstance(a, ast.Constant) and isinstance(a.value, str):
                    args.append(a.value)
    return args


def _call_target(call_node):
    """Return (module_or_obj, attr) for a Call node like subprocess.run(...) or a bare eval(...)."""
    func = call_node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return (func.value.id, func.attr)
    if isinstance(func, ast.Name):
        return ("__builtin__", func.id)
    return (None, None)


def _names_in_subtree(node, tainted_names):
    """Return True if any Name node in this subtree matches a tainted parameter name."""
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in tainted_names:
            return True
    return False


def _has_shell_true(call_node):
    for kw in call_node.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


class MCPAnalyzer(ast.NodeVisitor):
    def __init__(self, source: str):
        self.source = source
        self.findings = []

    def visit_FunctionDef(self, node):
        decorators = _decorator_names(node)
        is_tool = any(d in TOOL_DECORATOR_NAMES for d in decorators)
        is_resource = any(d in RESOURCE_DECORATOR_NAMES for d in decorators)

        if is_resource:
            self._check_resource(node)

        if is_tool:
            tainted = {arg.arg for arg in node.args.args if arg.arg != "self"}
            self._check_tool_body(node, tainted)

        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def _check_resource(self, node):
        uris = _decorator_string_args(node) + [node.name]
        for uri in uris:
            lowered = uri.lower()
            if any(kw in lowered for kw in SENSITIVE_RESOURCE_KEYWORDS):
                self.findings.append(
                    Finding(
                        rule_id="MCP005",
                        line=node.lineno,
                        function_name=node.name,
                        detail=f"resource '{uri}' looks like it exposes internal state",
                    )
                )
                return

    def _propagate_taint(self, node, tainted):
        """Extend the tainted set to local variables assigned from tainted expressions.

        Runs to a fixed point over simple `name = <expr>` assignments in
        execution order (as yielded by ast.walk, which is adequate for the
        straight-line code typical of MCP tool handlers). This is a
        best-effort approximation, not a full dataflow analysis.
        """
        tainted = set(tainted)
        changed = True
        while changed:
            changed = False
            for stmt in ast.walk(node):
                if isinstance(stmt, ast.Assign):
                    if _names_in_subtree(stmt.value, tainted):
                        for target in stmt.targets:
                            if isinstance(target, ast.Name) and target.id not in tainted:
                                tainted.add(target.id)
                                changed = True
                elif isinstance(stmt, ast.AugAssign):
                    if _names_in_subtree(stmt.value, tainted) and isinstance(stmt.target, ast.Name):
                        if stmt.target.id not in tainted:
                            tainted.add(stmt.target.id)
                            changed = True
        return tainted

    def _apply_validation_guards(self, node, tainted):
        """Best-effort recognition of guard-clause validation.

        If a name (or a name derived from it) is referenced in the test of an
        `if` block whose body raises or returns -- the common
        "if not valid(x): raise/return" pattern -- treat that name as
        validated for the rest of the function. This is deliberately
        approximate: it doesn't reason about which branch actually executes,
        only that a validation check exists somewhere against the value
        before it's used. That's enough to avoid flagging clearly-guarded
        code without requiring full control-flow analysis.
        """
        validated = set()
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.If):
                touches_tainted = _names_in_subtree(stmt.test, tainted)
                exits_early = any(
                    isinstance(s, (ast.Raise, ast.Return)) for s in ast.walk(stmt)
                )
                if touches_tainted and exits_early:
                    for n in ast.walk(stmt.test):
                        if isinstance(n, ast.Name) and n.id in tainted:
                            validated.add(n.id)
        return tainted - validated

    def _check_tool_body(self, node, tainted):
        tainted = self._propagate_taint(node, tainted)
        tainted = self._apply_validation_guards(node, tainted)
        sensitive_capabilities = set()

        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            module, attr = _call_target(child)
            if (module, attr) in SHELL_SINKS:
                sensitive_capabilities.add("process")
                tainted_reaches = any(_names_in_subtree(a, tainted) for a in child.args) or any(
                    _names_in_subtree(kw.value, tainted) for kw in child.keywords
                )
                always_shell = (module, attr) in {("os", "system"), ("os", "popen")}
                shell_true = _has_shell_true(child)
                # subprocess.* with an argv list and shell not set to True is the
                # standard safe pattern -- the shell never parses the string, so
                # metacharacters in a tainted argument aren't executed. Only flag
                # when a real shell is actually going to interpret the string.
                if tainted_reaches and (always_shell or shell_true):
                    detail = f"tainted parameter reaches {module}.{attr}("
                    detail += "shell=True)" if shell_true else ")"
                    self.findings.append(
                        Finding("MCP001", child.lineno, node.name, detail)
                    )
            elif (module, attr) in EVAL_SINKS:
                tainted_here = any(_names_in_subtree(a, tainted) for a in child.args)
                self.findings.append(
                    Finding(
                        "MCP003",
                        child.lineno,
                        node.name,
                        f"{attr}() call" + (" reachable from tool parameter" if tainted_here else " present in tool function"),
                    )
                )
            elif (module, attr) in FILE_SINKS:
                sensitive_capabilities.add("file")
                if child.args and _names_in_subtree(child.args[0], tainted):
                    self.findings.append(
                        Finding(
                            "MCP002",
                            child.lineno,
                            node.name,
                            "open() path built from tainted tool parameter",
                        )
                    )
            elif (module, attr) in DESERIALIZE_SINKS:
                self.findings.append(
                    Finding(
                        "MCP007",
                        child.lineno,
                        node.name,
                        f"{module}.{attr}() call on data that may be untrusted",
                    )
                )
            elif module in {"requests", "httpx", "urllib", "aiohttp", "socket"}:
                sensitive_capabilities.add("network")

        if len(sensitive_capabilities) >= 2:
            self.findings.append(
                Finding(
                    "MCP006",
                    node.lineno,
                    node.name,
                    f"tool combines capabilities: {', '.join(sorted(sensitive_capabilities))}",
                )
            )


def scan_secrets(source: str, filename: str):
    import re

    findings = []
    for i, line in enumerate(source.splitlines(), start=1):
        for pattern, label in SECRET_PATTERNS:
            if re.search(pattern, line):
                findings.append(
                    Finding(
                        rule_id="MCP004",
                        line=i,
                        function_name="(module level)",
                        detail=f"possible {label} in source",
                    )
                )
    return findings


def scan_file(path: str):
    with open(path, "r", encoding="utf-8") as f:
        source = f.read()

    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as e:
        return [], [f"Could not parse {path}: {e}"]

    analyzer = MCPAnalyzer(source)
    analyzer.visit(tree)
    findings = analyzer.findings + scan_secrets(source, path)
    findings.sort(key=lambda f: f.line)
    return findings, []
