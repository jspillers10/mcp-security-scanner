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

# FastMCP also supports registering tools/resources programmatically instead
# of via decorator -- e.g. `self.mcp.add_tool(self.my_tool)` -- which is the
# shape real servers use when FastMCP is wrapped inside a custom class
# (an SSE-transport server class, a plugin system, etc.) rather than
# decorated at module scope. The decorator-only version of this analyzer
# silently found nothing on servers built this way, which reads as "clean"
# when it actually means "didn't look." See _programmatic_registrations().
TOOL_REGISTER_METHODS = {"add_tool"}
RESOURCE_REGISTER_METHODS = {"add_resource"}

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


def _collect_functions_by_name(tree):
    """Map simple function name -> its FunctionDef/AsyncFunctionDef node.

    Covers both module-level functions and methods defined inside a class,
    since a server that wraps FastMCP in a custom class typically defines
    tool handlers as methods and registers them programmatically in
    __init__ rather than decorating them in place. If a name is reused,
    the last definition wins -- an acceptable approximation for a
    best-effort static scan.
    """
    by_name = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            by_name[node.name] = node
    return by_name


def _programmatic_registrations(tree, functions_by_name):
    """Find tools/resources registered via `mcp.add_tool(fn)` /
    `server.add_resource(fn)` calls instead of a decorator.

    Resolution is deliberately simple, matching this project's
    lightweight/explainable-over-exhaustive philosophy: the first
    positional argument must be a bare name (`add_tool(my_tool)`) or a
    `self.`-qualified attribute (`add_tool(self.my_tool)`) matching a known
    function or method name. A variable holding a function reference
    assigned earlier, a lambda, or a dynamically built name is out of scope
    for this pass -- those would need real dataflow tracking to resolve
    reliably, and a wrong guess there is worse than a known gap.
    """
    registrations = []  # list of (function_node, "tool" | "resource")
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        method = func.attr
        is_tool_reg = method in TOOL_REGISTER_METHODS
        is_resource_reg = method in RESOURCE_REGISTER_METHODS
        if not (is_tool_reg or is_resource_reg):
            continue
        if not node.args:
            continue
        target = node.args[0]
        name = None
        if isinstance(target, ast.Name):
            name = target.id
        elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self":
            name = target.attr
        if name and name in functions_by_name:
            registrations.append((functions_by_name[name], "tool" if is_tool_reg else "resource"))
    return registrations


class MCPAnalyzer(ast.NodeVisitor):
    def __init__(self, source: str):
        self.source = source
        self.findings = []
        self._processed_tool_ids = set()
        self._processed_resource_ids = set()

    def visit_FunctionDef(self, node):
        decorators = _decorator_names(node)
        is_tool = any(d in TOOL_DECORATOR_NAMES for d in decorators)
        is_resource = any(d in RESOURCE_DECORATOR_NAMES for d in decorators)

        if is_resource:
            self._check_resource(node)
            self._processed_resource_ids.add(id(node))

        if is_tool:
            tainted = {arg.arg for arg in node.args.args if arg.arg != "self"}
            self._check_tool_body(node, tainted)
            self._processed_tool_ids.add(id(node))

        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def run_programmatic_registrations(self, tree):
        """Second pass: catch tools/resources registered via add_tool()/
        add_resource() instead of a decorator. Runs after the decorator
        pass (visit) so id()-based dedup against _processed_*_ids works
        regardless of call order.
        """
        functions_by_name = _collect_functions_by_name(tree)
        for node, kind in _programmatic_registrations(tree, functions_by_name):
            if kind == "tool" and id(node) not in self._processed_tool_ids:
                before = len(self.findings)
                tainted = {arg.arg for arg in node.args.args if arg.arg != "self"}
                self._check_tool_body(node, tainted)
                self._processed_tool_ids.add(id(node))
                self._tag_programmatic(before)
            elif kind == "resource" and id(node) not in self._processed_resource_ids:
                before = len(self.findings)
                self._check_resource(node)
                self._processed_resource_ids.add(id(node))
                self._tag_programmatic(before)

    def _tag_programmatic(self, findings_before_count):
        """Mark findings from this pass as coming from programmatic
        registration rather than a decorator, so a report reader knows why
        this one didn't show up next to an @mcp.tool() line.
        """
        for f in self.findings[findings_before_count:]:
            f.detail = f"[registered via add_tool()/add_resource(), no decorator] {f.detail}"

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

        Recognizes only the classic single-sided guard-clause shape --
        `if <condition on tainted value>: raise/return`, with no `else` --
        and treats the tested name as validated for the rest of the
        function. This is deliberately approximate: it doesn't reason about
        which branch actually executes, only that a rejecting check exists
        against the value before it's used.

        Requiring `stmt.orelse` to be empty matters: an `if/else` where
        *both* branches simply return their own computed result (an
        ordinary branching computation, not a rejection) must NOT be
        treated as validation -- the tainted value is still used,
        unsanitized, down either branch. An earlier version of this check
        used `ast.walk(stmt)` over the whole if/else, which matched that
        shape and produced a real false negative: `if x.endswith(".json"):
        <use x> return ... else: <use x> return ...` was silently treated
        as "x is now validated" even though neither branch validates
        anything. Checking only `stmt.body` (not `stmt.orelse`) for the
        early exit, and requiring no `orelse` at all, avoids that.
        """
        validated = set()
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.If):
                if stmt.orelse:
                    continue
                touches_tainted = _names_in_subtree(stmt.test, tainted)
                exits_early = any(
                    isinstance(s, (ast.Raise, ast.Return)) for s in stmt.body
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
    analyzer.run_programmatic_registrations(tree)
    findings = analyzer.findings + scan_secrets(source, path)
    findings.sort(key=lambda f: f.line)
    return findings, []
