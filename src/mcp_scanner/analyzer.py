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
5. One-hop local resolution: if a tainted tool parameter is passed into a
   same-file helper or a function imported from a sibling file in the same
   local package (`import x`, `from . import x`, `from .x import y`, or a
   flat `from x import y` where `x.py` sits next to the file being
   scanned), the callee's matching parameter is treated as tainted too, and
   its body is checked for sinks the same way a tool body is. This stops
   after exactly one hop -- a sink two calls away from the tool parameter
   is out of scope. See _check_cross_file_calls() / _check_one_hop_function().

This is a lightweight, best-effort static analysis -- it favors clear,
explainable findings over exhaustive dataflow precision. False negatives are
expected on heavily obfuscated code; false positives are expected on code
that re-implements sanitization in a way the analyzer doesn't recognize.
"""

import ast
import os
import re
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

SENSITIVE_RESOURCE_KEYWORDS = (
    "debug",
    "log",
    "admin",
    "internal",
    "secret",
    "config",
    "token",
    "auth",
    "credential",
    "confidential",
    "private",
)

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key"),
    (r"[a-zA-Z0-9_.+-]+://[^:\s]+:[^@\s]+@[^\s'\"]+", "credential in connection string"),
]

# Identifier/key hints for the AST-based checks below (_scan_secret_assignments,
# _scan_secret_dicts). Matched case-insensitively as a substring, the same
# deliberately broad net as the rest of this project's heuristics -- see the
# module docstring's stated preference for explainable-over-exhaustive checks.
SECRET_KEY_HINTS = (
    "password",
    "passwd",
    "pwd",
    "api_key",
    "apikey",
    "api-key",
    "secret",
    "token",
    "access_key",
    "secret_key",
    "private_key",
    "auth_key",
    "credential",
    "client_secret",
    "api key",
)

# Substrings that mark a candidate value as a template/placeholder rather
# than a real secret -- e.g. "changeme", "YOUR_API_KEY_HERE", "<token>".
# Matched case-insensitively, as a substring of the VALUE (not the name).
#
# Known, accepted tradeoff: this is intentionally broad, matching the same
# philosophy documented elsewhere in this project (see AUTH_SUBSTRINGS in
# readiness.py). A real secret that happens to contain one of these
# substrings by coincidence (e.g. a token with "xxx" or "<" somewhere in
# its character content) would be misread as a placeholder and excluded --
# a false negative. This is accepted because the alternative (narrowing
# these markers to reduce that risk) would let more example/template
# values in fixtures, docs, and scaffolding through as false positives,
# which is the more common case in practice for this heuristic's inputs.
PLACEHOLDER_VALUE_MARKERS = (
    "changeme",
    "change_me",
    "change-me",
    "your_",
    "your-",
    "<",
    ">",
    "xxx",
    "example",
    "sample",
    "placeholder",
    "todo",
    "fixme",
    "insert_",
    "insert-",
    "replace_",
    "replace-",
    "dummy",
    "***",
    "redacted",
    "n/a",
)

# A "Label: value" or "Label = value" line inside a multiline string literal,
# optionally preceded by a list-bullet marker ("-", "*", "•"), used to find
# credential bundles embedded as free text (e.g. a config file or memo
# written via f.write("""...""")) rather than as a `key = "value"`
# assignment or a dict literal. Requires the label to look like an
# identifier/short phrase so it doesn't match arbitrary prose.
_LABEL_VALUE_RE = re.compile(r"^\s*[-*•]?\s*[\"']?([A-Za-z][A-Za-z0-9 _-]{2,30}?)[\"']?\s*[:=]\s*(.+?)\s*$")

# A section title with no value of its own, in either of two common plain-
# text documentation shapes: "Title:" (colon, nothing follows), or a bare
# title line immediately followed by an underline of repeated dashes/equals/
# tildes. A title recognized this way (e.g. "Current Production API Keys:",
# or "SYSTEM API KEYS" underlined with "---") opens a section: bulleted
# "Label: value" lines that follow it are read as belonging to that section
# even when the per-item label itself has no secret-shaped hint (e.g. "Main
# API: <token>", where the credential-ness comes from the section, not the
# item label). A blank line closes the section.
_SECTION_DIVIDER_RE = re.compile(r"^[-=~]{3,}$")
_MAX_HEADER_LENGTH = 40

# Names carrying one of these as their FINAL underscore/hyphen-separated
# word hold a one-way derived value (a digest), not the credential itself
# -- e.g. "password_hash" is standard practice for storing how to verify a
# password, not the password. Checked before SECRET_KEY_HINTS so a derived
# value is never treated as secret-shaped just because its base name is.
#
# This is an exact final-word match, not a substring match: "password_hash"
# and "token_digest" are excluded (their last word is exactly "hash"/
# "digest"), but "hashicorp_token" is not (its last word is "token", so it
# remains detectable as a possible hardcoded token) -- a plain substring
# check on the whole name would incorrectly exclude "hashicorp_token" too,
# since "hash" appears inside "hashicorp".
_DERIVED_VALUE_MARKERS = ("hash", "digest", "checksum")
_WORD_SPLIT_RE = re.compile(r"[^a-z0-9]+")


def _final_word(name: str) -> str:
    words = [w for w in _WORD_SPLIT_RE.split(name.lower()) if w]
    return words[-1] if words else ""


# A value that looks like a filesystem path or has a common non-secret file
# extension is a location, not a credential -- e.g. TOKEN_FILE = "/var/run/
# tokens.json" names where tokens live, it isn't one.
_PATH_LIKE_EXTENSIONS = (
    ".json",
    ".txt",
    ".log",
    ".yaml",
    ".yml",
    ".ini",
    ".conf",
    ".cfg",
    ".csv",
    ".db",
    ".sqlite",
    ".py",
    ".xml",
    ".toml",
)


def _is_secret_shaped_name(name: str) -> bool:
    if _final_word(name) in _DERIVED_VALUE_MARKERS:
        return False
    lowered = name.lower()
    return any(hint in lowered for hint in SECRET_KEY_HINTS)


def _looks_like_placeholder(value: str) -> bool:
    stripped = value.strip().strip("'\",")
    if len(stripped) < 6:
        return True
    lowered = stripped.lower()
    return any(marker in lowered for marker in PLACEHOLDER_VALUE_MARKERS)


def _looks_like_file_path(value: str) -> bool:
    stripped = value.strip()
    lowered = stripped.lower()
    if stripped.startswith(("/", "./", "../", "~/")):
        return True
    if len(stripped) > 2 and stripped[1] == ":" and stripped[2] in "\\/":
        return True
    if "://" in stripped:
        return True
    return lowered.endswith(_PATH_LIKE_EXTENSIONS)


def _is_plausible_secret_value(value: str) -> bool:
    return bool(value) and not _looks_like_placeholder(value) and not _looks_like_file_path(value)


def _is_plausible_secret_token(value: str) -> bool:
    """Stricter check used for free-text "Label: value" lines (see
    _multiline_string_secret_line): the value must also be a single token
    with no internal whitespace. Ordinary prose ("Upcoming Acquisition
    Plans", "Q3 2025") always contains a space; every real credential value
    seen in practice (a password, an API key, a JWT) does not. Without this,
    a document heading like "TOP SECRET: Upcoming Acquisition Plans" reads
    as a credential label ("secret" is a substring of "TOP SECRET") paired
    with a plausible-looking value, which it isn't.
    """
    return _is_plausible_secret_value(value) and " " not in value.strip() and "\t" not in value


def _is_docstring_constant(tree) -> set:
    """Return the id()s of string Constant nodes that are a module,
    class, or function docstring (the first statement of that node's
    body). Docstring text is documentation, not embedded source data --
    see AUTH_SUBSTRINGS' comment in readiness.py for the same reasoning
    applied to a different rule.
    """
    ids = set()
    candidates = [tree]
    candidates.extend(n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
    for node in candidates:
        body = getattr(node, "body", None)
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            ids.add(id(body[0].value))
    return ids


def _dict_has_secret_pair(node: "ast.Dict") -> bool:
    """True if this dict directly holds a secret-shaped key with a
    plausible literal string value, or nests a container (dict/list/
    tuple/set) that does -- see _container_has_secret_pair().
    """
    for key, value in zip(node.keys, node.values):
        if isinstance(key, ast.Constant) and isinstance(key.value, str) and _is_secret_shaped_name(key.value):
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                if _is_plausible_secret_value(value.value):
                    return True
        if isinstance(value, (ast.Dict, ast.List, ast.Tuple, ast.Set)) and _container_has_secret_pair(value):
            return True
    return False


def _container_has_secret_pair(node) -> bool:
    if isinstance(node, ast.Dict):
        return _dict_has_secret_pair(node)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(
            isinstance(el, (ast.Dict, ast.List, ast.Tuple, ast.Set)) and _container_has_secret_pair(el)
            for el in node.elts
        )
    return False


def _build_parent_map(tree):
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node
    return parents


def _is_nested_in_container(node_id, parents) -> bool:
    """True if walking up from `node_id` reaches a Dict/List/Tuple/Set
    before anything else -- i.e. this node is itself a value inside
    another literal container, not a standalone top-level one. Used so a
    credential bundle nested inside an already-reported dict is not
    reported a second time as its own finding.
    """
    current = parents.get(node_id)
    while current is not None:
        if isinstance(current, (ast.Dict, ast.List, ast.Tuple, ast.Set)):
            return True
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
            return False
        current = parents.get(id(current))
    return False


def _scan_secret_assignments(tree):
    """`NAME = "literal"` / `NAME: T = "literal"` where NAME looks
    secret-shaped and the literal isn't an obvious placeholder. Covers the
    simple single-line case the original regex handled, plus multi-target
    assignment (`a = b = "..."`), via AST instead of text matching.
    """
    findings = []
    for node in ast.walk(tree):
        targets = None
        value = None
        line = None
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
            line = node.lineno
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = [node.target]
            value = node.value
            line = node.lineno
        if targets is None or line is None:
            continue
        if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
            continue
        if not _is_plausible_secret_value(value.value):
            continue
        for target in targets:
            if isinstance(target, ast.Name) and _is_secret_shaped_name(target.id):
                findings.append(
                    Finding(
                        "MCP004",
                        line,
                        "(module level)",
                        f"possible hardcoded secret assigned to '{target.id}'",
                    )
                )
                break
    return findings


def _scan_secret_dicts(tree):
    """Top-level dict literals (not themselves nested inside another
    literal container already being reported) that hold a secret-shaped
    key with a plausible value, directly or in a nested container. One
    finding per outermost matching dict -- see the module counting note
    in docs/benchmark.md: one logical credential bundle is one case even
    when it holds several fields or one level of nesting.
    """
    parents = _build_parent_map(tree)
    findings = []
    reported_ids = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        if _is_nested_in_container(id(node), parents):
            continue
        if _dict_has_secret_pair(node):
            findings.append(
                Finding(
                    "MCP004",
                    node.lineno,
                    "(module level)",
                    "possible hardcoded credential bundle in a dict literal",
                )
            )
            reported_ids.add(id(node))
    return findings, reported_ids


def _is_section_header(stripped_line: str, next_stripped_line: str | None) -> bool:
    if len(stripped_line) > _MAX_HEADER_LENGTH:
        return False
    if stripped_line.endswith((":", "=")) and _is_secret_shaped_name(stripped_line[:-1]):
        return True
    return (
        next_stripped_line is not None
        and bool(_SECTION_DIVIDER_RE.match(next_stripped_line))
        and _is_secret_shaped_name(stripped_line)
    )


def _multiline_string_secret_line(text: str):
    """Return the first credential-shaped line inside `text`, or None. Only
    one match is needed -- several credential lines in the same string are
    one logical bundle.

    Two shapes are recognized:
      1. A direct "Label: value" / "Label = value" line whose own label
         looks secret-shaped and whose value is a plausible single-token
         secret (see _is_plausible_secret_token).
      2. A "Label: value" line inside a recognized section (see
         _is_section_header) whose value is a plausible token, even when
         the per-item label itself has no hint -- e.g. a titled list of
         named services each followed by their own key.
    """
    lines = text.splitlines()
    in_section = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            in_section = False
            continue
        m = _LABEL_VALUE_RE.match(line)
        if m:
            label, value = m.group(1), m.group(2)
            if _is_secret_shaped_name(label) and _is_plausible_secret_token(value):
                return line.strip()
            if in_section and _is_plausible_secret_token(value):
                return line.strip()
            continue
        next_stripped = lines[i + 1].strip() if i + 1 < len(lines) else None
        if _is_section_header(stripped, next_stripped):
            in_section = True
    return None


def _scan_secret_multiline_strings(tree, skip_ids):
    """Multiline string literals containing embedded "Label: value"
    credential lines -- e.g. a config file or memo built with
    f.write(\"\"\"...\"\"\"), where the secret is free text rather than a
    dict value or a `key = "value"` assignment. Docstrings are excluded
    (see _is_docstring_constant); string constants already covered by a
    reported dict finding are excluded via `skip_ids` so a nested
    multiline value inside a reported bundle isn't double-counted.

    Returns (findings, covered_ranges) -- covered_ranges is the
    (start_line, end_line) span of each string that produced a finding,
    used by scan_secrets() to stop the plain regex pass from re-reporting
    the same bundle a second time (e.g. a connection-string URL that's
    just one line inside a multiline block already counted here).
    """
    docstring_ids = _is_docstring_constant(tree)
    findings = []
    covered_ranges = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        if "\n" not in node.value:
            continue
        if id(node) in docstring_ids or id(node) in skip_ids:
            continue
        match = _multiline_string_secret_line(node.value)
        if match:
            findings.append(
                Finding(
                    "MCP004",
                    node.lineno,
                    "(module level)",
                    f"possible hardcoded credential bundle in a multiline string ({match!r})",
                )
            )
            covered_ranges.append((node.lineno, getattr(node, "end_lineno", node.lineno)))
    return findings, covered_ranges


@dataclass
class Finding:
    rule_id: str
    line: int
    function_name: str
    detail: str
    # None for an ordinary in-file finding. Set to the callee's absolute
    # file path for a one-hop cross-file finding, since `line` then refers
    # to a line in a *different* file from the one being scanned -- see
    # _check_one_hop_function(). report.py surfaces this explicitly rather
    # than silently reporting a line number that doesn't match the file the
    # user asked to scan.
    file: str | None = None
    # AST column offset of the sink call, when known -- e.g. two eval()
    # calls on the same line have distinct col_offset values. Combined with
    # (rule_id, file, line, function_name) this identifies one physical
    # sink call site, used by _dedupe_findings() to collapse the same call
    # site reported twice through different resolution paths (a tool
    # scanned directly, and again as another tool's one-hop callee) without
    # collapsing two genuinely distinct sinks that happen to share a line.
    col_offset: int | None = None
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


def _is_string_built_from_tainted(query_arg, function_node, tainted_names):
    """Return whether a SQL query argument is a tainted f-string or concat.

    A query is commonly assigned to a local variable before execute(), so
    follow simple assignments in the current function as well as inspecting
    the argument expression itself. This is deliberately narrower than the
    general taint check: a bare tainted value is not necessarily a SQL query.
    """
    seen_names = set()

    def is_built(expr):
        if isinstance(expr, ast.JoinedStr):
            return _names_in_subtree(expr, tainted_names)
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            return _names_in_subtree(expr, tainted_names)
        if not isinstance(expr, ast.Name) or expr.id in seen_names:
            return False
        seen_names.add(expr.id)
        for stmt in ast.walk(function_node):
            values: list[ast.expr] = []
            if isinstance(stmt, ast.Assign):
                if any(isinstance(target, ast.Name) and target.id == expr.id for target in stmt.targets):
                    values.append(stmt.value)
            elif (
                isinstance(stmt, ast.AnnAssign)
                and isinstance(stmt.target, ast.Name)
                and stmt.target.id == expr.id
                and stmt.value is not None
            ):
                values.append(stmt.value)
            if any(value is not None and is_built(value) for value in values):
                return True
        return False

    return is_built(query_arg)


def _has_shell_true(call_node):
    for kw in call_node.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


# AST call names that resolve a path against the filesystem, including
# symlinks. Lexical-only normpath()/abspath() are deliberately excluded: a
# containment check can pass before a symlink redirects the final open()
# outside the trusted base. A containment check against an unresolved
# candidate is unsound: `(BASE / "../../etc/passwd")` as a PurePath keeps
# the literal ".." segments, so a lexical prefix comparison against BASE
# (which is exactly what Path.is_relative_to and a `.parents` membership
# test both do) can still report "contained" even though the OS would
# resolve the same path outside BASE at open() time.
_CANONICALIZING_CALL_NAMES = {"resolve", "realpath"}


def _is_canonicalizing_call(node) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr in _CANONICALIZING_CALL_NAMES
    if isinstance(func, ast.Name):
        return func.id in _CANONICALIZING_CALL_NAMES
    return False


def _expr_contains_canonicalizing_call(expr) -> bool:
    return any(_is_canonicalizing_call(n) for n in ast.walk(expr))


def _local_assignment_values(name_id, function_scope):
    return [
        stmt.value
        for stmt in ast.walk(function_scope)
        if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name_id for t in stmt.targets)
    ]


def _module_level_assignment_values(name_id, module_scope):
    if module_scope is None:
        return []
    return [
        stmt.value
        for stmt in getattr(module_scope, "body", [])
        if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name_id for t in stmt.targets)
    ]


def _candidate_assignment_values(name_id, function_scope, module_scope):
    """Assignment RHS expressions for `name_id`, in Python's own scoping
    order: assignments inside `function_scope` first (a local binding
    shadows a same-named module-level one), falling back to *top-level*
    `module_scope` assignments only when the function itself never
    assigns this name locally.

    This split matters: two unrelated functions in the same file
    routinely reuse a local variable name like `candidate`. Searching the
    whole module tree indiscriminately for a name match -- rather than
    the enclosing function first -- would resolve one function's
    `candidate` to a completely different function's unrelated
    same-named local variable, e.g. reading a `.resolve()` call that
    belongs to someone else's guard. The module-level fallback only walks
    `module_scope.body` directly (not `ast.walk`), so it can't reach into
    another function's body either.
    """
    local_values = _local_assignment_values(name_id, function_scope)
    if local_values:
        return local_values
    if module_scope is function_scope:
        return []
    return _module_level_assignment_values(name_id, module_scope)


def _is_canonicalized(expr, function_scope, module_scope, seen_names=None) -> bool:
    """True if `expr` itself contains a canonicalizing call (see
    _is_canonicalizing_call), or is a bare Name whose nearest-scope
    assignment is -- resolved recursively through a simple Name chain via
    _candidate_assignment_values, so a module-level constant like `BASE =
    Path("/srv/reports").resolve()` is found without reaching into an
    unrelated function's own local variable of the same name.
    """
    if _expr_contains_canonicalizing_call(expr):
        return True
    if not isinstance(expr, ast.Name):
        return False
    seen_names = seen_names or set()
    if expr.id in seen_names:
        return False
    seen_names = seen_names | {expr.id}
    for value in _candidate_assignment_values(expr.id, function_scope, module_scope):
        if _is_canonicalized(value, function_scope, module_scope, seen_names):
            return True
    return False


def _resolves_to_fixed_literal_container(expr, function_scope, module_scope, tainted, seen_names=None) -> bool:
    """True if `expr` is a literal set/list/tuple of constants with no
    tainted content, or (recursively, through a simple Name chain via
    _candidate_assignment_values) resolves to one.

    Excludes: anything tainted (a collection built from a tool parameter
    is not a trusted allowlist just because the check technically didn't
    fail); a runtime Call result (`load_allowed()`), since a value loaded
    or computed at call time is not a "fixed developer-controlled
    literal" even when it happens not to be tainted right now; and
    anything else this can't trace back to an actual literal. See
    MCP001/MCP002's "trusted allowlist" requirement.
    """
    if _names_in_subtree(expr, tainted):
        return False
    if isinstance(expr, (ast.Set, ast.List, ast.Tuple)):
        return all(isinstance(el, ast.Constant) for el in expr.elts)
    if (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Name)
        and expr.func.id in ("set", "frozenset", "list", "tuple")
    ):
        if len(expr.args) == 1 and isinstance(expr.args[0], (ast.Set, ast.List, ast.Tuple)):
            return all(isinstance(el, ast.Constant) for el in expr.args[0].elts)
        return False
    if isinstance(expr, ast.Name):
        seen_names = seen_names or set()
        if expr.id in seen_names:
            return False
        seen_names = seen_names | {expr.id}
        for value in _candidate_assignment_values(expr.id, function_scope, module_scope):
            if _resolves_to_fixed_literal_container(value, function_scope, module_scope, tainted, seen_names):
                return True
    return False


def _test_contains_allowlist_membership(test_expr, name, tainted, function_scope, module_scope) -> bool:
    """True if `test_expr` contains `name not in <fixed-literal-set>` --
    the classic single-sided allowlist guard ("reject unless the value is
    one of these fixed, developer-controlled values").

    Three things distinguish this from a naive `NotIn` check: (1) the
    opposite polarity (`name in <something>`, "reject if the value is one
    of these") is a denylist, not an allowlist, and is deliberately NOT
    treated as adequate -- blocking a few known-bad values doesn't prove
    every other value is safe; (2) the right-hand side must resolve to a
    FIXED LITERAL container (see _resolves_to_fixed_literal_container),
    not a tainted, user-controlled, or dynamically loaded collection --
    `name not in allowed_names.split(",")` (tainted) and `name not in
    load_allowed()` (a runtime call, not a literal) are both rejected;
    (3) `name` must appear on the LEFT side of the comparison (the value
    being checked), not merely anywhere in the expression, so the
    tainted-name match lines up with what's actually being tested against
    the allowlist. This is the strong-guard shape shared by MCP001 (an
    exact command allowlist) and MCP002 (an exact path allowlist).
    """
    for n in ast.walk(test_expr):
        if not isinstance(n, ast.Compare):
            continue
        for op, comparator in zip(n.ops, n.comparators):
            if (
                isinstance(op, ast.NotIn)
                and _names_in_subtree(n.left, {name})
                and _resolves_to_fixed_literal_container(comparator, function_scope, module_scope, tainted)
            ):
                return True
    return False


def _test_contains_path_containment(test_expr, name, tainted, function_scope, module_scope) -> bool:
    """True if `test_expr` contains a recognized, sound path-containment
    check touching `name`: an exact allowlist (see
    _test_contains_allowlist_membership), a NEGATED, canonicalized
    `Path.is_relative_to(...)` call against an untainted base, or a
    NEGATED, canonicalized `<base> not in <candidate>.parents` membership
    test against an untainted base.

    Every one of these conditions matters, and each closes a real gap:

    - NEGATED (`not X.is_relative_to(BASE)` / `BASE not in
      candidate.parents`, not the bare positive form): `is_relative_to`
      and `in .parents` are both TRUE exactly when the path IS safe. A
      guard that rejects (raises/returns) when its test is true only
      makes sense as validation if the test represents the UNSAFE
      condition -- so the adequate shape is "reject when NOT contained",
      not "reject when contained" (which would reject exactly the safe
      case and let the unsafe case fall through to the sink).
    - CANONICALIZED (see _is_canonicalized): an unresolved candidate
      (`Path(user_path)` with no `.resolve()`/`realpath()` anywhere in its
      construction) can still report
      "contained" for a path with unresolved ".." components, because
      `is_relative_to`/`.parents` compare path components lexically, not
      against what the filesystem would actually resolve.
    - untainted base: `candidate.is_relative_to(user_supplied_base)` proves
      nothing if the caller also controls `user_supplied_base`.

    Deliberately NOT recognized as adequate on their own: an existence
    check (os.path.exists/isfile/isdir), an extension check
    (name.endswith(...)), or a raw string-prefix check
    (name.startswith(...)) against the unresolved value -- none of these
    prove the resolved path stays inside an approved directory.
    """
    if _test_contains_allowlist_membership(test_expr, name, tainted, function_scope, module_scope):
        return True
    for n in ast.walk(test_expr):
        if isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.Not) and isinstance(n.operand, ast.Call):
            call = n.operand
            if (
                isinstance(call.func, ast.Attribute)
                and call.func.attr == "is_relative_to"
                and call.args
                and _names_in_subtree(call.func.value, {name})
                and _is_canonicalized(call.func.value, function_scope, module_scope)
                and not _names_in_subtree(call.args[0], tainted)
            ):
                return True
        if isinstance(n, ast.Compare):
            for op, comparator in zip(n.ops, n.comparators):
                if (
                    isinstance(op, ast.NotIn)
                    and isinstance(comparator, ast.Attribute)
                    and comparator.attr == "parents"
                    and _names_in_subtree(comparator.value, {name})
                    and _is_canonicalized(comparator.value, function_scope, module_scope)
                    and _is_canonicalized(n.left, function_scope, module_scope)
                    and not _names_in_subtree(n.left, tainted)
                ):
                    return True
    return False


def _collect_strong_guard_positions(node, tainted, is_adequate, module_scope):
    """For each tainted name, record a direct function-body guard position.

    `node` doubles as the function-local scope passed to `is_adequate`
    (see _candidate_assignment_values); `module_scope` is the containing
    module's tree, used only as a fallback for names `node` itself never
    assigns locally (e.g. a module-level constant base directory).

    This is intentionally narrower than full control-flow analysis. The
    guard must be a direct sibling statement in the function body, have no
    else branch, and consist of exactly one direct return or raise. Guards
    nested in conditionals, loops, try/except blocks, or handlers are not
    collected. A later sink is protected only when it occurs in a later
    sibling statement, which gives the guard structural dominance within
    this conservative model.
    """
    guard_positions: dict = {}
    for position, stmt in enumerate(node.body):
        if not isinstance(stmt, ast.If) or stmt.orelse:
            continue
        if len(stmt.body) != 1 or not isinstance(stmt.body[0], (ast.Raise, ast.Return)):
            continue
        if not _names_in_subtree(stmt.test, tainted):
            continue
        for name_node in ast.walk(stmt.test):
            if (
                isinstance(name_node, ast.Name)
                and name_node.id in tainted
                and is_adequate(stmt.test, name_node.id, tainted, node, module_scope)
            ):
                guard_positions.setdefault(name_node.id, position)
    return guard_positions


def _direct_body_position(node, descendant):
    for position, stmt in enumerate(node.body):
        if any(child is descendant for child in ast.walk(stmt)):
            return position
    return None


def _tainted_names_reaching(expr, tainted, guard_positions, sink_node, function_node) -> bool:
    """True unless every tainted name is dominated by a direct guard."""
    sink_position = _direct_body_position(function_node, sink_node)
    for child in ast.walk(expr):
        if isinstance(child, ast.Name) and child.id in tainted:
            guard_position = guard_positions.get(child.id)
            if sink_position is None or guard_position is None or guard_position >= sink_position:
                return True
    return False


def _resolve_dict_literal(expr, function_node):
    """If `expr` is a dict literal, return it. If it's a Name, resolve it
    to a dict literal assigned earlier in `function_node` via a simple
    `name = {...}` assignment. Returns None if it can't be resolved to a
    literal dict -- see _is_dict_subscript_of_safe_literal.
    """
    if isinstance(expr, ast.Dict):
        return expr
    if not isinstance(expr, ast.Name):
        return None
    for stmt in ast.walk(function_node):
        if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == expr.id for t in stmt.targets):
            if isinstance(stmt.value, ast.Dict):
                return stmt.value
    return None


def _is_dict_subscript_of_safe_literal(value_expr, tainted, function_node) -> bool:
    """True if `value_expr` is `<dict-literal>[<key>]` where the dict's own
    values contain no tainted names.

    Subscripting a fixed literal dict lets a tainted key choose WHICH of
    several fixed values comes out, but never influences the CONTENT of
    that value -- `commands = {"a": "echo a", "b": "echo b"}; cmd =
    commands[key]` can only ever assign "echo a" or "echo b" to `cmd`, so
    `cmd` isn't actually tainted by `key`'s content. Without this, taint
    propagation over-approximates: any name in the subscript's subtree
    (including the dict's own values) marks the assignment target
    tainted, which is right when the dict's values themselves are
    tainted, but wrong when they're all fixed literals -- see MCP001's
    "exact command mapping" boundary in docs/benchmark.md.
    """
    if not isinstance(value_expr, ast.Subscript):
        return False
    dict_node = _resolve_dict_literal(value_expr.value, function_node)
    if dict_node is None:
        return False
    return not any(v is not None and _names_in_subtree(v, tainted) for v in dict_node.values)


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


def _collect_local_imports(tree, base_dir):
    """Return (module_alias -> file_path, imported_name -> (file_path, real_name))
    for imports in `tree` that resolve to a sibling .py file in `base_dir`.

    This is the only shape the one-hop resolver understands: a module or
    name imported from a file that actually exists next to the file being
    scanned. Third-party/stdlib imports, and imports that don't resolve to
    an existing local file, are left alone -- a call through one of those
    is out of scope for this pass, not an error. Covers:
      - `import helper`               (module_alias) if helper.py exists
      - `from . import helper`        (module_alias) if helper.py exists
      - `from .helper import fn`      (imported_name) -- relative
      - `from helper import fn`       (imported_name) -- flat/non-relative,
        common in single-directory MCP server layouts that aren't set up
        as an installable package
    """
    module_alias_to_path = {}
    name_to_target = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname or alias.name
                candidate = os.path.join(base_dir, alias.name.split(".")[-1] + ".py")
                if os.path.isfile(candidate):
                    module_alias_to_path[local_name] = candidate

        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                if not node.module:
                    continue
                mod_file = os.path.join(base_dir, node.module.split(".")[-1] + ".py")
                if not os.path.isfile(mod_file):
                    continue
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    name_to_target[local_name] = (mod_file, alias.name)
            else:
                # node.level >= 1: `from . import x` or `from .x import y`.
                # Only level 1 (same directory as the scanned file) is
                # handled -- `from .. import x` would need to walk up
                # parent packages, out of scope for a one-hop pass.
                if node.level != 1:
                    continue
                if node.module:
                    mod_file = os.path.join(base_dir, node.module.split(".")[-1] + ".py")
                    if not os.path.isfile(mod_file):
                        continue
                    for alias in node.names:
                        local_name = alias.asname or alias.name
                        name_to_target[local_name] = (mod_file, alias.name)
                else:
                    # `from . import helper` -- each imported name is itself
                    # a sibling module, not a function inside one.
                    for alias in node.names:
                        local_name = alias.asname or alias.name
                        candidate = os.path.join(base_dir, alias.name + ".py")
                        if os.path.isfile(candidate):
                            module_alias_to_path[local_name] = candidate

    return module_alias_to_path, name_to_target


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


def _find_sink_findings(node, tainted, raw_tainted=None, shell_guard_lines=None, path_guard_lines=None):
    """Walk `node`'s body for dangerous sink calls reachable from `tainted`
    names, returning (findings, sensitive_capabilities).

    `tainted` is the GENERAL, guard-pruned set (see
    MCPAnalyzer._apply_validation_guards) used for the eval/SQL/
    deserialization checks -- unchanged behavior, out of scope for the
    MCP001/MCP002 corrections below.

    `raw_tainted` is the full, UNPRUNED propagated-taint set (defaults to
    `tainted` if not given). The MCP001 shell check and the MCP002 open()
    check use it together with `shell_guard_lines`/`path_guard_lines` (see
    _collect_strong_guard_positions) instead of a flat pruned set: a guard
    clause can be adequate to rule out one sink's risk without being
    adequate for the other (an exact command allowlist doesn't validate a
    path, and vice versa), AND adequacy for either one requires the guard
    to occur before the specific sink call being checked -- see
    _tainted_names_reaching. This is why these two checks can't just reuse
    `tainted`'s single, position-blind pruning.

    Shared by the primary tool-body check and the one-hop cross-file check
    (_check_one_hop_function) so both use identical sink logic -- the
    caller decides what to do with the capability set, since only the
    primary tool aggregates it into an MCP006 finding.
    """
    if raw_tainted is None:
        raw_tainted = tainted
    if shell_guard_lines is None:
        shell_guard_lines = {}
    if path_guard_lines is None:
        path_guard_lines = {}

    findings = []
    sensitive_capabilities = set()

    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        module, attr = _call_target(child)
        sql_method = child.func.attr if isinstance(child.func, ast.Attribute) else None
        if (module, attr) in SHELL_SINKS:
            sensitive_capabilities.add("process")
            tainted_reaches = any(
                _tainted_names_reaching(a, raw_tainted, shell_guard_lines, child, node) for a in child.args
            ) or any(
                _tainted_names_reaching(kw.value, raw_tainted, shell_guard_lines, child, node) for kw in child.keywords
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
                findings.append(Finding("MCP001", child.lineno, node.name, detail, col_offset=child.col_offset))
        elif sql_method in {"execute", "executemany"}:
            # Parameterized database APIs keep the query template separate
            # from user-controlled values, e.g. cursor.execute("... %s ...",
            # (value,)). Only a single query argument can send a string-built
            # query to the database parser directly.
            if len(child.args) == 1 and _is_string_built_from_tainted(child.args[0], node, tainted):
                findings.append(
                    Finding(
                        "MCP008",
                        child.lineno,
                        node.name,
                        f"tainted parameter reaches .{sql_method}() in a string-built SQL query",
                        col_offset=child.col_offset,
                    )
                )
        elif (module, attr) in EVAL_SINKS:
            tainted_here = any(_names_in_subtree(a, tainted) for a in child.args)
            findings.append(
                Finding(
                    "MCP003",
                    child.lineno,
                    node.name,
                    f"{attr}() call"
                    + (" reachable from tool parameter" if tainted_here else " present in tool function"),
                    col_offset=child.col_offset,
                )
            )
        elif (module, attr) in FILE_SINKS:
            sensitive_capabilities.add("file")
            if child.args and _tainted_names_reaching(child.args[0], raw_tainted, path_guard_lines, child, node):
                findings.append(
                    Finding(
                        "MCP002",
                        child.lineno,
                        node.name,
                        "open() path built from tainted tool parameter",
                        col_offset=child.col_offset,
                    )
                )
        elif (module, attr) in DESERIALIZE_SINKS:
            findings.append(
                Finding(
                    "MCP007",
                    child.lineno,
                    node.name,
                    f"{module}.{attr}() call on data that may be untrusted",
                    col_offset=child.col_offset,
                )
            )
        elif module in {"requests", "httpx", "urllib", "aiohttp", "socket"}:
            sensitive_capabilities.add("network")

    return findings, sensitive_capabilities


class MCPAnalyzer(ast.NodeVisitor):
    def __init__(self, source: str, file_path: str | None = None):
        self.source = source
        # Needed to resolve local imports relative to this file's directory.
        # Without it (e.g. a caller that hands MCPAnalyzer an inline AST
        # rather than a real file), one-hop cross-file resolution simply
        # doesn't run -- see _check_cross_file_calls().
        self.file_path = file_path
        self.findings: list[Finding] = []
        self._processed_tool_ids: set[int] = set()
        self._processed_resource_ids: set[int] = set()
        self._own_tree: ast.Module | None = None
        self._local_imports: dict[str, str] | None = None
        self._local_from_imports: dict[str, tuple[str, str]] | None = None
        self._file_cache: dict[str, ast.Module | None] = {}
        self._hop_seen: set[tuple[str, str, frozenset[str]]] = set()

    def visit_Module(self, node):
        self._own_tree = node
        self.generic_visit(node)

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

        One deliberate exception: `target = <dict-literal>[<key>]` where
        the dict's own values are all untainted literals does NOT taint
        `target`, even though a tainted name appears in the subscript's
        subtree -- see _is_dict_subscript_of_safe_literal. A tainted key
        only selects which fixed value comes out; it doesn't reach the
        value's content.
        """
        tainted = set(tainted)
        changed = True
        while changed:
            changed = False
            for stmt in ast.walk(node):
                if isinstance(stmt, ast.Assign):
                    if _is_dict_subscript_of_safe_literal(stmt.value, tainted, node):
                        continue
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
                exits_early = any(isinstance(s, (ast.Raise, ast.Return)) for s in stmt.body)
                if touches_tainted and exits_early:
                    for n in ast.walk(stmt.test):
                        if isinstance(n, ast.Name) and n.id in tainted:
                            validated.add(n.id)
        return tainted - validated

    def _check_tool_body(self, node, tainted):
        tainted = self._propagate_taint(node, tainted)
        search_scope = self._own_tree if self._own_tree is not None else node
        shell_guard_lines = _collect_strong_guard_positions(
            node, tainted, _test_contains_allowlist_membership, search_scope
        )
        path_guard_lines = _collect_strong_guard_positions(node, tainted, _test_contains_path_containment, search_scope)
        general_tainted = self._apply_validation_guards(node, tainted)

        findings, sensitive_capabilities = _find_sink_findings(
            node, general_tainted, tainted, shell_guard_lines, path_guard_lines
        )
        self.findings.extend(findings)

        if len(sensitive_capabilities) >= 2:
            self.findings.append(
                Finding(
                    "MCP006",
                    node.lineno,
                    node.name,
                    f"tool combines capabilities: {', '.join(sorted(sensitive_capabilities))}",
                )
            )

        self._check_cross_file_calls(node, general_tainted)

    def _ensure_local_imports(self):
        if self._local_imports is not None:
            return
        if self.file_path is None:
            self._local_imports = {}
            self._local_from_imports = {}
            return
        tree = self._own_tree
        if tree is None:
            # Only reached if run_programmatic_registrations() is called
            # without a prior visit() pass -- fall back to re-parsing.
            tree = ast.parse(self.source)
        base_dir = os.path.dirname(os.path.abspath(self.file_path))
        self._local_imports, self._local_from_imports = _collect_local_imports(tree, base_dir)

    def _resolve_function_in_file(self, target_path, func_name):
        target_path = os.path.abspath(target_path)
        if target_path not in self._file_cache:
            try:
                with open(target_path, "r", encoding="utf-8") as f:
                    target_source = f.read()
                self._file_cache[target_path] = ast.parse(target_source, filename=target_path)
            except (OSError, SyntaxError):
                self._file_cache[target_path] = None
        target_tree = self._file_cache[target_path]
        if target_tree is None:
            return None
        callee_node = _collect_functions_by_name(target_tree).get(func_name)
        if callee_node is None:
            return None
        return target_path, callee_node

    def _resolve_local_call(self, call_node):
        """Return (target_file_path, callee_FunctionDef) for a Call node
        that invokes a function resolvable to a sibling local file, or None
        if the call doesn't match one of the import shapes
        _collect_local_imports() understands.
        """
        self._ensure_local_imports()
        local_imports = self._local_imports or {}
        local_from_imports = self._local_from_imports or {}
        func = call_node.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            target_path = local_imports.get(func.value.id)
            if target_path:
                return self._resolve_function_in_file(target_path, func.attr)
        elif isinstance(func, ast.Name):
            target = local_from_imports.get(func.id)
            if target:
                target_path, real_name = target
                return self._resolve_function_in_file(target_path, real_name)
        return None

    def _map_tainted_args(self, call_node, callee_node, caller_tainted):
        """Map tainted call-site arguments to the callee's parameter names,
        by position for positional args and by name for keyword args.
        """
        callee_params = [a.arg for a in callee_node.args.args if a.arg not in ("self", "cls")]
        tainted_params = set()
        for i, arg_expr in enumerate(call_node.args):
            if i >= len(callee_params):
                break
            if _names_in_subtree(arg_expr, caller_tainted):
                tainted_params.add(callee_params[i])
        for kw in call_node.keywords:
            if kw.arg and kw.arg in callee_params and _names_in_subtree(kw.value, caller_tainted):
                tainted_params.add(kw.arg)
        return tainted_params

    def _check_cross_file_calls(self, node, tainted):
        """Resolve one local call hop, either across a sibling-file import or
        into a same-module helper, then check the callee for sinks and stop.

        This deliberately does not call itself again on the callee, so a sink
        two calls away from the original tool parameter is out of scope by
        design; see the module docstring.
        """
        functions_by_name = _collect_functions_by_name(self._own_tree)
        own_path = os.path.abspath(self.file_path) if self.file_path else "<same-file>"
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            resolution = self._resolve_local_call(child) if self.file_path else None
            if resolution is not None:
                target_path, callee_node = resolution
                resolution_kind = "import"
            else:
                # A bare call that was not imported may name a helper defined
                # in this module. Resolve it with the same lightweight name
                # lookup used for programmatic tool registration.
                if not isinstance(child.func, ast.Name):
                    continue
                callee_node = functions_by_name.get(child.func.id)
                if callee_node is None:
                    continue
                target_path = own_path
                resolution_kind = "same-file"
            callee_tainted = self._map_tainted_args(child, callee_node, tainted)
            if not callee_tainted:
                continue
            self._check_one_hop_function(
                target_path,
                callee_node,
                callee_tainted,
                node.name,
                resolution_kind,
            )

    def _check_one_hop_function(self, target_path, callee_node, callee_tainted, source_tool_name, resolution_kind):
        key = (target_path, callee_node.name, frozenset(callee_tainted))
        if key in self._hop_seen:
            return
        self._hop_seen.add(key)

        tainted = self._propagate_taint(callee_node, callee_tainted)
        if resolution_kind == "same-file":
            search_scope = self._own_tree if self._own_tree is not None else callee_node
        else:
            cached_tree = self._file_cache.get(os.path.abspath(target_path))
            search_scope = cached_tree if cached_tree is not None else callee_node
        shell_guard_lines = _collect_strong_guard_positions(
            callee_node, tainted, _test_contains_allowlist_membership, search_scope
        )
        path_guard_lines = _collect_strong_guard_positions(
            callee_node, tainted, _test_contains_path_containment, search_scope
        )
        general_tainted = self._apply_validation_guards(callee_node, tainted)
        # Capabilities aggregation (MCP006) intentionally isn't repeated
        # here -- combining capabilities split across the tool and a helper
        # it calls would need real interprocedural analysis to do
        # correctly, which is explicitly out of scope for a one-hop pass.
        findings, _capabilities = _find_sink_findings(
            callee_node, general_tainted, tainted, shell_guard_lines, path_guard_lines
        )
        for f in findings:
            if resolution_kind == "import":
                f.file = target_path
                f.detail = (
                    f"[via one-hop import: tainted by {source_tool_name}() calling {callee_node.name}()] {f.detail}"
                )
            else:
                f.detail = (
                    f"[via same-file helper: tainted by {source_tool_name}() calling {callee_node.name}()] {f.detail}"
                )
        self.findings.extend(findings)


def _scan_secret_regex_patterns(source: str):
    """Value-shape patterns that don't need AST context: an AWS access key
    ID's fixed prefix/length, and a credential embedded directly in a
    connection-string URL. Unlike the assignment/dict/multiline-string
    checks above, these aren't tied to a secret-shaped name at all.
    """
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


def scan_secrets(tree, source: str):
    """AST-based hardcoded-secret detection.

    Four independent passes, each targeting a different literal shape a
    credential can appear in:
      1. `NAME = "literal"` assignment to a secret-shaped name.
      2. A dict literal holding a secret-shaped key (directly, or nested
         one or more containers deep) -- one finding per outermost dict.
      3. A multiline string literal containing an embedded "Label: value"
         credential line (e.g. a config file or memo written with
         f.write(\"\"\"...\"\"\")), excluding docstrings and strings
         already covered by pass 2's dict.
      4. Value-shape regex patterns with no associated name (AWS access
         key ID format, credential-in-URL).

    A dict or multiline string is one logical credential bundle regardless
    of how many secret-shaped fields it holds -- see docs/benchmark.md.
    """
    dict_findings, reported_dict_ids = _scan_secret_dicts(tree)

    skip_ids = set(reported_dict_ids)
    covered_ranges = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict) and id(node) in reported_dict_ids:
            skip_ids.update(id(child) for child in ast.walk(node))
            covered_ranges.append((node.lineno, getattr(node, "end_lineno", node.lineno)))

    multiline_findings, multiline_ranges = _scan_secret_multiline_strings(tree, skip_ids)
    covered_ranges.extend(multiline_ranges)

    # The plain regex pass reads raw source lines with no AST context, so a
    # connection-string URL (or an AWS key) that's just one line inside a
    # multiline block already counted above must not be reported a second
    # time as a second, separate bundle.
    regex_findings = [f for f in _scan_secret_regex_patterns(source) if not _line_in_ranges(f.line, covered_ranges)]

    findings = []
    findings.extend(_scan_secret_assignments(tree))
    findings.extend(dict_findings)
    findings.extend(multiline_findings)
    findings.extend(regex_findings)
    return findings


def _line_in_ranges(line: int, ranges) -> bool:
    return any(start <= line <= end for start, end in ranges)


def _finding_identity(f: Finding, scanned_path: str):
    """(rule_id, normalized file, line, column, function_name) for a
    finding -- see _dedupe_findings.
    """
    resolved_file = f.file if f.file else scanned_path
    normalized_file = os.path.normcase(os.path.abspath(resolved_file))
    return (f.rule_id, normalized_file, f.line, f.col_offset, f.function_name)


def _dedupe_findings(findings: list, scanned_path: str) -> list:
    """Collapse findings that identify the exact same physical sink call
    site reached through more than one analysis path.

    Concretely: a tool function scanned directly, and *also* reached as
    the one-hop callee of a different tool whose local name happens to
    resolve to it (see _check_cross_file_calls / _collect_functions_by_name
    -- name resolution is last-definition-wins, so two same-named
    functions or a wrapper that calls a shared helper can route the
    one-hop pass to a sink already found directly). Both passes call the
    same _find_sink_findings() over the same callee body, so a duplicate
    finding for the same rule/file/line/column/function is a re-discovery
    of one physical sink, not a second vulnerability.

    Column offset keeps this narrow: two distinct sink calls on the same
    line (e.g. `eval(a); eval(b)`) have different col_offset values and
    are kept as separate findings. Two distinct tools that each register
    their own sink keep their own function_name and/or line and are
    likewise unaffected. `file` is normalized against `scanned_path` first
    because a same-file one-hop finding and the direct finding it
    duplicates both leave `Finding.file` as None (see Finding's file
    field) -- both mean "the file being scanned", so both must normalize
    to the same value for the comparison to work; a genuine cross-file
    one-hop finding keeps its own (different) file and is unaffected.

    Findings with no column offset (MCP004/MCP101-104, which aren't tied
    to a single AST call site) fall back to comparing `None`, which is
    fine: those rules don't have this direct+one-hop duplication path.
    """
    seen = set()
    deduped = []
    for f in findings:
        key = _finding_identity(f, scanned_path)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    return deduped


def scan_file(path: str):
    with open(path, "r", encoding="utf-8") as f:
        source = f.read()

    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as e:
        return [], [f"Could not parse {path}: {e}"]

    analyzer = MCPAnalyzer(source, file_path=path)
    analyzer.visit(tree)
    analyzer.run_programmatic_registrations(tree)

    # Deferred import: description_scanner imports helpers from this module,
    # so importing it at module scope here would be circular. By the time
    # scan_file() runs, this module is fully loaded.
    from .description_scanner import scan_descriptions

    findings = analyzer.findings + scan_secrets(tree, source) + scan_descriptions(tree, source)
    findings = _dedupe_findings(findings, path)
    findings.sort(key=lambda f: f.line)
    return findings, []
