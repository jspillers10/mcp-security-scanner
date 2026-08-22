# Phase 3 results: measurement-driven detection improvements

This document describes the final corrected Phase 3 candidate. Candidate
evidence is unreviewed and is not the enforced benchmark baseline. The scanner
remains a static research tool: findings are review leads, not proof of runtime
exploitability, and these corpus results do not establish generalization to
production MCP servers.

## Starting point and preserved evidence

- Starting commit: `2232cf357423f6b31dec42b386a7f48377b4acf7`.
- Package version: `0.1.0`.
- Phase 2 security: TP 35, FP 3, FN 10, precision 0.921053, recall
  0.777778, F1 0.843374.
- Phase 2 readiness: TP 18, FP 0, FN 2, F1 0.947368.
- Historical evidence: `benchmark/baselines/*-phase2-historical/`.
- Enforced baseline: `benchmark/baselines/dvmcp-79734c19/metrics.json`,
  unchanged.
- Final unreviewed candidate evidence:
  `benchmark/baselines/*-phase3-candidate/`.

Ground-truth labels and the corpus manifest were not changed.

## Final detector behavior

### MCP004 hardcoded secrets

MCP004 now inspects AST literal assignments, dictionaries and nested literal
containers, multiline credential bundles, and remaining high-specificity value
shapes. A dictionary or multiline literal containing several related secrets
is counted once as one logical credential bundle.

Obvious placeholders, environment-variable access, documentation strings,
non-secret configuration dictionaries, path-like values, and derived values
whose normalized final word is exactly `hash`, `digest`, or `checksum` are
excluded. Exact final-word matching keeps `password_hash` and `token_digest`
out while allowing `hashicorp_token` and ordinary words that merely contain
`hash` to remain detectable. Placeholder exclusions remain heuristic and can
hide a real secret containing a marker such as `example` or `dummy`.

### MCP002 path validation

Existence, extension, string-prefix, and partial-denylist checks never suppress
MCP002. An exact allowlist suppresses only when it resolves to a fixed
developer-controlled literal container. A containment guard suppresses only
when all of these conservative conditions hold:

- The guard is a direct statement in the same function body.
- The sink occurs in a later sibling statement.
- The guard has no `else` and its body is exactly one direct `return` or
  `raise`.
- The unsafe branch is rejected using correctly polarized `is_relative_to`
  or `.parents` logic.
- Candidate and trusted base resolve through `Path.resolve()` or
  `os.path.realpath()`.
- The trusted base is not tainted.

Nested, conditional, looped, or exception-handled guards do not suppress.
`abspath()` and `normpath()` alone do not suppress because lexical
normalization does not resolve symlinks. This is a conservative dominance
model, not full control-flow analysis.

### MCP001 command validation

MCP001 uses the same direct-sibling dominance and fixed-literal allowlist
requirements. Guards after the sink, inverted checks, dynamic or
user-controlled allowlists, partial denylists, and incomplete character
filtering remain findings. Fixed argument-list subprocess calls remain safe. A
tainted key selecting from a fixed literal command mapping does not taint the
selected value, preserving the fixed diagnostic-map case through general taint
reasoning.

### MCP003 duplicate suppression

Finding identity is rule ID, normalized physical file, line, column, and
function context. Direct and helper-propagated reports for one physical sink
are collapsed. Separate sinks and registrations remain distinct.

### RDY002 transport authentication

Calls and authentication-shaped names inside tool/resource bodies, an
application-level `authenticate` tool, and every per-tool decorator are
excluded as transport-auth evidence. A decorator on one tool does not prove
that the HTTP/SSE transport is protected.

Registered middleware and other existing module-level enforcement evidence
may count. Explicit configuration is narrower: only `auth=` or
`authentication=` on recognized `FastMCP(...)` construction may count.
`requests.get(auth=...)`, `httpx.Client(auth=...)`, unrelated constructors,
tool-body constructors, empty/false values, and explicitly disabled providers
do not count. If transport authentication cannot be established statically,
RDY002 is retained.

## Test coverage

The final suite has 199 tests, up from the 121-test Phase 2 starting point, so
78 tests were added during Phase 3. The five focused Phase 3 modules contain
78 tests:

- `test_secret_detection.py`: 18.
- `test_path_validation.py`: 22.
- `test_command_validation.py`: 15.
- `test_duplicate_findings.py`: 5.
- `test_transport_auth_boundaries.py`: 18.

Fixtures are project-authored and not copied from DVMCP. They cover guard
dominance, lexical-only path normalization, unrelated and disabled `auth=`
configuration, derived-value names, duplicate suppression, and distinct
finding preservation.

## Final metrics

### DVMCP security

| Measurement | Phase 2 | Final candidate | Delta |
|---|---:|---:|---:|
| TP | 35 | 45 | +10 |
| FP | 3 | 1 | -2 |
| FN | 10 | 0 | -10 |
| Precision | 0.921053 | 0.978261 | +0.057208 |
| Recall | 0.777778 | 1.000000 | +0.222222 |
| F1 | 0.843374 | 0.989011 | +0.145637 |

Final per-rule security TP/FP/FN: MCP001 5/0/0, MCP002 7/0/0, MCP003
4/0/0, MCP004 11/1/0, MCP005 8/0/0, MCP006 4/0/0, MCP101 6/0/0.

### DVMCP readiness

| Measurement | Phase 2 | Final candidate |
|---|---:|---:|
| TP | 18 | 20 |
| FP | 0 | 0 |
| FN | 2 | 0 |
| Precision | 1.000000 | 1.000000 |
| Recall | 0.900000 | 1.000000 |
| F1 | 0.947368 | 1.000000 |

RDY001 and RDY002 each finish at TP 10, FP 0, FN 0 on DVMCP.

### Local boundaries

- Security: TP 0, FP 3, FN 0. The pre-existing review signals are MCP001
  registration resemblance, MCP101 benign imperative wording, and MCP103 a
  legitimate base64 example.
- Readiness: TP 0, FP 1, FN 0. The RDY002 report is disputed Case 15.

## Remaining and disputed cases

- DVMCP challenge10 line 123, MCP004: one scored false positive for a
  literal `Master Password` inside a resource response. Reviewer-packet Case
  16 treats this as a potential ground-truth gap awaiting independent review.
  A scanner defect, including over-eager section-header inference, is not ruled
  out. The label was not changed.
- local-boundaries-v1 `false_positive/imported_auth/server.py`, RDY002:
  disputed Case 15. Its sibling decorator is a no-op and does not establish
  transport protection. The existing safe label was not changed, so the
  conservative detector produces one readiness false positive pending separate
  adjudication.
- No false negatives are measured in either current corpus. This does not mean
  none exist outside these corpora.

## Coverage

The Phase 2 completion report recorded 91 percent branch-aware coverage. The
correction review initially measured Phase 3 at 88.74 percent. After adding the
final 17 regression tests in this round, the final Phase 3 measurement is
89.55 percent. The precise historical Phase 2 run could not be reproduced from
retained coverage artifacts. Phase 3 added substantial detector branches for
literals, scope resolution, guard dominance, canonicalization, auth
configuration, and duplicate identity, so the final result still represents a
modest coverage decrease from the reported Phase 2 figure.

## Threats to validity

- DVMCP is small, intentionally vulnerable, and not representative of the MCP
  ecosystem.
- Local fixtures and proposed outcomes are not independently reviewed.
- The benchmark has no exhaustive true-negative universe.
- Static evidence does not prove reachability or exploitability.
- Guard dominance is limited to direct function-body siblings.
- Literal-shape, placeholder, name, and section-header heuristics can still
  produce false positives or false negatives.
- RDY002 cannot prove arbitrary custom or cross-file transport enforcement.
- Candidate evidence and the reviewer packet remain unreviewed.

## Reviewer packet

`benchmark/reviewer_packet/phase3-reviewer-packet.md` contains source regions,
sources, sinks, preconditions, proposed outcomes, and blank reviewer fields.
No case is marked independently reviewed.

## Reproduction commands

```text
python -m pytest -q
python -m pytest --cov=mcp_scanner --cov-branch --cov-report=term-missing
python -m ruff check src benchmark tests
python -m ruff format --check src benchmark tests
python -m mypy src benchmark
python -m bandit -q -r src benchmark -x benchmark/fixtures,benchmark/.corpora,benchmark/results
python -m build
python -m benchmark.run --corpus local-boundaries-v1 --output-dir benchmark/results/local-boundaries-v1
python -m benchmark.run --corpus dvmcp-79734c19 --retrieve --output-dir benchmark/results/dvmcp-79734c19 --baseline benchmark/baselines/dvmcp-79734c19/metrics.json
git diff --check
```

No vulnerable corpus server is imported or executed by these commands.
