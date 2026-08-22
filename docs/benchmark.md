# Benchmark methodology

## 1. Purpose

This benchmark measures the current static scanner against reviewed, location-level
ground truth. It is designed to expose false positives, false negatives, duplicate
findings, rule-specific weaknesses, and unsupported attack classes. It is not a product
marketing score and does not establish performance on the broader MCP ecosystem.

The primary result is based on a pinned subset of Damn Vulnerable MCP Server (DVMCP).
A second project-owned corpus supplies safe examples and declared analysis boundaries.

### Research question

For the pinned scanner source and corpus, which declared rules produce correct findings,
which produce false alarms, which in-scope cases are missed, and which attack classes fall
outside the static scanner's claims?

### Scanner version

The measured run used package version 0.1.0, Git commit
`6ccd4587fbd6e76c8fec206e15e74bb6f6cd073a`, and scanner source SHA-256
`9b548e3b2e9c690c6e3d951b6fc288fb1d89ac95a96e85df59505c709233614d`.
The worktree was dirty because Phase 1 and Phase 2 changes were not committed without
maintainer approval. The source hash, rather than the commit alone, identifies measured
scanner code.

## 2. Corpus provenance and licensing

The primary corpus is
[Damn Vulnerable MCP Server](https://github.com/harishsg993010/damn-vulnerable-MCP-server),
pinned to commit `79734c19f5104cd11486c90926d245560f53befa` and retrieved on
2026-08-20. The upstream README describes ten intentionally vulnerable educational MCP
challenges and declares the project MIT-licensed.

There is a licensing caveat: the pinned tree has no `LICENSE` file even though its README
refers to one. The manifest therefore records `declared-unverified`, and this repository
does not vendor DVMCP. Retrieval produces a separate ignored checkout. Users should make
their own licensing determination before redistributing it.

The `local-boundaries-v1` fixtures are project-owned and covered by this repository's
MIT license. Each corpus file has an individual SHA-256, and the sorted scoped file set
has a canonical tree SHA-256 in `benchmark/manifest.json`.

## 3. Scope and exclusions

### Threat model

The scanner models an attacker or untrusted model-visible content influencing MCP tool
parameters, descriptions, or exposed resources, with consequences at selected command,
file, code-execution, secret, and capability sinks. It also reviews network deployment
defaults. Static source evidence cannot establish runtime reachability or exploitability,
and the benchmark does not prove that the scanner is production-ready.

The DVMCP scan scope is exactly ten files: each classic
`challenges/<difficulty>/challengeN/server.py`. The SSE variants are transport duplicates
and are excluded to prevent double-counting. Common code, upstream tests, solutions, and
documentation are not scanner inputs. Documentation is used only as adjudication
evidence.

The benchmark reads Python source and parses its AST. It does not import, install, launch,
or connect to DVMCP. Runtime mutation, cross-server collision behavior, dynamic metadata,
and attack classes with no current scanner rule are recorded under `excluded`, not
silently counted as false negatives. The benchmark does not perform dynamic red-team
execution or call external services.

## 4. Rule mapping

Ground-truth cases map to the scanner's public IDs:

- MCP001 command injection
- MCP002 path traversal
- MCP003 direct `eval` or `exec` reachability
- MCP004 hardcoded secrets
- MCP005 sensitive resource exposure
- MCP006 excessive combined capability
- MCP101 model-directed description language
- RDY001 all-interface binding and RDY002 missing transport-authentication evidence

MCP101 is placed in `description_vulnerability`; MCP001 through MCP008 are placed in
`code_vulnerability`. RDY findings are scored independently in `readiness` because they
are risky deployment signals, not confirmed vulnerabilities. Unsupported and runtime
cases use `excluded`.

## 5. Ground-truth process

Every case records a stable ID, file, line range and optional function, vulnerability
class, category, expected result, source, sink, attack preconditions, source-of-truth
reference, rationale, review state, and matching mode. Inputs are validated against the
JSON Schemas in `benchmark/schemas` plus semantic checks for unique IDs, scoped files,
corpus identity, review state, and metric-group consistency.

The initial adjudication is marked `single-reviewed` and identifies the review as
Codex-assisted manual source review. It is not represented as independent expert review.
Future changes to labels should preserve disputed decisions in version control and should
move a case to `independent-reviewed` only after a second reviewer checks source, sink,
preconditions, and rule mapping without relying on current scanner output.

One logical credential bundle is one MCP004 case even when it contains multiple literal
values. Distinct registrations and distinct dangerous sink calls are separate cases.
Scanner output was used to test the adjudication, not to define it.

## 6. Matching method

A finding is eligible to match a positive case only when all declared keys agree:

1. normalized corpus-relative file path;
2. expected rule ID;
3. expected severity;
4. function name when the case specifies one; and
5. exact line or a declared bounded line range and tolerance.

Candidate pairs are sorted by line distance, function specificity, case ID, and finding
ID. Matching is one-to-one. A ground-truth case and a scanner finding can each be used at
most once. This prevents duplicate findings at one sink from inflating true positives.
Extra findings are false positives; unmatched reviewed in-scope positive cases are false
negatives. Findings in reviewed safe regions are annotated with the corresponding safe
case ID when possible. Vulnerability class is retained on each case and match for
stratification and review; rule ID is the executable class mapping because scanner output
does not carry an independent vulnerability-class field.

Approximate matching is never implicit. The ground truth must declare `line_tolerant` and
its numeric tolerance. Current DVMCP ranges use zero additional tolerance.

## 7. Metrics

The harness reports TP, FP, FN, precision, recall, and F1 overall and per rule. It also
reports code, description, and readiness groups separately. A zero denominator is encoded
as JSON `null` and displayed as `N/A`, not coerced to zero or one.

Wilson 95% intervals are included for precision and recall. The corpus is curated rather
than randomly sampled, so these intervals describe finite denominator uncertainty only.
They do not justify population-level claims. Accuracy is intentionally `null` because the
benchmark does not define an exhaustive universe of true negatives.

## 8. Safe execution model

### Ethical and safety considerations

DVMCP is an intentionally vulnerable educational lab. Findings in it are not newly
discovered vulnerabilities in a production organization. The benchmark handles its code
as inert text, requires no credentials, sends no source to an external service, and does
not start a server or attempt exploitation.

The runner calls the scanner's AST entry points in process and only opens the exact files
listed in the verified manifest. It never imports a corpus module. Corpus retrieval uses
argument-list Git subprocesses with explicit timeouts. Scanner and corpus Git metadata
queries also use argument lists and ten-second timeouts. No shell is used by the harness.

A scanner read or parse error is recorded in raw output and makes the command exit 2.
Input, schema, commit, and hash failures also exit 2 before scoring. The vulnerable code
shown in fixtures exists only as static text.

## 9. Reproducibility

Install the project with the dedicated schema-validation extra:

```bash
python -m pip install -e ".[benchmark]"
```

From a fresh checkout, one command retrieves the pinned upstream corpus when absent,
verifies its commit and hashes, runs the static scan, compares ground truth, writes all
evidence, and checks the versioned baseline:

```bash
python -m benchmark.run --corpus dvmcp-79734c19 --retrieve --output-dir benchmark/results/dvmcp-79734c19 --baseline benchmark/baselines/dvmcp-79734c19/metrics.json
```

The project-owned boundary corpus requires no network access:

```bash
python -m benchmark.run --corpus local-boundaries-v1 --output-dir benchmark/results/local-boundaries-v1
```

`raw-results.json`, `classifications.json`, `metrics.json`, and `report.md` are stable for
the same scanner source and verified corpus. `run-metadata.json` is deliberately volatile:
it records UTC start time, elapsed seconds, command, Python, platform, dependency versions,
working directory, and corpus directory. Generated result directories are ignored; the
reviewed regression baseline is versioned.

The baseline policy has zero tolerance for measured regressions. The runner exits 1 if
true positives decrease, false positives or false negatives increase, a comparable
non-null precision, recall, or F1 value decreases, or scanner errors increase. It does not
treat volatile run metadata as regression input.

The scanner identity includes package version, Git commit, dirty-worktree state, and a
SHA-256 over scanner source files. A dirty tree is therefore visible rather than being
misrepresented as the recorded commit alone. The raw result also hashes the harness,
manifest, and exact ground-truth document used for the classification.

## 10. Measured results, Phase 2 historical baseline

This section preserves the Phase 2 historical baseline. It is not the latest candidate
measurement. See the [final Phase 3 candidate results](phase3-results.md) for the later
scanner measurement and its remaining limitations.

The Phase 2 measured static result at the pinned corpus is:

| Group | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| Security overall | 35 | 3 | 10 | 0.921 | 0.778 | 0.843 |
| Code vulnerabilities | 29 | 3 | 10 | 0.906 | 0.744 | 0.817 |
| Description vulnerabilities | 6 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Infrastructure readiness | 18 | 0 | 2 | 1.000 | 0.900 | 0.947 |

The three security false positives are one allowlisted fixed command map reported as
MCP001 and two duplicate MCP003 results produced by helper propagation at already-reported
eval sinks. The ten security false negatives are seven MCP004 hardcoded-secret bundles,
two MCP002 arbitrary-path reads, and one MCP001 shell call behind an inadequate denylist.

The two readiness false negatives are both RDY002. Token-handling identifiers in Challenge
7 and an application-level `authenticate` tool in Challenge 10 suppress the heuristic even
though neither protects the HTTP transport.

The local boundary corpus deliberately has no positive denominator. It currently exposes
three security false alarms: benign imperative prose, a legitimate base64 example, and a
non-MCP `add_tool` method. It also exposes one readiness false alarm for an authorization
guard imported under neutral names. The remaining seven boundary cases are excluded and
reported without being converted into false negatives.

### Failure analysis

Measured failures are retained in classifications and the Markdown report. The dominant
miss class is MCP004 on multiline strings and dictionary values. MCP002 misses show that
an existence check is incorrectly treated like path validation. The MCP001 miss shows the
same weakness for an incomplete command denylist. The duplicate MCP003 false positives
come from counting direct and helper-propagated paths to the same physical eval calls.

## 11. Statistical uncertainty and interpretation

The overall security precision interval is 0.792 to 0.973 and recall interval is 0.637 to
0.875 using Wilson 95% intervals. Per-rule intervals are wider. For example, MCP004 recall
is 0.364 on eleven adjudicated secret bundles, with a 0.152 to 0.646 interval.

These numbers are conditional on one pinned educational corpus, this rule taxonomy, these
case-counting decisions, and a single initial reviewer. They should be read as diagnostic
measurements, not estimates of detection rates for arbitrary production MCP servers.
Results apply only to the recorded scanner source hash and pinned corpus revision.

## 12. Historical comparison

Earlier project notes reported 31 findings across ten DVMCP files, later description-rule
observations, and readiness counts over both classic and SSE variants. Those runs lacked a
corpus commit, file hashes, dependency record, command, raw result, and machine-readable
ground truth. They are therefore not a comparable baseline.

The Phase 2 count of 38 security findings is not an improvement claim over the historical
31. It differs because the scanner changed, duplicate sink findings remain visible, scope
is now exact, and the present report distinguishes detections from correctness. The only
valid comparable Phase 2 baseline is the versioned metric record produced from the pinned
corpus and documented adjudication. The later candidate measurement is documented in the
[Phase 3 results](phase3-results.md).

## 13. Limitations and future benchmark work

- Ground truth has one initial review, not independent consensus.
- DVMCP is deliberately vulnerable and may not represent production code distributions.
- MCP004 literal patterns have low measured recall on multiline strings and dictionaries.
- The guard-clause model can mistake weak denylists or existence checks for validation.
- One-hop dataflow does not cover deeper helpers, class dispatch, aliases, or dynamic calls.
- Runtime tool mutation, indirect prompt injection through output, and cross-server tool
  resolution remain excluded until a safe, separately designed evaluation exists.
- Description results cover only MCP101 examples in this corpus; the perfect score is based
  on six cases and does not establish semantic robustness.
- Performance timing is recorded for auditability but no speed claim is made from a single
  machine or run.

Future benchmark revisions should add independent adjudication, more benign production-like
servers, reviewed MCP102 through MCP104 cases, explicit versioned case migrations, and only
then broader dynamic evaluation. Those additions are separate from packaging, SBOM,
provenance, or release automation work.
