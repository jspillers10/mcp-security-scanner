# mcp-security-scanner

[![CI](https://github.com/jspillers10/mcp-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/jspillers10/mcp-security-scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

mcp-security-scanner is a production-minded research preview for finding security risks
in Python Model Context Protocol servers. MCP tools turn model-selected inputs into real
side effects such as process execution, file access, database queries, and network calls.
This scanner looks for the source and metadata patterns that make those boundaries risky,
without importing or executing the source being scanned.

The project has three deliberately bounded modes:

| Mode | What it does | What it does not do |
| --- | --- | --- |
| Static | Parses Python source for tainted dangerous sinks, exposed resources, poisoned descriptions, and risky deployment defaults | Full dataflow, semantic validation, or non-Python analysis |
| Live | Connects once to an authorized MCP server and scans its reported tool/resource descriptions | Proxy traffic, inspect implementations, or monitor later changes |
| Config | Enumerates servers in an MCP client config and compares returned tool names | Prove that a collision is malicious or continuously monitor servers |

Development used the independently maintained
[Damn Vulnerable MCP Server](https://github.com/harishsg993010/damn-vulnerable-MCP-server)
lab. The research benchmark now pins the corpus commit and file hashes, validates reviewed
ground truth, and reports reproducible per-rule precision and recall without executing the
vulnerable servers. See the [benchmark methodology](docs/benchmark.md),
[benchmark harness](benchmark/README.md), and complete [rule reference](docs/rules.md).

## Install

Python 3.10 through 3.13 is supported.

```bash
python -m pip install .

# Development checkout
python -m pip install -e ".[test,dev]"

# Required only for live and config scans
python -m pip install -e ".[live]"

# Required only for the research benchmark schemas
python -m pip install -e ".[benchmark]"
```

The static scanner has no third-party runtime dependency. The `live` extra installs
version 1.x of the official MCP Python SDK because the current live implementation has
not yet migrated to its breaking 2.x API.

## Quick start

```bash
# Human-readable static scan
mcp-scanner path/to/server.py

# Scan a project and fail CI on high or critical vulnerability findings
mcp-scanner path/to/project --fail-on high

# Machine-readable output to stdout
mcp-scanner path/to/project --format json

# SARIF 2.1.0 output to a file
mcp-scanner path/to/project --format sarif -o results.sarif
```

`--fail-on` applies to MCP vulnerability findings, not the separately labeled readiness
checks. Exit code 0 means the scan completed without crossing that threshold, 1 means the
threshold was crossed, and 2 means the request or scan input was invalid. A clean scan is
not a certification of safety.

## Example

```text
MCP Security Scan: server.py
============================
  Summary: 1 CRITICAL, 1 HIGH

  [CRITICAL] MCP001 line 21 in export_report()
    Command injection via tool parameter
    SAIF: Insecure Integrated Component (IIC)
    tainted parameter reaches subprocess.run(shell=True)

  Readiness (risky defaults -- not necessarily exploitable on their own):
    [HIGH] RDY002 (line 79)
      No apparent authentication for SSE/HTTP transport
      SSE/HTTP transport set up here, but no auth-related import, decorator, or call found anywhere in this file
```

Static findings use the MCP001 through MCP008 and MCP101 through MCP104 namespaces and
include Google Secure AI Framework category metadata. RDY001 through RDY006 are reported
separately because a risky default is not automatically an exploitable vulnerability.
SHADOW001 and SHADOW002 are configuration-review signals. Exact descriptions, severities,
suppressions, and detection boundaries are in [docs/rules.md](docs/rules.md).

## SARIF and CI integration

SARIF output follows version 2.1.0 and includes tool/version metadata, rule definitions,
severity, messages, normalized source paths, and line numbers when available. Readiness
results carry `findingType: readiness` and SARIF `kind: review`; scan errors are execution
notifications and are never converted into findings.

A minimal CI step after installing the package is:

```yaml
- name: Scan MCP source
  run: mcp-scanner src --format sarif -o results.sarif --fail-on high
```

The repository's own [CI workflow](.github/workflows/ci.yml) tests supported Python
versions and Windows compatibility, produces coverage, checks lint/format/type/security
quality, builds wheel and source distributions, and smoke-tests the installed CLI.

## Live scanning

Only connect to systems you own or are explicitly authorized to assess.

```bash
# Launch a server and enumerate it over stdio
mcp-scanner live stdio python path/to/server.py

# Connect to a running SSE endpoint
mcp-scanner live sse http://127.0.0.1:8000/sse

# JSON output; live options precede the transport subcommand
mcp-scanner live --format json -o live-results.json stdio python path/to/server.py
```

The command calls `list_tools()` and `list_resources()`, applies MCP101 through MCP104 to
the returned descriptions, then disconnects. It cannot see normal tool traffic, tool
outputs, or a description that changes after enumeration.

## MCP client configuration scanning

```bash
mcp-scanner config path/to/mcp-config.json
mcp-scanner config path/to/mcp-config.json --format json -o config-results.json
```

The config must contain a top-level `mcpServers` object. Each server is enumerated once;
exact and edit-distance tool-name collisions across servers are reported for review. A
failed server is recorded without aborting enumeration of the remaining servers.

## How static analysis works

The scanner uses Python's `ast` module. Recognized MCP tool parameters begin as tainted,
taint propagates through simple assignments, and supported sink calls are inspected. The
analyzer distinguishes shell parsing from safe argv-list subprocess calls and recognizes
a narrow single-sided rejecting guard clause.

Tool and resource discovery covers supported decorator patterns plus direct
`add_tool()`/`add_resource()` registration. Taint follows one call into a bare same-file
helper or a function imported from a sibling Python file. It does not follow a second
hop, resolve indirect aliases, inspect arbitrary class methods, or model control flow
precisely. A bypassable check such as a naive path `.startswith()` guard may be mistaken
for validation.

Description checks are regex and character heuristics. They can miss paraphrased prompt
injection and flag legitimate imperative language or encoded examples. They inspect only
tool/resource descriptions, not runtime tool output or retrieved content.

## Research benchmark

The pinned DVMCP subset currently measures 35 true positives, 3 false positives, and 10
false negatives: precision 0.921, recall 0.778, and F1 0.843. Infrastructure readiness is
reported separately at 18 TP, 0 FP, and 2 FN. These results come from one curated lab
corpus and a single initial adjudication, so they are diagnostic rather than estimates of
real-world scanner performance.

```bash
python -m benchmark.run --corpus dvmcp-79734c19 --retrieve --output-dir benchmark/results/dvmcp-79734c19 --baseline benchmark/baselines/dvmcp-79734c19/metrics.json
```

The command verifies the pinned commit and SHA-256 manifest, scans exact files as text,
writes deterministic raw results and metrics plus volatile environment/timing metadata,
and returns nonzero for harness failures or a requested baseline regression. It never
imports or launches corpus code. Full scope, matching, uncertainty, and licensing caveats
are in [docs/benchmark.md](docs/benchmark.md).

## Development

```bash
python -m pip install -e ".[test,dev]"
python -m pytest -q
python -m ruff check src benchmark tests
python -m ruff format --check src benchmark tests
python -m mypy src benchmark
python -m bandit -q -r src benchmark -x benchmark/fixtures,benchmark/.corpora,benchmark/results
python -m build
```

Install `.[live,test,dev]` to include the real stdio and loopback SSE integration tests.
See [CONTRIBUTING.md](CONTRIBUTING.md) for the development and pull-request policy,
[SECURITY.md](SECURITY.md) for private reporting, and [CHANGELOG.md](CHANGELOG.md) for
notable changes.

## Limitations and research integrity

This is not a production SAST engine, runtime firewall, exploit detector, or proof of
safety. Findings require human review. Static scans can have both false positives and
false negatives; live and config scans deliberately make network or subprocess
connections and observe only one point in time.

The vulnerable examples in this repository and DVMCP are intentional lab material, not
real-world vulnerability claims. Current benchmark precision and recall apply only to the
pinned, adjudicated scope and must not be generalized to production MCP servers.
Historical observations, measured failures, uncertainty, and known misses are retained in
[docs/benchmark.md](docs/benchmark.md).

## License

[MIT](LICENSE)
