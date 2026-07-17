# mcp-security-scanner

A static security scanner for MCP (Model Context Protocol) server source code. It inspects tool and resource definitions for the vulnerability patterns most likely to turn a model's tool-use into an actual foothold, and maps every finding to a risk category from Google's [Secure AI Framework](https://saif.google/secure-ai-framework/risks) (SAIF).

## Why this exists

MCP servers expose tools that a model can call directly, often with real side effects — running shell commands, reading files, hitting internal APIs. That's a new-ish attack surface, and general-purpose static analysis tools weren't built with "an LLM decides which arguments to pass" as a threat model. This scanner targets that gap specifically: unsanitized tool parameters reaching a shell, a file path, an `eval()`, or a deserializer; debug/log resources with no access control; tools that combine more capability than they need.

## What it checks

| Rule | Finding | Severity | SAIF category |
|------|---------|----------|----------------|
| MCP001 | Command injection via tool parameter | Critical | Insecure Integrated Component |
| MCP002 | Path traversal via tool parameter | High | Insecure Integrated Component |
| MCP003 | Dynamic code execution (`eval`/`exec`) reachable from a tool | Critical | Insecure Integrated Component |
| MCP004 | Hardcoded credential or secret | High | Sensitive Data Disclosure |
| MCP005 | Sensitive resource exposed with no apparent access control | High | Sensitive Data Disclosure |
| MCP006 | Excessive tool functionality (multiple sensitive capabilities in one tool) | Medium | Rogue Actions |
| MCP007 | Deserialization of untrusted data (`pickle`, unsafe `yaml.load`) | High | Insecure Integrated Component |

## How it works

The scanner is a lightweight, best-effort static analyzer built on Python's `ast` module — not a full dataflow engine. For each function decorated as an MCP tool, it tracks the function's parameters as "tainted" inputs, propagates that taint through simple local variable assignments, and checks whether a tainted value reaches a dangerous sink (a shell command, a file open, `eval`, a deserializer). It also recognizes simple guard-clause validation (`if not valid(x): raise/return`) and suppresses findings for values that are checked before use, and it distinguishes real shell-injection risk (`shell=True`, or `os.system`/`os.popen`, which always invoke a shell) from the safe `subprocess.run([...])` argv-list pattern.

This means it will have both false positives and false negatives, the same as any lightweight SAST tool (Bandit and Semgrep included) — it's meant to flag things worth a human look, not to replace review.

## Usage

```bash
pip install -e .

# Scan a single file
mcp-scanner path/to/server.py

# Scan a directory
mcp-scanner path/to/mcp_project/

# Machine-readable output
mcp-scanner path/to/server.py --format json

# For CI: exit non-zero if anything critical or higher is found
mcp-scanner path/to/mcp_project/ --fail-on critical
```

### Example output

```
MCP Security Scan: server.py
=============================
  Summary: 1 CRITICAL, 1 HIGH

  [CRITICAL] MCP001 line 21 in export_report()
    Command injection via tool parameter
    SAIF: Insecure Integrated Component (IIC)
    tainted parameter reaches subprocess.run(shell=True)

  [HIGH] MCP005 line 49 in worker_log()
    Sensitive resource exposed without apparent access control
    SAIF: Sensitive Data Disclosure (SDD)
    resource 'debug://worker_log' looks like it exposes internal state
```

## Running the tests

```bash
pip install pytest
PYTHONPATH=src pytest tests/ -v
```

The test suite includes two regression tests worth calling out specifically: one confirms that `subprocess.run([...])` without `shell=True` is *not* flagged as command injection (the safe argv-list pattern), and one confirms that a parameter with an explicit validation guard before use is not flagged as path traversal. Both were real false positives caught during development and fixed before this was published — see `tests/fixtures/safe_example.py` for the patterns the scanner is expected to leave alone.

## Validated against a real-world benchmark

To check this against something other than fixtures written to be caught, I ran it against [Damn Vulnerable MCP Server](https://github.com/harishsg993010/damn-vulnerable-MCP-server) (1.3k+ stars), a public, independently-maintained lab of 10 intentionally vulnerable MCP servers.

Result: 31 findings across the 10 `server.py` implementations, correctly landing on several of the lab's own named vulnerability classes — all 4 command-injection points in the "Remote Access Control" challenge, the `eval()` calls in the vulnerable calculator, and hardcoded AWS credentials across three separate challenges.

Two honest misses worth naming rather than hiding: it found nothing on the "Tool Poisoning" challenge, because that attack is a malicious instruction embedded in a tool's docstring — a model-facing prompt-injection attack, not a code-level bug, and outside what a source-code static analyzer is built to catch. And it missed every `server_sse.py` variant, because those wrap FastMCP inside a custom class instead of using the `@mcp.tool()` / `@mcp.resource()` decorator pattern the analyzer looks for — a real gap, and the next thing worth fixing.

## Limitations

This is a proof-of-concept static analyzer, not a production SAST tool. It works on Python MCP servers using FastMCP-style `@mcp.tool()` / `@mcp.resource()` decorators. It does not follow imports across files, does not model control flow precisely (validation detection is a heuristic, not a real reachability analysis), and will miss vulnerabilities hidden behind sufficiently indirect code. Treat findings as a prioritized starting point for review, not a certification of safety — and treat a clean scan the same way.

## Background

Built while working through Hack The Box's Certified Offensive AI Expert path, applying the same categories of tool-use vulnerabilities to a purpose-built detection tool. Framing findings against SAIF's risk taxonomy specifically (rather than an ad hoc severity label) makes results easier to communicate to teams already using that framework for AI risk assessment.
