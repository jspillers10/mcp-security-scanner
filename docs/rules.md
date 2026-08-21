# Rule reference

This page summarizes the implemented checks. Findings are review leads, not proof that
an exploit is possible or that a clean target is safe.

## Static vulnerability rules

| ID | Severity | Check | Important boundary |
| --- | --- | --- | --- |
| MCP001 | Critical | Tainted tool input reaches a shell command | `subprocess` argv lists without `shell=True` are not flagged |
| MCP002 | High | Tainted tool input reaches `open()` | Guard recognition is approximate and can accept weak validation |
| MCP003 | Critical | `eval()` or `exec()` occurs in a tool | Presence in a tool is reported even when taint is not proven |
| MCP004 | High | Source matches a hardcoded-secret pattern | Pattern matching can flag fixture or example values |
| MCP005 | High | A resource name or URI looks sensitive | Names are heuristic and access control is not modeled |
| MCP006 | Medium | One tool combines at least two sensitive capabilities | Capability aggregation is limited to the primary tool body |
| MCP007 | High | A tool uses an unsafe deserialization API | Data provenance is not modeled precisely |
| MCP008 | High | Tainted input is interpolated or concatenated into a one-argument SQL execution call | Complex query builders and nonstandard database APIs are out of scope |
| MCP101 | Medium | A description contains model-directed imperative language | Regex matching cannot understand intent |
| MCP102 | High | A description contains invisible or bidi-control Unicode | A rare legitimate use may require suppression |
| MCP103 | Medium | A description contains a long base64-looking blob | Legitimate encoded examples can match |
| MCP104 | High | A description appears to redirect use from another tool | Only the implemented phrase patterns are recognized |

MCP001 through MCP008 inspect Python source with `ast`. MCP101 through MCP104 inspect
literal decorator descriptions and docstrings. Static discovery supports recognized
tool/resource decorators and direct `add_tool()` or `add_resource()` registrations.
Taint can be followed into a bare same-file helper or a directly imported sibling
module for one call hop. Full control-flow, alias, class-method, and package-wide
interprocedural analysis are not implemented.

## Readiness checks

Readiness results are deliberately separate from vulnerability results. They identify
risky defaults and missing project hardening, not confirmed exploits.

| ID | Severity | Check |
| --- | --- | --- |
| RDY001 | Medium | Literal default bind to `0.0.0.0` |
| RDY002 | High | SSE/HTTP setup with no auth-shaped code identifier in the same file |
| RDY003 | Low | Missing repository-root `SECURITY.md` |
| RDY004 | Low | Hardcoded privileged port below 1024 |
| RDY005 | High | Literal `debug=True` |
| RDY006 | Medium | Literal `reload=True` |

## Configuration checks

These checks connect to the servers listed in an MCP client configuration and compare
the tool names returned during that single enumeration.

| ID | Severity | Check |
| --- | --- | --- |
| SHADOW001 | High | Identical tool name returned by multiple configured servers |
| SHADOW002 | Medium | Tool names of at least four characters differ by at most two edits across servers |

Name collisions are review signals, not proof of malicious shadowing. The scan is a
snapshot and does not monitor later tool redefinition.

## Suppressions

Reviewed description findings can be suppressed on the description or docstring line:

```python
@mcp.tool(description="...")  # mcp-scanner: ignore=MCP101
```

A bare `# mcp-scanner: ignore` suppresses every description rule on that line. Static
sink and readiness checks do not currently have a general suppression mechanism.
