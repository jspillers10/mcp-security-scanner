# Security Policy

## Supported versions

mcp-security-scanner is currently a research preview. Security fixes are made on the
`main` branch. There is not yet a backward-support window for older snapshots or an
independently maintained stable release line.

| Version | Security support |
| --- | --- |
| Current `main` branch | Supported |
| Older commits or forks | Not guaranteed |

## Reporting a vulnerability

Please report suspected vulnerabilities through a private
[GitHub Security Advisory](https://github.com/jspillers10/mcp-security-scanner/security/advisories/new).
Do not open a public issue for an unpatched vulnerability.

Include enough information to reproduce and assess the problem:

- the affected version or commit;
- the operating system and Python version;
- a minimal proof of concept;
- the expected and actual behavior;
- the security impact; and
- any suggested remediation, if available.

The maintainer will coordinate validation, remediation, and a disclosure date with
the reporter. Please allow time for a fix before publishing technical details. No
bounty program or guaranteed response-time service level is currently offered.

## Scope

Security reports are appropriate for issues such as:

- scanning untrusted source unexpectedly executing that source;
- a crafted file escaping the requested scan or output boundary;
- unsafe handling of live-server connection data or credentials;
- dependency or packaging behavior that compromises scanner users; and
- a reliable false negative that materially contradicts a documented rule.

The intentionally vulnerable files under `tests/fixtures/` are test data, not
vulnerabilities in deployed software. Vulnerabilities in third-party benchmark
projects, including Damn Vulnerable MCP Server, should be reported to their own
maintainers. Ordinary false positives, feature requests, and documentation problems
may be filed as public GitHub issues.

Static scans read files and do not import or execute the target source. The `live`
and `config` commands intentionally connect to MCP servers. Only use those modes on
systems you own or are explicitly authorized to assess.
