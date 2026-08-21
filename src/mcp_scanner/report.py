"""Report formatting for scan results."""

import json
import os

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_LABEL = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}


def _readiness_lines(readiness):
    lines = []
    ordered = sorted(readiness, key=lambda r: (SEVERITY_ORDER[r.severity], r.line))
    for r in ordered:
        loc = f"line {r.line}" if r.line else "repository root"
        lines.append(f"    [{SEVERITY_LABEL[r.severity]}] {r.check_id} ({loc})")
        lines.append(f"      {r.title}")
        lines.append(f"      {r.detail}")
        lines.append("")
    return lines


def format_text(path, findings, errors, readiness=None):
    readiness = readiness or []
    header = f"MCP Security Scan: {path}"
    lines = [header, "=" * len(header)]

    if errors:
        for e in errors:
            lines.append(f"  [error] {e}")
        lines.append("")

    if not findings and not readiness:
        lines.append("  No findings.")
        return "\n".join(lines)

    if findings:
        ordered = sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.line))

        counts: dict[str, int] = {}
        for f in ordered:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        summary = "  Summary: " + ", ".join(
            f"{counts[s]} {SEVERITY_LABEL[s]}" for s in ("critical", "high", "medium", "low") if s in counts
        )
        lines.append(summary)
        lines.append("")

        for f in ordered:
            location = f"line {f.line} in {f.function_name}()"
            if f.file:
                # One-hop cross-file finding: `line` refers to a line in
                # this other file, not the file named in the header above.
                # Say so explicitly rather than leaving a line number that
                # silently doesn't match the scanned path. Shown relative
                # to the current directory when possible, purely for
                # readability -- the JSON output (to_dict/format_json)
                # always carries the absolute path.
                try:
                    shown_file = os.path.relpath(f.file)
                except ValueError:
                    shown_file = f.file
                location += f" [imported by {path}, defined in {shown_file}]"
            lines.append(f"  [{SEVERITY_LABEL[f.severity]}] {f.rule_id} {location}")
            lines.append(f"    {f.title}")
            lines.append(f"    SAIF: {f.saif_category} ({f.saif_code})")
            lines.append(f"    {f.detail}")
            lines.append("")

    if readiness:
        # Deliberately separate from the findings above -- these are risky
        # defaults, not confirmed vulnerabilities. See readiness.py.
        lines.append("  Readiness (risky defaults -- not necessarily exploitable on their own):")
        lines.extend(_readiness_lines(readiness))

    return "\n".join(lines)


def format_repo_readiness(path, readiness):
    """Report for repository-level readiness findings (currently just
    RDY003, the missing-SECURITY.md check) that aren't tied to any single
    scanned file.
    """
    header = f"MCP Security Scan: {path} (repository-level readiness)"
    lines = [header, "=" * len(header)]
    if not readiness:
        lines.append("  No findings.")
        return "\n".join(lines)
    lines.extend(_readiness_lines(readiness))
    return "\n".join(lines)


def to_dict(path, findings, errors, readiness=None):
    return {
        "path": path,
        "errors": errors,
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "saif_category": f.saif_category,
                "saif_code": f.saif_code,
                "line": f.line,
                "function": f.function_name,
                "detail": f.detail,
                "file": f.file,
            }
            for f in findings
        ],
        "readiness": [
            {
                "check_id": r.check_id,
                "title": r.title,
                "severity": r.severity,
                "line": r.line,
                "detail": r.detail,
            }
            for r in (readiness or [])
        ],
    }


def format_json(path, findings, errors, readiness=None):
    return json.dumps(to_dict(path, findings, errors, readiness), indent=2)


def format_live_text(target, findings, tool_count, resource_count):
    """Report for `mcp-scanner live` -- description-heuristic findings
    against a running server's actually-reported tools/resources. There's
    no source file or line number here (see scan_description_text()'s
    docstring), so findings are addressed by tool/resource name instead of
    `line X in Y()`.
    """
    header = f"MCP Live Scan: {target}"
    lines = [header, "=" * len(header)]
    lines.append(f"  Connected. {tool_count} tool(s), {resource_count} resource(s) enumerated.")
    lines.append("")

    if not findings:
        lines.append("  No description findings.")
        return "\n".join(lines)

    ordered = sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.function_name))
    counts: dict[str, int] = {}
    for f in ordered:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = "  Summary: " + ", ".join(
        f"{counts[s]} {SEVERITY_LABEL[s]}" for s in ("critical", "high", "medium", "low") if s in counts
    )
    lines.append(summary)
    lines.append("")

    for f in ordered:
        lines.append(f"  [{SEVERITY_LABEL[f.severity]}] {f.rule_id} '{f.function_name}'")
        lines.append(f"    {f.title}")
        lines.append(f"    SAIF: {f.saif_category} ({f.saif_code})")
        lines.append(f"    {f.detail}")
        lines.append("")

    return "\n".join(lines)


def live_to_dict(target, findings, tool_count, resource_count, error=None):
    return {
        "target": target,
        "error": error,
        "tool_count": tool_count,
        "resource_count": resource_count,
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "saif_category": f.saif_category,
                "saif_code": f.saif_code,
                "name": f.function_name,
                "detail": f.detail,
            }
            for f in findings
        ],
    }


def format_live_json(target, findings, tool_count, resource_count):
    return json.dumps(live_to_dict(target, findings, tool_count, resource_count), indent=2)


def format_config_text(config_path, shadow_findings, per_server, errors):
    """Report for `mcp-scanner config` -- per-server connection status plus
    any cross-server tool-name collisions found. Deliberately separate
    sections, same reasoning as findings vs. readiness elsewhere in this
    project: "server X failed to connect" and "servers X and Y both expose
    a tool named Y" are different kinds of problem.
    """
    header = f"MCP Config Scan: {config_path}"
    lines = [header, "=" * len(header)]

    for name in sorted(per_server):
        result = per_server[name]
        if result["error"]:
            lines.append(f"  [error] {name}: {result['error']}")
        else:
            lines.append(f"  {name}: {len(result['tools'])} tool(s) enumerated")
    lines.append("")

    if not shadow_findings:
        lines.append("  No tool-name collisions found across configured servers.")
        return "\n".join(lines)

    ordered = sorted(shadow_findings, key=lambda f: SEVERITY_ORDER[f.severity])
    counts: dict[str, int] = {}
    for f in ordered:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = "  Summary: " + ", ".join(
        f"{counts[s]} {SEVERITY_LABEL[s]}" for s in ("critical", "high", "medium", "low") if s in counts
    )
    lines.append(summary)
    lines.append("")

    for f in ordered:
        lines.append(f"  [{SEVERITY_LABEL[f.severity]}] {f.check_id}")
        lines.append(f"    {f.title}")
        lines.append(f"    {f.detail}")
        lines.append("")

    return "\n".join(lines)


def config_to_dict(config_path, shadow_findings, per_server, errors):
    return {
        "config_path": config_path,
        "servers": per_server,
        "errors": errors,
        "shadow_findings": [
            {
                "check_id": f.check_id,
                "title": f.title,
                "severity": f.severity,
                "detail": f.detail,
            }
            for f in shadow_findings
        ],
    }


def format_config_json(config_path, shadow_findings, per_server, errors):
    return json.dumps(config_to_dict(config_path, shadow_findings, per_server, errors), indent=2)
