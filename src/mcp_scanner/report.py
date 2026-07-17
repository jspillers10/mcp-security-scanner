"""Report formatting for scan results."""

import json

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_LABEL = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}


def format_text(path, findings, errors):
    lines = []
    lines.append(f"MCP Security Scan: {path}")
    lines.append("=" * (len(lines[0])))

    if errors:
        for e in errors:
            lines.append(f"  [error] {e}")
        lines.append("")

    if not findings:
        lines.append("  No findings.")
        return "\n".join(lines)

    ordered = sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.line))

    counts = {}
    for f in ordered:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = "  Summary: " + ", ".join(
        f"{counts[s]} {SEVERITY_LABEL[s]}" for s in ("critical", "high", "medium", "low") if s in counts
    )
    lines.append(summary)
    lines.append("")

    for f in ordered:
        lines.append(f"  [{SEVERITY_LABEL[f.severity]}] {f.rule_id} line {f.line} in {f.function_name}()")
        lines.append(f"    {f.title}")
        lines.append(f"    SAIF: {f.saif_category} ({f.saif_code})")
        lines.append(f"    {f.detail}")
        lines.append("")

    return "\n".join(lines)


def format_json(path, findings, errors):
    return json.dumps(
        {
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
                }
                for f in findings
            ],
        },
        indent=2,
    )
