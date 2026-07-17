"""CLI entrypoint for mcp-scanner."""

import argparse
import os
import sys

from .analyzer import scan_file
from .report import format_text, format_json


def iter_python_files(path):
    if os.path.isfile(path):
        yield path
        return
    for root, _, files in os.walk(path):
        if any(part.startswith(".") for part in root.split(os.sep)):
            continue
        for name in files:
            if name.endswith(".py"):
                yield os.path.join(root, name)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="mcp-scanner",
        description="Static security scanner for MCP (Model Context Protocol) server source code.",
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument(
        "--format", choices=["text", "json"], default="text", help="Output format (default: text)"
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default="none",
        help="Exit with a non-zero status if a finding at or above this severity is present",
    )
    args = parser.parse_args(argv)

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_findings = []
    json_results = []

    for file_path in iter_python_files(args.path):
        findings, errors = scan_file(file_path)
        all_findings.extend(findings)
        if args.format == "json":
            json_results.append(
                {
                    "path": file_path,
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
                }
            )
        else:
            print(format_text(file_path, findings, errors))
            print()

    if args.format == "json":
        import json as _json

        print(_json.dumps(json_results, indent=2))

    if args.fail_on != "none":
        threshold = severity_rank[args.fail_on]
        if any(severity_rank[f.severity] <= threshold for f in all_findings):
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
