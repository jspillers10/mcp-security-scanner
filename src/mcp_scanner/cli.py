"""CLI entrypoint for mcp-scanner.

Dispatch is manual rather than argparse subparsers, to keep the original
`mcp-scanner path/to/server.py` invocation working unchanged: if the first
argument is literally "live" or "config", that subcommand runs; anything
else is treated as a path for the static scanner, same as before this file
had subcommands at all.
"""

import argparse
import json
import os
import sys

from .analyzer import scan_file
from .readiness import check_security_md
from .readiness import scan_file as scan_readiness
from .report import format_repo_readiness, format_text, to_dict

MACHINE_FORMATS = {"json", "sarif"}


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


def _add_output_argument(parser):
    parser.add_argument(
        "-o",
        "--output",
        help="Write machine-readable output to this file instead of stdout (use '-' for stdout)",
    )


def _write_output(content, output_path):
    if not output_path or output_path == "-":
        print(content)
        return
    try:
        with open(output_path, "w", encoding="utf-8", newline="\n") as output_file:
            output_file.write(content)
            output_file.write("\n")
    except OSError as error:
        print(f"[error] Could not write {output_path}: {error}", file=sys.stderr)
        raise SystemExit(2) from error


def _main_scan(argv):
    parser = argparse.ArgumentParser(
        prog="mcp-scanner",
        description="Static security scanner for MCP (Model Context Protocol) server source code.",
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default="none",
        help="Exit with a non-zero status if a finding at or above this severity is present",
    )
    _add_output_argument(parser)
    args = parser.parse_args(argv)

    if args.output and args.format not in MACHINE_FORMATS:
        parser.error("--output requires --format json or --format sarif")
    if not os.path.exists(args.path):
        parser.error(f"path does not exist: {args.path}")

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_findings = []
    json_results = []
    scan_results = []

    # Repository-level readiness checks (currently: is there a SECURITY.md?)
    # run once per directory scan, not once per file -- there's nothing
    # file-specific about "does this repo have a SECURITY.md."
    repo_readiness = []
    if os.path.isdir(args.path):
        repo_check = check_security_md(args.path)
        if repo_check:
            repo_readiness.append(repo_check)

    python_files = sorted(iter_python_files(args.path))
    for file_path in python_files:
        try:
            findings, errors = scan_file(file_path)
            readiness, readiness_errors = scan_readiness(file_path)
        except (OSError, UnicodeError) as error:
            findings, readiness = [], []
            errors, readiness_errors = [f"Could not read {file_path}: {error}"], []
        combined_errors = errors + [e for e in readiness_errors if e not in errors]
        all_findings.extend(findings)
        scan_results.append((file_path, findings, combined_errors, readiness))
        if args.format == "json":
            json_results.append(to_dict(file_path, findings, combined_errors, readiness))
        elif args.format == "text":
            print(format_text(file_path, findings, combined_errors, readiness))
            print()

    if repo_readiness:
        if args.format == "json":
            json_results.append(to_dict(args.path, [], [], repo_readiness))
        elif args.format == "text":
            print(format_repo_readiness(args.path, repo_readiness))
            print()

    if args.format == "json":
        _write_output(json.dumps(json_results, indent=2), args.output)
    elif args.format == "sarif":
        from .sarif import to_sarif

        sarif_log = to_sarif(args.path, scan_results, repo_readiness)
        _write_output(json.dumps(sarif_log, indent=2), args.output)
    elif not python_files and not repo_readiness:
        header = f"MCP Security Scan: {args.path}"
        print(f"{header}\n{'=' * len(header)}\n  No Python files found.\n")

    if any(errors for _, _, errors, _ in scan_results):
        sys.exit(2)

    if args.fail_on != "none":
        threshold = severity_rank[args.fail_on]
        if any(severity_rank[f.severity] <= threshold for f in all_findings):
            sys.exit(1)

    sys.exit(0)


def _main_live(argv):
    parser = argparse.ArgumentParser(
        prog="mcp-scanner live",
        description=(
            "Connect to a running MCP server and scan the tool/resource descriptions it "
            "actually reports (via list_tools()/list_resources()) for the same heuristics "
            "as static scanning. This connects once, enumerates, and disconnects -- it is "
            "not a runtime traffic monitor."
        ),
    )
    parser.add_argument("--format", choices=["text", "json"], default="text")
    _add_output_argument(parser)
    transport = parser.add_subparsers(dest="transport", required=True)

    stdio_p = transport.add_parser("stdio", help="Launch COMMAND as a subprocess and speak MCP over its stdin/stdout")
    stdio_p.add_argument("command", help="Executable to launch")
    stdio_p.add_argument("args", nargs=argparse.REMAINDER, help="Arguments to pass to COMMAND")

    sse_p = transport.add_parser("sse", help="Connect to a running server over SSE/HTTP")
    sse_p.add_argument("url", help="Server URL, e.g. http://localhost:8000/sse")

    args = parser.parse_args(argv)
    if args.output and args.format != "json":
        parser.error("--output requires --format json")

    from .live_scanner import LiveConnectionError, scan_live_sse, scan_live_stdio
    from .report import format_live_json, format_live_text

    try:
        if args.transport == "stdio":
            target = f"stdio -> {args.command} {' '.join(args.args)}".strip()
            findings, tools, resources = scan_live_stdio(args.command, args.args)
        else:
            target = f"sse -> {args.url}"
            findings, tools, resources = scan_live_sse(args.url)
    except LiveConnectionError as e:
        print(f"[error] {e}", file=sys.stderr)
        sys.exit(2)

    if args.format == "json":
        _write_output(format_live_json(target, findings, len(tools), len(resources)), args.output)
    else:
        print(format_live_text(target, findings, len(tools), len(resources)))

    sys.exit(1 if any(f.severity in ("critical", "high") for f in findings) else 0)


def _main_config(argv):
    parser = argparse.ArgumentParser(
        prog="mcp-scanner config",
        description=(
            "Connect to every MCP server listed in a client config file (Claude Desktop's "
            "claude_desktop_config.json, or Claude Code's MCP config) and flag tool names "
            "that collide across servers -- a lightweight 'tool shadowing' check."
        ),
    )
    parser.add_argument("config_path", help="Path to the client MCP config JSON file")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    _add_output_argument(parser)
    args = parser.parse_args(argv)
    if args.output and args.format != "json":
        parser.error("--output requires --format json")

    from .config_scanner import scan_config
    from .report import format_config_json, format_config_text

    try:
        shadow_findings, per_server, errors = scan_config(args.config_path)
    except ValueError as e:
        print(f"[error] {e}", file=sys.stderr)
        sys.exit(2)

    if args.format == "json":
        _write_output(format_config_json(args.config_path, shadow_findings, per_server, errors), args.output)
    else:
        print(format_config_text(args.config_path, shadow_findings, per_server, errors))

    sys.exit(1 if shadow_findings else 0)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    if argv and argv[0] == "live":
        return _main_live(argv[1:])
    if argv and argv[0] == "config":
        return _main_config(argv[1:])
    return _main_scan(argv)


if __name__ == "__main__":
    main()
