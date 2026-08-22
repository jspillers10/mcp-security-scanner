# Runtime Validation Labs

## Purpose and authorization

These project-owned labs provide defensive runtime validation for two controlled scanner findings. They use synthetic input and controlled test fixtures only. They do not assess external systems, prove general production performance, or establish runtime exploitability beyond the exact patterns described here.

Current test IDs:

- `RV-MCP001-001`: command validation for MCP001.
- `RV-MCP002-001`: path validation for MCP002.

No other security test category is authorized by this checkpoint.

## Architecture

Each directory contains a FastMCP stdio server, a FastMCP client, a pinned direct dependency, and a dedicated Dockerfile. The client starts the server as a child stdio process, verifies the exact two-tool registration set, invokes the positive, corrected, and legitimate controls, asserts every result, and prints deterministic evidence only after all assertions pass.

Docker is the runtime boundary. Each image is built from only its lab directory. Runtime networking and host mounts are prohibited. The container runs as UID and GID `10001:10001`, with a read-only root filesystem, a small writable no-exec `/tmp`, no Linux capabilities, no new privileges, and explicit PID, memory, and CPU limits.

## Prerequisites

- Windows PowerShell.
- Docker Desktop with Linux containers enabled.
- Python 3.10 through 3.13 and this repository installed for static scanning.

From the repository root, install the scanner if needed:

```powershell
python -m pip install -e ".[test,dev]"
```

## Static scanner commands

```powershell
mcp-scanner runtime_lab/path_validation/server.py
mcp-scanner runtime_lab/command_validation/server.py
```

Expected static comparison:

- `path_validation/server.py` has exactly one MCP002 finding in `vulnerable_read` and none in `safe_read`.
- `command_validation/server.py` has exactly one MCP001 finding in `intentionally_unsafe_shell` and none in `safe_diagnostic`.
- No other scanner rule is expected in either controlled test fixture.

## Build commands

Use only the dedicated lab directory as each build context:

```powershell
docker build --pull=false --tag mcp-runtime-path-validation:phase4 runtime_lab/path_validation
docker build --pull=false --tag mcp-runtime-command-validation:phase4 runtime_lab/command_validation
```

## Hardened run commands

These commands use no host mounts and no runtime network:

```powershell
docker run --rm --network none --read-only --tmpfs "/tmp:rw,noexec,nosuid,nodev,size=16m" --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 --memory 256m --cpus 1 mcp-runtime-path-validation:phase4
docker run --rm --network none --read-only --tmpfs "/tmp:rw,noexec,nosuid,nodev,size=16m" --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 --memory 256m --cpus 1 mcp-runtime-command-validation:phase4
```

Do not add `-v`, `--volume`, or `--mount`. The labs must not receive host files, credentials, private data, or external connectivity.

## Expected evidence

Path validation:

```text
tools=vulnerable_read,safe_read
vulnerable_result=MCP_CANARY_ONLY
safe_escape_result=BLOCKED
safe_allowed_result=APPROVED_REPORT
validation_status=PASS
```

Command validation:

```text
tools=intentionally_unsafe_shell,safe_diagnostic
test_result=[SAFE_RUNTIME_MARKER]
blocked_control=BLOCKED
allowed_control=SERVICE_OK
validation_status=PASS
```

The positive controls demonstrate only the intended synthetic behavior. The corrected controls must return `BLOCKED`. The legitimate controls must continue to return `APPROVED_REPORT` and `SERVICE_OK`. A mismatch causes a nonzero client exit, and `validation_status=PASS` is printed only after all checks succeed.

## Cleanup verification

The `--rm` flag removes each temporary container after exit. Verify no stopped or running lab containers remain:

```powershell
docker ps --all --filter "ancestor=mcp-runtime-path-validation:phase4"
docker ps --all --filter "ancestor=mcp-runtime-command-validation:phase4"
```

Only the header should be present after each run.

## Known limitations

- These are two intentionally constructed, project-owned controlled test fixtures.
- The runtime validation uses MCP stdio transport, not HTTP or SSE.
- The images pin FastMCP directly but do not lock every transitive dependency.
- Path resolution plus containment prevented the tested path behavior, but does not prove protection against every filesystem race or path-security condition.
- A fixed command mapping with `shell=False` prevented the tested caller-selected shell behavior, but does not establish safety for every subprocess design.
- Static and runtime results for these fixtures do not establish production readiness or general scanner performance.

## Adding a future lab

Treat a future lab as a separate reviewed scope decision. Assign a new test ID and rule, document authorization and a harmless synthetic hypothesis, and add positive, corrected, and legitimate controls. Keep its build context self-contained, preserve the no-host-mount and no-runtime-network rules, use a non-root read-only container with the same resource controls, and make the client fail closed on unexpected tools or results. Do not reuse this process to add a new security category without explicit maintainer approval.
