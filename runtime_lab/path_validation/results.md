# MCP002 Runtime Validation

Date: 2026-08-22

Test ID: RV-MCP002-001

Branch: `phase-4-runtime-validation`
Verdict: Finding reproduced in a controlled test fixture

## Objective

Perform defensive runtime validation of whether the scanner's MCP002 finding corresponds to the tested behavior through an actual MCP tool invocation using synthetic input and project-owned files.

## Static finding

The scanner reported one high-severity MCP002 finding in `vulnerable_read()`:

```text
[HIGH] MCP002 line 19 in vulnerable_read()
Path traversal via tool parameter
open() path built from tainted tool parameter
```

The scanner did not report the remediated `safe_read()` implementation.

## Security reasoning

Source: MCP tool parameter `report_path`.

Guard: `os.path.exists(report_path)`.

Sink: `open(report_path)`.

The existence check establishes only that the requested file exists. It does not restrict the path to an approved directory.

## Hypothesis

If `/lab/canary.txt` exists and an MCP client supplies that absolute path to `vulnerable_read`, the existence check will pass and the tool will return the canary contents.

The same path should be rejected by `safe_read` because it resolves outside `/lab/allowed`.

## Isolation controls

- Docker Desktop 4.86.0
- Docker Engine 29.7.2
- Linux container
- FastMCP 3.4.5
- Non-root UID and GID `10001:10001`
- Network disabled
- Read-only root filesystem
- Writable no-exec, no-suid, no-device `/tmp` limited to 16 MiB
- All Linux capabilities dropped
- `no-new-privileges` enabled
- PID, memory, and CPU limits applied
- No host-directory mounts
- No host credentials
- Synthetic canary data only
- No host mounts

## Runtime procedure

A FastMCP client connected to the server over stdio, listed its tools, and invoked:

```text
vulnerable_read(report_path="/lab/canary.txt")
safe_read(report_name="/lab/canary.txt")
safe_read(report_name="report.txt")
```

The client required exactly `vulnerable_read` and `safe_read`, asserted all three returned values, and exited nonzero on an unexpected tool or result. It emitted evidence only after every assertion passed. Exact build and hardened run commands are in [`../README.md`](../README.md).

## Observed results

```text
tools=vulnerable_read,safe_read
vulnerable_result=MCP_CANARY_ONLY
safe_escape_result=BLOCKED
safe_allowed_result=APPROVED_REPORT
validation_status=PASS
```

## Analysis

The positive control reproduced the MCP002 behavior in this controlled test fixture because the client-controlled `report_path` reached `open(report_path)`, allowing the client to read the synthetic canary outside the intended directory.

The remediation worked because the server resolved the requested path and required it to remain inside the trusted `/lab/allowed` directory before opening it.

The corrected negative control returned `BLOCKED` for the same outside path. The legitimate control for `report.txt` returned `APPROVED_REPORT`, showing that the tested containment control preserved the intended fixture behavior.

## Conclusion

The finding was reproduced by this project-owned controlled test fixture. Canonical path resolution followed by containment within a trusted base directory prevented the tested outside-directory read. This runtime validation does not establish behavior beyond this case.

## Final image configuration

- Image ID: `sha256:ba78437e7c8b10eb74caf94c1e7785badea1f285e4b7656150a7dbfd62339ae0`
- Image user: `10001:10001`
- Working directory: `/app`
- Command: `["python", "client.py"]`
- Runtime: `--network none`, `--read-only`, writable no-exec `/tmp`, `--cap-drop ALL`, `no-new-privileges`, 64 PIDs, 256 MiB memory, and 1 CPU
- Mounts: none

## Limitations

- This was an intentionally constructed local lab.
- The result demonstrates one arbitrary-file-read pattern.
- The test used MCP stdio transport, not HTTP or SSE.
- The container image pins FastMCP but does not yet lock every transitive dependency.
- Resolution plus containment prevented the tested behavior but does not prove protection against every filesystem race or path-security condition.
- The result does not establish detection performance across production MCP servers.

## Artifact hashes

SHA-256 hashes recorded after runtime validation:

| Artifact | SHA-256 |
|---|---|
| `server.py` | `9EDBF34A088BE099A80B7794387F2BAEC3FD9F086719838C104A4FA090F8A0BC` |
| `client.py` | `9876B4209CE265B9A513B7997A970EC936A5823A166820667F3ABEC35A3BDAB9` |
| `Dockerfile` | `D47896213BA0186B4227B174228CE92A25AA4302947FBA80EFC14159D8CB3146` |
| `requirements.txt` | `511935EF7CAF81F56390136380742864232961FEA5C77D102542C101C0E22B73` |
| `evidence.txt` | `1EBA7B02E82F8D8413FF0C30B25D65D4E100C24F78741F87ABA8F72BBA2C7483` |
