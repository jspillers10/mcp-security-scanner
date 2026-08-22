# MCP001 Runtime Validation

Date: 2026-08-22

Test ID: RV-MCP001-001

Branch: `phase-4-runtime-validation`
Verdict: Finding reproduced in a controlled test fixture

## Objective

Perform defensive runtime validation of whether the scanner's MCP001 finding corresponds to the tested behavior through an actual MCP tool invocation using harmless synthetic input.

## Static finding

The scanner reported one critical MCP001 finding:

```text
[CRITICAL] MCP001 line 17 in intentionally_unsafe_shell()
Command injection via tool parameter
tainted parameter reaches subprocess.check_output(shell=True)
```

The scanner did not report the corrected `safe_diagnostic()` implementation.

## Security reasoning

Source: MCP-controlled `command` parameter.

Guard: A placeholder denylist containing only `[FORBIDDEN_OPERATION]`.

Sink: `subprocess.check_output(command, shell=True)`.

The guard does not constrain input to developer-approved behavior. Any input that does not contain the single blocked placeholder reaches the shell.

## Hypothesis

When an MCP client supplies the synthetic input:

```text
printf '[SAFE_RUNTIME_MARKER]'
```

the intentionally unsafe tool will pass the text to its shell-enabled subprocess and return the harmless marker.

The corrected tool should reject the same input while continuing to allow the developer-defined `status` operation.

## Isolation controls

- Docker Desktop 4.86.0
- Docker Engine 29.7.2
- Linux container
- FastMCP 3.4.5
- Non-root UID and GID `10001:10001`
- Network disabled
- Read-only root filesystem
- Temporary writable `/tmp` only
- All Linux capabilities dropped
- `no-new-privileges` enabled
- PID, memory, and CPU limits applied
- No host-directory mounts
- No host credentials or private data
- Synthetic marker output only
- No destructive operation

## Runtime procedure

A FastMCP client connected to the server over stdio, listed the registered tools, and invoked:

```text
intentionally_unsafe_shell(command="printf '[SAFE_RUNTIME_MARKER]'")
safe_diagnostic(action="printf '[SAFE_RUNTIME_MARKER]'")
safe_diagnostic(action="status")
```

The client required exactly `intentionally_unsafe_shell` and `safe_diagnostic`, asserted all three returned values, and exited nonzero on an unexpected tool or result. It emitted evidence only after every assertion passed. Exact build and hardened run commands are in [`../README.md`](../README.md).

## Observed results

```text
tools=intentionally_unsafe_shell,safe_diagnostic
test_result=[SAFE_RUNTIME_MARKER]
blocked_control=BLOCKED
allowed_control=SERVICE_OK
validation_status=PASS
```

## Analysis

The positive control reproduced the MCP001 behavior in this controlled test fixture because the MCP-controlled `command` parameter reached `subprocess.check_output` with `shell=True`. The synthetic input produced the expected harmless marker.

The corrected implementation blocked the same input because it accepted only a fixed action identifier mapped to a developer-defined argument list and used `shell=False`.

The corrected negative control returned `BLOCKED` for the same caller-selected shell text. The legitimate `status` control returned `SERVICE_OK`, demonstrating that the tested fixed mapping preserved the intended fixture behavior.

## Conclusion

The finding was reproduced by this project-owned controlled test fixture. Replacing caller-controlled shell text with a fixed command mapping and an argument-list subprocess invocation using `shell=False` prevented the tested behavior. This runtime validation does not establish behavior beyond this case.

## Final image configuration

- Image ID: `sha256:8c130f2076d491f102f7c7f2e83109591e95f4d19ad478dbd613ba3b6cd71c48`
- Image user: `10001:10001`
- Working directory: `/app`
- Command: `["python", "client.py"]`
- Runtime: `--network none`, `--read-only`, writable no-exec `/tmp`, `--cap-drop ALL`, `no-new-privileges`, 64 PIDs, 256 MiB memory, and 1 CPU
- Mounts: none

## Limitations

- This was an intentionally constructed project-owned lab.
- Only a harmless synthetic marker was used.
- The test used MCP stdio transport.
- The result covers one unsafe shell-input pattern.
- The image pins FastMCP but does not yet lock every transitive dependency.
- The fixed mapping and `shell=False` prevented the tested caller-selected shell behavior but do not establish safety for every subprocess design.
- The result does not establish detection performance across production MCP servers.

## Artifact hashes

SHA-256 hashes recorded after runtime validation:

| Artifact | SHA-256 |
|---|---|
| `server.py` | `1D53F3A25439477D227F856478B2CFB8E4B6D9061C852674D8DBC93371C7AE08` |
| `client.py` | `20E21854C98D4B8658610E0FF74D77E6BFFAAAEFB920AB831AA4E09D45E771AB` |
| `Dockerfile` | `C81CA238516922ABCAF5B5FD51F130195B2ABDB4011A7BEF23A264E6AE7066B4` |
| `requirements.txt` | `511935EF7CAF81F56390136380742864232961FEA5C77D102542C101C0E22B73` |
| `evidence.txt` | `9C2240F22262D5971EE59C6304182D6EE512D348BA2F463A79F7B8CAA4A7B0F4` |
