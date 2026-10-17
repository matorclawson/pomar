# Build progress

Read one current JSON observation with the released CLI:

```sh
pomar attempt progress -id JOB
```

Use the configured manager context or `POMAR_SOCKET`, as for other attempt
commands. The ordinary `pomar attempt get` response includes the same `progress`
object. Existing fixed callers use their authorized `get` operation; this does
not require another operation, grant, impersonation or access to the data root.
An older manager without this object returns an explicit unsupported-progress
error from the new CLI.

## What an agent can understand

The response includes a short `summary` and these structured fields:

| Field | Meaning |
| --- | --- |
| `contract`, `attempt`, `manager_key_id` | Versioned observation and bound attempt/manager; the key ID is present on signed managers |
| `observed_at` | Time this manager made the read snapshot; not a heartbeat or execution grant |
| `phase`, `phase_source`, `phase_since` | Observed helper phase, or explicitly identified manager-state fallback |
| `elapsed_seconds` | Attempt duration, frozen at its recorded end; null when not known |
| `workload_phase` | Optional explicitly reported dependency/check/build/package phase; untrusted, bounded log evidence |
| `log.availability`, `bytes`, `last_output_at`, `quiet_seconds` | Missing, unreadable, empty and available output are distinct; unknown amounts/times are null |
| `log.tail_text`, `tail_offset`, `tail_bytes` | A bounded live output tail with raw byte offset/count; invalid UTF-8 is replaced for display |
| `log.window_truncated`, `changed_during_read` | The window omits older bytes, or the file changed during this read |
| `registry.event_counts`, `cache_hits_observed`, `cache_misses_observed` | Actual received/cache/upstream/connect/first-byte/send_short/completion events in the inspected trace window |
| `registry.pending_observed`, `completed_status_counts`, `last_transfer_at` | Observed requests without a completion, HTTP outcomes and last observed network transfer. A completed 2xx is excluded from `last_transfer_at` when its own request also logged a `send_short` (docs/job-failure-diagnostics.md: a 2xx status alone is never proof the guest received every byte), or when this window's own evidence for that request is incomplete (a bounded tail window can retain a completion while an earlier `send_short` for the same request fell outside it) |
| `resources.observed_at`, `peaks`, `disk_scope` | Measurement time and historical VM peaks; the disk figure is a shared-filesystem delta, not per-job I/O |
| `stall_assessment` | `NOT_DETERMINED`: silence, heartbeats and low CPU alone do not prove a stall or its cause |

Helper phases distinguish guest creation, input/source preparation, command
execution and result finalization when the helper reports them. Older helpers
only report booting/running/terminal phases; the missing detail stays unknown.
`OUTCOME_UNCONFIRMED` identifies a lost helper record and does not authorize a
retry. A recorded terminal state directs the reader to the final signed result.

A running command is not proof that dependencies installed or the quality gate
started. A heartbeat updates output activity; it is not meaningful build
progress. For an install wait, compare registry received/cache/upstream/first-byte
and completion evidence, timestamps and the workload's explicitly reported
stage. No percentage is invented from runtime or CPU usage.

## Report an internal build stage

A workload can emit a bounded marker in its own stdout, with an increasing
integer sequence and one of the five supported phases:

```sh
printf '%s\n' 'POMAR_PROGRESS_V1 {"phase":"DEPENDENCIES","sequence":1}'
# run the locked install
printf '%s\n' 'POMAR_PROGRESS_V1 {"phase":"VALIDATION","sequence":2}'
# run the quality gate
printf '%s\n' 'POMAR_PROGRESS_V1 {"phase":"BUILD","sequence":3}'
# build the outputs
printf '%s\n' 'POMAR_PROGRESS_V1 {"phase":"PACKAGING","sequence":4}'
# package outputs
printf '%s\n' 'POMAR_PROGRESS_V1 {"phase":"FINALIZING","sequence":5}'
```

The marker must be a standalone line, at most 512 bytes, with only `phase` and
`sequence`. It describes the job's claim, not authenticated completion. Invalid,
unknown, conflicting and partial markers are ignored. Only the visible tail is
inspected; an older marker outside that window is not reconstructed. A reported
stage cannot replace the helper phase, modify admission, authorize a tool or
establish a valid release.

## Bounds, authority and final evidence

Each GET reads at most 16 KiB of guest output, 256 KiB of registry trace and
64 KiB of helper status. It rejects symlinks and nonregular files without
blocking on FIFOs. Class authorization applies before any progress read. The
registry projection contains aggregates, not raw paths, request headers or
upstream bodies. Its coverage is a trace window, not a complete request ledger;
reused legacy request IDs are identified explicitly. Resource sample age can
remain unknown after a manager restart.

The live tail is always **provisional**. This route does not change the existing
final-log API, its byte cap/hash, result signature or verification. Use
`pomar attempt log` with the independently retained public key after the original
attempt ends to verify those final bytes. This snapshot is neither an atomic
fleet capacity cut nor placement, restart or retry authority. Missing or quiet
output never requests a duplicate build.
