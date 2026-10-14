# Native provider identity fences (source preparation)

`internal/providerfence` implements persistent request identity transitions for
the proposed native provider. It is not connected to the manager, HTTP API,
CLI, scheduler or a process launcher. It does not admit a native job or a seat.

The existing VM manager continues to use its existing admission path. This
package does not replace it, expand its budget or establish distributed placement.

## Decisions and replay

The caller supplies a validated full-request binding digest, an immutable
provider namespace and a fresh incarnation. Each namespace keeps every identity
fence; reaching its bound refuses additional requests instead of evicting records.

| Operation | Persistent result |
|---|---|
| Reserve a new ID | RESERVED, opaque token and absolute expiry, maximum 30 seconds |
| Repeat the exact reservation | Original record and expiry; no renewal |
| First matching start | STARTING persisted before `first=true` is returned |
| Repeat a start after a lost response | Original STARTING/UNKNOWN; `first=false`, never another launch decision |
| Abandon an unseen or unstarted ID | ABANDONED with no token, preventing late reservation/start |
| Abandon STARTING/UNKNOWN | Refused; custodian reconciliation is required |
| Expire an unstarted reservation | EXPIRED with no token, retained durably |
| Change incarnation | Old RESERVED becomes EXPIRED, STARTING becomes UNKNOWN; old handles are fenced |
| Reuse a retired incarnation | Refused |
| Lookup an unseen ID | Unknown identity, explicitly not proof that nothing started |

A short cross-process file lock serializes every transition. The store uses a
held directory root, private owned files, no-follow opens, exclusive temporary
creation, file sync, atomic replacement and directory sync before acknowledgement.
If a write or directory sync fails, its effect can be uncertain: reconcile the
original ID. Never use a fresh ID to retry an uncertain start. Missing state
under an existing lock is a recovery error, not a new empty namespace.

## Gates still required before a custodian can act

- Authenticate the principal and validate the complete immutable request before
  hashing it, including seat/SOW, job/attempt, repository/commit/tree, tools,
  argv/environment/profile, class/resources and host incarnation/generation.
- Establish independently verified clock quality and the live monotonic lease
  deadline. The injected wall clock here only records/tests absolute expiry;
  it is not qualified time evidence or protection against clock rollback.
- Reserve aggregate host resources and a qualified exclusive per-attempt UID
  slot under the same admission decision. Other UIDs may run in parallel when
  their measured CPU, memory and disk fit; no host-exclusive lock is proposed.
- Bind the durable decision to the fixed custodian's launch gate, then record
  actual launch/exit/never-start proofs. An uncertain start remains in custody;
  lease expiry alone cannot release it. This package has no release operation.
- Qualify containment, limits, descendant cleanup, artifact export, measured CPU
  coverage, protected policy and signer bindings, and receiving enrollment.

No namespace retirement, compaction, renewed lease or terminal resource-release
proof is implemented in this first slice. Pending files from a process crash are
retained for owner inspection; the package removes only its own temporary file
after an ordinary operation. Do not delete a namespace to clear a full store.

## Qualification scope

`go test -race -count=1 ./internal/providerfence` exercises exact replay, expiry,
unseen abandonment, incarnation recovery, concurrent start/abandon decisions and
four independent processes racing to start once. Custody tests refuse symlinks,
hard links, corrupt state and state deletion without changing an outside canary.
These are source tests on a local owned directory, not privileged deployment,
power-loss qualification, live native execution or organizational admission.
