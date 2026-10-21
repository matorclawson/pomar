sow: zeroemployee-SOW-180

# Fixed Creator verification companion — unqualified source candidate

This source prepares the single Creator `59d423e0d2f0feadd2b7f96b934ade4fc85f7a14`
`make verify`, then `make doctor` workload. It adds no manager, submission API,
generic worker, account provisioning, source importer, guest boot, installation,
signer or scheduler. The real guest workload must not run on the authoring
host. The initial source checkpoint was unexecuted; subsequent ordinary source
formatting and focused synthetic tests passed under the standing Class1 rule.
That source feedback does not qualify this runner's real guest execution.

Coverage is SAME `zeroemployee-SOW-180` rev8, actual issuer commit
`edcd89a7b516fe6b1d93b2ef77a0e9ecf597b49d`; the original cumulative body is
33246 bytes, SHA256
`80ba4bfd399b2d36f843046c24529cd911b2f1ce17971e333eab5d3755a0191c`.
The Architect assigns zeroemployee as writer; Pomar receives compatibility.
Council accepted A1–A7 as design, including the explicit disposable copy,
not this implementation or any installed execution boundary. The review with
its addendum hashes
`a72b527aec92e6b459055c767cb10efafc90197cfad5313cffe55846e7239343`.

## Receiving contract before any invocation

Pomar/Runtime must independently receive the exact runner/tool/image/source/cache
closure, fixed layout below, distinct workload identity, actual read-only input
mount and protected collector/report permissions, OS-deny controls and guest
teardown. Scheduler must admit measured resources and a finite original/window.
These are prerequisites, not claims made by a manifest or this code. Native
UID503 sampling remains rejected as the OS-deny boundary. Source preparation
does not activate an account, change a service or make the managed guest usable.

The proposed fixed guest layout is deliberately not a manifest-selected path:

| Root | Purpose |
| --- | --- |
| `/pomar/inputs/creator-source` | Exact pinned read-only Git input; never executed in place |
| `/pomar/inputs/creator-cache` | Receiver-adopted immutable regular-file cache/build closure |
| `/pomar/tools/creator-verification/bin` | Pinned regular files for tools and their complete materialized runtime inputs |
| `/pomar/work/creator-verification/source` | Receiver-created fresh disposable Git clone at the same head |
| `/pomar/work/creator-verification/{home,tmp,cache,mypy}` | Receiver-created workload-owned private scratch; cache seeded with exact inventory |
| `/pomar/work/creator-verification/artifacts/{dist,site}` | Workload-owned artifact output, subject to byte/file limits |
| `/pomar/outputs/creator-verification` | Fresh protected collector log root; never workload-writable by pathname |

The collector must run as guest root; it only looks up the fixed pre-provisioned
guest user `creator-workload`, refuses root UID/GID, and drops supplementary
groups when launching the workload. It creates no user and offers no identity
selector. The fixed name/layout are proposed compatibility inputs requiring
Pomar adoption, not an assertion that an existing guest contains them. Parent
directories and collector files must be root-owned, not group/world-writable,
and not symlinks. Actual mount enforcement is independently qualified by the
owner, not inferred from mode bits or this program's checks.

The source is copied by the receiver, never by this tool. Each original gets
one fresh disposable clone. The workload may write that clone, not the pinned
input, executable, manifest or report directories. The immutable original and
copy have matching full inventories, commit, tree and clean Git status before
the fixed gate runs. Afterward the original inventory/head/tree and both Git
diff/status checks are collected. A dirty/unknown workload cannot yield a clean
result. The copy's after-tree is informational; before/after snapshots do not
exclude transient tampering. Only actual guest teardown destroys the workload.
The receiver must use an independent clone, not `--shared`, alternates, linked
worktrees or local hardlinked Git objects. The clone (including `.git`) and
private cache must be owned by the workload user, and regular files with extra
hardlinks are refused; the original/tool/cache inputs remain collector-owned.

Creator's unchanged generator and `reference-check` therefore execute in the
declared writable copy; no skipped gate or generator relocation. The manifest
and report both name `source_mode: disposable-copy-of-readonly-input`.

## Closed manifest

The entrypoint takes exactly one absolute manifest filename. It has no command,
mount, profile, output-path, account, arbitrary argv or environment option.
The manifest itself must be collector-owned, regular and not group/world-writable.
Its fields are exactly:

| Key | Type and binding |
| --- | --- |
| `schema` | `pomar.creator-verification/v1` |
| `source_mode` | `disposable-copy-of-readonly-input` |
| `source_commit` | Fixed Creator head above |
| `source_tree` | Actual lowercase 40-hex Git tree at that head |
| `closure_sha256` | SHA256 of the deterministic declared inventory capsule below |
| `source_files` | Complete nonempty materialized source inventory, excluding `.git` |
| `cache_files` | Complete nonempty receiver-adopted regular-file cache inventory |
| `tools` | Complete nonempty receiver-adopted regular-file tool/runtime inventory; includes exact root names `git`, `make`, `uv`, `node`, `python`, `sh` |
| `limits` | Exact eight positive integer fields listed below |

Each inventory entry has exactly `path`, `sha256`, `bytes`: canonical relative
UTF-8 path, lowercase 64-hex file digest, nonnegative byte count. Absolute paths,
escapes, duplicates, special files and links are refused. The one source-only
exception preserves the *actual pinned Git tree*: `.node-version` links exactly
to `packages/publication-core/.node-version`. Its inventory hashes the literal
link target bytes, never arbitrary dereferenced content; the target must be a
regular in-tree path with no linked ancestor. No such exception applies to tool,
cache or artifact outputs. No source content is rewritten to make it pass.

The closure digest is SHA256 of Go `json.Marshal` on an object with fields in
this order: `source`, `tools`, `cache`. Each value is the corresponding inventory
sorted by `path`; each entry field order is `path`, `sha256`, `bytes`. It binds
the declaration, not registry provenance, dependency selection or a guest image.
Actual materialized inventories must match before execution. The receiver still
must close interpreter libraries, make's helpers, build backend dependencies and
the offline uv cache; the six required executable names alone do not do that.
The entrypoint invokes only the fixed make targets with a fixed pinned `SHELL`;
their required helper tools must already be in the adopted inventory/PATH.

Canonical *decoded* key bytes are checked at every object before Go struct
decoding. `Source`, `SOURCE`, long-s `ſource`, Kelvin-sign fold aliases and
`source` plus `Source` are refused, as are unknown fields, duplicate decoded
keys (including escaped equivalents), nonfinite numbers, trailing JSON values,
wrong types and structurally misplaced/deep values. An escaped spelling that
decodes to the exact canonical bytes is legal once, never twice. The fixed
schema bounds structural depth; each list also has a 16384-entry ceiling.

## Bounds and result semantics

These ceilings are proposed contract maxima, **not allocated resources**. The
owner can adopt a tighter positive limit. Exceedance is failure, never successful
truncation.

| `limits` field | Maximum |
| --- | --- |
| `stdout_bytes` | 8388608 across both steps |
| `stderr_bytes` | 8388608 across both steps |
| `verify_seconds` | 600 |
| `doctor_seconds` | 60 |
| `cleanup_seconds` | 60 reserved for the independent guest owner |
| `whole_seconds` | 720 including that cleanup reserve |
| `output_bytes` | 1073741824 in artifact output |
| `output_files` | 4096 regular artifact files; no symlink/special output |

Manifest bytes are capped at1048576. Input inventories have a1GiB/16384-file
ceiling each. Per-step limits plus cleanup must fit within the whole budget;
the active whole deadline excludes the final cleanup reserve. Source/cache/Git
and private scratch storage also need actual independent guest fit; artifact
limits do not claim to bound the entire filesystem or cgroup.

Workload stdout/stderr go straight to separate exclusive regular files. The
collector does not read a pipe to EOF, so a descendant inheriting a descriptor
cannot hold that read open. Start observations, step waits and Git reads are
deadline-bound. Logs and artifacts are sampled for growth; these checks are
not kernel-enforced disk or CPU quotas and can overshoot between observations.
Log hashes are point-in-time self-reported snapshots, not proof of quiescence.
Retain the original files and failed/partial observations for independent
receiving; never relabel a timeout, oversized output or missing evidence.

On a failed step no doctor is launched. On timeout/failure/leader completion,
the companion attempts process-group termination and reports any actual exit.
Empty group observations cannot exclude `setsid` descendants. Late starts and
unconfirmed waits retain `UNKNOWN`; actual guest teardown and independent host
custody establish cleanup. The companion never claims that its own kill did so.

The clean environment includes offline/frozen uv, no Python downloads or
bytecode, disabled pytest cacheprovider, and private home/cache/temp/mypy/dist/site
locations. These application settings are not OS deny. The unchanged lifecycle
behavior stays enabled; no `--ignore-scripts` substitute is used for the gate.

Reports are always `SELF_REPORTED`; even two zero gate exits leave outcome and
quiescence `UNKNOWN`, with `GUEST_TEARDOWN_REQUIRED`. The fixed guest entrypoint
returns125 after a report rather than silently promoting that observation to a
successful admitted Pomar result. This is the companion's contract, not a change
to Pomar CLI exit-code semantics. Malformed input returns2 before running. Host
receiving must interpret actual step exits, the retained logs and real teardown
separately; this source implements no signed-result or admission integration.

## Source tests and outstanding qualification

`main_test.go` contains synthetic tests for key folding/duplicates/closed nested
objects, malformed/nonfinite/trailing inputs, identity and closure changes,
inventory tampering, escape/link/byte/file refusals, fixed order and failure
short-circuit, aggregate budgets, deadlines and conservative UNKNOWN reporting.
Fake executor tests do not spawn a workload, create accounts, boot a guest or
prove OS isolation. The inherited-descriptor/escaped-descendant cases test only
reporting logic; real process/guest controls are still required.

The issuer's standing execution correction (715rev25, delivered2026-10-21)
explicitly supersedes rev8's generic worker-only requirement for eligible
ordinary own-repository source checks. Formatting, focused synthetic tests and
ordinary native source gates may use Class1: under30minutes, at most4CPU/8GiB,
scratch HOME/XDG and actual tool configuration, ZeoWork TMP/cache, disk check,
exact source/log/time/exit evidence and parent-PID plus session descendant
inspection/recorded cleanup. These are ordinary source checks, not guest or
hostile-workload qualification. The real runner/OS-deny/escape controls retain
their separately admitted isolated boundary; Class1 supplies no such authority.
Longer work, excess resources or a campaign still require Scheduler Class2 fit.

Use a private non-symlink scratch TMPDIR; tests intentionally refuse symlinked
input ancestors. Required receiving still includes Pomar's unchanged full
committed-head Apple `make verify`, normal hooks and independent Council C4
source review. Record resource/output-location flags without dropping any gate
step. Failed attempts remain evidence; no result transfers to changed source.
Neither a source commit nor unit tests qualify an OS-deny boundary or complete
Creator's still-pending full gate and delivery.
