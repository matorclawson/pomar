# Pre-model disposable qualification (source core, not installed)

`internal/prequal` is the owner-phase core for testing isolation and a fixed
mail relay before a model starts. It is not a seat profile, ordinary seat
launch command or an interactive-agent qualification. It has no production
registry adapter, VM adapter or CLI yet. Calling it with missing adapters
refuses before allocation. This source alone cannot run D1.

The plan schema is `pomar.pre-model-plan/v2`; results use
`pomar.pre-model-observations/v2`. Neither is accepted as the declaration or
class catalogue used by `seat profile` and `seat up`. Normal interactive
qualification guards remain unchanged. Even a complete observation result
always has `admission_granted=false` and `interactive_qualified=false`.

The core requires original operation/environment/session/incarnation,
declaration/catalogue/image/source and public artifact pins, finite resource
ceilings, host-control evidence and an original live deadline at most ten
minutes. The actual owning adapter must verify the declaration/catalogue
pins and their lower class ceilings before staging any input. A digest or
an adapter's presence is not evidence that native qualification occurred.
The isolation probe is pinned to the reviewed repaired commit and full
binary SHA256 in plan.go; older or unpinned probes are refused.

`Registry.ClaimFreshRegistration` is a required real owning-registrar operation. It
verifies the original absent-name disposable registration and atomically claims
that exact registration for the qualification operation, checking actual empty
prior session and mail histories. The plan binds the actual instance, canonical managed store, registered_at
and captured record SHA256; it invents no generation or registration ID. An already-issued fresh mailbox is reconciled,
never created again or replaced under a new identity. It returns the exact captured registration, history evidence hash and
qualification operation. A caller Boolean, a
manually populated JSON row or an arbitrary callback is not an admission
adapter. Returned host rows, existing-name preimages, earlier sessions/mail,
wrong originals or missing evidence are rejected before VM boot. No host
seat (including an existing guest-maintainer seat) may be borrowed. Runtime
must implement and independently qualify this registry/retirement boundary;
the in-memory test registry is not that implementation.

`VM.Boot` is a distinct owner-controlled disposable backend. It stages the
verified public bytes and exact configuration and creates the owned scope;
it must issue no hidden guest exec or agent startup. Every phase-issued exec
is recorded durably before invocation and with bounded output afterwards.
The pinned isolation probe and mail driver run as UID1000; the driver
collector mode and process listing run as UID0. The single maintained mail
shim is started separately through the explicit journaled transport step. The probe has a
subdeadline at most55 seconds within the original phase. No broker,
supervisor, Codex, Claude or shell command is admitted by the phase executor.
A recording fake VM test fails on any such exec. The normal Swift agent
launcher is deliberately not reused until a separately reviewed no-model
branch implements this contract; it currently starts a broker.

The host-written terminal is `JOURNAL_ROOT/ORIGINAL_OPERATION/terminal.json`.
Its sibling plan.json and numbered exclusive event files retain original
inputs, register intent, every exec/result and retirement intent. Before
retirement the phase collects a guest process listing, positive owner
stop/reap with an empty live-process set, and the host's actual post-stop scope listing.
It records registration and retirement in the terminal, including the retirement
command terminal and independent readback hashes. A retirement command can
commit the status before teardown fails: that split outcome is retained as
unknown even if the row already says retired, with no blind retry. Missing or
uncertain stop, scope mismatch or unavailable host listing retains the row
and custody for original-operation reconciliation. A failed observation
with positive cleanup is recorded as failed_stopped, never acceptance.

The journal root must already be canonical and private to the current
owner. Allocation is exclusive; an existing operation is inspect-only,
including after response loss or an uncertain terminal write. No original
journal, VM disk or registry evidence is deleted here. Runtime must supply
actual host share/custody comparisons and receiving evidence; guest output
and exit0 alone do not accept isolation. A later successful observation
cannot resolve an earlier unknown registration or VM scope.

Current routing is the fixed host relay. A newly registered disposable seat
needs the reviewed Mini node mapping and fixed verb binding, followed by
Council read and the operator's live-file action. This work creates no
node, private tailnet daemon, policy change, login or credential. Native D1,
interactive agent login/restart/echo/wake, profile adoption and production
launch remain unfinished and separately observable.

## Council source-review repair

The owning Registry adapter supplies one frozen `ApprovedBinding` separately
from the plan. For this run its private policy names the accepted fresh
instance, store, registered_at and captured row digest; the plan cannot select
another row. Council accepts Root's actual absent-path/fresh-registration and
intended-use evidence for this sole row. No new registry field or general
history API is a prerequisite. Null fields alone still prove nothing.

The pre-stop owner-executed in-guest inventory carries the owning adapter's
scope, PID, UID, full executable path and complete argv. It is not a host
process view or a model-phase qualification. They are checked against a closed path/UID allowlist, including
only the configured init/sleep paths, verified kernel threads, the exact
root collector/relay shim, and ps. Interpreters, truncated names and unknown executables
are rejected. Kernel status must come from the owner collector; brackets in
guest text never confer it. Guest ps uses full arguments as a second view and
the same executable policy. The owner-executed guest snapshot is collected before stop, so
an agent the guest omits cannot disappear from the evidence at teardown.
A post-stop owner snapshot must positively report the same scope empty.
Transient allowed ps processes may exit between the views; their absence
from the later view is not treated as a mismatched PID.

Oversized output is bounded and durably recorded as a failed exec-after event
before the call returns an error. That record names the reported byte count
and truncation. Native adapters must also bound their capture streams; this
core check does not license unbounded transport buffering.

### Linux process inventory library

`CollectLinuxProcessSnapshot` is a library entry for a future pinned owner
adapter. It refuses non-Linux/non-root callers and reads only the current
namespace's `/proc`, checked as procfs. It obtains complete executable paths
from `/proc/PID/exe`, equal real/effective/saved/filesystem UIDs from status,
and kernel-thread identity from Linux's `PF_KTHREAD` bit. Mutable `comm`,
argv and bracketed names never establish executable or kernel identity.
Metadata reads and enumeration are bounded; missing, reused, changed,
malformed or inaccessible entries fail the whole observation. Birth, UID,
executable and kernel identity are sampled twice, with process membership
checked again after enumeration. Returned rows are sorted by PID.

This is a conservative, non-atomic view of process leaders. It cannot prove
absence between samples or detect an executable changing away and back
between reads. The existing closed exec policy and pinned image/driver are
still required. The caller-supplied scope string is a label: only an owning
adapter can establish the original VM/namespace binding. Guest-supplied JSON
or an arbitrary invocation does not become independent owner evidence by
using this library. No production executable, privileged transport, backend,
allowlist exception or invocation is added here. Any eventual collector exec
must be pinned and journaled through the qualification phase before use.

The field references are [Linux proc stat](https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html),
[proc status](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html), and
[Linux PF_KTHREAD](https://github.com/torvalds/linux/blob/master/include/linux/sched.h).

Zombie or dead leaders explicitly refuse the inventory until the owner reaps
them. Their missing executable link is never used to infer an allowlisted
program, a kernel thread, or an empty process set.


## Native phase transport contract

Boot issues no hidden exec. `StartTransport` is a separate owner call with a
journaled before/after record and original scope/operation/process handle.
It starts only the existing pinned `/pomar/shim` as UID0 with exactly
`-listen 127.0.0.1:7743 -socket /run/pomar/mail.sock -ready /pomar/shim-mail.ready`.
The plan binds its staged bytes as `mail_shim`. Root is needed to connect the
reviewed 0600/root mapped UDS and write the root-owned ready path; port7743
itself does not require root. Unknown start/readiness or changed handle
scope, original operation, executable, UID or args refuses further probes.
The root collector checks full shim executable/UID/argv before shutdown.

Only the host end of the approved disposable seat's fixed relay maps into
`/run/pomar/mail.sock`, direction into the guest, permissions0600. Its actual
canonical host path must be independently bound by the owning backend, never
guessed or guest-selected. No agent control socket out of the guest,
egress/module-proxy/other-seat socket or host directory share is allowed.
Actual denied guest/host resource pairs still need the pinned probe plan and
separate host-control evidence. This library supplies no live mapping.

The driver has separate exact phase entries: UID1000 `-mode mail -seat SEAT
-operation ORIGINAL -deadline DEADLINE`, and UID0 `-mode processes -scope
ACTUAL_SCOPE`. Every invocation is recorded before and after. The latter
returns `inventory_kind=owner_executed_in_guest_no_model` from the guest
kernel via the owned transport; it never claims to be a host observation.
The ordinary `ps` view is still checked separately. Post-stop `HostListing`
must report `inventory_kind=host_scope_after_stop`, same scope and an
explicitly empty process set. The owning backend must obtain that from its
actual stop/reap/scope state, not relabel a guest document.

These are phase interfaces with recording fixture tests, not production
adapters or an executable native run. The driver mail bytes remain retained
JSON awaiting the semantic wire validator and owner join. Messenger's actual
foreign-message refusal status/body is still unverified; a source guess or
json.Valid alone never completes native D1 acceptance. No normal profile or
model launch becomes authorized by these observations.


This successor uses v2 plan/result schemas. The earlier v1 source-only core
plan is explicitly refused: v2 adds the required pinned mail shim and sole
mail mapping (canonical owner host path, fixed guest path/direction/0600,
exact disposable seat and denied-pairs digest). The concrete backend must
verify the actual host end/custody against independent owner policy before
mapping; these fields or a digest alone are not evidence that the socket
exists or belongs to the fixed relay. Native process inventory must show
exactly one live shim and the root collector itself before stop.

After the mail Exec has completed, neither process view may contain a
UID1000 D1 driver. Even correct mail args cannot authorize a lingering or
extra process. Only the one UID0 collector mode is expected at inventory.

The isolation probe has also completed before either pre-stop inventory.
Any lingering or extra probe is refused in both views, independently of UID
or arguments. The earlier source allowance is not carried into this backend
follow-up.


## Mail-only host endpoint source seam

`agentenv.OpenMailOnlyChannel(ctx, options)` reuses the maintained mail relay,
HTTP timeouts, four-slot process upstream budget, per-guest shares, fixed
identity/header/body rules, retry-key namespace and revocation. It does not
call `Host.gate`, start egress/Go proxy channels, open an agent host, register a
seat or admit a profile. The owning phase must already have its real claim
and must journal the call and returned binding before VM mapping.

The caller supplies existing canonical private current-owner Root and
Root/Environment directories, exact environment/incarnation/operation/seat,
the approved upstream origin and a live owner context of at most ten minutes.
Only Root/Environment/mail.sock is bound (0600). Occupied regular/live/dead
socket paths refuse; no stale socket is removed to make room. Exclusive
intent/ready/closed evidence and an owner lock preserve original identity.
The live Binding method checks actual socket inode/mode and the privately
created listener's still-open kernel binding; a ready JSON file is historical
and cannot make an empty, dead or replaced pathname an endpoint.

`Revoke` cancels upstream work and closes the listener/connections. `Close`
also waits for actual handler and server drain, checks parent/socket identity,
and unlinks only its observed original socket. A timeout retains the original
for another Close/inspection; it does not write a positive drain terminal.
A replaced socket/parent is retained and reported, never removed as cleanup.
Owner context cancellation revokes the endpoint without granting a new life.

The listener binding is not upstream seat authorization. In the maintained
handler a foreign X-Zmail-Instance is refused locally before forwarding;
it is not merely overwritten. The native driver must validate that actual
layer, and the separate node-row/live-file prerequisites still apply. This
source seam is not installed in release410 and provides no live D1 pathname.

The root collector inventory enforces exactly one live shim and one root
collector. A missing or duplicate instance refuses qualification. The earlier
guest ps view must include the shim PID from that inventory and refuses any
D1 driver: its own collector has not been invoked at that point. These are
sequential observations, not a claim of simultaneous process snapshots.

## Internal process-observation command

The source-only `pomar-d1-driver` command now accepts exactly
`-mode processes -scope ORIGINAL`. It invokes the existing fixed `/proc`
Linux-root reader under a context of at most 20s and emits one bounded
process snapshot. Unknown roles/args, incomplete or differently bound
observations, cancellation, reader errors and output failures return nonzero.
Unexpected processes remain visible for the owner's separate policy checks.
No arbitrary executable, proc path or model command is accepted.

The command's scope label is not proof of the VM namespace or caller. The
owner adapter must establish that binding, retain complete output/exit and
apply the existing paired process policy. The owner also bounds transport
and drain; a context alone does not guarantee an interrupted stdout write.
This collector mode does not implement mail mode, semantic mail validation,
registration, a VM adapter or native D1 acceptance. It is a later source
increment than the qualified mail-only endpoint PR.
