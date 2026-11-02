# Pre-model disposable qualification (source core, not installed)

`internal/prequal` is the owner-phase core for testing isolation and a fixed
mail relay before a model starts. It is not a seat profile, ordinary seat
launch command or an interactive-agent qualification. It has no production
registry adapter, VM adapter or CLI yet. Calling it with missing adapters
refuses before allocation. This source alone cannot run D1.

The plan schema is `pomar.pre-model-plan/v1`; results use
`pomar.pre-model-observations/v1`. Neither is accepted as the declaration or
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
The only permitted programs are the pinned isolation probe, pinned D1
observation driver (both UID1000), and a process listing. The probe has a
subdeadline at most55 seconds within the original phase. No broker,
supervisor, Codex, Claude or shell command is admitted by the phase executor.
A recording fake VM test fails on any such exec. The normal Swift agent
launcher is deliberately not reused until a separately reviewed no-model
branch implements this contract; it currently starts a broker.

The host-written terminal is `JOURNAL_ROOT/ORIGINAL_OPERATION/terminal.json`.
Its sibling plan.json and numbered exclusive event files retain original
inputs, register intent, every exec/result and retirement intent. Before
retirement the phase collects a guest process listing, positive owner
stop/reap with an empty live-process set, and the host's actual scope listing.
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

Process inventories now carry the owning adapter's scope, PID, UID and full
executable path. They are checked against a closed path/UID allowlist, including
only the configured init/sleep paths, verified kernel threads, the pinned
probe/driver, and ps. Interpreters, truncated names and unknown executables
are rejected. Kernel status must come from the owner collector; brackets in
guest text never confer it. Guest ps uses full arguments as a second view and
the same executable policy. The owner snapshot is collected before stop, so
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
