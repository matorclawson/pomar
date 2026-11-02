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
prior session and mail histories. The plan binds both the original registrar
operation and registration ID. An already-issued fresh mailbox is reconciled,
never created again or replaced under a new identity. It returns exact row, registration,
row/history evidence hashes and original operation. A caller Boolean, a
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
It records row registration and retirement in the terminal. Missing or
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
