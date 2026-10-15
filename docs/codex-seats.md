# Codex inside a seat VM

A seat declaration can name `codex@0.160.0`. The owner's class catalogue
must supply its pinned archive and an actual interactive qualification record;
a headless qualification is insufficient. Compiling the declaration retains
that version, archive digest, explicit launch settings and declaration binding.
Codex declarations require `launch` with `sandbox`, `approvals`,
`network_access`, `model`, `effort` and `cwd`. The current source materializer
accepts `/work` only; another declared directory is refused rather than
silently replaced. Missing policy or an incompatible network promise is refused. The Go host and Swift
launcher accept this supported Codex seat while retaining the existing name,
source, fixture, controller and resource refusals. Other versions are refused.

The guest runs the Codex-specific supervisor as the root custodian, behind the
same private, session/incarnation-bound terminal route. The supervisor stays
idle until asked to start. It launches the pinned Linux ARM64 executable with
an explicit guest environment, file-based guest authentication and its declared sandbox, approvals, network,
model and effort; the host's credentials or environment are not inherited. The
existing Codex app-server path remains independent and unchanged. TUI
credentials must be obtained in this guest, never copied from another seat.
The terminal route does not infer authentication from a credential file.

First TUI startup durably records an intent and the pre-existing rollout file
set. Only one new CLI-root `session_meta` in the guest's exclusive Codex home
can bind its conversation: the supervisor reads the first metadata line only,
excluding prior sessions and subagent roots. It never chooses the newest
thread or parses private transcript contents. The bound ID is resumed
explicitly. An absent, corrupt, redirected, configuration-mismatched or
ambiguous binding holds further starts for inspection; no fresh conversation
is invented to recover it. A lost initial acknowledgement stays held even if
subsequent metadata might identify the original thread; explicit recovery
qualification is still required. The custodian owns the startup record and
exclusive fence under its private, immutable-parent state directory. The actor
and all native tools run as UID/GID1000, with supplementary groups replaced,
and receive no fence descriptor: they cannot unlock, replace or unlink it.
Before start or abandonment the root custodian scans the guest process table
for any UID1000 process (real, effective, saved or filesystem UID). A surviving
server holds the operation even after supervisor loss; missing/unreadable process
entries fail closed. Nothing kills a process to clear that hold.

The dedicated tmux server/socket and configuration are root-owned and private.
It uses only the fixed supervisor, no user configuration, command/key bindings,
usable default shell or environment update. Terminal access remains an owner
capability. The native actor uses only the declared guest environment; the root
terminal uses a separate fixed environment. This privileged terminal separation,
Linux process observation and attempted UID1000 interference still require
native qualification before use.

The selected executable and helper directories must stay custodian-owned and
not group/other writable. The first executable is hashed and executed through
its retained Linux file descriptor; the trampoline closes the binary descriptor
at native exec. The trampoline itself starts by the path returned by
`os.Executable()`; its executable and every parent directory are checked for
root ownership, no redirects and no group/other writes before launch. This is
path custody, not descriptor pinning of the trampoline. Helper re-execs performed by Codex use paths and therefore rely
on that directory custody, not a claim of descriptor pinning of every helper. Its digest is the already pinned Codex artifact; this is
binary custody, not new interactive acceptance. Thread records bind the seat,
version, executable, workspace and launch configuration and are written with
file and directory synchronization. The VM owner must keep the executable
immutable and preserve the original workspace, Codex home and startup record.

Declared policy is carried unchanged for fresh launch and exact-ID resume.
A changed declaration cannot restart a retained environment. Read-only plus enabled tool networking, and unrestricted sandbox plus disabled
networking, are refused because those combinations cannot honor this override.
The candidate effort set is medium/high only; actual Linux policy effects still
require qualification. Non-seat app-server profiles retain their original
no-agentVersion rule. The startup
canary and live-policy comparison required for remote health are not implemented
by this source change; flags alone do not prove effective live settings.

## Acceptance still required

This source launcher and its fixtures do not qualify actual Linux TUI
startup, login, native thread resume, effect replay, reboot recovery,
supervision or aggregate capacity. Raw terminal transport and a recorded
thread ID do not prove that an external tool effect committed. UNKNOWN actions
remain held and must not be automatically replayed. Stop and restart still
require the existing owner's process/VM fence and durable receipt; no guard,
resource ceiling or capacity refusal is bypassed by selecting Codex.

The session layer carries terminal bytes; its owner and the guest adapter
must agree on the state/receipt interface. Effect identity requires more than
a latest-only committed-operation string. Managed-seat acceptance, the
reviewed receiver, all fourteen criteria, the full qualification pilot and the operator attach test
precede any existing-seat move. This change starts no VM and installs nothing.

## Owner recovery of an unbound first start

A missing startup record with any prior rollout is held, never treated as a
new conversation. If Codex exits before producing a rollout, its `starting`
record remains held; an ordinary start/resume cannot clear it.

The VM owner can inspect `GET /v1/codex/startup` through the existing private
owner-to-guest broker route. An attended recovery uses
`POST /v1/codex/startup/abandon` with an original `operation_id`, the exact
`record_sha256` from inspection, and `acknowledge_unknown:true`. This is a
root-broker action, unavailable to coding-user processes. These recovery and
inspection routes have no additional session/run binding: anyone able to reach
the host owner socket can call them. That is acceptable only while that socket
remains owner-only (0600), with the guest broker root-only. It requires the root
fence and an independent empty coding-user process-table observation, no rollout
and an unchanged unbound record. Parsed state and SHA256 come from the same
no-follow opened snapshot. The original
record and owner intent/receipt are synchronized in the custodian's private
reset archive before/after removing only the matched startup pointer. Repeating
the same operation returns its immutable original receipt plus a fresh
`current_state` and `current_sha256`, so an old receipt cannot conceal a newer
stuck start. Conflicts remain held. The original receipt is not rewritten.

The owner must assess and fence any surviving execution scope before giving
that disposition. The receipt says `UNKNOWN_NOT_RETRIED`; it does not assert
that a tool succeeded, that no external effect occurred, or that a VM stopped.
Bound threads, existing rollouts, mismatched records and live locks cannot be
reset this way. This operation abandons an unbound conversation after explicit
owner acknowledgement; it is not an automatic retry of an uncertain action.

A read-only owner diagnostic names the root supervisor (PID, command name and
boot-relative start ticks) when it still holds the fence, plus every remaining
coding-scope process. It includes no command arguments, transcripts or auth.
Use the explicitly selected development owner root and original environment ID:

```sh
curl --fail --unix-socket "$OWNER_ROOT/host.sock" \
  "http://owner/v1/environments/$ENVIRONMENT_ID/agent/codex/fence"
```

An absent holder is not proof of quiescence; `coding_processes` and a successful
custodian observation are separate. Unsupported `/proc` or a raced/unreadable
entry yields an unavailable observation, never a healthy empty scope. These
metadata receipts do not prove external effects committed.
