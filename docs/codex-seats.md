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

The guest runs the Codex-specific supervisor as the coding user, behind the
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
qualification is still required. The actor inherits its exclusive lock, so
supervisor disappearance alone does not permit a second actor.

The selected executable is hashed and executed through its retained Linux
file descriptor. Its digest is the already pinned Codex artifact; this is
binary custody, not new interactive acceptance. Thread records bind the seat,
version, executable, workspace and launch configuration and are written with
file and directory synchronization. The VM owner must keep the executable
immutable and preserve the original workspace, Codex home and startup record.

Declared policy is carried unchanged for fresh launch and exact-ID resume.
A changed declaration cannot restart a retained environment. The startup
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
