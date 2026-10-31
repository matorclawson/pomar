# Moving a tmux fleet into retained Pomar seats

## Current implementation boundary

This gold-based source series adds inventory/planning and local attach detach.
The external snapshot's independent guest keepers, cold transfer and browser
transport are separate, unintegrated work. No mechanism in this slice imports
an arbitrary host Claude/Codex home or adopts its running process. A host process
cannot be moved into a Linux VM by reparenting its terminal.

The migration commands added here are read-only discovery and planning. They do
not stop a pane, export a transcript, provision a box or change Runtime's route.
Plans deliberately report `can_cut_over:false`. Native history import, exact
resume qualification, source fencing and the location handoff remain required.

## First step: inventory and explicit mapping

On the source host, use its actual tmux executable and socket:

```sh
pomar migrate inventory -tmux-bin /ABSOLUTE/PATH/tmux \
  -socket /EXPLICIT/TMUX/SOCKET > inventory.json
pomar migrate plan -inventory inventory.json -manifest seats.json > plan.json
```

Discovery invokes only `list-panes -a` with a fixed format. It records session,
window and pane IDs, pane PID, dead flag, session name, current command and cwd.
It does not read prompts, terminal output, environment variables, auth stores or
history. `pane_pid` is not proof of the harness process or its descendant tree.
A command named `node` is not evidence of Claude or Codex. Names are display
labels, not seat identities. Ambiguous tab/newline fields and duplicate panes are
refused. The call is bounded to ten seconds, 4 MiB and 1,024 panes.

The mapping file is explicit and bound to the returned inventory SHA256:

```json
{
  "schema": "pomar.seat-migration/v1",
  "inventory_sha256": "COPY_THE_INVENTORY_DIGEST",
  "memory_budget_bytes": 51539607552,
  "cpu_budget_millis": 8000,
  "seats": [{
    "seat": "zeomessenger",
    "pane_id": "%3",
    "session_id": "$1",
    "environment": "seat-zeomessenger",
    "profile": "claude-seat",
    "harness": "claude",
    "native_conversation": "EXACT_NATIVE_CONVERSATION_ID",
    "memory_bytes": 2147483648,
    "cpu_millis": 1000
  }]
}
```

These capacities are arithmetic examples, not adopted host budgets. Use the
owner's available budget after host/control headroom. The planner rejects
conflicting identities and stale inventory, reports unmapped panes, lists each
seat's blockers and totals the requested active CPU/memory. Profiles are named
but not loaded or assumed to exist by this offline planner. Requested budgets
must subsequently be compared with the actual owner profile. A successful plan
command means the plan was computed, not that migration is authorized or ready.

## Required adoption transaction

1. Establish the seat's identity, exact native conversation ID, harness version,
   source workspace(s), dirty/untracked work, instruction/skill bindings and
   scoped credential enrollment. Preserve seat/mail identity across the move.
2. Stop accepting new work for that seat. Let its current turn end or explicitly
   interrupt it. Fence the source actor and descendants with host-local evidence;
   a dead tmux pane alone is insufficient. Only then capture the final workspace
   and native history, including referenced subagent/session files. An earlier
   live snapshot is only staging, never the final authoritative capture.
3. Prepare a stopped target with checksummed private capture and a durable import
   receipt. Preserve each vendor's native history; do not turn scrollback into a
   new prompt. Shared host harness homes must be split per seat, not copied into
   every guest. Re-enroll scoped credentials rather than exporting global auth.
4. Resume the exact original conversation in the target while ordinary incoming
   work is fenced. Verify identity, history visibility, workspace/dirty files,
   tools, permissions and terminal attach/detach. The current guest materializer
   uses `/work`; host cwd relocation must be tested per pinned harness version.
   Never silently create a new conversation if resume or identity binding fails.
5. Change Runtime's location/incarnation with the same durable operation ID and
   release work to the verified target. This needs Runtime's real ownership
   contract. Receipt uncertainty holds both launch paths until reconciled.
6. Retain the stopped source for rollback. Rollback first fences the target; if
   it has performed work, reconcile its new history and files before resuming
   the old source. Never run both actors for the same seat.

Start with one Claude and one Codex seat, then small batches after observed
success. Moving the fleet should not also switch harness vendors. Preserve the
original vendor first; use fenced actor-switch separately after adoption.

Fifty persistent seats need not mean fifty simultaneously running VMs. At a
hypothetical 2 GiB each, fifty already reserve 100 GiB before host/helper overhead.
Admit active boxes against actual capacity, spread them across hosts, or stop
explicitly quiescent boxes while retaining their disks. Stopping a VM ends its
live PTY and processes; subsequent activation is native harness resume, not live
process continuity. Screen heuristics are not permission to suspend an actor.

## Exposing the multiplexer

The existing retained guest terminal routes remain unchanged by this slice.
Interactive `pomar seat attach` consumes Ctrl-b d locally; Ctrl-b Ctrl-b sends
a literal prefix. No new host tmux layer is created. Independent guest keepers,
browser reconnect/control and host inventory APIs from the external snapshot
must be separately integrated and qualified before claiming those capabilities.
The standalone `pomar session` service is not a replacement for a retained guest
ownership contract. Additional shell/build terminals need their own owner-approved
spawn/stop interface and resource budgets.
