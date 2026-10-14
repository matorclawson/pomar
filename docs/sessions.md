# Pomar sessions

A Pomar session is a named program on a terminal that Pomar owns, so the
program keeps running when every client leaves. It replaces tmux for
programs that run on a host: agents, shells, builds, anything. People and
programs drive it the same way.

The host's session service (`pomar session serve`) is the same session host
that a seat's guest will run, behind the same protocol (`pomar-terminal/v2`).
So a console that speaks to one speaks to both.

## What it is, and what it isn't

- **It is native execution under the OS user that runs the service.** It
  isn't guest isolation, and it isn't organisational admission: a session's
  program can do whatever that user can.
- **Its socket admits only that same user,** by the uid the kernel records
  for the connecting process. It authenticates the OS principal and nothing
  finer: on a host where several seats share one user, they are one
  principal to the service.
- **Binding a client to a seat or an elder, and any role key, aren't here.**
  They belong to ZEO-RT and the Architect, and nothing of them is kept in
  session state.
- **Control is explicit.** Any number of clients view a session; at most one
  controls it. Only the controller's input and window size reach the program,
  and each write is fenced by the controller's grant epoch: a revoked
  controller's queued input never lands.
- **`new`, `send` and `stop` are once per operation ID.** A retry with the
  same ID returns what the operation did, and never acts twice. A `stop`
  acts on the session that held the name when it began, never on a later
  generation that took the name since. Never retry under a new ID: if a reply
  is lost, ask again with the same one.
- **Sessions don't survive a restart of the service, or a reboot.** On
  start, the service reconciles its journal. It lists the sessions an earlier
  service held and never saw end as out of its reach (`unrecovered` in
  `pomar session ls -json`). It never says they exited: a program can outlive
  the service that started it. Surviving a restart isn't provided, and isn't
  promised. **Its durable log is the one exception:** the bytes already
  captured stay on disk, and are readable by the session's exact ID, even
  once a restarted service knows nothing else about it.
- **The journal is metadata only:** who created, entered, controlled,
  wrote to or stopped which session, and when. It never holds input, screens,
  commands or their arguments.
- **A screen isn't claimed to be free of secrets.** A program can show one,
  and `screen` and `attach` show what the program shows.
- **Installing the service** to start at login (a launchd agent, or a systemd
  user unit) is a separate, reviewed owner operation. Nothing in Pomar
  installs it, or stops any tmux session.

## The service

```sh
pomar session serve [-root DIR]
```

- **It runs in the foreground** until it is interrupted. When it is ready, it
  prints one JSON line with its socket.
- **When it ends, it stops every session it holds,** and journals each end.
- **The root** is `-root`, else `$POMAR_SESSION_ROOT`, else
  `~/.local/state/pomar/sessions`:
  - it is made 0700 if it's missing;
  - it is refused if it is a link, isn't owned by the user, or is open to
    its group or others.
- **One service serves a root,** under a kernel lock. A second one exits 5.
- **The root holds:**
  - `sessions.sock`, mode 0600;
  - `journal.jsonl`, appended and synced line by line;
  - `logs/ID.log`, one durable log per session (below), private, append-only;
  - `serve.lock`.

## Commands

Every command takes `-root`. Everything but `attach` prints JSON (`screen` and
`ls` print text unless they're given `-json`).

| Command | What it does |
|---|---|
| `pomar session new -id OP [-kind K] [-cols C -rows R] [-env K=V]... [-dir D] [-state] NAME -- /ABS/PROGRAM ARGS...` | Starts PROGRAM on a terminal named NAME. A name that is running is refused; a name whose program ended is taken by a new generation. `-state` gives it a state channel (see [Agent state](#agent-state)). |
| `pomar session ls [-json]` | Lists every session, and those an earlier service held (`unrecovered`). |
| `pomar session show NAME` | One session's state (below). |
| `pomar session screen [-json] NAME` | The current screen as text rows. With `-json`, also the cursor, the title and the output offset. |
| `pomar session logs [-from N] [-limit N] [-o PATH] NAME` | The session's durable log, paged (below). To stdout, or `-o PATH`. |
| `pomar session send -id OP [-enter] [-take] [-session ID] [-epoch N] [-when-ready [-ready-wait D]] [-accept-wait D] NAME [--] TEXT` | Writes TEXT as the program's input (below). `-enter` adds a carriage return. After `--`, TEXT may begin with a dash. |
| `pomar session paste -id OP [-file PATH] [-take] [-raw] [-session ID] [-epoch N] [-when-ready [-ready-wait D]] [-accept-wait D] NAME` | Sends a file's, or stdin's, whole content as one write (below). |
| `pomar session attach [-view] [-take] [-title=false] NAME` | Enters the session's terminal (see below). |
| `pomar session stop -id OP NAME` | Stops the program, and reads back its process group (below). |

**What `ls -json` and `show` give, for each session:**

| Field | Meaning |
|---|---|
| `host`, `uid`, `user` | where the session runs, and as whom |
| `id` | the session's ID: its generation's identity |
| `name`, `kind` | its label, never authority |
| `generation` | 1 for a name's first session, then one more for each that took the name |
| `outcome` | `running` or `exited` (with `exit_code`); `ls` lists an earlier service's as `unrecovered` |
| `program`, `dir` | the program's path and working directory: never its arguments or environment |
| `epoch` | the grant epoch: it changes at every grant, take and release |
| `controller`, `viewers` | the principals controlling and attached |
| `agent` | the state its adapter last reported, or `unknown` |
| `state_channel` | whether it has one |
| `cols`, `rows`, `last_output` | its window size, and when it last printed |

**A new program's environment is exactly:**
- TERM (`xterm-256color` if yours is unset), HOME, PATH and LANG from yours;
- then each `-env`, which wins;
- with `-state`, `POMAR_SESSION_STATE`, which only the service sets.

Nothing else of the caller's environment reaches it. Its window is your
terminal's size, or 80x24.

### Logs

A session's output is retained live only in memory (bounded, and only
reachable by attaching). Its log is durable: every byte the program has
printed, from the moment the session was created, on disk, whether or not
anything was ever attached. A restarted service forgets every name, but not
the logs on disk: `pomar session logs` by name works only for a session this
service still knows; a log from before a restart is reachable by its exact
session ID (`ls -json`'s `unrecovered` gives it), over the same JSON API at
`/v1/sessions/by-id/ID/logs`, not yet a CLI verb of its own.

- **It's raw bytes,** the same ones any attached client would see: never
  JSON, never re-rendered.
- **It's paged.** `-limit` bounds one read (1 MiB by default and at most);
  `-from` is the byte offset to continue from. Past the end of what's
  retrieved, stderr says so, with the offset to continue from.
- **It's bounded, per session** (64 MiB). Past the bound, further output
  isn't logged; this is recorded once, in the journal, metadata only, never
  inside the log itself.
- **It's never the audit journal.** The journal stays who did what, when; the
  log is exactly the program's bytes, with the same "not claimed free of
  secrets" caveat as a screen read.

### Sending

A send:
- takes control only when nobody holds it, or, with `-take`, from whoever does;
- writes, waits up to 10 s for the program to read the input, and gives
  control back.

**It is fenced.** With `-session ID` or `-epoch N`, the values you last read
from `show`, a session that has changed since is refused as stale (exit 7),
and nothing is written. The name may have a new generation, or control may
have changed hands. Read it again, then decide.

**It is raw by default,** and says so: `"mode": "raw"`. A raw send can land
while a person is typing at a prompt; that is what tmux's send-keys does too.
**`-when-ready` waits instead:**
- the text is held until the session's adapter reports the program
  `waiting-input`, in a report no send has used yet, for up to `-ready-wait`
  (30 s by default, at most 10 min);
- a send whose session doesn't report it in time is refused (exit 9), and
  nothing is written;
- a session without a state channel can't say when it is ready, so a
  `-when-ready` send to it is refused (exit 8), never written raw.

**Its reply tells each stage apart:**

| Field | Meaning |
|---|---|
| `queued` | the whole text is in Pomar's input queue |
| `written` | it reached the program's terminal |
| `accepted` | `yes` once the adapter reports the program accepted it (by `input_id`); `pending` until then; `unsupported` without a state channel |
| `input_id` | the send's operation ID, which the adapter is told |
| `epoch` | the grant epoch after the send |
| `outcome` | `written`, `accepted` (with `-accept-wait`, once confirmed), `partial` (some bytes reached the program, and nothing is resent) or `uncertain` (the program didn't read in time) |

### Pasting

A paste is a big send, not a separate wire primitive: `pomar session paste`
reads a whole payload at once (`-file PATH`, or stdin) and writes it as a
single send, with the same fencing, control-taking, `-when-ready` and reply
shape as `send`. It invents nothing of its own: a huge paste that the
program can't keep up with reports `partial`, exactly as a huge `send` would.

- **It's bracketed by default:** wrapped in `ESC[200~` … `ESC[201~`, so a
  program that supports bracketed paste treats it as one paste, not
  per-character typing (an editor's auto-indent, say, usually reacts
  differently to a paste). `-raw` sends the payload as it is.
- **It's bounded** at 8 MiB; over that, it is refused (exit 2), and nothing
  is sent.
- **Fencing is identical to `send`'s:** `-session`/`-epoch` refuse it as
  stale (exit 7) if the session changed since you read it; a stale paste
  writes nothing, same as a stale send.

### Stopping

A stop:
- runs with the authority of the service's own user, the only one its socket
  admits;
- hangs up the program's process group, and kills the group if its leader is still
  running after 3 s;
- once the leader is reaped, gives any process left in its process group
  (one that ignored the hangup) 3 s more, then kills the group.

**It reads back** `leader` (`reaped`) and `group` (`gone`, or `remaining` if a
process outlived even the kill), and `group_killed` when a member had to be
killed. A process that left the group with its own `setsid` or `setpgid` is
outside what it reads. The group is signalled only while it is known to
exist: once the leader is reaped and the group is empty, its id may be reused.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | done |
| 1 | failed, or its outcome is uncertain: stderr says what to do |
| 2 | a flag or argument is wrong |
| 3 | no session service answers for the root |
| 4 | no session has that name |
| 5 | refused as it stands: the name is running, another client controls it, or the operation is still running (ask again with the same ID) |
| 6 | the session's program has exited |
| 7 | stale: the send named a generation or epoch the session no longer has; nothing was written |
| 8 | unsupported: a `-when-ready` send to a session without a state channel; nothing was written |
| 9 | not ready: the adapter didn't report the program waiting for input in time; nothing was written |

## Agent state

A session's agent state says whether its program is working, waiting for
input, or waiting on a permission prompt. **It is only ever reported by an
adapter, never read off the screen,** and is `unknown` until one reports.
Pomar has no adapter of its own and knows nothing of which agent a session
runs: an adapter is whatever program speaks for it (a Claude Code or Codex
adapter is its owner's work).

**The contract, for an adapter:**
1. A session made with `-state` has `POMAR_SESSION_STATE` in its
   environment: the path of a Unix socket in the service's private root, mode
   0600, which admits only the service's user.
2. The adapter connects to it, from the session's program or anything it
   starts. The latest connection is the adapter's.
3. It writes one JSON object per line, at most 4096 bytes:
   - `{"state": "running" | "waiting-input" | "permission" | "idle", "detail": "..."}`, `detail` being an optional short label;
   - `{"accepted": "INPUT_ID"}`, once the program has taken an input as a
     submission;
   - or both in one line.
4. Once a send's text has reached the program, the service writes it a line:
   `{"input_id": "...", "bytes": N, "mode": "raw" | "when-ready"}`.
5. A malformed line (unknown fields, an unknown state, neither field) is
   answered with `{"error": "..."}`, and the connection ends. The adapter
   reconnects.

**What the service does with a report:**
- `waiting-input` is what `-when-ready` waits for. Each such report admits
  one send: a report carrying only an acceptance doesn't renew it.
- `show` and `ls` carry the last report as `agent`: `state`, `detail`,
  `seen`, `seq` (counting reports), `state_seq` and `accepted_input`.
- Every attached client gets it as a `State` frame, on attach and on every
  report.

**What it doesn't claim:** a state is what the adapter said, when it said
it. The program may have moved on since; `-when-ready` narrows the window
in which a raw send would land mid-edit, and the adapter's acceptance is
the only confirmation that it was taken.

## Entering a session

```sh
pomar session attach NAME          # control it if nobody does, else view
pomar session attach -view NAME    # view only
pomar session attach -take NAME    # take control from whoever has it
```

- **You see the exact current screen at once:** the service keeps a model of
  each session's screen (termstate), not a replay of its history.
- **Ctrl-] detaches,** and is never sent to the program. A dropped connection
  is a detach too. Detaching never stops the program.
- **As controller,** your window size becomes the session's, and each resize
  follows.
- **As viewer,** nothing you type is sent.
- **Your status is live, and never drawn over the program's screen:** your
  role, the grant epoch, how many are attached, and the agent state.
  - When stderr isn't the terminal you attach from, each change is a line on
    stderr, and so are the service's notices.
  - Otherwise it is the terminal's title, written only between the program's
    sequences and characters, and the terminal's own title is restored when
    you leave (`-title=false` turns it off). The notices (viewing, control
    taken, the program exited, the screen redrawn after you fell behind) are
    printed when you leave.

## The protocol

The attach stream and the JSON API are specified in
[sessions-protocol.md](sessions-protocol.md), for any client, such as
ZEOAPP's console.
