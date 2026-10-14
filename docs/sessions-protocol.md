# Pomar sessions: the protocol

This is the wire protocol of a Pomar session service, for any client: the
`pomar` CLI, ZEOAPP's console, or a seat's runtime. It has two parts on one
socket: a JSON API, and the `pomar-terminal/v2` attach stream. What sessions
are, and what they don't claim, is in [sessions.md](sessions.md).

The same session host is meant to run in a seat's guest, behind the same
protocol, so a client written to this document speaks to both.

## Transport

- **The socket** is `ROOT/sessions.sock`, a Unix socket of mode 0600 in a
  private root (see sessions.md).
- **The service admits a connection only when the kernel's peer uid is its
  own.** Anything else is closed unanswered, and journaled as refused.
- **A client checks the socket's custody** before it sends anything: owned
  by its own uid, and not a link.
- **Requests are HTTP/1.1** with the host `sessions`. Bodies are JSON, at
  most 1 MiB in, 4 MiB out. Unknown request fields are refused.

## The JSON API

| Method and path | Body | Reply |
|---|---|---|
| `GET /v1/sessions` | | a listing |
| `POST /v1/sessions` | a create | 201 a new session, or 200 the one this operation already made |
| `GET /v1/sessions/NAME` | | a session |
| `GET /v1/sessions/NAME/screen` | | its screen |
| `GET /v1/sessions/NAME/logs?from=N&limit=N` | | a log chunk |
| `GET /v1/sessions/by-id/ID/logs?from=N&limit=N` | | a log chunk, by exact ID, reachable after a restart |
| `POST /v1/sessions/NAME/send` | a send | an operation result |
| `POST /v1/sessions/NAME/stop` | a stop | an operation result |
| `POST /v1/sessions/NAME/attach?view=1&take=1` | | an upgrade to `pomar-terminal/v2` |

### A create

```json
{"operation": "OP", "name": "work", "kind": "agent", "path": "/abs/program",
 "args": ["..."], "env": ["TERM=xterm-256color", "..."], "dir": "/abs/dir",
 "cols": 120, "rows": 40, "state_channel": true}
```

- **`operation`** is the caller's own ID. A retry with the same ID and the
  same spec returns the same session. A different spec under it is refused
  (`conflict`).
- **`name`** is a lower-case word of up to 32 letters, digits and dashes.
- **`path`** is absolute, and **`env`** is the program's whole environment:
  the service adds nothing but, with `state_channel`, `POMAR_SESSION_STATE`.
  An `env` that names it is refused.
- **Bounds:** `cols` 1 to 1000, `rows` 1 to 500, and at most 8 live sessions.

### A session

```json
{"id": "…", "name": "work", "kind": "agent", "running": true, "exit_code": 0,
 "host": "…", "uid": 501, "user": "…", "generation": 2, "outcome": "running",
 "program": "/abs/program", "dir": "/abs/dir", "cols": 120, "rows": 40,
 "epoch": 7, "controller": "uid:501", "viewers": ["uid:501", "uid:501"],
 "last_output": "RFC 3339 time", "state_channel": true,
 "agent": {"state": "waiting-input", "detail": "…", "seen": "RFC 3339 time",
           "seq": 4, "state_seq": 3, "accepted_input": "OP"}}
```

- **`outcome`** is `running` or `exited`. `exit_code` is present only once
  the program has exited.
- **Principals** are `uid:N`: the service authenticates OS users, nothing
  finer, so clients of one user share one principal.
- **`agent.state`** is `unknown` until an adapter reports. It is never
  derived from the screen.
- **A session never carries** its arguments, its environment, its input or
  its screen.

### A listing

```json
{"serve": "…", "started": "…", "root": "…", "host": "…", "uid": 501, "user": "…",
 "sessions": [ /* sessions, by name */ ],
 "unrecovered": [{"id": "…", "name": "…", "serve": "…", "outcome": "unrecovered"}],
 "survives": "clients and dropped connections; not a restart of this service, and not a reboot"}
```

`unrecovered` lists the sessions an earlier service held and never saw end.
Whether they still run isn't known; they are never reported as exited.

### A screen

```json
{"cols": 120, "rows": 40, "cursor": [0, 3], "title": "…", "alternate_screen": false,
 "lines": ["each row, trailing blanks trimmed"], "offset": 12345, "running": true}
```

`offset` is the output offset the screen reflects.

### Scrollback

`GET .../scrollback[?lines=N]` answers the lines scrolled off the screen,
oldest first, up to `HistoryLines` (2000), readable without attaching:

```json
{"lines": ["each history line, trailing blanks trimmed"], "truncated": false}
```

`lines` (query, optional, a positive integer) bounds the most recent lines
returned; `truncated` is `true` when more history is kept than was asked
for.

### Health

`GET .../health` answers a passive, heuristic read of the current screen,
for criterion 14 of the tmux-replacement acceptance (remote seat health,
without the seat's cooperation):

```json
{"possible_panic": false, "possible_readonly_refusal": false, "possible_approval_prompt": false,
 "last_output": "2026-10-14T17:00:00Z"}
```

Every `possible_*` field is a fixed, documented substring match against the
current screen's text, nothing more: diagnostic only, never authoritative,
never fed back into any control or readiness decision, and never a
substitute for agent state (below) when an adapter can speak at all.

### A log chunk

`GET .../logs` answers raw bytes, never JSON, with headers naming the whole
log's size and this chunk's bounds:

```
X-Pomar-Log-Size: 12345
X-Pomar-Log-From: 0
X-Pomar-Log-Truncated: true

<body: raw bytes, at most 1 MiB>
```

- **`from`** (query, default 0) is the byte offset to start from.
- **`limit`** (query, default and max 1 MiB) bounds this read; a longer log
  is paged, never answered whole in one reply.
- **`X-Pomar-Log-Truncated`** is `true` when more of the log follows this
  chunk: read again with `from` at `X-Pomar-Log-From` plus the body's length.
- **The log is exactly the program's own bytes,** from the session's
  creation, whether or not anything was ever attached: never JSON-wrapped,
  never re-rendered, and bounded per session at 64 MiB (past it, further
  output isn't logged; this closes without ever growing past its bound).
- **By name,** it answers only for a session this service still knows (as
  `screen` and `show` do). **By ID,** it answers for any log file on disk,
  including one from before this service's own restart, since the log
  survives a restart even though the session itself doesn't.

### A send

```json
{"operation": "OP", "text": "…", "take": false, "session": "ID", "epoch": 7,
 "when_ready": true, "ready_wait_ms": 30000, "accept_wait_ms": 5000}
```

- **`session` and `epoch`** are optional fences: the generation and grant
  epoch the caller last read. A session that has changed since is refused as
  `stale`.
- **`when_ready`** holds the text until the adapter reports `waiting-input`,
  in a report no send has used.
  - It waits `ready_wait_ms`, by default 30 s and at most 10 min. A session
    that isn't ready by then is refused as `not_ready`.
  - A session without a state channel is refused as `unsupported`.
- **`accept_wait_ms`** waits, after the write, for the adapter to report the
  input accepted.

A paste (`pomar session paste`) is this same request, with `text` wrapped in
bracketed-paste markers (`ESC[200~` … `ESC[201~`) by the client before it's
sent: the service has no separate paste primitive, and never interprets
`text` either way.

### A stop

`{"operation": "OP"}`.

### An operation result

A send or a stop answers with an operation result, the same for every retry
of its operation:

```json
{"session": "ID", "outcome": "written", "detail": "…",
 "mode": "raw", "input_id": "OP", "epoch": 9,
 "queued": true, "written": true, "accepted": "pending",
 "leader": "reaped", "group": "gone", "group_killed": false}
```

| Operation | `outcome` |
|---|---|
| send | `written`, `accepted`, `partial` or `uncertain`. The last two come with status 409. |
| stop | `stopped` or `already-exited` |

- **A send's acknowledgements** are each a later stage:
  - `queued`: in Pomar's input queue;
  - `written`: at the program's terminal;
  - `accepted`: `yes`, `pending` or `unsupported`, from the adapter.
- **`mode`** is `raw` or `when-ready`.
- **A stop's readback** is `leader` (`reaped`, or `running` when uncertain)
  and `group` (`gone` or `remaining`).
- **An operation still running** is refused as `in_progress`. Ask again with
  the same ID.
- **An operation refused before it acted** (`stale`, `unsupported`,
  `not_ready`, `exited`, `not_found`) did nothing. Its ID decides afresh on a
  retry.

### Refusals

A refusal's body is `{"error": "…", "kind": "…"}`:

| `kind` | Status | Meaning |
|---|---|---|
| `usage` | 400 | the request is malformed |
| `not_found` | 404 | no session has that name |
| `conflict` | 409 | refused as it stands: a running name, another controller, a full bound or queue, a different spec under one operation |
| `in_progress` | 409 | the operation (or a create) is still running |
| `exited` | 409 | the session's program has exited |
| `stale` | 409 | the request named a generation or epoch the session no longer has |
| `unsupported` | 409 | a `when_ready` send to a session without a state channel |
| `not_ready` | 409 | the adapter didn't report the program waiting for input in time |
| `uncertain` | 409 | the outcome couldn't be confirmed: a take's fence, or a stop |
| `internal` | 500 | anything else |

A lost reply's effect is unknown. Ask again with the same operation ID;
never retry under a new one.

## The attach stream: `pomar-terminal/v2`

```text
POST /v1/sessions/NAME/attach?view=1&take=1 HTTP/1.1
Host: sessions
Connection: Upgrade
Upgrade: pomar-terminal/v2
```

- The service answers `101 Switching Protocols`, or a refusal as above.
- `view=1` attaches read-only. `take=1` takes control from whoever holds it.
- Without either, the client controls the session if nobody does, and views
  it otherwise.

### Frames

Every frame is one type byte, a big-endian uint16 payload length, and the
payload.

| Type | Name | Direction | Payload | Bound |
|---|---|---|---|---|
| `d` | Data | both | terminal bytes: the program's output, or the controller's input | 32 KiB |
| `r` | Resize | client to service | columns and rows, two big-endian uint16 | 1..1000 x 1..500 |
| `x` | Close | both | nothing | 0 |
| `n` | Notice | service to client | a line of text about the session, never terminal bytes | 512 B |
| `c` | Control | both | one JSON object: a request, or an answer or change | 4096 B |
| `p` | Presence | service to client | one JSON object: who is attached, who controls, your role | 4096 B |
| `s` | State | service to client | one JSON object: the agent state | 4096 B |

- A frame of an unknown type, an over-long payload, or a meta frame (`c`,
  `p`, `s`) that isn't one JSON object ends the stream.
- `pomar-terminal/v1` has only `d`, `r` and `x`, and never carries the
  others.

### The order

1. **The client's first frame is its window size** (`r`), within 10 s.
2. **If the client asked for control,** the service answers `c`:
   `{"event": "granted", "epoch": N}`, or
   `{"event": "refused", "epoch": N, "reason": "…"}`. A controller's size
   becomes the session's.
3. **The service sends** `p`, then `s`, then the screen.
   - The screen is `d`, an ANSI reconstruction (`pomar-termstate-ansi/1`) of
     the session's screen at the cut.
   - Then come the session's live output, from exactly that cut, and the
     notices.
4. **From then on, the service sends** `p` whenever presence changes (an
   attach, a detach, a grant, a take, a release), and `s` at every adapter
   report.
   - A client that falls behind gets a fresh screen, never a silent gap.
5. **The stream ends** with `x` from either side. A dropped connection is a
   detach. Neither stops the program.
6. **When the program exits,** the service sends a notice with its exit code,
   then `x`.

### Control

A client sends `c` with `op`:
- `request`: granted only if nobody controls the session;
- `take`: from whoever does;
- `release`: give it up.

The service answers with `event`:

| `event` | Meaning |
|---|---|
| `granted` | this client controls the session, under `epoch` |
| `refused` | not granted; `reason` says why |
| `released` | this client gave control up |
| `taken` | another client took control: this one now views |

- **Every grant, take and release** moves the session's grant epoch.
- **A write is fenced at the terminal** by the epoch under which it was
  queued: once a take lands, the old controller's queued input never does.
- **A take is granted only once** the old controller's write in flight is
  confirmed ended. If that can't be confirmed in 3 s, nothing is granted
  (`refused`, kind `uncertain` in the API).
- **A viewer's** `d` and `r` frames are dropped, and it is told once by a
  notice.

### Presence

```json
{"session": "ID", "viewers": ["uid:501", "uid:501"], "controller": "uid:501", "epoch": 7, "you": "controller"}
```

- **`viewers`** counts every attached client, the controller included.
- **`you`** is `controller` or `viewer`.

### Agent state

`s` carries a session's `agent`, as in the API. It is adapter-reported, and
never derived from the screen.

## The adapter-state channel: operations

On the same `POMAR_SESSION_STATE` socket an adapter reports agent state on
(one JSON object per line, at most 4096 bytes), it may also call a durable
per-operation primitive, distinguished from a state report by carrying
`"op"`:

| Request | Reply |
|---|---|
| `{"op": "begin", "id": "OPID", "digest": "D"}` | `{"first": true}` (or `false` on a retry with the same digest) |
| `{"op": "finish", "id": "OPID", "known": true\|false}` | `{"ok": true}` |
| `{"op": "status", "id": "OPID"}` | `{"disposition": "pending"\|"sent"\|"acceptance_unknown"\|"not_found"}` |

`id` is one printable-ASCII token, at most 128 bytes. A conflicting digest
for an `id` already begun, or a `finish` on an `id` never begun or already
finished, is `{"error": "..."}`, same as a malformed state report.

This durably survives a service restart: any operation still `pending`
when a session's journal is reopened becomes `acceptance_unknown` then and
there. It is the session layer's own guarantee (no input byte replayed, no
operation resubmitted) extended with a place an adapter can durably record
whether its *own* effect is known to have landed — it is never a claim that
the session layer can stop a model from choosing to act again on its own.

## Versioning

- **The upgrade token names the stream's version.** A client asks for
  `pomar-terminal/v2`; a service that doesn't speak it refuses the upgrade.
- **Within v2:**
  - JSON objects may gain fields, and a client ignores those it doesn't
    know. The service refuses unknown fields in an API request.
  - A new frame type needs a new version.
  - A new `event`, `kind` or agent `state` value may be added. A client
    treats one it doesn't know as it would a refusal, or as `unknown`.
- **The JSON API is versioned by its path** (`/v1/`).
- **The adapter contract** (sessions.md, Agent state) is versioned with the
  API.
