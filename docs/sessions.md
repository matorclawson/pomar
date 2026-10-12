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
  promised.
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
  - `serve.lock`.

## Commands

Every command takes `-root`. Everything but `attach` prints JSON (`screen` and
`ls` print text unless they're given `-json`).

| Command | What it does |
|---|---|
| `pomar session new -id OP [-kind K] [-cols C -rows R] [-env K=V]... [-dir D] NAME -- /ABS/PROGRAM ARGS...` | Starts PROGRAM on a terminal named NAME. A name that is running is refused; a name whose program ended is taken by a new generation. |
| `pomar session ls [-json]` | Lists every session: state, size, controller and viewers. It also lists those an earlier service held. |
| `pomar session show NAME` | One session's state. |
| `pomar session screen [-json] NAME` | The current screen as text rows. With `-json`, also the cursor, the title and the output offset. |
| `pomar session send -id OP [-enter] [-take] NAME TEXT` | Writes TEXT as the program's input. `-enter` adds a carriage return. |
| `pomar session attach [-view] [-take] NAME` | Enters the session's terminal (see below). |
| `pomar session stop -id OP NAME` | Hangs up the program's process group, and kills it if it is still running after 3 s. |

**A new program's environment is exactly:**
- TERM (`xterm-256color` if yours is unset), HOME, PATH and LANG from yours;
- then each `-env`, which wins.

Nothing else of the caller's environment reaches it. Its window is your
terminal's size, or 80x24.

**A send:**
- takes control only when nobody holds it, or, with `-take`, from whoever does;
- waits up to 10 s for the program to read the input;
- gives control back.

Its `outcome` is one of:
- `written`;
- `partial`: some bytes reached the program, and nothing is resent;
- `uncertain`: the program didn't read in time.

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
- **The service's notices** (viewing, control taken, the program exited, the
  screen redrawn after you fell behind) are printed when you leave, not over
  the program's screen.

## The protocol

`pomar-terminal/v2` is an HTTP upgrade on the service's socket:
`POST /v1/sessions/NAME/attach?view=1&take=1`. It uses `pomar-terminal/v1`'s
frames (`d` data, `r` resize, `x` close), plus `n`, a notice from the service
of at most 512 bytes of text.

The stream runs in this order:
1. The client's first frame is its window size.
2. The service sends the screen: an ANSI reconstruction (`pomar-termstate-ansi/1`) of
   the cut, then the session's live output from exactly that cut.
3. A client that falls behind gets a fresh screen, never a silent gap.
4. v1 streams never carry a notice.

The control API is JSON on the same socket:

| Route | Does |
|---|---|
| `GET /v1/sessions` | The listing, with `unrecovered` |
| `POST /v1/sessions` | `new` |
| `GET /v1/sessions/NAME` | `show` |
| `GET /v1/sessions/NAME/screen` | `screen` |
| `POST /v1/sessions/NAME/send` | `send` |
| `POST /v1/sessions/NAME/stop` | `stop` |

A refusal's body is `{error, kind}`, and `kind` is one of `usage`,
`not_found`, `conflict`, `in_progress`, `exited`, `uncertain` or `internal`.
