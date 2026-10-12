# Pomar for agents

This is for any program that drives Pomar: a coding agent, a script, a CI
caller. Every command below prints JSON (except `logs`, which prints the
job's own output) and has fixed exit codes. `pomar help -json` lists them all.

## What Pomar does

Pomar runs a command in a fresh, disposable Linux micro-VM on an Apple
silicon Mac, with pinned inputs, no host credentials and controlled egress.
It returns a signed result.

You don't need the Pomar source to use it, only the `pomar` client and a
manager's control socket.

## 1. Find your manager

Your host owner gives you a control socket. Pomar never guesses one.

```sh
export POMAR_SOCKET=/path/your/owner/gave/you.sock
pomar doctor -json
```

`doctor -json` is an array of checks, each `{name, ok, skipped, detail, next}`:
- it exits 0 when everything you need is usable;
- a check with `skipped: true` doesn't apply to you, and isn't a failure;
- a check that isn't OK carries `next`, the exact thing to do.

**If the socket is refused, stop and ask your host owner.** Never use sudo,
and never change the socket's permissions.

## 2. The loop

```sh
pomar status                                    # classes you may run: .classes[].name
pomar run -wait -id build-1 -class ci -- make test
echo $?                                         # the job's own exit code
pomar logs -id build-1                          # its output, checked against its result
pomar attempt result -id build-1                # the signed result document
```

- **IDs are yours to choose, and unique.** Reusing one is refused (HTTP 409); pick a new one.
- **Without `-wait`, `run` returns at admission.** Admission is not success.
- **If `run` says the manager didn't reply,** the job may have been admitted: look it up with `pomar attempt get -id ID`. Never start it again under a new ID.
- **Every manager call is bounded** (60 s), and `-timeout` bounds a whole wait, calls included.
- **To wait for a job you started without `-wait`:** `pomar wait -id build-1 [-timeout 10m]`.
- **For a repository job,** name the owner's mirror and a commit: `-mirror NAME -ref main [-sha SHA]`.
- **Files in:** `-input NAME=PATH` arrives at `/pomar/inputs/NAME`.
- **Files out:** `-output NAME` is copied back from `/pomar/outputs/NAME`. Fetch it with `pomar attempt output -id ID -name NAME -o PATH`.
- **While a job runs,** `pomar attempt progress -id ID` shows its phase and bounded provisional output, where the manager supports it.

## 3. Exit codes of `run -wait` and `wait`

| Code | Meaning |
|---|---|
| the job's own | the job exited by itself (0 is success) |
| 75 | `-timeout` passed; the job is **still running** and was not stopped |
| 124 | the job was stopped by its class's time limit |
| 125 | Pomar couldn't run the job to its end (it failed, or its helper was lost): read the record's `reason` |
| 143 | the job was stopped on request |
| 1 | the command itself failed: stderr says why, and what to do |
| 2 | a flag or argument is wrong |

## 4. Trust the result, not the exit code alone

The result is signed by the manager. Verify it with the owner's public key,
which you got from them independently, not from the manager you're checking:

```sh
pomar attempt result -id build-1 > result.json
pomar result verify -reply result.json -public-key "$OWNER_KEY"
pomar logs -id build-1 -public-key "$OWNER_KEY"   # the log, checked against the verified result
```

## 5. Seats: interactive environments

A development seat is a long-lived environment for an agent, whose terminal
an operator can enter.
- `pomar seats` lists them.
- `pomar seat status SEAT` shows one, as JSON.

Starting a seat and entering it are the host owner's acts (`pomar help all`).

## 6. Sessions: programs that outlive their terminal

`pomar session` runs a program on a terminal that this user's session service
owns, so it keeps running when every client leaves. It works the same for
any program: an agent, a shell, a build. The service must already be running
(`pomar session serve`, which the host's owner starts); without one, every
command exits 3.

```sh
pomar session new -id new-1 build -- /bin/sh -c 'make test; exec /bin/sh'
pomar session screen build                      # the screen as text, now
pomar session send -id send-1 -enter build 'echo done'
pomar session ls -json
pomar session stop -id stop-1 build
```

- **`-id` makes `new`, `send` and `stop` once-only.** If a reply is lost, ask again with the same ID: you get what it did, and nothing happens twice. Never retry under a new ID.
- **A send takes control only if nobody holds it.** If someone does, it exits 5; `-take` takes control, and a person who is attached then becomes a viewer.
- **The program's environment is exactly** TERM, HOME, PATH and LANG from yours, plus each `-env K=V`. The program is named by its absolute path.
- **Fence a send on what you read.** `show` gives the session's `id` and `epoch`: `send -session ID -epoch N` is refused as stale (exit 7), and writes nothing, if the name has a new generation or control changed since.
- **A send is raw unless you say `-when-ready`,** and its reply says `"mode": "raw"`. A session made with `-state` gives its adapter a state channel. `-when-ready` then waits for the adapter to report the program waiting for input. Without one, `-when-ready` exits 8 and writes nothing. Its reply tells `queued`, `written` and `accepted` apart: only the adapter can say `accepted`.
- **`stop` reads back** the leader's reap and whether anything remains in its process group.
- **Exit codes:** 3, no service; 4, no such name; 5, refused as it stands; 6, the program exited; 7, stale; 8, unsupported; 9, not ready in time.
- **Agent state is only what an adapter reports,** never the screen, and is `unknown` without one. The adapter contract is in docs/sessions.md.
- **Sessions don't survive** a restart of the service, or a reboot.
- **A screen can show a secret.** Read it as you would read the terminal.

See [docs/sessions.md](docs/sessions.md), and [docs/sessions-protocol.md](docs/sessions-protocol.md) for the wire protocol.

## Never

- **Guess a socket or a data root.**
- **Use sudo, or widen a permission, when you're refused.** That is the host owner's decision.
- **Treat admission as success.** Wait for the end, then read and verify the result.
- **Put a credential in a job's command, inputs or environment.** Guests run without host credentials by design.

## More

- `pomar help -json`: commands, exit codes, the loop.
- `pomar help all`: every command, for the host owner too.
- [docs/operations.md](docs/operations.md): operations, seats and result verification.
- [docs/attempt-progress.md](docs/attempt-progress.md): progress while a job runs.

## Changing Pomar itself

Contributors: see [CONTRIBUTING.md](CONTRIBUTING.md). The merge gate is
`make verify`, run on the committed tree.
