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
