# Understand your Pomar

Start with a short read-only report from the approved manager socket:

```sh
export POMAR_SOCKET=/path/supplied/by/your/host/owner/control.sock
pomar health
pomar health -json
```

`health` answers whether the manager's authorized capacity API responds,
whether admission is drained, what its configured budget and disk observation
are, and which caller-visible classes numerically fit **current known claims**.
It prints typed resource deficits when no class fits. It never starts a job,
restarts a service, changes a grant, releases storage or tries another socket.

Add `-expected-key-id YOUR_INDEPENDENTLY_RETAINED_KEY_ID` to compare the result
public key with your host's existing binding. An unpinned response is labelled
`UNPINNED`; never copy the response back as its own trust anchor. `MATCH` checks
the public key bytes and ID, not endpoint possession, code signing or a signed
job result. A mismatch is an attention condition and exits 1.

## Choose the right view

| Question | Command | What it establishes |
| --- | --- | --- |
| Is my installed client usable? | `pomar doctor -json`, `pomar version` | Client/tool checks and client source; not daemon identity |
| Is the manager answering, and what is unknown? | `pomar health` | Bounded authorized observations, explicit limits and next steps |
| What fits beside current work? | `pomar status` | Numerical capacity, current fits and typed deficits when supported |
| Which jobs can I inspect? | `pomar jobs` | Attempts visible to this caller; not every user's work |
| What is this job doing? | `pomar attempt progress -id ID` | Phase, provisional output, age and registry activity when supported |
| Did it finish and produce the expected artifact? | `pomar logs -id ID`, `pomar attempt result -id ID` | Retained final bytes; verify the signed result against the independent key |
| What retained development state needs attention? | `pomar seats -root ROOT`, `pomar seat status -root ROOT SEAT` | Owner-scoped declared seat/lifecycle state |
| Where is storage going? | `pomar venue status -root ROOT`, owner-authorized `attempt caches` | Existing scoped storage evidence; access denial does not permit owner-data inspection |

The installed manager may predate current capacity or progress fields. `health`
reports `UNKNOWN` current admission instead of substituting `fits_idle` or
assuming missing values are zero. A reachable socket or an idle host is never
a completed build. Use the host owner's reviewed release procedure to add
missing diagnostics; a client update alone cannot add server evidence.

## JSON contract and limits

`pomar.health/v1` contains the client receipt time, selected socket, client
version/source, manager response status, result-key binding, admission
observation, configured host budget, disk, known live attempts, capacity
coverage, caller-visible current fits/deficits, unknowns and next steps.
Missing amounts are null. This is `UNSIGNED_MANAGER_OBSERVATIONS`: the two API
reads are not atomic, and the snapshot is not an attested health certificate.

The total deadline is 8 seconds by default (`-timeout`, 100ms to 30s); each
successful response is limited to 1 MiB. Only the existing capacity and
signing-key GET routes are used. Redirects are refused, unsuccessful response
bodies are not printed, and no provider/account/private data files are read.
Explicit `-root` selects that owner's socket ahead of the socket environment;
explicit `-socket` wins. No target is guessed. Exit 0 means capacity responded
and any requested key binding passed; it does **not** mean work is admitted or
healthy. Exit 1 means attention/read failure; exit 2 means invocation/selection
is incomplete. Drained or numerically full hosts can still be responsive.

## The operator surface still to complete

The full view must answer: which enrolled host/release is serving; what can run
now; what each job is doing; why and where it waits; and what needs attention.
This command is the first local view. It deliberately reports physical load
and memory pressure, external/retained-environment claims, installed daemon
release/signature, guest/helper health, signed execution and fleet queues as
unobserved. It does not implement discovery, placement, fairness or a watcher.

The retained fleet plan supplies host-independent placement and host-specific
typed waits. Further increments need live log follow, meaningful workload
stages and silence/transfer ages, restart/reconcile and retained-state health,
owner-scoped storage attribution, and an allowlisted support-bundle export.
Every view needs observation time, coverage, explicit unknowns and a named
action owner. Quiet startup cannot justify a duplicate build, and recovery
must not automatically reset or stop somebody else's work.
