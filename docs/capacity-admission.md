# Capacity admission

Managed attempts share each manager's configured host budget. Admission sums
the CPU, memory and disk claims of **every known nonterminal attempt**, across
classes, under the manager's admission mutex. Starting and stopping attempts
remain charged. A class ceiling applies to that class on that host; it does
not give one class an exclusive host or block another host.

Submit managed work directly through `pomar attempt start`. Its admission and
wait must not hold an unrelated native host-exclusive wrapper or require that
the host have no VMs. CPU/memory budgets, class policy, pinned sources, caller
authorization and disk safeguards still apply. Native work outside the manager
needs its separately approved host reservation mechanism.

## Read the current capacity

`pomar attempt capacity` retains `fits_idle` for compatibility. That field is
the number of the default class fitting on an **idle** host, not current room.
Use the additive `current` rows, selected by class name:

| Field | Meaning |
| --- | --- |
| `allocation.reserved` | Aggregate known nonterminal CPU, memory and disk claims |
| `allocation.free` | Budget/allowed disk minus those claims; may be negative |
| `current[].name` | A configured class the caller may use |
| `current[].allocation.demand` | One additional attempt's complete claim |
| `current[].allocation.fits_current` | Additional attempts fitting beside current work and below this host's class ceiling |
| `current[].allocation.failures` | Every failed numerical predicate with exact demand, available amount, deficit and unit |
| `allocation.disk_floor_bytes` | Free-space floor from the existing shared-disk 85% maximum fill |
| `coverage` | `KNOWN_NONTERMINAL_ATTEMPTS_ONLY`; external/native and retained agent-environment claims are not enrolled by this interface |

One thousand millicores is one logical/vCPU accounting slot; it is not a
promise of CPU affinity or equal performance across core types. Memory includes
the class's VM overhead. Disk includes its declared peak plus per-job headroom.
For shared storage, its current free allowance also respects the fill floor.
Existing claims conservatively remain fully charged even if part of their
disk claim has already been written. Polling this read does not reserve room.

For example, with an 8-CPU/20-GiB budget, a 2-CPU/8-GiB job and a 4-CPU/6-GiB
job, each with 300 MiB VM overhead, reserve 6000 millicores and 15,661,531,136
memory bytes. Another 4-CPU/6-GiB attempt waits for 2000 millicores and
943,718,400 memory bytes. Two 2-CPU/8-GiB jobs fit numerically when their
configured per-host class ceiling is at least two. This is arithmetic, not a
claim that this workload has passed concurrent execution qualification.

`draining` is a separate owner admission fence. A positive numerical fit does
not override it, base verification, authorization or source policy. A one-time
drained installation window is not the ordinary admission rule. A refusal
creates no new attempt or resource reservation. The HTTP 503 keeps its legacy
`reason` and adds `failures` with typed resources and exact amounts. In
particular, `host-budget` can now be explained as `CPU_BUDGET`,
`MEMORY_BUDGET`, or both, without parsing prose.

This legacy status extension is not the proposed pooled capacity/queue export,
durable fairness scheduler, restart-incarnation fence or native pressure
adapter. It has no placement authority. Missing external coverage cannot be
treated as a proven free host. Each manager retains its own data root and
claims; multi-host placement must bind each independently qualified host and
policy. Increasing a protected budget or class ceiling requires the host's
reviewed configuration and installation procedure plus qualification; this
read or a source PR does not change the installed service.
