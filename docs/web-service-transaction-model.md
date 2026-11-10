# Web service transaction model (source preparation)

`internal/webservice` is a platform-independent model for an admitted,
fixed-port web service deployment. It supplies no CLI, native controller,
systemd integration, persistent store, installation, switch, or rollback
implementation. Existing VM execution and service upgrade behavior is unchanged.

The caller must supply admitted release, profile and persistent database
identities, an operation ID, epoch and exact expected previous release. The
store owns one atomic revision/current/epoch/database/active-operation record
with retained original operations. It must return detached snapshots and
atomically persist a compare-and-swap before reporting success. No production
implementation of that storage contract is included.

The model persists maintenance intent, then stop intent after maintenance
observation. Only a complete previous-writer departure observation permits API
start intent. API readiness precedes web start intent; web readiness precedes
route-reopen intent; route readiness alone completes the operation and releases
the active fence. The same fixed ports and build are retained. There is a
maintenance window, not a side-by-side candidate with a second database writer.

Events bind operation, epoch and expected phase. Evidence references must be
exact digests, but a digest alone proves no native fact. A future trusted
adapter must authenticate observations against the actual generation, complete
writer/cgroup departure, effective isolation/resource/network properties,
readiness predicates and installed control authority before supplying them.
The model is an internal source interface, not an admitted wire API or a generic
permission to execute release-supplied commands.

Same-ID retries return the original retained operation; changed inputs conflict.
After an ambiguous store acknowledgement, inspect the original ID and phase.
Do not replay a stale transition or manufacture a replacement ID. Unknown
outcomes retain the active fence and prior identity; this slice has no generic
clear-unknown or recovery bypass. It does not restore the database, discard
rows, or claim a failed candidate has rolled back. Ordinary eventual code-only
rollback must keep compatible database/WAL and candidate-window writes; the
native compatibility and recovery contract remains separate work.

The tests simulate commit failure, committed-but-lost acknowledgement,
restart/unknown outcomes at each modeled boundary, out-of-order or unbound
observations and competing admissions. A memory store models the atomic durable
boundary; it does not qualify filesystem durability, actual isolation or native
single-writer custody. Exact control policy, resource limits, egress endpoints,
actuator lock/fence namespace and native reconciliation require owning review
before effects are implemented.
