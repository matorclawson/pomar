# Recovering completed results

Execution and publication have separate states. An exited, failed, stopped or
timed-out command is never restarted to repair a missing result.

The manager freezes the exact canonical result bytes, their SHA-256 and the
admission-pinned signing policy in the same fsynced table transaction as the
terminal execution state. Result and signature files are individually staged,
synced and installed without overwriting an existing name, then the record
directory is synced. Identical partial publication can be completed; different
bytes are retained as a conflict. A lost publication acknowledgment can be
reconciled without replacing either file.

On startup and on every poll, including when no job is running, the manager
retries due trusted completion intents. Each pass attempts at most sixteen due
intents. Storage failures and unavailable original signing authority retain the
intent and use persisted delays of 1, 2, 4, 8, 16, 32 and then at most 60 seconds.
Kernel filesystem calls themselves are not interruptible deadlines. Directory
sync and process-interruption tests do not establish physical power-loss
behavior on every storage device.

The existing protected signer signs these frozen manager observations. There is
no imported-manifest signing API. A replacement key cannot sign an intent bound
to the old key. Missing signing authority is a visible `key_unavailable` hold;
there is no unsigned fallback. Nonsigning development managers explicitly pin
an unsigned development policy when they admit a job.

The existing authorized result reader returns:

| HTTP | Meaning |
|---|---|
| 404 | No such execution or no terminal result yet |
| 503 | Trusted publication pending, including original key unavailable; `Retry-After` and safe `reason_code` explain retry eligibility |
| 409 | Conflicting/corrupt evidence or legacy completion without recoverable proof; `retryable` is false |
| 200 | Exact original document, verified required signature and original key ID, or explicitly admitted unsigned development result |

Pending/error replies include `error`, `result_state`, `retryable` and
`reason_code`. Existing class/caller authorization runs before these checks.
The reader verifies actual files even if the table says publication completed.
Legacy signed results can be read under the currently trusted matching public
identity; missing legacy proof is held, never reconstructed from current
configuration. Legacy rotated-key trust enrollment is not introduced here.

Cache eviction and explicit removal retain unresolved completion evidence.
After successful durable publication, the existing record-retention rules apply.
Manual administrator deletion outside the supported APIs cannot be prevented by
this mechanism. Release authorization and deployment receipts remain consumer
responsibilities.

The opened record directory is checked without following its final symlink and
pinned by descriptor; staging, reads and no-overwrite links stay relative to
that descriptor. Table visibility after process restart is not treated as proof
of a successful directory sync: retained completion intent is re-acknowledged
before new publication or a successful modern-result response. A storage refusal
keeps that original pending; it cannot be bypassed by loading the table again.

Final result names must themselves be regular files naming the opened inode.
An in-record symlink is conflicting evidence even when it currently resolves to
identical bytes. The directory-scoped Go API can follow such links; containment
alone is insufficient. The record directory identity check also rejects a
mismatch between the non-following open and the rooted descriptor. Parents of
the configured data root remain trusted host-owned configuration; this slice
does not qualify arbitrary symlinked parent paths or physical power loss.

Adoption requires draining attempts admitted by the previous manager before the
upgrade: an empty legacy admission policy cannot be retroactively pinned.
Legacy unsigned results without an admission-bound policy remain unknown (409).
Do not downgrade while completion intents are unresolved: an older binary does
not preserve the new recovery contract. Publication and admission policy must be
included in the upgrade/rollback compatibility review.


Terminal VM cleanup does not depend on result publication. On completion and
recovery, disposable VM objects are removed even when signing authority is
unavailable or a result is pending, unknown or corrupt. The attempt record,
frozen intent, output and log evidence remain protected. Only nonterminal
execution pins caches whose policy is KeepWhileLive. A failed VM cleanup is
retried and the record cannot be removed while its VM object is still open.
VM removal runs outside the admission/status lock, with the original record
reserved against deletion and same-name reuse until cleanup returns.

Acknowledged published results do not consume the sixteen due-intent retry
budget forever. A restarted manager still validates/acknowledges retained
modern results in bounded passes; until that acknowledgment the reader can
return pending. Every actual reader independently validates the retained bytes.
Table directory-sync failures continue to fail closed, including admission;
source qualification checks its own test filesystem, not the production data
volume or physical power-loss behavior.

These cleanup observations are not a client-verifiable closure receipt. A
signed execution result alone does not certify teardown. A separately reviewed
per-attempt closure statement and receiving policy remain required before a
consumer can rely on explicit cleanup evidence.

## Per-attempt closure (source candidate; not installed)

The separately signed `pomar.closure/v1` document is read at
`GET /v1/attempts/{id}/closure`, with the same attempt/class authorization as
result reads. Its successful wrapper has `closure`, `signature`, and `key_id`.
The closure signature covers ASCII `pomar.closure/v1`, one NUL byte, then
the exact closure JSON bytes. Consumers use `result.VerifyClosure`; raw
`pomar.result/v1` signatures and their wire format remain unchanged. A raw
signature over a closure document is refused.
The exact `pomar.result/v1` document and successful result wrapper are unchanged.
Only the manager assembles closure evidence; there is no manifest-import or
arbitrary-signing endpoint.

New admissions require closure evidence before retention may remove their
records. The helper records successful stop and delete acknowledgments separately
using `pomar.vm-cleanup/v1`. Neither a successful job exit nor a missing pathname
supplies either acknowledgment. Failed stop/delete remains explicit and does not
change the actual job exit. The original pre-deletion disk observation remains
intact. Failures before a container was successfully created provide no invented
positive cleanup acknowledgment.

The manager binds these acknowledgments to the original attempt, helper PID and
birth identity, linked VM-service PID and birth identity, admission pins and
class, original result digest and original public signing identity. It additionally
records the closing manager's version and executable digest, observation time,
identified helper/VM departure observations and the venue's recorded removal of
the owned VM object. This is a narrow VM lifecycle statement, not a claim about
all native descendants, external actions or release authorization. Process
absence alone cannot produce a closure. An unlinked VM or missing original
identity is held, even if the filesystem happens to look empty.

The immutable closure intent is persisted before publication. Recovery signs
only that original intent with its pinned original identity; an unavailable or
rotated key stays held. A complete original proof can be re-acknowledged without
its private key. Storage failures remain pending, conflicting or malformed
proofs return HTTP409, and incomplete/unacknowledged publication returns HTTP503.
Readers check the actual retained bytes and signature. Job execution is never
repeated to repair publication. Unresolved closure evidence is retained alongside
unresolved result evidence; disposable VM storage and live-only caches remain
independent.

Legacy attempts do not gain fabricated retrospective closure records. Their
closure endpoint reports unknown. This candidate requires coordinated adoption
of the qualified Go manager and matching Swift helper, original signing-key
custody, admissions drained for upgrade, preservation of all unresolved intents,
and refusal of an incompatible downgrade. A manager upgrade with an old helper
cannot produce the required acknowledgment and stays held. No candidate has been
installed, and tests/real interruption acceptance must be reported separately.
