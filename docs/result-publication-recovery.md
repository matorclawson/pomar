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
