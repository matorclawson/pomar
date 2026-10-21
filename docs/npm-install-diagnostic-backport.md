# Fresh-install diagnostic backport

This source candidate backports the bounded attempt-progress and install-stall
collectors from main 63af97a01970a96e6cbae1542eb3285e32a7265f onto the installed
service baseline 2195b7f943773049324faf9152e19d529038b6f5. It is diagnostic;
it does not establish or repair the cause of a stalled npm installation.

An authorized client reads the existing GET /v1/attempts/{id} endpoint. Its
optional progress field contains provisional guest-output and registry-event
observations, including source coverage, timestamps, unknown reasons and local
short-delivery evidence. Authorization is unchanged. No additional caller verb,
helper, image, signing identity, dependency or egress change is required.

The collector reads at most 16 KiB of guest log and 256 KiB of registry trace.
The install_stall report is capped at 4 KiB of serialized JSON. Missing, changed,
truncated or unbound observations cannot establish a cause. Registry request
paths use the existing route redaction; error reasons come from a closed set.
These observations are not a signed result or proof that a guest received bytes.

## Observations versus execution behavior

The manager changes add read-only collectors and the response field. The npm
proxy change captures the existing io.Copy return error and expected file size,
and emits send_short for an error or short count. It also represents zero-byte
counts explicitly. It preserves the same io.Copy operation, response status,
Content-Length, cache validation, upstream selection and allowed methods. It
does not add retries, change timeouts, alter package inputs or disable scripts.
Short-write and redaction tests exercise these boundaries separately from the
collector's classification and reader-authorization tests.

## Adoption and acceptance

This branch is a temporary diagnostic candidate, not a separately supported
long-term version. Compared with adopting all current main, it omits unrelated
agent/session, worker and service changes. The receiving owner must review the
actual delta and qualification evidence before choosing this backport or an
organisation-supported newer version. Publication and service adoption are
separate actions; unchanged signed helpers/images/configuration must be bound
in the normal upgrade packet, with the installed baseline checked at adoption.

After adoption, the consumer identifies exactly one new diagnostic execution
with pinned source, lock, command and inputs. It must exercise the failed fresh
locked installation with lifecycle scripts enabled. Retain its complete log,
registry observations, result and evidence of the install step. Link the new
execution to the historical failure without replaying or revising that failure.
A failed attempt is useful if it localizes where progress stops; a successful
cached install alone does not qualify the previously failing fresh path.

The log tail display is bounded to 16 KiB for its serialized JSON string value,
including quotes, control-character escaping and HTML escaping. It retains a
valid UTF-8 suffix. The optional `tail_text_truncated` flag reports additional
display truncation; `tail_offset`, `tail_bytes` and `window_truncated` continue
to describe the raw read window. Complete logs, phase classification and signed
results are unaffected. This is a diagnostic bound, not an npm failure repair.

The unattended source gate uses the already-qualified file-key unit fixture
from the finalizer source: it calls the file-key primitive in private temporary
storage and verifies mode, reload and signature behavior. It does not invoke
the aggregate platform probe. Secure Enclave and keychain observations remain
the separate explicit B2 operation; scratch HOME alone is not a keychain fence.
