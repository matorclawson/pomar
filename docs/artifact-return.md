# Explicit artifact output and verified receiving

An artifact class is an explicit protected configuration. Ordinary reports keep
their historical 64 MiB ceiling and inputs keep their 32 MiB/16-file limits.
No default class gains artifact permission. An opted-in class specifies
`artifact_output` with `per_file_bytes`, `max_files`, `transfer_seconds`, a
closed `names` list, and provisional or measured sizing. The aggregate is
`output_cap_bytes`, at most 1 GiB; count is at most16 and transfer time600s.
The JSON profile file must be root-owned, regular, single-link and not writable
by group or others. It also fixes a nonroot job, command, source mirror/ref;
artifact starts require an explicit Git source and the exact output-name set.
This initial mode uses only the pinned image and source; per-run input files
are refused rather than accepted without an independent input binding.
These settings do not grant permission to install, adopt a class or start a job.

Provisional limits cannot claim a measurement. A measured policy records
`measured_bytes`, `margin_bytes`, `measurement_attempt` and
`measurement_result_sha256`; measured bytes plus margin must equal the chosen
aggregate. The retained class and signed result bind the actual limits and
output count, not caller-selected limits.

The helper uses a separate framed regular-file export. It never invokes the
library's archive-aware copy-out for artifact mode. The release-pinned static Go shim
opens an anchored, nonsymlink, single-link job-owned regular leaf and hashes
bounded bytes twice. The host verifies the fixed name, length, SHA256 and
completion frame, with exclusive files and one shared deadline/aggregate.
Writer errors are retained and explicitly checked because the pinned library
can log them without propagating them. Deadline checks bound writes and
acceptance; stop/delete acknowledgement remains necessary even after an export
failure, and dependency teardown can outlive that deadline. Failure retains
private partial evidence. The manager records a failed artifact set and serves
none of its files unless the original job and every declared artifact succeed.

## Receiving a whole set

`pomar attempt artifact-set -id ID -binding FILE -public-key BASE64 -out-dir DIR`
uses the existing selected manager socket. `DIR` must already be a private
receiving directory belonging to the invoking user, with no group/other
permissions. It is not created or chmodded automatically. The binding file
is bounded to64 KiB, regular, single-link, owner-controlled and not writable
by group/others. It is a closed flat JSON object with **every** field explicit:

- `schema`: `pomar.artifact-binding/v1`;
- `attempt`, `class`, `caller_uid`, `mirror`, `ref`, `source_sha`;
- `source_git`, `readonly_source`;
- `image_digest`, `package_set`, `rootfs_sha256`;
- `command_sha256`, `policy_sha256`, `key_id`.

Pins and public key come independently from the reviewed request/handoff,
never from the returned result being checked. `policy_sha256` is the exported
`artifactreturn.PolicyDigest` of the expected policy and aggregate. Unknown,
case-alias, duplicate, missing or null binding fields are refused. A missing
signed caller is unknown and cannot alias an explicit root caller.

The client fetches original result bytes with a60s control bound and2 MiB size
ceiling, checks the original Ed25519 signature and independent tuple, then
fetches only the signed closed set. Redirects and mismatched response lengths
or hashes are refused. The legacy `attempt output` remains separate and is not
independent acceptance of a whole artifact set. Argument errors return2,
operational/verification failures1, and only full successful receiving returns0
with a JSON receipt containing the original attempt and staged path.

`Receive` checks free space against the full class ceiling, creates a one-use
private stage and syncs the original-result file, staging namespace and parent
namespace **before** any fetch. Sync failure refuses transfer and retains the
uncertain claim. Later failures preserve that durable claim, never unlink it
to make the same attempt reusable. Each fragment is checked before disk writes.
Only a nil return after all hashes/files/directories/final deadline checks is
acceptance; no on-disk success marker exists. Never scan staged paths to infer
success. Reconcile a lost acknowledgement against retained original state.
The receiving parent must persist across restarts; preserve the claim through
the eventual consuming transaction. Free-space preflight is not a reservation.
Private ownership does not protect against a hostile process with the same UID.

## Qualification boundary

Source/unit checks do not establish an adopted image/class or successful native
transfer. The release-pinned static Linux ARM64 shim is required for the
fixed exporter, and its digest is recorded in admission and result pins. Actual guest export, loader/tool
availability, full App build, measured sizing, source release and privileged
adoption remain separate checks. A catalogue entry, offline layer and fixed App
build entry are not supplied by this transport change. It switches no serving
application and changes no credentials or permanent service automatically.

Artifact helpers use the versioned `artifact-helper-v1` command. An older helper
refuses that unknown command before starting a VM instead of ignoring new limit
flags. The current helper requires artifact limits for that command and refuses
artifact mode under the legacy `helper` command. Reconciliation recognizes both
verbs; ordinary classes keep the legacy transport. Adopt the manager, helper and
static shim together through the release path.

The receiver checks cancellation again immediately after every payload read,
before writing a returned fragment. Bytes returned by a cancellation-unblocked
reader are discarded, including bytes accompanied by EOF or another error;
the original attempt claim and evidence remain retained for reconciliation.
