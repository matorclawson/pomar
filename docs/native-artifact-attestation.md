# Native artifact attestation

sow: pomar-SOW-90

Library source; unqualified and not adopted. The allocated source
base is 2b33e8fbdcd2ef6bb757409cc3be4176bd3469dc. Council reviews the interface
and source together in one PR under the received Architect sequencing decision.

The native proof uses `pomar.native-artifact/v1`, with detached Ed25519 signature
over that UTF-8 context followed by NUL and exact frozen canonical proof bytes.
The existing protected result signer and immutable pinned-directory publication
are reused. Fixed files are `native-artifact.json` and `native-artifact.json.sig`.
Legacy result and closure wires, signature domains and files remain unchanged.
Signature verification alone does not establish policy, current authority,
consumer acceptance or release permission. Consumers independently pin the key,
signing purpose, schema and complete source/input/tool/output policy.

The nine-file slice implements the distinct signature/publication primitives,
closed proof wire, fixed policy and unavailable-by-default collector. No
executable caller, observer, endpoint, key loader or native run is connected.
Synthetic keys and observers used by tests cannot be installed through this API.

`nativeattestation.Policy` is selected by the protected owner and independently
pinned by the consumer. This version supports only `profrod-hetzner-ci/v1`, the
maintained ProfRod `make --no-print-directory hetzner-ci` recipe. The first argv
element must be an absolute, immutable `make` tool pin; it is never ambient PATH.
The repository is `https://github.com/rodriveracom/profrod-site.git`, ref
`refs/heads/main`, with exact clean commit/tree/source-manifest identity. The
fixed inputs are `opportunity-sources.json` and `public-config.json`; the only
artifact is `release.json.gz`. Concrete paths, tool/OS/closure hashes, policy
generation/validity and protected caller/producer identities must be adopted
later. No production values or successful recipe execution are invented here.

The proof binds the original admission, journal, incarnation, command, caller
UID/PID/birth, boot and continuous-clock identity. It records native start/end,
real Wait and positive cleanup observations, complete streams/artifacts, durable
journal evidence and exact policy digest. Wall times and continuous ticks must
remain ordered within the original budget. Only complete exit-zero executions
fit this success wire; missing/failed/uncertain observations cannot claim success.
The policy binds producer principal/role UID, observer version, independently
selected signing-key ID and native signing purpose. Role UID alone does not
establish observation authority or signing-purpose adoption.

`Decode` accepts only the closed canonical JSON encoding, rejecting unknown or
duplicate fields, suffixes, whitespace variants and documents over 64 KiB.
`Verify` checks the original native-domain signature bytes, independently pinned
key, complete expected policy and same original. Signature validity alone does
not select an expected policy. The exact tool, source, input, OS and artifact
identities cannot be taken from the proof to populate that policy.

`NewCollector` snapshots a valid policy and ALWAYS has no observer. Its `Collect`
operation returns `ErrHeld` plus `ErrUnavailable` until separate source/adoption
connects an actual protected observer. There is no public observer-registration
or manifest-import API. Package-private observation/freeze interfaces are the
proposed protected integration contract, not an installed implementation. Tests
use same-package fakes; ordinary actor JSON cannot reach them.

The observer contract authenticates the original and policy before collection,
after validation and immediately after durable freezing. `Observe` only reads
already captured evidence; it cannot start, rerun, re-admit or release a job.
`Freeze` must durably associate exact bytes with the original and return the same
bytes on replay, refusing conflicting evidence. Hashing checks bounded raw
stdout/stderr and every exact artifact. The aggregate return bound includes both
streams, artifacts, proof JSON and detached 64-byte signature. Integration must
also budget its own protocol envelopes, copies, journal and cleanup work; these
library limits are not an installed whole-lifecycle reservation.

Cancellation, revocation, observer/persistence errors, conflicting freeze bytes
and incomplete cleanup return no collected proof. A canceled freeze can leave
durable original evidence; it must remain retained, charged and reconciled rather
than being re-admitted under a new ID. Publication reuses the existing immutable
pair protocol: exact same-original retry can finish a partial pair; changed
bytes or symlinks refuse. It never overwrites existing result/closure evidence.
The protected receiver must recheck actual authority before signing/publication;
this library makes no atomic lifecycle, installed resource-release or key-rotation
claim. Existing native result readers recover frozen bytes separately from
current-validity policy acceptance; expiry is not erased by replay.

A genuine protected observer must authenticate the complete typed observation
against owner-held original admission and durable journals. Required evidence
includes actual start identity, PID birth, executable and worker identity,
registered clock and complete lifetime, native end and real Wait provenance,
complete bounded raw logs, immutable artifact readbacks and positive cleanup.
Ordinary actor JSON, imported logs, an already-built artifact, process absence,
or an injected fixture cannot establish this trust. Unknown or partial evidence
must remain held on the same original with charges retained and no rerun.

The production observer/receiver integration requires its separately pinned
existing-source amendment. The nine-path library allocation does not supply
that integration. Actual signing-purpose adoption, admitted qualification,
protected installation, current readbacks and ProfRod's distinct native consumer
remain required. Native proof must never masquerade as a VM-pinned guest result.
Acceptance is an automatically consumed newly observed native execution after a
real main update, including failure, restart, custody and guarded rollback.
