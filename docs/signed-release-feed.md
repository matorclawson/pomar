# Signed release feed custody (source preparation)

`pomar-feed-key` is the designated ENG-UK-0006 fixed custodian program. Its
production configuration is UID/GID530, key home `/Library/Application Support/pomar-feed`,
production key id `pomar-feed-a-202611`. It has no path, identity, seed, raw-header
or arbitrary signing flags. An exact binary review and the separate operator-installed
root-owned binary/fixed-verbs route are required before operational use. Source
qualification, account creation, custody and production trust adoption are distinct.

Fixed operations: `self-test-public`, `probe`, `generate`, `public`,
`generate-rehearsal`, `public-rehearsal`, `issue-current`, `issue-rehearsal`,
`publish-trust`. Core dumps are disabled. Generate is once-only; entropy failure,
partial state and uncertain predecessors preserve their original intent and refuse
fresh execution. Private seeds are never output. Public readback verifies seed/public
binding inside the custodian. No login shell or generic impersonation route is part
of this program.

The rehearsal uses a different key (`pomar-feed-rehearsal-a-202611`) in the fixed
0700 `rehearsal/` child of the key home. It is never exported into production trust.
Its completed entries go only into `/Users/Shared/pomar-feed/rehearsal/`, which Ops'
production pull must not read. Sequence140 /0.1.140 is a rehearsal; the first
production policy must name the real PR326-bearing successor, sequence greater
than140. The command's numerical floor does not prove a release contains PR326:
the protected policy owner must independently bind that source qualification.

`pomar-feed-observe` reads an explicitly named actual release/1 artifact directory
and the independently received source head/tree/owner-message. It validates artifact
length/hash and checksum inventory and emits `pomar.release-artifact-observation/v1`.
The receipt explicitly has `build_qualification=false` and
`deployment_independently_observed=false`. It is not a CI result or signing grant.
Later release schemas require separate admission; this increment refuses them.

The issuer reads only the fixed root-owned policies
`/Library/Application Support/pomar-feed-policy/current.json` or `rehearsal.json`.
Their parent must be real0755, leaf real0644, root-owned and ACL-free. The closed
wrapper has `policy` (schema `pomar.feed-issuance-policy/v1`) and
`inputs_directory`. Policy binds purpose, typed21-field claims, real public-key
SHA256, exact artifact/receipt hashes, target/profile/current generations and an
explicit `successor_due_at`. These are adopted policy values, never guessed from
an artifact or fabricated from a missing CI receipt. The input directory contains
the exact four release files plus exact `receipt.json`; it supplies no authority.

A durable whole-issuer lock and monotonically advancing per-sequence intent precede
any signing-key read/signature. Signature bytes are durably retained before publish;
all unknown/failed states remain held for original-operation reconciliation.
Completed sequences can never be reused for different bytes. Expiry is enforced:
issuance requires now before expires_at and a future successor_due_at no later than
expiry. Ops'300-second reader skew does not permit the producer to issue stale data.

Production output is `/Users/Shared/pomar-feed/entries/<sequence:06d>-<commit12>/`.
Before every publication the fixed root, entries, trust and rehearsal directories
must be real0755, owned by root or530 and ACL-free. The publisher holds a durable
exclusive global lock in that custodian-controlled root, writes/fsyncs an exclusive
pending directory, atomically renames only to an observed-absent destination and
verifies every published byte. Only the fixed issuer writes this namespace; an
administrator's mutation requires reconciliation. Partial or unknown publication
retains the lock and pending evidence. Nothing overwrites an existing entry.

`publish-trust` exports only the production public key into the closed consumer
schema `zeoconnect.pomar-feed-trust/v1`, writes it completely then installs via
exclusive hard link, syncs and reads it back. Its output gives exact public key,
key id and trust-file SHA256, with `production_trust_adopted=false`. The Council
must read the fingerprint before Ops copies the trust once and pins its hash.
The trust anchor is never automatically pulled. Ops' add-only regular-file SSH
pull into its private Mini feed directory and the replay-fenced consumer switch
remain separately reviewed owner operations.

Tests contain published/deterministic PUBLIC TEST-ONLY keys, never operational keys.
Three accepted Connect5beb6146 attestations are reproduced byte for byte with the
same transcript constructor used by the typed producer. Focused checks cover
mutation refusals, true byte observation, key/receipt/purpose policy binding,
expiry/successor windows, replay custody, rehearsal isolation, unsafe namespace
refusal and immutable original publication. A full committed-tree make verify is
still required before public source push and operational binary adoption.
