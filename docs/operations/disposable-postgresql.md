# Disposable PostgreSQL for local gates

sow: pomar-SOW-87 rev27 (seven-path source grant in revisions22/23).

This is source for an ordinary-account local helper. It is not installed or
adopted by this document. It creates a fresh PostgreSQL17 cluster for one gate,
using a caller-selected, independently pinned tool manifest. It does not start a
host service, use Docker, allocate a Runtime job, download software or connect to
an existing database. Shared-account processes are not isolated from each other
by an OS security boundary.

## Invocation

```sh
pomar postgres run \
  -work-root /owned/private/work \
  -tools /owned/approved-postgres-tools.json \
  -tools-sha256 APPROVED_MANIFEST_SHA256 \
  -cwd /owned/consumer-checkout \
  -whole 5m -startup 30s -stop 10s -log-bytes 8388608 \
  -extension uuid-ossp@1.1 \
  -env PATH=/approved/node/bin:/usr/bin:/bin \
  -- /absolute/path/to/gate arg
```

Flags precede the gate; the gate executable must be absolute. The existing work
root must belong to the calling non-root UID and have mode0700. Paths must have
no symlink or group/other-writable ancestors; ancestors may belong to root or the
caller. The gate directory must already exist and belong to the caller. Socket
roots containing whitespace, comma, quote or backslash are refused, as are Unix
socket paths reaching104 bytes. A short owned work root may be needed.

Each invocation uses a new exclusive `pg-*` directory. The helper records and
syncs intent, tool identities and paths before starting initialization, then
syncs the containing work directory. PostgreSQL runs in the foreground under the
same UID with `listen_addresses` empty and private0700 Unix sockets. Readiness
queries check both no TCP address and the empty listening-address setting.

`-extension NAME@VERSION` is repeatable. Missing pinned control/version SQL files
refuse before cluster creation; actual extension creation must also succeed.
`-role-profile NAME` selects an explicitly reviewed SQL file already named in the
pinned manifest. There are no implicit Supabase roles, guessed BYPASSRLS grants,
authentication service, schema parity, extension stub or migration shortcut.
The manifest explicitly selects the cluster bootstrap role. `initdb` necessarily
creates its local bootstrap superuser; that role is not an application role or
an operational service credential.

The child receives a new private HOME/TMPDIR and fixed Unix-socket PG variables,
with password/service files disabled. No parent environment is inherited.
Explicit `-env` permits only PATH, LANG, LC_ALL, TZ and CI. Database URLs,
PGHOST/PGSERVICE overrides, credentials, alternate HOME and dynamic-loader
variables are not accepted by this interface. Gate code still runs as its caller
and must follow its own source/tool/credential policy; this wrapper is not a
sandbox or a signed execution observer.

## Independently selected tool manifest

### Fixed disposable Vault fixture (source; not installed or qualified here)

An independently selected tools manifest may explicitly set
`"fixture_profile": "supabase-vault-0.3.1"` for PostgreSQL **17.11**. Omission
keeps the ordinary no-preload behavior. Unknown profiles refuse. The caller must
also request `-extension supabase_vault@0.3.1`; a manifest profile alone does not
start or enable it. There is no caller-supplied preload list, command or GUC.

The full prefix inventory must contain regular pinned `lib/supabase_vault.so`,
the fixed-version/schema/module control file, `supabase_vault--0.3.0.sql` and
`supabase_vault--0.3.0--0.3.1.sql`. Genuine upstream0.3.1 installs through that
SQL upgrade chain, not an invented0.3.1 base SQL file. Native sodium/crypto link
closure, actual extension versions and real SQL must still be qualified; file
presence or a synthetic test is not that qualification. This profile does not
create pgcrypto in a guessed schema: the consuming gate creates it in its
reviewed `extensions` schema using the genuine pinned prefix.

For this profile only, the helper durably records nonsecret fixture intent,
then generates32 cryptographically random synthetic bytes for each new cluster.
The64-hex protocol is stored in a private0600 file, served by one fixed0700
getkey script inside that original's owned0700 directory. Because upstream uses
`popen`, only canonical paths composed of ASCII letters, digits, `/`, `_`, `-`
and `.` are accepted. Neither the key nor its digest is placed in public
metadata, logs or environment. The script invokes only `/bin/cat` with the
internally constructed key path; no external key service or production key is
read. The server starts with exactly `shared_preload_libraries=supabase_vault`
and this internally constructed `vault.getkey_script`. Plain clusters retain
their previous argument list.

Original server shutdown, stream handling, absent custody markers and unchanged
directory identity must be confirmed before the exact original key/helper files
are unlinked and the directory is synced. File identity, bytes, modes, ownership
and single-link custody are rechecked. A changed path, failed write/sync/removal
or uncertain shutdown prevents a clean result. Private original state is then
held for supported owner reconciliation; it is never reused by a later cluster.
A successful key cleanup retains the ordinary nonsecret evidence/data root.
Deletion is unlinking, not a promise of physical-media erasure. Shared-account
processes still are not an OS isolation boundary.

`POMAR_POSTGRES_VAULT_TEST_MANIFEST` and its separate `_SHA256` select the
opt-in real Vault encryption/decryption/pgcrypto/cleanup test. Without both it
skips; ordinary tests do not infer native tool authority. Executed native smoke,
the consumer's complete migrations/four assertions, independent lifecycle review
and actual Scheduler admission remain required. No service, installed release
or consumer result follows from these source changes.

The JSON schema is `pomar.postgres-tools/v1`. The separate manifest SHA256 is
mandatory; an input cannot select its own expected hash. Unknown/duplicate keys,
trailing documents, a wrong host version or an incomplete closure refuse.

Required fields:

| Field | Binding |
|---|---|
| `version` | Exact PostgreSQL17 package version |
| `platform` | Exact `darwin/arm64`, or the admitted host's GOOS/GOARCH |
| `os_identity_sha256` | Hash of the public SystemVersion.plist on Darwin or /etc/os-release on Linux |
| `source_sha256` | Reviewed exact source package digest |
| `prefix`, `owner` | Canonical owned tool prefix and actual caller UID |
| `bootstrap_role` | Explicit local bootstrap role, not an inferred Supabase identity |
| `files` | Every regular file and symlink in the prefix, no unlisted files |
| `role_profiles` | Optional reviewed name to a pinned relative SQL path |

Each regular-file pin contains `path`, `sha256`, `bytes`, numeric permission
`mode`, and optional `links` (default1). Each symlink pin contains `path`, `mode`
and exact relative `link`. Links cannot escape the prefix. Normal PostgreSQL
zoneinfo packages use internal hardlinks: their expected link counts must be
pinned, and **every alias** must be inventoried inside the prefix. A count change
or any external alias refuses. Devices/FIFOs, writable files/directories,
foreign owners, unknown entries and changed bytes refuse. Required executable
pins are `bin/initdb`, `bin/postgres` and `bin/psql`; the inventory also covers all
libraries, share files, extension SQL/control files and headers. Owner-writable
prefixes are checked before/after use, not represented as OS-immutable storage.
A version-file hash is not a complete operating-system attestation.

The earlier17.11+uuid tool manifest has a different evidence schema; it is not
silently accepted as this caller policy. Its bytes remain unchanged. A receiving
owner must independently freeze the full new manifest and approve the exact
package/host/consumer binding. New OpenSSL, Rust/pgrx or pg_graphql inputs need
their actual source/checksum disposition before build or installation. Building
pgcrypto/GraphQL does not establish a genuine Supabase Auth/role/migration
baseline. That maintained migration/materialization contract remains separate.

## Completion, deadlines and uncertain custody

The whole clock starts before manifest verification. Initialization/readiness
have bounded stage contexts; a shutdown reserve is withheld from gate time.
Regular-file syscalls and an OS process stuck in uninterruptible IO cannot be
turned into a kernel-enforced wall-time guarantee by Go contexts. A forced kill
or exceeded shutdown/stream deadline therefore remains uncertain, never a clean
cluster result or permission to refund unrelated resource claims.

Server logs, gate stdout and gate stderr share the requested aggregate byte
budget in three bounded portions. Overflow cancels execution and prevents a
complete-success result. Outputs are retained as files, not copied unboundedly
into JSON. Each lifecycle intent is exclusive and fsynced; partial/existing
intent files are not overwritten or treated as absent.

The wrapper handles cancellation by stopping the exact child obtained from
`Start`, not a process reconstructed from a saved PID. It waits for PostgreSQL's
exit and output handling and requires its socket/lock/PID markers to be absent.
A kill, wait/stream failure, retained marker or uninspectable path prevents
confirmed cleanup. Killing only the postmaster does not prove its descendants
are gone. Gate exit and cleanup outcomes remain separate in `result.json` and
the final JSON stdout; a nonzero gate or any infrastructure/persistence/cleanup
failure gives CLI exit1. Argument/flag errors give2. This command does not use or
change the existing attempt-loop job exit protocol.

All invocation data and evidence are retained, including after a successful
shutdown. There is no resume, reuse, automatic deletion, scan-and-kill or
PID-based recovery operation. After SIGKILL or incomplete persistence, the
installed owner must obtain a supported owner/birth-bound custody disposition
before acting on old state. Running a new cluster is not reconciliation of an
old one. Retention/disk budgets remain the caller's responsibility; no host
allocator or managed backup service is installed here.

## Qualification and receiving

Ordinary package tests check closure mutation/omission/links, explicit clean
environment, bounded streams, exclusive persistence, missing-extension refusal
and a synthetic uncooperative shutdown. Opt-in real tests require the actual
`POMAR_POSTGRES_TEST_MANIFEST` and its independently selected
`POMAR_POSTGRES_TEST_MANIFEST_SHA256`; they perform no downloads. They exercise
concurrent clusters, actual UUID extension/no-TCP queries, gate failure and
cancellation with separate positive shutdown evidence. Test fixtures are not
production policy or consumer adoption.

`pomar help all` includes the usage line. The curated everyday/JSON help inventory
has not been expanded by the seven-path grant; this explicit command and this
operation document are the current source entry points. Any required additional
help metadata path needs a specific amendment, not an unrelated edit.

Full exact-head repository gate, Council/Architect review, normal integration,
actual qualification on each admitted host and one real Clipping consumer receipt
are separate acceptance steps. A completed Clipping original must not be replayed
just to refresh a report. Managed Hetzner PostgreSQL is a later design increment;
no database cutover, production access, service activation or signing-authority
change follows from this source.
