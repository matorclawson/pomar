# Offline PostgreSQL extension recipe preparation

sow: pomar-SOW-87 rev35 (three-path allocation from rev29)

This is **partial source**: safe input preflight, a fixed build plan and refusal
of native execution while the maintained controller is unbound. It does not build
an artifact. Pomar owns the actual PostgreSQL17.11/OpenSSL3.5.9/pgcrypto/uuid-ossp/
pg_graphql1.6.1 artifact; Runtime Root owns its closed archive/tool/controller/
principal route. There is no alternate fetch client, installer or second manager.

The original immutable design envelope remains16126bytes/SHA256
`0466d82e8a2d8c85c204b757758b4a4c5d38b07fe2f8f0540df109c83b852321`.
Its old0dcbad99 consumer reference is historical. Current consumer and baseline
binding belong to actual receiving, not to this frozen input.

## Current execution boundary

Pomar's direct receiving `ans_aacf44e064b5351e` agrees to this partial shape:
`--build` **always refuses before input/output allocation, extraction, cache copy
or any native child**. The controller identity, lease, start interface, cleanup
receipt and adopted source preimage are all `NO_CURRENT_BINDING_VERIFIED`.
Runtime Root owns the missing interface. An in-process `PreparedExecutable` or
`LookupPin`, a numeric PID/PGID, source-only library, manifest or source review
cannot substitute. No caller-supplied command/token/flag bypass exists.

`--check` inspects received source/tool/runtime/cache inputs without creating an
output directory or invoking a build tool. `--plan` also returns fixed DATA,
labelled `FIXED_SOURCE_BUILD_PLAN_NOT_EXECUTABLE`, with explicit pending controller,
whole-descendant/stream quiescence, linkage, smoke and receipt integration. Neither
mode emits postgres-tools, artifact success, actual version/help or cleanup proof.
The native selector-failure/descendant/TERM/KILL/reap controls remain **deferred**
until the maintained controller is bound; no fake cleanup PASS is claimed.

## Independently adopted Python runtime

Architect `ans_4a38c85fac387c87` accepts existing explicitly pinned direct Python
with standard library only; no third-party module/install/download. Both entry
points use an empty environment and `-I -S -B`. The distinction between isolated
mode and disabling global site initialization is documented by
[Python](https://docs.python.org/3.14/using/cmdline.html#cmdoption-S).

Before Python starts, the shell checks the externally selected executable pin and
an **independently adopted complete runtime SHA256SUMS** file's byte count/hash,
restricts its entries to the selected canonical runtime root, and checks every
listed file. The inventory must include the direct interpreter and all of its
stdlib/dynamic modules/runtime files. The receiver supplies its accepted
completeness/binding: the script does not manufacture adoption by hashing its own
files, infer completeness from a version string, or attest the OS. Same-UID races
are not an isolation boundary. The input's complete Python closure must match
that same root and bootstrap inventory pin before a plan can pass preflight.

Required explicit environment for **both** scripts:

| Variable | Independently selected value |
|---|---|
| `POMAR_RECIPE_PYTHON` | Absolute direct non-symlink existing Python executable |
| `POMAR_RECIPE_PYTHON_SHA256`, `POMAR_RECIPE_PYTHON_BYTES` | Executable hash and length |
| `POMAR_RECIPE_RUNTIME_ROOT` | Canonical adopted complete runtime root |
| `POMAR_RECIPE_RUNTIME_SUMS` | Canonical accepted complete SHA256SUMS file |
| `POMAR_RECIPE_RUNTIME_SUMS_SHA256`, `POMAR_RECIPE_RUNTIME_SUMS_BYTES` | Inventory hash and length |
| `POMAR_RECIPE_WHOLE_SECONDS` | Explicit admitted whole invocation limit, matching the input |

The sums format is lowercase SHA256, whitespace, absolute runtime file path,
one entry per line, no outside-root/traversal path or ambiguous name. The shell
captures entry time **before bootstrap reads**. Python bridges once to one
monotonic deadline; hashing, archive inspection, extraction helpers and plan phases
check the same original deadline. No phase resets it. A backwards bootstrap wall
clock refuses. Blocking OS calls and clock discontinuities still require the
independently adopted **outer** hard envelope: the Python checks are advisory,
not a hard process/syscall cancellation guarantee. Future native integration must
reserve finite cleanup within that same original deadline, never append a fresh
cleanup budget or claim quiescence from direct-child wait.

```sh
# Set the explicit independently accepted environment above, then:
sh tools/build-postgresql-extensions.sh --check \
  --input /owned/reviewed-input.json --input-sha256 INDEPENDENT_INPUT_SHA256 \
  --output /owned/approved-parent/NEW-original --output-parent /owned/approved-parent
```

Use `--plan` for DATA after the same checks. No output path is created. The output
parent must be explicitly adopted, owned0700, and the proposed child fresh and
nonoverlapping with inputs. Paths refuse symlinks, unowned/writable ancestors,
whitespace, colon, comma, quotes and backslash. Existing outputs refuse.

## Proposed private input format

Pomar received the input shape in `ans_10ac1872b55397fb`; implementation findings
required repair, not a new product reader/signing schema. Every field is required;
unknown/duplicate keys, trailing JSON and nonfinite values refuse. A file pin has
exactly `path`, lowercase `sha256`, positive integer `bytes`. The JSON itself is
selected by an external hash, not its own declared expected digest.

| Field | Binding |
|---|---|
| `schema`, `platform`, `owner` | `pomar.postgres-extension-build/v1`, `darwin/arm64`, actual non-root UID |
| `recipe_sha256`, `runtime_sums` | Exact independently reviewed script digest and prebound runtime sums file pin |
| `output`, `output_parent` | Reviewed absolute paths matching CLI; no allocation occurs |
| `frozen_recipe`, `smoke_sql` | Exact0466 envelope and original1519-byte smoke file pin |
| `archives` | Exactly `postgres`, `openssl`, `graphql`, actual received file pins |
| `graphql_commit` | `66d4c551db213000506fd858676269ba8f801a44` |
| `graphql_toml_sha256`, `graphql_lock_sha256` | Actual Root descriptor hashes matching archive members |
| `closures` | Exactly `tools`, `cargo`, `sdk`, `uuid`, `python`; each a pinned closure JSON |
| `tools` | Exactly `rustc`, `cargo`, `cargo-pgrx`, `clang`, `make`, `perl`, `xcrun`, `otool`, `pomar`; direct executable pins inside tools closure |
| `libclang_dir`, `os_identity_sha256` | Actual adopted libclang directory and public SystemVersion.plist hash |
| `jobs` | Actual allocated integer1–32; no CPU-count default |
| `whole_seconds`, `log_bytes`, `disk_bytes` | Explicit integer ceilings: at most7200s,64MiB logs,64GiB output |
| `bootstrap_role` | Explicit reviewed local bootstrap identifier, not a Supabase role profile |

A closure JSON has exactly `root` and sorted complete `files`. File fields match
existing tools-policy inventory: `path`, numeric `mode`, `sha256`, `bytes`, `links`,
or `path`, `mode`, relative `link`. Input caches may contain zero-byte regular
files. All regular/link entries are listed; internal hardlinks require all aliases
and counts. External/dangling links, writable/special/unlisted files refuse.
Cargo credential files and root configuration overrides refuse; a user's Cargo
home is not an offline dependency closure. UUID headers/libraries and actual
linkage are separate explicit inputs; portability is not inferred.

PostgreSQL source is21787224bytes/SHA256
`dd27f2b3c59e73ed14aa3324901242bf69a032a6347805f274e6260322d42979`.
OpenSSL source is53279637bytes/SHA256
`603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a`.
GraphQL archive/lock/tool closure pins remain absent upstream. Nulls, placeholders
or another commit cannot pass. Tar inspection requires fixed version/commit root,
unique canonical members, at most128MiB per member/512MiB aggregate, and refuses
links, devices, FIFOs, set-ID, traversal and file-parent collisions. An actual
approved archive needing a refused member type requires a reviewed source repair.

## Fixed plan and remaining native integration

The DATA sequence preserves the frozen recipe: direct tool version observations,
static OpenSSL build/test/install, coherent new PostgreSQL configure/build/check/
install with OpenSSL and UUID, both contrib modules, then frozen pg_graphql
metadata/init/install against the new pg_config. Planned environment has new
private HOME/TMPDIR/CARGO_HOME/PGRX_HOME, offline Cargo and frozen build flags;
inherited credentials/PG/loader/flag values are absent. Offline flags are not a
network sandbox. Actual worker admission must enforce its custody/network policy.

Plugin argv names the independently pinned **absolute cargo-pgrx directly**, with
`pgrx` as its second argument, matching Cargo's documented external-tool dispatch
[contract](https://doc.rust-lang.org/cargo/reference/external-tools.html#custom-subcommands).
It does not invoke `cargo pgrx` and rely on CARGO_HOME/bin/PATH search. `CARGO`
points back to the selected direct cargo. Actual adopted0.16.1 interface/help
compatibility is still owed before native use; no unsupported `--locked` flag is
added. A digest-different, version-identical shadow cannot replace the selected pin.
Cargo source/lock pre/post checks, SDK/new pg_config readbacks, native linkage and
original complete command/descendant/stream/cleanup observations are **required
future execution integration**, not observed by planning these commands.

The actual builder must eventually inventory the whole new prefix into EXISTING
`pomar.postgres-tools/v1`, retain separate unsigned input/build provenance, and use
existing `pomar postgres run` for the original actual-extension SQL smoke and
positive stop receipt. This source does not emit those artifacts or invent a
release/2 feed, signing purpose, caller token or accepted consumer profile.
A source plan is not a signed result, genuine Supabase Auth/catalog/type parity,
immutable installed prefix, live migration or consumer acceptance.

## Offline source checks

With the same accepted runtime environment and an owned0700 fixture parent:

```sh
POMAR_RECIPE_TEST_ROOT=/owned/approved-test-parent \
sh tools/test-build-postgresql-extensions.sh
```

Synthetic tests cover pin/custody/JSON/archive/inventory refusal, closed planned
environments, exact plugin selection, preflight deadline exhaustion, refusal before
any native build effect and an inert **owned** venv site-startup sentinel with a
positive control. They do not mutate the installed global runtime, install pip,
fetch dependencies or execute a native build/controller. The only fixture subtree
removed is the one newly allocated by this test original. No suite result is
claimed until its actually admitted original finishes.

Each source check requires its actual current Scheduler selection; source approval
does not start a job or renew a consumed grant. Preserve failed originals and exact
source hashes/cleanup. Commit coherent source with DCO sign-off and
`sow: pomar-SOW-87`.

Issued revision35 permits an explicitly **partial source-only review PR** for
these three paths after the complete owning `make verify` passes on the exact
committed candidate in an admitted isolated worker. The existing owner-seat
publication/admission route, hooks, and Council/Architect source review remain.
A focused test is not the complete owning gate. A changed comparison base needs
its own committed-head qualification; historical source-blob results do not
transfer. Do not publish an unqualified code patch through a records carrier.

The native source/tool/controller closure is still required before any actual
artifact build. Source staging does not qualify an execution controller, build
an extension, install a prefix or prove SQL/consumer compatibility. Native
`--build` remains unconditionally refused in this partial increment.
