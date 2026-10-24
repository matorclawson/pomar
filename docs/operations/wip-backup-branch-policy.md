# Own-fork WIP backup policy

Controlling owner: Architect `ans_647a2c18bcee56a6` (2026-10-24), allocated
by Pomar87 rev17. This supersedes the former per-repository/source-SOW rows,
six-Runtime-role exemption, multiupdate exemption and Pomar3a36-only intent.

The existing hook carries exactly the first-column seat names below, from
`seat-charters-architect-v1-20261024.tsv` (3429 bytes, SHA256
`f3b1f17211b5240ecfe75a0079f18a6a35092b1b050be5ca6d33289ca87ac694`).
`owners-v1-20261024.tsv` (4405 bytes, SHA256
`6789e20de96b2626b190a54782bfeb4ee7264404351a44e53ea7dcd86d6cdb7e`)
has the same 43 names. Both are Architect-owned inventory files under
`/Volumes/ZeoWork/zeo-evidence/architect/inventory`. No runtime fetch,
configurable store, extra policy artifact or per-seat repository inference.
Mailbox alias equals the seat name. These shared-UID correlations are attribution,
not OS authentication or isolation.

Exactly ONE update is eligible: local current symbolic branch and destination
are the SAME `refs/heads/<seat>/wip/<topic>`, the declared mailbox seat is in the
literal list, and the pushed commit is reachable from that local branch.
Destination must resolve to exactly one GitHub `matorclawson/<repository>` fork
URL, via canonical `git@github.com:` or `https://github.com/` spelling, with
optional `.git`. Upstream organizations, URL credentials/query/port/extra path,
rewrites, mirror/refspec expansion, multiple push URLs, second updates, deletion,
non-FF, unavailable ancestry, malformed/truncated/unreadable/NUL/oversize input,
unknown aliases and detached/mismatched source refuse. There is no table-repo
or source-SOW eligibility restriction. Preserve ordinary repository guards.
Git pre-push does not expose an inert `--force` flag: enforce observable FF-only
effects, never claim detection of every force invocation.

Supplied owner intent: `zeoarchitect`, `matorclawson/zero-employee`,
`refs/heads/zeoarchitect/wip/commitments-stack`, source full H
`f4e371780d77b40d67c841fdbb9fd6a8349c53d4`, `zeoarchitect-SOW-15`.
This is policy DATA, not a successful backup. Backup branches never open PRs,
merge or qualify releases. Normal publication and full gates remain owed.

Literal seat matrix (the harness exercises every name plus unknown-seat refusal):

- `dt-animated-comics-maintainer`
- `dt-comic-slides-maintainer`
- `dt-hud-maintainer`
- `dt-library`
- `dt-proofreader`
- `dt-x-capture-maintainer`
- `ducktyper`
- `ducktyper-ops`
- `pomar`
- `pomar-cc`
- `pomar-guest`
- `profrod`
- `profrod-ops`
- `profrod-site-design`
- `rasa`
- `rasa-ops`
- `rasa-bench`
- `zbs`
- `zeo-ledger`
- `zeo-rt`
- `zeo-rt-ledger`
- `zeo-rt-pr`
- `zeo-rt-review`
- `zeo-rt-sched`
- `zeo-rt-seats`
- `zeoagenda-maintainer`
- `zeoapp`
- `zeoarchitect`
- `zeoconnect`
- `zeoconnect-integrations`
- `zeoconnect-ops`
- `zeoconnect-tools`
- `zeoconnect-ui`
- `zeocontrolling`
- `zeocore`
- `zeocouncil`
- `zeocreator`
- `zeofetch`
- `zeointegrations`
- `zeomessenger`
- `zeonewsroom`
- `zeoreviewer`
- `zeroemployee`

Qualification requires exact-source pristine/refusal tests and intended EOF,
config-error and unknown-seat mutants with restored-source passes. Existing
legacy no-argument refusal (Runtime) or ordinary `make verify` (Pomar) remains.
The harness runs the actual hook in private Git fixtures, without network pushes,
credentials or live installation. Candidate execution requires a route satisfying
CURRENT instructions; proposed instruction text cannot bootstrap its own gate.
Old c082/27b11 receipts do not qualify this successor. Full gate/review/normal
publication precede adoption.

Only the owning repository maintainer adopts its own clones: Runtime for
zeoruntime, Pomar for pomar. No arbitrary fork installation follows. Before LIVE,
record adopted hook/policy hashes, prior bytes and rollback hash/readback,
qualified exact source, adopter and owner remote backup ref equal to intended
full H. Rollback restores recorded prior bytes only after checking current
postimages, preserving ordinary guards. No fleet/credential/service changes.
Until this supported adoption and readback occur, NOT LIVE; retain ZeoWork git
bundles. The 16:00Z target is not a completed or guaranteed deployment.

## Council C2/C3 carried from Architect 13:01

A topic is exactly `[a-z0-9][a-z0-9-]{0,63}`: one component of 1..64
characters. Slash, underscore, uppercase, leading hyphen and overlong topics
refuse. The harness includes lower/upper length positives and the corresponding
refusals. Destination, unknown seat, non-FF, deletion, second-update and topic
semantic mutants must each fail their intended bad-input-acceptance assertion,
then the fixed source must pass; unrelated setup failures are not kill credit.
The deletion mutant models incorrect normalization of a delete OID into HEAD;
other mutants remove the relevant refusal. Existing EOF/config mutants remain.
All these controls remain AUTHORED, NOT_RUN until permitted execution.

The next owning SOW done_when must require actual LIVE backup proof: owner
remote WIP ref equals exact intended full H. Adoption, documentation merge,
source agreement or a gate alone cannot satisfy this criterion.

## Git hook environment containment

After resolving and entering the source root, the hook obtains variable names
from `git rev-parse --local-env-vars` and unsets all of them before descendant
tools or the ordinary gate. This prevents inherited `GIT_DIR`, `GIT_WORK_TREE`,
`GIT_COMMON_DIR` and `GIT_INDEX_FILE` from redirecting foreign fixture operations
into the source repository. Failure to enumerate names refuses the operation.
The harness covers a plain clone and linked worktree, requires a separate
fixture administrative directory and unchanged source HEAD, refs, index and
configuration, and removes sanitization for an intended-failure mutant followed
by a pristine restored control. Authored controls require actual qualification;
source inspection alone does not establish that they passed.
