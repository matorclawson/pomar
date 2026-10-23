# Private release executor: source contracts, not activation

sow: pomar-SOW-87

This unreleased increment adds the closed private-release adapter models and
recovery state machine. It does not install a runner, sign or publish anything,
activate a repository, or provide a live executor. The entry accepts only
protected-config/event path options and returns held without opening them while
the actual owner-installed providers are unavailable. There is no manual
version, commit, build, shell, service or deployment option.

## Responsibility and authority

Runtime owns job identity, admission, placement, attempts, authority and the
accepted-result store's fencing compare-and-set. Pomar prepares, launches,
supervises, checkpoints and stops on the host through its existing worker.
Several attempts may compute; only the authorised attempt commits at Runtime's
store. This package's journal CAS protects local release-intent transitions; it
does not create a second accepted-result authority or worker.

Ordinary build/test jobs have no push, sign, publish or deploy privilege. Each
release effect requires its separately adopted fixed profile. The shared
component remains Zeocore's unchanged version/tag/changelog/event implementation;
Pomar creates the approved annotated tag and owns the private signing/feed path.
The engine's installed identity adapter and separate consumer remain their
owners' work. Reserved definitions and the operator veto are unchanged.

## Closed configuration and observations

`ParseConfig` validates the adapter's own versioned config against an independent
protected byte pin. It rejects missing/null/duplicate/unknown fields and Go
case-fold aliases, unpinned component/trust/profile/feed/consumer/authority data,
unsupported index/platform and absent bounds. Parsing and hash equality are not
authentication or section 6.2 activation. `Authority.CheckConfig` must establish
those against the actual protected owner bindings, including expiry and current
claims. The current engine proposal is deliberately not a valid adopted config.

The only execution input is an authenticated observed gold-main move with exact
repository/commit/tree and public provenance evidence. The owner verifier must
accept a captured main tip or legitimate ancestor, reject nonmain/forged events,
and bind current authority. Event labels, a caller boolean or an equal hash are
insufficient. Process repository events in order; a held original suspends later
events. Actor turns and arbitrary shell are never result-cacheable; identity
hashes here do not claim reproducibility or permission for a cache.

## Original intent and interrupted effects

The fixed stages are plan, tag, build, sign, shared-event generation, payload
seal, publish and consumer. There is no version computation in this adapter.
The journal must durably reserve the same original and persist an in-flight
intent before an effect. Every completion requires independent receipt
verification and a durable CAS transition. Partial/lost execution or persistence
holds; no exception text, credentials or provider conversation is stored as a
receipt. Duplicate delivery never directly executes an in-flight effect.

`Reconcile` requires explicit recovery authority and checks only that same
original. It advances only a positively verified completed effect. Unknown,
failed and even not-started results stay held for a separately authorised
disposition; there is no automatic replay, new ID, version reroll or claim
release. Recovery authority must include the rule's suspension/renewed-activation
conditions. A real durable journal and repository-order implementation are
required injected providers, not supplied by the in-memory test fixture.

## Signature and installed inventory

The outer receipt preserves the exact shared event and canonical payload bytes.
It does not define a second shared-event schema, canonicalise them, or create a
signature algorithm/service. The owning verifier must authenticate the frozen
shared payload, its exact fields/exclusions, approved signer/trust/receipt chain,
and actual gold-main observation. A rehashed altered payload must refuse.

Sign runnable/bundle bytes first; generate the event against final post-sign
artifact/member inventory; authenticate the canonical release payload after
that, with signature/digest outside the bytes they cover. The same existing
producer must supply the accepted payload-seal/verification contract. Signed Node
alone, pre-sign staging hashes, a branch label or a digest are insufficient.

The inventory validator bounds entry count/expanded bytes, checks complete
parent directories, modes, UTF-8/control/path traversal, Unicode SimpleFold
aliases and basic link confinement. Actual content verification must independently
walk the relocated final bytes, reject filesystem-normalisation aliases and
enforce the producer's stricter framework/code/link rules. Metadata validation
is not a filesystem or code-signature proof. Unsupported/missing verifiers hold.

## Qualification and receiving

Synthetic tests cover strict positives/refusals, same-original lost-response and
failed-persistence recovery, no side effects before durable intent, no unknown
replay, accepted main ancestors, original retarget refusal, unchanged shared
bytes, rehashed tampering, wrong/missing authenticity/content and unsafe inventory.
They do not establish actual signature, durable host recovery or live consumer
acceptance. No author-host compiler/test/formatter was run to prepare this source.

Before real invocation: receive the exact reviewed gold component/interface,
adopt the protected profiles and durable journal, establish whole setup-through-
WaitEOF/cleanup/return bounds and resource reservation, qualify the exact source
and signed bytes independently, and read back every section 6.2 prerequisite.
The host needs observed power/FileVault/mount/network/credential recovery before
post-reboot availability; LaunchDaemon installation alone is not that proof.
Actual job interruption must yield one accepted result with stale attempts
rejected by Runtime's store. Actor/workspace transfer is a separate scenario and
does not change registry seat occupancy or infer a storage owner.

## Received shared component at the merged source

The first reviewed source binding is `zeroemployeeorg/zeocore` merge
`cce868d77b30298344e730087dcee65c2ba4ac12` (PR182). Direct source retrieval
established these unchanged component bytes:

| Path | Bytes | SHA256 |
| --- | ---: | --- |
| `.github/release/plan.py` | 5795 | `a239d4f76e1f79f32ee16608368cd6206589d4d40a6398224edace014668fb59` |
| `.github/release/event.py` | 3772 | `d994c9c921079f96d6564ca1d1e75dc2b15c6b17f2ba030167733d83121da9b7` |
| `.github/release/README.md` | 4605 | `beae47fc494234e238fdf745750ef915c697c56e871f4597700dd2f084a6d1a3` |

These are source readbacks, not an executed component compatibility result or
protected config adoption. The eventual component binding must cover its exact
file inventory; a commit identifier alone cannot replace byte verification.

The plan provider runs the pinned `plan.py` from a fresh exact merged repository
checkout with all tags, `TAG_PREFIX=engine/v` and `INDEX=none` for the private
non-package engine. It consumes the `version=`, `floor=` and `tag=` output and
notes file without independently computing a version. The allowed prefix is
`v` or one lower-case name followed by `/v`, matching the merged planner.
Pomar creates the annotated tag; the planner does not. Same-commit reruns and
tag-at-another-commit refusals remain the shared component's decisions. A failed
release still suspends subsequent releases under section 6.4.

After runnable signing and final byte inventory, the event provider invokes the
unchanged pinned `event.py TAG NOTES ARTIFACT_DIR --repository REPOSITORY
--detached DIR`. The repository value must be the adopted gold identity, never
an authenticated origin URL. It receives stdout event bytes and the exact
`release-event.payload.json` and `release-event.sha256` files. The shared
canonical payload excludes only `event_sha256`; its producer uses sorted keys
and no spaces. The adapter does not reimplement that encoding. A detached
signature remains outside the payload and needs the actual existing producer's
verification contract. The event's file list is not by itself a complete tree,
mode, symlink or code-signature proof: the separate final inventory and existing
producer's stricter rules remain mandatory.

This source increment provides injectable closed contracts and transition logic.
The command remains held until the actual durable journal, protected authority,
component runner, signer/verifier, feed and consumer providers are implemented,
qualified and adopted. It is not an operational release executor yet.
