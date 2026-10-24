# Unqualified WIP backup policy

sow: pomar-SOW-87

Architect msg-architect-architect-wip-backup-push-ruling-20261024 permits own-fork `<seat>/wip/<topic>` backups without the full gate. This is a backup effect, not a publication receipt, release, merge or source approval. Later msg-architect-architect-zeo-rt-open-prs-20261024 separates exact-head own `make verify` before code-PR opening from qualification while that PR is open; it does not fabricate a passing gate.

The hook consumes the complete update stream and rejects malformed/empty data, mixed/tag/delete/foreign refs, unknown owner mapping, changed source, extra destinations, URL rewrite configuration, implicit push refspecs, mirror configuration and non-fast-forward effects. It accepts only named remotes resolving to the accepted matorclawson repository. Existing remote objects must be present locally so ancestry can be proven without fetching. No network, credential acquisition, hook disabling, source mutation or installed adoption occurs in this source change.

Git pre-push reports proposed ref effects, not every original command-line option. The hook constrains all reported effects and rejects mirror configuration; it does not claim to detect an inert `--force` flag on an otherwise fast-forward push. No non-fast-forward/delete/out-of-policy effect is allowed. A Git hook and shared-UID seat labels are advisory local policy, not hostile-user isolation. Accepted repository/owner/source/ref correlation adds constraints beyond environment text; none authenticates a kernel principal. A stronger authentication requirement needs an actual adopted owner port, not a fixture.

Pomar accepts ONLY mailbox zeroemployee, declared role zeo-site-maintainer, matorclawson/pomar, exact refs/heads/zeo-site-maintainer/wip/creator-verification-20261024 and owner-selected H3a36b259ab1cdac8c4c3e56a81cbee077732bfe1, per owner receipt ans_e0e32846c5121f83 and Pomar acceptance ans_401620a808dd686b. Charter a0606767 line32 independently verifies the alias; its historical work repo is not the Pomar source allocation. Other roles/refs/heads require their actual owning acceptance; no generic environment exemption. Ordinary pushes still execute make verify.

Source is NOT_LIVE. Before adoption: actual permitted synthetic/refusal/ancestry controls, ordinary-guard checks, independent owning review and exact hook hash readback are required. The receiver adopts through its supported per-clone route with normal hooks preserved. Then only the actual owner performs the exact permitted backup and remote ref/H readback. No fleet-live claim from a commit or document. Roll back through the receiver to the previous recorded hook bytes; do not disable hooks or change hooksPath to escape a refusal. No tests or hook execution are claimed on the author host.


The complete update stream is captured in private, bounded scratch before any
exception is considered. Capture errors, oversize input, NUL bytes and nonempty
unterminated final records refuse; a valid earlier record cannot hide a suffix.
The input fixture includes allowed-plus-unterminated mixed/tag/delete/malformed
and otherwise-valid suffixes, each partial record alone, and a closed-descriptor
read failure. All of these exercise the actual hook, without a network push.

Configuration queries distinguish success, exit1 (absent), and every other
failure. A present mirror value must be exactly one false value; invalid Boolean
syntax, repeated values, rewrite-query errors and refspec-query errors refuse.
The fixture injects errors only at each actual config query and checks the
specific refusal boundary. Positive missing-config and explicit-false cases
remain required. No query error is treated as evidence that policy is absent.

Required semantic mutants, only after an admitted pristine harness PASS: remove
the partial-record refusal so a valid update plus an ignored suffix is accepted;
then independently treat config-query errors as absence. Each must fail its
intended refusal assertion, with the fixed source passing again. These controls
and mutants have not been executed by this source contribution. Formatting,
source commits and static review are not a harness, mutant or full-gate receipt.


Every refusal case now binds its expected exact closed-hook diagnostic; success
requires the backup-only marker as well as exit0. Ordinary Runtime refusal and
Pomar's fixture make-verify invocation have separate exact boundary assertions.
Deletion is checked before current-source equality so its control reaches the
intended guard. A generic nonzero exit is never sufficient refusal evidence.

After the full pristine suite passes, the harness makes private hook copies for
two exact mutants: remove only the nonempty partial-record guard, or treat the
three config-query errors as absence. Each child must fail the specific accepted
bad-input assertion (valid-then-partial-mixed or config-read-error-rewrite).
Unrelated parse/setup/other-guard failures refuse kill credit. The unchanged
source suite must pass again after each mutant. These fixture-only hook-path
selectors do not exist in the production hook or authorize live installation.
No pristine or mutant result has been executed or accepted from this source edit.


Additional actual-hook fixture cases bind source identity refusals: wrong current
local ref and wrong local object ID in both repositories; allowed Runtime role
with a different source SOW; changed selected Pomar HEAD. Each asserts its exact
closed refusal. Synthetic commit/ref changes stay inside the private fixture,
then restore the original fixture ref before later positive controls. This does
not change the actual accepted owner/source policy or prove live authentication.
