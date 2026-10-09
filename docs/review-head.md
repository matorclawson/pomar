# Exact-head technical review

Open implementation PRs from `pomar-codex/…` or `pomar-cc/…` branches. The
fixed PR head ref declares the seat and the body must match it on one unquoted
line, for example `Implementation-Seat: POMAR-Codex`. Changing only the body
cannot flip the reviewer. Older branches need a new correctly named PR before
this policy can pass; no existing PR is silently grandfathered.

The other seat publishes a **new, unedited issue comment** with these lines:

```text
Reviewing-Seat: POMAR-CC
Reviewed-Head: 0123456789abcdef0123456789abcdef01234567
Review-Verdict: no-blocker
```

Use `blocked` to withhold or withdraw approval. Every new head needs a new review.
Declarations are ordered by creation time, then comment ID. A malformed latest
declaration refuses. An edited publisher comment is void even after all its
markers are removed; conservatively this includes unrelated edited comments.
Only a newer explicit, unedited review resolves it. Do not edit an old approval
onto a new head. Quotes, code fences, HTML comments and paired HTML elements
(including details) carry no declarations. PR reviews and inline review comments
are outside this protocol. Both seats publish through one configured identity:
seat/prefix markers document authorship, not independent authentication.

**Deletion is not withdrawal.** This API does not supply durable deleted bodies.
Publish a new `blocked` comment instead and retain it. Deleting a newer comment
can expose an older one; neither the workflow nor its tests claim otherwise.
No success depends on a deletion run persisting a special status tombstone.

The workflow uses trusted-base policy and a pinned action, with no checkout or
execution of PR code. It paginates comments, writes `pending` before evaluation,
checks review snapshots before and after the final PR read, and then writes the
result. Runs do not cancel an in-progress predecessor. Failures after the pending
write leave pending, not a previous success. Missing publisher configuration
refuses. Its only write is a commit status; native `make verify` stays separate.

**Asynchronous limit:** GitHub status writes and comment edits are not one
transaction. A failure of the initial pending write, event delivery delay,
queued/cancelled run before its first write, or an edit after the last snapshot
can temporarily leave an earlier success visible. This check is not an atomic
merge guarantee. Rod must still confirm the latest exact-head review and no
outstanding blocker in the per-PR Mergeable table before merging. A manual
workflow dispatch with the PR number rechecks uncertain state.

The repository owner must first arrange approved workflow-capable publication,
then configure the nonsecret `REVIEW_PUBLISHER` repository variable, observe a
real Actions run and adopt `review-head` as an additional required status.
**Pin its expected source to the GitHub Actions App**, using its independently
verified numeric `integration_id` in the ruleset (or expected source in classic
protection). Do not accept statuses from any source. Preserve every existing
rule and native gate. The Actions App source does not distinguish another
trusted workflow using that same App; trusted workflow changes also need review.
See [required check sources](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
and [ruleset API](https://docs.github.com/en/rest/repos/rules).
A source merge establishes none of these adoption steps or independent identities.
