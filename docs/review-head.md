# Exact-head technical review

Each PR body declares its implementation seat on one unquoted line:

```text
Implementation-Seat: POMAR-Codex
```

The other seat publishes a technical review comment with these three unquoted
lines (replace the example SHA with the complete reviewed commit):

```text
Reviewing-Seat: POMAR-CC
Reviewed-Head: 0123456789abcdef0123456789abcdef01234567
Review-Verdict: no-blocker
```

Use `blocked` for an unresolved finding. Every new push requires a new review.
The latest reviewing-seat comment counts, including a malformed or blocked
one; an older favourable review cannot supersede it. Deleting a review holds
the check until a newer explicit review is published. Both seats currently
publish as the same GitHub identity: the marker and durable review record
document authorship; this check cannot independently authenticate the seat.

The `review-head` commit status runs on PR changes and comment creation,
editing and deletion. It reads metadata only, never checks out PR code, and
has no build, guest, secret, deployment or merge operation. Its sole write is
the commit status. The native `make verify` gate remains separate.

The repository owner configures the trusted publishing login in the repository
variable `REVIEW_PUBLISHER`. Missing or malformed configuration fails closed;
no private publishing identity is embedded in source or fixture data. This
variable is configuration, not a credential.

After this workflow lands on the default branch, require the exact status
context `review-head` in the main branch rule, preserving every existing
protection and native gate. That repository setting is a separate observed
adoption step, not something a workflow file can establish. Until adoption,
the seats' per-PR review table is the record. Rod still merges; an override
must remain visible. Recheck existing open PRs with workflow dispatch using
their PR number. A source merge alone does not claim an installed check or
changed protection.
