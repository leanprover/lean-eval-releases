# Production release controller contract

The automatic controller has two independent gates. GitHub must run the exact
`leanprover/lean-eval-releases` `main` ref in the protected
`release-production` environment, and the repository variable
`PUBLICATION_ENABLED` must be exactly `true`. The tracked repository does not
set that variable. The manual credential preflight instead requires it to be
absent or exactly `false`, so the same run cannot qualify publication.

[`configuration/release-controller-credential-contract-v1.json`](../configuration/release-controller-credential-contract-v1.json)
is the closed, reviewed Git authority contract. It names three non-overlapping
credentials:

- `RELEASE_PUBLISH_KEY` can update only this repository's `main`;
- `PRODUCTION_STATE_CONTROLLER_KEY` can update only production State `main`;
- `AUDIT_READ_KEY` can only read the immutable audit repository.

The environment's OIDC release-unwrapper role remains separately restricted to
the production unwrap Lambda. Neither this contract nor the qualification tool
creates, installs, reads, or tests an AWS credential.

The manual production OIDC preflight tests only that separate trust boundary.
An environment-free guard requires the exact upstream `main` ref and explicit
publication-disabled confirmation before the protected `release-production`
job can start. That job has only `id-token: write`, receives no repository
permission or secret, requires `PUBLICATION_ENABLED` to remain absent or
exactly `false`, and requires `AWS_RELEASE_UNWRAP_ROLE_ARN` to equal
`arn:aws:iam::161072922960:role/lean-eval-release-unwrap-invoker-production`.
It requests a 15-minute session under an inline session policy that permits only
`sts:GetCallerIdentity`. It binds the returned account, assumed-role ARN, and
session suffix, then blanks the AWS credential variables and GitHub OIDC request
variables in the same final repository-authored step. A negative credential
probe confirms that no AWS authority handle remains locally. No later
repository-authored step runs in that job; a separate job with no permissions
writes the source-free summary. The workflow does not invoke Lambda, inspect an
archive, check out a repository, write State, publish, or upload an artifact. It
uses a dedicated non-cancelling concurrency group, so a pending controller run
and an environment approval wait cannot evict or indefinitely block one
another. It is an after-reconciliation proof, not a mechanism for changing AWS
trust, and must not be dispatched before the live trust policy is corrected and
read back by an authenticated operator.

The production credential checks preserve those authority boundaries. The
write-key preflight never receives `AUDIT_READ_KEY`. A separate audit-read
workflow has one job whose only secret is `AUDIT_READ_KEY`; it never receives
either write key. It performs a blobless sparse checkout with an intentionally
absent path, so it authenticates Git upload-pack without downloading a blob or
materializing a private audit file; private commit and tree metadata remain
present on the ephemeral runner. Successful reads of the same exact audit
`main` on both sides of a receive-pack dry run fail closed unless the push
returns an explicit GitHub permission denial. The key persists for the remainder
of the job and is deleted by the checkout action's post-job cleanup, so the
proof is deliberately the job's final step. Both manual checks require the
publication latch to remain absent or exactly `false`. A secret-free guard job
fails an invalid repository, ref, or confirmation before the audit credentialed
job can start. The audit preflight has a separate non-cancelling concurrency
group, so dispatching it cannot evict a pending production controller run.

Before planning work, `scripts/release_qualification.py` fails closed unless
both local checkouts are tracked-clean, are the exact fetched `origin/main`,
have complete history, resolve at their Git toplevel, and have the expected
GitHub origin. Production State must also descend from
the reviewed `release.started`, `release.published`, `release.failed`, owner
opt-out, monotone release-revision, and immediate-predecessor contract commit
recorded in the credential contract. Its live `schema` and `scripts` trees must
still equal the trees at that reviewed commit, so later data-only State commits
remain usable while any contract-code drift fails closed. Full Git
history is checked out because interrupted-release recovery must inspect the
commit that first published a release path.

The source-free qualification records its `preflight` or `publication` mode,
the exact controller and State commits,
State event count and digest, and canonical SHA-256 digests of both State
materializations consumed by the run: the release queue and acceptance
snapshot. Each digest is SHA-256 over its distinct
`lean-eval-release-controller-*-v1` NUL-terminated domain followed by compact
UTF-8 JSON with lexicographically sorted object keys and no insignificant
whitespace. A Unicode-containing test vector freezes the encoding. The
production planner copies that closed object into the execution
plan. Reconstruction validates the object and refuses an acceptance snapshot
whose canonical JSON value does not match the plan. The queue digest and its State
source provenance are checked before planning. Synthetic and credentialed
staging tools remain backward compatible and never create a production
qualification. A preflight qualification is deliberately rejected by the
production planner; the production workflow also asserts that an execution
plan contains a production, publication-mode qualification.

The controller's mutation protocol remains compare-and-swap and idempotent.
Every controller-authored release transition first reads the exact targeted
`views/result-release-status/<prefix>/<result-id>.json` blob from the protected
State head. The schema-version-2 head carries a monotone `release_revision` and
the exact immediately superseded release-event marker; every transition
increments the revision once and atomically records the old marker as its
predecessor. `scripts/release_controller.py stage-state-transition` refuses a
missing, noncanonical, dirty, or head-mismatched document, requires its current
status and release-event marker to match the new event's causation, and stages
exactly two paths: the immutable event and the replacement targeted status.
The State validator checks that pair against the complete event graph before
Git creates one commit. Immediately after validation and before the commit, a
separate verification command re-derives the transition from the protected
head, reasserts that the cached diff contains only those two paths, compares
both cached blobs with their expected canonical bytes, and rejects any
post-staging worktree change. A normal, non-forced push is the only retry
boundary; the workflow never rebases a prepared transition onto a different
State head.

The resulting sequence is:

1. A non-forced State push atomically records `release.started` and changes its
   exact targeted status from `scheduled` or retryable `failed` to `running`
   before any archive access.
2. A non-forced release push publishes one append-only commit. A concurrent
   main update rejects the push rather than overwriting it.
3. A terminal State push atomically records the exact release commit, path,
   and tree digest and replaces the same targeted status with `published`.
   Failure and interrupted-run recovery use the identical two-path transition
   for `failed` or recovered `published` state.
4. If publication succeeds but the terminal callback is lost, a later run
   reconstructs evidence from full release history and records
   `release.published`. This also converges if the first run recorded a
   retryable failure after pushing but before exporting its commit: the next
   attempt validates the already-published tree against its historical
   manifest and compares the deterministic source bundle plus stable public
   source/metadata fields against a fresh reconstruction. The run-specific
   generation clock and the controller checkout's current license text are
   deliberately excluded from the fresh comparison. It then recovers the
   first-publishing commit and records the terminal event without overwriting
   the release. A bundle already published for another result from the same
   submission is compared and reused. Any deletion history for either a release
   path or its shared submission bundle is a permanent fail-closed tombstone,
   even if the path was later re-added; neither is republished. Otherwise,
   after the recovery interval, it records one retryable interruption.
   Re-running recovery is deterministic.

The publication workflow must remain disabled until the rollout runbook's
external staging and credential gates have passed and an operator deliberately
creates `PUBLICATION_ENABLED=true`. Reviewing or merging this contract does not
authorize that environment change.
