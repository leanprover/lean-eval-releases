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

Before planning work, `scripts/release_qualification.py` fails closed unless
both local checkouts are tracked-clean, are the exact fetched `origin/main`,
have complete history, resolve at their Git toplevel, and have the expected
GitHub origin. Production State must also descend from
the reviewed `release.started`, `release.published`, `release.failed`, and
owner opt-out contract commit recorded in the credential contract. Full Git
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

The controller's mutation protocol remains compare-and-swap and idempotent:

1. A non-forced State push records `release.started` against its exact
   causation event before any archive access.
2. A non-forced release push publishes one append-only commit. A concurrent
   main update rejects the push rather than overwriting it.
3. A terminal State push records the exact release commit, path, and tree
   digest.
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
   submission is compared and reused. A release path present in history but
   later removed is never republished. Otherwise, after the
   recovery interval, it records one retryable interruption. Re-running
   recovery is deterministic.

The publication workflow must remain disabled until the rollout runbook's
external staging and credential gates have passed and an operator deliberately
creates `PUBLICATION_ENABLED=true`. Reviewing or merging this contract does not
authorize that environment change.
