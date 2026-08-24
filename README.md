# lean-eval delayed source releases

This repository will publish source bundles whose embargo has expired. It is
separate from the live leaderboard, private State, submission intake, and
encrypted audit archive so none of those write credentials are present during
publication.

The release delay is exactly two UTC calendar months after acceptance. Adding
months preserves the UTC clock time and day where possible; if the target month
has no such day, it clamps to that month's final day. For example, a submission
accepted at `2026-12-31T12:00:00.000Z` becomes eligible at
`2027-02-28T12:00:00.000Z`.

The validator refuses self-declared clocks and provenance: `generated_at` must
equal the workflow-supplied trusted UTC instant; acceptance time and the full
archive locator plus digest must match a trusted State materialization; release
IDs contain the real generation date; identities cannot escape the canonical
bundle path; and each bundle's bytes must match its digest.
Submission identities are canonical lowercase UUIDv7 values allocated at
authenticated intake.

The machine-readable contracts are
[`schema/release-manifest-v1.schema.json`](schema/release-manifest-v1.schema.json),
[`schema/release-queue-v1.schema.json`](schema/release-queue-v1.schema.json),
[`schema/release-plan-v1.schema.json`](schema/release-plan-v1.schema.json),
[`schema/release-metadata-v1.schema.json`](schema/release-metadata-v1.schema.json), and
[`schema/release-acceptance-snapshot-v1.schema.json`](schema/release-acceptance-snapshot-v1.schema.json).
The latter is the exact handoff the State materializer must produce for a
publication workflow; callers may not synthesize it from the proposed release.

`archive_ciphertext_sha256` is the lowercase SHA-256 of the exact encrypted
archive ciphertext blob bytes stored in the audit repository. It is copied
from the archive sidecar's `sha256_ciphertext`; it is not the digest of the
plaintext tar stream, sidecar JSON, Git tree, decrypted contents, or repacked
publication bundle. The separately named `bundle_sha256` covers the exact
published `sources/<submission-id>.tar.gz` bytes.

The immutable archive locator consists of `archive_repository`,
`archive_commit`, and `archive_path`. The schema-version-1 path is exactly
`archives/<first-two-UUID-hex>/<submission-id>.tar.age`; it cannot use a legacy
issue-derived name or contain absolute or traversal components. A publisher
retrieves that path at the pinned commit and verifies the ciphertext bytes
against `archive_ciphertext_sha256` before any decryption.

`scripts/release_orchestrator.py` validates the State-owned release queue,
recomputes result identity, archive path, consent, and the two-calendar-month
boundary, and selects the lexicographically first due result. Its execution
plan carries the exact archive and result provenance, canonical
`releases/YYYY/MM/<result_id>` path, and a `release.started` transition body.
It never generates event identity or time, unwraps a key, decrypts an archive,
writes this repository, or marks a release complete.

`scripts/reconstruct_release.py` takes one execution plan, the corresponding
already-decrypted `source.tar.gz`, the trusted State acceptance snapshot, and
a trusted as-of time. It publishes nothing. It selects only the bytes actually
used by evaluation: `source/Submission.lean` and regular UTF-8 `.lean` files
beneath `source/Submission/`. Other repository files are deliberately omitted.
Links, devices, traversal, duplicate members, decompression-size abuse,
non-UTF-8 Lean files, output overwrite, early release, and State/provenance
mismatches fail closed.

The deterministic reconstruction contains both the stable public result path
and a source-only transport bundle:

```text
releases/YYYY/MM/<result_id>/
  Submission.lean
  Submission/**/*.lean
  metadata.json
  LICENSE
sources/<submission-id>.tar.gz
release-manifest.json
```

The manifest is unique by `result_id`, since one submission may solve several
problems. `release_tree_sha256` is SHA-256 over the domain
`lean-eval-release-tree-v1\0` followed by compact UTF-8 JSON containing the
byte-sorted `(path, size, file SHA-256)` projection of the exact result
directory. File modes, gzip time, tar ownership, and ordering are normalized.
The same inputs and trusted time therefore produce identical bundle and tree
digests. `tests/fixtures/release-tree-digest-v1.json` freezes a
language-neutral byte/hash vector for this domain-separated projection.

The manual `Reconstruct one synthetic staging release` workflow exercises this
boundary in the protected `release-staging` environment with harmless source.
It has read-only repository permission, receives no OIDC or secret, uploads no
artifact, writes neither Git nor State, and leaves publication disabled. A
later credentialed workflow must first verify the pinned ciphertext digest,
consume exactly one `lean-eval-release` unwrap capability, decrypt it, and only
then invoke this provider-neutral reconstruction tool.

`Publish due source release` is the credentialed production controller. Its
daily schedule is inert unless the repository variable `PUBLICATION_ENABLED`
is exactly `true`; a manual run additionally requires an explicit confirmation.
It also refuses any repository or ref other than the exact upstream `main`.
It materializes the private production State repository through a read/write
deploy key scoped only to that repository, selects at most one due result,
atomically stages `release.started` and its exact targeted result release-status
replacement, and commits them with a non-forced compare-and-swap push. A
missing, stale, or mismatched status fails closed, and a rejected push is never
rebased onto another State head. The controller then retrieves the exact audit
commit and verifies that the schema-version-3 sidecar, KMS envelope, and
ciphertext bytes agree. It assumes only the production release Lambda-invoker
role, consumes one five-minute `lean-eval-release` capability, drops AWS
authority before decryption, reconstructs the allowlisted public tree, and
publishes with a second deploy key scoped only to this repository. The terminal
State commit likewise atomically records the event and status replacement; its
event pins the exact release commit, path, and tree digest.

Before planning, the controller checks both full-history Git checkouts against
the closed credential contract, requires exact tracked-clean `origin/main`
commits, and requires production State to descend from the reviewed release
event contract. A source-free qualification binds the exact controller commit,
State commit and event provenance, release-queue bytes, and acceptance-snapshot
bytes into the execution plan. Reconstruction rechecks the acceptance snapshot
binding. The detailed authority, compare-and-swap, idempotence, and recovery
contract is in
[`docs/release-controller-contract.md`](docs/release-controller-contract.md).

No plaintext or identity artifact is uploaded. A pre-publication failure is
recorded as retryable. If a runner disappears after `release.started`, the next
scheduled controller run waits one hour, then either records a retryable
interruption or proves an already-published tree and records
`release.published`; this closes the push-succeeded/callback-lost ambiguity.
Owner publication changes are folded into the State-owned release queue, so an
opt-out ordered before `release.started` is not executable work.

The protected `release-production` environment contains only:

- `AUDIT_READ_KEY`, a read-only deploy key scoped only to the private audit
  repository;
- `RELEASE_PUBLISH_KEY`, whose public deploy key is the only automatic bypass
  on this repository's append-only publication branch;
- `PRODUCTION_STATE_CONTROLLER_KEY`, whose public deploy key can update only
  production State through its validator and non-forced pushes; and
- non-secret `AWS_RELEASE_UNWRAP_ROLE_ARN`, which can invoke only the immutable
  production unwrap Lambda alias.

The workflow receives no archive writer, results writer, intake, OAuth, GitHub
App, KMS, DynamoDB, or general AWS credential.

`Verify production release controller credentials` is a separate manual,
publication-disabled preflight for the controller's two write-capable deploy
keys. It runs only from protected `main` in `release-production`, shares the
controller's non-cancelling concurrency group, and fails unless the repository
publication variable remains absent or exactly `false`. It validates and
materializes the exact live production State checkout, creates the same exact
source-free qualification in non-publishing mode, then uses
`git push --dry-run` against the already-current `main` SHA in each repository.
This contacts GitHub's write-side `receive-pack` service and proves the matching
key is accepted without updating either ref. The workflow has no OIDC
permission, AWS step, audit key, release planner/controller invocation,
artifact upload, commit, or non-dry-run push.

`Verify production audit read credential` is a second manual,
publication-disabled preflight with a deliberately separate job and credential
boundary. Its only secret is `AUDIT_READ_KEY`; the release and State write keys
are never referenced by that workflow. A blobless, non-cone sparse checkout
authenticates to the private audit repository without downloading a blob or
materializing a tracked file; commit and tree metadata still reach the runner.
Two exact `main` upload-pack reads surround a receive-pack dry run that must
return an explicit GitHub permission denial, proving the credential retains read
access without write access. It shares the production controller's
non-cancelling policy in its own preflight concurrency group, so it cannot evict
a pending publication run. A secret-free guard fails an invalid repository,
ref, or confirmation before the credentialed job can start. The workflow
performs no checkout of State or release publication content and has no OIDC,
AWS, artifact, commit, or non-dry-run push step.

`Verify production release OIDC trust` is a third manual, publication-disabled
preflight for the production environment's release-unwrapper role. A
secret-free job first requires an exact upstream `main` dispatch and explicit
confirmation. The protected `release-production` job then receives only
`id-token: write`, requires the publication latch to remain absent or `false`,
and refuses a role variable other than the exact production release Invoke
role. It assumes that role for 15 minutes under an inline session policy that
permits only STS caller identity, verifies the exact account, role, and session,
then removes both the AWS credentials and GitHub OIDC request handle from the
final trust-proof process. No later repository-authored step runs in that job;
a separate permissionless job writes the source-free summary. The workflow uses
its own non-cancelling concurrency group and has no repository permission,
secret, checkout, Git operation, archive access, Lambda invocation, State
operation, or artifact. The workflow must remain undispatched until an
authenticated operator has reconciled and read back the live production trust
policy.

`Prove one credentialed staging release unwrap` is the non-publishing launch
gate for this boundary. Given an accepted staging submission, it derives the
exact queued release from validated staging State, checks out the pinned audit
commit with separate read-only keys, consumes one staging release-purpose
capability, drops AWS and OIDC authority, and verifies the decrypted tarball
against the private sidecar. It neither reconstructs before the embargo nor
writes State or this repository, and it uploads no artifact.
Before executing any checked-out staging State code, the workflow requires the
checkout to be clean, complete-history, and exact `origin/main`, to descend from
the reviewed staging release contract, and to retain its exact reviewed
`schema` and `scripts` trees.

`scripts/plan_release_removal.py` is the Git-read-only first response tool for
an erroneous publication or confidentiality incident. From exact local
checkouts it resolves each repository's live protected `main`, reads the
original `release.published` event and private evidence as exact Git blobs, and
binds them to the published Git commit/tree, canonical release-tree digest,
public source bundle, and publication manifest. It emits a deterministic,
source-free private containment plan with exclusive mode-0600 creation outside
every repository; an optional explicitly redacted public projection is
available only for ordinary erroneous publications. Confidentiality incidents
cannot produce a public output. It performs no deletion, commit, index/ref
update, Results rewrite, or State write. It binds the exact reviewed
`release.removed` State contract and
emits a correction skeleton whose fresh identity, timestamp, and verified
post-containment commit/tree remain operator-supplied. The operator procedure
and multi-result confidentiality scope are in
[`docs/release-confidentiality-incident-recovery.md`](docs/release-confidentiality-incident-recovery.md).

`scripts/release_removal.py` is the non-networked second half of that operator
boundary. It consumes the private plan, stages only its exact path set, verifies
the Git index, and creates an ordinary local containment commit. It then
independently reopens the exact upstream release checkout and rederives the
containment commit and root tree in every State-facing API; no caller-supplied
binding document is trusted. It completes every `release.removed` skeleton
against that one commit and root
tree, stages the full incident group plus every targeted release-status view,
runs the pinned State validator/materializer/public projection, and creates one
local State commit. Its output is a private, source-free compare-and-swap
description whose expected remote head must still match; it still contains
incident Git locators and must not be published. The tool has no push operation
and never checks out Results. If a State push is rejected after the release
commit has landed, rerunning with the same plan, release commit, State checkout,
and event-identity file recognizes the existing exact local State commit. It
never rebases or regenerates event identities.

The local confidentiality mode is deliberately labeled
`synthetic_target_tree_only`. It proves deletion, manifest, multi-result State,
and consumer semantics using harmless bytes; it does **not** prove that a real
secret has been removed from Git history, refs, forks, caches, artifacts,
mirrors, or prior downloads. Without the explicit synthetic qualification flag,
the tool refuses to turn a confidentiality target-tree commit into State
corrections. The flag also requires the immutable harmless-fixture marker in
the plan-bound release base, so it cannot be applied to a real production
incident plan. `owner_retraction` also fails closed: maintainers have not yet
decided whether that case shares this protected operator lane.
Every synthetic release stage, containment binding, State stage, and State CAS
sets `push_prohibited = true` and `remote_update_permitted = false` and omits
the ref, expected remote head, and push mode needed by the ordinary CAS path.
The CAS precondition verifier rejects such output even if a supplied observed
head happens to match.

Publication remains disabled until the production credentials and a
single-submission decrypt/reconstruction check are complete. The contributor
acknowledgement and Apache-2.0 release choice are fixed by the approved rollout
decision; eligibility and current consent still come only from validated
State.

```bash
python -m unittest discover -s tests -v
python scripts/validate_manifest.py path/to/release-manifest.json \
  --trusted-as-of "$TRUSTED_UTC_NOW" \
  --state-acceptance-snapshot path/to/trusted-state-export.json \
  --bundle-root path/to/release-tree

python scripts/release_orchestrator.py path/to/release-queue.json \
  --trusted-as-of "$TRUSTED_UTC_NOW" \
  --output /tmp/release-plan.json

python scripts/reconstruct_release.py /tmp/release-plan.json \
  --plaintext-tar /tmp/source.tar.gz \
  --trusted-as-of "$TRUSTED_UTC_NOW" \
  --state-acceptance-snapshot path/to/trusted-state-export.json \
  --output-root /tmp/reconstructed-release

python scripts/release_removal.py finalize-release /private/removal-plan.json \
  --release-root /checkouts/lean-eval-releases \
  --message "Remove erroneous source release" \
  --output /private/release-containment-binding.json

python scripts/release_removal.py finalize-state /private/removal-plan.json \
  --release-root /checkouts/lean-eval-releases \
  --release-commit '<verified-local-release-commit>' \
  --state-root /checkouts/lean-eval-state \
  --protected-state-head '<exact-plan-State-head>' \
  --event-identities /private/removal-event-identities.json \
  --message "Record release removal" \
  --output /private/state-removal-cas.json
```
