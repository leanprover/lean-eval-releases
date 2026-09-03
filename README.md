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
[`schema/release-unwrap-authority-v1.schema.json`](schema/release-unwrap-authority-v1.schema.json),
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
daily schedule is inert unless the `release-production` environment variable
`PUBLICATION_ENABLED` is exactly `true`. A minimal job attached to that
environment reads and caches the latch before either authority-bearing job can
start. This avoids relying on environment-scoped variables in job-level
conditions, which GitHub evaluates before attaching a job's environment. Both
authority-bearing jobs require the cached exact-true output as defense in
depth. The cached value is not a live revocation mechanism, so a queued job
must not be assumed to observe a later variable change. After disabling the
variable, operators must cancel every queued or running controller run. An
emergency stop must additionally revoke the scoped production keys or unwrap
role, or block the job with `release-production` environment protection. A
manual run additionally requires an explicit confirmation. Every job also
refuses any repository or ref other than the exact upstream `main`.
A State-writing preparation job materializes the private production State
repository through a read/write deploy key scoped only to that repository,
selects at most one due result, atomically stages `release.started` and its
exact targeted result release-status replacement, and commits them with a
non-forced compare-and-swap push under the run-context latch. The authority
boundary described below does not remove that State-key authority; the job has
no OIDC permission. A
missing, stale, or mismatched status fails closed, and a rejected push is never
rebased onto another State head. The controller then retrieves the exact audit
commit and verifies that the schema-version-3 sidecar, KMS envelope, and
ciphertext bytes agree. It assumes only the production release Lambda-invoker
role, consumes one five-minute `lean-eval-release` capability, drops AWS
authority before decryption, reconstructs the allowlisted public tree, and
publishes with a second deploy key scoped only to this repository. The terminal
State commit likewise atomically records the event and status replacement; its
event pins the exact release commit, path, and tree digest.

Before assumption, the workflow compares the environment role variable with
the reviewed production ARN. The resulting 15-minute session is restricted
again to the exact qualified production unwrap Lambda alias (plus caller
identity) and fails if AWS returns credentials for another account.
Because GitHub injects OIDC handles into every step of an `id-token: write`
job, unwrap runs in a separate job that executes only pinned actions and
literal workflow code before role assumption. The credential action is
followed by exactly one final authored step. Its literal provider phase accepts
only a fixed-field, disclosure-safe authority descriptor, binds it to the exact
sidecar/envelope/ciphertext, and consumes the one-use capability after a
bounded scan of runner credential-file locations. It then
uses `exec env -i` to replace the secret-bearing shell with a process whose
environment contains no AWS or OIDC handle before any checked-out program
executes. The checked-out tail proves its own `/proc` environment is clean,
repeats the credential-name file scan, then deterministically reconstructs the
private execution plan from the exact pinned State commit and exact committed
`release.started` transition before decrypting, publishing, recording terminal
or retryable State, and removing private scratch. Job outputs and ordinary step
environments carry only exact commits, UUID/digests, the canonical encrypted
archive locator, and eligibility time. The execution plan, `release.started`
body, owner/model, and production prompt/notes never cross that boundary and
are not logged, summarized, or uploaded as artifacts. No identity, plaintext,
or private archive is transferred between jobs or uploaded.

Before planning, the controller checks both full-history Git checkouts against
the closed credential contract, requires exact tracked-clean `origin/main`
commits, and requires production State to descend from the reviewed release
event contract. That reviewed production State contract is commit
`4dd6c5498559599d250f8803b765e92c56397659`, root tree
`637318bbc07ecf09cf0714888123c0522cae92e4`, with README blob
`1dd08b8569c1a3a8eadec72af96276f520d4afec`, docs tree
`7401f6bf26083ebbc0db05f11cd90007d2a74f80`, schema tree
`92a7c3433e85931c8be355e81b20a42a932f6950`, and scripts tree
`ee7965eb33ecf4f7d062b4836a2d9b755b2da9fd`. A source-free qualification
binds the exact controller commit, State commit and event provenance,
release-queue bytes, and acceptance-snapshot bytes into the execution plan.
Reconstruction rechecks the acceptance snapshot binding. The detailed
authority, compare-and-swap, idempotence, and recovery contract is in
[`docs/release-controller-contract.md`](docs/release-controller-contract.md).
The validation workflow's private pinned-State integration is intentionally
limited to exact upstream protected `main`; a branch `workflow_dispatch` does
not receive the production State key. This preserves the secret boundary
rather than weakening it to make branch validation convenient.

No plaintext or identity artifact is uploaded. A pre-publication failure is
recorded as retryable. If a runner disappears after `release.started`, the next
scheduled controller run waits one hour, then either records a retryable
interruption or proves an already-published tree and records
`release.published`; this closes the push-succeeded/callback-lost ambiguity.
The production environment currently has no reviewer or wait-timer rule, so
its two split jobs do not create a second manual approval after
`release.started`; the runbook must reverify that external fact before enabling
publication.
Owner publication changes are folded into the State-owned release queue. A
submission initially marked `withheld` contributes no executable work; its sole
later owner transition is an irreversible change to `scheduled`, which adds the
release task. A scheduled submission cannot return to private.

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
secret-free job first requires an exact upstream protected-`main` dispatch, a
40-hex reviewed commit equal to the workflow run SHA, and explicit confirmation.
It is unconditional, and every later job is an unconditional dependency, so a
failed authorization cannot become a skipped-success run. The protected
`release-production` job then receives only
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

`Prove one credentialed staging release reconstruction` is the non-publishing launch
gate for this boundary. Given an accepted staging submission, it derives the
exact queued release from validated staging State, checks out the pinned audit
commit with separate read-only keys, consumes one staging release-purpose
capability, and requires an identical second request to fail with the exact
already-consumed response. Planning runs in a job with no OIDC. The separate unwrap job uses
the same literal-provider/`exec env -i` process boundary as production,
reconstructs its private plan from the exact pinned staging State commit after
authority erasure, verifies the decrypted tarball against the private sidecar,
and performs the real deterministic reconstruction against the exact State
acceptance snapshot using the scheduled `eligible_at` as the staging-only
trusted as-of time. It validates the public-only manifest and source allowlist,
then deletes both plaintext and reconstructed output. All of this occurs only
after its `/proc` authority proof. Its displayed submission ID is
derived from that reconstructed and digest-bound plan, never from the unbound
dispatch input passed to the authority job. It never publishes, commits, pushes,
or changes either Git checkout, and it uploads no artifact.
Before executing any checked-out staging State code, the workflow requires the
checkout to be clean, complete-history, and exact `origin/main`, to descend from
the reviewed staging release contract, and to retain its exact reviewed
`schema` and `scripts` trees. That staging contract is commit
`6105a6255ec40409bcce66c6cf6b6764e0e93ed4`, schema tree
`5d3218039b1c4079d751fb54a30b1516917a81cd`, and scripts tree
`6527eafbad98ed43206e9e26f1731ae16d4fc995`.
The workflow also refuses a role variable other than the reviewed staging ARN
and restricts its 15-minute session to the exact qualified staging unwrap
Lambda alias (plus caller identity) in account `161072922960`.
Its invoke-and-sanitized-tail step is likewise the final authored step, and the
tail uses an exit trap to remove all private scratch on both success and
failure.

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
