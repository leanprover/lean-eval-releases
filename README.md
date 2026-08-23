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
It materializes the private production State repository through a read/write
deploy key scoped only to that repository, selects at most one due result,
appends `release.started` with a non-forced compare-and-swap push, retrieves the
exact audit commit, and verifies the schema-version-3 sidecar, KMS envelope,
and ciphertext bytes agree. It then assumes only the production release
Lambda-invoker role, consumes one five-minute `lean-eval-release` capability,
drops AWS authority before decryption, reconstructs the allowlisted public
tree, and publishes with a second deploy key scoped only to this repository.
The terminal State event pins the exact release commit, path, and tree digest.

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
```
