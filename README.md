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
[`schema/release-manifest-v1.schema.json`](schema/release-manifest-v1.schema.json)
and
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

Publication remains disabled until the source-license language, contributor
rights, replay decryption boundary, provenance format, and release
reconstruction path are reviewed. The code here implements and tests the
embargo calculation and manifest validation only; it does not decrypt or
publish source.

```bash
python -m unittest discover -s tests -v
python scripts/validate_manifest.py path/to/release-manifest.json \
  --trusted-as-of "$TRUSTED_UTC_NOW" \
  --state-acceptance-snapshot path/to/trusted-state-export.json \
  --bundle-root path/to/release-tree
```
