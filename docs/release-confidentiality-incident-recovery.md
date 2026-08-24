# Release confidentiality-incident recovery

The lifecycle-overhaul contract distinguishes two cases:

- An **erroneous publication** is removed from `lean-eval-releases` by a normal
  forward deletion. Results and immutable State history are not rewritten.
- A **true confidentiality incident** requires immediate visibility
  restriction and may require security-coordinated history cleanup, but only in
  `lean-eval-releases`. Results are not rewritten, and State records a forward
  correction rather than deleting or changing the original publication event.

Publication must remain disabled throughout either response. This procedure is
a containment and evidence contract, not authorization to change repository
visibility, bypass rulesets, rewrite history, update refs, or append live State.

## Read-only containment plan

First preserve a bounded private evidence document on protected `main` in
`leanprover/lean-eval-state` or `leanprover/lean-eval-audit`. Do not put source
text, credentials, archive identities, or raw incident evidence in workflow
inputs, issues, public logs, job summaries, or a public plan. The request records
only its exact repository, commit, path, and SHA-256. The full containment plan
also carries these private locators and therefore **must remain private**.

Prepare clean, current local checkouts of the release repository, production
State, and the private evidence repository. Their `origin` URLs must identify
the requested upstream repositories, and every referenced object must already
be present locally. Set `GH_TOKEN` to read all three repositories: the planner
uses the GitHub API read-only to resolve each live protected `main`; it does not
fetch because a fetch writes remote-tracking refs and objects.

Prepare an exact request outside the release checkout:

```json
{
  "base_commit": "<clean-release-main-commit>",
  "classification": "erroneous_publication",
  "evidence": {
    "commit": "<private-evidence-commit>",
    "path": "incidents/<incident-id>.json",
    "repository": "leanprover/lean-eval-state",
    "sha256": "<sha256-of-exact-evidence-bytes>"
  },
  "incident_id": "<canonical-uuidv7>",
  "planned_at": "<trusted-UTC-milliseconds>",
  "published_events": [
    {
      "commit": "<production-State-commit-containing-the-event>",
      "path": "events/<prefix>/<release.published-event-id>.json",
      "repository": "leanprover/lean-eval-state",
      "sha256": "<sha256-of-exact-event-blob>"
    }
  ],
  "release_repository": "leanprover/lean-eval-releases",
  "schema_version": 1
}
```

Use `classification = "confidentiality_incident"` only when the response must
treat already-published bytes as confidential. If one submission bundle is
exposed by multiple result paths, include one exact `release.published` locator
for **every** such result in the canonically sorted `published_events` list.
Ordinary erroneous-publication requests remain single-result. Then run with the
request and outputs outside every repository:

```bash
python scripts/plan_release_removal.py /private/request.json \
  --repository-root /checkouts/lean-eval-releases \
  --state-repository-root /checkouts/lean-eval-state \
  --evidence-repository-root /checkouts/lean-eval-state \
  --output /private/release-removal-plan.json
```

The private output is created once with mode `0600`, without following a final
symlink. It is never overwritten. If maintainers decide that a source-free
summary is appropriate for public disclosure, add
`--public-output /public/release-removal-summary.json`; that separate projection
omits every State-event and evidence locator. Do not publish the full plan.

The tool is deterministic and read-only. It requires:

1. `base_commit` to be the clean checked-out release `HEAD` and the exact live
   upstream `main` returned by GitHub;
2. each event locator to name one exact mode-100644 blob in production State,
   at a commit reachable from live State `main`, under the canonical path for
   its event ID, with the requested SHA-256, and containing one canonical
   system-authored `release.published` event;
3. every event's release commit to be reachable from live release `main`;
4. the event's canonical release path and tree digest to match the exact Git
   objects at both the publication commit and the current base;
5. `metadata.json`, `release-manifest.json`, and the source bundle to agree on
   the result, submission, canonical submission-derived bundle path, complete
   archive locator/digest, timestamps, release path, license, and SHA-256;
6. the current source bundle to be byte-identical to the published bundle; the
   plan inventories any other release path sharing that submission bundle,
   retains a shared bundle for an ordinary single-result correction, and refuses
   a confidentiality plan until every path exposing those bytes is in scope; and
7. the evidence locator to name one exact bounded blob at a commit reachable
   from its live private-repository `main`, with the requested SHA-256.

Git is invoked with optional locks disabled, system/global configuration
disabled, replacement objects and promisor lazy-fetches disabled, and
fsmonitor/untracked-cache/index write accelerators overridden. Input sizes are
checked before reads; Git output is streamed through hard caps, Git blob sizes
are checked before blob output is consumed, and the release metadata inventory
has aggregate entry and byte budgets. Private and public outputs are likewise
size-capped before exclusive creation. The plan binds the remote main commits,
publication and base commit/tree IDs, exact State-event and evidence Git blob
IDs and SHA-256s, release-tree and bundle digests, all affected public paths,
and the required manifest action. It never includes source or evidence bytes.

## Erroneous-publication procedure

After independent review of the plan:

1. Keep `PUBLICATION_ENABLED` absent or `false` and ensure no controller run is
   active.
2. Starting from the exact planned base, delete only the bound release directory
   and any source bundle whose plan action is `delete`. A `retain_shared` bundle
   remains because another public result still depends on the same submission
   bytes. Apply the plan's exact `release-manifest.json` action:
   delete it only when no entries remain, retain an unrelated later manifest,
   or remove exactly the scoped incident entries and verify the planned
   replacement digest. Object equality with a publication-time multi-entry
   manifest never authorizes deleting the whole manifest.
3. Review the staged diff for the exact paths, verify the old tree/bundle hashes,
   and create an ordinary non-forced correction commit through the protected
   process. The planner does not perform this step.
4. Verify the affected paths are absent at the exact correction commit and
   capture that commit and root Git tree ID.
5. Append the forward State correction described below only after its schema,
   materializer, projection behavior, and tests are merged. Never edit or delete
   the original `release.published` event.
6. Rebuild public consumers from corrected State. Do not change Results.

An ordinary forward deletion removes the bytes from the current branch but not
from existing Git history, clones, forks, caches, or previously downloaded
copies. If the bytes are confidential, stop and use the incident procedure.

## True-confidentiality-incident procedure

Do not wait for a tooling change before containment:

1. Pause publication and immediately use the organization incident process to
   restrict visibility of `lean-eval-releases`. Treat the public bytes as
   disclosed and preserve evidence privately.
2. Notify the designated security/legal maintainers and GitHub Support as
   appropriate. Identify every affected branch, tag, pull-request ref, release,
   Pages/artifact/cache surface, fork, and clone. Rotate a credential only when
   the disclosed material included that credential.
3. Run the read-only planner against the last clean, visible incident base to
   freeze exact affected objects. The plan deliberately contains no force-push,
   filtering, garbage-collection, visibility, or ruleset command.
4. Obtain explicit approval for a reviewed history-cleanup procedure scoped only
   to `lean-eval-releases`. Any temporary ruleset exception must be time-bounded,
   independently reviewed, and removed immediately after verified cleanup.
5. Before restoring visibility, independently verify the affected paths and
   objects are absent from every maintained ref and public delivery surface.
   Record the sanitized head commit and root Git tree ID in private evidence.
6. Append the forward State correction after the State dependency below lands.
   Never rewrite Results or the immutable State log to imitate sanitized release
   history.

History cleanup reduces repository exposure; it cannot revoke earlier clones,
forks, downloads, mirrors, or caches. Incident classification and disclosure
decisions remain human security/legal decisions.

## Required forward State correction

As of the implementation of this planner, State schema version 1 has no legal
transition after `release.published`. It registers only `release.scheduled`,
`release.started`, `release.published`, `release.failed`, and
`release.cancelled`; the materializer and public projection likewise have no
removed/contained status. The planner therefore reports
each `required_state_corrections[].status = "blocked_on_state_schema"` and does not
fabricate an event that production State would reject.

The minimal proposed dependency is a `release.removed` event caused by the
original `release.published` event. Its closed payload must preserve:

- classification;
- exact original State-event repository, commit, path, Git blob ID and SHA-256,
  plus the published release commit/tree, release path, and release-tree digest;
- exact public bundle path, digest, deletion/retention disposition, and any
  other release paths sharing it;
- private evidence repository, commit, path, Git blob ID, and digest; and
- the post-containment release-repository commit and root Git tree.

The State change must validate this transition, materialize a terminal removed
status, remove the public solution link from the public projection while
retaining visible correction history, and keep the task out of the release
queue. Whether policy needs a separate `release.incident_reported` event before
`release.removed` is unresolved; the planner's fixed bindings support either
causal design.

## Unresolved policy

Maintainers must still decide:

- who may classify a true confidentiality incident and authorize emergency
  visibility restriction;
- whether incident report and corrective action are one State event or a
  two-event causal chain, and which actor kinds may append them;
- whether and under what new consent a removed release can ever be republished;
- the public wording and stable-link behavior for erroneous versus confidential
  removals;
- the exact approved GitHub history-cleanup/support procedure, including refs,
  forks, caches, Pages, artifacts, mirrors, and restoration evidence; and
- evidence repository ownership, retention, access, and disclosure policy.

The current tooling restricts evidence to the production State or audit
repository. Expanding that allowlist requires a reviewed decision that the new
repository is private, protected, retained appropriately, and accessible to the
incident responders.

Until these decisions and the State schema dependency land, the safe automated
boundary ends at deterministic read-only planning.
