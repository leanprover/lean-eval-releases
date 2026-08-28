# Production release controller contract

The automatic controller has two run-admission gates. GitHub must run the exact
`leanprover/lean-eval-releases` `main` ref in the protected
`release-production` environment, and the repository variable
`PUBLICATION_ENABLED` must be exactly `true`. The tracked repository does not
set that variable. The variable gate is evaluated from workflow run context,
not as live revocation. The manual credential preflight instead requires it to
be absent or exactly `false`, so the same run cannot qualify publication.

[`configuration/release-controller-credential-contract-v1.json`](../configuration/release-controller-credential-contract-v1.json)
is the closed, reviewed Git authority contract. It names three non-overlapping
credentials:

- `RELEASE_PUBLISH_KEY` can update only this repository's `main`;
- `PRODUCTION_STATE_CONTROLLER_KEY` can update only production State `main`;
- `AUDIT_READ_KEY` can only read the immutable audit repository.

The environment's OIDC release-unwrapper role remains separately restricted to
the production unwrap Lambda. Neither this contract nor the qualification tool
creates, installs, reads, or tests an AWS credential.

The publishing job independently refuses an environment role variable other
than the reviewed production role ARN. Its 15-minute assumed-role session adds
an inline session policy that permits only `lambda:InvokeFunction` on the exact
qualified `lean-eval-archive-unwrap-production:live` alias plus
`sts:GetCallerIdentity`, and the credential action rejects any account other
than `161072922960`. The pinned action's reviewed `action.yml` at
`e6de054238d6b7531b4efff3b6587d9aade6a06c` explicitly declares
`allowed-account-ids`; this is not an ignored workflow input. These source
controls narrow the live role's permissions; they do not replace the required
external trust-policy and identity-policy review.

GitHub injects the OIDC request handle separately into every step of a job with
`id-token: write`; clearing a shell variable or `$GITHUB_ENV` cannot erase the
process-start environment or constrain another step. Planning, qualification,
recovery, and `release.started` therefore run in a preparation job with no OIDC
permission. The separate authority job executes only pinned actions and
literal workflow shell/Python before and during role assumption; it never
executes a checked-out program while AWS or OIDC authority exists. The
credential action is followed by exactly one final authored step. Its literal
provider phase validates a fixed-field disclosure-safe authority descriptor,
binds it to the exact sidecar, envelope, and ciphertext, creates and invokes
the exact one-use capability, and refuses every failure without executing
checkout code. Only a successful provider and Lambda invocation reach the
empty-environment `exec -c` handoff.
The final step installs literal scratch-cleanup `EXIT`, `INT`, and `TERM` traps
as its first command, before resolving Python or inspecting the authority
result. A direct `exec -c` into the absolute system Bash then replaces the
secret-bearing shell with an empty-environment process. The literal sanitizer
uses absolute `/usr/bin/env` and `/usr/bin/bash` paths before executing the
blob-verified checked-out authority tail. Before provider validation or the AWS invocation, an
empty-environment cleanup supervisor enters a session separate from the
authority process and reports readiness. The authority step itself starts in a
dedicated session, so its process group can be terminated without killing the
supervisor. The supervisor polls the exact authority-process PID plus Linux
process start-time identity; no cleanup pipe or descriptor is inherited by the
checked-out tail or its subprocesses. After abrupt parent death it scrubs,
terminates the isolated authority process group, keeps scrubbing while any live
group member remains, and scrubs once more after the last writer is gone. It
therefore covers failed handoff exec, parent or process-group death, and
descendants that would otherwise recreate private scratch. The exact tail
installs the same synchronous cancellation coverage before sensitive work and
replaces it with
mode-specific traps only after its cleanup functions exist. Thus early setup
failure, cancellation, and a failed closed-environment handoff remove the
unwrap response, plaintext identity, and every staged private scratch file
without executing checkout recovery code.

The literal provider validates only the closed authority descriptor defined by
`schema/release-unwrap-authority-v1.schema.json`: exact release and State
commits, production `release.started` identity/digest where applicable,
canonical encrypted-archive locator/digest, eligibility, and private-plan
digest. It also includes the closed sidecar and key-envelope checks: exact
fields and integer schema versions,
canonical UUIDs, repository and commit identifiers, canonical/nonempty bounded
wrapped identity, recipient and adapter grammar, ciphertext size and all three
digest bindings, and the exact archiver-run URL.
`scripts/release_provider_literal.py` is a non-executed review mirror; tests
require both workflow heredocs to equal it byte-for-byte, compare its accepted
request with `prepare_unwrap` under fixed time and randomness, and
adversarially mutate every descriptor field and binding. The
capability is still created immediately before invocation, never passed between
jobs, so approval or runner queue time cannot consume its five-minute lifetime.

The post-`env -i` literal sanitizer scans `/proc/self/environ` for AWS
credentials and GitHub OIDC request handles; inability to read that environment
or any surviving authority name fails closed. It makes no claim about the
runner-parent process because `/usr/bin/setsid --wait` may fork depending on
process-group topology. The sanitizer then validates a closed pre-authority
staging record, hashes the authority descriptor, every encrypted input,
and the age binary, proves the release and State checkouts remain at
the exact planned commits with no tracked, cached, or untracked change, and
proves the tail's working bytes are the exact Git blob at that release commit.
In both modes the root status check excludes only the intentional nested
`state/` checkout, whose exact head and complete cleanliness are checked
separately; every other root untracked path remains forbidden.
`scripts/release_sanitizer_literal.sh` is only its
non-executed review mirror; tests require both workflow heredocs to equal it.
Only after every literal proof succeeds does it execute the checked-out tail.
That tail first verifies the reviewed State contract, then materializes the
exact pinned State history and deterministically
reconstructs the complete private execution plan (and, in production, the
exact committed `release.started` body), rejects any descriptor digest or
causality mismatch, then validates the Lambda response and decrypts. Staging
also requires the identical request to receive the exact consumed-capability
refusal, reconstructs and validates the public-only tree against the exact
acceptance snapshot, verifies both Git checkouts are unchanged, and deletes the
temporary tree without publication. Production reconstructs source, publishes,
writes terminal or retryable-failure State, and runs trap-based source cleanup.
Every checked-out
Python entry point runs under `-I` through a literal launcher which adds only
that exact-clean checkout's script directory after isolated standard-library
startup, blocking ambient or untracked import shadowing. The encrypted audit
sidecar's plaintext-tar SHA-256 is compared with the decrypted bytes in both
staging and production before any source parser or reconstruction can run. The
State CLI always receives the exact checked-out or reconstructed source commit
as `--protected-main-commit`; repair events therefore remain valid without
turning protected-head selection into ambient repository state.
The encrypted audit object remains in its private checkout; neither the identity
nor plaintext nor private archive crosses a job boundary or is uploaded. No
later authored step can receive a new OIDC request handle; only the pinned
actions' post-job cleanup remains.
The canonical execution plan and `release.started` body never cross a job-output
boundary. Job outputs and ordinary step environments contain only explicitly
disclosure-safe identifiers: exact release/State/audit commits, the canonical
encrypted archive path and ciphertext digest, eligibility, the private-plan
digest, and in production the `release.started` UUID and digest. The descriptor
cannot reveal owner/model or `production_metadata.prompt`/`notes`; no workflow
log, step summary, or artifact receives those private values. State validation
and materialization output used for reconstruction is captured or suppressed;
the plan, decrypted-archive validation, source reconstruction, manifest
validation, publication classification, and the copy/Git/push publication
transaction likewise suppress their detailed stdout/stderr. The literal
provider, identity validation, and decryption map failures to the same closed
diagnostic vocabulary. `scripts/publish_release.py` captures every Git stream
before the release push and returns only the public commit and tree digests in
a mode-0600 handoff. The exact staged-set and committed-object checks replace
path-sensitive Git diagnostics, so only a fixed fail-closed phase class can
reach the log; hostile tar member names and private source lines cannot become
pre-publication log disclosures. Base64 is not treated as confidentiality.

Before invocation, literal code also scans the current AWS/OIDC values and
their canonical variable names under `$RUNNER_TEMP/_runner_file_commands` and
`$HOME/.aws`; the post-`env -i` literal sanitizer repeats the name scan before
checkout code.
Symlinks, special files, unreadable paths, and bounded-scan overflow fail
closed. This proves only those runner-owned credential locations and the
sanitized process environment; it does not claim a whole-disk or other-process
memory erasure proof. The audit checkout uses pinned checkout v7 with
`persist-credentials: false`, whose main action synchronously removes its SSH
key before returning. Literal runtime code additionally proves that no audit
Git auth remains. Its private-key sweep is deliberately limited to regular
files directly under the top level of `$RUNNER_TEMP`: production requires
exactly the two paths referenced by the release and State Git configurations,
while staging requires zero matches. It does not claim a recursive runner-disk
private-key inventory.

The production failure trap is installed at the beginning of the checked-out
tail, which can be reached only after the literal authority and checkout proof.
Any later failure first removes the unwrap response, identity, plaintext tar,
private archive, sidecar, authority descriptor, reconstructed release plan,
completed or in-progress hidden
reconstruction directories, and State
materialization, preserving only the committed non-source `release.started`
event needed by retry recording. Only after that synchronous erasure may it
attempt a compare-and-swap `release.failed`; `INT` and `TERM` skip network
recovery entirely and leave the next controller to reconcile the committed
start. After publication it preserves recovery semantics instead. If role
assumption, provider validation, Lambda invocation, literal sanitation,
pre-authority staging, or exact-checkout proof fails, executing checked-out
recovery code would violate the boundary. Those failure paths perform only
literal scratch
cleanup and leave the committed `release.started` for the next controller's
one-hour interrupted-run recovery.

Both split production jobs require environment-scoped keys and therefore name
`release-production`. Both job-level conditions retain a
`PUBLICATION_ENABLED == 'true'` check as defense in depth, but GitHub evaluates
them from the workflow run context. They are not a live revocation
mechanism, and a queued job must not be assumed to observe a later variable
change. The workflow deliberately does not attempt a REST re-read with
`github.token`: the repository-variable endpoint requires the separate
`Variables` repository permission (read), which is not an available
`GITHUB_TOKEN` workflow `permissions` key. This boundary applies specifically
to the authority job: `prepare-one`
can already use the production State key and append `release.started` under its
run-context latch. After disabling the variable, operators must cancel every
queued or running controller run and allow the committed start to follow the
documented interrupted-run recovery path. For an emergency stop they must also
revoke the scoped production keys or unwrap role, or use
`release-production` environment protection to block authority. The second
environment deployment occurs after `release.started`, and its protection
rules, variables, and secrets are mutable external state.
This is an explicit publication-launch blocker, not a property proved by
repository CI.
A read-only GitHub API check on 2026-08-25 showed its
only protection rule was the protected-branch policy: no reviewers and no wait
timer, so that snapshot would not introduce another manual approval or timer.
An authenticated operator must read back and record the environment protection
rules again immediately before enabling the publication latch, after the last
environment change and after both credential preflights pass; any reviewer,
wait-timer, branch-policy, role-variable, or credential drift keeps publication
disabled. The workflow-level non-cancelling concurrency group prevents a later
controller from recovering while the authority job is still queued or running;
the one-hour stale threshold applies only after that workflow ends or is
interrupted.

The manual production OIDC preflight tests only that separate trust boundary.
An environment-free guard requires the exact upstream protected `main` ref, a
canonical 40-hex reviewed commit equal to the workflow run SHA, and explicit
publication-disabled confirmation before the protected `release-production`
job can start. The guard and both dependent jobs are unconditional, so failed
authorization cannot be converted into a successful run by skipping the
credentialed path. That credentialed job has only `id-token: write`, receives no
repository permission or secret, requires `PUBLICATION_ENABLED` to remain
absent or exactly `false`, and requires `AWS_RELEASE_UNWRAP_ROLE_ARN` to equal
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
recorded in the credential contract. The current reviewed commit is
`3b7f713c5f39de27e84db5916980d4e96c353112`, with root tree
`a4f2cf17dab8b3be80427e2560ad2a4cbf2b93b7`, README blob
`9def120f4d0aae84fc3b713a029832e86b9a961e`, docs tree
`df80aab31568ba6d715895b4d058e2cf53178e33`, schema tree
`d5ab8e25ce33cfc54e19cd8fae4c4bdcc0455045`, and scripts tree
`9e019a7b631b93df2b5d91bd2ba3d164838c290d`. Its live `schema` and `scripts`
trees must still equal the trees at that reviewed commit, so later data-only
State commits remain usable while any contract-code drift fails closed. Full
Git history is checked out because interrupted-release recovery must inspect
the commit that first published a release path.

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

Retryable tasks have a four-attempt controller budget. The planner skips an
exhausted due task when other due work is available, preventing one
deterministic per-result failure from starving the queue. An execution plan
records the number of other exhausted due tasks, and the workflow emits a
non-fatal fixed warning whenever that count is nonzero. If every due task is
exhausted, it returns a closed `stalled` plan and the workflow fails with a
fixed operator-review diagnostic; it neither starts another attempt nor gains
archive authority.

The publication workflow must remain disabled until the rollout runbook's
external staging and credential gates have passed and an operator deliberately
creates `PUBLICATION_ENABLED=true`. Reviewing or merging this contract does not
authorize that environment change.
