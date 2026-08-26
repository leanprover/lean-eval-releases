#!/usr/bin/env bash

# This first command covers cancellation before the reviewed functions below
# have been defined. The later mode-specific traps replace it.
# shellcheck disable=SC2154
trap 'status=$?
trap - EXIT INT TERM
set +e
if [ -n "${RUNNER_TEMP:-}" ] && [ -d "$RUNNER_TEMP" ]; then
  /usr/bin/rm -rf "$RUNNER_TEMP/reconstructed" \
    "$RUNNER_TEMP"/.reconstructed-* "$RUNNER_TEMP/state-views"
  /usr/bin/rm -f "$RUNNER_TEMP"/release-*.json "$RUNNER_TEMP"/unwrap-*.json \
    "$RUNNER_TEMP"/identity.age "$RUNNER_TEMP"/source.tar.gz \
    "$RUNNER_TEMP"/archive.tar.age "$RUNNER_TEMP"/archive-sidecar.json \
    "$RUNNER_TEMP"/age-bin "$RUNNER_TEMP"/pre-authority-stage.json
fi
if [ "$status" -eq 0 ]; then status=1; fi
exit "$status"' EXIT INT TERM
set -euo pipefail
umask 077

mode=${1:-}
case "$mode" in
  production|staging) ;;
  *) echo "release authority tail mode is invalid" >&2; exit 2 ;;
esac

authority_proven=false
publication_recorded=false

remove_sensitive_scratch() {
  if [ -z "${RUNNER_TEMP:-}" ] || [ ! -d "$RUNNER_TEMP" ]; then
    return
  fi
  rm -rf "$RUNNER_TEMP/reconstructed" \
    "$RUNNER_TEMP"/.reconstructed-* "$RUNNER_TEMP/state-views"
  for path in "$RUNNER_TEMP"/release-*.json; do
    if [ "$path" != "$RUNNER_TEMP/release-started-event.json" ]; then
      rm -f "$path"
    fi
  done
  rm -f "$RUNNER_TEMP"/unwrap-*.json \
    "$RUNNER_TEMP"/identity.age "$RUNNER_TEMP"/source.tar.gz \
    "$RUNNER_TEMP"/archive.tar.age "$RUNNER_TEMP"/archive-sidecar.json \
    "$RUNNER_TEMP"/age-bin "$RUNNER_TEMP"/pre-authority-stage.json
}

remove_common_scratch() {
  remove_sensitive_scratch
  if [ -n "${RUNNER_TEMP:-}" ] && [ -d "$RUNNER_TEMP" ]; then
    rm -f "$RUNNER_TEMP/release-started-event.json"
  fi
}

run_exact_python() {
  "$PYTHON_BIN" -I -c '
import pathlib
import runpy
import sys

path = pathlib.Path(sys.argv[1])
if path.is_symlink() or not path.is_file():
    raise SystemExit("exact Python entry point is not a regular file")
path = path.resolve(strict=True)
sys.path.insert(0, str(path.parent))
sys.argv = sys.argv[1:]
runpy.run_path(str(path), run_name="__main__")
' "$@"
}

run_exact_python_quiet() {
  local phase=$1
  shift
  case "$phase" in
    authority-contract|manifest-validation|plan-reconstruction|\
      identity-validation|publication-classification|publication-write|\
      reuse-validation|source-decryption|source-reconstruction|source-validation|\
      state-materialization|state-validation) ;;
    *) echo "private release phase is invalid" >&2; return 1 ;;
  esac
  if ! run_exact_python "$@" >/dev/null 2>&1; then
    echo "private release failed closed: $phase" >&2
    return 1
  fi
}

require_private_regular() {
  local path=$1
  [ -f "$path" ] && [ ! -L "$path" ]
  test "$(stat --format=%a -- "$path")" = 600
}

record_retryable_failure() (
  set -euo pipefail
  if [ "$authority_proven" != true ]; then
    echo "authority proof failed; checked-out recovery code remains forbidden" >&2
    echo "the next controller run must recover release.started" >&2
    return 1
  fi
  if [ -z "${RUNNER_TEMP:-}" ] || [ ! -f "$RUNNER_TEMP/release-started-event.json" ] || \
    [ ! -d state ] || [ -z "${PYTHON_BIN:-}" ] || [ ! -x "$PYTHON_BIN" ]; then
    echo "retryable failure cannot be recorded on this runner" >&2
    echo "the next controller run must recover release.started" >&2
    return 1
  fi
  run_exact_python scripts/release_controller.py state-event failed \
    --started-event "$RUNNER_TEMP/release-started-event.json" \
    --trusted-now "$(date --utc +%Y-%m-%dT%H:%M:%S.000Z)" \
    --reason-code controller_failed \
    --retryable true \
    --output "$RUNNER_TEMP/release-failed-event.json"
  state_head=$(git -C state rev-parse HEAD)
  run_exact_python scripts/release_controller.py stage-state-transition \
    --state-root state \
    --event "$RUNNER_TEMP/release-failed-event.json" \
    --protected-state-head "$state_head" \
    --output "$RUNNER_TEMP/release-failed-transition.json"
  event_id=$(jq -er .event_id "$RUNNER_TEMP/release-failed-event.json")
  event_path=$(jq -er .event_path "$RUNNER_TEMP/release-failed-transition.json")
  status_path=$(jq -er .status_path "$RUNNER_TEMP/release-failed-transition.json")
  test -f "state/$event_path"
  test -f "state/$status_path"
  run_exact_python state/scripts/state.py --root state \
    --protected-main-commit "$state_head" validate
  run_exact_python scripts/release_controller.py verify-staged-state-transition \
    --state-root state \
    --event "$RUNNER_TEMP/release-failed-event.json" \
    --plan "$RUNNER_TEMP/release-failed-transition.json"
  git -C state commit --quiet -m "Record failed release $event_id"
  test "$(git -C state rev-parse HEAD^)" = "$state_head"
  git -C state push origin HEAD:main
)

# shellcheck disable=SC2329  # Invoked indirectly by the EXIT trap below.
finish_production() {
  local status=$?
  trap - EXIT INT TERM
  set +e
  if [ "$status" -ne 0 ] && [ "$publication_recorded" = false ]; then
    remove_sensitive_scratch
    record_retryable_failure
  fi
  remove_common_scratch
  exit "$status"
}

# shellcheck disable=SC2329  # Invoked indirectly by the EXIT trap below.
cleanup_staging() {
  local status=$?
  trap - EXIT INT TERM
  set +e
  remove_common_scratch
  exit "$status"
}

# shellcheck disable=SC2329  # Invoked indirectly by signal traps below.
cleanup_signal() {
  local status=$1
  trap - EXIT INT TERM
  set +e
  remove_common_scratch
  exit "$status"
}

trap - EXIT INT TERM
if [ "$mode" = production ]; then
  trap finish_production EXIT
  trap 'cleanup_signal 130' INT
  trap 'cleanup_signal 143' TERM
elif [ "$mode" = staging ]; then
  trap cleanup_staging EXIT
  trap 'cleanup_signal 130' INT
  trap 'cleanup_signal 143' TERM
fi

: "${HOME:?}"
: "${RUNNER_TEMP:?}"
: "${LITERAL_AUTHORITY_PROOF:?}"
test "$LITERAL_AUTHORITY_PROOF" = release-authority-sanitized-v1
authority_proven=true

: "${PATH:?}"
: "${PYTHON_BIN:?}"
case "$PYTHON_BIN" in
  /*) ;;
  *) echo "sanitized Python path is not absolute" >&2; exit 1 ;;
esac
[ -x "$PYTHON_BIN" ]
"$PYTHON_BIN" -I -c 'import sys; assert sys.version_info[:2] == (3, 11)'

if [ "$mode" = production ]; then
  git -C state config user.name lean-eval-release-controller
  git -C state config user.email \
    lean-eval-release-controller@users.noreply.github.com
fi
expected_state_head=$(jq -er .state_commit \
  "$RUNNER_TEMP/release-authority.json")
[[ "$expected_state_head" =~ ^[0-9a-f]{40}$ ]]
run_exact_python_quiet authority-contract \
  scripts/verify_release_state_contract.py \
  --environment "$mode" \
  --state-root state \
  --expected-head "$expected_state_head"
unset expected_state_head

reconstruct_arguments=(
  scripts/reconstruct_release_plan.py
  --authority "$RUNNER_TEMP/release-authority.json"
  --state-root state
  --release-root .
  --scratch-root "$RUNNER_TEMP"
  --output "$RUNNER_TEMP/release-plan.json"
)
if [ "$mode" = production ]; then
  reconstruct_arguments+=(
    --started-event-output "$RUNNER_TEMP/release-started-event.json"
  )
fi
run_exact_python_quiet plan-reconstruction "${reconstruct_arguments[@]}"
unset reconstruct_arguments
require_private_regular "$RUNNER_TEMP/release-plan.json"
if [ "$mode" = production ]; then
  require_private_regular "$RUNNER_TEMP/release-started-event.json"
fi

if [ "$mode" = staging ]; then
  : "${GITHUB_STEP_SUMMARY:?}"
  release_head_before=$(git rev-parse HEAD)
  release_tree_before=$(git rev-parse 'HEAD^{tree}')
  state_head_before=$(git -C state rev-parse HEAD)
  state_tree_before=$(git -C state rev-parse 'HEAD^{tree}')
  submission_id=$(jq -er .request.submission.submission_id \
    "$RUNNER_TEMP/release-plan.json")
  require_private_regular "$RUNNER_TEMP/unwrap-request.json"
  require_private_regular "$RUNNER_TEMP/unwrap-response.json"
  require_private_regular "$RUNNER_TEMP/unwrap-metadata.json"
  run_exact_python_quiet identity-validation \
    scripts/release_controller.py unwrap-identity \
    --request "$RUNNER_TEMP/unwrap-request.json" \
    --response "$RUNNER_TEMP/unwrap-response.json" \
    --metadata "$RUNNER_TEMP/unwrap-metadata.json" \
    --output "$RUNNER_TEMP/identity.age"
  require_private_regular "$RUNNER_TEMP/identity.age"
  require_private_regular "$RUNNER_TEMP/unwrap-reuse-response.json"
  require_private_regular "$RUNNER_TEMP/unwrap-reuse-metadata.json"
  run_exact_python_quiet reuse-validation \
    scripts/release_controller.py verify-unwrap-reuse-refusal \
    --response "$RUNNER_TEMP/unwrap-reuse-response.json" \
    --metadata "$RUNNER_TEMP/unwrap-reuse-metadata.json"
  test "$("$RUNNER_TEMP/age-bin" --version)" = v1.3.1
  if ! "$RUNNER_TEMP/age-bin" --decrypt \
    --identity "$RUNNER_TEMP/identity.age" \
    --output "$RUNNER_TEMP/source.tar.gz" \
    "$RUNNER_TEMP/archive.tar.age" >/dev/null 2>&1; then
    echo "private release failed closed: source-decryption" >&2
    exit 1
  fi
  require_private_regular "$RUNNER_TEMP/source.tar.gz"
  expected_plaintext=$(jq -er .sha256_plaintext_tar \
    "$RUNNER_TEMP/archive-sidecar.json")
  actual_plaintext=$(sha256sum "$RUNNER_TEMP/source.tar.gz" | awk '{print $1}')
  test "$actual_plaintext" = "$expected_plaintext"
  run_exact_python_quiet source-validation \
    scripts/validate_release_source_archive.py \
    --plaintext-tar "$RUNNER_TEMP/source.tar.gz"
  run_exact_python_quiet state-validation \
    state/scripts/state.py --root state \
    --protected-main-commit "$state_head_before" validate
  run_exact_python_quiet state-materialization \
    state/scripts/state.py --root state \
    --protected-main-commit "$state_head_before" materialize \
    --output "$RUNNER_TEMP/state-views"
  require_private_regular \
    "$RUNNER_TEMP/state-views/release-acceptance-snapshot.json"
  trusted_as_of=$(jq -er .request.release.eligible_at \
    "$RUNNER_TEMP/release-plan.json")
  run_exact_python_quiet source-reconstruction scripts/reconstruct_release.py \
    "$RUNNER_TEMP/release-plan.json" \
    --plaintext-tar "$RUNNER_TEMP/source.tar.gz" \
    --trusted-as-of "$trusted_as_of" \
    --state-acceptance-snapshot \
      "$RUNNER_TEMP/state-views/release-acceptance-snapshot.json" \
    --output-root "$RUNNER_TEMP/reconstructed"
  run_exact_python_quiet manifest-validation scripts/validate_manifest.py \
    "$RUNNER_TEMP/reconstructed/release-manifest.json" \
    --trusted-as-of "$trusted_as_of" \
    --state-acceptance-snapshot \
      "$RUNNER_TEMP/state-views/release-acceptance-snapshot.json" \
    --bundle-root "$RUNNER_TEMP/reconstructed"
  release_path=$(jq -er .request.release.path \
    "$RUNNER_TEMP/release-plan.json")
  test -f "$RUNNER_TEMP/reconstructed/$release_path/Submission.lean"
  test -f "$RUNNER_TEMP/reconstructed/$release_path/metadata.json"
  test -f "$RUNNER_TEMP/reconstructed/$release_path/LICENSE"
  test -f "$RUNNER_TEMP/reconstructed/sources/$submission_id.tar.gz"
  test "$(git rev-parse HEAD)" = "$release_head_before"
  test "$(git rev-parse 'HEAD^{tree}')" = "$release_tree_before"
  test "$(git -C state rev-parse HEAD)" = "$state_head_before"
  test "$(git -C state rev-parse 'HEAD^{tree}')" = "$state_tree_before"
  test -z "$(git status --porcelain --untracked-files=all -- \
    . ':(exclude)state')"
  git diff --quiet HEAD --
  git diff --cached --quiet HEAD --
  test -z "$(git -C state status --porcelain --untracked-files=all)"
  ciphertext_digest=$(jq -er .sha256_ciphertext \
    "$RUNNER_TEMP/archive-sidecar.json")
  audit_commit=$(jq -er .request.archive.archive_commit \
    "$RUNNER_TEMP/release-plan.json")
  remove_sensitive_scratch
  test ! -e "$RUNNER_TEMP/reconstructed"
  test ! -e "$RUNNER_TEMP/source.tar.gz"
  test ! -e "$RUNNER_TEMP/identity.age"
  test ! -e "$RUNNER_TEMP/unwrap-response.json"
  test ! -e "$RUNNER_TEMP/unwrap-reuse-response.json"
  test ! -e "$RUNNER_TEMP/state-views"
  {
    echo '### Credentialed staging release reconstruction passed'
    echo
    echo "- submission: \`$submission_id\`"
    echo "- audit commit: \`$audit_commit\`"
    echo "- ciphertext SHA-256: \`$ciphertext_digest\`"
    echo '- the identical unwrap request was refused after its first successful use'
    echo '- the public-only tree was reconstructed, validated, and discarded without publication, State/Git mutation, or artifact upload'
  } >> "$GITHUB_STEP_SUMMARY"
  exit 0
fi

expected_release_head=$(jq -er .request.controller.release_commit \
  "$RUNNER_TEMP/release-plan.json")
test "$(git rev-parse HEAD)" = "$expected_release_head"
protected_state_head=$(git -C state rev-parse HEAD)
[[ "$protected_state_head" =~ ^[0-9a-f]{40}$ ]]
started_event_id=$(jq -er .event_id "$RUNNER_TEMP/release-started-event.json")
started_event_path="events/${started_event_id:0:2}/$started_event_id.json"
git -C state show "HEAD:$started_event_path" \
  > "$RUNNER_TEMP/committed-release-started-event.json"
cmp "$RUNNER_TEMP/release-started-event.json" \
  "$RUNNER_TEMP/committed-release-started-event.json"
run_exact_python_quiet state-validation \
  state/scripts/state.py --root state \
  --protected-main-commit "$protected_state_head" validate
run_exact_python_quiet state-materialization \
  state/scripts/state.py --root state \
  --protected-main-commit "$protected_state_head" materialize \
  --output "$RUNNER_TEMP/state-views"

require_private_regular "$RUNNER_TEMP/unwrap-request.json"
require_private_regular "$RUNNER_TEMP/unwrap-response.json"
require_private_regular "$RUNNER_TEMP/unwrap-metadata.json"
run_exact_python_quiet identity-validation \
  scripts/release_controller.py unwrap-identity \
  --request "$RUNNER_TEMP/unwrap-request.json" \
  --response "$RUNNER_TEMP/unwrap-response.json" \
  --metadata "$RUNNER_TEMP/unwrap-metadata.json" \
  --output "$RUNNER_TEMP/identity.age"
require_private_regular "$RUNNER_TEMP/identity.age"
test "$("$RUNNER_TEMP/age-bin" --version)" = v1.3.1
if ! "$RUNNER_TEMP/age-bin" --decrypt \
  --identity "$RUNNER_TEMP/identity.age" \
  --output "$RUNNER_TEMP/source.tar.gz" \
  "$RUNNER_TEMP/archive.tar.age" >/dev/null 2>&1; then
  echo "private release failed closed: source-decryption" >&2
  exit 1
fi
require_private_regular "$RUNNER_TEMP/source.tar.gz"
expected_plaintext=$(jq -er .sha256_plaintext_tar \
  "$RUNNER_TEMP/archive-sidecar.json")
actual_plaintext=$(sha256sum "$RUNNER_TEMP/source.tar.gz" | awk '{print $1}')
test "$actual_plaintext" = "$expected_plaintext"
trusted_now=$(date --utc +%Y-%m-%dT%H:%M:%S.000Z)
run_exact_python_quiet source-reconstruction scripts/reconstruct_release.py \
  "$RUNNER_TEMP/release-plan.json" \
  --plaintext-tar "$RUNNER_TEMP/source.tar.gz" \
  --trusted-as-of "$trusted_now" \
  --state-acceptance-snapshot \
    "$RUNNER_TEMP/state-views/release-acceptance-snapshot.json" \
  --output-root "$RUNNER_TEMP/reconstructed"
run_exact_python_quiet manifest-validation scripts/validate_manifest.py \
  "$RUNNER_TEMP/reconstructed/release-manifest.json" \
  --trusted-as-of "$trusted_now" \
  --state-acceptance-snapshot \
    "$RUNNER_TEMP/state-views/release-acceptance-snapshot.json" \
  --bundle-root "$RUNNER_TEMP/reconstructed"
rm -f "$RUNNER_TEMP/source.tar.gz" "$RUNNER_TEMP/archive.tar.age" \
  "$RUNNER_TEMP/archive-sidecar.json" "$RUNNER_TEMP/identity.age"

result_id=$(jq -er .request.result.result_id "$RUNNER_TEMP/release-plan.json")
release_path=$(jq -er .request.release.path "$RUNNER_TEMP/release-plan.json")
submission_id=$(jq -er .request.submission.submission_id \
  "$RUNNER_TEMP/release-plan.json")
run_exact_python_quiet publication-classification \
  scripts/classify_release_publication.py \
  --release-root . \
  --reconstructed-root "$RUNNER_TEMP/reconstructed" \
  --release-path "$release_path" \
  --submission-id "$submission_id" \
  --output "$RUNNER_TEMP/release-publication-classification.json"
publication_kind=$(jq -er .kind \
  "$RUNNER_TEMP/release-publication-classification.json")
if [ "$publication_kind" = existing ]; then
  repository_commit=$(jq -er .repository_commit \
    "$RUNNER_TEMP/release-publication-classification.json")
  git show "$repository_commit:release-manifest.json" \
    > "$RUNNER_TEMP/publishing-manifest.json"
  generated_at=$(jq -er .generated_at "$RUNNER_TEMP/publishing-manifest.json")
  run_exact_python_quiet manifest-validation scripts/validate_manifest.py \
    "$RUNNER_TEMP/publishing-manifest.json" \
    --trusted-as-of "$generated_at" \
    --state-acceptance-snapshot \
      "$RUNNER_TEMP/state-views/release-acceptance-snapshot.json" \
    --bundle-root .
  tree_digest=$(jq -er --arg result "$result_id" --arg path "$release_path" \
    '.entries[] | select(.result_id == $result and .release_path == $path) | .release_tree_sha256' \
    "$RUNNER_TEMP/publishing-manifest.json")
elif [ "$publication_kind" = new ]; then
  run_exact_python_quiet publication-write scripts/publish_release.py \
    --release-root . \
    --reconstructed-root "$RUNNER_TEMP/reconstructed" \
    --release-path "$release_path" \
    --submission-id "$submission_id" \
    --classification \
      "$RUNNER_TEMP/release-publication-classification.json" \
    --trusted-as-of "$trusted_now" \
    --state-acceptance-snapshot \
      "$RUNNER_TEMP/state-views/release-acceptance-snapshot.json" \
    --output "$RUNNER_TEMP/release-publication-result.json"
  require_private_regular "$RUNNER_TEMP/release-publication-result.json"
  tree_digest=$(jq -er .release_tree_sha256 \
    "$RUNNER_TEMP/release-publication-result.json")
  repository_commit=$(jq -er .repository_commit \
    "$RUNNER_TEMP/release-publication-result.json")
else
  echo "publication classifier returned an unknown kind" >&2
  exit 1
fi
[[ "$tree_digest" =~ ^[0-9a-f]{64}$ ]]
publication_recorded=true

run_exact_python scripts/release_controller.py state-event published \
  --started-event "$RUNNER_TEMP/release-started-event.json" \
  --trusted-now "$(date --utc +%Y-%m-%dT%H:%M:%S.000Z)" \
  --repository-commit "$repository_commit" \
  --tree-digest "$tree_digest" \
  --release-path "$release_path" \
  --output "$RUNNER_TEMP/release-terminal-event.json"
state_head=$(git -C state rev-parse HEAD)
run_exact_python scripts/release_controller.py stage-state-transition \
  --state-root state \
  --event "$RUNNER_TEMP/release-terminal-event.json" \
  --protected-state-head "$state_head" \
  --output "$RUNNER_TEMP/release-terminal-transition.json"
event_id=$(jq -er .event_id "$RUNNER_TEMP/release-terminal-event.json")
event_path=$(jq -er .event_path "$RUNNER_TEMP/release-terminal-transition.json")
status_path=$(jq -er .status_path "$RUNNER_TEMP/release-terminal-transition.json")
test -f "state/$event_path"
test -f "state/$status_path"
run_exact_python state/scripts/state.py --root state \
  --protected-main-commit "$state_head" validate
run_exact_python scripts/release_controller.py verify-staged-state-transition \
  --state-root state \
  --event "$RUNNER_TEMP/release-terminal-event.json" \
  --plan "$RUNNER_TEMP/release-terminal-transition.json"
git -C state commit --quiet -m "Record published release $event_id"
test "$(git -C state rev-parse HEAD^)" = "$state_head"
git -C state push origin HEAD:main
