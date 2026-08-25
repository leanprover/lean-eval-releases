#!/usr/bin/env bash

set -euo pipefail

mode=${1:-}
case "$mode" in
  production|staging) ;;
  *) echo "release authority tail mode is invalid" >&2; exit 2 ;;
esac

authority_proven=false
publication_recorded=false

remove_common_scratch() {
  if [ -z "${RUNNER_TEMP:-}" ] || [ ! -d "$RUNNER_TEMP" ]; then
    return
  fi
  rm -rf "$RUNNER_TEMP/reconstructed" "$RUNNER_TEMP/state-views"
  rm -f "$RUNNER_TEMP"/release-*.json "$RUNNER_TEMP"/unwrap-*.json \
    "$RUNNER_TEMP"/identity.age "$RUNNER_TEMP"/source.tar.gz \
    "$RUNNER_TEMP"/archive.tar.age "$RUNNER_TEMP"/archive-sidecar.json \
    "$RUNNER_TEMP"/age-bin "$RUNNER_TEMP"/pre-authority-stage.json
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
  "$PYTHON_BIN" scripts/release_controller.py state-event failed \
    --started-event "$RUNNER_TEMP/release-started-event.json" \
    --trusted-now "$(date --utc +%Y-%m-%dT%H:%M:%S.000Z)" \
    --reason-code controller_failed \
    --retryable true \
    --output "$RUNNER_TEMP/release-failed-event.json"
  state_head=$(git -C state rev-parse HEAD)
  "$PYTHON_BIN" scripts/release_controller.py stage-state-transition \
    --state-root state \
    --event "$RUNNER_TEMP/release-failed-event.json" \
    --protected-state-head "$state_head" \
    --output "$RUNNER_TEMP/release-failed-transition.json"
  event_id=$(jq -er .event_id "$RUNNER_TEMP/release-failed-event.json")
  event_path=$(jq -er .event_path "$RUNNER_TEMP/release-failed-transition.json")
  status_path=$(jq -er .status_path "$RUNNER_TEMP/release-failed-transition.json")
  test -f "state/$event_path"
  test -f "state/$status_path"
  "$PYTHON_BIN" state/scripts/state.py --root state \
    --protected-main-commit "$state_head" validate
  "$PYTHON_BIN" scripts/release_controller.py verify-staged-state-transition \
    --state-root state \
    --event "$RUNNER_TEMP/release-failed-event.json" \
    --plan "$RUNNER_TEMP/release-failed-transition.json"
  git -C state commit -m "Record failed release $event_id"
  test "$(git -C state rev-parse HEAD^)" = "$state_head"
  git -C state push origin HEAD:main
)

# shellcheck disable=SC2329  # Invoked indirectly by the EXIT trap below.
finish_production() {
  local status=$?
  trap - EXIT
  set +e
  if [ "$status" -ne 0 ] && [ "$publication_recorded" = false ]; then
    record_retryable_failure
  fi
  remove_common_scratch
  exit "$status"
}

# shellcheck disable=SC2329  # Invoked indirectly by the EXIT trap below.
cleanup_staging() {
  local status=$?
  trap - EXIT
  set +e
  remove_common_scratch
  exit "$status"
}

if [ "$mode" = production ]; then
  trap finish_production EXIT
elif [ "$mode" = staging ]; then
  trap cleanup_staging EXIT
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

if [ "$mode" = staging ]; then
  : "${GITHUB_STEP_SUMMARY:?}"
  : "${SUBMISSION_ID:?}"
  "$PYTHON_BIN" scripts/release_controller.py unwrap-identity \
    --request "$RUNNER_TEMP/unwrap-request.json" \
    --response "$RUNNER_TEMP/unwrap-response.json" \
    --metadata "$RUNNER_TEMP/unwrap-metadata.json" \
    --output "$RUNNER_TEMP/identity.age"
  test "$("$RUNNER_TEMP/age-bin" --version)" = v1.3.1
  "$RUNNER_TEMP/age-bin" --decrypt --identity "$RUNNER_TEMP/identity.age" \
    --output "$RUNNER_TEMP/source.tar.gz" "$RUNNER_TEMP/archive.tar.age"
  expected_plaintext=$(jq -r .sha256_plaintext_tar \
    "$RUNNER_TEMP/archive-sidecar.json")
  actual_plaintext=$(sha256sum "$RUNNER_TEMP/source.tar.gz" | awk '{print $1}')
  test "$actual_plaintext" = "$expected_plaintext"
  PYTHONPATH=scripts "$PYTHON_BIN" -c \
    'import pathlib; from reconstruct_release import _read_release_sources; _read_release_sources(pathlib.Path("'"$RUNNER_TEMP"'/source.tar.gz"))'
  ciphertext_digest=$(jq -r .sha256_ciphertext \
    "$RUNNER_TEMP/archive-sidecar.json")
  audit_commit=$(jq -er .request.archive.archive_commit \
    "$RUNNER_TEMP/release-plan.json")
  {
    echo '### Credentialed staging release boundary passed'
    echo
    echo "- submission: \`$SUBMISSION_ID\`"
    echo "- audit commit: \`$audit_commit\`"
    echo "- ciphertext SHA-256: \`$ciphertext_digest\`"
    echo '- plaintext matched the private sidecar and was discarded without publication or artifact upload'
  } >> "$GITHUB_STEP_SUMMARY"
  exit 0
fi

expected_release_head=$(jq -er .request.controller.release_commit \
  "$RUNNER_TEMP/release-plan.json")
test "$(git rev-parse HEAD)" = "$expected_release_head"
started_event_id=$(jq -er .event_id "$RUNNER_TEMP/release-started-event.json")
started_event_path="events/${started_event_id:0:2}/$started_event_id.json"
git -C state show "HEAD:$started_event_path" \
  > "$RUNNER_TEMP/committed-release-started-event.json"
cmp "$RUNNER_TEMP/release-started-event.json" \
  "$RUNNER_TEMP/committed-release-started-event.json"
"$PYTHON_BIN" scripts/verify_release_state_contract.py \
  --environment production \
  --state-root state
"$PYTHON_BIN" state/scripts/state.py --root state validate
"$PYTHON_BIN" state/scripts/state.py --root state materialize \
  --output "$RUNNER_TEMP/state-views"

"$PYTHON_BIN" scripts/release_controller.py unwrap-identity \
  --request "$RUNNER_TEMP/unwrap-request.json" \
  --response "$RUNNER_TEMP/unwrap-response.json" \
  --metadata "$RUNNER_TEMP/unwrap-metadata.json" \
  --output "$RUNNER_TEMP/identity.age"
test "$("$RUNNER_TEMP/age-bin" --version)" = v1.3.1
"$RUNNER_TEMP/age-bin" --decrypt --identity "$RUNNER_TEMP/identity.age" \
  --output "$RUNNER_TEMP/source.tar.gz" "$RUNNER_TEMP/archive.tar.age"
expected_plaintext=$(jq -er .sha256_plaintext_tar \
  "$RUNNER_TEMP/archive-sidecar.json")
actual_plaintext=$(sha256sum "$RUNNER_TEMP/source.tar.gz" | awk '{print $1}')
test "$actual_plaintext" = "$expected_plaintext"
trusted_now=$(date --utc +%Y-%m-%dT%H:%M:%S.000Z)
"$PYTHON_BIN" scripts/reconstruct_release.py \
  "$RUNNER_TEMP/release-plan.json" \
  --plaintext-tar "$RUNNER_TEMP/source.tar.gz" \
  --trusted-as-of "$trusted_now" \
  --state-acceptance-snapshot \
    "$RUNNER_TEMP/state-views/release-acceptance-snapshot.json" \
  --output-root "$RUNNER_TEMP/reconstructed"
"$PYTHON_BIN" scripts/validate_manifest.py \
  "$RUNNER_TEMP/reconstructed/release-manifest.json" \
  --trusted-as-of "$trusted_now" \
  --state-acceptance-snapshot \
    "$RUNNER_TEMP/state-views/release-acceptance-snapshot.json" \
  --bundle-root "$RUNNER_TEMP/reconstructed"
rm -f "$RUNNER_TEMP/source.tar.gz" "$RUNNER_TEMP/archive.tar.age" \
  "$RUNNER_TEMP/archive-sidecar.json" "$RUNNER_TEMP/identity.age"

result_id=$(jq -r .request.result.result_id "$RUNNER_TEMP/release-plan.json")
release_path=$(jq -r .request.release.path "$RUNNER_TEMP/release-plan.json")
submission_id=$(jq -r .request.submission.submission_id \
  "$RUNNER_TEMP/release-plan.json")
"$PYTHON_BIN" scripts/classify_release_publication.py \
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
  "$PYTHON_BIN" scripts/validate_manifest.py "$RUNNER_TEMP/publishing-manifest.json" \
    --trusted-as-of "$generated_at" \
    --state-acceptance-snapshot \
      "$RUNNER_TEMP/state-views/release-acceptance-snapshot.json" \
    --bundle-root .
  tree_digest=$(jq -er --arg result "$result_id" --arg path "$release_path" \
    '.entries[] | select(.result_id == $result and .release_path == $path) | .release_tree_sha256' \
    "$RUNNER_TEMP/publishing-manifest.json")
elif [ "$publication_kind" = new ]; then
  mkdir -p "$(dirname "$release_path")" sources
  cp -a "$RUNNER_TEMP/reconstructed/$release_path" "$release_path"
  if [ "$(jq -r .bundle_exists \
    "$RUNNER_TEMP/release-publication-classification.json")" = false ]; then
    cp "$RUNNER_TEMP/reconstructed/sources/$submission_id.tar.gz" \
      "sources/$submission_id.tar.gz"
  fi
  cp "$RUNNER_TEMP/reconstructed/release-manifest.json" release-manifest.json
  "$PYTHON_BIN" scripts/validate_manifest.py release-manifest.json \
    --trusted-as-of "$trusted_now" \
    --state-acceptance-snapshot \
      "$RUNNER_TEMP/state-views/release-acceptance-snapshot.json" \
    --bundle-root .
  tree_digest=$(jq -er --arg result "$result_id" --arg path "$release_path" \
    '.entries[] | select(.result_id == $result and .release_path == $path) | .release_tree_sha256' \
    release-manifest.json)
  git config user.name lean-eval-release-controller
  git config user.email lean-eval-release-controller@users.noreply.github.com
  git add "$release_path" "sources/$submission_id.tar.gz" release-manifest.json
  git diff --cached --check
  git commit -m "Publish delayed source $result_id"
  git push origin HEAD:main
  repository_commit=$(git rev-parse HEAD)
else
  echo "publication classifier returned an unknown kind" >&2
  exit 1
fi
[[ "$tree_digest" =~ ^[0-9a-f]{64}$ ]]
publication_recorded=true

"$PYTHON_BIN" scripts/release_controller.py state-event published \
  --started-event "$RUNNER_TEMP/release-started-event.json" \
  --trusted-now "$(date --utc +%Y-%m-%dT%H:%M:%S.000Z)" \
  --repository-commit "$repository_commit" \
  --tree-digest "$tree_digest" \
  --release-path "$release_path" \
  --output "$RUNNER_TEMP/release-terminal-event.json"
state_head=$(git -C state rev-parse HEAD)
"$PYTHON_BIN" scripts/release_controller.py stage-state-transition \
  --state-root state \
  --event "$RUNNER_TEMP/release-terminal-event.json" \
  --protected-state-head "$state_head" \
  --output "$RUNNER_TEMP/release-terminal-transition.json"
event_id=$(jq -er .event_id "$RUNNER_TEMP/release-terminal-event.json")
event_path=$(jq -er .event_path "$RUNNER_TEMP/release-terminal-transition.json")
status_path=$(jq -er .status_path "$RUNNER_TEMP/release-terminal-transition.json")
test -f "state/$event_path"
test -f "state/$status_path"
"$PYTHON_BIN" state/scripts/state.py --root state \
  --protected-main-commit "$state_head" validate
"$PYTHON_BIN" scripts/release_controller.py verify-staged-state-transition \
  --state-root state \
  --event "$RUNNER_TEMP/release-terminal-event.json" \
  --plan "$RUNNER_TEMP/release-terminal-transition.json"
git -C state commit -m "Record published release $event_id"
test "$(git -C state rev-parse HEAD^)" = "$state_head"
git -C state push origin HEAD:main
