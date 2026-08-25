#!/usr/bin/env bash

# Review mirror for the empty-environment literal in both release workflows.
# The workflows execute their embedded copies, never this checked-out file.

# shellcheck disable=SC2154  # Assigned inside this first-command EXIT trap.
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
if [ "${LITERAL_CLEAN_EXIT:-false}" != true ] && [ "$status" -eq 0 ]; then
  status=1
fi
exit "$status"' EXIT INT TERM
set -euo pipefail
umask 077

mode=${1:-}
case "$mode" in
  probe|production|staging) ;;
  *) echo "literal release sanitizer mode is invalid" >&2; exit 2 ;;
esac

if [ "$mode" = probe ]; then
  HOME=${HOME:-}
  PATH=${PATH:-}
  RUNNER_TEMP=${RUNNER_TEMP:-}
else
  [ "$#" -eq 5 ]
  HOME=$2
  PYTHON_BIN=$3
  RUNNER_TEMP=$4
  GITHUB_STEP_SUMMARY=$5
  PATH=/usr/local/bin:/usr/bin:/bin
fi
export HOME PATH

authority_names=(
  AWS_ACCESS_KEY_ID
  AWS_SECRET_ACCESS_KEY
  AWS_SESSION_TOKEN
  ACTIONS_ID_TOKEN_REQUEST_TOKEN
  ACTIONS_ID_TOKEN_REQUEST_URL
)

: "${HOME:?}"
: "${PATH:?}"
: "${RUNNER_TEMP:?}"
case "$HOME:$RUNNER_TEMP" in
  /*:/*) ;;
  *) echo "literal release sanitizer received a relative path" >&2; exit 1 ;;
esac
[ -d "$HOME" ] && [ ! -L "$HOME" ]
[ -d "$RUNNER_TEMP" ] && [ ! -L "$RUNNER_TEMP" ]

for name in "${authority_names[@]}"; do
  if [[ -v "$name" ]]; then
    echo "authority variable survived literal sanitized exec: $name" >&2
    exit 1
  fi
done

proc="/proc/self/environ"
if [ ! -r "$proc" ]; then
  echo "cannot prove literal sanitized process environment: $proc" >&2
  exit 1
fi
while IFS= read -r -d '' entry; do
  for name in "${authority_names[@]}"; do
    case "$entry" in
      "$name="*)
        echo "authority remains process-readable in $proc: $name" >&2
        exit 1
        ;;
    esac
  done
done < "$proc"

count=0
total=0
for root in "$RUNNER_TEMP/_runner_file_commands" "$HOME/.aws"; do
  [ ! -e "$root" ] || [ -d "$root" ] || {
    echo "authority scan root is unsafe: $root" >&2
    exit 1
  }
  [ ! -L "$root" ] || {
    echo "authority scan root is a symlink: $root" >&2
    exit 1
  }
  [ -d "$root" ] || continue
  unsafe=$(find -P "$root" -mindepth 1 \
    \( -type l -o \( ! -type d ! -type f \) \) -print -quit)
  if [ -n "$unsafe" ]; then
    echo "authority scan encountered an unsafe path: $unsafe" >&2
    exit 1
  fi
  while IFS= read -r -d '' path; do
    size=$(stat --format=%s -- "$path")
    count=$((count + 1))
    total=$((total + size))
    if [ "$count" -gt 1024 ] || [ "$size" -gt 8388608 ] || \
      [ "$total" -gt 33554432 ]; then
      echo "authority scan exceeded its size limit" >&2
      exit 1
    fi
    if LC_ALL=C grep --text --quiet --extended-regexp \
      'AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)|ACTIONS_ID_TOKEN_REQUEST_(TOKEN|URL)|aws_(access_key_id|secret_access_key|session_token)' \
      "$path"; then
      echo "authority name remains in runner file: $path" >&2
      exit 1
    fi
  done < <(find -P "$root" -type f -print0)
done

if [ "$mode" = probe ]; then
  LITERAL_CLEAN_EXIT=true
  exit 0
fi

: "${PYTHON_BIN:?}"
: "${GITHUB_STEP_SUMMARY:?}"
case "$PYTHON_BIN:$GITHUB_STEP_SUMMARY" in
  /*:/*) ;;
  *) echo "literal release sanitizer received a relative path" >&2; exit 1 ;;
esac
[ -x "$PYTHON_BIN" ] && [ ! -L "$PYTHON_BIN" ]

proof="$RUNNER_TEMP/pre-authority-stage.json"
[ -f "$proof" ] && [ ! -L "$proof" ]
jq -e --arg mode "$mode" '
  type == "object" and
  (keys == [
    "age_binary_sha256",
    "archive_ciphertext_sha256",
    "archive_sidecar_sha256",
    "authority_tail_blob",
    "mode",
    "plan_sha256",
    "release_commit",
    "schema_version",
    "started_event_sha256",
    "state_commit"
  ]) and
  .schema_version == 1 and (.schema_version | type) == "number" and
  .mode == $mode and
  (.release_commit | test("^[0-9a-f]{40}$")) and
  (.authority_tail_blob | test("^[0-9a-f]{40}$")) and
  (.plan_sha256 | test("^[0-9a-f]{64}$")) and
  (.archive_sidecar_sha256 | test("^[0-9a-f]{64}$")) and
  (.archive_ciphertext_sha256 | test("^[0-9a-f]{64}$")) and
  (.age_binary_sha256 | test("^[0-9a-f]{64}$")) and
  (if $mode == "production" then
    (.state_commit | test("^[0-9a-f]{40}$")) and
    (.started_event_sha256 | test("^[0-9a-f]{64}$"))
  else
    .state_commit == "" and .started_event_sha256 == ""
  end)
' "$proof" >/dev/null

check_digest() {
  local field=$1 path=$2 expected actual
  expected=$(jq -er --arg field "$field" '.[$field]' "$proof")
  actual=$(sha256sum -- "$path" | awk '{print $1}')
  test "$actual" = "$expected"
}

check_digest plan_sha256 "$RUNNER_TEMP/release-plan.json"
check_digest archive_sidecar_sha256 "$RUNNER_TEMP/archive-sidecar.json"
check_digest archive_ciphertext_sha256 "$RUNNER_TEMP/archive.tar.age"
check_digest age_binary_sha256 "$RUNNER_TEMP/age-bin"
if [ "$mode" = production ]; then
  check_digest started_event_sha256 "$RUNNER_TEMP/release-started-event.json"
fi

release_commit=$(jq -er .release_commit "$proof")
tail_blob=$(jq -er .authority_tail_blob "$proof")
test "$(git rev-parse HEAD)" = "$release_commit"
test "$(git rev-parse HEAD:scripts/release_authority_tail.sh)" = "$tail_blob"
test "$(git hash-object scripts/release_authority_tail.sh)" = "$tail_blob"
if [ "$mode" = production ]; then
  test -z "$(git status --porcelain --untracked-files=all -- \
    . ':(exclude)state')"
else
  test -z "$(git status --porcelain --untracked-files=all)"
fi
git diff --quiet HEAD --
git diff --cached --quiet HEAD --
if [ "$mode" = production ]; then
  state_commit=$(jq -er .state_commit "$proof")
  test "$(git -C state rev-parse HEAD)" = "$state_commit"
  test -z "$(git -C state status --porcelain --untracked-files=all)"
fi

test "$($PYTHON_BIN -I -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')" = 3.11

trap - EXIT INT TERM
exec env -i \
  HOME="$HOME" \
  PATH="$PATH" \
  LITERAL_AUTHORITY_PROOF=release-authority-sanitized-v1 \
  PYTHON_BIN="$PYTHON_BIN" \
  RUNNER_TEMP="$RUNNER_TEMP" \
  GITHUB_STEP_SUMMARY="$GITHUB_STEP_SUMMARY" \
  bash --noprofile --norc scripts/release_authority_tail.sh "$mode"
