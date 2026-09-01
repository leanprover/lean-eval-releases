#!/usr/bin/env python3
"""Prepare one release unwrap and canonical State transition events.

This trusted helper performs no network, Git, AWS, decryption, or publication
operation.  It validates the immutable release plan and schema-version-3 audit
sidecar, builds one five-minute release-purpose unwrap request, validates the
Lambda response, and constructs source-free State events for the workflow.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
from typing import Any

if __package__:
    from .reconstruct_release import _validate_execution_plan
    from .release_orchestrator import (
        COMMIT,
        DIGEST,
        PROBLEM,
        REPOSITORY,
        RESULT_ID,
        UUID7,
        ReleaseError,
        plan_next,
        validate_release_queue,
    )
    from .release_tree import tree_digest
else:
    from reconstruct_release import _validate_execution_plan
    from release_orchestrator import (
        COMMIT,
        DIGEST,
        PROBLEM,
        REPOSITORY,
        RESULT_ID,
        UUID7,
        ReleaseError,
        plan_next,
        validate_release_queue,
    )
    from release_tree import tree_digest

ARCHIVE_KEY_ID = re.compile(r"ak1_[0-9a-f]{64}")
ADAPTER = re.compile(r"[a-z][a-z0-9-]{0,63}-v[1-9][0-9]*")
AGE_RECIPIENT = re.compile(r"age1[0-9a-z]{40,4090}")
CAPABILITY_DIGEST = re.compile(r"uc1_[0-9a-f]{64}")
AWS_REQUEST_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)
REASON = re.compile(r"[a-z][a-z0-9_]{1,63}")
BASE64 = re.compile(r"[A-Za-z0-9+/]+={0,2}")
MAX_WRAPPED_BYTES = 16_384
MAX_IDENTITY_BYTES = 4096
MAX_SAFE_INTEGER = 9_007_199_254_740_991

AUTHORITY_DESCRIPTOR_FIELDS = {
    "schema_version",
    "environment",
    "release_commit",
    "state_commit",
    "started_event_id",
    "archive_repository",
    "archive_commit",
    "archive_path",
    "archive_ciphertext_sha256",
    "eligible_at",
    "plan_sha256",
    "started_event_sha256",
}

RELEASE_STATUS_FIELDS = {
    "schema_version",
    "result_id",
    "authority_event_id",
    "status",
    "release_event_id",
    "release_revision",
    "supersedes_release_event_id",
}
CONTROLLER_RELEASE_TRANSITIONS = {
    "release.started": ({"scheduled", "failed"}, "running"),
    "release.published": ({"running"}, "published"),
    "release.failed": ({"running"}, "failed"),
}
STATE_TRANSITION_PLAN_FIELDS = {
    "schema_version",
    "protected_state_head",
    "event_path",
    "status_path",
    "status_before_sha256",
    "status_after",
}

SIDECAR_REQUIRED_FIELDS = {
    "schema_version",
    "submission_id",
    "submission_repo",
    "submission_ref",
    "submission_kind",
    "submission_public",
    "submitter",
    "model",
    "size_bytes_plaintext_tar",
    "sha256_plaintext_tar",
    "key_envelope",
    "sha256_ciphertext",
    "size_bytes_ciphertext",
    "archived_at",
    "benchmark_commit",
    "archiver_workflow_run",
}
SIDECAR_OPTIONAL_FIELDS = {
    "production_description",
    "solution_publication_status",
    "solution_publication_date",
    "problem_ids",
    "evaluator_verdict",
}

ENVELOPE_FIELDS = {
    "schema_version",
    "submission_id",
    "archive_ciphertext_sha256",
    "data_key_id",
    "age_recipient",
    "adapter",
    "wrapped_identity",
}
CAPABILITY_FIELDS = {
    "schema_version",
    "purpose",
    "request_id",
    "submission_id",
    "archive_repository",
    "archive_commit",
    "archive_path",
    "archive_ciphertext_sha256",
    "data_key_id",
    "runner_nonce",
    "issued_at",
    "expires_at",
    "max_uses",
}
UNWRAP_FIELDS = {
    "schema_version",
    "operation",
    "adapter",
    "envelope",
    "capability",
    "expected_purpose",
    "expected_runner_nonce",
}


class ControllerError(ValueError):
    """A release-controller input or provider response is unsafe."""


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ControllerError(f"{label} must be an object with string keys")
    return value


def _fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ControllerError(
            f"{label} fields are not canonical; "
            f"missing={sorted(expected - set(value))}, extra={sorted(set(value) - expected)}"
        )


def _match(pattern: re.Pattern[str], value: Any, label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ControllerError(f"{label} is not canonical")
    return value


def _read(path: pathlib.Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ControllerError(f"{label} is not one UTF-8 JSON object") from error


def _write(path: pathlib.Path, value: Any) -> None:
    if path.exists() or path.is_symlink():
        raise ControllerError(f"refusing to overwrite {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def canonical_json(value: Any) -> str:
    """Return State's byte-canonical operational-view representation."""
    return json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n"


def authority_descriptor(
    plan_value: Any,
    state_commit: str,
    release_commit: str,
    environment: str,
    started_event_value: Any | None = None,
) -> dict[str, Any]:
    """Reduce a private plan to the fixed, disclosure-safe cross-job handoff."""
    try:
        plan = _validate_execution_plan(plan_value)
    except (ReleaseError, ValueError, TypeError) as error:
        raise ControllerError(str(error)) from error
    _match(COMMIT, state_commit, "authority State commit")
    _match(COMMIT, release_commit, "authority release commit")
    if environment not in {"production", "staging"}:
        raise ControllerError("authority environment is invalid")
    request = plan["request"]
    controller = request.get("controller")
    if controller is not None and (
        controller["environment"] != environment
        or controller["release_commit"] != release_commit
    ):
        raise ControllerError("authority commits/environment do not match the plan")
    archive = request["archive"]
    descriptor = {
        "schema_version": 1,
        "environment": environment,
        "release_commit": release_commit,
        "state_commit": state_commit,
        "started_event_id": "",
        "archive_repository": archive["archive_repository"],
        "archive_commit": archive["archive_commit"],
        "archive_path": archive["archive_path"],
        "archive_ciphertext_sha256": archive["archive_ciphertext_sha256"],
        "eligible_at": request["release"]["eligible_at"],
        "plan_sha256": hashlib.sha256(canonical_json(plan).encode("utf-8")).hexdigest(),
        "started_event_sha256": "",
    }
    if environment == "production":
        if started_event_value is None:
            raise ControllerError("production authority requires release.started")
        started = _object(started_event_value, "release.started event")
        if started.get("event_type") != "release.started":
            raise ControllerError("authority event is not release.started")
        if started.get("subject_id") != request["result"]["result_id"]:
            raise ControllerError("release.started does not identify the plan result")
        descriptor["started_event_id"] = _match(
            UUID7, started.get("event_id"), "release.started event_id"
        )
        descriptor["started_event_sha256"] = hashlib.sha256(
            canonical_json(started).encode("utf-8")
        ).hexdigest()
    elif started_event_value is not None:
        raise ControllerError("staging authority must not include release.started")
    if set(descriptor) != AUTHORITY_DESCRIPTOR_FIELDS:
        raise AssertionError("authority descriptor fields drifted")
    return descriptor


def result_release_status_path(result_id: str) -> pathlib.PurePosixPath:
    _match(RESULT_ID, result_id, "result_id")
    return pathlib.PurePosixPath(
        "views", "result-release-status", result_id[3:5], f"{result_id}.json"
    )


def release_event_path(event_id: str) -> pathlib.PurePosixPath:
    _match(UUID7, event_id, "release event_id")
    return pathlib.PurePosixPath(
        "events", event_id.replace("-", "")[:2], f"{event_id}.json"
    )


def plan_release_state_transition(
    current_value: Any,
    event_value: Any,
    protected_state_head: str,
) -> dict[str, Any]:
    """Bind one controller event and status replacement to one State head."""
    _match(COMMIT, protected_state_head, "protected State head")
    current = _object(current_value, "current result release status")
    _fields(current, RELEASE_STATUS_FIELDS, "current result release status")
    if type(current["schema_version"]) is not int or current["schema_version"] != 2:
        raise ControllerError("current result release status schema_version is invalid")
    result_id = _match(
        RESULT_ID, current["result_id"], "current result release status result_id"
    )
    _match(
        UUID7,
        current["authority_event_id"],
        "current result release status authority_event_id",
    )
    current_status = current["status"]
    if current_status not in {
        "not_scheduled",
        "scheduled",
        "running",
        "published",
        "failed",
        "cancelled",
        "removed",
    }:
        raise ControllerError("current result release status is invalid")
    release_event_id = current["release_event_id"]
    release_revision = current["release_revision"]
    if (
        isinstance(release_revision, bool)
        or not isinstance(release_revision, int)
        or not 0 <= release_revision <= MAX_SAFE_INTEGER
    ):
        raise ControllerError("current result release status revision is invalid")
    predecessor = current["supersedes_release_event_id"]
    if current_status == "not_scheduled":
        if (
            release_event_id is not None
            or release_revision != 0
            or predecessor is not None
        ):
            raise ControllerError(
                "not_scheduled result release status must be the revision-zero head"
            )
    else:
        _match(
            UUID7,
            release_event_id,
            "current result release status release_event_id",
        )
        if release_revision < 1:
            raise ControllerError("released result status revision must be positive")
        if release_revision == 1:
            if predecessor is not None:
                raise ControllerError(
                    "first release status revision must not name a predecessor"
                )
        else:
            _match(
                UUID7,
                predecessor,
                "current result release status supersedes_release_event_id",
            )

    event = _object(event_value, "release transition event")
    expected_event_fields = {
        "schema_version",
        "event_id",
        "event_type",
        "occurred_at",
        "subject_id",
        "causation_event_id",
        "actor",
        "payload",
    }
    _fields(event, expected_event_fields, "release transition event")
    if event["schema_version"] != 1 or isinstance(event["schema_version"], bool):
        raise ControllerError("release transition event schema_version is invalid")
    event_id = _match(UUID7, event["event_id"], "release transition event_id")
    kind = event["event_type"]
    transition = CONTROLLER_RELEASE_TRANSITIONS.get(kind)
    if transition is None:
        raise ControllerError("release transition is not controller-writable")
    allowed_current, next_status = transition
    if event["subject_id"] != result_id:
        raise ControllerError("release transition subject does not match status result")
    if current_status not in allowed_current:
        raise ControllerError(
            f"release transition {kind} cannot follow status {current_status}"
        )
    if event["causation_event_id"] != release_event_id:
        raise ControllerError(
            "release transition cause does not match current status release event"
        )
    if event.get("actor") != {"kind": "system"}:
        raise ControllerError("release transition must be system-authored")
    if release_revision == MAX_SAFE_INTEGER:
        raise ControllerError("current result release status revision is exhausted")

    after = {
        **current,
        "status": next_status,
        "release_event_id": event_id,
        "release_revision": release_revision + 1,
        "supersedes_release_event_id": release_event_id,
    }
    status_path = result_release_status_path(result_id).as_posix()
    return {
        "schema_version": 1,
        "protected_state_head": protected_state_head,
        "event_path": release_event_path(event_id).as_posix(),
        "status_path": status_path,
        "status_before_sha256": hashlib.sha256(
            canonical_json(current).encode("utf-8")
        ).hexdigest(),
        "status_after": after,
    }


def _git(
    root: pathlib.Path, *arguments: str, check: bool = True
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            ["git", "--no-replace-objects", "-C", str(root), *arguments],
            check=check,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise ControllerError("State Git inspection failed closed") from error


def _state_root_at_head(
    state_root: pathlib.Path, protected_state_head: str
) -> pathlib.Path:
    root = state_root.resolve(strict=True)
    if state_root.is_symlink() or not root.is_dir():
        raise ControllerError("State root must be a regular directory")
    top = pathlib.Path(
        _git(root, "rev-parse", "--show-toplevel").stdout.decode("utf-8").strip()
    ).resolve()
    if top != root:
        raise ControllerError("State root is not the Git toplevel")
    _match(COMMIT, protected_state_head, "protected State head")
    head = _git(root, "rev-parse", "HEAD").stdout.decode("ascii").strip()
    if head != protected_state_head:
        raise ControllerError("State checkout moved from the protected State head")
    return root


def verify_staged_release_state_transition(
    state_root: pathlib.Path,
    event_value: Any,
    plan_value: Any,
) -> None:
    """Reassert one exact two-path State transition immediately before commit."""
    plan = _object(plan_value, "State transition plan")
    _fields(plan, STATE_TRANSITION_PLAN_FIELDS, "State transition plan")
    if plan["schema_version"] != 1 or isinstance(plan["schema_version"], bool):
        raise ControllerError("State transition plan schema_version is invalid")
    protected_state_head = _match(
        COMMIT, plan["protected_state_head"], "protected State head"
    )
    root = _state_root_at_head(state_root, protected_state_head)
    event = _object(event_value, "release transition event")
    subject = _match(RESULT_ID, event.get("subject_id"), "release transition subject")
    relative_status = result_release_status_path(subject)
    try:
        status_before_raw = _git(
            root,
            "show",
            f"{protected_state_head}:{relative_status.as_posix()}",
        ).stdout
        status_before = json.loads(status_before_raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ControllerError(
            "protected targeted result release status is unreadable"
        ) from error
    if status_before_raw != canonical_json(status_before).encode("utf-8"):
        raise ControllerError(
            "protected targeted result release status is not byte-canonical"
        )
    expected_plan = plan_release_state_transition(
        status_before, event, protected_state_head
    )
    if plan != expected_plan:
        raise ControllerError(
            "State transition plan does not match the event and protected State head"
        )

    relative_event = pathlib.PurePosixPath(plan["event_path"])
    staged = {
        line
        for line in _git(root, "diff", "--cached", "--name-only", "--")
        .stdout.decode("utf-8")
        .splitlines()
        if line
    }
    expected_paths = {relative_event.as_posix(), relative_status.as_posix()}
    if staged != expected_paths:
        raise ControllerError(
            "State transition cached diff is not the exact event/status pair"
        )
    expected_raw = {
        relative_event: canonical_json(event).encode("utf-8"),
        relative_status: canonical_json(plan["status_after"]).encode("utf-8"),
    }
    for relative, raw in expected_raw.items():
        if _git(root, "show", f":{relative.as_posix()}").stdout != raw:
            raise ControllerError(
                "State transition cached bytes are not the expected canonical bytes"
            )
    unstaged = _git(
        root,
        "diff",
        "--name-only",
        "--",
        relative_event.as_posix(),
        relative_status.as_posix(),
    ).stdout
    if unstaged:
        raise ControllerError("State transition paths changed after staging")


def stage_release_state_transition(
    state_root: pathlib.Path,
    event_value: Any,
    protected_state_head: str,
) -> dict[str, Any]:
    """Stage exactly one release event and its targeted status replacement."""
    root = _state_root_at_head(state_root, protected_state_head)
    dirty = _git(
        root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--",
        "events",
        "state.json",
        "views",
    ).stdout
    if dirty:
        raise ControllerError("State event and operational-view tree is not clean")

    event = _object(event_value, "release transition event")
    subject = _match(RESULT_ID, event.get("subject_id"), "release transition subject")
    relative_status = result_release_status_path(subject)
    status_path = root.joinpath(*relative_status.parts)
    if status_path.is_symlink() or not status_path.is_file():
        raise ControllerError("targeted result release status must be a regular file")
    try:
        raw = status_path.read_bytes()
        current = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ControllerError(
            "targeted result release status is missing or unreadable"
        ) from error
    if raw != canonical_json(current).encode("utf-8"):
        raise ControllerError("targeted result release status is not byte-canonical")
    committed = _git(
        root,
        "show",
        f"{protected_state_head}:{relative_status.as_posix()}",
    ).stdout
    if committed != raw:
        raise ControllerError(
            "targeted result release status is not bound to the protected State head"
        )
    plan = plan_release_state_transition(current, event, protected_state_head)
    relative_event = pathlib.PurePosixPath(plan["event_path"])
    event_path = root.joinpath(*relative_event.parts)
    if event_path.exists() or event_path.is_symlink():
        raise ControllerError("release transition event path already exists")
    if (
        _git(
            root,
            "cat-file",
            "-e",
            f"{protected_state_head}:{relative_event.as_posix()}",
            check=False,
        ).returncode
        == 0
    ):
        raise ControllerError("release transition event already exists in State")

    event_path.parent.mkdir(parents=True, exist_ok=True)
    event_raw = canonical_json(event).encode("utf-8")
    status_after_raw = canonical_json(plan["status_after"]).encode("utf-8")
    event_path.write_bytes(event_raw)
    status_path.write_bytes(status_after_raw)
    _git(root, "add", "--", relative_event.as_posix(), relative_status.as_posix())
    verify_staged_release_state_transition(root, event, plan)
    return plan


def parse_timestamp(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str) or value.startswith("0000-"):
        raise ControllerError(f"{label} is not canonical UTC milliseconds")
    try:
        parsed = dt.datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise ControllerError(f"{label} is not canonical UTC milliseconds") from error
    if canonical_timestamp(parsed) != value:
        raise ControllerError(f"{label} is not canonical UTC milliseconds")
    return parsed


def canonical_timestamp(value: dt.datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != dt.timedelta(0):
        raise ControllerError("trusted time must be timezone-aware UTC")
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def event_timestamp(trusted_now: str, cause_timestamp: str) -> str:
    now = parse_timestamp(trusted_now, "trusted_now")
    cause = parse_timestamp(cause_timestamp, "causation occurred_at")
    return canonical_timestamp(max(now, cause + dt.timedelta(milliseconds=1)))


def uuid7(timestamp: dt.datetime, random_bytes: bytes | None = None) -> str:
    if timestamp.tzinfo is None or timestamp.utcoffset() != dt.timedelta(0):
        raise ControllerError("UUIDv7 time must be timezone-aware UTC")
    milliseconds = int(timestamp.timestamp() * 1000)
    if not 0 <= milliseconds <= 0xFFFFFFFFFFFF:
        raise ControllerError("UUIDv7 time is outside its 48-bit range")
    randomness = os.urandom(10) if random_bytes is None else random_bytes
    if not isinstance(randomness, bytes) or len(randomness) != 10:
        raise ControllerError("UUIDv7 randomness must contain exactly ten bytes")
    raw = bytearray(16)
    raw[:6] = milliseconds.to_bytes(6, "big")
    raw[6] = 0x70 | (randomness[0] & 0x0F)
    raw[7] = randomness[1]
    raw[8] = 0x80 | (randomness[2] & 0x3F)
    raw[9:] = randomness[3:]
    encoded = raw.hex()
    return f"{encoded[:8]}-{encoded[8:12]}-{encoded[12:16]}-{encoded[16:20]}-{encoded[20:]}"


def archive_key_id(submission_id: str, recipient: str) -> str:
    _match(UUID7, submission_id, "submission_id")
    _match(AGE_RECIPIENT, recipient, "age_recipient")
    value = f"{submission_id}\0{recipient}".encode("ascii")
    return "ak1_" + hashlib.sha256(b"lean-eval-archive-key-v1\0" + value).hexdigest()


def _canonical_base64(value: Any, label: str, maximum: int) -> bytes:
    raw = _match(BASE64, value, label)
    if len(raw) % 4 != 0:
        raise ControllerError(f"{label} is not canonical base64")
    try:
        decoded = base64.b64decode(raw, validate=True)
    except ValueError as error:
        raise ControllerError(f"{label} is not valid base64") from error
    if (
        not decoded
        or len(decoded) > maximum
        or base64.b64encode(decoded).decode("ascii") != raw
    ):
        raise ControllerError(
            f"{label} is empty, noncanonical, or exceeds its size limit"
        )
    return decoded


def _bounded_integer(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER:
        raise ControllerError(f"{label} must be a nonnegative safe integer")
    return value


def validate_sidecar(value: Any, ciphertext: bytes) -> dict[str, Any]:
    sidecar = _object(value, "archive sidecar")
    missing = SIDECAR_REQUIRED_FIELDS - set(sidecar)
    extra = set(sidecar) - SIDECAR_REQUIRED_FIELDS - SIDECAR_OPTIONAL_FIELDS
    if missing or extra:
        raise ControllerError(
            "archive sidecar fields are not canonical; "
            f"missing={sorted(missing)}, extra={sorted(extra)}"
        )
    if type(sidecar["schema_version"]) is not int or sidecar["schema_version"] != 3:
        raise ControllerError("archive sidecar schema_version must be integer 3")
    _match(UUID7, sidecar["submission_id"], "sidecar submission_id")
    _match(REPOSITORY, sidecar["submission_repo"], "sidecar submission_repo")
    _match(COMMIT, sidecar["submission_ref"], "sidecar submission_ref")
    if sidecar["submission_kind"] not in {"github_repo", "gist"}:
        raise ControllerError("sidecar submission_kind is invalid")
    if type(sidecar["submission_public"]) is not bool:
        raise ControllerError("sidecar submission_public must be boolean")
    for field in ("submitter", "model"):
        value = sidecar[field]
        if (
            not isinstance(value, str)
            or not value.strip()
            or len(value.encode("utf-8")) > 256
        ):
            raise ControllerError(f"sidecar {field} is invalid")
    _bounded_integer(sidecar["size_bytes_plaintext_tar"], "sidecar plaintext size")
    _match(DIGEST, sidecar["sha256_plaintext_tar"], "sidecar plaintext digest")
    ciphertext_size = _bounded_integer(
        sidecar["size_bytes_ciphertext"], "sidecar ciphertext size"
    )
    if ciphertext_size != len(ciphertext):
        raise ControllerError(
            "sidecar ciphertext size does not match the archive bytes"
        )
    _match(DIGEST, sidecar["sha256_ciphertext"], "sidecar ciphertext digest")
    _match(COMMIT, sidecar["benchmark_commit"], "sidecar benchmark commit")
    archived_at = sidecar["archived_at"]
    if (
        not isinstance(archived_at, str)
        or re.fullmatch(
            r"(?!0000-)[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
            archived_at,
        )
        is None
    ):
        raise ControllerError("sidecar archived_at is not canonical UTC seconds")
    try:
        parsed_archive_time = dt.datetime.fromisoformat(archived_at[:-1] + "+00:00")
    except ValueError as error:
        raise ControllerError("sidecar archived_at is not a real timestamp") from error
    if parsed_archive_time.strftime("%Y-%m-%dT%H:%M:%SZ") != archived_at:
        raise ControllerError("sidecar archived_at is not a real timestamp")
    workflow_run = sidecar["archiver_workflow_run"]
    if (
        not isinstance(workflow_run, str)
        or re.fullmatch(
            r"https://github\.com/leanprover/lean-eval-submissions/actions/runs/[1-9][0-9]*",
            workflow_run,
        )
        is None
    ):
        raise ControllerError("sidecar archiver_workflow_run is invalid")
    if "problem_ids" in sidecar:
        problems = sidecar["problem_ids"]
        if (
            not isinstance(problems, list)
            or not problems
            or any(not isinstance(item, str) for item in problems)
            or len(problems) != len(set(problems))
            or problems != sorted(problems)
            or any(PROBLEM.fullmatch(item) is None for item in problems)
        ):
            raise ControllerError(
                "sidecar problem_ids is not a sorted unique problem list"
            )
    if "evaluator_verdict" in sidecar and not isinstance(
        sidecar["evaluator_verdict"], dict
    ):
        raise ControllerError("sidecar evaluator_verdict must be an object")
    return sidecar


def validate_envelope(value: Any) -> dict[str, Any]:
    envelope = _object(value, "key envelope")
    _fields(envelope, ENVELOPE_FIELDS, "key envelope")
    if type(envelope["schema_version"]) is not int or envelope["schema_version"] != 1:
        raise ControllerError("key envelope schema_version must be integer 1")
    submission_id = _match(UUID7, envelope["submission_id"], "envelope submission_id")
    _match(DIGEST, envelope["archive_ciphertext_sha256"], "envelope archive digest")
    recipient = _match(
        AGE_RECIPIENT, envelope["age_recipient"], "envelope age recipient"
    )
    if envelope["data_key_id"] != archive_key_id(submission_id, recipient):
        raise ControllerError(
            "envelope data_key_id does not match submission and recipient"
        )
    _match(ARCHIVE_KEY_ID, envelope["data_key_id"], "envelope data_key_id")
    _match(ADAPTER, envelope["adapter"], "envelope adapter")
    wrapped = envelope["wrapped_identity"]
    if not isinstance(wrapped, str) or len(wrapped) > MAX_WRAPPED_BYTES:
        raise ControllerError(
            "envelope wrapped_identity exceeds its encoded size limit"
        )
    _canonical_base64(wrapped, "envelope wrapped_identity", MAX_WRAPPED_BYTES)
    return envelope


def capability_digest(value: Any) -> str:
    capability = _object(value, "capability")
    _fields(capability, CAPABILITY_FIELDS, "capability")
    canonical = json.dumps(
        capability,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return (
        "uc1_"
        + hashlib.sha256(b"lean-eval-unwrap-capability-v1\0" + canonical).hexdigest()
    )


def prepare_unwrap(
    plan_value: Any,
    sidecar_value: Any,
    ciphertext: bytes,
    trusted_now: str,
    *,
    random_bytes: bytes | None = None,
    runner_nonce: str | None = None,
) -> dict[str, Any]:
    try:
        plan = _validate_execution_plan(plan_value)
    except (ReleaseError, ValueError, TypeError) as error:
        raise ControllerError(str(error)) from error
    now = parse_timestamp(trusted_now, "trusted_now")
    sidecar = validate_sidecar(sidecar_value, ciphertext)
    envelope = validate_envelope(sidecar.get("key_envelope"))
    request = plan["request"]
    archive = request["archive"]
    submission_id = request["submission"]["submission_id"]
    actual_digest = hashlib.sha256(ciphertext).hexdigest()
    for candidate, label in (
        (sidecar.get("submission_id"), "sidecar submission_id"),
        (envelope["submission_id"], "envelope submission_id"),
    ):
        if candidate != submission_id:
            raise ControllerError(f"{label} does not match the release plan")
    for candidate, label in (
        (sidecar.get("sha256_ciphertext"), "sidecar ciphertext digest"),
        (envelope["archive_ciphertext_sha256"], "envelope ciphertext digest"),
        (actual_digest, "ciphertext bytes digest"),
    ):
        if candidate != archive["archive_ciphertext_sha256"]:
            raise ControllerError(f"{label} does not match the release plan")
    nonce = os.urandom(32).hex() if runner_nonce is None else runner_nonce
    _match(DIGEST, nonce, "runner nonce")
    request_id = uuid7(now, random_bytes)
    capability = {
        "schema_version": 1,
        "purpose": "lean-eval-release",
        "request_id": request_id,
        "submission_id": submission_id,
        "archive_repository": archive["archive_repository"],
        "archive_commit": archive["archive_commit"],
        "archive_path": archive["archive_path"],
        "archive_ciphertext_sha256": archive["archive_ciphertext_sha256"],
        "data_key_id": envelope["data_key_id"],
        "runner_nonce": nonce,
        "issued_at": canonical_timestamp(now),
        "expires_at": canonical_timestamp(now + dt.timedelta(minutes=5)),
        "max_uses": 1,
    }
    return {
        "schema_version": 1,
        "operation": "unwrap",
        "adapter": envelope["adapter"],
        "envelope": envelope,
        "capability": capability,
        "expected_purpose": "lean-eval-release",
        "expected_runner_nonce": nonce,
    }


def staging_smoke_plan(queue_value: Any, submission_id: str) -> dict[str, Any]:
    """Build an unwrap-only staging plan for one scheduled accepted result.

    This deliberately does not make a release due.  The staging workflow may
    use the plan only to prove the release-purpose key boundary and plaintext
    archive digest; normal reconstruction still enforces the real embargo.
    """
    try:
        queue = validate_release_queue(queue_value)
    except (ReleaseError, ValueError, TypeError) as error:
        raise ControllerError(str(error)) from error
    if queue["environment"] != "staging":
        raise ControllerError("staging smoke requires the staging release queue")
    _match(UUID7, submission_id, "staging submission_id")
    matches = [
        task for task in queue["tasks"] if task["submission_id"] == submission_id
    ]
    if len(matches) != 1:
        raise ControllerError(
            "staging submission must have exactly one queueable release"
        )
    requested_queue = {**queue, "tasks": [matches[0]]}
    plan = plan_next(requested_queue, matches[0]["release_at"])
    if (
        plan.get("kind") != "execution"
        or plan.get("request", {}).get("submission", {}).get("submission_id")
        != submission_id
    ):
        raise ControllerError("staging plan did not select requested submission")
    return plan


def unwrap_identity(
    request_value: Any, response_value: Any, metadata_value: Any
) -> bytes:
    request = _object(request_value, "unwrap request")
    _fields(request, UNWRAP_FIELDS, "unwrap request")
    metadata = _object(metadata_value, "Lambda metadata")
    if metadata.get("StatusCode") != 200 or "FunctionError" in metadata:
        raise ControllerError("unwrap Lambda did not return a successful invocation")
    response = _object(response_value, "unwrap response")
    _fields(
        response,
        {
            "schema_version",
            "adapter",
            "request_id",
            "data_key_id",
            "capability_digest",
            "plaintext_identity_base64",
        },
        "unwrap response",
    )
    capability = _object(request["capability"], "unwrap capability")
    envelope = _object(request["envelope"], "unwrap envelope")
    if (
        response["schema_version"] != 1
        or response["adapter"] != request["adapter"]
        or response["request_id"] != capability["request_id"]
        or response["data_key_id"] != envelope["data_key_id"]
        or response["capability_digest"] != capability_digest(capability)
    ):
        raise ControllerError("unwrap response is not bound to the exact request")
    _match(CAPABILITY_DIGEST, response["capability_digest"], "capability digest")
    identity = _canonical_base64(
        response["plaintext_identity_base64"],
        "plaintext identity",
        MAX_IDENTITY_BYTES,
    )
    try:
        lines = identity.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ControllerError("age identity must be ASCII") from error
    secrets = [line for line in lines if line and not line.startswith("#")]
    if len(secrets) != 1 or not secrets[0].startswith("AGE-SECRET-KEY-"):
        raise ControllerError("unwrap response did not contain one native age identity")
    return identity


def verify_unwrap_reuse_refusal(
    response_value: Any, metadata_value: Any
) -> None:
    """Require an exact consumed-capability refusal without private output."""
    metadata = _object(metadata_value, "repeat Lambda metadata")
    if (
        metadata.get("StatusCode") != 200
        or metadata.get("FunctionError") != "Unhandled"
    ):
        raise ControllerError(
            "repeat unwrap did not report a Lambda function error"
        )
    response = _object(response_value, "repeat unwrap response")
    _fields(
        response,
        {"errorMessage", "errorType", "requestId", "stackTrace"},
        "repeat unwrap response",
    )
    message = response.get("errorMessage")
    if message != "capability has already been consumed":
        raise ControllerError("repeat unwrap failed for an unexpected reason")
    if response["errorType"] != "AwsAdapterError":
        raise ControllerError("repeat unwrap error type is unexpected")
    _match(AWS_REQUEST_ID, response["requestId"], "repeat unwrap requestId")
    stack = response["stackTrace"]
    if (
        not isinstance(stack, list)
        or not stack
        or len(stack) > 64
        or any(not isinstance(line, str) or len(line) > 8192 for line in stack)
    ):
        raise ControllerError("repeat unwrap stack trace is invalid")
    serialized = canonical_json(response).encode("utf-8")
    if len(serialized) > 65_536 or any(
        marker in serialized
        for marker in (
            b"plaintext_identity_base64",
            b"wrapped_identity",
            b"AGE-SECRET-KEY-",
            b"AWS_ACCESS_KEY_ID",
            b"AWS_SECRET_ACCESS_KEY",
            b"AWS_SESSION_TOKEN",
        )
    ):
        raise ControllerError("repeat unwrap exposed private identity material")


def _event_id(occurred_at: str, random_bytes: bytes | None = None) -> str:
    return uuid7(parse_timestamp(occurred_at, "event occurred_at"), random_bytes)


def started_event(
    plan_value: Any,
    trusted_now: str,
    *,
    random_bytes: bytes | None = None,
) -> dict[str, Any]:
    try:
        plan = _validate_execution_plan(plan_value)
    except (ReleaseError, ValueError, TypeError) as error:
        raise ControllerError(str(error)) from error
    transition = plan["started_transition"]
    occurred_at = event_timestamp(
        trusted_now, plan["request"]["release"]["eligible_at"]
    )
    return {
        "schema_version": 1,
        "event_id": _event_id(occurred_at, random_bytes),
        "event_type": "release.started",
        "occurred_at": occurred_at,
        "subject_id": transition["subject_id"],
        "causation_event_id": transition["causation_event_id"],
        "actor": {"kind": "system"},
        "payload": transition["payload"],
    }


def terminal_event(
    started_value: Any,
    trusted_now: str,
    kind: str,
    *,
    reason_code: str | None = None,
    retryable: bool | None = None,
    repository_commit: str | None = None,
    tree_digest: str | None = None,
    release_path: str | None = None,
    random_bytes: bytes | None = None,
) -> dict[str, Any]:
    started = _object(started_value, "release.started event")
    if started.get("event_type") != "release.started":
        raise ControllerError("terminal event cause must be release.started")
    _match(UUID7, started.get("event_id"), "release.started event_id")
    subject = _match(RESULT_ID, started.get("subject_id"), "release.started subject")
    payload = _object(started.get("payload"), "release.started payload")
    if (
        set(payload) != {"attempt"}
        or type(payload["attempt"]) is not int
        or payload["attempt"] < 1
    ):
        raise ControllerError("release.started attempt is invalid")
    occurred_at = event_timestamp(trusted_now, started.get("occurred_at"))
    terminal_payload: dict[str, Any] = {"attempt": payload["attempt"]}
    if kind == "failed":
        terminal_payload.update(
            reason_code=_match(REASON, reason_code, "release failure reason"),
            retryable=retryable,
        )
        if type(retryable) is not bool:
            raise ControllerError("release failure retryable must be boolean")
    elif kind == "published":
        terminal_payload.update(
            repository_commit=_match(COMMIT, repository_commit, "release commit"),
            tree_digest=_match(DIGEST, tree_digest, "release tree digest"),
            path=release_path,
        )
        if not isinstance(release_path, str) or not release_path.endswith(subject):
            raise ControllerError("release path does not match result identity")
    else:
        raise ControllerError("terminal event kind must be failed or published")
    return {
        "schema_version": 1,
        "event_id": _event_id(occurred_at, random_bytes),
        "event_type": f"release.{kind}",
        "occurred_at": occurred_at,
        "subject_id": subject,
        "causation_event_id": started["event_id"],
        "actor": {"kind": "system"},
        "payload": terminal_payload,
    }


def recover_running(
    domain_value: Any,
    release_root: pathlib.Path,
    trusted_now: str,
    *,
    stale_after: dt.timedelta = dt.timedelta(hours=1),
) -> dict[str, Any]:
    """Classify the oldest interrupted release without changing either repo."""
    domain = _object(domain_value, "State domain view")
    tasks = domain.get("release_tasks")
    if not isinstance(tasks, list):
        raise ControllerError("State domain release_tasks must be an array")
    running = []
    for value in tasks:
        task = _object(value, "release task")
        if task.get("status") == "running":
            running.append(task)
    if not running:
        return {"schema_version": 1, "kind": "none"}
    task = min(
        running,
        key=lambda item: (str(item.get("occurred_at")), str(item.get("result_id"))),
    )
    result_id = _match(RESULT_ID, task.get("result_id"), "release task result_id")
    submission_id = _match(
        UUID7, task.get("submission_id"), "release task submission_id"
    )
    event_id = _match(UUID7, task.get("event_id"), "release task event_id")
    occurred_at = task.get("occurred_at")
    started_at = parse_timestamp(occurred_at, "release task occurred_at")
    now = parse_timestamp(trusted_now, "trusted_now")
    attempt = task.get("attempt")
    if type(attempt) is not int or attempt < 1:
        raise ControllerError("running release task attempt is invalid")
    started = {
        "schema_version": 1,
        "event_id": event_id,
        "event_type": "release.started",
        "occurred_at": occurred_at,
        "subject_id": result_id,
        "causation_event_id": task.get("causation_event_id"),
        "actor": {"kind": "system"},
        "payload": {"attempt": attempt},
    }
    if now - started_at < stale_after:
        return {
            "schema_version": 1,
            "kind": "busy",
            "result_id": result_id,
            "started_event": started,
        }
    release_at = task.get("release_at")
    parse_timestamp(release_at, "release task release_at")
    relative = f"releases/{release_at[:4]}/{release_at[5:7]}/{result_id}"
    path = release_root.joinpath(*relative.split("/"))
    if path.exists() or path.is_symlink():
        try:
            digest = tree_digest(path)
        except ValueError as error:
            raise ControllerError("existing release tree is not canonical") from error
        return {
            "schema_version": 1,
            "kind": "published",
            "result_id": result_id,
            "submission_id": submission_id,
            "release_path": relative,
            "tree_digest": digest,
            "started_event": started,
        }
    return {
        "schema_version": 1,
        "kind": "failed",
        "result_id": result_id,
        "reason_code": "controller_interrupted",
        "started_event": started,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    prepare = commands.add_parser("prepare-unwrap")
    prepare.add_argument("--plan", required=True, type=pathlib.Path)
    prepare.add_argument("--sidecar", required=True, type=pathlib.Path)
    prepare.add_argument("--ciphertext", required=True, type=pathlib.Path)
    prepare.add_argument("--trusted-now", required=True)
    prepare.add_argument("--output", required=True, type=pathlib.Path)

    identity = commands.add_parser("unwrap-identity")
    identity.add_argument("--request", required=True, type=pathlib.Path)
    identity.add_argument("--response", required=True, type=pathlib.Path)
    identity.add_argument("--metadata", required=True, type=pathlib.Path)
    identity.add_argument("--output", required=True, type=pathlib.Path)

    reuse = commands.add_parser("verify-unwrap-reuse-refusal")
    reuse.add_argument("--response", required=True, type=pathlib.Path)
    reuse.add_argument("--metadata", required=True, type=pathlib.Path)

    event = commands.add_parser("state-event")
    event.add_argument("kind", choices=["started", "failed", "published"])
    event.add_argument("--plan", type=pathlib.Path)
    event.add_argument("--started-event", type=pathlib.Path)
    event.add_argument("--trusted-now", required=True)
    event.add_argument("--reason-code")
    event.add_argument("--retryable", choices=["true", "false"])
    event.add_argument("--repository-commit")
    event.add_argument("--tree-digest")
    event.add_argument("--release-path")
    event.add_argument("--output", required=True, type=pathlib.Path)

    recover = commands.add_parser("recover")
    recover.add_argument("--domain", required=True, type=pathlib.Path)
    recover.add_argument("--release-root", required=True, type=pathlib.Path)
    recover.add_argument("--trusted-now", required=True)
    recover.add_argument("--output", required=True, type=pathlib.Path)

    staging = commands.add_parser("staging-smoke-plan")
    staging.add_argument("--queue", required=True, type=pathlib.Path)
    staging.add_argument("--submission-id", required=True)
    staging.add_argument("--output", required=True, type=pathlib.Path)

    authority = commands.add_parser("authority-descriptor")
    authority.add_argument("--plan", required=True, type=pathlib.Path)
    authority.add_argument("--state-commit", required=True)
    authority.add_argument("--release-commit", required=True)
    authority.add_argument(
        "--environment", required=True, choices=["production", "staging"]
    )
    authority.add_argument("--started-event", type=pathlib.Path)
    authority.add_argument("--output", required=True, type=pathlib.Path)

    transition = commands.add_parser("stage-state-transition")
    transition.add_argument("--state-root", required=True, type=pathlib.Path)
    transition.add_argument("--event", required=True, type=pathlib.Path)
    transition.add_argument("--protected-state-head", required=True)
    transition.add_argument("--output", required=True, type=pathlib.Path)

    verify_transition = commands.add_parser("verify-staged-state-transition")
    verify_transition.add_argument("--state-root", required=True, type=pathlib.Path)
    verify_transition.add_argument("--event", required=True, type=pathlib.Path)
    verify_transition.add_argument("--plan", required=True, type=pathlib.Path)

    args = parser.parse_args(argv)
    try:
        if args.command == "prepare-unwrap":
            plan = _read(args.plan, "release plan")
            sidecar = _read(args.sidecar, "archive sidecar")
            ciphertext = args.ciphertext.read_bytes()
            _write(
                args.output, prepare_unwrap(plan, sidecar, ciphertext, args.trusted_now)
            )
        elif args.command == "unwrap-identity":
            result = unwrap_identity(
                _read(args.request, "unwrap request"),
                _read(args.response, "unwrap response"),
                _read(args.metadata, "Lambda metadata"),
            )
            if args.output.exists() or args.output.is_symlink():
                raise ControllerError(f"refusing to overwrite {args.output}")
            args.output.write_bytes(result)
            args.output.chmod(0o600)
        elif args.command == "verify-unwrap-reuse-refusal":
            verify_unwrap_reuse_refusal(
                _read(args.response, "repeat unwrap response"),
                _read(args.metadata, "repeat Lambda metadata"),
            )
        elif args.command == "recover":
            _write(
                args.output,
                recover_running(
                    _read(args.domain, "State domain view"),
                    args.release_root.resolve(),
                    args.trusted_now,
                ),
            )
        elif args.command == "staging-smoke-plan":
            _write(
                args.output,
                staging_smoke_plan(
                    _read(args.queue, "staging release queue"),
                    args.submission_id,
                ),
            )
        elif args.command == "authority-descriptor":
            _write(
                args.output,
                authority_descriptor(
                    _read(args.plan, "release plan"),
                    args.state_commit,
                    args.release_commit,
                    args.environment,
                    None
                    if args.started_event is None
                    else _read(args.started_event, "release.started event"),
                ),
            )
        elif args.command == "stage-state-transition":
            if args.output.exists() or args.output.is_symlink():
                raise ControllerError(f"refusing to overwrite {args.output}")
            plan = stage_release_state_transition(
                args.state_root,
                _read(args.event, "release transition event"),
                args.protected_state_head,
            )
            _write(args.output, plan)
        elif args.command == "verify-staged-state-transition":
            verify_staged_release_state_transition(
                args.state_root,
                _read(args.event, "release transition event"),
                _read(args.plan, "State transition plan"),
            )
        elif args.kind == "started":
            if args.plan is None:
                raise ControllerError("started event requires --plan")
            _write(
                args.output,
                started_event(_read(args.plan, "release plan"), args.trusted_now),
            )
        else:
            if args.started_event is None:
                raise ControllerError("terminal event requires --started-event")
            _write(
                args.output,
                terminal_event(
                    _read(args.started_event, "release.started event"),
                    args.trusted_now,
                    args.kind,
                    reason_code=args.reason_code,
                    retryable=None
                    if args.retryable is None
                    else args.retryable == "true",
                    repository_commit=args.repository_commit,
                    tree_digest=args.tree_digest,
                    release_path=args.release_path,
                ),
            )
    except (ControllerError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
