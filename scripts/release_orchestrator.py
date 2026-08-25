"""Validate State release work and build one provider-neutral preparation plan."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import pathlib
import re
import sys
from typing import Any

if __package__:
    from .embargo import eligible_at, parse_utc_milliseconds
else:
    from embargo import eligible_at, parse_utc_milliseconds

UUID7 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
RESULT_ID = re.compile(r"r2_[0-9a-f]{64}")
LOGIN = re.compile(r"[a-z\d](?:[a-z\d-]{0,37}[a-z\d])?")
PROBLEM = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
COMMIT = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
REASON = re.compile(r"[a-z][a-z0-9_]{1,63}")
SAFE_INTEGER = 9_007_199_254_740_991
STATE_RELEASE_CONTRACT_COMMIT = "6799522f7fe57263de4a66499e52ce4bfda69baa"
STATE_RELEASE_CONTRACT_TREES = {
    "schema": "3043a7b6afa042577645e0520ee9bd105a15424a",
    "scripts": "4e2c39cac2510716577a7fd6d13abf0f9cf26976",
}
STAGING_STATE_RELEASE_CONTRACT_COMMIT = (
    "48f8c975d725a9ac18df545653fdb2f8371c3293"
)
STAGING_STATE_RELEASE_CONTRACT_TREES = {
    "schema": "730d44520c70fdd6da4d27e381d4e6593c5c77fe",
    "scripts": "438693aed415474802beae32a5398fb436a4ac71",
}
CONTROLLER_QUALIFICATION_FIELDS = {
    "schema_version",
    "environment",
    "mode",
    "release_repository",
    "release_commit",
    "state_repository",
    "state_commit",
    "state_contract_commit",
    "state_source_event_count",
    "state_source_digest",
    "release_queue_sha256",
    "acceptance_snapshot_sha256",
}
METADATA_FIELDS = {
    "credit_identity",
    "component_models",
    "harness",
    "human_involvement",
    "web_access",
    "wall_time_seconds",
    "input_tokens",
    "output_tokens",
    "cost_usd",
    "billing_mode",
    "prompt",
    "notes",
}
TASK_FIELDS = {
    "result_id",
    "submission_id",
    "owner_login",
    "declared_model",
    "problem_id",
    "statement_revision",
    "result_commit",
    "result_tree_digest",
    "accepted_at",
    "release_at",
    "archive_repository",
    "archive_commit",
    "archive_path",
    "archive_ciphertext_sha256",
    "publication_choice",
    "production_metadata",
    "status",
    "attempt",
    "event_id",
    "occurred_at",
}


class ReleaseError(ValueError):
    """A release queue or preparation plan violates release schema version 1."""


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ReleaseError(f"{label} must be an object with string keys")
    return value


def _fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ReleaseError(
            f"{label} fields are not canonical; "
            f"missing={sorted(expected - set(value))}, extra={sorted(set(value) - expected)}"
        )


def _match(pattern: re.Pattern[str], value: Any, label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ReleaseError(f"{label} is not canonical")
    return value


def _safe_integer(value: Any, label: str, minimum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= SAFE_INTEGER
    ):
        raise ReleaseError(f"{label} must be a safe integer >= {minimum}")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ReleaseError(f"{label} must be a timestamp string")
    try:
        parse_utc_milliseconds(value)
    except ValueError as error:
        raise ReleaseError(f"{label} must be canonical UTC milliseconds") from error
    return value


def _metadata_text(value: Any, label: str, maximum: int) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) <= 0x1F or ord(character) == 0x7F for character in value)
    ):
        raise ReleaseError(
            f"{label} must be non-empty control-free text of at most {maximum} code points"
        )


def _production_metadata(value: Any, label: str) -> dict[str, Any]:
    metadata = _object(value, label)
    if not set(metadata) <= METADATA_FIELDS:
        raise ReleaseError(f"{label} has unknown fields")
    text_limits = {
        "credit_identity": 256,
        "harness": 1024,
        "human_involvement": 1024,
        "prompt": 8192,
        "notes": 4096,
    }
    for key, item in metadata.items():
        item_label = f"{label}.{key}"
        if key in text_limits:
            _metadata_text(item, item_label, text_limits[key])
        elif key == "component_models":
            if not isinstance(item, list) or len(item) > 16:
                raise ReleaseError(f"{item_label} must have at most 16 entries")
            for index, component in enumerate(item):
                _metadata_text(component, f"{item_label}[{index}]", 256)
        elif key == "web_access":
            if not isinstance(item, bool):
                raise ReleaseError(f"{item_label} must be boolean")
        elif key in {"wall_time_seconds", "cost_usd"}:
            maximum = 31_536_000 if key == "wall_time_seconds" else 1_000_000
            if (
                isinstance(item, bool)
                or not isinstance(item, (int, float))
                or not math.isfinite(item)
                or not 0 <= item <= maximum
            ):
                raise ReleaseError(f"{item_label} must be finite and in range")
        elif key in {"input_tokens", "output_tokens"}:
            _safe_integer(item, item_label, 0)
        elif key == "billing_mode" and item not in {"api", "subscription", "unknown"}:
            raise ReleaseError(f"{item_label} is invalid")
    return metadata


def result_id(login: str, model: str, problem_id: str, revision: int) -> str:
    canonical = json.dumps(
        [login.lower(), model, problem_id, revision],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(b"lean-eval-result-v2\0" + canonical).hexdigest()
    return f"r2_{digest}"


def canonical_archive_path(submission_id: str) -> str:
    return f"archives/{submission_id.replace('-', '')[:2]}/{submission_id}.tar.age"


def canonical_release_path(result_identity: str, release_at: str) -> str:
    instant = parse_utc_milliseconds(release_at)
    return f"releases/{instant.year:04d}/{instant.month:02d}/{result_identity}"


def _validate_task(value: Any, index: int) -> dict[str, Any]:
    label = f"tasks[{index}]"
    task = _object(value, label)
    expected = TASK_FIELDS | (
        {"reason_code", "retryable"} if task.get("status") == "failed" else set()
    )
    _fields(task, expected, label)
    identity = _match(RESULT_ID, task["result_id"], f"{label}.result_id")
    submission = _match(UUID7, task["submission_id"], f"{label}.submission_id")
    login = _match(LOGIN, task["owner_login"], f"{label}.owner_login")
    model = task["declared_model"]
    if (
        not isinstance(model, str)
        or not model
        or len(model.encode("utf-8")) > 256
        or any(ord(character) <= 0x1F or ord(character) == 0x7F for character in model)
    ):
        raise ReleaseError(f"{label}.declared_model is invalid")
    problem = _match(PROBLEM, task["problem_id"], f"{label}.problem_id")
    revision = _safe_integer(
        task["statement_revision"], f"{label}.statement_revision", 1
    )
    if identity != result_id(login, model, problem, revision):
        raise ReleaseError(
            f"{label}.result_id does not match its deterministic identity"
        )
    for field in ("result_commit", "archive_commit"):
        _match(COMMIT, task[field], f"{label}.{field}")
    for field in ("result_tree_digest", "archive_ciphertext_sha256"):
        _match(DIGEST, task[field], f"{label}.{field}")
    _match(REPOSITORY, task["archive_repository"], f"{label}.archive_repository")
    if task["archive_path"] != canonical_archive_path(submission):
        raise ReleaseError(f"{label}.archive_path does not match submission_id")
    accepted_at = _timestamp(task["accepted_at"], f"{label}.accepted_at")
    release_at = _timestamp(task["release_at"], f"{label}.release_at")
    if release_at != eligible_at(accepted_at):
        raise ReleaseError(f"{label}.release_at does not equal two UTC calendar months")
    if task["publication_choice"] != "scheduled":
        raise ReleaseError(f"{label}.publication_choice must be scheduled")
    _production_metadata(task["production_metadata"], f"{label}.production_metadata")
    attempt = _safe_integer(task["attempt"], f"{label}.attempt", 0)
    if task["status"] == "failed":
        if attempt < 1 or task["retryable"] is not True:
            raise ReleaseError(f"{label}: failed queue task must be retryable")
        _match(REASON, task["reason_code"], f"{label}.reason_code")
    elif task["status"] != "scheduled":
        raise ReleaseError(f"{label}.status is not queueable")
    _match(UUID7, task["event_id"], f"{label}.event_id")
    _timestamp(task["occurred_at"], f"{label}.occurred_at")
    return task


def validate_release_queue(value: Any) -> dict[str, Any]:
    queue = _object(value, "release queue")
    _fields(
        queue,
        {
            "schema_version",
            "environment",
            "source_event_count",
            "source_digest",
            "tasks",
        },
        "release queue",
    )
    if queue["schema_version"] != 1 or isinstance(queue["schema_version"], bool):
        raise ReleaseError("release queue schema_version must be integer 1")
    if queue["environment"] not in {"production", "staging"}:
        raise ReleaseError("release queue environment is invalid")
    _safe_integer(queue["source_event_count"], "source_event_count", 1)
    _match(DIGEST, queue["source_digest"], "source_digest")
    if not isinstance(queue["tasks"], list):
        raise ReleaseError("release queue tasks must be an array")
    tasks = [_validate_task(task, index) for index, task in enumerate(queue["tasks"])]
    identities = [task["result_id"] for task in tasks]
    if identities != sorted(identities) or len(identities) != len(set(identities)):
        raise ReleaseError("release queue tasks must be unique and sorted by result_id")
    return queue


def canonical_json_digest(value: Any, materialization: str) -> str:
    domains = {
        "release-queue": b"lean-eval-release-controller-queue-v1\0",
        "acceptance-snapshot": b"lean-eval-release-controller-acceptance-v1\0",
    }
    try:
        domain = domains[materialization]
    except KeyError as error:
        raise ReleaseError(
            "controller materialization digest domain is invalid"
        ) from error
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(domain + encoded).hexdigest()


def validate_controller_binding(value: Any) -> dict[str, Any]:
    qualification = _object(value, "controller qualification")
    _fields(
        qualification,
        CONTROLLER_QUALIFICATION_FIELDS,
        "controller qualification",
    )
    if (
        qualification["schema_version"] != 1
        or isinstance(qualification["schema_version"], bool)
        or qualification["environment"] != "production"
        or qualification["mode"] != "publication"
        or qualification["release_repository"] != "leanprover/lean-eval-releases"
        or qualification["state_repository"] != "leanprover/lean-eval-state"
        or qualification["state_contract_commit"] != STATE_RELEASE_CONTRACT_COMMIT
    ):
        raise ReleaseError("controller qualification identity is invalid")
    for field in ("release_commit", "state_commit"):
        _match(COMMIT, qualification[field], f"controller qualification.{field}")
    for field in (
        "state_source_digest",
        "release_queue_sha256",
        "acceptance_snapshot_sha256",
    ):
        _match(DIGEST, qualification[field], f"controller qualification.{field}")
    _safe_integer(
        qualification["state_source_event_count"],
        "controller qualification.state_source_event_count",
        1,
    )
    return qualification


def validate_controller_qualification(
    value: Any, queue: dict[str, Any]
) -> dict[str, Any]:
    qualification = validate_controller_binding(value)
    if (
        qualification["environment"] != queue["environment"]
        or qualification["state_source_event_count"] != queue["source_event_count"]
        or qualification["state_source_digest"] != queue["source_digest"]
        or qualification["release_queue_sha256"]
        != canonical_json_digest(queue, "release-queue")
    ):
        raise ReleaseError(
            "controller qualification does not bind the exact production queue"
        )
    return qualification


def plan_next(
    queue_value: Any,
    trusted_as_of: str,
    controller_qualification: Any | None = None,
) -> dict[str, Any]:
    queue = validate_release_queue(queue_value)
    qualification = (
        None
        if controller_qualification is None
        else (validate_controller_qualification(controller_qualification, queue))
    )
    as_of = _timestamp(trusted_as_of, "trusted_as_of")
    eligible = [task for task in queue["tasks"] if task["release_at"] <= as_of]
    if not queue["tasks"]:
        return {"schema_version": 1, "kind": "empty"}
    if not eligible:
        return {
            "schema_version": 1,
            "kind": "not_due",
            "next_release_at": min(task["release_at"] for task in queue["tasks"]),
        }
    task = min(eligible, key=lambda item: item["result_id"])
    attempt = task["attempt"] + 1
    release_path = canonical_release_path(task["result_id"], task["release_at"])
    request = {
        "schema_version": 1,
        "result": {
            "result_id": task["result_id"],
            "problem_id": task["problem_id"],
            "statement_revision": task["statement_revision"],
            "commit": task["result_commit"],
            "tree_digest": task["result_tree_digest"],
        },
        "submission": {
            "submission_id": task["submission_id"],
            "owner_login": task["owner_login"],
            "declared_model": task["declared_model"],
            "production_metadata": task["production_metadata"],
        },
        "archive": {
            "archive_repository": task["archive_repository"],
            "archive_commit": task["archive_commit"],
            "archive_path": task["archive_path"],
            "archive_ciphertext_sha256": task["archive_ciphertext_sha256"],
            "encrypted": True,
        },
        "release": {
            "accepted_at": task["accepted_at"],
            "eligible_at": task["release_at"],
            "path": release_path,
            "license": "Apache-2.0",
        },
    }
    if qualification is not None:
        request["controller"] = qualification
    return {
        "schema_version": 1,
        "kind": "execution",
        "started_transition": {
            "event_type": "release.started",
            "subject_id": task["result_id"],
            "causation_event_id": task["event_id"],
            "payload": {"attempt": attempt},
        },
        "request": request,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("queue", type=pathlib.Path)
    parser.add_argument("--trusted-as-of", required=True)
    parser.add_argument("--controller-qualification", type=pathlib.Path)
    parser.add_argument("--require-controller-qualification", action="store_true")
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        queue = json.loads(args.queue.read_text(encoding="utf-8"))
        qualification = (
            None
            if args.controller_qualification is None
            else json.loads(args.controller_qualification.read_text(encoding="utf-8"))
        )
        if args.require_controller_qualification and qualification is None:
            raise ReleaseError("controller qualification is required")
        plan = plan_next(queue, args.trusted_as_of, qualification)
        args.output.write_text(
            json.dumps(plan, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        ReleaseError,
        ValueError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"wrote release plan: {plan['kind']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
