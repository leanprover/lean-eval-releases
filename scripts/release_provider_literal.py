"""Source mirror for the literal, authority-bearing workflow provider phase.

The workflows embed this file byte-for-byte and execute only the embedded copy
with ``python -I -``. They never execute the checked-out mirror while AWS or
OIDC authority exists. Tests enforce that both embedded copies remain exact.
"""

from __future__ import annotations

import base64
import calendar
import datetime as dt
import hashlib
import json
import math
import os
import pathlib
import re
import stat
import sys
from collections.abc import Mapping
from typing import Any

UUID7 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
RESULT_ID = re.compile(r"r2_[0-9a-f]{64}")
LOGIN = re.compile(r"[a-z\d](?:[a-z\d-]{0,37}[a-z\d])?")
PROBLEM = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
COMMIT = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
BASE64 = re.compile(r"[A-Za-z0-9+/]+={0,2}")
AGE_RECIPIENT = re.compile(r"age1[0-9a-z]{40,4090}")
ADAPTER = re.compile(r"[a-z][a-z0-9-]{0,63}-v[1-9][0-9]*")
RUNNER_ENV_FILE = re.compile(
    r"set_env_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)
RUNNER_ENV_HEADER = re.compile(
    r"([A-Z][A-Z0-9_]*)<<(ghadelimiter_[0-9a-f]{8}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
)
MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_WRAPPED_BYTES = 16_384
MAX_SCAN_FILES = 1024
MAX_SCAN_FILE_BYTES = 8 * 1024 * 1024
MAX_SCAN_TOTAL_BYTES = 32 * 1024 * 1024
STATE_RELEASE_CONTRACT_COMMIT = "c6a4bb67b55609ae7215bdd3cac2378b2db42a0a"

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
AUTHORITY_NAMES = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
)
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


class ProviderError(ValueError):
    """Literal provider input or runner authority state is invalid."""

    def __init__(self, message: str, *, diagnostic: str = "input-validation") -> None:
        super().__init__(message)
        self.diagnostic = diagnostic


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(
        isinstance(key, str) for key in value
    ):
        raise ProviderError(f"{label} must be an object")
    return value


def _fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ProviderError(
            f"{label} fields are not canonical; "
            f"missing={sorted(expected - set(value))}, "
            f"extra={sorted(set(value) - expected)}"
        )


def _match(pattern: re.Pattern[str], value: Any, label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ProviderError(f"{label} is invalid")
    return value


def _bounded_integer(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER:
        raise ProviderError(f"{label} must be a nonnegative safe integer")
    return value


def _safe_integer(value: Any, label: str, minimum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= MAX_SAFE_INTEGER
    ):
        raise ProviderError(f"{label} must be a safe integer >= {minimum}")
    return value


def _parse_utc_milliseconds(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str):
        raise ProviderError(f"{label} must be a timestamp string")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=dt.UTC
        )
    except ValueError as error:
        raise ProviderError(f"{label} must be canonical UTC milliseconds") from error
    if parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z" != value:
        raise ProviderError(f"{label} must be canonical UTC milliseconds")
    return parsed


def _eligible_at(value: Any, label: str) -> str:
    accepted = _parse_utc_milliseconds(value, label)
    month_index = accepted.year * 12 + accepted.month + 1
    year, zero_based_month = divmod(month_index, 12)
    month = zero_based_month + 1
    day = min(accepted.day, calendar.monthrange(year, month)[1])
    eligible = accepted.replace(year=year, month=month, day=day)
    return eligible.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def _metadata_text(value: Any, label: str, maximum: int) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) <= 0x1F or ord(character) == 0x7F for character in value)
    ):
        raise ProviderError(
            f"{label} must be non-empty control-free text of at most "
            f"{maximum} code points"
        )


def _production_metadata(value: Any, label: str) -> dict[str, Any]:
    metadata = _object(value, label)
    if not set(metadata) <= METADATA_FIELDS:
        raise ProviderError(f"{label} has unknown fields")
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
                raise ProviderError(f"{item_label} must have at most 16 entries")
            for index, component in enumerate(item):
                _metadata_text(component, f"{item_label}[{index}]", 256)
        elif key == "web_access":
            if not isinstance(item, bool):
                raise ProviderError(f"{item_label} must be boolean")
        elif key in {"wall_time_seconds", "cost_usd"}:
            maximum = 31_536_000 if key == "wall_time_seconds" else 1_000_000
            if (
                isinstance(item, bool)
                or not isinstance(item, (int, float))
                or not math.isfinite(item)
                or not 0 <= item <= maximum
            ):
                raise ProviderError(f"{item_label} must be finite and in range")
        elif key in {"input_tokens", "output_tokens"}:
            _safe_integer(item, item_label, 0)
        elif key == "billing_mode" and item not in {
            "api",
            "subscription",
            "unknown",
        }:
            raise ProviderError(f"{item_label} is invalid")
    return metadata


def _result_id(login: str, model: str, problem_id: str, revision: int) -> str:
    canonical = json.dumps(
        [login.lower(), model, problem_id, revision],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return "r2_" + hashlib.sha256(b"lean-eval-result-v2\0" + canonical).hexdigest()


def _validate_controller_binding(value: Any) -> dict[str, Any]:
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
        or qualification["release_repository"]
        != "leanprover/lean-eval-releases"
        or qualification["state_repository"] != "leanprover/lean-eval-state"
        or qualification["state_contract_commit"]
        != STATE_RELEASE_CONTRACT_COMMIT
    ):
        raise ProviderError("controller qualification identity is invalid")
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


def validate_execution_plan(value: Any) -> dict[str, Any]:
    """Mirror the complete plan validator used by ``prepare_unwrap``."""
    plan = _object(value, "release plan")
    _fields(
        plan,
        {
            "schema_version",
            "kind",
            "exhausted_task_count",
            "started_transition",
            "request",
        },
        "release plan",
    )
    if plan["schema_version"] != 1 or isinstance(plan["schema_version"], bool):
        raise ProviderError("release plan schema_version must be integer 1")
    if plan["kind"] != "execution":
        raise ProviderError("release plan must contain one execution")
    exhausted = plan["exhausted_task_count"]
    if type(exhausted) is not int or not 0 <= exhausted <= MAX_SAFE_INTEGER:
        raise ProviderError("release plan exhausted_task_count is invalid")

    started = _object(plan["started_transition"], "started_transition")
    _fields(
        started,
        {"event_type", "subject_id", "causation_event_id", "payload"},
        "started_transition",
    )
    if started["event_type"] != "release.started":
        raise ProviderError("started transition must be release.started")
    subject = _match(
        RESULT_ID, started["subject_id"], "started_transition.subject_id"
    )
    _match(
        UUID7,
        started["causation_event_id"],
        "started_transition.causation_event_id",
    )
    started_payload = _object(started["payload"], "started_transition.payload")
    _fields(started_payload, {"attempt"}, "started_transition.payload")
    _safe_integer(started_payload["attempt"], "started_transition.payload.attempt", 1)

    request = _object(plan["request"], "request")
    request_fields = {"schema_version", "result", "submission", "archive", "release"}
    if "controller" in request:
        request_fields.add("controller")
    _fields(request, request_fields, "request")
    if request["schema_version"] != 1 or isinstance(
        request["schema_version"], bool
    ):
        raise ProviderError("request schema_version must be integer 1")
    if "controller" in request:
        _validate_controller_binding(request["controller"])

    result = _object(request["result"], "request.result")
    _fields(
        result,
        {"result_id", "problem_id", "statement_revision", "commit", "tree_digest"},
        "request.result",
    )
    identity = _match(RESULT_ID, result["result_id"], "request.result.result_id")
    problem = _match(PROBLEM, result["problem_id"], "request.result.problem_id")
    revision = _safe_integer(
        result["statement_revision"], "request.result.statement_revision", 1
    )
    _match(COMMIT, result["commit"], "request.result.commit")
    _match(DIGEST, result["tree_digest"], "request.result.tree_digest")
    if identity != subject:
        raise ProviderError("started transition subject differs from result_id")

    submission = _object(request["submission"], "request.submission")
    _fields(
        submission,
        {"submission_id", "owner_login", "declared_model", "production_metadata"},
        "request.submission",
    )
    submission_id = _match(
        UUID7,
        submission["submission_id"],
        "request.submission.submission_id",
    )
    login = _match(LOGIN, submission["owner_login"], "request.submission.owner_login")
    model = submission["declared_model"]
    if (
        not isinstance(model, str)
        or not model
        or len(model.encode("utf-8")) > 256
        or any(ord(character) <= 0x1F or ord(character) == 0x7F for character in model)
    ):
        raise ProviderError("request.submission.declared_model is invalid")
    if identity != _result_id(login, model, problem, revision):
        raise ProviderError("request result_id does not match its deterministic identity")
    _production_metadata(
        submission["production_metadata"],
        "request.submission.production_metadata",
    )

    archive = _object(request["archive"], "request.archive")
    _fields(
        archive,
        {
            "archive_repository",
            "archive_commit",
            "archive_path",
            "archive_ciphertext_sha256",
            "encrypted",
        },
        "request.archive",
    )
    _match(
        REPOSITORY,
        archive["archive_repository"],
        "request.archive.archive_repository",
    )
    _match(COMMIT, archive["archive_commit"], "request.archive.archive_commit")
    _match(
        DIGEST,
        archive["archive_ciphertext_sha256"],
        "request.archive.archive_ciphertext_sha256",
    )
    canonical_archive = (
        f"archives/{submission_id.replace('-', '')[:2]}/{submission_id}.tar.age"
    )
    if archive["archive_path"] != canonical_archive:
        raise ProviderError("request archive_path does not match submission_id")
    if archive["encrypted"] is not True:
        raise ProviderError("request archive must be encrypted")

    release = _object(request["release"], "request.release")
    _fields(
        release,
        {"accepted_at", "eligible_at", "path", "license"},
        "request.release",
    )
    accepted = release["accepted_at"]
    eligible = release["eligible_at"]
    _parse_utc_milliseconds(accepted, "request.release.accepted_at")
    eligible_instant = _parse_utc_milliseconds(
        eligible, "request.release.eligible_at"
    )
    if eligible != _eligible_at(accepted, "request.release.accepted_at"):
        raise ProviderError("request release eligibility is not two UTC calendar months")
    canonical_release = (
        f"releases/{eligible_instant.year:04d}/{eligible_instant.month:02d}/{identity}"
    )
    if release["path"] != canonical_release:
        raise ProviderError("request release path is not canonical")
    if release["license"] != "Apache-2.0":
        raise ProviderError("request release license must be Apache-2.0")
    return plan


def _canonical_base64(value: Any, label: str, maximum: int) -> bytes:
    raw = _match(BASE64, value, label)
    if len(raw) % 4 != 0:
        raise ProviderError(f"{label} is not canonical base64")
    try:
        decoded = base64.b64decode(raw, validate=True)
    except ValueError as error:
        raise ProviderError(f"{label} is not valid base64") from error
    if (
        not decoded
        or len(decoded) > maximum
        or base64.b64encode(decoded).decode("ascii") != raw
    ):
        raise ProviderError(
            f"{label} is empty, noncanonical, or exceeds its size limit"
        )
    return decoded


def archive_key_id(submission_id: str, recipient: str) -> str:
    _match(UUID7, submission_id, "submission_id")
    _match(AGE_RECIPIENT, recipient, "age_recipient")
    value = f"{submission_id}\0{recipient}".encode("ascii")
    return "ak1_" + hashlib.sha256(
        b"lean-eval-archive-key-v1\0" + value
    ).hexdigest()


def validate_sidecar(value: Any, ciphertext: bytes) -> dict[str, Any]:
    sidecar = _object(value, "archive sidecar")
    missing = SIDECAR_REQUIRED_FIELDS - set(sidecar)
    extra = set(sidecar) - SIDECAR_REQUIRED_FIELDS - SIDECAR_OPTIONAL_FIELDS
    if missing or extra:
        raise ProviderError(
            "archive sidecar fields are not canonical; "
            f"missing={sorted(missing)}, extra={sorted(extra)}"
        )
    if type(sidecar["schema_version"]) is not int or sidecar["schema_version"] != 3:
        raise ProviderError("archive sidecar schema_version must be integer 3")
    _match(UUID7, sidecar["submission_id"], "sidecar submission_id")
    _match(REPOSITORY, sidecar["submission_repo"], "sidecar submission_repo")
    _match(COMMIT, sidecar["submission_ref"], "sidecar submission_ref")
    if sidecar["submission_kind"] not in {"github_repo", "gist"}:
        raise ProviderError("sidecar submission_kind is invalid")
    if type(sidecar["submission_public"]) is not bool:
        raise ProviderError("sidecar submission_public must be boolean")
    for field in ("submitter", "model"):
        field_value = sidecar[field]
        if (
            not isinstance(field_value, str)
            or not field_value.strip()
            or len(field_value.encode("utf-8")) > 256
        ):
            raise ProviderError(f"sidecar {field} is invalid")
    _bounded_integer(sidecar["size_bytes_plaintext_tar"], "sidecar plaintext size")
    _match(DIGEST, sidecar["sha256_plaintext_tar"], "sidecar plaintext digest")
    ciphertext_size = _bounded_integer(
        sidecar["size_bytes_ciphertext"], "sidecar ciphertext size"
    )
    if ciphertext_size != len(ciphertext):
        raise ProviderError(
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
        raise ProviderError("sidecar archived_at is not canonical UTC seconds")
    try:
        parsed_archive_time = dt.datetime.fromisoformat(
            archived_at[:-1] + "+00:00"
        )
    except ValueError as error:
        raise ProviderError("sidecar archived_at is not a real timestamp") from error
    if parsed_archive_time.strftime("%Y-%m-%dT%H:%M:%SZ") != archived_at:
        raise ProviderError("sidecar archived_at is not a real timestamp")
    workflow_run = sidecar["archiver_workflow_run"]
    if (
        not isinstance(workflow_run, str)
        or re.fullmatch(
            r"https://github\.com/leanprover/lean-eval-submissions/actions/runs/[1-9][0-9]*",
            workflow_run,
        )
        is None
    ):
        raise ProviderError("sidecar archiver_workflow_run is invalid")
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
            raise ProviderError(
                "sidecar problem_ids is not a sorted unique problem list"
            )
    if "evaluator_verdict" in sidecar and not isinstance(
        sidecar["evaluator_verdict"], dict
    ):
        raise ProviderError("sidecar evaluator_verdict must be an object")
    return sidecar


def validate_envelope(value: Any) -> dict[str, Any]:
    envelope = _object(value, "key envelope")
    if set(envelope) != ENVELOPE_FIELDS:
        raise ProviderError("key envelope fields are not canonical")
    if type(envelope["schema_version"]) is not int or envelope["schema_version"] != 1:
        raise ProviderError("key envelope schema_version must be integer 1")
    submission_id = _match(
        UUID7, envelope["submission_id"], "envelope submission_id"
    )
    _match(
        DIGEST,
        envelope["archive_ciphertext_sha256"],
        "envelope archive digest",
    )
    recipient = _match(
        AGE_RECIPIENT, envelope["age_recipient"], "envelope age recipient"
    )
    if envelope["data_key_id"] != archive_key_id(submission_id, recipient):
        raise ProviderError(
            "envelope data_key_id does not match submission and recipient"
        )
    _match(ADAPTER, envelope["adapter"], "envelope adapter")
    wrapped = envelope["wrapped_identity"]
    if not isinstance(wrapped, str) or len(wrapped) > MAX_WRAPPED_BYTES:
        raise ProviderError("envelope wrapped_identity exceeds its encoded size limit")
    _canonical_base64(wrapped, "envelope wrapped_identity", MAX_WRAPPED_BYTES)
    return envelope


def _iter_scan_files(root: pathlib.Path) -> list[pathlib.Path]:
    if not root.exists():
        return []
    if root.is_symlink() or not root.is_dir():
        raise ProviderError(f"authority scan root is unsafe: {root}")
    files: list[pathlib.Path] = []
    total = 0
    for directory, names, filenames in os.walk(root, followlinks=False):
        directory_path = pathlib.Path(directory)
        for name in names:
            child = directory_path / name
            if child.is_symlink():
                raise ProviderError(f"authority scan directory is a symlink: {child}")
        for name in filenames:
            child = directory_path / name
            metadata = child.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                raise ProviderError(f"authority scan file is not regular: {child}")
            if metadata.st_size > MAX_SCAN_FILE_BYTES:
                raise ProviderError(f"authority scan file is too large: {child}")
            total += metadata.st_size
            files.append(child)
            if len(files) > MAX_SCAN_FILES or total > MAX_SCAN_TOTAL_BYTES:
                raise ProviderError("authority scan exceeds its aggregate limit")
    return files


def remove_expected_aws_credential_export(environ: Mapping[str, str]) -> None:
    """Remove only the pinned AWS action's exact short-lived GITHUB_ENV export."""
    root = pathlib.Path(environ["RUNNER_TEMP"]) / "_runner_file_commands"
    credential_names = (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    )
    credentials = tuple(
        environ.get(name, "").encode("utf-8") for name in credential_names
    )
    if not all(credentials):
        raise ProviderError(
            "AWS credential environment is incomplete",
            diagnostic="runner-state-validation",
        )
    if (
        environ.get("AWS_REGION") != "us-east-1"
        or environ.get("AWS_DEFAULT_REGION") != "us-east-1"
    ):
        raise ProviderError(
            "AWS region environment is not canonical",
            diagnostic="runner-state-validation",
        )
    expected = (
        ("AWS_ACCESS_KEY_ID", ""),
        ("AWS_SECRET_ACCESS_KEY", ""),
        ("AWS_SESSION_TOKEN", ""),
        ("AWS_REGION", ""),
        ("AWS_DEFAULT_REGION", ""),
        ("AWS_DEFAULT_REGION", "us-east-1"),
        ("AWS_REGION", "us-east-1"),
    ) + tuple(
        (name, value.decode("utf-8"))
        for name, value in zip(credential_names, credentials, strict=True)
    )
    candidates: list[tuple[pathlib.Path, int, int]] = []
    try:
        for path in _iter_scan_files(root):
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode):
                    raise ProviderError("AWS credential export is not regular")
                chunks: list[bytes] = []
                remaining = metadata.st_size + 1
                while remaining:
                    chunk = os.read(descriptor, remaining)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                content = b"".join(chunks)
                if len(content) != metadata.st_size:
                    raise ProviderError("AWS credential export changed while reading")
                present = tuple(credential in content for credential in credentials)
                if not any(present):
                    continue
                try:
                    text = content.decode("utf-8")
                except UnicodeError as error:
                    raise ProviderError("AWS credential export is not UTF-8") from error
                if "\r" in text or not text.endswith("\n"):
                    raise ProviderError("AWS credential export has noncanonical lines")
                lines = text.splitlines()
                records: list[tuple[str, str]] = []
                delimiters: set[str] = set()
                index = 0
                while index < len(lines):
                    header = RUNNER_ENV_HEADER.fullmatch(lines[index])
                    if header is None or index + 2 >= len(lines):
                        raise ProviderError("AWS credential export has invalid grammar")
                    name, delimiter = header.groups()
                    if delimiter in delimiters or lines[index + 2] != delimiter:
                        raise ProviderError("AWS credential export has invalid delimiter")
                    delimiters.add(delimiter)
                    records.append((name, lines[index + 1]))
                    index += 3
                current = path.lstat()
                if not (
                    all(present)
                    and tuple(records) == expected
                    and len(delimiters) == len(expected)
                    and RUNNER_ENV_FILE.fullmatch(path.name) is not None
                    and path.parent == root
                    and metadata.st_nlink == 1
                    and current.st_nlink == 1
                    and current.st_dev == metadata.st_dev
                    and current.st_ino == metadata.st_ino
                ):
                    raise ProviderError("AWS credential export is not canonical")
                candidates.append((path, metadata.st_dev, metadata.st_ino))
            finally:
                os.close(descriptor)
    except (OSError, ProviderError) as error:
        raise ProviderError(
            "AWS credential export cleanup failed",
            diagnostic="runner-command-scan",
        ) from error
    if len(candidates) > 1:
        raise ProviderError(
            "AWS credential export is not unique",
            diagnostic="runner-command-scan",
        )
    if candidates:
        try:
            path, device, inode = candidates[0]
            current = path.lstat()
            if (
                current.st_nlink != 1
                or current.st_dev != device
                or current.st_ino != inode
            ):
                raise ProviderError("AWS credential export changed before cleanup")
            # Pinned actions have exited and no concurrent writer is authorized.
            path.unlink()
        except (OSError, ProviderError) as error:
            raise ProviderError(
                "AWS credential export cleanup failed",
                diagnostic="runner-command-scan",
            ) from error


def scan_authority_files(environ: Mapping[str, str]) -> None:
    runner_temp = pathlib.Path(environ["RUNNER_TEMP"])
    home = pathlib.Path(environ["HOME"])
    needles = [name.encode("ascii") for name in AUTHORITY_NAMES]
    needles.extend(
        name.encode("ascii")
        for name in ("aws_access_key_id", "aws_secret_access_key", "aws_session_token")
    )
    for name in AUTHORITY_NAMES:
        value = environ.get(name, "")
        if value:
            needles.append(value.encode("utf-8"))
    roots = (
        (runner_temp / "_runner_file_commands", "runner-command-scan"),
        (home / ".aws", "aws-home-scan"),
    )
    for root, diagnostic in roots:
        try:
            for path in _iter_scan_files(root):
                content = path.read_bytes()
                if any(needle in content for needle in needles):
                    raise ProviderError(f"authority remains in runner file: {path}")
        except (OSError, ProviderError) as error:
            raise ProviderError(
                "authority file scan failed", diagnostic=diagnostic
            ) from error


def validate_authority_descriptor(value: Any) -> dict[str, Any]:
    descriptor = _object(value, "release authority descriptor")
    _fields(
        descriptor,
        AUTHORITY_DESCRIPTOR_FIELDS,
        "release authority descriptor",
    )
    if descriptor["schema_version"] != 1 or isinstance(
        descriptor["schema_version"], bool
    ):
        raise ProviderError("release authority descriptor schema is invalid")
    environment = descriptor["environment"]
    if environment not in {"production", "staging"}:
        raise ProviderError("release authority descriptor environment is invalid")
    _match(COMMIT, descriptor["release_commit"], "authority release commit")
    _match(COMMIT, descriptor["state_commit"], "authority State commit")
    _match(REPOSITORY, descriptor["archive_repository"], "archive repository")
    _match(COMMIT, descriptor["archive_commit"], "archive commit")
    archive_path = descriptor["archive_path"]
    if not isinstance(archive_path, str):
        raise ProviderError("archive path is invalid")
    archive_name = pathlib.PurePosixPath(archive_path).name
    suffix = ".tar.age"
    if not archive_name.endswith(suffix):
        raise ProviderError("archive path is invalid")
    submission_id = archive_name[: -len(suffix)]
    _match(UUID7, submission_id, "archive submission_id")
    expected_path = f"archives/{submission_id.replace('-', '')[:2]}/{archive_name}"
    if archive_path != expected_path:
        raise ProviderError("archive path is not canonical")
    _match(DIGEST, descriptor["archive_ciphertext_sha256"], "archive digest")
    _parse_utc_milliseconds(descriptor["eligible_at"], "eligible_at")
    _match(DIGEST, descriptor["plan_sha256"], "release plan digest")
    if environment == "production":
        _match(UUID7, descriptor["started_event_id"], "release.started event_id")
        _match(
            DIGEST,
            descriptor["started_event_sha256"],
            "release.started event digest",
        )
    elif (
        descriptor["started_event_id"] != ""
        or descriptor["started_event_sha256"] != ""
    ):
        raise ProviderError("staging authority must not name release.started")
    return descriptor


def build_request_from_authority(
    descriptor_value: Any,
    sidecar_value: Any,
    ciphertext: bytes,
    trusted_now: dt.datetime,
    *,
    random_bytes: bytes | None = None,
    runner_nonce: str | None = None,
) -> dict[str, Any]:
    descriptor = validate_authority_descriptor(descriptor_value)
    sidecar = validate_sidecar(sidecar_value, ciphertext)
    envelope = validate_envelope(sidecar.get("key_envelope"))
    archive_path = descriptor["archive_path"]
    submission_id = pathlib.PurePosixPath(archive_path).name.removesuffix(".tar.age")
    archive_digest = descriptor["archive_ciphertext_sha256"]
    actual_digest = hashlib.sha256(ciphertext).hexdigest()
    for candidate, label in (
        (sidecar["submission_id"], "sidecar submission_id"),
        (envelope["submission_id"], "envelope submission_id"),
    ):
        if candidate != submission_id:
            raise ProviderError(f"{label} does not match release authority")
    for candidate, label in (
        (sidecar["sha256_ciphertext"], "sidecar ciphertext digest"),
        (envelope["archive_ciphertext_sha256"], "envelope ciphertext digest"),
        (actual_digest, "ciphertext bytes digest"),
    ):
        if candidate != archive_digest:
            raise ProviderError(f"{label} does not match release authority")
    if trusted_now.tzinfo is None or trusted_now.utcoffset() != dt.timedelta(0):
        raise ProviderError("trusted time must be timezone-aware UTC")
    if descriptor[
        "environment"
    ] == "production" and trusted_now < _parse_utc_milliseconds(
        descriptor["eligible_at"], "eligible_at"
    ):
        raise ProviderError("production release is not yet eligible")
    randomness = os.urandom(10) if random_bytes is None else random_bytes
    if not isinstance(randomness, bytes) or len(randomness) != 10:
        raise ProviderError("UUIDv7 randomness must contain exactly ten bytes")
    milliseconds = int(trusted_now.timestamp() * 1000)
    if not 0 <= milliseconds <= 0xFFFFFFFFFFFF:
        raise ProviderError("UUIDv7 time is outside its 48-bit range")
    raw = bytearray(milliseconds.to_bytes(6, "big") + randomness)
    raw[6] = 0x70 | (raw[6] & 0x0F)
    raw[8] = 0x80 | (raw[8] & 0x3F)
    encoded = raw.hex()
    request_id = (
        f"{encoded[:8]}-{encoded[8:12]}-{encoded[12:16]}-"
        f"{encoded[16:20]}-{encoded[20:]}"
    )
    nonce = os.urandom(32).hex() if runner_nonce is None else runner_nonce
    _match(DIGEST, nonce, "runner nonce")
    issued_at = trusted_now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    expires_at = (
        (trusted_now + dt.timedelta(minutes=5))
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )
    capability = {
        "schema_version": 1,
        "purpose": "lean-eval-release",
        "request_id": request_id,
        "submission_id": submission_id,
        "archive_repository": descriptor["archive_repository"],
        "archive_commit": descriptor["archive_commit"],
        "archive_path": archive_path,
        "archive_ciphertext_sha256": archive_digest,
        "data_key_id": envelope["data_key_id"],
        "runner_nonce": nonce,
        "issued_at": issued_at,
        "expires_at": expires_at,
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


def build_request(
    plan_value: Any,
    sidecar_value: Any,
    ciphertext: bytes,
    trusted_now: dt.datetime,
    *,
    random_bytes: bytes | None = None,
    runner_nonce: str | None = None,
) -> dict[str, Any]:
    plan = validate_execution_plan(plan_value)
    request = plan["request"]
    archive = request["archive"]
    submission = request["submission"]
    submission_id = submission["submission_id"]
    archive_path = archive["archive_path"]
    archive_digest = archive["archive_ciphertext_sha256"]
    sidecar = validate_sidecar(sidecar_value, ciphertext)
    envelope = validate_envelope(sidecar.get("key_envelope"))
    actual_digest = hashlib.sha256(ciphertext).hexdigest()
    if sidecar["submission_id"] != submission_id:
        raise ProviderError("sidecar submission_id does not match the release plan")
    if envelope["submission_id"] != submission_id:
        raise ProviderError("envelope submission_id does not match the release plan")
    if sidecar["sha256_ciphertext"] != archive_digest:
        raise ProviderError("sidecar ciphertext digest does not match the release plan")
    if envelope["archive_ciphertext_sha256"] != archive_digest:
        raise ProviderError("envelope ciphertext digest does not match the release plan")
    if actual_digest != archive_digest:
        raise ProviderError("ciphertext bytes digest does not match the release plan")
    if trusted_now.tzinfo is None or trusted_now.utcoffset() != dt.timedelta(0):
        raise ProviderError("trusted time must be timezone-aware UTC")
    randomness = os.urandom(10) if random_bytes is None else random_bytes
    if not isinstance(randomness, bytes) or len(randomness) != 10:
        raise ProviderError("UUIDv7 randomness must contain exactly ten bytes")
    milliseconds = int(trusted_now.timestamp() * 1000)
    if not 0 <= milliseconds <= 0xFFFFFFFFFFFF:
        raise ProviderError("UUIDv7 time is outside its 48-bit range")
    raw = bytearray(milliseconds.to_bytes(6, "big") + randomness)
    raw[6] = 0x70 | (raw[6] & 0x0F)
    raw[8] = 0x80 | (raw[8] & 0x3F)
    encoded = raw.hex()
    request_id = (
        f"{encoded[:8]}-{encoded[8:12]}-{encoded[12:16]}-"
        f"{encoded[16:20]}-{encoded[20:]}"
    )
    nonce = os.urandom(32).hex() if runner_nonce is None else runner_nonce
    _match(DIGEST, nonce, "runner nonce")
    issued_at = trusted_now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    expires_at = (trusted_now + dt.timedelta(minutes=5)).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")
    capability = {
        "schema_version": 1,
        "purpose": "lean-eval-release",
        "request_id": request_id,
        "submission_id": submission_id,
        "archive_repository": archive["archive_repository"],
        "archive_commit": archive["archive_commit"],
        "archive_path": archive_path,
        "archive_ciphertext_sha256": archive_digest,
        "data_key_id": envelope["data_key_id"],
        "runner_nonce": nonce,
        "issued_at": issued_at,
        "expires_at": expires_at,
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


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 4:
        raise ProviderError("literal provider requires four paths")
    authority_path, sidecar_path, ciphertext_path, output_path = map(
        pathlib.Path, arguments
    )
    try:
        remove_expected_aws_credential_export(os.environ)
        scan_authority_files(os.environ)
    except (KeyError, OSError, ProviderError, UnicodeError, ValueError) as error:
        diagnostic = (
            error.diagnostic
            if isinstance(error, ProviderError)
            else "runner-state-validation"
        )
        print("literal provider failed closed", file=sys.stderr)
        return {
            "runner-command-scan": 10,
            "aws-home-scan": 11,
            "runner-state-validation": 12,
        }[diagnostic]
    try:
        authority = json.loads(authority_path.read_text(encoding="utf-8"))
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        ciphertext = ciphertext_path.read_bytes()
        value = build_request_from_authority(
            authority,
            sidecar,
            ciphertext,
            dt.datetime.now(dt.timezone.utc),
        )
    except (KeyError, OSError, ProviderError, UnicodeError, ValueError):
        print("literal provider failed closed", file=sys.stderr)
        return 13
    try:
        output_path.write_text(
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        os.chmod(output_path, 0o600)
    except (OSError, UnicodeError, ValueError):
        print("literal provider failed closed", file=sys.stderr)
        return 14
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, OSError, ProviderError, UnicodeError, ValueError):
        print("literal provider failed closed", file=sys.stderr)
        raise SystemExit(1) from None
