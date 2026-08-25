"""Source mirror for the literal, authority-bearing workflow provider phase.

The workflows embed this file byte-for-byte and execute only the embedded copy
with ``python -I -``. They never execute the checked-out mirror while AWS or
OIDC authority exists. Tests enforce that both embedded copies remain exact.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
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
PROBLEM = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
COMMIT = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
BASE64 = re.compile(r"[A-Za-z0-9+/]+={0,2}")
AGE_RECIPIENT = re.compile(r"age1[0-9a-z]{40,4090}")
ADAPTER = re.compile(r"[a-z][a-z0-9-]{0,63}-v[1-9][0-9]*")
MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_WRAPPED_BYTES = 16_384
MAX_SCAN_FILES = 1024
MAX_SCAN_FILE_BYTES = 8 * 1024 * 1024
MAX_SCAN_TOTAL_BYTES = 32 * 1024 * 1024

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


class ProviderError(ValueError):
    """Literal provider input or runner authority state is invalid."""


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(
        isinstance(key, str) for key in value
    ):
        raise ProviderError(f"{label} must be an object")
    return value


def _match(pattern: re.Pattern[str], value: Any, label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ProviderError(f"{label} is invalid")
    return value


def _bounded_integer(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER:
        raise ProviderError(f"{label} must be a nonnegative safe integer")
    return value


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
    for root in (runner_temp / "_runner_file_commands", home / ".aws"):
        for path in _iter_scan_files(root):
            content = path.read_bytes()
            if any(needle in content for needle in needles):
                raise ProviderError(f"authority remains in runner file: {path}")


def build_request(
    plan_value: Any,
    sidecar_value: Any,
    ciphertext: bytes,
    trusted_now: dt.datetime,
    *,
    random_bytes: bytes | None = None,
    runner_nonce: str | None = None,
) -> dict[str, Any]:
    plan = _object(plan_value, "release plan")
    if plan.get("kind") != "execution":
        raise ProviderError("release plan must contain one execution")
    request = _object(plan.get("request"), "release request")
    archive = _object(request.get("archive"), "release archive")
    submission = _object(request.get("submission"), "release submission")
    submission_id = _match(
        UUID7, submission.get("submission_id"), "release submission_id"
    )
    _match(
        REPOSITORY,
        archive.get("archive_repository"),
        "release archive repository",
    )
    _match(COMMIT, archive.get("archive_commit"), "release archive commit")
    archive_path = archive.get("archive_path")
    prefix = submission_id.replace("-", "")[:2]
    if archive_path != f"archives/{prefix}/{submission_id}.tar.age":
        raise ProviderError("release archive path is not canonical")
    archive_digest = _match(
        DIGEST,
        archive.get("archive_ciphertext_sha256"),
        "release archive digest",
    )
    if archive.get("encrypted") is not True:
        raise ProviderError("release archive must be encrypted")
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
    plan_path, sidecar_path, ciphertext_path, output_path = map(
        pathlib.Path, arguments
    )
    scan_authority_files(os.environ)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    ciphertext = ciphertext_path.read_bytes()
    value = build_request(
        plan,
        sidecar,
        ciphertext,
        dt.datetime.now(dt.timezone.utc),
    )
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
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, OSError, ProviderError, UnicodeError, ValueError) as error:
        print(f"literal provider failed closed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
