"""Reconstruct one public release tree from one already-decrypted archive.

This tool is provider-neutral and performs no fetch, unwrap, publication, Git
write, or State write. Its caller must authenticate the immutable ciphertext,
consume one release-purpose capability, and decrypt before invoking it.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import pathlib
import shutil
import sys
import tarfile
import tempfile
from typing import Any

from embargo import eligible_at, parse_utc_milliseconds
from release_orchestrator import (
    COMMIT,
    DIGEST,
    LOGIN,
    PROBLEM,
    REPOSITORY,
    RESULT_ID,
    UUID7,
    ReleaseError,
    _fields,
    _match,
    _object,
    _production_metadata,
    _safe_integer,
    _timestamp,
    canonical_archive_path,
    canonical_json_digest,
    canonical_release_path,
    result_id,
    validate_controller_binding,
)
from release_tree import TreeError, tree_digest
from validate_manifest import load_state_snapshot, validate_manifest

MAX_COMPRESSED_ARCHIVE_BYTES = 10 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 4096
MAX_ARCHIVE_MEMBER_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_RELEASE_FILES = 1024
MAX_RELEASE_FILE_BYTES = 8 * 1024 * 1024
MAX_RELEASE_TOTAL_BYTES = 32 * 1024 * 1024


class ReconstructionError(ValueError):
    """The plan, decrypted archive, or requested output is unsafe."""


def _validate_execution_plan(value: Any) -> dict[str, Any]:
    plan = _object(value, "release plan")
    _fields(plan, {"schema_version", "kind", "started_transition", "request"}, "release plan")
    if plan["schema_version"] != 1 or isinstance(plan["schema_version"], bool):
        raise ReconstructionError("release plan schema_version must be integer 1")
    if plan["kind"] != "execution":
        raise ReconstructionError("release plan must contain one execution")

    started = _object(plan["started_transition"], "started_transition")
    _fields(
        started,
        {"event_type", "subject_id", "causation_event_id", "payload"},
        "started_transition",
    )
    if started["event_type"] != "release.started":
        raise ReconstructionError("started transition must be release.started")
    subject = _match(RESULT_ID, started["subject_id"], "started_transition.subject_id")
    _match(UUID7, started["causation_event_id"], "started_transition.causation_event_id")
    started_payload = _object(started["payload"], "started_transition.payload")
    _fields(started_payload, {"attempt"}, "started_transition.payload")
    _safe_integer(started_payload["attempt"], "started_transition.payload.attempt", 1)

    request = _object(plan["request"], "request")
    request_fields = {"schema_version", "result", "submission", "archive", "release"}
    if "controller" in request:
        request_fields.add("controller")
    _fields(request, request_fields, "request")
    if request["schema_version"] != 1 or isinstance(request["schema_version"], bool):
        raise ReconstructionError("request schema_version must be integer 1")
    if "controller" in request:
        try:
            validate_controller_binding(request["controller"])
        except ReleaseError as error:
            raise ReconstructionError(str(error)) from error

    result = _object(request["result"], "request.result")
    _fields(
        result,
        {"result_id", "problem_id", "statement_revision", "commit", "tree_digest"},
        "request.result",
    )
    identity = _match(RESULT_ID, result["result_id"], "request.result.result_id")
    problem = _match(PROBLEM, result["problem_id"], "request.result.problem_id")
    revision = _safe_integer(result["statement_revision"], "request.result.statement_revision", 1)
    _match(COMMIT, result["commit"], "request.result.commit")
    _match(DIGEST, result["tree_digest"], "request.result.tree_digest")
    if identity != subject:
        raise ReconstructionError("started transition subject differs from result_id")

    submission = _object(request["submission"], "request.submission")
    _fields(
        submission,
        {"submission_id", "owner_login", "declared_model", "production_metadata"},
        "request.submission",
    )
    submission_id = _match(UUID7, submission["submission_id"], "request.submission.submission_id")
    login = _match(LOGIN, submission["owner_login"], "request.submission.owner_login")
    model = submission["declared_model"]
    if (
        not isinstance(model, str)
        or not model
        or len(model.encode("utf-8")) > 256
        or any(ord(character) <= 0x1F or ord(character) == 0x7F for character in model)
    ):
        raise ReconstructionError("request.submission.declared_model is invalid")
    if identity != result_id(login, model, problem, revision):
        raise ReconstructionError("request result_id does not match its deterministic identity")
    _production_metadata(submission["production_metadata"], "request.submission.production_metadata")

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
    _match(REPOSITORY, archive["archive_repository"], "request.archive.archive_repository")
    _match(COMMIT, archive["archive_commit"], "request.archive.archive_commit")
    _match(DIGEST, archive["archive_ciphertext_sha256"], "request.archive.archive_ciphertext_sha256")
    if archive["archive_path"] != canonical_archive_path(submission_id):
        raise ReconstructionError("request archive_path does not match submission_id")
    if archive["encrypted"] is not True:
        raise ReconstructionError("request archive must be encrypted")

    release = _object(request["release"], "request.release")
    _fields(release, {"accepted_at", "eligible_at", "path", "license"}, "request.release")
    accepted = _timestamp(release["accepted_at"], "request.release.accepted_at")
    eligible = _timestamp(release["eligible_at"], "request.release.eligible_at")
    if eligible != eligible_at(accepted):
        raise ReconstructionError("request release eligibility is not two UTC calendar months")
    if release["path"] != canonical_release_path(identity, eligible):
        raise ReconstructionError("request release path is not canonical")
    if release["license"] != "Apache-2.0":
        raise ReconstructionError("request release license must be Apache-2.0")
    return plan


def _safe_member_name(name: str) -> pathlib.PurePosixPath:
    if (
        not name
        or "\\" in name
        or "\x00" in name
        or any(ord(character) <= 0x1F or ord(character) == 0x7F for character in name)
    ):
        raise ReconstructionError(f"archive member has an unsafe name: {name!r}")
    raw = name.removesuffix("/")
    if not raw or any(part in {"", ".", ".."} for part in raw.split("/")):
        raise ReconstructionError(f"archive member escapes its root: {name!r}")
    path = pathlib.PurePosixPath(name)
    if path.is_absolute():
        raise ReconstructionError(f"archive member escapes its root: {name!r}")
    return path


def _read_release_sources(plaintext_tar: pathlib.Path) -> dict[str, bytes]:
    if plaintext_tar.is_symlink() or not plaintext_tar.is_file():
        raise ReconstructionError("plaintext archive must be one regular file")
    if plaintext_tar.stat().st_size > MAX_COMPRESSED_ARCHIVE_BYTES:
        raise ReconstructionError("plaintext archive exceeds the 10 MiB compressed cap")

    selected: dict[str, bytes] = {}
    seen: set[str] = set()
    selected_total = 0
    declared_total = 0
    member_count = 0
    try:
        with tarfile.open(plaintext_tar, mode="r|gz") as archive:
            for member in archive:
                member_count += 1
                if member_count > MAX_ARCHIVE_MEMBERS:
                    raise ReconstructionError("plaintext archive has too many members")
                path = _safe_member_name(member.name)
                canonical_name = path.as_posix()
                if canonical_name in seen:
                    raise ReconstructionError(f"plaintext archive repeats member {canonical_name!r}")
                seen.add(canonical_name)
                if not (member.isdir() or member.isreg()):
                    raise ReconstructionError(
                        f"plaintext archive contains a link or special member: {canonical_name!r}"
                    )
                if member.isdir():
                    continue
                if member.size < 0 or member.size > MAX_ARCHIVE_MEMBER_BYTES:
                    raise ReconstructionError(f"archive member size is unsafe: {canonical_name!r}")
                declared_total += member.size
                if declared_total > MAX_ARCHIVE_TOTAL_BYTES:
                    raise ReconstructionError("plaintext archive expands beyond its byte cap")

                relative: pathlib.PurePosixPath | None = None
                if path == pathlib.PurePosixPath("source/Submission.lean"):
                    relative = pathlib.PurePosixPath("Submission.lean")
                elif (
                    len(path.parts) >= 3
                    and path.parts[:2] == ("source", "Submission")
                    and path.suffix == ".lean"
                ):
                    relative = pathlib.PurePosixPath(*path.parts[1:])
                if relative is None:
                    continue
                if member.size > MAX_RELEASE_FILE_BYTES:
                    raise ReconstructionError(f"release source is too large: {canonical_name!r}")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ReconstructionError(f"cannot read release source {canonical_name!r}")
                content = extracted.read(MAX_RELEASE_FILE_BYTES + 1)
                if len(content) != member.size or len(content) > MAX_RELEASE_FILE_BYTES:
                    raise ReconstructionError(f"release source size mismatch: {canonical_name!r}")
                try:
                    content.decode("utf-8")
                except UnicodeDecodeError as error:
                    raise ReconstructionError(f"release source is not UTF-8: {canonical_name!r}") from error
                selected[relative.as_posix()] = content
                selected_total += len(content)
                if (
                    len(selected) > MAX_RELEASE_FILES
                    or selected_total > MAX_RELEASE_TOTAL_BYTES
                ):
                    raise ReconstructionError("selected release source exceeds its file or byte cap")
    except (tarfile.TarError, EOFError, OSError) as error:
        raise ReconstructionError("plaintext archive is not one valid gzip tar stream") from error
    submission = selected.get("Submission.lean")
    if submission is None or not submission:
        raise ReconstructionError("plaintext archive has no nonempty source/Submission.lean")
    return selected


def _write_deterministic_bundle(path: pathlib.Path, sources: dict[str, bytes]) -> str:
    path.parent.mkdir(mode=0o755, parents=True)
    buffer = io.BytesIO()
    with (
        gzip.GzipFile(filename="", mode="wb", fileobj=buffer, mtime=0) as compressed,
        tarfile.open(
            fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT
        ) as bundle,
    ):
        for name in sorted(sources, key=lambda item: item.encode("utf-8")):
            content = sources[name]
            member = tarfile.TarInfo(name=name)
            member.size = len(content)
            member.mode = 0o644
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.mtime = 0
            bundle.addfile(member, io.BytesIO(content))
    content = buffer.getvalue()
    path.write_bytes(content)
    path.chmod(0o644)
    return hashlib.sha256(content).hexdigest()


def _metadata(plan: dict[str, Any], generated_at: str, sources: dict[str, bytes]) -> dict[str, Any]:
    request = plan["request"]
    return {
        "schema_version": 1,
        "generated_at": generated_at,
        "result": request["result"],
        "submission": request["submission"],
        "archive": request["archive"],
        "release": request["release"],
        "source_files": [
            {
                "path": name,
                "size_bytes": len(sources[name]),
                "sha256": hashlib.sha256(sources[name]).hexdigest(),
            }
            for name in sorted(sources, key=lambda item: item.encode("utf-8"))
        ],
    }


def reconstruct_one(
    *,
    plan_value: Any,
    plaintext_tar: pathlib.Path,
    trusted_as_of: str,
    state_snapshot_value: Any,
    output_root: pathlib.Path,
) -> dict[str, Any]:
    plan = _validate_execution_plan(plan_value)
    generated = _timestamp(trusted_as_of, "trusted_as_of")
    if parse_utc_milliseconds(plan["request"]["release"]["eligible_at"]) > parse_utc_milliseconds(generated):
        raise ReconstructionError("release embargo has not expired at trusted_as_of")
    trusted = load_state_snapshot(state_snapshot_value)
    controller = plan["request"].get("controller")
    if (
        controller is not None
        and controller["acceptance_snapshot_sha256"]
        != canonical_json_digest(state_snapshot_value, "acceptance-snapshot")
    ):
        raise ReconstructionError(
            "controller qualification does not bind the exact acceptance snapshot"
        )
    sources = _read_release_sources(plaintext_tar)
    if output_root.exists() or output_root.is_symlink():
        raise ReconstructionError("output root must not already exist")
    output_root.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    staging = pathlib.Path(
        tempfile.mkdtemp(prefix=f".{output_root.name}-", dir=output_root.parent)
    )
    try:
        request = plan["request"]
        release_relative = pathlib.PurePosixPath(request["release"]["path"])
        release_root = staging.joinpath(*release_relative.parts)
        release_root.mkdir(mode=0o755, parents=True)
        for name, content in sorted(sources.items()):
            target = release_root.joinpath(*pathlib.PurePosixPath(name).parts)
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            target.write_bytes(content)
            target.chmod(0o644)

        license_source = pathlib.Path(__file__).resolve().parents[1] / "LICENSE"
        license_bytes = license_source.read_bytes()
        (release_root / "LICENSE").write_bytes(license_bytes)
        (release_root / "LICENSE").chmod(0o644)
        metadata = _metadata(plan, generated, sources)
        (release_root / "metadata.json").write_text(
            json.dumps(metadata, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (release_root / "metadata.json").chmod(0o644)

        submission_id = request["submission"]["submission_id"]
        bundle_relative = f"sources/{submission_id}.tar.gz"
        bundle_digest = _write_deterministic_bundle(staging / bundle_relative, sources)
        release_digest = tree_digest(release_root)
        manifest = {
            "schema_version": 1,
            "release_id": f"lean-eval-{generated[:10]}",
            "generated_at": generated,
            "entries": [
                {
                    "result_id": request["result"]["result_id"],
                    "submission_id": submission_id,
                    "accepted_at": request["release"]["accepted_at"],
                    "eligible_at": request["release"]["eligible_at"],
                    "archive_repository": request["archive"]["archive_repository"],
                    "archive_commit": request["archive"]["archive_commit"],
                    "archive_path": request["archive"]["archive_path"],
                    "archive_ciphertext_sha256": request["archive"]["archive_ciphertext_sha256"],
                    "bundle_sha256": bundle_digest,
                    "bundle_path": bundle_relative,
                    "release_tree_sha256": release_digest,
                    "release_path": request["release"]["path"],
                    "license": "Apache-2.0",
                }
            ],
        }
        manifest_path = staging / "release-manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        validate_manifest(
            manifest,
            trusted_as_of=generated,
            trusted_submissions=trusted,
            bundle_root=staging,
        )
        os.replace(staging, output_root)
        return manifest
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=pathlib.Path)
    parser.add_argument("--plaintext-tar", required=True, type=pathlib.Path)
    parser.add_argument("--trusted-as-of", required=True)
    parser.add_argument("--state-acceptance-snapshot", required=True, type=pathlib.Path)
    parser.add_argument("--output-root", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        manifest = reconstruct_one(
            plan_value=json.loads(args.plan.read_text(encoding="utf-8")),
            plaintext_tar=args.plaintext_tar,
            trusted_as_of=args.trusted_as_of,
            state_snapshot_value=json.loads(
                args.state_acceptance_snapshot.read_text(encoding="utf-8")
            ),
            output_root=args.output_root,
        )
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        ReleaseError,
        ReconstructionError,
        TreeError,
        ValueError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "release_id": manifest["release_id"],
                "result_id": manifest["entries"][0]["result_id"],
                "release_tree_sha256": manifest["entries"][0]["release_tree_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
