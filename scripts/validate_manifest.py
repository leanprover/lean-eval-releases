"""Validate a delayed-source release against trusted State and bundle bytes."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import stat
import sys
from typing import Any

from embargo import eligible_at, parse_utc_milliseconds
from release_tree import TreeError, tree_digest

SHA256 = re.compile(r"[0-9a-f]{64}")
RESULT_ID = re.compile(r"r2_[0-9a-f]{64}")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
COMMIT = re.compile(r"[0-9a-f]{40}")
RELEASE_ID = re.compile(r"lean-eval-(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})")
SUBMISSION_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)


class ManifestError(ValueError):
    """A release manifest violates the publication contract."""


def object_value(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ManifestError(f"{label} must be an object with string keys")
    return value


def string_value(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ManifestError(f"{label} must be a string")
    return value


def canonical_archive_path(submission_id: str) -> str:
    """Return the only schema-version-1 audit-repository path for a submission ciphertext."""
    return f"archives/{submission_id.replace('-', '')[:2]}/{submission_id}.tar.age"


def load_state_snapshot(value: Any) -> dict[str, dict[str, str]]:
    snapshot = object_value(value, "State acceptance snapshot")
    if (
        set(snapshot) != {"schema_version", "submissions"}
        or snapshot["schema_version"] != 1
        or isinstance(snapshot["schema_version"], bool)
    ):
        raise ManifestError("State acceptance snapshot fields do not match schema version 1")
    submissions = object_value(snapshot["submissions"], "State acceptance submissions")
    trusted: dict[str, dict[str, str]] = {}
    for submission_id, raw_record in submissions.items():
        if SUBMISSION_ID.fullmatch(submission_id) is None:
            raise ManifestError(f"State submission id is not canonical: {submission_id!r}")
        record = object_value(raw_record, f"State submission {submission_id}")
        fields = {
            "accepted_at",
            "archive_repository",
            "archive_commit",
            "archive_path",
            "archive_ciphertext_sha256",
        }
        if set(record) != fields:
            raise ManifestError(f"State submission {submission_id} fields are not canonical")
        accepted_at = string_value(record["accepted_at"], "accepted_at")
        parse_utc_milliseconds(accepted_at)
        archive_repository = string_value(record["archive_repository"], "archive_repository")
        if REPOSITORY.fullmatch(archive_repository) is None:
            raise ManifestError(f"State submission {submission_id} archive repository is invalid")
        archive_commit = string_value(record["archive_commit"], "archive_commit")
        if COMMIT.fullmatch(archive_commit) is None:
            raise ManifestError(f"State submission {submission_id} archive commit is invalid")
        archive_path = string_value(record["archive_path"], "archive_path")
        if archive_path != canonical_archive_path(submission_id):
            raise ManifestError(f"State submission {submission_id} archive path is not canonical")
        archive_ciphertext_sha256 = string_value(record["archive_ciphertext_sha256"], "archive_ciphertext_sha256")
        if SHA256.fullmatch(archive_ciphertext_sha256) is None:
            raise ManifestError(f"State submission {submission_id} archive digest is invalid")
        trusted[submission_id] = {
            "accepted_at": accepted_at,
            "archive_repository": archive_repository,
            "archive_commit": archive_commit,
            "archive_path": archive_path,
            "archive_ciphertext_sha256": archive_ciphertext_sha256,
        }
    return trusted


def file_sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_manifest(
    value: Any,
    *,
    trusted_as_of: str,
    trusted_submissions: dict[str, dict[str, str]],
    bundle_root: pathlib.Path | None = None,
) -> int:
    as_of = parse_utc_milliseconds(trusted_as_of)
    manifest = object_value(value, "manifest")
    expected = {"schema_version", "release_id", "generated_at", "entries"}
    if set(manifest) != expected:
        raise ManifestError("manifest fields do not match schema version 1")
    if manifest["schema_version"] != 1 or isinstance(manifest["schema_version"], bool):
        raise ManifestError("schema_version must be integer 1")
    release_id = string_value(manifest["release_id"], "release_id")
    match = RELEASE_ID.fullmatch(release_id)
    if match is None:
        raise ManifestError("release_id is not canonical")
    try:
        release_date = dt.date.fromisoformat(match.group("date"))
    except ValueError as error:
        raise ManifestError("release_id does not contain a real calendar date") from error
    generated_at = string_value(manifest["generated_at"], "generated_at")
    generated = parse_utc_milliseconds(generated_at)
    if generated != as_of:
        raise ManifestError("generated_at must equal the trusted workflow as-of time")
    if release_date != generated.date():
        raise ManifestError("release_id date must equal generated_at date")
    entries = manifest["entries"]
    if not isinstance(entries, list) or not entries:
        raise ManifestError("entries must be a nonempty array")

    root: pathlib.Path | None = None
    if bundle_root is not None:
        if bundle_root.is_symlink():
            raise ManifestError("bundle root must not be a symlink")
        try:
            root = bundle_root.resolve(strict=True)
        except OSError as error:
            raise ManifestError("bundle root does not exist") from error
        if not root.is_dir():
            raise ManifestError("bundle root must be a regular directory")

    seen: set[str] = set()
    for index, raw_entry in enumerate(entries):
        entry = object_value(raw_entry, f"entries[{index}]")
        fields = {
            "result_id",
            "submission_id",
            "accepted_at",
            "eligible_at",
            "archive_repository",
            "archive_commit",
            "archive_path",
            "archive_ciphertext_sha256",
            "bundle_sha256",
            "bundle_path",
            "release_tree_sha256",
            "release_path",
            "license",
        }
        if set(entry) != fields:
            raise ManifestError(f"entries[{index}] fields do not match schema version 1")
        result_id = string_value(entry["result_id"], "result_id")
        if RESULT_ID.fullmatch(result_id) is None:
            raise ManifestError(f"entries[{index}].result_id is not canonical")
        if result_id in seen:
            raise ManifestError(f"duplicate result_id {result_id}")
        seen.add(result_id)
        submission_id = string_value(entry["submission_id"], "submission_id")
        if SUBMISSION_ID.fullmatch(submission_id) is None:
            raise ManifestError(f"entries[{index}].submission_id is not canonical")

        trusted = trusted_submissions.get(submission_id)
        if trusted is None:
            raise ManifestError(f"{submission_id}: no acceptance exists in trusted State")
        accepted_at = string_value(entry["accepted_at"], "accepted_at")
        if accepted_at != trusted["accepted_at"]:
            raise ManifestError(f"{submission_id}: accepted_at differs from trusted State")
        declared_eligible = string_value(entry["eligible_at"], "eligible_at")
        if declared_eligible != eligible_at(accepted_at):
            raise ManifestError(f"{submission_id}: eligible_at does not equal two calendar months")
        if parse_utc_milliseconds(declared_eligible) > generated:
            raise ManifestError(f"{submission_id}: embargo had not expired at generation")

        archive_repository = string_value(entry["archive_repository"], "archive_repository")
        if REPOSITORY.fullmatch(archive_repository) is None:
            raise ManifestError(f"{submission_id}: archive_repository is not canonical")
        archive_commit = string_value(entry["archive_commit"], "archive_commit")
        if COMMIT.fullmatch(archive_commit) is None:
            raise ManifestError(f"{submission_id}: archive_commit is not canonical")
        archive_path = string_value(entry["archive_path"], "archive_path")
        if archive_path != canonical_archive_path(submission_id):
            raise ManifestError(f"{submission_id}: archive_path is not canonical")
        for locator_field in ("archive_repository", "archive_commit", "archive_path"):
            if entry[locator_field] != trusted[locator_field]:
                raise ManifestError(
                    f"{submission_id}: {locator_field} differs from trusted State"
                )
        archive_ciphertext_sha256 = string_value(entry["archive_ciphertext_sha256"], "archive_ciphertext_sha256")
        if SHA256.fullmatch(archive_ciphertext_sha256) is None:
            raise ManifestError(f"{submission_id}: archive_ciphertext_sha256 is not lowercase SHA-256")
        if archive_ciphertext_sha256 != trusted["archive_ciphertext_sha256"]:
            raise ManifestError(f"{submission_id}: archive digest differs from trusted State")
        bundle_sha256 = string_value(entry["bundle_sha256"], "bundle_sha256")
        if SHA256.fullmatch(bundle_sha256) is None:
            raise ManifestError(f"{submission_id}: bundle_sha256 is not lowercase SHA-256")
        bundle_path = string_value(entry["bundle_path"], "bundle_path")
        if bundle_path != f"sources/{submission_id}.tar.gz":
            raise ManifestError(f"{submission_id}: bundle_path is not canonical")
        release_path = string_value(entry["release_path"], "release_path")
        eligible_instant = parse_utc_milliseconds(declared_eligible)
        expected_release_path = (
            f"releases/{eligible_instant.year:04d}/{eligible_instant.month:02d}/{result_id}"
        )
        if release_path != expected_release_path:
            raise ManifestError(f"{result_id}: release_path is not canonical")
        release_tree_sha256 = string_value(
            entry["release_tree_sha256"], "release_tree_sha256"
        )
        if SHA256.fullmatch(release_tree_sha256) is None:
            raise ManifestError(
                f"{result_id}: release_tree_sha256 is not lowercase SHA-256"
            )
        if root is not None:
            absolute_bundle = root / bundle_path
            relative_parts = pathlib.PurePosixPath(bundle_path).parts
            cursor = root
            has_symlink = False
            for part in relative_parts:
                cursor = cursor / part
                has_symlink = has_symlink or cursor.is_symlink()
            try:
                resolved_bundle = absolute_bundle.resolve(strict=True)
            except OSError as error:
                raise ManifestError(f"{submission_id}: bundle path does not exist") from error
            if has_symlink or not resolved_bundle.is_relative_to(root):
                raise ManifestError(f"{submission_id}: bundle path must not traverse a symlink")
            if (
                not resolved_bundle.is_file()
                or stat.S_IMODE(resolved_bundle.stat().st_mode) != 0o644
            ):
                raise ManifestError(
                    f"{submission_id}: bundle must be a regular mode-0644 file"
                )
            if file_sha256(resolved_bundle) != bundle_sha256:
                raise ManifestError(f"{submission_id}: bundle bytes do not match bundle_sha256")
            release_root = root.joinpath(*pathlib.PurePosixPath(release_path).parts)
            release_cursor = root
            release_has_symlink = False
            for part in pathlib.PurePosixPath(release_path).parts:
                release_cursor = release_cursor / part
                release_has_symlink = release_has_symlink or release_cursor.is_symlink()
            if release_has_symlink:
                raise ManifestError(f"{result_id}: release path must not traverse a symlink")
            try:
                actual_tree_digest = tree_digest(release_root)
            except (OSError, TreeError) as error:
                raise ManifestError(f"{result_id}: release tree is not canonical: {error}") from error
            if actual_tree_digest != release_tree_sha256:
                raise ManifestError(
                    f"{result_id}: release tree bytes do not match release_tree_sha256"
                )
        if entry["license"] != "Apache-2.0":
            raise ManifestError(f"{submission_id}: license must be Apache-2.0")
    return len(entries)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=pathlib.Path)
    parser.add_argument("--trusted-as-of", required=True)
    parser.add_argument("--state-acceptance-snapshot", required=True, type=pathlib.Path)
    parser.add_argument("--bundle-root", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        state = json.loads(args.state_acceptance_snapshot.read_text(encoding="utf-8"))
        count = validate_manifest(
            json.loads(args.manifest.read_text(encoding="utf-8")),
            trusted_as_of=args.trusted_as_of,
            trusted_submissions=load_state_snapshot(state),
            bundle_root=args.bundle_root,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ManifestError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"validated {count} delayed release entry or entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
