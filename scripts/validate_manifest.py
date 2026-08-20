#!/usr/bin/env python3
"""Validate a delayed-source release against trusted State and bundle bytes."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import sys
from typing import Any

from embargo import eligible_at, parse_utc_milliseconds

SHA256 = re.compile(r"[0-9a-f]{64}")
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
        if set(record) != {"accepted_at", "archive_ciphertext_sha256"}:
            raise ManifestError(f"State submission {submission_id} fields are not canonical")
        accepted_at = string_value(record["accepted_at"], "accepted_at")
        parse_utc_milliseconds(accepted_at)
        archive_ciphertext_sha256 = string_value(record["archive_ciphertext_sha256"], "archive_ciphertext_sha256")
        if SHA256.fullmatch(archive_ciphertext_sha256) is None:
            raise ManifestError(f"State submission {submission_id} archive digest is invalid")
        trusted[submission_id] = {
            "accepted_at": accepted_at,
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
    if not isinstance(entries, list):
        raise ManifestError("entries must be an array")

    seen: set[str] = set()
    for index, raw_entry in enumerate(entries):
        entry = object_value(raw_entry, f"entries[{index}]")
        fields = {
            "submission_id",
            "accepted_at",
            "eligible_at",
            "archive_ciphertext_sha256",
            "bundle_sha256",
            "bundle_path",
            "license",
        }
        if set(entry) != fields:
            raise ManifestError(f"entries[{index}] fields do not match schema version 1")
        submission_id = string_value(entry["submission_id"], "submission_id")
        if SUBMISSION_ID.fullmatch(submission_id) is None:
            raise ManifestError(f"entries[{index}].submission_id is not canonical")
        if submission_id in seen:
            raise ManifestError(f"duplicate submission_id {submission_id}")
        seen.add(submission_id)

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
        if bundle_root is not None:
            root = bundle_root.resolve()
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
            if not resolved_bundle.is_file() or file_sha256(resolved_bundle) != bundle_sha256:
                raise ManifestError(f"{submission_id}: bundle bytes do not match bundle_sha256")
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
            bundle_root=args.bundle_root.resolve(),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ManifestError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"validated {count} delayed release entry or entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
