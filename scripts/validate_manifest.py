#!/usr/bin/env python3
"""Validate a delayed-source release manifest without touching source bytes."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Any

from embargo import eligible_at, parse_utc_milliseconds

SHA256 = re.compile(r"[0-9a-f]{64}")
RELEASE_ID = re.compile(r"lean-eval-[0-9]{4}-[0-9]{2}-[0-9]{2}")


class ManifestError(ValueError):
    """A release manifest violates the publication contract."""


def object_value(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ManifestError(f"{label} must be an object")
    return value


def string_value(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ManifestError(f"{label} must be a string")
    return value


def validate_manifest(value: Any) -> int:
    manifest = object_value(value, "manifest")
    expected = {"schema_version", "release_id", "generated_at", "entries"}
    if set(manifest) != expected:
        raise ManifestError("manifest fields do not match schema version 1")
    if manifest["schema_version"] != 1 or isinstance(manifest["schema_version"], bool):
        raise ManifestError("schema_version must be integer 1")
    release_id = string_value(manifest["release_id"], "release_id")
    if RELEASE_ID.fullmatch(release_id) is None:
        raise ManifestError("release_id is not canonical")
    generated_at = string_value(manifest["generated_at"], "generated_at")
    generated = parse_utc_milliseconds(generated_at)
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
            "archive_sha256",
            "bundle_sha256",
            "bundle_path",
            "license",
        }
        if set(entry) != fields:
            raise ManifestError(f"entries[{index}] fields do not match schema version 1")
        submission_id = string_value(entry["submission_id"], "submission_id")
        if submission_id in seen:
            raise ManifestError(f"duplicate submission_id {submission_id}")
        seen.add(submission_id)
        accepted_at = string_value(entry["accepted_at"], "accepted_at")
        declared_eligible = string_value(entry["eligible_at"], "eligible_at")
        if declared_eligible != eligible_at(accepted_at):
            raise ManifestError(f"{submission_id}: eligible_at does not equal two calendar months")
        if parse_utc_milliseconds(declared_eligible) > generated:
            raise ManifestError(f"{submission_id}: embargo had not expired at generation")
        for name in ("archive_sha256", "bundle_sha256"):
            if SHA256.fullmatch(string_value(entry[name], name)) is None:
                raise ManifestError(f"{submission_id}: {name} is not lowercase SHA-256")
        bundle_path = string_value(entry["bundle_path"], "bundle_path")
        if bundle_path != f"sources/{submission_id}.tar.gz" or ".." in bundle_path:
            raise ManifestError(f"{submission_id}: bundle_path is not canonical")
        if entry["license"] != "Apache-2.0":
            raise ManifestError(f"{submission_id}: license must be Apache-2.0")
    return len(entries)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        count = validate_manifest(json.loads(args.manifest.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError, ManifestError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"validated {count} delayed release entry or entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
