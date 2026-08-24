#!/usr/bin/env python3
"""Classify a release as new, already published, or unsafe to retry."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
from typing import Any

from release_tree import TreeError, canonical_release_files

RESULT_ID = re.compile(r"r2_[0-9a-f]{64}")
SUBMISSION_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
COMMIT = re.compile(r"[0-9a-f]{40}")


class PublicationClassificationError(ValueError):
    """Existing publication state cannot be reconciled safely."""


def _git(root: pathlib.Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise PublicationClassificationError("release history lookup failed") from error
    return completed.stdout.strip()


def _release_relative_path(value: str) -> pathlib.PurePosixPath:
    path = pathlib.PurePosixPath(value)
    parts = path.parts
    if (
        len(parts) != 4
        or parts[0] != "releases"
        or re.fullmatch(r"[0-9]{4}", parts[1]) is None
        or re.fullmatch(r"(?:0[1-9]|1[0-2])", parts[2]) is None
        or RESULT_ID.fullmatch(parts[3]) is None
    ):
        raise PublicationClassificationError("release path is not canonical")
    return path


def _regular_file(path: pathlib.Path, root: pathlib.Path, label: str) -> pathlib.Path:
    if path.is_symlink():
        raise PublicationClassificationError(f"{label} must not be a symlink")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise PublicationClassificationError(f"{label} is missing") from error
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise PublicationClassificationError(f"{label} is not a regular in-tree file")
    return resolved


def _stable_release_projection(root: pathlib.Path) -> dict[str, bytes]:
    try:
        files = canonical_release_files(root)
    except (OSError, TreeError) as error:
        raise PublicationClassificationError("release tree is not canonical") from error
    projection: dict[str, bytes] = {}
    resolved_root = root.resolve(strict=True)
    for relative in files:
        name = relative.as_posix()
        if name == "LICENSE":
            continue
        file_path = _regular_file(resolved_root / relative, resolved_root, name)
        if name == "metadata.json":
            try:
                metadata = json.loads(file_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                raise PublicationClassificationError(
                    "metadata.json is invalid"
                ) from error
            if not isinstance(metadata, dict) or "generated_at" not in metadata:
                raise PublicationClassificationError("metadata.json lacks generated_at")
            stable = {
                key: value for key, value in metadata.items() if key != "generated_at"
            }
            projection[name] = json.dumps(
                stable,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        else:
            projection[name] = file_path.read_bytes()
    return projection


def classify_publication(
    release_root: pathlib.Path,
    reconstructed_root: pathlib.Path,
    release_path: str,
    submission_id: str,
) -> dict[str, Any]:
    relative = _release_relative_path(release_path)
    if SUBMISSION_ID.fullmatch(submission_id) is None:
        raise PublicationClassificationError("submission id is not canonical")
    release_root = release_root.resolve(strict=True)
    reconstructed_root = reconstructed_root.resolve(strict=True)
    existing_release = release_root.joinpath(*relative.parts)
    reconstructed_release = reconstructed_root.joinpath(*relative.parts)
    reconstructed_projection = _stable_release_projection(reconstructed_release)

    bundle_relative = pathlib.PurePosixPath("sources", f"{submission_id}.tar.gz")
    reconstructed_bundle = _regular_file(
        reconstructed_root.joinpath(*bundle_relative.parts),
        reconstructed_root,
        "reconstructed source bundle",
    )
    existing_bundle_path = release_root.joinpath(*bundle_relative.parts)
    bundle_exists = existing_bundle_path.exists() or existing_bundle_path.is_symlink()
    if bundle_exists:
        existing_bundle = _regular_file(
            existing_bundle_path, release_root, "published source bundle"
        )
        if existing_bundle.read_bytes() != reconstructed_bundle.read_bytes():
            raise PublicationClassificationError(
                "published source bundle differs from reconstruction"
            )

    history = _git(
        release_root,
        "log",
        "--diff-filter=A",
        "--format=%H",
        "--",
        relative.as_posix(),
    ).splitlines()
    for commit in history:
        if COMMIT.fullmatch(commit) is None:
            raise PublicationClassificationError(
                "release history contains an invalid commit"
            )
    if history:
        if not existing_release.exists() or existing_release.is_symlink():
            raise PublicationClassificationError(
                "previously published release is absent; refusing republication"
            )
        if not bundle_exists:
            raise PublicationClassificationError(
                "published release is missing its source bundle"
            )
        if _stable_release_projection(existing_release) != reconstructed_projection:
            raise PublicationClassificationError(
                "published release differs from the reconstructed stable allowlist"
            )
        return {
            "schema_version": 1,
            "kind": "existing",
            "repository_commit": history[-1],
            "bundle_exists": True,
        }
    if existing_release.exists() or existing_release.is_symlink():
        raise PublicationClassificationError(
            "unhistorical release path exists in the qualified checkout"
        )
    return {
        "schema_version": 1,
        "kind": "new",
        "repository_commit": None,
        "bundle_exists": bundle_exists,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-root", required=True, type=pathlib.Path)
    parser.add_argument("--reconstructed-root", required=True, type=pathlib.Path)
    parser.add_argument("--release-path", required=True)
    parser.add_argument("--submission-id", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        result = classify_publication(
            args.release_root,
            args.reconstructed_root,
            args.release_path,
            args.submission_id,
        )
        args.output.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (OSError, UnicodeError, PublicationClassificationError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
