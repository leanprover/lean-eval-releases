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


def _is_ancestor(root: pathlib.Path, ancestor: str, descendant: str) -> bool:
    try:
        completed = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "merge-base",
                "--is-ancestor",
                ancestor,
                descendant,
            ],
            check=False,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PublicationClassificationError("release history lookup failed") from error
    if completed.returncode not in {0, 1}:
        raise PublicationClassificationError("release history lookup failed")
    return completed.returncode == 0


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


def _oldest_undeleted_addition(
    release_root: pathlib.Path,
    relative: pathlib.PurePosixPath,
    label: str,
) -> str | None:
    additions = _git(
        release_root,
        "log",
        "--full-history",
        "--reverse",
        "--topo-order",
        "--diff-filter=A",
        "--format=%H",
        "--",
        relative.as_posix(),
    ).splitlines()
    deletions = _git(
        release_root,
        "log",
        "--full-history",
        "--diff-filter=D",
        "--format=%H",
        "--",
        relative.as_posix(),
    ).splitlines()
    for commit in additions + deletions:
        if COMMIT.fullmatch(commit) is None:
            raise PublicationClassificationError(
                f"{label} history contains an invalid commit"
            )
    if len(additions) != len(set(additions)) or len(deletions) != len(set(deletions)):
        raise PublicationClassificationError(f"{label} history is ambiguous")
    if deletions:
        raise PublicationClassificationError(
            f"{label} has deletion history; refusing republication"
        )
    if not additions:
        return None
    oldest = additions[0]
    if any(
        not _is_ancestor(release_root, oldest, descendant)
        for descendant in additions[1:]
    ):
        raise PublicationClassificationError(
            f"{label} has no unique oldest adding commit"
        )
    return oldest


def classify_existing_publication_history(
    release_root: pathlib.Path,
    release_path: str,
    submission_id: str,
) -> dict[str, Any]:
    """Validate an extant publication and recover its first adding commit."""
    relative = _release_relative_path(release_path)
    if SUBMISSION_ID.fullmatch(submission_id) is None:
        raise PublicationClassificationError("submission id is not canonical")
    release_root = release_root.resolve(strict=True)
    existing_release = release_root.joinpath(*relative.parts)
    bundle_relative = pathlib.PurePosixPath("sources", f"{submission_id}.tar.gz")
    existing_bundle_path = release_root.joinpath(*bundle_relative.parts)

    repository_commit = _oldest_undeleted_addition(
        release_root, relative, "release path"
    )
    bundle_commit = _oldest_undeleted_addition(
        release_root, bundle_relative, "source bundle"
    )
    if repository_commit is None:
        raise PublicationClassificationError(
            "existing release has no historical adding commit"
        )
    if bundle_commit is None:
        raise PublicationClassificationError(
            "existing release source bundle has no historical adding commit"
        )
    if not existing_release.exists() or existing_release.is_symlink():
        raise PublicationClassificationError(
            "previously published release is absent; refusing republication"
        )
    _stable_release_projection(existing_release)
    _regular_file(existing_bundle_path, release_root, "published source bundle")
    return {
        "schema_version": 1,
        "kind": "existing",
        "repository_commit": repository_commit,
        "bundle_exists": True,
    }


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
    release_addition = _oldest_undeleted_addition(
        release_root, relative, "release path"
    )
    bundle_addition = _oldest_undeleted_addition(
        release_root, bundle_relative, "source bundle"
    )
    if bundle_exists:
        existing_bundle = _regular_file(
            existing_bundle_path, release_root, "published source bundle"
        )
        if existing_bundle.read_bytes() != reconstructed_bundle.read_bytes():
            raise PublicationClassificationError(
                "published source bundle differs from reconstruction"
            )

    if release_addition is not None:
        history = classify_existing_publication_history(
            release_root, release_path, submission_id
        )
        if _stable_release_projection(existing_release) != reconstructed_projection:
            raise PublicationClassificationError(
                "published release differs from the reconstructed stable allowlist"
            )
        return history
    if existing_release.exists() or existing_release.is_symlink():
        raise PublicationClassificationError(
            "unhistorical release path exists in the qualified checkout"
        )
    if bundle_addition is not None and not bundle_exists:
        raise PublicationClassificationError(
            "previously published source bundle is absent; refusing republication"
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
    parser.add_argument("--reconstructed-root", type=pathlib.Path)
    parser.add_argument("--release-path", required=True)
    parser.add_argument("--submission-id", required=True)
    parser.add_argument("--history-only", action="store_true")
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        if args.history_only:
            if args.reconstructed_root is not None:
                raise PublicationClassificationError(
                    "history-only classification does not accept a reconstruction"
                )
            result = classify_existing_publication_history(
                args.release_root,
                args.release_path,
                args.submission_id,
            )
        else:
            if args.reconstructed_root is None:
                raise PublicationClassificationError(
                    "publication classification requires a reconstruction"
                )
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
