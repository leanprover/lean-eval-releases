#!/usr/bin/env python3
"""Publish one already-classified reconstructed release without log disclosure."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
from typing import Any

if __package__:
    from .validate_manifest import load_state_snapshot, validate_manifest
else:
    from validate_manifest import load_state_snapshot, validate_manifest

COMMIT = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
RESULT_ID = re.compile(r"r2_[0-9a-f]{64}")
SUBMISSION_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)


class PublicationError(ValueError):
    """The private publication transaction failed closed."""


def _read_json(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _git(root: pathlib.Path, *arguments: str, timeout: int = 30) -> bytes:
    try:
        return subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True,
            capture_output=True,
            timeout=timeout,
        ).stdout
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise PublicationError("release Git transaction failed") from None


def _release_relative(value: str) -> pathlib.PurePosixPath:
    relative = pathlib.PurePosixPath(value)
    if (
        len(relative.parts) != 4
        or relative.parts[0] != "releases"
        or re.fullmatch(r"[0-9]{4}", relative.parts[1]) is None
        or re.fullmatch(r"(?:0[1-9]|1[0-2])", relative.parts[2]) is None
        or RESULT_ID.fullmatch(relative.parts[3]) is None
    ):
        raise PublicationError("release path is not canonical")
    return relative


def _write_private_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise PublicationError("publication result already exists")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(
                json.dumps(
                    value,
                    ensure_ascii=True,
                    allow_nan=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            )
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def publish(
    *,
    release_root: pathlib.Path,
    reconstructed_root: pathlib.Path,
    release_path: str,
    submission_id: str,
    classification_value: Any,
    trusted_as_of: str,
    state_snapshot_value: Any,
) -> dict[str, Any]:
    if release_root.is_symlink() or reconstructed_root.is_symlink():
        raise PublicationError("publication root is unsafe")
    release_root = release_root.resolve(strict=True)
    reconstructed_root = reconstructed_root.resolve(strict=True)
    if not release_root.is_dir():
        raise PublicationError("release root is unsafe")
    if not reconstructed_root.is_dir():
        raise PublicationError("reconstructed root is unsafe")
    if _git(release_root, "rev-parse", "--show-toplevel").decode(
        "utf-8"
    ).strip() != str(release_root):
        raise PublicationError("release root is not its Git toplevel")
    relative = _release_relative(release_path)
    if SUBMISSION_ID.fullmatch(submission_id) is None:
        raise PublicationError("submission id is not canonical")
    classification = classification_value
    if not isinstance(classification, dict) or classification != {
        "schema_version": 1,
        "kind": "new",
        "repository_commit": None,
        "bundle_exists": classification.get("bundle_exists")
        if isinstance(classification, dict)
        else None,
    }:
        raise PublicationError("publication classification is not canonical")
    if type(classification["bundle_exists"]) is not bool:
        raise PublicationError("publication bundle classification is invalid")

    source_release = reconstructed_root.joinpath(*relative.parts)
    target_release = release_root.joinpath(*relative.parts)
    if target_release.exists() or target_release.is_symlink():
        raise PublicationError("new release target already exists")
    source_bundle = reconstructed_root / "sources" / f"{submission_id}.tar.gz"
    target_bundle = release_root / "sources" / f"{submission_id}.tar.gz"
    source_manifest = reconstructed_root / "release-manifest.json"
    target_manifest = release_root / "release-manifest.json"

    try:
        target_release.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        (release_root / "sources").mkdir(mode=0o755, exist_ok=True)
        shutil.copytree(source_release, target_release, copy_function=shutil.copy2)
        if not classification["bundle_exists"]:
            if target_bundle.exists() or target_bundle.is_symlink():
                raise PublicationError("new source bundle target already exists")
            shutil.copy2(source_bundle, target_bundle)
        shutil.copy2(source_manifest, target_manifest)
    except (OSError, shutil.Error, PublicationError):
        raise PublicationError("release copy transaction failed") from None

    manifest = _read_json(target_manifest)
    validate_manifest(
        manifest,
        trusted_as_of=trusted_as_of,
        trusted_submissions=load_state_snapshot(state_snapshot_value),
        bundle_root=release_root,
    )
    matching = [
        entry
        for entry in manifest["entries"]
        if entry.get("result_id") == relative.parts[3]
        and entry.get("release_path") == release_path
    ]
    if len(matching) != 1:
        raise PublicationError("manifest does not contain the exact release")
    tree_digest = matching[0].get("release_tree_sha256")
    if not isinstance(tree_digest, str) or DIGEST.fullmatch(tree_digest) is None:
        raise PublicationError("release tree digest is not canonical")

    _git(release_root, "config", "user.name", "lean-eval-release-controller")
    _git(
        release_root,
        "config",
        "user.email",
        "lean-eval-release-controller@users.noreply.github.com",
    )
    _git(
        release_root,
        "add",
        release_path,
        f"sources/{submission_id}.tar.gz",
        "release-manifest.json",
    )
    _git(release_root, "diff", "--cached", "--check")
    _git(
        release_root,
        "commit",
        "--quiet",
        "-m",
        f"Publish delayed source {relative.parts[3]}",
    )
    _git(release_root, "push", "--quiet", "origin", "HEAD:main", timeout=120)
    repository_commit = _git(release_root, "rev-parse", "HEAD").decode("ascii").strip()
    if COMMIT.fullmatch(repository_commit) is None:
        raise PublicationError("published repository commit is not canonical")
    return {
        "schema_version": 1,
        "repository_commit": repository_commit,
        "release_tree_sha256": tree_digest,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-root", required=True, type=pathlib.Path)
    parser.add_argument("--reconstructed-root", required=True, type=pathlib.Path)
    parser.add_argument("--release-path", required=True)
    parser.add_argument("--submission-id", required=True)
    parser.add_argument("--classification", required=True, type=pathlib.Path)
    parser.add_argument("--trusted-as-of", required=True)
    parser.add_argument("--state-acceptance-snapshot", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        result = publish(
            release_root=args.release_root,
            reconstructed_root=args.reconstructed_root,
            release_path=args.release_path,
            submission_id=args.submission_id,
            classification_value=_read_json(args.classification),
            trusted_as_of=args.trusted_as_of,
            state_snapshot_value=_read_json(args.state_acceptance_snapshot),
        )
        _write_private_json(args.output, result)
    except (
        KeyError,
        OSError,
        PublicationError,
        UnicodeError,
        ValueError,
    ):
        print("release publication failed closed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
