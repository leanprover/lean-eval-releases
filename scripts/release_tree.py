"""Canonical LeanEval release-tree paths and content digest."""

from __future__ import annotations

import hashlib
import json
import pathlib
from collections.abc import Iterable

DOMAIN = b"lean-eval-release-tree-v1\0"


class TreeError(ValueError):
    """A release tree is unsafe or differs from its canonical file set."""


def _regular_file(root: pathlib.Path, relative: pathlib.PurePosixPath) -> pathlib.Path:
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise TreeError(f"release path traverses a symlink: {relative.as_posix()}")
    try:
        resolved = cursor.resolve(strict=True)
    except OSError as error:
        raise TreeError(f"release file does not exist: {relative.as_posix()}") from error
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise TreeError(f"release path is not a regular in-tree file: {relative.as_posix()}")
    return resolved


def canonical_release_files(root: pathlib.Path) -> list[pathlib.PurePosixPath]:
    """Return the exact allowed files in one public result directory."""
    resolved_root = root.resolve(strict=True)
    if root.is_symlink() or not resolved_root.is_dir():
        raise TreeError("release root must be one regular directory")
    allowed = {
        pathlib.PurePosixPath("Submission.lean"),
        pathlib.PurePosixPath("metadata.json"),
        pathlib.PurePosixPath("LICENSE"),
    }
    submission = resolved_root / "Submission"
    if submission.exists() or submission.is_symlink():
        if submission.is_symlink() or not submission.is_dir():
            raise TreeError("Submission must be a regular directory when present")
        for entry in submission.rglob("*"):
            relative = pathlib.PurePosixPath(entry.relative_to(resolved_root).as_posix())
            if entry.is_symlink():
                raise TreeError(f"release path is a symlink: {relative.as_posix()}")
            if entry.is_dir():
                continue
            if not entry.is_file() or entry.suffix != ".lean":
                raise TreeError(f"release tree contains a forbidden file: {relative.as_posix()}")
            allowed.add(relative)

    actual: set[pathlib.PurePosixPath] = set()
    for entry in resolved_root.rglob("*"):
        relative = pathlib.PurePosixPath(entry.relative_to(resolved_root).as_posix())
        if entry.is_symlink():
            raise TreeError(f"release path is a symlink: {relative.as_posix()}")
        if entry.is_dir():
            continue
        if not entry.is_file():
            raise TreeError(f"release path is not a regular file: {relative.as_posix()}")
        actual.add(relative)
    if actual != allowed:
        missing = sorted(path.as_posix() for path in allowed - actual)
        extra = sorted(path.as_posix() for path in actual - allowed)
        raise TreeError(f"release file set is not canonical; missing={missing}, extra={extra}")
    return sorted(allowed, key=lambda path: path.as_posix().encode("utf-8"))


def tree_digest(root: pathlib.Path) -> str:
    """Hash the exact public tree using a language-neutral canonical projection."""
    resolved_root = root.resolve(strict=True)
    projection: list[list[object]] = []
    for relative in canonical_release_files(root):
        file_path = _regular_file(resolved_root, relative)
        content = file_path.read_bytes()
        projection.append(
            [relative.as_posix(), len(content), hashlib.sha256(content).hexdigest()]
        )
    canonical = json.dumps(
        projection,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(DOMAIN + canonical).hexdigest()


def projected_digest(entries: Iterable[tuple[str, bytes]]) -> str:
    """Test/helper form of :func:`tree_digest` over already-read files."""
    projection = [
        [path, len(content), hashlib.sha256(content).hexdigest()]
        for path, content in sorted(entries, key=lambda item: item[0].encode("utf-8"))
    ]
    canonical = json.dumps(
        projection,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(DOMAIN + canonical).hexdigest()
