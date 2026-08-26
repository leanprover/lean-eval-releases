#!/usr/bin/env python3
"""Reconstruct a private release plan from one exact pinned State commit."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
from typing import Any

if __package__:
    from .release_controller import canonical_json, staging_smoke_plan, started_event
    from .release_orchestrator import plan_next
    from .release_provider_literal import (
        ProviderError,
        validate_authority_descriptor,
    )
    from .release_qualification import build_qualification
else:
    from release_controller import canonical_json, staging_smoke_plan, started_event
    from release_orchestrator import plan_next
    from release_provider_literal import ProviderError, validate_authority_descriptor
    from release_qualification import build_qualification


class ReconstructionError(ValueError):
    """The exact State commit cannot reproduce the disclosure-safe handoff."""


EXACT_PYTHON_LAUNCHER = """\
import pathlib
import runpy
import sys

path = pathlib.Path(sys.argv[1])
if path.is_symlink() or not path.is_file():
    raise SystemExit("exact Python entry point is not a regular file")
path = path.resolve(strict=True)
sys.path.insert(0, str(path.parent))
sys.argv = sys.argv[1:]
runpy.run_path(str(path), run_name="__main__")
"""


def _git(root: pathlib.Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()


def _read_json(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _run_exact_python(path: pathlib.Path, *arguments: str) -> None:
    subprocess.run(
        [sys.executable, "-I", "-c", EXACT_PYTHON_LAUNCHER, str(path), *arguments],
        check=True,
        capture_output=True,
        timeout=30,
    )


def _materialize_at(
    state_root: pathlib.Path,
    state_commit: str,
    scratch_root: pathlib.Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    worktree = scratch_root / "state-views" / "release-plan-source"
    views = scratch_root / "state-views" / "release-plan-materialized"
    if (
        worktree.exists()
        or worktree.is_symlink()
        or views.exists()
        or views.is_symlink()
    ):
        raise ReconstructionError("release plan reconstruction scratch already exists")
    try:
        subprocess.run(
            [
                "git",
                "-C",
                str(state_root),
                "worktree",
                "add",
                "--detach",
                str(worktree),
                state_commit,
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        _run_exact_python(
            worktree / "scripts/state.py",
            "--root",
            str(worktree),
            "--protected-main-commit",
            state_commit,
            "validate",
        )
        _run_exact_python(
            worktree / "scripts/state.py",
            "--root",
            str(worktree),
            "--protected-main-commit",
            state_commit,
            "materialize",
            "--output",
            str(views),
        )
        return (
            _read_json(views / "release-queue.json"),
            _read_json(views / "release-acceptance-snapshot.json"),
        )
    finally:
        try:
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(state_root),
                    "worktree",
                    "remove",
                    "--force",
                    str(worktree),
                ],
                check=False,
                capture_output=True,
                timeout=30,
            )
        except subprocess.SubprocessError:
            pass
        shutil.rmtree(scratch_root / "state-views", ignore_errors=True)


def reconstruct(
    descriptor_value: Any,
    *,
    state_root: pathlib.Path,
    release_root: pathlib.Path,
    scratch_root: pathlib.Path,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    try:
        descriptor = validate_authority_descriptor(descriptor_value)
    except ProviderError as error:
        raise ReconstructionError(str(error)) from error
    state_root = state_root.resolve(strict=True)
    release_root = release_root.resolve(strict=True)
    scratch_root = scratch_root.resolve(strict=True)
    if scratch_root == pathlib.Path("/") or scratch_root in {state_root, release_root}:
        raise ReconstructionError("release plan scratch root is unsafe")
    if _git(state_root, "rev-parse", "--show-toplevel") != str(state_root):
        raise ReconstructionError("State root is not its Git toplevel")
    if _git(release_root, "rev-parse", "--show-toplevel") != str(release_root):
        raise ReconstructionError("release root is not its Git toplevel")
    state_commit = descriptor["state_commit"]
    if _git(state_root, "rev-parse", "HEAD") != state_commit:
        raise ReconstructionError("State checkout is not the authority commit")
    if _git(state_root, "status", "--porcelain", "--untracked-files=all"):
        raise ReconstructionError("State checkout is dirty")
    release_commit = _git(release_root, "rev-parse", "HEAD")
    if release_commit != descriptor["release_commit"]:
        raise ReconstructionError("release checkout is not the authority commit")

    started: dict[str, Any] | None = None
    if descriptor["environment"] == "production":
        parents = _git(state_root, "show", "-s", "--format=%P", state_commit).split()
        if len(parents) != 1:
            raise ReconstructionError(
                "release.started State commit is not single-parent"
            )
        source_state_commit = parents[0]
        started_id = descriptor["started_event_id"]
        started_path = f"events/{started_id.replace('-', '')[:2]}/{started_id}.json"
        started_raw = subprocess.run(
            ["git", "-C", str(state_root), "show", f"{state_commit}:{started_path}"],
            check=True,
            capture_output=True,
            timeout=30,
        ).stdout
        started = json.loads(started_raw.decode("utf-8"))
        if started_raw != canonical_json(started).encode("utf-8"):
            raise ReconstructionError("release.started event is not byte-canonical")
        if (
            hashlib.sha256(started_raw).hexdigest()
            != descriptor["started_event_sha256"]
        ):
            raise ReconstructionError("release.started event digest changed")
        status_path = (
            "views/result-release-status/"
            f"{started['subject_id'][3:5]}/{started['subject_id']}.json"
        )
        changed = _git(
            state_root,
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            state_commit,
        ).splitlines()
        if set(changed) != {started_path, status_path} or len(changed) != 2:
            raise ReconstructionError(
                "State commit is not the exact started transition"
            )
    else:
        source_state_commit = state_commit

    queue, snapshot = _materialize_at(
        state_root,
        source_state_commit,
        scratch_root,
    )
    if descriptor["environment"] == "production":
        contract = _read_json(
            release_root
            / "configuration/release-controller-credential-contract-v1.json"
        )
        qualification = build_qualification(
            contract,
            queue,
            snapshot,
            environment="production",
            publication_enabled="true",
            mode="publication",
            release_commit=release_commit,
            state_commit=source_state_commit,
        )
        if started is None:
            raise ReconstructionError("production release.started is missing")
        plan = plan_next(queue, started["occurred_at"], qualification)
        event_randomness = bytes.fromhex(started["event_id"].replace("-", ""))[6:]
        if (
            started_event(
                plan,
                started["occurred_at"],
                random_bytes=event_randomness,
            )
            != started
        ):
            raise ReconstructionError(
                "release.started does not bind reconstructed plan"
            )
    else:
        submission_id = pathlib.PurePosixPath(
            descriptor["archive_path"]
        ).name.removesuffix(".tar.age")
        plan = staging_smoke_plan(queue, submission_id)

    request = plan["request"]
    archive = request["archive"]
    for field in (
        "archive_repository",
        "archive_commit",
        "archive_path",
        "archive_ciphertext_sha256",
    ):
        if archive[field] != descriptor[field]:
            raise ReconstructionError(f"reconstructed {field} changed")
    if request["release"]["eligible_at"] != descriptor["eligible_at"]:
        raise ReconstructionError("reconstructed eligibility changed")
    if _digest(plan) != descriptor["plan_sha256"]:
        raise ReconstructionError("reconstructed release plan digest changed")
    return plan, started


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authority", required=True, type=pathlib.Path)
    parser.add_argument("--state-root", required=True, type=pathlib.Path)
    parser.add_argument("--release-root", required=True, type=pathlib.Path)
    parser.add_argument("--scratch-root", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--started-event-output", type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        plan, started = reconstruct(
            _read_json(args.authority),
            state_root=args.state_root,
            release_root=args.release_root,
            scratch_root=args.scratch_root.resolve(strict=True),
        )
        if args.output.exists() or args.output.is_symlink():
            raise ReconstructionError("release plan output already exists")
        args.output.write_text(canonical_json(plan), encoding="utf-8")
        args.output.chmod(0o600)
        if started is not None:
            if args.started_event_output is None:
                raise ReconstructionError("production started-event output is required")
            if (
                args.started_event_output.exists()
                or args.started_event_output.is_symlink()
            ):
                raise ReconstructionError("started-event output already exists")
            args.started_event_output.write_text(
                canonical_json(started), encoding="utf-8"
            )
            args.started_event_output.chmod(0o600)
        elif args.started_event_output is not None:
            raise ReconstructionError("staging must not request started-event output")
    except (
        json.JSONDecodeError,
        KeyError,
        OSError,
        ReconstructionError,
        subprocess.SubprocessError,
        UnicodeError,
        TypeError,
        ValueError,
    ):
        print("release plan reconstruction failed closed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
