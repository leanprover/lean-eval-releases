#!/usr/bin/env python3
"""Bind one controller run to exact release, State, and materialized inputs.

The helper is provider-neutral and performs no network, credential, State,
publication, archive, or AWS operation. It verifies already-local Git objects
and writes a source-free qualification consumed by the release planner.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
from typing import Any

from release_orchestrator import (
    COMMIT,
    STATE_RELEASE_CONTRACT_COMMIT,
    STATE_RELEASE_CONTRACT_TREES,
    canonical_json_digest,
    validate_release_queue,
)
from validate_manifest import load_state_snapshot

CONTRACT_FIELDS = {
    "schema_version",
    "environment",
    "publication_latch",
    "release",
    "state",
    "audit",
}
REPOSITORY_CONTRACT_FIELDS = {"repository", "credential", "permission"}
MUTABLE_REPOSITORY_CONTRACT_FIELDS = REPOSITORY_CONTRACT_FIELDS | {"ref"}
STATE_CONTRACT_FIELDS = MUTABLE_REPOSITORY_CONTRACT_FIELDS | {"minimum_contract_commit"}
GITHUB_ORIGIN = re.compile(
    r"(?:https://github\.com/|git@github\.com:)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"
)


class QualificationError(ValueError):
    """The local controller inputs do not match the reviewed contract."""


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise QualificationError(f"{label} must be an object with string keys")
    return value


def _fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise QualificationError(f"{label} fields do not match the reviewed contract")


def validate_contract(value: Any) -> dict[str, Any]:
    contract = _object(value, "credential contract")
    _fields(contract, CONTRACT_FIELDS, "credential contract")
    if (
        contract["schema_version"] != 1
        or isinstance(contract["schema_version"], bool)
        or contract["environment"] != "release-production"
        or contract["publication_latch"] != "PUBLICATION_ENABLED"
    ):
        raise QualificationError("credential contract identity is invalid")
    expected = {
        "release": (
            MUTABLE_REPOSITORY_CONTRACT_FIELDS,
            "leanprover/lean-eval-releases",
            "RELEASE_PUBLISH_KEY",
            "contents-read-write",
        ),
        "state": (
            STATE_CONTRACT_FIELDS,
            "leanprover/lean-eval-state",
            "PRODUCTION_STATE_CONTROLLER_KEY",
            "contents-read-write",
        ),
        "audit": (
            REPOSITORY_CONTRACT_FIELDS,
            "leanprover/lean-eval-audit",
            "AUDIT_READ_KEY",
            "contents-read",
        ),
    }
    for name, (fields, repository, credential, permission) in expected.items():
        entry = _object(contract[name], f"credential contract {name}")
        _fields(entry, fields, f"credential contract {name}")
        if (
            entry["repository"] != repository
            or entry["credential"] != credential
            or entry["permission"] != permission
        ):
            raise QualificationError(f"credential contract {name} authority is invalid")
        if "ref" in fields and entry["ref"] != "refs/heads/main":
            raise QualificationError(f"credential contract {name} ref is invalid")
    minimum = contract["state"]["minimum_contract_commit"]
    if minimum != STATE_RELEASE_CONTRACT_COMMIT:
        raise QualificationError("State minimum contract commit is invalid")
    return contract


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
        raise QualificationError(f"Git qualification failed for {root}") from error
    return completed.stdout.strip()


def qualify_repository(
    root: pathlib.Path,
    expected_repository: str,
    minimum_commit: str | None = None,
    contract_trees: dict[str, str] | None = None,
    *,
    reject_untracked: bool = False,
) -> str:
    resolved = root.resolve(strict=True)
    if root.is_symlink() or not resolved.is_dir():
        raise QualificationError("qualified repository root must be a directory")
    if (
        pathlib.Path(_git(resolved, "rev-parse", "--show-toplevel")).resolve()
        != resolved
    ):
        raise QualificationError("qualified repository root is not the Git toplevel")
    if _git(resolved, "rev-parse", "--is-shallow-repository") != "false":
        raise QualificationError("qualified repository must have complete history")
    origin = _git(resolved, "remote", "get-url", "origin")
    match = GITHUB_ORIGIN.fullmatch(origin.removesuffix(".git"))
    if match is None or match.group(1).lower() != expected_repository.lower():
        raise QualificationError("qualified repository origin is invalid")
    head = _git(resolved, "rev-parse", "HEAD")
    remote_main = _git(resolved, "rev-parse", "refs/remotes/origin/main")
    if COMMIT.fullmatch(head) is None or head != remote_main:
        raise QualificationError("qualified repository is not exact origin/main")
    if _git(resolved, "diff", "--name-only", "HEAD"):
        raise QualificationError("qualified repository has tracked changes")
    if reject_untracked and _git(resolved, "ls-files", "--others"):
        raise QualificationError("qualified repository has untracked files")
    if minimum_commit is not None:
        try:
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(resolved),
                    "merge-base",
                    "--is-ancestor",
                    minimum_commit,
                    head,
                ],
                check=True,
                capture_output=True,
                timeout=10,
            )
        except (
            OSError,
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
        ) as error:
            raise QualificationError(
                "State main does not descend from the reviewed release contract"
            ) from error
    if contract_trees is not None:
        if minimum_commit is None:
            raise QualificationError("State contract trees require a contract commit")
        for path, expected_tree in sorted(contract_trees.items()):
            if COMMIT.fullmatch(expected_tree) is None:
                raise QualificationError("reviewed State contract tree is invalid")
            reviewed_tree = _git(resolved, "rev-parse", f"{minimum_commit}:{path}")
            live_tree = _git(resolved, "rev-parse", f"{head}:{path}")
            if reviewed_tree != expected_tree or live_tree != expected_tree:
                raise QualificationError(
                    f"live State {path} tree has drifted from the reviewed contract"
                )
            if any(
                _git(resolved, "cat-file", "-t", tree) != "tree"
                for tree in (reviewed_tree, live_tree)
            ):
                raise QualificationError(f"reviewed State {path} path is not a tree")
    return head


def build_qualification(
    contract_value: Any,
    queue_value: Any,
    snapshot_value: Any,
    *,
    environment: str,
    publication_enabled: str,
    mode: str,
    release_commit: str,
    state_commit: str,
) -> dict[str, Any]:
    contract = validate_contract(contract_value)
    queue = validate_release_queue(queue_value)
    load_state_snapshot(snapshot_value)
    if environment != "production" or queue["environment"] != environment:
        raise QualificationError(
            "controller requires the production State materialization"
        )
    if mode == "preflight":
        if publication_enabled not in {"", "false"}:
            raise QualificationError("preflight requires publication absent or false")
    elif mode == "publication":
        if publication_enabled != "true":
            raise QualificationError("publication controller latch is not exactly true")
    else:
        raise QualificationError("qualification mode is invalid")
    for value, label in ((release_commit, "release"), (state_commit, "State")):
        if COMMIT.fullmatch(value) is None:
            raise QualificationError(f"{label} commit is invalid")
    return {
        "schema_version": 1,
        "environment": environment,
        "mode": mode,
        "release_repository": contract["release"]["repository"],
        "release_commit": release_commit,
        "state_repository": contract["state"]["repository"],
        "state_commit": state_commit,
        "state_contract_commit": contract["state"]["minimum_contract_commit"],
        "state_source_event_count": queue["source_event_count"],
        "state_source_digest": queue["source_digest"],
        "release_queue_sha256": canonical_json_digest(queue, "release-queue"),
        "acceptance_snapshot_sha256": canonical_json_digest(
            snapshot_value, "acceptance-snapshot"
        ),
    }


def _read(path: pathlib.Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise QualificationError(f"{label} is not one UTF-8 JSON object") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", required=True, type=pathlib.Path)
    parser.add_argument("--release-root", required=True, type=pathlib.Path)
    parser.add_argument("--state-root", required=True, type=pathlib.Path)
    parser.add_argument("--queue", required=True, type=pathlib.Path)
    parser.add_argument("--acceptance-snapshot", required=True, type=pathlib.Path)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--publication-enabled", required=True)
    parser.add_argument("--mode", choices=["preflight", "publication"], required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        contract = validate_contract(_read(args.contract, "credential contract"))
        release_commit = qualify_repository(
            args.release_root, contract["release"]["repository"]
        )
        state_commit = qualify_repository(
            args.state_root,
            contract["state"]["repository"],
            contract["state"]["minimum_contract_commit"],
            STATE_RELEASE_CONTRACT_TREES,
        )
        qualification = build_qualification(
            contract,
            _read(args.queue, "release queue"),
            _read(args.acceptance_snapshot, "acceptance snapshot"),
            environment=args.environment,
            publication_enabled=args.publication_enabled,
            mode=args.mode,
            release_commit=release_commit,
            state_commit=state_commit,
        )
        if args.output.exists() or args.output.is_symlink():
            raise QualificationError("refusing to overwrite qualification output")
        args.output.write_text(
            json.dumps(qualification, ensure_ascii=True, indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
    except (QualificationError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
