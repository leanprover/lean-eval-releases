#!/usr/bin/env python3
"""Plan source-free containment of erroneous public release paths.

The planner reads exact Git objects from protected-main release, State, and
private-evidence repositories. It never changes a worktree, index, object, ref,
or remote. Its full output is private; an optional public projection omits
State and evidence locators.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
from typing import Any

from release_controller import ControllerError, parse_timestamp
from release_orchestrator import COMMIT, DIGEST, REPOSITORY, RESULT_ID, UUID7
from release_tree import projected_digest


MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_RELEASE_BYTES = 16 * 1024 * 1024
MAX_INCIDENT_RESULTS = 128
MAX_GIT_METADATA_BYTES = 32 * 1024 * 1024
MAX_RELEASE_METADATA_ENTRIES = 4096
MAX_RELEASE_METADATA_BYTES = 32 * 1024 * 1024
MAX_PLAN_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_SHARED_RELEASE_PATHS = 128
RELEASE_PATH = re.compile(
    r"releases/[0-9]{4}/(?:0[1-9]|1[0-2])/r2_[0-9a-f]{64}"
)
BUNDLE_PATH = re.compile(
    r"sources/[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\.tar\.gz"
)
CLASSIFICATIONS = {"erroneous_publication", "confidentiality_incident"}
EXPECTED_RELEASE_REPOSITORY = "leanprover/lean-eval-releases"
EXPECTED_STATE_REPOSITORY = "leanprover/lean-eval-state"
PRIVATE_EVIDENCE_REPOSITORIES = {
    "leanprover/lean-eval-audit",
    EXPECTED_STATE_REPOSITORY,
}
STATE_REMOVAL_CONTRACT_COMMIT = "0c943edde8a247b8670e10339b80fc65be6c0f33"
STATE_REMOVAL_CONTRACT_TREES = {
    "schema": "2c0004214d90b82cf895e79a91c239ac9e7bbf67",
    "scripts": "ed830aea8fe7a4a0e6db7acdcf82f23cb24a296d",
}
STATE_REMOVAL_CONTRACT_COMPONENTS = {
    "schema/public-state-projection-v1.schema.json": (
        "100644",
        "9d6c546a2139f587d1a3c8d76c1df7674c4a9759",
        "74398c7c81dad719637bdad2e9c73974719a077beb3a1f4a503cd55bf4d93c58",
    ),
    "schema/public-state-projection-v2.schema.json": (
        "100644",
        "fc782883787ed654bcfc69ed15241e1cadee80df",
        "94dac7dcfbf3d322d5f72b20992e2950f8fa714641f2bb9ee6fd5b84d288a336",
    ),
    "schema/public-state-projection-v3.schema.json": (
        "100644",
        "cfd577d818119917a6060c06abd48d24f32028aa",
        "eea75447b8c13778b454f1313778068f9908c189724107a9e3be3635b00c5bee",
    ),
    "schema/state-event-v1.schema.json": (
        "100644",
        "d5acc1bb0bce0a913e26ce8c6dae6a6076505453",
        "2d19515da1b0798f00dd3e9809c3a2770fee8b27ce6323ac9b9e827db4c7ea27",
    ),
    "schema/result-overlays-v1.schema.json": (
        "100644",
        "41d4078133d6854bf8de839873a3f58e9ba1afd1",
        "245324f32265d0476ca45e55ec5fbe2363c47da852d2641ddc292df0c5d9d474",
    ),
    "scripts/materialize_state.py": (
        "100755",
        "bebf968fe9a3bc70b43db4e80042b5b0d360d20d",
        "5c437c12f1b3c24f9cd9d5a9da3f876fddc4f55e126cee74bf213723984719e7",
    ),
    "scripts/public_projection.py": (
        "100755",
        "847443f5ecaafa5fa041293ced73cecad7f4835c",
        "559b4197e7427bf8411ea04171a10d767008075e239de77e23a63e15303b2abf",
    ),
    "scripts/state.py": (
        "100644",
        "9812adf2ab40b8b8072a1cbe32e66d072844d596",
        "95695b4c9a4c34e5380f08c97c35547d7d7a87f4d37e7a024bbbc932d3c5d99c",
    ),
    "scripts/validate_state.py": (
        "100755",
        "4116bb34ef7ba55018c20f14ba4407618ccfc698",
        "d36222c071054c2bf925d081141c1f1dc4fca0c65ec686e5438b2eb02a131ed2",
    ),
}
REQUEST_FIELDS = {
    "schema_version", "incident_id", "planned_at", "classification",
    "release_repository", "base_commit", "published_events", "evidence",
}
LOCATOR_FIELDS = {"repository", "commit", "path", "sha256"}
EVENT_FIELDS = {
    "schema_version", "event_id", "event_type", "occurred_at", "subject_id",
    "causation_event_id", "actor", "payload",
}
STATE_REMOVAL_FIXED_PAYLOAD_FIELDS = {
    "incident_id", "classification", "published_state_event_repository",
    "published_state_event_commit", "published_state_event_path",
    "published_state_event_blob", "published_state_event_sha256",
    "published_repository_commit", "published_repository_tree",
    "published_release_tree_sha256", "release_path", "bundle_path",
    "bundle_sha256", "bundle_disposition", "shared_release_paths",
    "evidence_repository", "evidence_commit", "evidence_path",
    "evidence_blob", "evidence_sha256",
}
STATE_REMOVAL_LATE_PAYLOAD_FIELDS = {
    "removal_repository_commit", "removal_repository_tree",
}
PUBLISHED_PAYLOAD_FIELDS = {"attempt", "repository_commit", "tree_digest", "path"}
MANIFEST_FIELDS = {"schema_version", "release_id", "generated_at", "entries"}
MANIFEST_ENTRY_FIELDS = {
    "result_id", "submission_id", "accepted_at", "eligible_at",
    "archive_repository", "archive_commit", "archive_path",
    "archive_ciphertext_sha256", "bundle_sha256", "bundle_path",
    "release_tree_sha256", "release_path", "license",
}
METADATA_FIELDS = {
    "schema_version", "generated_at", "result", "submission", "archive",
    "release", "source_files",
}
RESULT_FIELDS = {"result_id", "problem_id", "statement_revision", "commit", "tree_digest"}
SUBMISSION_FIELDS = {
    "submission_id", "owner_login", "declared_model", "production_metadata",
}
ARCHIVE_FIELDS = {
    "archive_repository", "archive_commit", "archive_path",
    "archive_ciphertext_sha256", "encrypted",
}
RELEASE_FIELDS = {"accepted_at", "eligible_at", "path", "license"}


class RemovalPlanError(ValueError):
    """The requested containment cannot be bound safely and exactly."""


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise RemovalPlanError(f"{label} must be an object with string keys")
    return value


def _fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise RemovalPlanError(
            f"{label} fields are not canonical; missing={sorted(expected - set(value))}, "
            f"extra={sorted(set(value) - expected)}"
        )


def _match(pattern: re.Pattern[str], value: Any, label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise RemovalPlanError(f"{label} is not canonical")
    return value


def _safe_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 512:
        raise RemovalPlanError(f"{label} is not a bounded relative path")
    path = pathlib.PurePosixPath(value)
    if (
        path.is_absolute() or value != path.as_posix() or "\\" in value
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(ord(character) <= 0x1F or ord(character) == 0x7F for character in value)
    ):
        raise RemovalPlanError(f"{label} is not a canonical safe relative path")
    return value


def _timestamp(value: Any, label: str) -> dt.datetime:
    try:
        return parse_timestamp(value, label)
    except ControllerError as error:
        raise RemovalPlanError(str(error)) from error


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_regular(path: pathlib.Path, label: str, maximum: int) -> bytes:
    """Read one unchanged regular file without following its final symlink."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise RemovalPlanError(f"{label} is empty or exceeds its size limit")
        descriptor = os.open(path, flags)
    except RemovalPlanError:
        raise
    except OSError as error:
        raise RemovalPlanError(f"{label} must be one readable regular file") from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or opened.st_size != before.st_size
        ):
            raise RemovalPlanError(f"{label} changed while it was opened")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(raw) != opened.st_size or after.st_size != opened.st_size:
            raise RemovalPlanError(f"{label} changed while it was read")
        if not raw or len(raw) > maximum:
            raise RemovalPlanError(f"{label} is empty or exceeds its size limit")
        return raw
    except OSError as error:
        raise RemovalPlanError(f"{label} cannot be read") from error
    finally:
        os.close(descriptor)


def _json_document(raw: bytes, label: str) -> dict[str, Any]:
    try:
        return _object(json.loads(raw.decode("utf-8")), label)
    except RemovalPlanError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RemovalPlanError(f"{label} is not one UTF-8 JSON object") from error


def _git_environment() -> dict[str, str]:
    environment = {
        key: os.environ[key]
        for key in ("PATH", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT")
        if key in os.environ
    }
    environment.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_COUNT": "4",
        "GIT_CONFIG_KEY_0": "core.fsmonitor",
        "GIT_CONFIG_VALUE_0": "false",
        "GIT_CONFIG_KEY_1": "core.untrackedCache",
        "GIT_CONFIG_VALUE_1": "false",
        "GIT_CONFIG_KEY_2": "core.preloadIndex",
        "GIT_CONFIG_VALUE_2": "false",
        "GIT_CONFIG_KEY_3": "gc.auto",
        "GIT_CONFIG_VALUE_3": "0",
    })
    return environment


def _git(
    root: pathlib.Path,
    *arguments: str,
    label: str,
    maximum: int = MAX_GIT_METADATA_BYTES,
) -> bytes:
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            ["git", "-C", str(root), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_git_environment(),
        )
        if process.stdout is None:
            raise OSError("Git stdout pipe was not created")
        raw = process.stdout.read(maximum + 1)
        if len(raw) > maximum:
            process.kill()
            process.wait()
            raise RemovalPlanError(f"Git returned oversized {label}")
        if process.wait() != 0:
            raise RemovalPlanError(f"Git could not validate {label}")
        return raw
    except RemovalPlanError:
        raise
    except OSError as error:
        raise RemovalPlanError(f"Git could not validate {label}") from error
    finally:
        if process is not None:
            if process.stdout is not None:
                process.stdout.close()
            if process.poll() is None:
                process.kill()
                process.wait()


def _git_text(root: pathlib.Path, *arguments: str, label: str) -> str:
    try:
        return _git(root, *arguments, label=label, maximum=4096).decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise RemovalPlanError(f"Git returned non-ASCII {label}") from error


def _run_git(root: pathlib.Path, *arguments: str, label: str) -> None:
    try:
        subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=_git_environment(),
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise RemovalPlanError(f"Git could not validate {label}") from error


def _expected_origins(repository: str) -> set[str]:
    return {
        f"git@github.com:{repository}.git",
        f"https://github.com/{repository}",
        f"https://github.com/{repository}.git",
        f"ssh://git@github.com/{repository}.git",
    }


def _remote_main(repository: str) -> str:
    environment = {
        key: os.environ[key]
        for key in ("PATH", "LANG", "LC_ALL", "GH_TOKEN", "GITHUB_TOKEN", "GH_HOST")
        if key in os.environ
    }
    try:
        completed = subprocess.run(
            [
                "gh",
                "api",
                f"repos/{repository}/branches/main",
                "--jq",
                "[.commit.sha, .protected] | @tsv",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
        commit, protected = completed.stdout.decode("ascii").strip().split("\t")
    except (OSError, subprocess.CalledProcessError, UnicodeDecodeError) as error:
        raise RemovalPlanError(f"cannot resolve remote protected main for {repository}") from error
    except ValueError as error:
        raise RemovalPlanError(f"GitHub returned malformed main metadata for {repository}") from error
    if protected != "true":
        raise RemovalPlanError(f"remote main is not protected for {repository}")
    return _match(COMMIT, commit, f"{repository} remote main")


def _repository_root(root_value: pathlib.Path, repository: str) -> pathlib.Path:
    if root_value.is_symlink() or not root_value.is_dir():
        raise RemovalPlanError(f"{repository} root is not one regular directory")
    root = root_value.resolve(strict=True)
    top = pathlib.Path(
        _git_text(root, "rev-parse", "--show-toplevel", label=f"{repository} root")
    ).resolve(strict=True)
    if top != root:
        raise RemovalPlanError(f"{repository} root must be the Git worktree root")
    origin = _git_text(root, "remote", "get-url", "origin", label=f"{repository} origin")
    if origin not in _expected_origins(repository):
        raise RemovalPlanError(f"origin is not {repository}")
    return root


def _commit_on_remote_main(
    root: pathlib.Path, commit: str, remote_main: str, label: str
) -> None:
    if _git_text(root, "cat-file", "-t", commit, label=label) != "commit":
        raise RemovalPlanError(f"{label} is not a commit")
    _run_git(
        root, "merge-base", "--is-ancestor", commit, remote_main,
        label=f"{label} ancestry",
    )


def _tree_entries(
    root: pathlib.Path, commit: str, path: str, *, label: str
) -> list[tuple[str, str, str, str]]:
    raw = _git(root, "ls-tree", "-rz", "--full-tree", commit, "--", path, label=label)
    entries: list[tuple[str, str, str, str]] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            header, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id = header.decode("ascii").split(" ")
            entry_path = raw_path.decode("utf-8")
        except (ValueError, UnicodeError) as error:
            raise RemovalPlanError(f"Git returned malformed {label}") from error
        entries.append((mode, object_type, object_id, entry_path))
    return entries


def _blob(root: pathlib.Path, object_id: str, label: str, maximum: int) -> bytes:
    try:
        size = int(_git_text(root, "cat-file", "-s", object_id, label=f"{label} size"))
    except ValueError as error:
        raise RemovalPlanError(f"Git returned malformed {label} size") from error
    if size < 0 or size > maximum:
        raise RemovalPlanError(f"{label} exceeds its size limit")
    raw = _git(root, "cat-file", "blob", object_id, label=label, maximum=maximum)
    if len(raw) != size:
        raise RemovalPlanError(f"Git returned truncated {label}")
    return raw


def _one_blob(
    root: pathlib.Path,
    commit: str,
    path: str,
    *,
    label: str,
    maximum: int,
    expected_mode: str = "100644",
) -> tuple[str, bytes]:
    entries = _tree_entries(root, commit, path, label=label)
    if len(entries) != 1:
        raise RemovalPlanError(f"{label} is absent or ambiguous")
    mode, object_type, object_id, actual_path = entries[0]
    if mode != expected_mode or object_type != "blob" or actual_path != path:
        raise RemovalPlanError(f"{label} is not one mode-{expected_mode} blob")
    return object_id, _blob(root, object_id, label, maximum)


def _optional_blob(
    root: pathlib.Path,
    commit: str,
    path: str,
    *,
    label: str,
    maximum: int,
) -> tuple[str, bytes] | None:
    entries = _tree_entries(root, commit, path, label=label)
    if not entries:
        return None
    if len(entries) != 1:
        raise RemovalPlanError(f"{label} is ambiguous")
    mode, object_type, object_id, actual_path = entries[0]
    if mode != "100644" or object_type != "blob" or actual_path != path:
        raise RemovalPlanError(f"{label} is not one mode-100644 blob")
    return object_id, _blob(root, object_id, label, maximum)


def _validate_state_removal_schema(raw: bytes) -> None:
    """Prove the reviewed schema shape agrees with the emitted skeleton."""
    schema = _json_document(raw, "release removal State event schema")
    properties = _object(schema.get("properties"), "State event schema properties")
    required = schema.get("required")
    if (
        schema.get("additionalProperties") is not False
        or set(properties) != EVENT_FIELDS
        or not isinstance(required, list)
        or len(required) != len(EVENT_FIELDS)
        or set(required) != EVENT_FIELDS
    ):
        raise RemovalPlanError("State event schema top-level contract has drifted")
    definitions = _object(schema.get("$defs"), "State event schema definitions")
    release_path = _object(
        definitions.get("releasePath"), "State release-path definition"
    )
    if release_path.get("pattern") != f"^{RELEASE_PATH.pattern}$":
        raise RemovalPlanError("State release-path schema disagrees with the planner")

    branches = schema.get("allOf")
    if not isinstance(branches, list):
        raise RemovalPlanError("State event schema has no conditional branches")
    removal_branches = []
    for candidate in branches:
        if not isinstance(candidate, dict):
            continue
        condition = candidate.get("if")
        if not isinstance(condition, dict):
            continue
        condition_properties = condition.get("properties")
        if not isinstance(condition_properties, dict):
            continue
        event_type = condition_properties.get("event_type")
        if isinstance(event_type, dict) and event_type.get("const") == "release.removed":
            removal_branches.append(candidate)
    if len(removal_branches) != 1:
        raise RemovalPlanError("State schema has no unique release.removed branch")
    then = _object(removal_branches[0].get("then"), "release.removed schema then")
    branch_properties = _object(
        then.get("properties"), "release.removed schema properties"
    )
    if set(branch_properties) != {"actor", "payload"}:
        raise RemovalPlanError("release.removed branch fields have drifted")
    actor = _object(branch_properties["actor"], "release.removed actor schema")
    if actor != {
        "type": "object",
        "additionalProperties": False,
        "required": ["kind"],
        "properties": {"kind": {"const": "system"}},
    }:
        raise RemovalPlanError("release.removed actor schema has drifted")
    payload = _object(branch_properties["payload"], "release.removed payload schema")
    payload_properties = _object(
        payload.get("properties"), "release.removed payload properties"
    )
    expected_payload_fields = (
        STATE_REMOVAL_FIXED_PAYLOAD_FIELDS | STATE_REMOVAL_LATE_PAYLOAD_FIELDS
    )
    payload_required = payload.get("required")
    if (
        payload.get("additionalProperties") is not False
        or set(payload_properties) != expected_payload_fields
        or not isinstance(payload_required, list)
        or len(payload_required) != len(expected_payload_fields)
        or set(payload_required) != expected_payload_fields
    ):
        raise RemovalPlanError("release.removed payload fields have drifted")
    shared = _object(
        payload_properties["shared_release_paths"],
        "release.removed shared paths schema",
    )
    if (
        shared.get("type") != "array"
        or shared.get("maxItems") != MAX_SHARED_RELEASE_PATHS
        or shared.get("uniqueItems") is not True
        or shared.get("items") != {"$ref": "#/$defs/releasePath"}
    ):
        raise RemovalPlanError("release.removed shared paths schema has drifted")
    if payload_properties["release_path"] != {"$ref": "#/$defs/releasePath"}:
        raise RemovalPlanError("release.removed release-path schema has drifted")


def _state_removal_contract(
    state_root: pathlib.Path, remote_main: str
) -> dict[str, Any]:
    """Bind planning to the exact reviewed and currently effective contract."""
    _commit_on_remote_main(
        state_root,
        STATE_REMOVAL_CONTRACT_COMMIT,
        remote_main,
        "release removal State contract",
    )
    trees = []
    for path, expected_tree in sorted(STATE_REMOVAL_CONTRACT_TREES.items()):
        reviewed_tree = _git_text(
            state_root,
            "rev-parse",
            f"{STATE_REMOVAL_CONTRACT_COMMIT}:{path}",
            label=f"reviewed release removal State tree {path}",
        )
        live_tree = _git_text(
            state_root,
            "rev-parse",
            f"{remote_main}:{path}",
            label=f"live release removal State tree {path}",
        )
        if reviewed_tree != expected_tree or live_tree != expected_tree:
            raise RemovalPlanError(
                f"live release removal State tree {path} has drifted from the "
                "reviewed contract"
            )
        if any(
            _git_text(state_root, "cat-file", "-t", tree, label=f"{path} tree type")
            != "tree"
            for tree in (reviewed_tree, live_tree)
        ):
            raise RemovalPlanError(f"release removal State path {path} is not a tree")
        trees.append({"path": path, "tree": expected_tree})
    components = []
    for path, (expected_mode, expected_blob, expected_sha256) in sorted(
        STATE_REMOVAL_CONTRACT_COMPONENTS.items()
    ):
        reviewed_blob, reviewed_raw = _one_blob(
            state_root,
            STATE_REMOVAL_CONTRACT_COMMIT,
            path,
            label=f"reviewed release removal State component {path}",
            maximum=MAX_DOCUMENT_BYTES,
            expected_mode=expected_mode,
        )
        if (
            reviewed_blob != expected_blob
            or _sha256(reviewed_raw) != expected_sha256
        ):
            raise RemovalPlanError(
                f"release removal State component {path} does not match the "
                "reviewed contract"
            )
        live_blob, live_raw = _one_blob(
            state_root,
            remote_main,
            path,
            label=f"live release removal State component {path}",
            maximum=MAX_DOCUMENT_BYTES,
            expected_mode=expected_mode,
        )
        if live_blob != expected_blob or _sha256(live_raw) != expected_sha256:
            raise RemovalPlanError(
                f"live release removal State component {path} has drifted from "
                "the reviewed contract"
            )
        components.append({
            "path": path,
            "blob": expected_blob,
            "sha256": expected_sha256,
        })
        if path == "schema/state-event-v1.schema.json":
            _validate_state_removal_schema(reviewed_raw)
    return {
        "repository": EXPECTED_STATE_REPOSITORY,
        "commit": STATE_REMOVAL_CONTRACT_COMMIT,
        "event_type": "release.removed",
        "trees": trees,
        "components": components,
    }


def _release_tree(
    root: pathlib.Path, commit: str, release_path: str, *, label: str
) -> tuple[str, dict[str, bytes]]:
    entries = _tree_entries(root, commit, release_path, label=label)
    if not entries:
        raise RemovalPlanError(f"{label} is absent")
    files: dict[str, bytes] = {}
    total = 0
    prefix = release_path + "/"
    for mode, object_type, object_id, path in entries:
        if mode != "100644" or object_type != "blob" or not path.startswith(prefix):
            raise RemovalPlanError(f"{label} contains a noncanonical Git entry")
        relative = path.removeprefix(prefix)
        if relative not in {"Submission.lean", "metadata.json", "LICENSE"} and not (
            relative.startswith("Submission/")
            and relative.endswith(".lean")
            and _safe_path(relative, f"{label} path") == relative
        ):
            raise RemovalPlanError(f"{label} contains a forbidden path")
        if relative in files:
            raise RemovalPlanError(f"{label} contains a duplicate path")
        try:
            size = int(
                _git_text(root, "cat-file", "-s", object_id, label=f"{label} blob size")
            )
        except ValueError as error:
            raise RemovalPlanError(f"Git returned malformed {label} blob size") from error
        if size < 0 or total + size > MAX_RELEASE_BYTES:
            raise RemovalPlanError(f"{label} exceeds its aggregate size limit")
        content = _blob(root, object_id, f"{label} blob", MAX_RELEASE_BYTES - total)
        total += len(content)
        files[relative] = content
    if not {"Submission.lean", "metadata.json", "LICENSE"} <= set(files):
        raise RemovalPlanError(f"{label} is missing its canonical required files")
    return projected_digest(files.items()), files


def _validate_published_event(value: Any) -> tuple[dict[str, Any], str]:
    event = _object(value, "release.published event")
    _fields(event, EVENT_FIELDS, "release.published event")
    if event["schema_version"] != 1 or isinstance(event["schema_version"], bool):
        raise RemovalPlanError("release.published schema_version must be integer 1")
    event_id = _match(UUID7, event["event_id"], "release.published event_id")
    if event["event_type"] != "release.published":
        raise RemovalPlanError("State event is not release.published")
    _timestamp(event["occurred_at"], "release.published occurred_at")
    result_id = _match(RESULT_ID, event["subject_id"], "release.published subject")
    _match(UUID7, event["causation_event_id"], "release.published causation")
    if event["actor"] != {"kind": "system"}:
        raise RemovalPlanError("release.published actor is not canonical system authority")
    payload = _object(event["payload"], "release.published payload")
    _fields(payload, PUBLISHED_PAYLOAD_FIELDS, "release.published payload")
    if type(payload["attempt"]) is not int or payload["attempt"] < 1:
        raise RemovalPlanError("release.published attempt is not positive")
    _match(COMMIT, payload["repository_commit"], "published repository commit")
    _match(DIGEST, payload["tree_digest"], "published release tree digest")
    path = _match(RELEASE_PATH, payload["path"], "published release path")
    if not path.endswith("/" + result_id):
        raise RemovalPlanError("published release path does not match result identity")
    expected_path = f"events/{event_id.replace('-', '')[:2]}/{event_id}.json"
    return event, expected_path


def _locator(value: Any, label: str) -> dict[str, Any]:
    locator = _object(value, label)
    _fields(locator, LOCATOR_FIELDS, label)
    _match(REPOSITORY, locator["repository"], f"{label}.repository")
    _match(COMMIT, locator["commit"], f"{label}.commit")
    _safe_path(locator["path"], f"{label}.path")
    _match(DIGEST, locator["sha256"], f"{label}.sha256")
    return locator


def _validate_request(value: Any) -> dict[str, Any]:
    request = _object(value, "removal request")
    _fields(request, REQUEST_FIELDS, "removal request")
    if request["schema_version"] != 1 or isinstance(request["schema_version"], bool):
        raise RemovalPlanError("removal request schema_version must be integer 1")
    _match(UUID7, request["incident_id"], "incident_id")
    _timestamp(request["planned_at"], "planned_at")
    if request["classification"] not in CLASSIFICATIONS:
        raise RemovalPlanError("incident classification is not registered")
    if request["release_repository"] != EXPECTED_RELEASE_REPOSITORY:
        raise RemovalPlanError("release_repository is not the production release repository")
    _match(COMMIT, request["base_commit"], "base_commit")
    events = request["published_events"]
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_INCIDENT_RESULTS:
        raise RemovalPlanError("published_events must contain 1 to 128 exact State locators")
    request["published_events"] = [
        _locator(item, f"published_events[{index}]") for index, item in enumerate(events)
    ]
    if any(
        item["repository"] != EXPECTED_STATE_REPOSITORY
        for item in request["published_events"]
    ):
        raise RemovalPlanError("published events must come from production State")
    keys = [
        (item["repository"], item["commit"], item["path"])
        for item in request["published_events"]
    ]
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        raise RemovalPlanError("published_events must be unique and canonically sorted")
    request["evidence"] = _locator(request["evidence"], "incident evidence")
    if request["evidence"]["repository"] not in PRIVATE_EVIDENCE_REPOSITORIES:
        raise RemovalPlanError("incident evidence repository is not an approved private store")
    if request["classification"] == "erroneous_publication" and len(events) != 1:
        raise RemovalPlanError("ordinary erroneous-publication scope must contain one result")
    return request


def _manifest_entry(value: Any, label: str) -> dict[str, Any]:
    entry = _object(value, label)
    _fields(entry, MANIFEST_ENTRY_FIELDS, label)
    _match(RESULT_ID, entry["result_id"], f"{label}.result_id")
    submission = _match(UUID7, entry["submission_id"], f"{label}.submission_id")
    _timestamp(entry["accepted_at"], f"{label}.accepted_at")
    _timestamp(entry["eligible_at"], f"{label}.eligible_at")
    _match(REPOSITORY, entry["archive_repository"], f"{label}.archive_repository")
    _match(COMMIT, entry["archive_commit"], f"{label}.archive_commit")
    _safe_path(entry["archive_path"], f"{label}.archive_path")
    _match(DIGEST, entry["archive_ciphertext_sha256"], f"{label}.archive digest")
    _match(DIGEST, entry["bundle_sha256"], f"{label}.bundle digest")
    _match(BUNDLE_PATH, entry["bundle_path"], f"{label}.bundle_path")
    _match(DIGEST, entry["release_tree_sha256"], f"{label}.release tree digest")
    _match(RELEASE_PATH, entry["release_path"], f"{label}.release_path")
    if entry["bundle_path"] != f"sources/{submission}.tar.gz":
        raise RemovalPlanError(f"{label}.bundle_path does not match submission_id")
    prefix = submission.replace("-", "")[:2]
    if entry["archive_path"] != f"archives/{prefix}/{submission}.tar.age":
        raise RemovalPlanError(f"{label}.archive_path does not match submission_id")
    if entry["license"] != "Apache-2.0":
        raise RemovalPlanError(f"{label}.license is not canonical")
    return entry


def _manifest(value: Any, label: str) -> dict[str, Any]:
    manifest = _object(value, label)
    _fields(manifest, MANIFEST_FIELDS, label)
    if manifest["schema_version"] != 1 or isinstance(manifest["schema_version"], bool):
        raise RemovalPlanError(f"{label}.schema_version must be integer 1")
    if not isinstance(manifest["release_id"], str):
        raise RemovalPlanError(f"{label}.release_id is not canonical")
    match = re.fullmatch(
        r"lean-eval-(?P<date>[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01]))",
        manifest["release_id"],
    )
    if match is None:
        raise RemovalPlanError(f"{label}.release_id is not canonical")
    try:
        release_date = dt.date.fromisoformat(match.group("date"))
    except ValueError as error:
        raise RemovalPlanError(f"{label}.release_id has an impossible date") from error
    generated_at = _timestamp(manifest["generated_at"], f"{label}.generated_at")
    if release_date != generated_at.date():
        raise RemovalPlanError(f"{label}.release_id disagrees with generated_at")
    if not isinstance(manifest["entries"], list) or not manifest["entries"]:
        raise RemovalPlanError(f"{label}.entries must be nonempty")
    entries = [
        _manifest_entry(entry, f"{label}.entries[{index}]")
        for index, entry in enumerate(manifest["entries"])
    ]
    identities = [entry["result_id"] for entry in entries]
    if len(identities) != len(set(identities)):
        raise RemovalPlanError(f"{label} duplicates a result_id")
    manifest["entries"] = entries
    return manifest


def _metadata(value: Any, *, result_id: str, release_path: str) -> dict[str, Any]:
    _match(RESULT_ID, result_id, "metadata result path identity")
    _match(RELEASE_PATH, release_path, "metadata release path")
    metadata = _object(value, "published metadata")
    _fields(metadata, METADATA_FIELDS, "published metadata")
    if metadata["schema_version"] != 1 or isinstance(metadata["schema_version"], bool):
        raise RemovalPlanError("published metadata schema_version must be integer 1")
    result = _object(metadata["result"], "published metadata result")
    submission = _object(metadata["submission"], "published metadata submission")
    archive = _object(metadata["archive"], "published metadata archive")
    release = _object(metadata["release"], "published metadata release")
    _fields(result, RESULT_FIELDS, "published metadata result")
    _fields(submission, SUBMISSION_FIELDS, "published metadata submission")
    _fields(archive, ARCHIVE_FIELDS, "published metadata archive")
    _fields(release, RELEASE_FIELDS, "published metadata release")
    if result["result_id"] != result_id:
        raise RemovalPlanError("published metadata result does not match State")
    submission_id = _match(UUID7, submission["submission_id"], "metadata submission_id")
    if release["path"] != release_path or release["license"] != "Apache-2.0":
        raise RemovalPlanError("published metadata release does not match State")
    _timestamp(release["accepted_at"], "metadata accepted_at")
    eligible_at = _timestamp(release["eligible_at"], "metadata eligible_at")
    expected_release_path = (
        f"releases/{eligible_at.year:04d}/{eligible_at.month:02d}/{result_id}"
    )
    if release_path != expected_release_path:
        raise RemovalPlanError("published metadata release path disagrees with eligibility")
    _match(REPOSITORY, archive["archive_repository"], "metadata archive_repository")
    _match(COMMIT, archive["archive_commit"], "metadata archive_commit")
    _match(DIGEST, archive["archive_ciphertext_sha256"], "metadata archive digest")
    prefix = submission_id.replace("-", "")[:2]
    if (
        archive["archive_path"] != f"archives/{prefix}/{submission_id}.tar.age"
        or archive["encrypted"] is not True
    ):
        raise RemovalPlanError("published metadata archive does not match submission identity")
    return {
        "submission_id": submission_id,
        "accepted_at": release["accepted_at"],
        "eligible_at": release["eligible_at"],
        "license": release["license"],
        "archive_repository": archive["archive_repository"],
        "archive_commit": archive["archive_commit"],
        "archive_path": archive["archive_path"],
        "archive_ciphertext_sha256": archive["archive_ciphertext_sha256"],
    }


def _cross_bind_entry(
    entry: dict[str, Any], metadata: dict[str, Any], release_digest: str, release_path: str
) -> None:
    expected = {
        **metadata,
        "release_tree_sha256": release_digest,
        "release_path": release_path,
    }
    for name, wanted in expected.items():
        if entry.get(name) != wanted:
            raise RemovalPlanError(f"published manifest {name} does not match metadata")


def _manifest_action(
    current: tuple[str, bytes] | None, records: list[dict[str, Any]]
) -> dict[str, Any]:
    if current is None:
        return {"action": "already_absent", "path": "release-manifest.json"}
    _, raw = current
    current_sha256 = _sha256(raw)
    manifest = _manifest(
        _json_document(raw, "current release manifest"), "current release manifest"
    )
    by_result = {record["result_id"]: record for record in records}
    matching = [entry for entry in manifest["entries"] if entry["result_id"] in by_result]
    for entry in matching:
        if entry != by_result[entry["result_id"]]["manifest_entry"]:
            raise RemovalPlanError(
                "current manifest incident entry differs from published binding"
            )
    if not matching:
        return {
            "action": "retain", "path": "release-manifest.json",
            "expected_blob_sha256": current_sha256,
        }
    remaining = [
        entry for entry in manifest["entries"] if entry["result_id"] not in by_result
    ]
    if not remaining:
        return {
            "action": "delete", "path": "release-manifest.json",
            "expected_blob_sha256": current_sha256,
        }
    replacement = {**manifest, "entries": remaining}
    replacement_bytes = (
        json.dumps(replacement, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    return {
        "action": "remove_incident_entries",
        "path": "release-manifest.json",
        "expected_blob_sha256": current_sha256,
        "replacement_sha256": _sha256(replacement_bytes),
        "removed_result_ids": sorted(entry["result_id"] for entry in matching),
        "remaining_entry_count": len(remaining),
    }


def plan_removal(
    *,
    repository_root: pathlib.Path,
    state_repository_roots: dict[str, pathlib.Path],
    evidence_repository_root: pathlib.Path,
    request_value: Any,
    remote_main_commits: dict[str, str] | None = None,
) -> dict[str, Any]:
    request = _validate_request(request_value)
    roots: dict[str, pathlib.Path] = {
        EXPECTED_RELEASE_REPOSITORY: _repository_root(
            repository_root, EXPECTED_RELEASE_REPOSITORY
        )
    }
    for repository in {item["repository"] for item in request["published_events"]}:
        supplied = state_repository_roots.get(repository)
        if supplied is None:
            raise RemovalPlanError(f"no repository root supplied for {repository}")
        roots[repository] = _repository_root(supplied, repository)
    evidence_locator = request["evidence"]
    evidence_repository = evidence_locator["repository"]
    evidence_root = _repository_root(evidence_repository_root, evidence_repository)
    if evidence_repository in roots and evidence_root != roots[evidence_repository]:
        raise RemovalPlanError("one repository was supplied through two different roots")
    roots[evidence_repository] = evidence_root

    resolved_heads: dict[str, str] = {}
    for repository, root in roots.items():
        remote = (
            remote_main_commits.get(repository)
            if remote_main_commits is not None
            else _remote_main(repository)
        )
        if remote is None:
            raise RemovalPlanError(f"no remote-main proof supplied for {repository}")
        remote = _match(COMMIT, remote, f"{repository} remote main")
        _commit_on_remote_main(root, remote, remote, f"{repository} remote main")
        resolved_heads[repository] = remote

    release_root = roots[EXPECTED_RELEASE_REPOSITORY]
    state_contract = _state_removal_contract(
        roots[EXPECTED_STATE_REPOSITORY],
        resolved_heads[EXPECTED_STATE_REPOSITORY],
    )
    if _git(
        release_root, "status", "--porcelain", "--untracked-files=all",
        label="cleanliness",
    ):
        raise RemovalPlanError("release repository worktree is not clean")
    base_commit = _git_text(release_root, "rev-parse", "HEAD", label="release HEAD")
    if base_commit != request["base_commit"]:
        raise RemovalPlanError("release repository HEAD does not match requested base_commit")
    if base_commit != resolved_heads[EXPECTED_RELEASE_REPOSITORY]:
        raise RemovalPlanError("release base_commit is not exact remote protected main")

    evidence_commit = evidence_locator["commit"]
    _commit_on_remote_main(
        evidence_root, evidence_commit, resolved_heads[evidence_repository], "evidence commit"
    )
    evidence_blob_id, evidence_raw = _one_blob(
        evidence_root, evidence_commit, evidence_locator["path"],
        label="incident evidence blob", maximum=MAX_DOCUMENT_BYTES,
    )
    if not evidence_raw or _sha256(evidence_raw) != evidence_locator["sha256"]:
        raise RemovalPlanError("incident evidence blob does not match exact locator digest")

    records: list[dict[str, Any]] = []
    seen_results: set[str] = set()
    seen_paths: set[str] = set()
    for locator in request["published_events"]:
        state_root = roots[locator["repository"]]
        _commit_on_remote_main(
            state_root, locator["commit"], resolved_heads[locator["repository"]],
            "State event commit",
        )
        state_blob_id, event_raw = _one_blob(
            state_root, locator["commit"], locator["path"],
            label="release.published State event blob", maximum=MAX_DOCUMENT_BYTES,
        )
        if not event_raw or _sha256(event_raw) != locator["sha256"]:
            raise RemovalPlanError(
                "release.published State event does not match exact locator digest"
            )
        event, expected_path = _validate_published_event(
            _json_document(event_raw, "release.published event")
        )
        if locator["path"] != expected_path:
            raise RemovalPlanError("State event path does not match event identity")
        result_id = event["subject_id"]
        release_path = event["payload"]["path"]
        if result_id in seen_results or release_path in seen_paths:
            raise RemovalPlanError("incident scope repeats a result or release path")
        seen_results.add(result_id)
        seen_paths.add(release_path)

        published_commit = event["payload"]["repository_commit"]
        _commit_on_remote_main(
            release_root, published_commit,
            resolved_heads[EXPECTED_RELEASE_REPOSITORY], "published release commit",
        )
        published_digest, published_files = _release_tree(
            release_root, published_commit, release_path, label="published release tree"
        )
        if published_digest != event["payload"]["tree_digest"]:
            raise RemovalPlanError("published release tree does not match State digest")
        metadata = _metadata(
            _json_document(published_files["metadata.json"], "published metadata"),
            result_id=result_id, release_path=release_path,
        )
        manifest_object, manifest_raw = _one_blob(
            release_root, published_commit, "release-manifest.json",
            label="published release manifest", maximum=MAX_DOCUMENT_BYTES,
        )
        manifest = _manifest(
            _json_document(manifest_raw, "published release manifest"),
            "published release manifest",
        )
        matches = [entry for entry in manifest["entries"] if entry["result_id"] == result_id]
        if len(matches) != 1:
            raise RemovalPlanError("published manifest has no unique incident result")
        entry = matches[0]
        _cross_bind_entry(entry, metadata, published_digest, release_path)
        bundle_path = entry["bundle_path"]
        bundle_object, published_bundle = _one_blob(
            release_root, published_commit, bundle_path,
            label="published source bundle", maximum=MAX_RELEASE_BYTES,
        )
        if _sha256(published_bundle) != entry["bundle_sha256"]:
            raise RemovalPlanError("published source bundle does not match manifest digest")

        base_digest, base_files = _release_tree(
            release_root, base_commit, release_path, label="base release tree"
        )
        if base_digest != published_digest or base_files != published_files:
            raise RemovalPlanError("base release tree differs from published incident tree")
        base_bundle_object, base_bundle = _one_blob(
            release_root, base_commit, bundle_path,
            label="base source bundle", maximum=MAX_RELEASE_BYTES,
        )
        if base_bundle != published_bundle:
            raise RemovalPlanError(
                "base source bundle differs from published incident bundle"
            )
        records.append({
            "result_id": result_id,
            "submission_id": metadata["submission_id"],
            "release_path": release_path,
            "release_tree_sha256": published_digest,
            "bundle_path": bundle_path,
            "bundle_sha256": entry["bundle_sha256"],
            "bundle_blob": bundle_object,
            "base_bundle_blob": base_bundle_object,
            "repository_commit": published_commit,
            "repository_tree": _git_text(
                release_root, "rev-parse", f"{published_commit}^{{tree}}",
                label="published root tree",
            ),
            "manifest_blob": manifest_object,
            "manifest_sha256": _sha256(manifest_raw),
            "manifest_entry": entry,
            "state": {
                **locator, "blob": state_blob_id, "event_id": event["event_id"],
            },
        })

    metadata_entries = _tree_entries(
        release_root, base_commit, "releases", label="base release metadata inventory"
    )
    public_by_submission: dict[str, list[dict[str, str]]] = {}
    metadata_count = 0
    metadata_bytes = 0
    for mode, object_type, object_id, path in metadata_entries:
        if not path.endswith("/metadata.json"):
            continue
        metadata_count += 1
        if metadata_count > MAX_RELEASE_METADATA_ENTRIES:
            raise RemovalPlanError("base release metadata inventory has too many entries")
        if mode != "100644" or object_type != "blob":
            raise RemovalPlanError("base release metadata inventory is noncanonical")
        release_path = path.removesuffix("/metadata.json")
        result_id = release_path.rsplit("/", 1)[-1]
        remaining_metadata_bytes = MAX_RELEASE_METADATA_BYTES - metadata_bytes
        if remaining_metadata_bytes <= 0:
            raise RemovalPlanError("base release metadata inventory exceeds its byte limit")
        metadata_raw = _blob(
            release_root,
            object_id,
            "base release metadata",
            min(MAX_DOCUMENT_BYTES, remaining_metadata_bytes),
        )
        metadata_bytes += len(metadata_raw)
        metadata = _metadata(
            _json_document(metadata_raw, "base release metadata"),
            result_id=result_id,
            release_path=release_path,
        )
        public_by_submission.setdefault(metadata["submission_id"], []).append({
            "result_id": result_id, "release_path": release_path,
        })

    scoped_paths = {record["release_path"] for record in records}
    out_of_scope: list[dict[str, str]] = []
    for record in records:
        for exposure in public_by_submission.get(record["submission_id"], []):
            if exposure["release_path"] not in scoped_paths and exposure not in out_of_scope:
                out_of_scope.append(exposure)
    if request["classification"] == "confidentiality_incident" and out_of_scope:
        required_ids = sorted(item["result_id"] for item in out_of_scope)
        required_paths = sorted(item["release_path"] for item in out_of_scope)
        raise RemovalPlanError(
            "confidential shared-bundle scope is incomplete; add exact release.published "
            f"State locators for result_ids={required_ids}, release_paths={required_paths}"
        )

    affected_paths = [{
        "action": "delete",
        "kind": "release_tree",
        "path": record["release_path"],
        "expected_sha256": record["release_tree_sha256"],
    } for record in sorted(records, key=lambda item: item["release_path"])]
    bundle_actions: list[dict[str, Any]] = []
    for bundle_path in sorted({record["bundle_path"] for record in records}):
        bundled = [record for record in records if record["bundle_path"] == bundle_path]
        if len({record["bundle_sha256"] for record in bundled}) != 1:
            raise RemovalPlanError("one canonical bundle path has conflicting incident digests")
        shared = sorted(
            item["release_path"]
            for item in public_by_submission.get(bundled[0]["submission_id"], [])
            if item["release_path"] not in scoped_paths
        )
        if len(shared) > MAX_SHARED_RELEASE_PATHS:
            raise RemovalPlanError(
                "shared release-path scope exceeds the State correction contract"
            )
        action = "retain_shared" if shared else "delete"
        bundle = {
            "action": action,
            "path": bundle_path,
            "expected_sha256": bundled[0]["bundle_sha256"],
            "shared_release_paths": shared,
        }
        bundle_actions.append(bundle)
        if action == "delete":
            affected_paths.append({
                "action": "delete", "kind": "source_bundle", "path": bundle_path,
                "expected_sha256": bundled[0]["bundle_sha256"],
            })

    current_manifest = _optional_blob(
        release_root, base_commit, "release-manifest.json",
        label="current release manifest", maximum=MAX_DOCUMENT_BYTES,
    )
    manifest_action = _manifest_action(current_manifest, records)
    base_root_tree = _git_text(
        release_root, "rev-parse", f"{base_commit}^{{tree}}", label="base root tree"
    )
    classification = request["classification"]
    bundle_by_path = {item["path"]: item for item in bundle_actions}
    corrections = []
    for record in sorted(records, key=lambda item: item["result_id"]):
        bundle = bundle_by_path[record["bundle_path"]]
        fixed_payload_bindings = {
            "incident_id": request["incident_id"],
            "classification": classification,
            "published_state_event_repository": record["state"]["repository"],
            "published_state_event_commit": record["state"]["commit"],
            "published_state_event_path": record["state"]["path"],
            "published_state_event_blob": record["state"]["blob"],
            "published_state_event_sha256": record["state"]["sha256"],
            "published_repository_commit": record["repository_commit"],
            "published_repository_tree": record["repository_tree"],
            "published_release_tree_sha256": record["release_tree_sha256"],
            "release_path": record["release_path"],
            "bundle_path": record["bundle_path"],
            "bundle_sha256": record["bundle_sha256"],
            "bundle_disposition": bundle["action"],
            "shared_release_paths": bundle["shared_release_paths"],
            "evidence_repository": evidence_locator["repository"],
            "evidence_commit": evidence_locator["commit"],
            "evidence_path": evidence_locator["path"],
            "evidence_blob": evidence_blob_id,
            "evidence_sha256": evidence_locator["sha256"],
        }
        if set(fixed_payload_bindings) != STATE_REMOVAL_FIXED_PAYLOAD_FIELDS:
            raise RemovalPlanError("planner payload bindings disagree with State contract")
        corrections.append({
            "status": "ready_after_containment",
            "required_event_type": "release.removed",
            "subject_id": record["result_id"],
            "causation_event_id": record["state"]["event_id"],
            "fixed_payload_bindings": fixed_payload_bindings,
            "event_skeleton": {
                "schema_version": 1,
                "event_type": "release.removed",
                "subject_id": record["result_id"],
                "causation_event_id": record["state"]["event_id"],
                "actor": {"kind": "system"},
                "payload": dict(fixed_payload_bindings),
            },
            "required_after_containment": [
                "event_id", "occurred_at", "payload.removal_repository_commit",
                "payload.removal_repository_tree",
            ],
        })

    return {
        "schema_version": 1,
        "kind": "release_removal_plan",
        "visibility": "private",
        "incident_id": request["incident_id"],
        "planned_at": request["planned_at"],
        "classification": classification,
        "release_repository": request["release_repository"],
        "state_contract": state_contract,
        "remote_main_commits": dict(sorted(resolved_heads.items())),
        "base": {"commit": base_commit, "tree": base_root_tree},
        "published": [{
            "state_event_repository": record["state"]["repository"],
            "state_event_commit": record["state"]["commit"],
            "state_event_path": record["state"]["path"],
            "state_event_blob": record["state"]["blob"],
            "state_event_id": record["state"]["event_id"],
            "state_event_sha256": record["state"]["sha256"],
            "result_id": record["result_id"],
            "submission_id": record["submission_id"],
            "repository_commit": record["repository_commit"],
            "repository_tree": record["repository_tree"],
            "release_path": record["release_path"],
            "release_tree_sha256": record["release_tree_sha256"],
            "bundle_path": record["bundle_path"],
            "bundle_sha256": record["bundle_sha256"],
            "manifest_blob": record["manifest_blob"],
            "manifest_sha256": record["manifest_sha256"],
        } for record in sorted(records, key=lambda item: item["result_id"])],
        "evidence": {**evidence_locator, "blob": evidence_blob_id},
        "containment": {
            "strategy": (
                "security_coordinated_history_cleanup"
                if classification == "confidentiality_incident"
                else "forward_deletion"
            ),
            "emergency_visibility_restriction_required": (
                classification == "confidentiality_incident"
            ),
            "history_cleanup_required": classification == "confidentiality_incident",
            "affected_paths": sorted(affected_paths, key=lambda item: item["path"]),
            "bundles": bundle_actions,
            "manifest": manifest_action,
        },
        "required_state_corrections": corrections,
        "safety": {
            "publication_must_remain_disabled": True,
            "must_not_rewrite_results": True,
            "must_not_edit_or_delete_state_events": True,
            "full_plan_must_remain_private": True,
            "live_refs_mutated_by_this_tool": False,
        },
    }


def public_projection(plan: dict[str, Any]) -> dict[str, Any]:
    """Return a source-free public summary for an ordinary erroneous release."""
    if plan["classification"] == "confidentiality_incident":
        raise RemovalPlanError(
            "a confidentiality-incident plan cannot produce a public projection"
        )
    return {
        "schema_version": 1,
        "kind": "release_removal_public_summary",
        "visibility": "public",
        "incident_id": plan["incident_id"],
        "planned_at": plan["planned_at"],
        "classification": plan["classification"],
        "release_repository": plan["release_repository"],
        "base": plan["base"],
        "published": [{
            key: item[key]
            for key in (
                "result_id", "repository_commit", "repository_tree", "release_path",
                "release_tree_sha256", "bundle_path", "bundle_sha256",
            )
        } for item in plan["published"]],
        "containment": plan["containment"],
        "state_correction_status": "ready_after_containment",
        "safety": {
            "publication_must_remain_disabled": True,
            "must_not_rewrite_results": True,
            "live_refs_mutated_by_this_tool": False,
        },
    }


def _write_exclusive(
    path: pathlib.Path,
    value: Any,
    forbidden_roots: list[pathlib.Path],
    mode: int,
    maximum: int = MAX_PLAN_OUTPUT_BYTES,
) -> None:
    parent = path.parent.resolve(strict=True)
    for forbidden in forbidden_roots:
        root = forbidden.resolve(strict=True)
        if parent == root or parent.is_relative_to(root):
            raise RemovalPlanError("plan output must be outside every repository")
    encoder = json.JSONEncoder(ensure_ascii=True, indent=2, sort_keys=True)

    def encoded_chunks() -> Any:
        yield from encoder.iterencode(value)
        yield "\n"

    encoded_size = 0
    for chunk in encoded_chunks():
        encoded_size += len(chunk.encode("utf-8"))
        if encoded_size > maximum:
            raise RemovalPlanError("plan output exceeds its size limit")
    directory_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    output_flags = (
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        directory = os.open(parent, directory_flags)
        try:
            descriptor = os.open(path.name, output_flags, mode, dir_fd=directory)
            try:
                for chunk in encoded_chunks():
                    view = memoryview(chunk.encode("utf-8"))
                    while view:
                        written = os.write(descriptor, view)
                        if written <= 0:
                            raise OSError("short output write")
                        view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            os.close(directory)
    except FileExistsError as error:
        raise RemovalPlanError(f"refusing to overwrite {path}") from error
    except OSError as error:
        raise RemovalPlanError(f"cannot create exact output {path}") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request", type=pathlib.Path)
    parser.add_argument("--state-repository-root", required=True, type=pathlib.Path)
    parser.add_argument("--evidence-repository-root", required=True, type=pathlib.Path)
    parser.add_argument("--repository-root", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--public-output", type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        request = _json_document(
            _read_regular(args.request, "removal request", MAX_DOCUMENT_BYTES),
            "removal request",
        )
        plan = plan_removal(
            repository_root=args.repository_root,
            state_repository_roots={EXPECTED_STATE_REPOSITORY: args.state_repository_root},
            evidence_repository_root=args.evidence_repository_root,
            request_value=request,
        )
        public_value = (
            public_projection(plan) if args.public_output is not None else None
        )
        roots = [
            args.repository_root, args.state_repository_root,
            args.evidence_repository_root,
        ]
        _write_exclusive(args.output, plan, roots, 0o600)
        if args.public_output is not None and public_value is not None:
            _write_exclusive(
                args.public_output, public_value, roots, 0o644
            )
    except RemovalPlanError as error:
        print(f"release-removal-plan: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
