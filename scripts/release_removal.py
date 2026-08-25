#!/usr/bin/env python3
"""Stage and locally commit an exact reviewed release-removal plan.

This operator tool never contacts a remote and has no push subcommand.  It
turns a private read-only removal plan into two independently reviewable local
commits: the release containment commit and one atomic State correction
commit.  The returned compare-and-swap plans name exact commits but deliberately
contain no executable push command or credential handling.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any

from plan_release_removal import (
    EXPECTED_RELEASE_REPOSITORY,
    EXPECTED_STATE_REPOSITORY,
    MAX_DOCUMENT_BYTES,
    MAX_RELEASE_BYTES,
    RELEASE_PATH,
    STATE_REMOVAL_FIXED_PAYLOAD_FIELDS,
    STATE_REMOVAL_LATE_PAYLOAD_FIELDS,
    _git_environment,
    _repository_root,
    _state_removal_contract,
    _write_exclusive,
)
from release_controller import canonical_json, parse_timestamp
from release_orchestrator import COMMIT, DIGEST, RESULT_ID, UUID7
from release_tree import tree_digest

MAX_PLAN_BYTES = 8 * 1024 * 1024
MAX_IDENTITIES_BYTES = 128 * 1024
MAX_INCIDENT_RESULTS = 128
SYNTHETIC_FIXTURE_MARKER = ".lean-eval-synthetic-release-removal-fixture"
SYNTHETIC_FIXTURE_BYTES = b"harmless synthetic release-removal qualification only\n"
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
PLAN_FIELDS = {
    "schema_version",
    "kind",
    "visibility",
    "incident_id",
    "planned_at",
    "classification",
    "release_repository",
    "state_contract",
    "remote_main_commits",
    "base",
    "published",
    "evidence",
    "containment",
    "required_state_corrections",
    "safety",
}
PUBLISHED_FIELDS = {
    "state_event_repository",
    "state_event_commit",
    "state_event_path",
    "state_event_blob",
    "state_event_id",
    "state_event_sha256",
    "result_id",
    "submission_id",
    "repository_commit",
    "repository_tree",
    "release_path",
    "release_tree_sha256",
    "bundle_path",
    "bundle_sha256",
    "manifest_blob",
    "manifest_sha256",
}
CORRECTION_FIELDS = {
    "status",
    "required_event_type",
    "subject_id",
    "causation_event_id",
    "fixed_payload_bindings",
    "event_skeleton",
    "required_after_containment",
}
EVENT_FIELDS = {
    "schema_version",
    "event_id",
    "event_type",
    "occurred_at",
    "subject_id",
    "causation_event_id",
    "actor",
    "payload",
}
STATUS_FIELDS = {
    "schema_version",
    "result_id",
    "authority_event_id",
    "status",
    "release_event_id",
    "release_revision",
    "supersedes_release_event_id",
}
IDENTITY_FIELDS = {"subject_id", "event_id", "occurred_at"}
MANIFEST_FIELDS = {"schema_version", "release_id", "generated_at", "entries"}
MANIFEST_ENTRY_RESULT = re.compile(r"r2_[0-9a-f]{64}")
CONTAINMENT_FIELDS = {
    "strategy",
    "emergency_visibility_restriction_required",
    "history_cleanup_required",
    "affected_paths",
    "bundles",
    "manifest",
}
EVIDENCE_FIELDS = {"repository", "commit", "path", "sha256", "blob"}


class ReleaseRemovalError(ValueError):
    """A local containment or State correction was not exact."""


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ReleaseRemovalError(f"{label} must be an object with string keys")
    return value


def _fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ReleaseRemovalError(
            f"{label} fields are not canonical; "
            f"missing={sorted(expected - set(value))}, "
            f"extra={sorted(set(value) - expected)}"
        )


def _match(pattern: re.Pattern[str], value: Any, label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ReleaseRemovalError(f"{label} is not canonical")
    return value


def _canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _git(
    root: pathlib.Path,
    *arguments: str,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            ["git", "--no-replace-objects", "-C", str(root), *arguments],
            check=check,
            capture_output=True,
            timeout=30,
            env=_git_environment(),
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise ReleaseRemovalError("local Git operation failed closed") from error


def _git_text(root: pathlib.Path, *arguments: str) -> str:
    try:
        return _git(root, *arguments).stdout.decode("ascii").strip()
    except UnicodeError as error:
        raise ReleaseRemovalError("local Git output is not ASCII") from error


def _repository(root_value: pathlib.Path, label: str) -> pathlib.Path:
    if not isinstance(root_value, pathlib.Path):
        raise ReleaseRemovalError(f"{label} path must be a pathlib.Path")
    try:
        root = root_value.resolve(strict=True)
    except OSError as error:
        raise ReleaseRemovalError(f"{label} is unavailable") from error
    if root_value.is_symlink() or not root.is_dir():
        raise ReleaseRemovalError(f"{label} must be a regular directory")
    top = pathlib.Path(_git_text(root, "rev-parse", "--show-toplevel")).resolve()
    if top != root:
        raise ReleaseRemovalError(f"{label} must be the Git toplevel")
    return root


def _clean(root: pathlib.Path, label: str) -> None:
    if _git(root, "status", "--porcelain=v1", "--untracked-files=all").stdout:
        raise ReleaseRemovalError(f"{label} must be tracked-clean")


def _publication_disabled() -> None:
    if os.environ.get("PUBLICATION_ENABLED") not in {None, "", "false"}:
        raise ReleaseRemovalError("PUBLICATION_ENABLED must remain absent or exactly false")


def _require_synthetic_confidentiality_fixture(
    root: pathlib.Path,
    plan: dict[str, Any],
    enabled: bool,
) -> str | None:
    if plan["classification"] != "confidentiality_incident":
        if enabled:
            raise ReleaseRemovalError(
                "synthetic confidentiality mode requires a confidentiality plan"
            )
        return None
    if not enabled:
        raise ReleaseRemovalError(
            "confidentiality release mutation requires explicit synthetic fixture mode; "
            "real history-cleanup verification is not implemented"
        )
    base = plan["base"]["commit"]
    entry = _git(
        root,
        "ls-tree",
        base,
        "--",
        SYNTHETIC_FIXTURE_MARKER,
    ).stdout.decode("utf-8").strip().split()
    raw = _git(
        root,
        "show",
        f"{base}:{SYNTHETIC_FIXTURE_MARKER}",
        check=False,
    )
    if (
        len(entry) < 4
        or entry[0] != "100644"
        or entry[1] != "blob"
        or raw.returncode != 0
        or raw.stdout != SYNTHETIC_FIXTURE_BYTES
    ):
        raise ReleaseRemovalError(
            "synthetic confidentiality qualification requires the exact tracked "
            "harmless-fixture marker in the planned base"
        )
    return _sha256(raw.stdout)


def _head_tree(root: pathlib.Path) -> tuple[str, str]:
    return (
        _git_text(root, "rev-parse", "HEAD"),
        _git_text(root, "rev-parse", "HEAD^{tree}"),
    )


def _safe_relative(value: Any, label: str) -> pathlib.PurePosixPath:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 512:
        raise ReleaseRemovalError(f"{label} is not a bounded relative path")
    relative = pathlib.PurePosixPath(value)
    if (
        relative.is_absolute()
        or relative.as_posix() != value
        or "\\" in value
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ReleaseRemovalError(f"{label} is not a canonical relative path")
    return relative


def _read_regular(path: pathlib.Path, label: str, maximum: int) -> bytes:
    descriptor: int | None = None
    try:
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise ReleaseRemovalError(f"{label} is not one bounded regular file")
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or opened.st_size != before.st_size
        ):
            raise ReleaseRemovalError(f"{label} changed while opened")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    except ReleaseRemovalError:
        raise
    except OSError as error:
        raise ReleaseRemovalError(f"{label} is unreadable") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(raw) != before.st_size or len(raw) > maximum:
        raise ReleaseRemovalError(f"{label} changed while read")
    return raw


def _parse_json_file(path: pathlib.Path, label: str, maximum: int) -> Any:
    try:
        return json.loads(_read_regular(path, label, maximum).decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseRemovalError(f"{label} is not canonical UTF-8 JSON") from error


def _validate_plan(value: Any) -> dict[str, Any]:
    plan = _object(value, "release-removal plan")
    _fields(plan, PLAN_FIELDS, "release-removal plan")
    if (
        plan["schema_version"] != 1
        or isinstance(plan["schema_version"], bool)
        or plan["kind"] != "release_removal_plan"
        or plan["visibility"] != "private"
        or plan["release_repository"] != EXPECTED_RELEASE_REPOSITORY
    ):
        raise ReleaseRemovalError("release-removal plan identity is invalid")
    classification = plan["classification"]
    if classification == "owner_retraction":
        raise ReleaseRemovalError(
            "owner_retraction removal policy is unresolved and is not supported"
        )
    if classification not in {"erroneous_publication", "confidentiality_incident"}:
        raise ReleaseRemovalError("release-removal classification is unsupported")
    _match(UUID7, plan["incident_id"], "incident_id")
    parse_timestamp(plan["planned_at"], "planned_at")
    base = _object(plan["base"], "release-removal base")
    _fields(base, {"commit", "tree"}, "release-removal base")
    _match(COMMIT, base["commit"], "release-removal base commit")
    _match(COMMIT, base["tree"], "release-removal base tree")
    remote = _object(plan["remote_main_commits"], "remote main commits")
    if remote.get(EXPECTED_RELEASE_REPOSITORY) != base["commit"]:
        raise ReleaseRemovalError("plan release base is not its protected-main binding")
    _match(
        COMMIT,
        remote.get(EXPECTED_STATE_REPOSITORY),
        "plan protected State head",
    )
    evidence = _object(plan["evidence"], "private evidence binding")
    _fields(evidence, EVIDENCE_FIELDS, "private evidence binding")
    if evidence["repository"] not in {
        EXPECTED_STATE_REPOSITORY,
        "leanprover/lean-eval-audit",
    }:
        raise ReleaseRemovalError("private evidence repository is not approved")
    _match(COMMIT, evidence["commit"], "private evidence commit")
    _match(COMMIT, evidence["blob"], "private evidence blob")
    _match(DIGEST, evidence["sha256"], "private evidence digest")
    _safe_relative(evidence["path"], "private evidence path")
    if remote.get(evidence["repository"]) is None:
        raise ReleaseRemovalError("private evidence protected head is absent")
    state_contract = _object(plan["state_contract"], "State removal contract")
    if (
        state_contract.get("repository") != EXPECTED_STATE_REPOSITORY
        or state_contract.get("event_type") != "release.removed"
        or COMMIT.fullmatch(str(state_contract.get("commit"))) is None
        or not isinstance(state_contract.get("trees"), list)
        or not isinstance(state_contract.get("components"), list)
    ):
        raise ReleaseRemovalError("State removal contract binding is invalid")
    containment = _object(plan["containment"], "containment")
    _fields(containment, CONTAINMENT_FIELDS, "containment")
    expected_strategy = (
        "security_coordinated_history_cleanup"
        if classification == "confidentiality_incident"
        else "forward_deletion"
    )
    confidential = classification == "confidentiality_incident"
    if (
        containment["strategy"] != expected_strategy
        or containment["emergency_visibility_restriction_required"] is not confidential
        or containment["history_cleanup_required"] is not confidential
    ):
        raise ReleaseRemovalError("containment strategy disagrees with classification")
    bundles_value = containment["bundles"]
    if not isinstance(bundles_value, list) or not bundles_value:
        raise ReleaseRemovalError("containment has no bounded bundle actions")
    bundles: dict[str, dict[str, Any]] = {}
    for bundle_value in bundles_value:
        bundle = _object(bundle_value, "bundle action")
        _fields(
            bundle,
            {"action", "path", "expected_sha256", "shared_release_paths"},
            "bundle action",
        )
        path = _safe_relative(bundle["path"], "bundle action path").as_posix()
        _match(DIGEST, bundle["expected_sha256"], "bundle action digest")
        shared = bundle["shared_release_paths"]
        if (
            bundle["action"] not in {"delete", "retain_shared"}
            or not isinstance(shared, list)
            or shared != sorted(set(shared))
            or (bundle["action"] == "delete") != (not shared)
            or path in bundles
        ):
            raise ReleaseRemovalError("bundle action is not canonical")
        if any(RELEASE_PATH.fullmatch(item) is None for item in shared):
            raise ReleaseRemovalError("shared release path is not canonical")
        bundles[path] = bundle
    published = plan["published"]
    corrections = plan["required_state_corrections"]
    if (
        not isinstance(published, list)
        or not isinstance(corrections, list)
        or not 1 <= len(published) == len(corrections) <= MAX_INCIDENT_RESULTS
    ):
        raise ReleaseRemovalError("plan incident scope is empty or unbounded")
    if classification == "erroneous_publication" and len(published) != 1:
        raise ReleaseRemovalError("erroneous publication must remove exactly one result")
    result_ids: list[str] = []
    for item_value in published:
        item = _object(item_value, "published binding")
        _fields(item, PUBLISHED_FIELDS, "published binding")
        result_id = _match(RESULT_ID, item["result_id"], "published result_id")
        if item["state_event_repository"] != EXPECTED_STATE_REPOSITORY:
            raise ReleaseRemovalError("published event repository is not production State")
        _match(COMMIT, item["state_event_commit"], "published State event commit")
        _match(COMMIT, item["state_event_blob"], "published State event blob")
        _match(DIGEST, item["state_event_sha256"], "published State event digest")
        _match(COMMIT, item["repository_commit"], "published repository commit")
        _match(COMMIT, item["repository_tree"], "published repository tree")
        _match(DIGEST, item["release_tree_sha256"], "published release tree digest")
        _match(DIGEST, item["bundle_sha256"], "published bundle digest")
        _match(COMMIT, item["manifest_blob"], "published manifest blob")
        _match(DIGEST, item["manifest_sha256"], "published manifest digest")
        state_event_id = _match(
            UUID7, item["state_event_id"], "published State event_id"
        )
        state_event_path = _safe_relative(
            item["state_event_path"], "published State event path"
        ).as_posix()
        if state_event_path != (
            f"events/{state_event_id.replace('-', '')[:2]}/{state_event_id}.json"
        ):
            raise ReleaseRemovalError("published State event path is not canonical")
        _safe_relative(item["release_path"], "published release path")
        _safe_relative(item["bundle_path"], "published bundle path")
        if RELEASE_PATH.fullmatch(item["release_path"]) is None:
            raise ReleaseRemovalError("published release path is not canonical")
        result_ids.append(result_id)
    if result_ids != sorted(set(result_ids)):
        raise ReleaseRemovalError("published results are not uniquely sorted")
    correction_subjects: list[str] = []
    published_by_result = {item["result_id"]: item for item in published}
    for correction_value in corrections:
        correction = _object(correction_value, "required State correction")
        _fields(correction, CORRECTION_FIELDS, "required State correction")
        subject = _match(RESULT_ID, correction["subject_id"], "correction subject")
        fixed = _object(correction["fixed_payload_bindings"], "fixed payload")
        _fields(fixed, STATE_REMOVAL_FIXED_PAYLOAD_FIELDS, "fixed payload")
        skeleton = _object(correction["event_skeleton"], "event skeleton")
        published_item = published_by_result.get(subject)
        if published_item is None:
            raise ReleaseRemovalError("State correction has no published binding")
        bundle = bundles.get(published_item["bundle_path"])
        if bundle is None:
            raise ReleaseRemovalError("State correction has no bundle action")
        expected_fixed = {
            "incident_id": plan["incident_id"],
            "classification": classification,
            "published_state_event_repository": published_item[
                "state_event_repository"
            ],
            "published_state_event_commit": published_item["state_event_commit"],
            "published_state_event_path": published_item["state_event_path"],
            "published_state_event_blob": published_item["state_event_blob"],
            "published_state_event_sha256": published_item["state_event_sha256"],
            "published_repository_commit": published_item["repository_commit"],
            "published_repository_tree": published_item["repository_tree"],
            "published_release_tree_sha256": published_item["release_tree_sha256"],
            "release_path": published_item["release_path"],
            "bundle_path": published_item["bundle_path"],
            "bundle_sha256": published_item["bundle_sha256"],
            "bundle_disposition": bundle["action"],
            "shared_release_paths": bundle["shared_release_paths"],
            "evidence_repository": evidence["repository"],
            "evidence_commit": evidence["commit"],
            "evidence_path": evidence["path"],
            "evidence_blob": evidence["blob"],
            "evidence_sha256": evidence["sha256"],
        }
        if (
            correction["status"] != "ready_after_containment"
            or correction["required_event_type"] != "release.removed"
            or correction["causation_event_id"]
            != fixed["published_state_event_path"].rsplit("/", 1)[-1].removesuffix(".json")
            or correction["required_after_containment"]
            != [
                "event_id",
                "occurred_at",
                "payload.removal_repository_commit",
                "payload.removal_repository_tree",
            ]
            or skeleton
            != {
                "schema_version": 1,
                "event_type": "release.removed",
                "subject_id": subject,
                "causation_event_id": correction["causation_event_id"],
                "actor": {"kind": "system"},
                "payload": fixed,
            }
            or fixed["incident_id"] != plan["incident_id"]
            or fixed["classification"] != classification
            or fixed != expected_fixed
        ):
            raise ReleaseRemovalError("State correction does not match its fixed skeleton")
        correction_subjects.append(subject)
    if correction_subjects != result_ids:
        raise ReleaseRemovalError("State correction scope differs from published scope")
    safety = _object(plan["safety"], "release-removal safety")
    if safety != {
        "publication_must_remain_disabled": True,
        "must_not_rewrite_results": True,
        "must_not_edit_or_delete_state_events": True,
        "full_plan_must_remain_private": True,
        "live_refs_mutated_by_this_tool": False,
    }:
        raise ReleaseRemovalError("release-removal safety contract has drifted")
    return plan


def _base_release_files(root: pathlib.Path, plan: dict[str, Any]) -> set[str]:
    files: set[str] = set()
    for item in plan["published"]:
        prefix = f"{item['release_path']}/"
        listed = _git(
            root,
            "ls-tree",
            "-r",
            "--name-only",
            plan["base"]["commit"],
            "--",
            item["release_path"],
        ).stdout
        try:
            names = listed.decode("utf-8").splitlines()
        except UnicodeError as error:
            raise ReleaseRemovalError("planned release tree paths are not UTF-8") from error
        if not names or any(not name.startswith(prefix) for name in names):
            raise ReleaseRemovalError("planned release directory is absent or ambiguous")
        files.update(names)
    return files


def _manifest_replacement(
    raw: bytes,
    manifest_plan: dict[str, Any],
    incident_result_ids: set[str],
) -> bytes:
    try:
        manifest = _object(json.loads(raw.decode("utf-8")), "release manifest")
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseRemovalError("release manifest is invalid") from error
    _fields(manifest, MANIFEST_FIELDS, "release manifest")
    entries = manifest["entries"]
    if not isinstance(entries, list) or not all(isinstance(item, dict) for item in entries):
        raise ReleaseRemovalError("release manifest entries are invalid")
    result_ids = [item.get("result_id") for item in entries]
    if any(MANIFEST_ENTRY_RESULT.fullmatch(item or "") is None for item in result_ids):
        raise ReleaseRemovalError("release manifest result identity is invalid")
    if len(result_ids) != len(set(result_ids)):
        raise ReleaseRemovalError("release manifest has duplicate results")
    remaining = [item for item in entries if item["result_id"] not in incident_result_ids]
    removed = sorted(set(result_ids) & incident_result_ids)
    if (
        removed != manifest_plan.get("removed_result_ids")
        or len(remaining) != manifest_plan.get("remaining_entry_count")
    ):
        raise ReleaseRemovalError("release manifest removal scope differs from the plan")
    return _canonical_bytes({**manifest, "entries": remaining})


def _expected_release_stage(
    root: pathlib.Path,
    plan: dict[str, Any],
) -> tuple[set[str], bytes | None]:
    expected = _base_release_files(root, plan)
    containment = _object(plan["containment"], "containment")
    affected = containment.get("affected_paths")
    bundles = containment.get("bundles")
    if not isinstance(affected, list) or not isinstance(bundles, list):
        raise ReleaseRemovalError("containment paths or bundles are invalid")
    affected_by_path = {
        _safe_relative(_object(item, "affected path").get("path"), "affected path").as_posix(): item
        for item in affected
    }
    if len(affected_by_path) != len(affected):
        raise ReleaseRemovalError("containment repeats an affected path")
    for item in plan["published"]:
        action = affected_by_path.get(item["release_path"])
        release_root = root.joinpath(*pathlib.PurePosixPath(item["release_path"]).parts)
        if (
            not isinstance(action, dict)
            or action != {
                "action": "delete",
                "kind": "release_tree",
                "path": item["release_path"],
                "expected_sha256": item["release_tree_sha256"],
            }
            or release_root.is_symlink()
            or not release_root.is_dir()
            or tree_digest(release_root) != item["release_tree_sha256"]
        ):
            raise ReleaseRemovalError("planned release tree no longer matches its digest")
    for bundle_value in bundles:
        bundle = _object(bundle_value, "bundle action")
        path = _safe_relative(bundle.get("path"), "bundle path").as_posix()
        matches = [item for item in plan["published"] if item["bundle_path"] == path]
        if not matches or len({item["bundle_sha256"] for item in matches}) != 1:
            raise ReleaseRemovalError("bundle action is not bound to the incident")
        bundle_path = root.joinpath(*pathlib.PurePosixPath(path).parts)
        raw = _read_regular(bundle_path, "planned source bundle", MAX_RELEASE_BYTES)
        if _sha256(raw) != matches[0]["bundle_sha256"]:
            raise ReleaseRemovalError("planned source bundle digest changed")
        action = bundle.get("action")
        if action == "delete":
            expected.add(path)
            if affected_by_path.get(path) != {
                "action": "delete",
                "kind": "source_bundle",
                "path": path,
                "expected_sha256": matches[0]["bundle_sha256"],
            }:
                raise ReleaseRemovalError("source-bundle deletion differs from the plan")
        elif action != "retain_shared":
            raise ReleaseRemovalError("bundle disposition is invalid")
    manifest_plan = _object(containment.get("manifest"), "manifest action")
    manifest_path = root / "release-manifest.json"
    manifest_action = manifest_plan.get("action")
    replacement: bytes | None = None
    if manifest_action == "already_absent":
        if manifest_path.exists() or manifest_path.is_symlink():
            raise ReleaseRemovalError("planned absent manifest is present")
    elif manifest_action in {"delete", "retain", "remove_incident_entries"}:
        raw = _read_regular(manifest_path, "release manifest", MAX_DOCUMENT_BYTES)
        if _sha256(raw) != manifest_plan.get("expected_blob_sha256"):
            raise ReleaseRemovalError("release manifest digest changed")
        if manifest_action == "delete":
            expected.add("release-manifest.json")
        elif manifest_action == "remove_incident_entries":
            replacement = _manifest_replacement(
                raw,
                manifest_plan,
                {item["result_id"] for item in plan["published"]},
            )
            if _sha256(replacement) != manifest_plan.get("replacement_sha256"):
                raise ReleaseRemovalError("release manifest replacement digest disagrees")
            expected.add("release-manifest.json")
    else:
        raise ReleaseRemovalError("manifest action is invalid")
    if set(affected_by_path) != {
        item["release_path"] for item in plan["published"]
    } | {
        bundle["path"] for bundle in bundles if bundle.get("action") == "delete"
    }:
        raise ReleaseRemovalError("containment affected-path scope is not exact")
    return expected, replacement


def _remove_release_directory(root: pathlib.Path, relative: str) -> None:
    directory = root.joinpath(*pathlib.PurePosixPath(relative).parts)
    files = sorted(
        (path for path in directory.rglob("*") if path.is_file() and not path.is_symlink()),
        reverse=True,
    )
    if any(path.is_symlink() for path in directory.rglob("*")):
        raise ReleaseRemovalError("planned release directory contains a symlink")
    for path in files:
        path.unlink()
    for path in sorted((path for path in directory.rglob("*") if path.is_dir()), reverse=True):
        path.rmdir()
    directory.rmdir()


def stage_release_containment(
    plan_value: Any,
    release_root: pathlib.Path,
    *,
    synthetic_confidentiality_qualification: bool = False,
) -> dict[str, Any]:
    """Apply and stage only the exact containment paths from a reviewed plan."""
    plan = _validate_plan(plan_value)
    _publication_disabled()
    root = _repository(release_root, "release repository")
    try:
        _repository_root(root, EXPECTED_RELEASE_REPOSITORY)
    except Exception as error:
        raise ReleaseRemovalError("release repository origin is not exact upstream") from error
    _require_synthetic_confidentiality_fixture(
        root, plan, synthetic_confidentiality_qualification
    )
    _clean(root, "release repository")
    head, tree = _head_tree(root)
    if (head, tree) != (plan["base"]["commit"], plan["base"]["tree"]):
        raise ReleaseRemovalError("release checkout is not the exact planned base")
    expected, replacement = _expected_release_stage(root, plan)
    for item in plan["published"]:
        _remove_release_directory(root, item["release_path"])
    for bundle in plan["containment"]["bundles"]:
        if bundle["action"] == "delete":
            root.joinpath(*pathlib.PurePosixPath(bundle["path"]).parts).unlink()
    manifest_action = plan["containment"]["manifest"]["action"]
    if manifest_action == "delete":
        (root / "release-manifest.json").unlink()
    elif manifest_action == "remove_incident_entries":
        assert replacement is not None
        (root / "release-manifest.json").write_bytes(replacement)
    _git(root, "add", "-A", "--", *sorted(expected))
    return verify_staged_release_containment(
        plan,
        root,
        synthetic_confidentiality_qualification=(
            synthetic_confidentiality_qualification
        ),
    )


def verify_staged_release_containment(
    plan_value: Any,
    release_root: pathlib.Path,
    *,
    synthetic_confidentiality_qualification: bool = False,
) -> dict[str, Any]:
    """Verify the cached diff is exactly the plan-derived containment tree."""
    plan = _validate_plan(plan_value)
    _publication_disabled()
    root = _repository(release_root, "release repository")
    try:
        _repository_root(root, EXPECTED_RELEASE_REPOSITORY)
    except Exception as error:
        raise ReleaseRemovalError("release repository origin is not exact upstream") from error
    synthetic_attestation = _require_synthetic_confidentiality_fixture(
        root, plan, synthetic_confidentiality_qualification
    )
    head, tree = _head_tree(root)
    if (head, tree) != (plan["base"]["commit"], plan["base"]["tree"]):
        raise ReleaseRemovalError("release checkout moved from the planned base")
    expected, replacement = _expected_release_stage_from_base(root, plan)
    staged = set(
        _git(root, "diff", "--cached", "--name-only", "--").stdout.decode("utf-8").splitlines()
    )
    if staged != expected:
        raise ReleaseRemovalError("cached release diff is not the exact containment path set")
    for path in expected:
        index_object = _git(root, "cat-file", "-e", f":{path}", check=False)
        if path == "release-manifest.json" and replacement is not None:
            if index_object.returncode != 0 or _git(root, "show", f":{path}").stdout != replacement:
                raise ReleaseRemovalError("cached manifest is not the exact replacement")
        elif index_object.returncode == 0:
            raise ReleaseRemovalError("a planned deletion remains in the Git index")
    if _git(root, "diff", "--name-only", "--", *sorted(expected)).stdout:
        raise ReleaseRemovalError("containment paths changed after staging")
    if (
        _git(root, "diff", "--name-only", "--").stdout
        or _git(root, "ls-files", "--others", "--exclude-standard").stdout
    ):
        raise ReleaseRemovalError("release repository has an unstaged or untracked change")
    synthetic = plan["classification"] == "confidentiality_incident"
    result = {
        "schema_version": 1,
        "kind": "release_containment_stage",
        "visibility": "private",
        "classification": plan["classification"],
        "incident_id": plan["incident_id"],
        "base_commit": head,
        "base_tree": tree,
        "staged_tree": _git_text(root, "write-tree"),
        "staged_paths": sorted(expected),
        "semantics": (
            "synthetic_target_tree_only"
            if plan["classification"] == "confidentiality_incident"
            else "forward_deletion"
        ),
        "synthetic_fixture_attestation": synthetic_attestation,
        "push_prohibited": synthetic,
        "live_refs_mutated": False,
    }
    if synthetic:
        result.update(
            remote_update_permitted=False,
            prohibition_reason="synthetic_target_tree_is_not_history_cleanup",
        )
    else:
        result.update(remote_update_permitted=True)
    return result


def _expected_release_stage_from_base(
    root: pathlib.Path,
    plan: dict[str, Any],
) -> tuple[set[str], bytes | None]:
    """Compute expected staged paths from immutable base objects after mutation."""
    expected = _base_release_files(root, plan)
    for bundle in plan["containment"]["bundles"]:
        if bundle["action"] == "delete":
            expected.add(bundle["path"])
    manifest = plan["containment"]["manifest"]
    replacement = None
    if manifest["action"] in {"delete", "remove_incident_entries"}:
        expected.add("release-manifest.json")
    if manifest["action"] == "remove_incident_entries":
        raw = _git(root, "show", f"{plan['base']['commit']}:release-manifest.json").stdout
        replacement = _manifest_replacement(
            raw,
            manifest,
            {item["result_id"] for item in plan["published"]},
        )
        if _sha256(replacement) != manifest["replacement_sha256"]:
            raise ReleaseRemovalError("base-derived manifest replacement disagrees")
    return expected, replacement


def _commit(root: pathlib.Path, message: str) -> str:
    if not isinstance(message, str) or not message.strip() or "\x00" in message:
        raise ReleaseRemovalError("local commit message is invalid")
    _git(
        root,
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "commit.gpgSign=false",
        "commit",
        "-m",
        message,
    )
    return _git_text(root, "rev-parse", "HEAD")


def finalize_release_containment(
    plan_value: Any,
    release_root: pathlib.Path,
    *,
    message: str,
    synthetic_confidentiality_qualification: bool = False,
) -> dict[str, Any]:
    """Create or recognize the exact local release containment commit."""
    plan = _validate_plan(plan_value)
    _publication_disabled()
    root = _repository(release_root, "release repository")
    try:
        _repository_root(root, EXPECTED_RELEASE_REPOSITORY)
    except Exception as error:
        raise ReleaseRemovalError("release repository origin is not exact upstream") from error
    # Qualify confidentiality semantics before inspecting an index that this
    # function may commit.  The lower-level stage and verify functions repeat
    # this check independently; this top-level gate ensures every path to
    # _commit is dominated by the explicit harmless-fixture qualification.
    _require_synthetic_confidentiality_fixture(
        root, plan, synthetic_confidentiality_qualification
    )
    head = _git_text(root, "rev-parse", "HEAD")
    if head == plan["base"]["commit"]:
        if not _git(root, "diff", "--cached", "--name-only", "--").stdout:
            stage_release_containment(
                plan,
                root,
                synthetic_confidentiality_qualification=(
                    synthetic_confidentiality_qualification
                ),
            )
        staged = verify_staged_release_containment(
            plan,
            root,
            synthetic_confidentiality_qualification=(
                synthetic_confidentiality_qualification
            ),
        )
        commit = _commit(root, message)
    else:
        commit = head
        staged = None
    binding = verify_release_containment_commit(
        plan,
        root,
        commit,
        synthetic_confidentiality_qualification=(
            synthetic_confidentiality_qualification
        ),
    )
    if staged is not None and binding["tree"] != staged["staged_tree"]:
        raise ReleaseRemovalError("release commit tree differs from the verified index")
    return binding


def verify_release_containment_commit(
    plan_value: Any,
    release_root: pathlib.Path,
    commit: str,
    *,
    synthetic_confidentiality_qualification: bool = False,
) -> dict[str, Any]:
    """Bind an already-landed local containment commit for State resumption."""
    plan = _validate_plan(plan_value)
    _publication_disabled()
    root = _repository(release_root, "release repository")
    try:
        _repository_root(root, EXPECTED_RELEASE_REPOSITORY)
    except Exception as error:
        raise ReleaseRemovalError("release repository origin is not exact upstream") from error
    synthetic_attestation = _require_synthetic_confidentiality_fixture(
        root, plan, synthetic_confidentiality_qualification
    )
    _match(COMMIT, commit, "release containment commit")
    _clean(root, "release repository")
    if _git_text(root, "rev-parse", "HEAD") != commit:
        raise ReleaseRemovalError("release checkout is not at the containment commit")
    parents = _git_text(root, "rev-list", "--parents", "-n", "1", commit).split()
    if parents != [commit, plan["base"]["commit"]]:
        raise ReleaseRemovalError("release containment commit is not a one-parent base child")
    expected, replacement = _expected_release_stage_from_base(root, plan)
    changed = set(
        _git(
            root, "diff-tree", "--no-commit-id", "--name-only", "-r", commit
        ).stdout.decode("utf-8").splitlines()
    )
    if changed != expected:
        raise ReleaseRemovalError("release containment commit changed unplanned paths")
    for path in expected:
        present = _git(root, "cat-file", "-e", f"{commit}:{path}", check=False)
        if path == "release-manifest.json" and replacement is not None:
            if present.returncode != 0 or _git(root, "show", f"{commit}:{path}").stdout != replacement:
                raise ReleaseRemovalError("containment commit manifest is not exact")
        elif present.returncode == 0:
            raise ReleaseRemovalError("containment commit retains a deleted path")
    tree = _git_text(root, "rev-parse", f"{commit}^{{tree}}")
    if synthetic_attestation is not None:
        marker = _git(
            root, "show", f"{commit}:{SYNTHETIC_FIXTURE_MARKER}", check=False
        )
        if marker.returncode != 0 or marker.stdout != SYNTHETIC_FIXTURE_BYTES:
            raise ReleaseRemovalError(
                "synthetic harmless-fixture marker did not survive containment"
            )
    result = {
        "schema_version": 1,
        "kind": "release_containment_binding",
        "visibility": "private",
        "incident_id": plan["incident_id"],
        "classification": plan["classification"],
        "base_commit": plan["base"]["commit"],
        "commit": commit,
        "tree": tree,
        "semantics": (
            "synthetic_target_tree_only"
            if plan["classification"] == "confidentiality_incident"
            else "forward_deletion"
        ),
        "synthetic_fixture_attestation": synthetic_attestation,
        "history_cleanup_verified": False,
        "live_refs_mutated": False,
    }
    if plan["classification"] == "confidentiality_incident":
        result.update(
            push_prohibited=True,
            remote_update_permitted=False,
            prohibition_reason="synthetic_target_tree_is_not_history_cleanup",
        )
    else:
        result.update(
            expected_remote_head=plan["base"]["commit"],
            ref="refs/heads/main",
            push_mode="non_forced_fast_forward_exact_base",
            push_prohibited=False,
            remote_update_permitted=True,
        )
    return result


def _identity_map(value: Any, subjects: list[str]) -> dict[str, dict[str, str]]:
    identities = value
    if not isinstance(identities, list) or len(identities) != len(subjects):
        raise ReleaseRemovalError("event identities do not cover the full incident")
    mapped: dict[str, dict[str, str]] = {}
    ordered_markers: list[tuple[str, str]] = []
    for item_value in identities:
        item = _object(item_value, "event identity")
        _fields(item, IDENTITY_FIELDS, "event identity")
        subject = _match(RESULT_ID, item["subject_id"], "event identity subject")
        _match(UUID7, item["event_id"], "release.removed event_id")
        occurred_at = parse_timestamp(
            item["occurred_at"], "release.removed occurred_at"
        )
        embedded_milliseconds = int(item["event_id"].replace("-", "")[:12], 16)
        if embedded_milliseconds != int(occurred_at.timestamp() * 1000):
            raise ReleaseRemovalError(
                "release.removed UUIDv7 timestamp differs from occurred_at"
            )
        if subject in mapped:
            raise ReleaseRemovalError("event identities repeat a subject")
        mapped[subject] = item
        ordered_markers.append((item["occurred_at"], item["event_id"]))
    if list(mapped) != subjects:
        raise ReleaseRemovalError("event identities are not in canonical subject order")
    if ordered_markers != sorted(set(ordered_markers)):
        raise ReleaseRemovalError("event identities are not unique and strictly ordered")
    return mapped


def complete_removal_events(
    plan_value: Any,
    release_root: pathlib.Path,
    release_commit: str,
    identities_value: Any,
    *,
    synthetic_confidentiality_qualification: bool = False,
) -> list[dict[str, Any]]:
    """Reverify release Git state, then complete every incident skeleton."""
    binding = verify_release_containment_commit(
        plan_value,
        release_root,
        release_commit,
        synthetic_confidentiality_qualification=(
            synthetic_confidentiality_qualification
        ),
    )
    events = _complete_removal_events_preverified(
        plan_value,
        binding,
        identities_value,
        synthetic_confidentiality_qualification=(
            synthetic_confidentiality_qualification
        ),
    )
    reverified = verify_release_containment_commit(
        plan_value,
        release_root,
        release_commit,
        synthetic_confidentiality_qualification=(
            synthetic_confidentiality_qualification
        ),
    )
    if reverified != binding:
        raise ReleaseRemovalError("release containment binding changed during State preparation")
    return events


def _complete_removal_events_preverified(
    plan_value: Any,
    release_binding_value: Any,
    identities_value: Any,
    *,
    synthetic_confidentiality_qualification: bool = False,
) -> list[dict[str, Any]]:
    """Complete every skeleton against one exact containment commit and tree."""
    plan = _validate_plan(plan_value)
    binding = _object(release_binding_value, "release containment binding")
    if (
        binding.get("kind") != "release_containment_binding"
        or binding.get("incident_id") != plan["incident_id"]
        or binding.get("classification") != plan["classification"]
        or binding.get("base_commit") != plan["base"]["commit"]
    ):
        raise ReleaseRemovalError("release containment binding differs from the plan")
    commit = _match(COMMIT, binding.get("commit"), "release containment commit")
    tree = _match(COMMIT, binding.get("tree"), "release containment tree")
    if plan["classification"] == "confidentiality_incident" and not synthetic_confidentiality_qualification:
        raise ReleaseRemovalError(
            "confidentiality correction requires approved real cleanup; "
            "the local target tree is synthetic semantics only"
        )
    if (
        plan["classification"] == "confidentiality_incident"
        and binding.get("synthetic_fixture_attestation")
        != _sha256(SYNTHETIC_FIXTURE_BYTES)
    ):
        raise ReleaseRemovalError(
            "synthetic confidentiality qualification requires the immutable harmless-fixture marker"
        )
    subjects = [item["subject_id"] for item in plan["required_state_corrections"]]
    identities = _identity_map(identities_value, subjects)
    planned_at = parse_timestamp(plan["planned_at"], "planned_at")
    if any(
        parse_timestamp(identity["occurred_at"], "release.removed occurred_at")
        < planned_at
        for identity in identities.values()
    ):
        raise ReleaseRemovalError("release.removed occurred before the reviewed plan")
    events = []
    for correction in plan["required_state_corrections"]:
        subject = correction["subject_id"]
        identity = identities[subject]
        event = {
            **correction["event_skeleton"],
            "event_id": identity["event_id"],
            "occurred_at": identity["occurred_at"],
            "payload": {
                **correction["fixed_payload_bindings"],
                "removal_repository_commit": commit,
                "removal_repository_tree": tree,
            },
        }
        if set(event) != EVENT_FIELDS or set(event["payload"]) != (
            STATE_REMOVAL_FIXED_PAYLOAD_FIELDS | STATE_REMOVAL_LATE_PAYLOAD_FIELDS
        ):
            raise ReleaseRemovalError("completed release.removed event is not closed")
        events.append(event)
    if len({event["payload"]["removal_repository_commit"] for event in events}) != 1 or len(
        {event["payload"]["removal_repository_tree"] for event in events}
    ) != 1:
        raise ReleaseRemovalError("incident corrections do not share one containment tree")
    return events


def _event_path(event_id: str) -> str:
    return f"events/{event_id.replace('-', '')[:2]}/{event_id}.json"


def _status_path(result_id: str) -> str:
    return f"views/result-release-status/{result_id[3:5]}/{result_id}.json"


def _current_status(root: pathlib.Path, head: str, event: dict[str, Any]) -> dict[str, Any]:
    path = _status_path(event["subject_id"])
    try:
        raw = _git(root, "show", f"{head}:{path}").stdout
        value = _object(json.loads(raw.decode("utf-8")), "current release status")
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseRemovalError("current release status is unreadable") from error
    _fields(value, STATUS_FIELDS, "current release status")
    if raw != _canonical_bytes(value):
        raise ReleaseRemovalError("current release status is not byte-canonical")
    revision = value["release_revision"]
    if (
        value["schema_version"] != 2
        or value["result_id"] != event["subject_id"]
        or value["status"] != "published"
        or value["release_event_id"] != event["causation_event_id"]
        or isinstance(revision, bool)
        or not isinstance(revision, int)
        or not 1 <= revision < 9_007_199_254_740_991
    ):
        raise ReleaseRemovalError("release.removed does not follow the exact published status")
    return value


def _next_status(current: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    return {
        **current,
        "status": "removed",
        "release_event_id": event["event_id"],
        "release_revision": current["release_revision"] + 1,
        "supersedes_release_event_id": current["release_event_id"],
    }


def _verify_state_contract(root: pathlib.Path, head: str, plan: dict[str, Any]) -> None:
    try:
        actual = _state_removal_contract(root, head)
    except Exception as error:
        raise ReleaseRemovalError("live State removal contract is not the reviewed contract") from error
    if actual != plan["state_contract"]:
        raise ReleaseRemovalError("State contract differs from the removal plan")


def _verify_published_state_events(
    root: pathlib.Path,
    protected_head: str,
    plan: dict[str, Any],
) -> None:
    for item in plan["published"]:
        commit = item["state_event_commit"]
        path = item["state_event_path"]
        ancestry = _git(
            root,
            "merge-base",
            "--is-ancestor",
            commit,
            protected_head,
            check=False,
        )
        if ancestry.returncode != 0:
            raise ReleaseRemovalError("published State event is not on protected main")
        blob = _git_text(root, "rev-parse", f"{commit}:{path}")
        raw = _git(root, "show", f"{commit}:{path}").stdout
        live_raw = _git(root, "show", f"{protected_head}:{path}").stdout
        try:
            event = _object(json.loads(raw.decode("utf-8")), "release.published event")
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ReleaseRemovalError("release.published State event is invalid") from error
        if (
            blob != item["state_event_blob"]
            or _sha256(raw) != item["state_event_sha256"]
            or live_raw != raw
            or event.get("event_id") != item["state_event_id"]
            or event.get("event_type") != "release.published"
            or event.get("subject_id") != item["result_id"]
            or event.get("actor") != {"kind": "system"}
            or event.get("payload")
            != {
                "attempt": event.get("payload", {}).get("attempt")
                if isinstance(event.get("payload"), dict)
                else None,
                "repository_commit": item["repository_commit"],
                "tree_digest": item["release_tree_sha256"],
                "path": item["release_path"],
            }
            or not isinstance(event["payload"]["attempt"], int)
            or isinstance(event["payload"]["attempt"], bool)
            or event["payload"]["attempt"] < 1
        ):
            raise ReleaseRemovalError("release.published State event binding changed")


def _run_state_tool(root: pathlib.Path, script: str, *arguments: str) -> None:
    environment = {
        key: os.environ[key]
        for key in ("PATH", "LANG", "LC_ALL")
        if key in os.environ
    }
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                EXACT_PYTHON_LAUNCHER,
                str(root / "scripts" / script),
                *arguments,
            ],
            cwd=root,
            check=True,
            capture_output=True,
            timeout=60,
            env=environment,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise ReleaseRemovalError(f"pinned State {script} qualification failed") from error


def _verify_materialized_statuses(
    root: pathlib.Path,
    protected_head: str,
    expected_statuses: dict[str, dict[str, Any]],
) -> tuple[str, str]:
    with tempfile.TemporaryDirectory(prefix="lean-eval-removal-views-") as directory:
        output = pathlib.Path(directory)
        _run_state_tool(
            root,
            "materialize_state.py",
            "--root",
            str(root),
            "--output",
            str(output),
            "--protected-main-commit",
            protected_head,
        )
        for path, expected in expected_statuses.items():
            actual = _read_regular(
                output / path, "materialized removal status", MAX_DOCUMENT_BYTES
            )
            if actual != _canonical_bytes(expected):
                raise ReleaseRemovalError("State materializer disagrees with a targeted status")
        queue_raw = _read_regular(
            output / "release-queue.json", "release queue", 64 * 1024 * 1024
        )
        try:
            queue = _object(json.loads(queue_raw.decode("utf-8")), "release queue")
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ReleaseRemovalError("materialized release queue is invalid") from error
        removed = {status["result_id"] for status in expected_statuses.values()}
        tasks = queue.get("tasks")
        if not isinstance(tasks, list) or any(
            isinstance(task, dict) and task.get("result_id") in removed for task in tasks
        ):
            raise ReleaseRemovalError("a removed result remains in the release queue")
        return _sha256(queue_raw), _sha256(
            b"".join(_canonical_bytes(expected_statuses[path]) for path in sorted(expected_statuses))
        )


def stage_state_corrections(
    plan_value: Any,
    release_root: pathlib.Path,
    release_commit: str,
    identities_value: Any,
    state_root: pathlib.Path,
    protected_state_head: str,
    *,
    synthetic_confidentiality_qualification: bool = False,
) -> dict[str, Any]:
    """Reverify release Git state, then stage one atomic State correction."""
    binding = verify_release_containment_commit(
        plan_value,
        release_root,
        release_commit,
        synthetic_confidentiality_qualification=(
            synthetic_confidentiality_qualification
        ),
    )
    staged = _stage_state_corrections_preverified(
        plan_value,
        binding,
        identities_value,
        state_root,
        protected_state_head,
        synthetic_confidentiality_qualification=(
            synthetic_confidentiality_qualification
        ),
    )
    reverified = verify_release_containment_commit(
        plan_value,
        release_root,
        release_commit,
        synthetic_confidentiality_qualification=(
            synthetic_confidentiality_qualification
        ),
    )
    if reverified != binding:
        raise ReleaseRemovalError("release containment binding changed during State staging")
    return staged


def _stage_state_corrections_preverified(
    plan_value: Any,
    release_binding_value: Any,
    identities_value: Any,
    state_root: pathlib.Path,
    protected_state_head: str,
    *,
    synthetic_confidentiality_qualification: bool = False,
) -> dict[str, Any]:
    """Stage every incident event and targeted status as one exact State diff."""
    plan = _validate_plan(plan_value)
    _publication_disabled()
    _match(COMMIT, protected_state_head, "protected State head")
    if plan["remote_main_commits"][EXPECTED_STATE_REPOSITORY] != protected_state_head:
        raise ReleaseRemovalError("protected State head differs from the removal plan")
    root = _repository(state_root, "State repository")
    try:
        _repository_root(root, EXPECTED_STATE_REPOSITORY)
    except Exception as error:
        raise ReleaseRemovalError("State repository origin is not exact upstream") from error
    _clean(root, "State repository")
    if _git_text(root, "rev-parse", "HEAD") != protected_state_head:
        raise ReleaseRemovalError("State checkout is not at the protected State head")
    _verify_state_contract(root, protected_state_head, plan)
    _verify_published_state_events(root, protected_state_head, plan)
    events = _complete_removal_events_preverified(
        plan,
        release_binding_value,
        identities_value,
        synthetic_confidentiality_qualification=synthetic_confidentiality_qualification,
    )
    expected_raw: dict[str, bytes] = {}
    statuses: dict[str, dict[str, Any]] = {}
    for event in events:
        event_path = _event_path(event["event_id"])
        if _git(root, "cat-file", "-e", f"{protected_state_head}:{event_path}", check=False).returncode == 0:
            raise ReleaseRemovalError("release.removed event identity already exists")
        current = _current_status(root, protected_state_head, event)
        status_path = _status_path(event["subject_id"])
        statuses[status_path] = _next_status(current, event)
        expected_raw[event_path] = _canonical_bytes(event)
        expected_raw[status_path] = _canonical_bytes(statuses[status_path])
    for path, raw in expected_raw.items():
        target = root.joinpath(*pathlib.PurePosixPath(path).parts)
        if path.startswith("events/"):
            if target.exists() or target.is_symlink():
                raise ReleaseRemovalError("release.removed event worktree path already exists")
            target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    _git(root, "add", "--", *sorted(expected_raw))
    _run_state_tool(
        root,
        "validate_state.py",
        "--root",
        str(root),
        "--protected-main-commit",
        protected_state_head,
    )
    queue_sha256, statuses_sha256 = _verify_materialized_statuses(
        root, protected_state_head, statuses
    )
    return _verify_staged_state_corrections_preverified(
        plan,
        release_binding_value,
        events,
        statuses,
        root,
        protected_state_head,
        queue_sha256=queue_sha256,
        statuses_sha256=statuses_sha256,
        synthetic_confidentiality_qualification=synthetic_confidentiality_qualification,
    )


def _verify_staged_state_corrections_preverified(
    plan_value: Any,
    release_binding_value: Any,
    events: list[dict[str, Any]],
    statuses: dict[str, dict[str, Any]],
    state_root: pathlib.Path,
    protected_state_head: str,
    *,
    queue_sha256: str,
    statuses_sha256: str,
    synthetic_confidentiality_qualification: bool = False,
) -> dict[str, Any]:
    plan = _validate_plan(plan_value)
    root = _repository(state_root, "State repository")
    if _git_text(root, "rev-parse", "HEAD") != protected_state_head:
        raise ReleaseRemovalError("State checkout moved while corrections were staged")
    expected_raw = {_event_path(event["event_id"]): _canonical_bytes(event) for event in events}
    expected_raw.update({path: _canonical_bytes(value) for path, value in statuses.items()})
    staged = set(
        _git(root, "diff", "--cached", "--name-only", "--").stdout.decode("utf-8").splitlines()
    )
    if staged != set(expected_raw):
        raise ReleaseRemovalError("State cached diff is not the complete incident group")
    for path, raw in expected_raw.items():
        if _git(root, "show", f":{path}").stdout != raw:
            raise ReleaseRemovalError("State cached bytes differ from the completed correction")
    if _git(root, "diff", "--name-only", "--", *sorted(expected_raw)).stdout:
        raise ReleaseRemovalError("State correction paths changed after staging")
    if (
        _git(root, "diff", "--name-only", "--").stdout
        or _git(root, "ls-files", "--others", "--exclude-standard").stdout
    ):
        raise ReleaseRemovalError("State repository has an unstaged or untracked change")
    binding = _object(release_binding_value, "release containment binding")
    synthetic = (
        plan["classification"] == "confidentiality_incident"
        and synthetic_confidentiality_qualification
    )
    result = {
        "schema_version": 1,
        "kind": "release_removal_state_stage",
        "visibility": "private",
        "incident_id": plan["incident_id"],
        "classification": plan["classification"],
        "protected_state_head": protected_state_head,
        "release_repository_commit": binding["commit"],
        "release_repository_tree": binding["tree"],
        "event_paths": sorted(path for path in expected_raw if path.startswith("events/")),
        "status_paths": sorted(statuses),
        "events_sha256": _sha256(
            b"".join(expected_raw[path] for path in sorted(expected_raw) if path.startswith("events/"))
        ),
        "statuses_sha256": statuses_sha256,
        "release_queue_sha256": queue_sha256,
        "staged_tree": _git_text(root, "write-tree"),
        "synthetic_confidentiality_qualification": synthetic,
        "results_repository_required": False,
        "live_refs_mutated": False,
    }
    if synthetic:
        result.update(
            push_prohibited=True,
            remote_update_permitted=False,
            prohibition_reason="synthetic_state_semantics_are_not_incident_evidence",
        )
    else:
        result.update(
            push_prohibited=False,
            remote_update_permitted=True,
        )
    return result


def _commit_changed_paths(root: pathlib.Path, commit: str) -> set[str]:
    return set(
        _git(
            root, "diff-tree", "--no-commit-id", "--name-only", "-r", commit
        ).stdout.decode("utf-8").splitlines()
    )


def _verify_state_precommit_scope(
    root: pathlib.Path, expected_paths: set[str]
) -> None:
    """Reject executable/worktree drift before invoking pinned State tools."""
    staged = set(
        _git(root, "diff", "--cached", "--name-only", "--")
        .stdout.decode("utf-8")
        .splitlines()
    )
    if staged != expected_paths:
        raise ReleaseRemovalError("State cached diff is not the complete incident group")
    if (
        _git(root, "diff", "--name-only", "--").stdout
        or _git(root, "ls-files", "--others", "--exclude-standard").stdout
    ):
        raise ReleaseRemovalError(
            "State repository has executable, unstaged, or untracked drift"
        )


def verify_cas_precondition(cas_plan_value: Any, observed_remote_head: str) -> None:
    """Fail unless a read-only remote observation matches one exact CAS plan."""
    plan = _object(cas_plan_value, "State CAS plan")
    if plan.get("kind") != "release_removal_state_cas":
        raise ReleaseRemovalError("State CAS plan kind is invalid")
    if plan.get("push_prohibited") is not False:
        raise ReleaseRemovalError("this State correction is explicitly push-prohibited")
    expected = _match(COMMIT, plan.get("expected_remote_head"), "expected remote head")
    observed = _match(COMMIT, observed_remote_head, "observed remote head")
    if observed != expected:
        raise ReleaseRemovalError(
            "protected State head changed; do not rebase or regenerate the correction"
        )


def finalize_state_corrections(
    plan_value: Any,
    release_root: pathlib.Path,
    release_commit: str,
    identities_value: Any,
    state_root: pathlib.Path,
    protected_state_head: str,
    *,
    message: str,
    synthetic_confidentiality_qualification: bool = False,
) -> dict[str, Any]:
    """Create or resume the one-commit State CAS without pushing it."""
    plan = _validate_plan(plan_value)
    _publication_disabled()
    _match(COMMIT, protected_state_head, "protected State head")
    if plan["remote_main_commits"][EXPECTED_STATE_REPOSITORY] != protected_state_head:
        raise ReleaseRemovalError("protected State head differs from the removal plan")
    release_binding = verify_release_containment_commit(
        plan,
        release_root,
        release_commit,
        synthetic_confidentiality_qualification=(
            synthetic_confidentiality_qualification
        ),
    )
    root = _repository(state_root, "State repository")
    try:
        _repository_root(root, EXPECTED_STATE_REPOSITORY)
    except Exception as error:
        raise ReleaseRemovalError("State repository origin is not exact upstream") from error
    _verify_state_contract(root, protected_state_head, plan)
    _verify_published_state_events(root, protected_state_head, plan)
    head = _git_text(root, "rev-parse", "HEAD")
    events = _complete_removal_events_preverified(
        plan,
        release_binding,
        identities_value,
        synthetic_confidentiality_qualification=synthetic_confidentiality_qualification,
    )
    expected_paths = {
        *(_event_path(event["event_id"]) for event in events),
        *(_status_path(event["subject_id"]) for event in events),
    }
    if head == protected_state_head:
        if _git(root, "diff", "--cached", "--name-only", "--").stdout:
            _verify_state_precommit_scope(root, expected_paths)
            statuses = {
                _status_path(event["subject_id"]): _next_status(
                    _current_status(root, protected_state_head, event), event
                )
                for event in events
            }
            _run_state_tool(
                root,
                "validate_state.py",
                "--root",
                str(root),
                "--protected-main-commit",
                protected_state_head,
            )
            queue_sha256, statuses_sha256 = _verify_materialized_statuses(
                root, protected_state_head, statuses
            )
            stage = _verify_staged_state_corrections_preverified(
                plan,
                release_binding,
                events,
                statuses,
                root,
                protected_state_head,
                queue_sha256=queue_sha256,
                statuses_sha256=statuses_sha256,
                synthetic_confidentiality_qualification=(
                    synthetic_confidentiality_qualification
                ),
            )
        else:
            stage = _stage_state_corrections_preverified(
                plan,
                release_binding,
                identities_value,
                root,
                protected_state_head,
                synthetic_confidentiality_qualification=(
                    synthetic_confidentiality_qualification
                ),
            )
        commit = _commit(root, message)
        if _git_text(root, "rev-parse", f"{commit}^{{tree}}") != stage["staged_tree"]:
            raise ReleaseRemovalError("State commit tree differs from the verified index")
        resumed = False
    else:
        commit = head
        resumed = True
    _clean(root, "State repository")
    parents = _git_text(root, "rev-list", "--parents", "-n", "1", commit).split()
    if parents != [commit, protected_state_head]:
        raise ReleaseRemovalError("State correction commit is not an exact protected-head child")
    if _commit_changed_paths(root, commit) != expected_paths:
        raise ReleaseRemovalError("State correction commit is not the atomic incident path set")
    for event in events:
        event_path = _event_path(event["event_id"])
        if _git(root, "show", f"{commit}:{event_path}").stdout != _canonical_bytes(event):
            raise ReleaseRemovalError("committed release.removed event is not exact")
        current = _current_status(root, protected_state_head, event)
        expected_status = _next_status(current, event)
        committed_status = _git(
            root, "show", f"{commit}:{_status_path(event['subject_id'])}"
        ).stdout
        if committed_status != _canonical_bytes(expected_status):
            raise ReleaseRemovalError("committed targeted release status is not exact")
    _run_state_tool(
        root,
        "validate_state.py",
        "--root",
        str(root),
        "--protected-main-commit",
        protected_state_head,
    )
    statuses = {
        _status_path(event["subject_id"]): _next_status(
            _current_status(root, protected_state_head, event), event
        )
        for event in events
    }
    queue_sha256, statuses_sha256 = _verify_materialized_statuses(
        root, protected_state_head, statuses
    )
    projection_sha256 = _qualify_public_projection(
        root, protected_state_head, commit, {event["subject_id"] for event in events}
    )
    binding = verify_release_containment_commit(
        plan,
        release_root,
        release_commit,
        synthetic_confidentiality_qualification=(
            synthetic_confidentiality_qualification
        ),
    )
    if binding != release_binding:
        raise ReleaseRemovalError(
            "release containment binding changed during State finalization"
        )
    result = {
        "schema_version": 1,
        "kind": "release_removal_state_cas",
        "visibility": "private",
        "incident_id": plan["incident_id"],
        "classification": plan["classification"],
        "commit": commit,
        "tree": _git_text(root, "rev-parse", f"{commit}^{{tree}}"),
        "release_repository_commit": binding["commit"],
        "release_repository_tree": binding["tree"],
        "event_paths": sorted(path for path in expected_paths if path.startswith("events/")),
        "status_paths": sorted(path for path in expected_paths if path.startswith("views/")),
        "release_queue_sha256": queue_sha256,
        "statuses_sha256": statuses_sha256,
        "public_projection_sha256": projection_sha256,
        "idempotent_resume": resumed,
        "synthetic_confidentiality_qualification": (
            plan["classification"] == "confidentiality_incident"
            and synthetic_confidentiality_qualification
        ),
        "results_repository_required": False,
        "live_refs_mutated": False,
    }
    if result["synthetic_confidentiality_qualification"]:
        result.update(
            push_prohibited=True,
            remote_update_permitted=False,
            prohibition_reason="synthetic_state_semantics_are_not_incident_evidence",
        )
    else:
        result.update(
            expected_remote_head=protected_state_head,
            ref="refs/heads/main",
            push_mode="non_forced_fast_forward_exact_base",
            push_prohibited=False,
            remote_update_permitted=True,
        )
    return result


def _qualify_public_projection(
    root: pathlib.Path,
    protected_head: str,
    state_commit: str,
    removed_subjects: set[str],
) -> str:
    with tempfile.TemporaryDirectory(prefix="lean-eval-removal-public-") as directory:
        output = pathlib.Path(directory) / "public-v5.json"
        _run_state_tool(
            root,
            "public_projection.py",
            "--root",
            str(root),
            "--state-commit",
            state_commit,
            "--schema-version",
            "5",
            "--protected-main-commit",
            protected_head,
            "--output",
            str(output),
        )
        raw = _read_regular(output, "public removal projection", 64 * 1024 * 1024)
        try:
            projection = _object(json.loads(raw.decode("utf-8")), "public projection")
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ReleaseRemovalError("public removal projection is invalid") from error
        results = projection.get("results")
        if not isinstance(results, list):
            raise ReleaseRemovalError("public projection has no result list")
        by_id = {
            item.get("result_id"): item
            for item in results
            if isinstance(item, dict) and isinstance(item.get("result_id"), str)
        }
        for subject in removed_subjects:
            item = by_id.get(subject)
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("release"), dict)
                or item["release"].get("status") != "removed"
                or item.get("public_solution") != {"available": False, "url": None}
            ):
                raise ReleaseRemovalError("public projection does not hide a removed solution")
        encoded = json.dumps(
            {subject: by_id[subject] for subject in sorted(removed_subjects)},
            ensure_ascii=True,
            sort_keys=True,
        )
        for private_name in (
            "incident_id",
            "evidence_repository",
            "published_state_event_commit",
            "bundle_sha256",
        ):
            if private_name in encoded:
                raise ReleaseRemovalError("public projection exposes private removal evidence")
        return _sha256(raw)


def _read_input(path: pathlib.Path, label: str, maximum: int) -> Any:
    return _parse_json_file(path.resolve(strict=True), label, maximum)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    release = commands.add_parser("finalize-release")
    release.add_argument("plan", type=pathlib.Path)
    release.add_argument("--release-root", type=pathlib.Path, required=True)
    release.add_argument("--message", required=True)
    release.add_argument("--output", type=pathlib.Path, required=True)
    release.add_argument("--synthetic-confidentiality-qualification", action="store_true")
    state = commands.add_parser("finalize-state")
    state.add_argument("plan", type=pathlib.Path)
    state.add_argument("--release-root", type=pathlib.Path, required=True)
    state.add_argument("--release-commit", required=True)
    state.add_argument("--state-root", type=pathlib.Path, required=True)
    state.add_argument("--protected-state-head", required=True)
    state.add_argument("--event-identities", type=pathlib.Path, required=True)
    state.add_argument("--message", required=True)
    state.add_argument("--output", type=pathlib.Path, required=True)
    state.add_argument("--synthetic-confidentiality-qualification", action="store_true")
    args = parser.parse_args(argv)
    try:
        plan = _read_input(args.plan, "private removal plan", MAX_PLAN_BYTES)
        if args.command == "finalize-release":
            result = finalize_release_containment(
                plan,
                args.release_root,
                message=args.message,
                synthetic_confidentiality_qualification=(
                    args.synthetic_confidentiality_qualification
                ),
            )
            _write_exclusive(
                args.output,
                result,
                [args.release_root],
                0o600,
            )
        else:
            identities = _read_input(
                args.event_identities, "release.removed identities", MAX_IDENTITIES_BYTES
            )
            result = finalize_state_corrections(
                plan,
                args.release_root,
                args.release_commit,
                identities,
                args.state_root,
                args.protected_state_head,
                message=args.message,
                synthetic_confidentiality_qualification=(
                    args.synthetic_confidentiality_qualification
                ),
            )
            _write_exclusive(
                args.output,
                result,
                [args.release_root, args.state_root],
                0o600,
            )
    except (OSError, ReleaseRemovalError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
