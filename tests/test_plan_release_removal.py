from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "scripts"))

import plan_release_removal as removal_module
from plan_release_removal import (
    MAX_DOCUMENT_BYTES,
    MAX_PLAN_OUTPUT_BYTES,
    MAX_SHARED_RELEASE_PATHS,
    RELEASE_PATH,
    RemovalPlanError,
    _blob,
    _git,
    _git_environment,
    _read_regular,
    _write_exclusive,
    main,
    plan_removal,
    public_projection,
)
from release_tree import tree_digest


RESULT_1 = "r2_" + "4" * 64
RESULT_2 = "r2_" + "6" * 64
SUBMISSION_ID = "01a157eb-ab28-7001-8203-040506070809"
EVENT_1 = "01a157eb-ab28-7001-9203-040506070809"
EVENT_2 = "01a157eb-ab28-7001-9303-040506070809"
CAUSE_1 = "01a157eb-ab28-7001-a203-040506070809"
CAUSE_2 = "01a157eb-ab28-7001-a303-040506070809"
INCIDENT_ID = "01a157eb-ab28-7001-b203-040506070809"
BUNDLE_PATH = f"sources/{SUBMISSION_ID}.tar.gz"
EVIDENCE_PATH = f"incidents/{INCIDENT_ID}.json"
RELEASE_REPOSITORY = "leanprover/lean-eval-releases"
STATE_REPOSITORY = "leanprover/lean-eval-state"
SECRET_MARKER = b"private-source-must-not-enter-the-plan"


class ReleaseRemovalPlanTests(unittest.TestCase):
    def test_pinned_state_contract_manifest_is_exact(self) -> None:
        self.assertEqual(
            removal_module.STATE_REMOVAL_CONTRACT_COMMIT,
            "6799522f7fe57263de4a66499e52ce4bfda69baa",
        )
        self.assertEqual(
            removal_module.STATE_REMOVAL_CONTRACT_TREES,
            {
                "schema": "3043a7b6afa042577645e0520ee9bd105a15424a",
                "scripts": "4e2c39cac2510716577a7fd6d13abf0f9cf26976",
            },
        )
        self.assertEqual(
            removal_module.STATE_REMOVAL_CONTRACT_COMPONENTS,
            {
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
                    "151d2de843c963efb5057a3e26cb6fd65f446312",
                    "73598fb935b14ce9e9a02a1d49ee443f8f18b1fe9ed9d13e069ecb8fa2b8ab73",
                ),
                "schema/result-overlays-v1.schema.json": (
                    "100644",
                    "41d4078133d6854bf8de839873a3f58e9ba1afd1",
                    "245324f32265d0476ca45e55ec5fbe2363c47da852d2641ddc292df0c5d9d474",
                ),
                "scripts/materialize_state.py": (
                    "100755",
                    "3bc4af9360aa3199391bb29790a21755ba62d842",
                    "c5b26fab538b4b0920d20246d1821c2995a439e8c543e5c68de9a80487dbe6d5",
                ),
                "scripts/public_projection.py": (
                    "100755",
                    "ff0940d0117c7783ef3c5d868247b8ef4bef9418",
                    "2391e7574faff98763b2e8d60370f76876e8062eea5e1848a2d6a98579a0727b",
                ),
                "scripts/state.py": (
                    "100644",
                    "9812adf2ab40b8b8072a1cbe32e66d072844d596",
                    "95695b4c9a4c34e5380f08c97c35547d7d7a87f4d37e7a024bbbc932d3c5d99c",
                ),
                "scripts/validate_state.py": (
                    "100755",
                    "19b4801ca6b7d9edc4f43d9e55bc86a6b24ac315",
                    "07d19fc4d30222cd0bbeccd246397737203301fa79e748bb6a2ac041c510c6f7",
                ),
            },
        )

    def git(self, root: pathlib.Path, *arguments: str) -> str:
        environment = {
            **os.environ,
            "GIT_AUTHOR_DATE": "2026-10-20T06:07:05Z",
            "GIT_COMMITTER_DATE": "2026-10-20T06:07:05Z",
        }
        return subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
        ).stdout.strip()

    @staticmethod
    def git_bytes(root: pathlib.Path, *arguments: str) -> bytes:
        return subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout

    def init_repository(self, root: pathlib.Path, repository: str) -> None:
        root.mkdir()
        self.git(root, "init", "--initial-branch=main")
        self.git(root, "config", "user.name", "release-test")
        self.git(root, "config", "user.email", "release-test@example.invalid")
        self.git(root, "remote", "add", "origin", f"https://github.com/{repository}.git")
        self.git(root, "commit", "--allow-empty", "-m", "Initialize repository")

    @staticmethod
    def canonical(value: object) -> bytes:
        return (
            json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")

    @staticmethod
    def removal_schema() -> dict[str, object]:
        fixed = removal_module.STATE_REMOVAL_FIXED_PAYLOAD_FIELDS
        late = removal_module.STATE_REMOVAL_LATE_PAYLOAD_FIELDS
        payload_properties = {field: {} for field in fixed | late}
        payload_properties["release_path"] = {"$ref": "#/$defs/releasePath"}
        payload_properties["shared_release_paths"] = {
            "type": "array",
            "maxItems": removal_module.MAX_SHARED_RELEASE_PATHS,
            "uniqueItems": True,
            "items": {"$ref": "#/$defs/releasePath"},
        }
        return {
            "$defs": {
                "releasePath": {
                    "type": "string",
                    "pattern": f"^{removal_module.RELEASE_PATH.pattern}$",
                }
            },
            "type": "object",
            "additionalProperties": False,
            "required": sorted(removal_module.EVENT_FIELDS),
            "properties": {
                field: {} for field in removal_module.EVENT_FIELDS
            },
            "allOf": [{
                "if": {
                    "properties": {
                        "event_type": {"const": "release.removed"}
                    }
                },
                "then": {
                    "properties": {
                        "actor": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["kind"],
                            "properties": {"kind": {"const": "system"}},
                        },
                        "payload": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": sorted(fixed | late),
                            "properties": payload_properties,
                        },
                    }
                },
            }],
        }

    def write_json(self, path: pathlib.Path, value: object) -> bytes:
        raw = self.canonical(value)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return raw

    @staticmethod
    def release_path(result_id: str) -> str:
        return f"releases/2026/10/{result_id}"

    def metadata(self, result_id: str) -> dict[str, object]:
        return {
            "schema_version": 1,
            "generated_at": "2026-10-20T06:07:05.000Z",
            "result": {
                "result_id": result_id,
                "problem_id": "Demo",
                "statement_revision": 1,
                "commit": "7" * 40,
                "tree_digest": "8" * 64,
            },
            "submission": {
                "submission_id": SUBMISSION_ID,
                "owner_login": "alice",
                "declared_model": "Example Model",
                "production_metadata": {},
            },
            "archive": {
                "archive_repository": "leanprover/lean-eval-audit",
                "archive_commit": "9" * 40,
                "archive_path": f"archives/01/{SUBMISSION_ID}.tar.age",
                "archive_ciphertext_sha256": "a" * 64,
                "encrypted": True,
            },
            "release": {
                "accepted_at": "2026-08-20T06:07:05.000Z",
                "eligible_at": "2026-10-20T06:07:05.000Z",
                "path": self.release_path(result_id),
                "license": "Apache-2.0",
            },
            "source_files": [
                {"path": "Submission.lean", "size_bytes": 45, "sha256": "b" * 64}
            ],
        }

    def add_release(self, root: pathlib.Path, result_id: str) -> tuple[str, dict[str, object]]:
        release = root.joinpath(*self.release_path(result_id).split("/"))
        (release / "Submission").mkdir(parents=True)
        (release / "Submission.lean").write_text(
            "import Mathlib\nexample : True := by trivial\n", encoding="utf-8"
        )
        (release / "Submission" / "Helper.lean").write_text(
            "def helper : Nat := 4\n", encoding="utf-8"
        )
        (release / "LICENSE").write_text("Apache-2.0 fixture\n", encoding="utf-8")
        metadata = self.metadata(result_id)
        self.write_json(release / "metadata.json", metadata)
        return tree_digest(release), metadata

    def entry(
        self,
        result_id: str,
        release_digest: str,
        bundle_digest: str,
        metadata: dict[str, object],
    ) -> dict[str, object]:
        archive = metadata["archive"]
        release = metadata["release"]
        return {
            "result_id": result_id,
            "submission_id": SUBMISSION_ID,
            "accepted_at": release["accepted_at"],
            "eligible_at": release["eligible_at"],
            "archive_repository": archive["archive_repository"],
            "archive_commit": archive["archive_commit"],
            "archive_path": archive["archive_path"],
            "archive_ciphertext_sha256": archive["archive_ciphertext_sha256"],
            "bundle_sha256": bundle_digest,
            "bundle_path": BUNDLE_PATH,
            "release_tree_sha256": release_digest,
            "release_path": self.release_path(result_id),
            "license": "Apache-2.0",
        }

    def event(
        self, result_id: str, event_id: str, cause_id: str, release_commit: str,
        release_digest: str,
    ) -> dict[str, object]:
        return {
            "schema_version": 1,
            "event_id": event_id,
            "event_type": "release.published",
            "occurred_at": "2026-10-20T06:07:06.000Z",
            "subject_id": result_id,
            "causation_event_id": cause_id,
            "actor": {"kind": "system"},
            "payload": {
                "attempt": 1,
                "repository_commit": release_commit,
                "tree_digest": release_digest,
                "path": self.release_path(result_id),
            },
        }

    def fixture(
        self,
        parent: pathlib.Path,
        *,
        results: tuple[str, ...] = (RESULT_1,),
        mutate_entry: Callable[[str, dict[str, object]], None] | None = None,
        mutate_metadata: Callable[[str, dict[str, object]], None] | None = None,
    ) -> dict[str, object]:
        release_root = parent / "releases"
        state_root = parent / "state"
        self.init_repository(release_root, RELEASE_REPOSITORY)
        self.init_repository(state_root, STATE_REPOSITORY)

        state_initial_commit = self.git(state_root, "rev-parse", "HEAD")
        state_contract_raw: dict[str, bytes] = {}
        for path, (mode, _blob_oid, _sha256) in (
            removal_module.STATE_REMOVAL_CONTRACT_COMPONENTS.items()
        ):
            state_contract_raw[path] = self.write_json(
                state_root / path,
                self.removal_schema()
                if path == "schema/state-event-v1.schema.json"
                else {"fixture_component": path},
            )
            if mode == "100755":
                (state_root / path).chmod(0o755)
        self.git(state_root, "add", ".")
        self.git(state_root, "commit", "-m", "Add release removal contract")
        state_contract_commit = self.git(state_root, "rev-parse", "HEAD")
        state_contract_components = {
            path: (
                self.git(
                    state_root,
                    "ls-tree",
                    state_contract_commit,
                    "--",
                    path,
                ).split()[0],
                self.git(state_root, "rev-parse", f"{state_contract_commit}:{path}"),
                hashlib.sha256(raw).hexdigest(),
            )
            for path, raw in state_contract_raw.items()
        }
        state_contract_trees = {
            path: self.git(state_root, "rev-parse", f"{state_contract_commit}:{path}")
            for path in removal_module.STATE_REMOVAL_CONTRACT_TREES
        }

        bundle = release_root.joinpath(*BUNDLE_PATH.split("/"))
        bundle.parent.mkdir()
        bundle.write_bytes(b"deterministic-gzip-fixture\0" + SECRET_MARKER)
        bundle_digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
        release_digests: dict[str, str] = {}
        entries: list[dict[str, object]] = []
        for result_id in results:
            release_digest, metadata = self.add_release(release_root, result_id)
            if mutate_metadata is not None:
                mutate_metadata(result_id, metadata)
                self.write_json(
                    release_root / self.release_path(result_id) / "metadata.json", metadata
                )
                release_digest = tree_digest(release_root / self.release_path(result_id))
            release_digests[result_id] = release_digest
            entry = self.entry(result_id, release_digest, bundle_digest, metadata)
            if mutate_entry is not None:
                mutate_entry(result_id, entry)
            entries.append(entry)
        manifest = {
            "schema_version": 1,
            "release_id": "lean-eval-2026-10-20",
            "generated_at": "2026-10-20T06:07:05.000Z",
            "entries": entries,
        }
        self.write_json(release_root / "release-manifest.json", manifest)
        self.git(release_root, "add", ".")
        self.git(release_root, "commit", "-m", "Publish delayed source")
        release_commit = self.git(release_root, "rev-parse", "HEAD")

        event_specs = [
            (RESULT_1, EVENT_1, CAUSE_1),
            (RESULT_2, EVENT_2, CAUSE_2),
        ]
        event_locators = []
        for result_id, event_id, cause_id in event_specs:
            if result_id not in results:
                continue
            value = self.event(
                result_id, event_id, cause_id, release_commit,
                release_digests[result_id],
            )
            path = f"events/{event_id.replace('-', '')[:2]}/{event_id}.json"
            raw = self.write_json(state_root / path, value)
            event_locators.append({
                "repository": STATE_REPOSITORY,
                "path": path,
                "sha256": hashlib.sha256(raw).hexdigest(),
            })
        evidence_raw = self.write_json(
            state_root / EVIDENCE_PATH,
            {"private_case": "operator-reviewed; source omitted"},
        )
        self.git(state_root, "add", ".")
        self.git(state_root, "commit", "-m", "Record publication and incident evidence")
        state_commit = self.git(state_root, "rev-parse", "HEAD")
        for locator in event_locators:
            locator["commit"] = state_commit
        event_locators.sort(key=lambda item: (item["repository"], item["commit"], item["path"]))
        request = {
            "schema_version": 1,
            "incident_id": INCIDENT_ID,
            "planned_at": "2026-10-20T06:08:00.000Z",
            "classification": "erroneous_publication",
            "release_repository": RELEASE_REPOSITORY,
            "base_commit": release_commit,
            "published_events": event_locators,
            "evidence": {
                "repository": STATE_REPOSITORY,
                "commit": state_commit,
                "path": EVIDENCE_PATH,
                "sha256": hashlib.sha256(evidence_raw).hexdigest(),
            },
        }
        return {
            "release_root": release_root,
            "state_root": state_root,
            "request": request,
            "release_commit": release_commit,
            "state_commit": state_commit,
            "state_initial_commit": state_initial_commit,
            "state_contract_commit": state_contract_commit,
            "state_contract_trees": state_contract_trees,
            "state_contract_components": state_contract_components,
            "evidence_raw": evidence_raw,
        }

    def contract_patch(self, fixture: dict[str, object]):
        return mock.patch.multiple(
            removal_module,
            STATE_REMOVAL_CONTRACT_COMMIT=fixture["state_contract_commit"],
            STATE_REMOVAL_CONTRACT_TREES=fixture["state_contract_trees"],
            STATE_REMOVAL_CONTRACT_COMPONENTS=fixture["state_contract_components"],
        )

    def rebind_contract(self, fixture: dict[str, object]) -> None:
        commit = self.git(fixture["state_root"], "rev-parse", "HEAD")
        fixture["state_contract_commit"] = commit
        fixture["state_commit"] = commit
        fixture["state_contract_trees"] = {
            directory: self.git(
                fixture["state_root"], "rev-parse", f"{commit}:{directory}"
            )
            for directory in removal_module.STATE_REMOVAL_CONTRACT_TREES
        }
        fixture["state_contract_components"] = {
            component: (
                self.git(
                    fixture["state_root"],
                    "ls-tree",
                    commit,
                    "--",
                    component,
                ).split()[0],
                self.git(
                    fixture["state_root"], "rev-parse", f"{commit}:{component}"
                ),
                hashlib.sha256(
                    self.git_bytes(
                        fixture["state_root"], "show", f"{commit}:{component}"
                    )
                ).hexdigest(),
            )
            for component in removal_module.STATE_REMOVAL_CONTRACT_COMPONENTS
        }

    def call_plan(self, fixture: dict[str, object]) -> dict[str, object]:
        return plan_removal(
            repository_root=fixture["release_root"],
            state_repository_roots={STATE_REPOSITORY: fixture["state_root"]},
            evidence_repository_root=fixture["state_root"],
            request_value=copy.deepcopy(fixture["request"]),
            remote_main_commits={
                RELEASE_REPOSITORY: fixture["release_commit"],
                STATE_REPOSITORY: fixture["state_commit"],
            },
        )

    def plan(self, fixture: dict[str, object]) -> dict[str, object]:
        with self.contract_patch(fixture):
            return self.call_plan(fixture)

    def test_plan_is_exact_private_deterministic_source_free_and_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            release_head = self.git(fixture["release_root"], "rev-parse", "HEAD")
            state_head = self.git(fixture["state_root"], "rev-parse", "HEAD")
            plans = [self.plan(fixture), self.plan(fixture)]
            self.assertEqual(plans[0], plans[1])
            plan = plans[0]
            self.assertEqual(plan["visibility"], "private")
            self.assertEqual(plan["published"][0]["state_event_commit"], state_head)
            self.assertRegex(plan["published"][0]["state_event_blob"], r"^[0-9a-f]{40}$")
            self.assertRegex(plan["evidence"]["blob"], r"^[0-9a-f]{40}$")
            self.assertEqual(plan["containment"]["manifest"]["action"], "delete")
            self.assertEqual(len(plan["required_state_corrections"]), 1)
            correction = plan["required_state_corrections"][0]
            self.assertEqual(correction["status"], "ready_after_containment")
            self.assertEqual(correction["required_event_type"], "release.removed")
            self.assertEqual(
                set(correction["fixed_payload_bindings"]),
                {
                    "incident_id",
                    "classification",
                    "published_state_event_repository",
                    "published_state_event_commit",
                    "published_state_event_path",
                    "published_state_event_blob",
                    "published_state_event_sha256",
                    "published_repository_commit",
                    "published_repository_tree",
                    "published_release_tree_sha256",
                    "release_path",
                    "bundle_path",
                    "bundle_sha256",
                    "bundle_disposition",
                    "shared_release_paths",
                    "evidence_repository",
                    "evidence_commit",
                    "evidence_path",
                    "evidence_blob",
                    "evidence_sha256",
                },
            )
            self.assertEqual(
                correction["fixed_payload_bindings"]["incident_id"], INCIDENT_ID
            )
            self.assertEqual(
                correction["event_skeleton"],
                {
                    "schema_version": 1,
                    "event_type": "release.removed",
                    "subject_id": RESULT_1,
                    "causation_event_id": EVENT_1,
                    "actor": {"kind": "system"},
                    "payload": correction["fixed_payload_bindings"],
                },
            )
            self.assertEqual(
                correction["required_after_containment"],
                [
                    "event_id",
                    "occurred_at",
                    "payload.removal_repository_commit",
                    "payload.removal_repository_tree",
                ],
            )
            self.assertEqual(
                plan["state_contract"],
                {
                    "repository": STATE_REPOSITORY,
                    "commit": fixture["state_contract_commit"],
                    "event_type": "release.removed",
                    "trees": [
                        {"path": path, "tree": tree}
                        for path, tree in sorted(
                            fixture["state_contract_trees"].items()
                        )
                    ],
                    "components": [
                        {
                            "path": path,
                            "blob": blob,
                            "sha256": sha256,
                        }
                        for path, (_mode, blob, sha256) in sorted(
                            fixture["state_contract_components"].items()
                        )
                    ],
                },
            )
            encoded = json.dumps(plan, sort_keys=True).encode("utf-8")
            self.assertNotIn(SECRET_MARKER, encoded)
            self.assertNotIn(fixture["evidence_raw"].strip(), encoded)
            self.assertEqual(self.git(fixture["release_root"], "rev-parse", "HEAD"), release_head)
            self.assertEqual(self.git(fixture["state_root"], "rev-parse", "HEAD"), state_head)
            self.assertEqual(self.git(fixture["release_root"], "status", "--porcelain"), "")
            self.assertEqual(self.git(fixture["state_root"], "status", "--porcelain"), "")

    def test_public_projection_redacts_state_and_evidence_locators(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan = self.plan(self.fixture(pathlib.Path(temporary)))
            projection = public_projection(plan)
            encoded = json.dumps(projection, sort_keys=True)
            self.assertEqual(projection["visibility"], "public")
            self.assertNotIn("evidence", encoded)
            self.assertNotIn("state_event", encoded)
            self.assertNotIn(STATE_REPOSITORY, encoded)
            self.assertEqual(
                projection["state_correction_status"], "ready_after_containment"
            )

    def test_confidentiality_incident_cannot_produce_any_public_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            fixture = self.fixture(parent)
            fixture["request"]["classification"] = "confidentiality_incident"
            plan = self.plan(fixture)
            with self.assertRaisesRegex(RemovalPlanError, "cannot produce"):
                public_projection(plan)

            request_path = parent / "request.json"
            request_path.write_bytes(self.canonical(fixture["request"]))
            private_path = parent / "private.json"
            public_path = parent / "public.json"
            with self.contract_patch(fixture), mock.patch(
                "plan_release_removal._remote_main",
                side_effect=lambda repository: {
                    RELEASE_REPOSITORY: fixture["release_commit"],
                    STATE_REPOSITORY: fixture["state_commit"],
                }[repository],
            ), mock.patch("sys.stderr"):
                self.assertEqual(
                    main([
                        str(request_path),
                        "--repository-root", str(fixture["release_root"]),
                        "--state-repository-root", str(fixture["state_root"]),
                        "--evidence-repository-root", str(fixture["state_root"]),
                        "--output", str(private_path),
                        "--public-output", str(public_path),
                    ]),
                    1,
                )
            self.assertFalse(private_path.exists())
            self.assertFalse(public_path.exists())

    def test_rejects_local_head_or_state_commit_not_on_remote_main(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            release_parent = self.git(fixture["release_root"], "rev-parse", "HEAD^")
            with self.contract_patch(fixture), self.assertRaisesRegex(
                RemovalPlanError, "remote protected main"
            ):
                self.call_plan({
                    **fixture,
                    "release_commit": release_parent,
                })

            self.git(fixture["state_root"], "checkout", "--orphan", "unrelated")
            (fixture["state_root"] / "unrelated").write_text("x", encoding="utf-8")
            self.git(fixture["state_root"], "add", "unrelated")
            self.git(fixture["state_root"], "commit", "-m", "Unrelated remote head")
            unrelated = self.git(fixture["state_root"], "rev-parse", "HEAD")
            self.git(fixture["state_root"], "checkout", "main")
            with self.contract_patch(fixture), self.assertRaisesRegex(
                RemovalPlanError, "ancestry"
            ):
                plan_removal(
                    repository_root=fixture["release_root"],
                    state_repository_roots={STATE_REPOSITORY: fixture["state_root"]},
                    evidence_repository_root=fixture["state_root"],
                    request_value=fixture["request"],
                    remote_main_commits={
                        RELEASE_REPOSITORY: fixture["release_commit"],
                        STATE_REPOSITORY: unrelated,
                    },
                )

    def test_rejects_unreviewed_or_tampered_state_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            tampered = dict(fixture["state_contract_components"])
            first_path = sorted(tampered)[0]
            tampered[first_path] = (
                tampered[first_path][0],
                tampered[first_path][1],
                "0" * 64,
            )
            with self.contract_patch(fixture), mock.patch.object(
                removal_module, "STATE_REMOVAL_CONTRACT_COMPONENTS", tampered
            ), self.assertRaisesRegex(RemovalPlanError, "reviewed contract"):
                self.call_plan(fixture)

            mode_tampered = dict(fixture["state_contract_components"])
            executable = "scripts/materialize_state.py"
            _mode, blob, sha256 = mode_tampered[executable]
            mode_tampered[executable] = ("100644", blob, sha256)
            with self.contract_patch(fixture), mock.patch.object(
                removal_module,
                "STATE_REMOVAL_CONTRACT_COMPONENTS",
                mode_tampered,
            ), self.assertRaisesRegex(RemovalPlanError, "mode-100644"):
                self.call_plan(fixture)

            with self.contract_patch(fixture), self.assertRaisesRegex(
                RemovalPlanError, "ancestry"
            ):
                plan_removal(
                    repository_root=fixture["release_root"],
                    state_repository_roots={STATE_REPOSITORY: fixture["state_root"]},
                    evidence_repository_root=fixture["state_root"],
                    request_value=fixture["request"],
                    remote_main_commits={
                        RELEASE_REPOSITORY: fixture["release_commit"],
                        STATE_REPOSITORY: fixture["state_initial_commit"],
                    },
                )

    def test_rejects_effective_live_contract_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            path = sorted(fixture["state_contract_components"])[0]
            self.write_json(fixture["state_root"] / path, {"drifted": True})
            self.git(fixture["state_root"], "add", path)
            self.git(fixture["state_root"], "commit", "-m", "Drift contract")
            fixture["state_commit"] = self.git(
                fixture["state_root"], "rev-parse", "HEAD"
            )
            with self.assertRaisesRegex(RemovalPlanError, "has drifted"):
                self.plan(fixture)

    def test_rejects_digest_pinned_schema_shape_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            path = "schema/state-event-v1.schema.json"
            schema = self.removal_schema()
            branch = schema["allOf"][0]
            branch["then"]["properties"]["payload"]["properties"][
                "shared_release_paths"
            ]["maxItems"] = 127
            self.write_json(fixture["state_root"] / path, schema)
            self.git(fixture["state_root"], "add", path)
            self.git(fixture["state_root"], "commit", "-m", "Pin incompatible schema")
            self.rebind_contract(fixture)
            with self.assertRaisesRegex(RemovalPlanError, "shared paths schema"):
                self.plan(fixture)

    def test_state_schema_path_and_cardinality_constraints_are_mirrored(self) -> None:
        self.assertEqual(MAX_SHARED_RELEASE_PATHS, 128)
        for month in ("01", "12"):
            self.assertIsNotNone(
                RELEASE_PATH.fullmatch(f"releases/2026/{month}/{RESULT_1}")
            )
        for month in ("00", "13", "99"):
            self.assertIsNone(
                RELEASE_PATH.fullmatch(f"releases/2026/{month}/{RESULT_1}")
            )

        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(
                pathlib.Path(temporary), results=(RESULT_1, RESULT_2)
            )
            fixture["request"]["published_events"] = [
                fixture["request"]["published_events"][0]
            ]
            path = fixture["state_root"] / "schema/state-event-v1.schema.json"
            schema = json.loads(path.read_text(encoding="utf-8"))
            schema["allOf"][0]["then"]["properties"]["payload"]["properties"][
                "shared_release_paths"
            ]["maxItems"] = 0
            self.write_json(path, schema)
            self.git(
                fixture["state_root"], "add", "schema/state-event-v1.schema.json"
            )
            self.git(fixture["state_root"], "commit", "-m", "Use zero shared paths")
            self.rebind_contract(fixture)
            with (
                mock.patch.object(removal_module, "MAX_SHARED_RELEASE_PATHS", 0),
                self.assertRaisesRegex(RemovalPlanError, "exceeds"),
            ):
                self.plan(fixture)

    def test_rejects_event_and_evidence_locator_forgery(self) -> None:
        mutations = (
            lambda request: request["published_events"][0].update(path="events/01/wrong.json"),
            lambda request: request["published_events"][0].update(sha256="0" * 64),
            lambda request: request["evidence"].update(path="incidents/missing.json"),
            lambda request: request["evidence"].update(sha256="0" * 64),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as temporary:
                fixture = self.fixture(pathlib.Path(temporary))
                mutate(fixture["request"])
                with self.assertRaises(RemovalPlanError):
                    self.plan(fixture)

    def test_rejects_bundle_submission_and_archive_metadata_mismatch(self) -> None:
        other_submission = "01a157eb-ab28-7001-8203-040506070810"
        mutations = (
            lambda _result, entry: entry.update(
                bundle_path=f"sources/{other_submission}.tar.gz"
            ),
            lambda _result, entry: entry.update(
                archive_path=f"archives/01/{other_submission}.tar.age"
            ),
            lambda _result, entry: entry.update(archive_commit="d" * 40),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as temporary:
                fixture = self.fixture(pathlib.Path(temporary), mutate_entry=mutate)
                with self.assertRaises(RemovalPlanError):
                    self.plan(fixture)

    def test_equal_multi_entry_manifest_removes_only_incident_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary), results=(RESULT_1, RESULT_2))
            fixture["request"]["published_events"] = [
                fixture["request"]["published_events"][0]
            ]
            plan = self.plan(fixture)
            action = plan["containment"]["manifest"]
            self.assertEqual(action["action"], "remove_incident_entries")
            self.assertEqual(action["removed_result_ids"], [RESULT_1])
            self.assertEqual(action["remaining_entry_count"], 1)
            self.assertEqual(plan["containment"]["bundles"][0]["action"], "retain_shared")

    def test_confidential_shared_bundle_requires_and_accepts_complete_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary), results=(RESULT_1, RESULT_2))
            fixture["request"]["classification"] = "confidentiality_incident"
            both = copy.deepcopy(fixture["request"]["published_events"])
            fixture["request"]["published_events"] = [both[0]]
            with self.assertRaisesRegex(
                RemovalPlanError, f"result_ids=\\['{RESULT_2}'\\]"
            ):
                self.plan(fixture)

            fixture["request"]["published_events"] = both
            plan = self.plan(fixture)
            self.assertEqual(len(plan["published"]), 2)
            self.assertEqual(len(plan["required_state_corrections"]), 2)
            self.assertEqual(plan["containment"]["bundles"][0]["action"], "delete")
            self.assertEqual(plan["containment"]["manifest"]["action"], "delete")

    def test_confidential_scope_rejects_duplicate_path_for_same_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            release_root = fixture["release_root"]
            original = release_root / self.release_path(RESULT_1)
            duplicate_path = f"releases/2026/11/{RESULT_1}"
            duplicate = release_root / duplicate_path
            shutil.copytree(original, duplicate)
            metadata = json.loads((duplicate / "metadata.json").read_text())
            metadata["release"]["path"] = duplicate_path
            metadata["release"]["eligible_at"] = "2026-11-20T06:07:05.000Z"
            self.write_json(duplicate / "metadata.json", metadata)
            self.git(release_root, "add", ".")
            self.git(release_root, "commit", "-m", "Add duplicate public exposure")
            new_head = self.git(release_root, "rev-parse", "HEAD")
            fixture["release_commit"] = new_head
            fixture["request"]["base_commit"] = new_head
            fixture["request"]["classification"] = "confidentiality_incident"

            with self.assertRaisesRegex(
                RemovalPlanError, re.escape(duplicate_path)
            ):
                self.plan(fixture)

    def test_inputs_are_bounded_before_read_and_symlinks_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            oversized = root / "oversized"
            with oversized.open("wb") as output:
                output.truncate(MAX_DOCUMENT_BYTES + 1)
            with self.assertRaisesRegex(RemovalPlanError, "size limit"):
                _read_regular(oversized, "oversized", MAX_DOCUMENT_BYTES)
            target = root / "target"
            target.write_bytes(b"{}")
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaises(RemovalPlanError):
                _read_regular(link, "link", MAX_DOCUMENT_BYTES)

    def test_release_metadata_inventory_has_aggregate_limits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(
                pathlib.Path(temporary), results=(RESULT_1, RESULT_2)
            )
            fixture["request"]["classification"] = "confidentiality_incident"
            with mock.patch(
                "plan_release_removal.MAX_RELEASE_METADATA_ENTRIES", 1
            ), self.assertRaisesRegex(RemovalPlanError, "too many entries"):
                self.plan(fixture)
            with mock.patch(
                "plan_release_removal.MAX_RELEASE_METADATA_BYTES", 1
            ), self.assertRaisesRegex(RemovalPlanError, "size limit"):
                self.plan(fixture)

    def test_git_output_is_capped_while_reading(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(pathlib.Path(temporary))
            with self.assertRaisesRegex(RemovalPlanError, "oversized"):
                _git(
                    fixture["release_root"],
                    "cat-file",
                    "blob",
                    f"{fixture['release_commit']}:{BUNDLE_PATH}",
                    label="oversized test blob",
                    maximum=1,
                )

    def test_outputs_are_exclusive_nofollow_and_private_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            outside = root / "outside"
            outside.mkdir()
            output = outside / "plan.json"
            _write_exclusive(output, {"safe": True}, [repository], 0o600)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            with self.assertRaisesRegex(RemovalPlanError, "overwrite"):
                _write_exclusive(output, {"safe": True}, [repository], 0o600)
            link = outside / "link.json"
            link.symlink_to(outside / "missing")
            with self.assertRaisesRegex(RemovalPlanError, "overwrite"):
                _write_exclusive(link, {"safe": True}, [repository], 0o600)
            with self.assertRaisesRegex(RemovalPlanError, "outside every repository"):
                _write_exclusive(repository / "plan.json", {}, [repository], 0o600)
            oversized = outside / "oversized.json"
            with self.assertRaisesRegex(RemovalPlanError, "size limit"):
                _write_exclusive(
                    oversized,
                    {"value": "x" * (MAX_PLAN_OUTPUT_BYTES + 1)},
                    [repository],
                    0o600,
                )
            self.assertFalse(oversized.exists())

    def test_git_environment_disables_locks_and_local_write_accelerators(self) -> None:
        environment = _git_environment()
        self.assertEqual(environment["GIT_OPTIONAL_LOCKS"], "0")
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(environment["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(environment["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertIn("core.fsmonitor", environment.values())
        self.assertIn("core.untrackedCache", environment.values())
        self.assertNotIn("GIT_DIR", environment)
        self.assertNotIn("GIT_WORK_TREE", environment)

    def test_missing_promisor_blob_is_not_lazily_fetched(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = root / "source"
            source.mkdir()
            self.git(source, "init", "--initial-branch=main")
            self.git(source, "config", "user.name", "release-test")
            self.git(source, "config", "user.email", "release-test@example.invalid")
            self.git(source, "config", "uploadpack.allowFilter", "true")
            payload = source / "payload"
            payload.write_bytes(b"promisor-only payload")
            self.git(source, "add", "payload")
            self.git(source, "commit", "-m", "Add promisor payload")
            blob_id = self.git(source, "rev-parse", "HEAD:payload")

            clone = root / "clone"
            subprocess.run(
                [
                    "git", "clone", "--filter=blob:none", "--no-checkout",
                    source.resolve().as_uri(), str(clone),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            absent = subprocess.run(
                ["git", "--no-lazy-fetch", "-C", str(clone), "cat-file", "-e", blob_id],
                check=False,
            )
            self.assertNotEqual(absent.returncode, 0)
            with self.assertRaises(RemovalPlanError):
                _blob(clone, blob_id, "promisor blob", 1024)
            still_absent = subprocess.run(
                ["git", "--no-lazy-fetch", "-C", str(clone), "cat-file", "-e", blob_id],
                check=False,
            )
            self.assertNotEqual(still_absent.returncode, 0)

    def test_cli_uses_exact_repository_blobs_and_exclusive_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            fixture = self.fixture(parent)
            request_path = parent / "request.json"
            request_path.write_bytes(self.canonical(fixture["request"]))
            output_path = parent / "private-plan.json"
            public_path = parent / "public-plan.json"
            with self.contract_patch(fixture), mock.patch(
                "plan_release_removal._remote_main",
                side_effect=lambda repository: {
                    RELEASE_REPOSITORY: fixture["release_commit"],
                    STATE_REPOSITORY: fixture["state_commit"],
                }[repository],
            ):
                self.assertEqual(
                    main([
                        str(request_path),
                        "--repository-root", str(fixture["release_root"]),
                        "--state-repository-root", str(fixture["state_root"]),
                        "--evidence-repository-root", str(fixture["state_root"]),
                        "--output", str(output_path),
                        "--public-output", str(public_path),
                    ]),
                    0,
                )
            self.assertEqual(json.loads(output_path.read_text())["visibility"], "private")
            self.assertEqual(json.loads(public_path.read_text())["visibility"], "public")
            self.assertEqual(stat.S_IMODE(output_path.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
