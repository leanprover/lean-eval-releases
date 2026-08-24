from __future__ import annotations

import copy
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import plan_release_removal as planner_module
import release_removal as removal_module
from classify_release_publication import (
    PublicationClassificationError,
    classify_existing_publication_history,
)
from plan_release_removal import plan_removal
from release_removal import (
    ReleaseRemovalError,
    complete_removal_events,
    finalize_release_containment,
    finalize_state_corrections,
    stage_release_containment,
    stage_state_corrections,
    verify_cas_precondition,
    verify_staged_release_containment,
)
import test_plan_release_removal as planner_tests

BUNDLE_PATH = planner_tests.BUNDLE_PATH
EVENT_1 = planner_tests.EVENT_1
EVENT_2 = planner_tests.EVENT_2
RELEASE_REPOSITORY = planner_tests.RELEASE_REPOSITORY
RESULT_1 = planner_tests.RESULT_1
RESULT_2 = planner_tests.RESULT_2
STATE_REPOSITORY = planner_tests.STATE_REPOSITORY


REMOVAL_EVENT_1 = "01a157ed-6c60-7101-8101-010101010101"
REMOVAL_EVENT_2 = "01a157ed-6c61-7202-8202-020202020202"


class ReleaseRemovalQualificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = planner_tests.ReleaseRemovalPlanTests(
            methodName="test_plan_is_exact_private_deterministic_source_free_and_read_only"
        )

    def git(self, root: pathlib.Path, *arguments: str) -> str:
        return self.builder.git(root, *arguments)

    @staticmethod
    def _script(path: pathlib.Path, source: str) -> None:
        path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
        path.chmod(
            stat.S_IRUSR
            | stat.S_IWUSR
            | stat.S_IXUSR
            | stat.S_IRGRP
            | stat.S_IXGRP
            | stat.S_IROTH
            | stat.S_IXOTH
        )

    def _install_qualification_state_tools(
        self,
        fixture: dict[str, object],
        results: tuple[str, ...],
    ) -> None:
        root = fixture["state_root"]
        assert isinstance(root, pathlib.Path)
        expected = root / "qualification-subjects.json"
        expected.write_text(json.dumps(sorted(results)) + "\n", encoding="utf-8")
        self._script(
            root / "scripts" / "validate_state.py",
            """
            import argparse
            import json
            import pathlib

            parser = argparse.ArgumentParser()
            parser.add_argument("--root", type=pathlib.Path, required=True)
            parser.add_argument("--protected-main-commit", required=True)
            args = parser.parse_args()
            expected = set(json.loads((args.root / "qualification-subjects.json").read_text()))
            removals = []
            for path in (args.root / "events").glob("*/*.json"):
                event = json.loads(path.read_text())
                if event.get("event_type") == "release.removed":
                    removals.append(event)
            subjects = {event["subject_id"] for event in removals}
            if removals and subjects != expected:
                raise SystemExit("partial incident group")
            if len(removals) != len(subjects):
                raise SystemExit("duplicate incident subject")
            """,
        )
        self._script(
            root / "scripts" / "materialize_state.py",
            """
            import argparse
            import json
            import pathlib

            parser = argparse.ArgumentParser()
            parser.add_argument("--root", type=pathlib.Path, required=True)
            parser.add_argument("--output", type=pathlib.Path, required=True)
            parser.add_argument("--protected-main-commit", required=True)
            args = parser.parse_args()
            for source in (args.root / "views" / "result-release-status").glob("*/*.json"):
                relative = source.relative_to(args.root)
                target = args.output / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.read_bytes())
            (args.output / "release-queue.json").write_text(
                json.dumps({"schema_version": 1, "tasks": []}, indent=2, sort_keys=True) + "\\n"
            )
            """,
        )
        self._script(
            root / "scripts" / "public_projection.py",
            """
            import argparse
            import json
            import pathlib

            parser = argparse.ArgumentParser()
            parser.add_argument("--root", type=pathlib.Path, required=True)
            parser.add_argument("--state-commit", required=True)
            parser.add_argument("--schema-version", required=True)
            parser.add_argument("--protected-main-commit", required=True)
            parser.add_argument("--output", type=pathlib.Path, required=True)
            args = parser.parse_args()
            results = []
            for source in (args.root / "views" / "result-release-status").glob("*/*.json"):
                status = json.loads(source.read_text())
                results.append({
                    "result_id": status["result_id"],
                    "release": {"status": status["status"], "release_at": None, "reason": None},
                    "public_solution": {"available": status["status"] == "published", "url": None},
                })
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(
                    {"schema_version": 5, "results": results},
                    indent=2,
                    sort_keys=True,
                ) + "\\n"
            )
            """,
        )
        event_by_result = {RESULT_1: EVENT_1, RESULT_2: EVENT_2}
        for result in results:
            status = {
                "schema_version": 2,
                "result_id": result,
                "authority_event_id": event_by_result[result],
                "status": "published",
                "release_event_id": event_by_result[result],
                "release_revision": 3,
                "supersedes_release_event_id": "01a157eb-ab28-7001-a203-040506070809",
            }
            path = root / "views" / "result-release-status" / result[3:5] / f"{result}.json"
            self.builder.write_json(path, status)
        self.git(root, "add", ".")
        self.git(root, "commit", "-m", "Install local removal qualification fixture")
        self.builder.rebind_contract(fixture)

    def _fixture(
        self,
        parent: pathlib.Path,
        *,
        results: tuple[str, ...] = (RESULT_1,),
        classification: str = "erroneous_publication",
        request_results: tuple[str, ...] | None = None,
    ) -> tuple[dict[str, object], dict[str, object]]:
        fixture = self.builder.fixture(parent, results=results)
        if classification == "confidentiality_incident":
            marker = fixture["release_root"] / removal_module.SYNTHETIC_FIXTURE_MARKER
            marker.write_bytes(removal_module.SYNTHETIC_FIXTURE_BYTES)
            self.git(fixture["release_root"], "add", marker.name)
            self.git(
                fixture["release_root"],
                "commit",
                "-m",
                "Mark harmless synthetic removal fixture",
            )
            fixture["release_commit"] = self.git(
                fixture["release_root"], "rev-parse", "HEAD"
            )
            fixture["request"]["base_commit"] = fixture["release_commit"]
        if request_results is not None:
            fixture["request"]["published_events"] = [
                locator
                for locator in fixture["request"]["published_events"]
                if pathlib.PurePosixPath(locator["path"]).stem
                in {EVENT_1 if result == RESULT_1 else EVENT_2 for result in request_results}
            ]
        fixture["request"]["classification"] = classification
        self._install_qualification_state_tools(
            fixture, request_results if request_results is not None else results
        )
        with self.builder.contract_patch(fixture):
            plan = plan_removal(
                repository_root=fixture["release_root"],
                state_repository_roots={STATE_REPOSITORY: fixture["state_root"]},
                evidence_repository_root=fixture["state_root"],
                request_value=copy.deepcopy(fixture["request"]),
                remote_main_commits={
                    RELEASE_REPOSITORY: fixture["release_commit"],
                    STATE_REPOSITORY: fixture["state_commit"],
                },
            )
        return fixture, plan

    @staticmethod
    def _identities(results: tuple[str, ...]) -> list[dict[str, str]]:
        identity_by_result = {
            RESULT_1: {
                "subject_id": RESULT_1,
                "event_id": REMOVAL_EVENT_1,
                "occurred_at": "2026-10-20T06:09:00.000Z",
            },
            RESULT_2: {
                "subject_id": RESULT_2,
                "event_id": REMOVAL_EVENT_2,
                "occurred_at": "2026-10-20T06:09:00.001Z",
            },
        }
        return [identity_by_result[result] for result in sorted(results)]

    def _contract_patch(self, fixture: dict[str, object]):
        return mock.patch.multiple(
            planner_module,
            STATE_REMOVAL_CONTRACT_COMMIT=fixture["state_contract_commit"],
            STATE_REMOVAL_CONTRACT_TREES=fixture["state_contract_trees"],
            STATE_REMOVAL_CONTRACT_COMPONENTS=fixture["state_contract_components"],
        )

    def test_delete_bundle_atomic_state_projection_queue_and_resume(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture, plan = self._fixture(pathlib.Path(directory))
            state_root = fixture["state_root"]
            original_path = pathlib.PurePosixPath(plan["published"][0]["state_event_path"])
            original = self.git(
                state_root,
                "show",
                f"{fixture['state_commit']}:{original_path.as_posix()}",
            )
            with self._contract_patch(fixture):
                binding = finalize_release_containment(
                    plan, fixture["release_root"], message="Remove erroneous release"
                )
                self.assertFalse((fixture["release_root"] / BUNDLE_PATH).exists())
                self.assertFalse((fixture["release_root"] / "release-manifest.json").exists())
                cas = finalize_state_corrections(
                    plan,
                    binding,
                    self._identities((RESULT_1,)),
                    state_root,
                    fixture["state_commit"],
                    message="Record release removal",
                )
                self.assertFalse(cas["idempotent_resume"])
                self.assertFalse(cas["results_repository_required"])
                verify_cas_precondition(cas, fixture["state_commit"])
                with self.assertRaisesRegex(ReleaseRemovalError, "do not rebase"):
                    verify_cas_precondition(cas, "f" * 40)
                resumed = finalize_state_corrections(
                    plan,
                    binding,
                    self._identities((RESULT_1,)),
                    state_root,
                    fixture["state_commit"],
                    message="Record release removal",
                )
            self.assertTrue(resumed["idempotent_resume"])
            self.assertEqual(resumed["commit"], cas["commit"])
            self.assertEqual(
                self.git(state_root, "show", f"{cas['commit']}:{original_path.as_posix()}"),
                original,
            )
            event = json.loads(
                self.git(state_root, "show", f"{cas['commit']}:{cas['event_paths'][0]}")
            )
            self.assertEqual(event["event_type"], "release.removed")
            self.assertEqual(event["payload"]["removal_repository_commit"], binding["commit"])
            status = json.loads(
                self.git(state_root, "show", f"{cas['commit']}:{cas['status_paths'][0]}")
            )
            self.assertEqual(status["status"], "removed")

    def test_state_finalizer_recovers_the_exact_precommit_index(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture, plan = self._fixture(pathlib.Path(directory))
            with self._contract_patch(fixture):
                binding = finalize_release_containment(
                    plan, fixture["release_root"], message="Remove erroneous release"
                )
                staged = stage_state_corrections(
                    plan,
                    binding,
                    self._identities((RESULT_1,)),
                    fixture["state_root"],
                    fixture["state_commit"],
                )
                cas = finalize_state_corrections(
                    plan,
                    binding,
                    self._identities((RESULT_1,)),
                    fixture["state_root"],
                    fixture["state_commit"],
                    message="Record release removal",
                )
            self.assertEqual(cas["tree"], staged["staged_tree"])
            self.assertFalse(cas["idempotent_resume"])

    def test_shared_bundle_and_unrelated_manifest_entry_are_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture, plan = self._fixture(
                pathlib.Path(directory),
                results=(RESULT_1, RESULT_2),
                request_results=(RESULT_1,),
            )
            self.assertEqual(plan["containment"]["bundles"][0]["action"], "retain_shared")
            self.assertEqual(plan["containment"]["manifest"]["action"], "remove_incident_entries")
            stage = stage_release_containment(plan, fixture["release_root"])
            self.assertIn("release-manifest.json", stage["staged_paths"])
            binding = finalize_release_containment(
                plan, fixture["release_root"], message="Remove one erroneous release"
            )
            self.assertTrue((fixture["release_root"] / BUNDLE_PATH).is_file())
            self.assertTrue(
                (fixture["release_root"] / self.builder.release_path(RESULT_2)).is_dir()
            )
            manifest = json.loads(
                (fixture["release_root"] / "release-manifest.json").read_text()
            )
            self.assertEqual(
                [entry["result_id"] for entry in manifest["entries"]], [RESULT_2]
            )
            self.assertEqual(binding["semantics"], "forward_deletion")

    def test_confidential_group_is_atomic_partial_group_fails_and_resume_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture, plan = self._fixture(
                pathlib.Path(directory),
                results=(RESULT_1, RESULT_2),
                classification="confidentiality_incident",
            )
            binding = finalize_release_containment(
                plan, fixture["release_root"], message="Build synthetic sanitized tree"
            )
            self.assertEqual(binding["semantics"], "synthetic_target_tree_only")
            with self.assertRaisesRegex(ReleaseRemovalError, "approved real cleanup"):
                complete_removal_events(
                    plan, binding, self._identities((RESULT_1, RESULT_2))
                )
            unmarked = {**binding, "synthetic_fixture_attestation": None}
            with self.assertRaisesRegex(ReleaseRemovalError, "harmless-fixture marker"):
                complete_removal_events(
                    plan,
                    unmarked,
                    self._identities((RESULT_1, RESULT_2)),
                    synthetic_confidentiality_qualification=True,
                )
            with self.assertRaisesRegex(ReleaseRemovalError, "full incident"):
                complete_removal_events(
                    plan,
                    binding,
                    self._identities((RESULT_1,)),
                    synthetic_confidentiality_qualification=True,
                )
            with self.assertRaisesRegex(ReleaseRemovalError, "canonical subject order"):
                complete_removal_events(
                    plan,
                    binding,
                    list(reversed(self._identities((RESULT_1, RESULT_2)))),
                    synthetic_confidentiality_qualification=True,
                )
            mismatched_time = self._identities((RESULT_1, RESULT_2))
            mismatched_time[0] = {
                **mismatched_time[0],
                "occurred_at": "2026-10-20T06:09:00.002Z",
            }
            with self.assertRaisesRegex(ReleaseRemovalError, "UUIDv7 timestamp"):
                complete_removal_events(
                    plan,
                    binding,
                    mismatched_time,
                    synthetic_confidentiality_qualification=True,
                )
            with self._contract_patch(fixture):
                cas = finalize_state_corrections(
                    plan,
                    binding,
                    self._identities((RESULT_1, RESULT_2)),
                    fixture["state_root"],
                    fixture["state_commit"],
                    message="Qualify atomic synthetic removal",
                    synthetic_confidentiality_qualification=True,
                )
                resumed = finalize_state_corrections(
                    plan,
                    binding,
                    self._identities((RESULT_1, RESULT_2)),
                    fixture["state_root"],
                    fixture["state_commit"],
                    message="Qualify atomic synthetic removal",
                    synthetic_confidentiality_qualification=True,
                )
            self.assertEqual(len(cas["event_paths"]), 2)
            self.assertEqual(len(cas["status_paths"]), 2)
            self.assertTrue(cas["synthetic_confidentiality_qualification"])
            self.assertTrue(resumed["idempotent_resume"])
            self.assertEqual(resumed["commit"], cas["commit"])
            events = [
                json.loads(self.git(fixture["state_root"], "show", f"{cas['commit']}:{path}"))
                for path in cas["event_paths"]
            ]
            self.assertEqual(
                {event["payload"]["removal_repository_commit"] for event in events},
                {binding["commit"]},
            )
            self.assertEqual(
                {event["payload"]["removal_repository_tree"] for event in events},
                {binding["tree"]},
            )

    def test_removed_release_history_refuses_republication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture, plan = self._fixture(pathlib.Path(directory))
            finalize_release_containment(
                plan, fixture["release_root"], message="Remove erroneous release"
            )
            with self.assertRaisesRegex(
                PublicationClassificationError, "refusing republication"
            ):
                classify_existing_publication_history(
                    fixture["release_root"],
                    plan["published"][0]["release_path"],
                    plan["published"][0]["submission_id"],
                )

    def test_owner_retraction_fails_closed_without_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture, plan = self._fixture(pathlib.Path(directory))
            plan["classification"] = "owner_retraction"
            plan["required_state_corrections"][0]["fixed_payload_bindings"][
                "classification"
            ] = "owner_retraction"
            plan["required_state_corrections"][0]["event_skeleton"]["payload"][
                "classification"
            ] = "owner_retraction"
            with self.assertRaisesRegex(ReleaseRemovalError, "policy is unresolved"):
                stage_release_containment(plan, fixture["release_root"])

    def test_release_stage_rejects_unplanned_cached_or_worktree_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture, plan = self._fixture(pathlib.Path(directory))
            root = fixture["release_root"]
            (root / "unplanned.txt").write_text("not part of removal\n", encoding="utf-8")
            with self.assertRaisesRegex(ReleaseRemovalError, "tracked-clean"):
                stage_release_containment(plan, root)
            (root / "unplanned.txt").unlink()
            (root / BUNDLE_PATH).write_bytes(b"changed")
            with self.assertRaisesRegex(ReleaseRemovalError, "tracked-clean"):
                stage_release_containment(plan, root)
            self.git(root, "restore", "--", BUNDLE_PATH)
            stage_release_containment(plan, root)
            (root / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
            self.git(root, "add", "unexpected.txt")
            with self.assertRaisesRegex(ReleaseRemovalError, "exact containment"):
                verify_staged_release_containment(plan, root)

    def test_publication_latch_must_remain_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture, plan = self._fixture(pathlib.Path(directory))
            with mock.patch.dict(os.environ, {"PUBLICATION_ENABLED": "true"}):
                with self.assertRaisesRegex(
                    ReleaseRemovalError, "must remain absent or exactly false"
                ):
                    stage_release_containment(plan, fixture["release_root"])


if __name__ == "__main__":
    unittest.main()
