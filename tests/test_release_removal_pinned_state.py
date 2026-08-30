from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import plan_release_removal as planner_module  # noqa: E402
import test_plan_release_removal as planner_tests  # noqa: E402
from plan_release_removal import plan_removal  # noqa: E402
from release_removal import (  # noqa: E402
    finalize_release_containment,
    finalize_state_corrections,
)
from release_tree import tree_digest  # noqa: E402

STATE_CONTRACT_COMMIT = "0c943edde8a247b8670e10339b80fc65be6c0f33"
STATE_CONTRACT_TREE = "0ba2090d9c43e0d51fb08272efbd12a3efb490e9"
STATE_CONTRACT_ROOTS = {
    "README.md": "ff7430d32bf28e2a2814852a16cabda710b74182",
    "docs": "5d3923158bd8f620f184fee5a4d00924220464fa",
    "schema": "2c0004214d90b82cf895e79a91c239ac9e7bbf67",
    "scripts": "ed830aea8fe7a4a0e6db7acdcf82f23cb24a296d",
}
STATE_CONTRACT_TREES = {
    path: STATE_CONTRACT_ROOTS[path] for path in ("schema", "scripts")
}
STATE_REPOSITORY = "leanprover/lean-eval-state"
RELEASE_REPOSITORY = "leanprover/lean-eval-releases"
INCIDENT_ID = "01a157eb-ab28-7001-b203-040506070809"
REMOVAL_EVENT_ID = "01a157ed-6c60-7101-8101-010101010101"


class PinnedStateWorkflowTests(unittest.TestCase):
    def test_validate_workflow_runs_the_exact_state_contract_integration(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "validate.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("repository: leanprover/lean-eval-state", workflow)
        self.assertIn(f"ref: {STATE_CONTRACT_COMMIT}", workflow)
        self.assertIn("path: .pinned-state-contract", workflow)
        self.assertIn("environment: release-production", workflow)
        self.assertIn(
            "ssh-key: ${{ secrets.PRODUCTION_STATE_CONTROLLER_KEY }}", workflow
        )
        self.assertIn("github.event_name != 'pull_request'", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        documentation = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertRegex(
            documentation,
            r"branch `workflow_dispatch` does\s+not receive",
        )
        self.assertIn(
            "LEAN_EVAL_PINNED_STATE_ROOT: "
            "${{ github.workspace }}/.pinned-state-contract",
            workflow,
        )
        self.assertEqual(workflow.count(f"ref: {STATE_CONTRACT_COMMIT}"), 1)
        self.assertEqual(workflow.count("repository: leanprover/lean-eval-state"), 1)


class PinnedStateConsumerIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        source = os.environ.get("LEAN_EVAL_PINNED_STATE_ROOT")
        if source is None:
            self.skipTest(
                "set LEAN_EVAL_PINNED_STATE_ROOT to run the exact pinned State integration"
            )
        self.state_source = pathlib.Path(source).resolve(strict=True)
        self.builder = planner_tests.ReleaseRemovalPlanTests(
            methodName="test_plan_is_exact_private_deterministic_source_free_and_read_only"
        )

    @staticmethod
    def git(root: pathlib.Path, *arguments: str) -> str:
        environment = {
            **os.environ,
            "GIT_AUTHOR_DATE": "2026-10-20T06:10:00Z",
            "GIT_COMMITTER_DATE": "2026-10-20T06:10:00Z",
        }
        return subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
            env=environment,
        ).stdout.strip()

    @staticmethod
    def canonical(value: object) -> bytes:
        return (
            json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")

    def write_json(self, path: pathlib.Path, value: object) -> bytes:
        raw = self.canonical(value)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return raw

    def load_pinned_lifecycle(self) -> list[dict[str, object]]:
        source = subprocess.run(
            [
                "git",
                "-C",
                str(self.state_source),
                "show",
                f"{STATE_CONTRACT_COMMIT}:tests/fixtures.py",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        completed = subprocess.run(
            [sys.executable, "-"],
            input=(
                source.stdout
                + "\nprint(json.dumps(published_and_removed()[:-1], "
                + "ensure_ascii=True, sort_keys=True))\n"
            ),
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return copy.deepcopy(json.loads(completed.stdout))

    def qualify_state_source(self) -> None:
        origin = self.git(self.state_source, "remote", "get-url", "origin")
        self.assertIn(
            origin.removesuffix(".git"),
            {
                "https://github.com/leanprover/lean-eval-state",
                "git@github.com:leanprover/lean-eval-state",
            },
        )
        self.assertEqual(
            self.git(
                self.state_source,
                "rev-parse",
                f"{STATE_CONTRACT_COMMIT}^{{commit}}",
            ),
            STATE_CONTRACT_COMMIT,
        )
        self.assertEqual(
            self.git(
                self.state_source,
                "rev-parse",
                f"{STATE_CONTRACT_COMMIT}^{{tree}}",
            ),
            STATE_CONTRACT_TREE,
        )
        for path, object_id in STATE_CONTRACT_ROOTS.items():
            self.assertEqual(
                self.git(
                    self.state_source,
                    "rev-parse",
                    f"{STATE_CONTRACT_COMMIT}:{path}",
                ),
                object_id,
            )
        for path, tree in STATE_CONTRACT_TREES.items():
            self.assertEqual(
                self.git(
                    self.state_source,
                    "rev-parse",
                    f"{STATE_CONTRACT_COMMIT}:{path}",
                ),
                tree,
            )

    def materialize_operational_views(
        self, state_root: pathlib.Path, output: pathlib.Path
    ) -> None:
        source = """
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
sys.path.insert(0, str(root / "scripts"))
from materialize_state import materialize, write_views

events = [
    json.loads(path.read_text(encoding="utf-8"))
    for path in sorted((root / "events").glob("[0-9a-f][0-9a-f]/*.json"))
]
write_views(materialize("production", events), output, False)
"""
        subprocess.run(
            [sys.executable, "-c", source, str(state_root), str(output)],
            cwd=state_root,
            check=True,
            capture_output=True,
            timeout=60,
            env={
                key: os.environ[key]
                for key in ("PATH", "LANG", "LC_ALL")
                if key in os.environ
            },
        )

    def test_exact_pinned_consumers_accept_atomic_removal_and_hide_solution(self) -> None:
        self.qualify_state_source()
        self.assertEqual(planner_module.STATE_REMOVAL_CONTRACT_COMMIT, STATE_CONTRACT_COMMIT)
        self.assertEqual(planner_module.STATE_REMOVAL_CONTRACT_TREES, STATE_CONTRACT_TREES)

        with tempfile.TemporaryDirectory() as directory:
            parent = pathlib.Path(directory)
            release_root = parent / "releases"
            state_root = parent / "state"
            subprocess.run(
                [
                    "git",
                    "clone",
                    "--no-checkout",
                    "--shared",
                    str(self.state_source),
                    str(state_root),
                ],
                check=True,
                capture_output=True,
                timeout=30,
            )
            self.git(state_root, "checkout", "--detach", STATE_CONTRACT_COMMIT)
            self.git(
                state_root,
                "remote",
                "set-url",
                "origin",
                f"https://github.com/{STATE_REPOSITORY}.git",
            )
            self.git(state_root, "config", "user.name", "release-test")
            self.git(state_root, "config", "user.email", "release-test@example.invalid")
            self.builder.init_repository(release_root, RELEASE_REPOSITORY)

            events = self.load_pinned_lifecycle()
            published = events[-1]
            result_id = str(published["subject_id"])
            submission_id = str(events[1]["subject_id"])
            release_path = f"releases/2026/10/{result_id}"
            bundle_path = f"sources/{submission_id}.tar.gz"
            bundle = release_root.joinpath(*bundle_path.split("/"))
            bundle.parent.mkdir(parents=True)
            bundle.write_bytes(b"exact pinned State consumer integration fixture\n")

            release = release_root.joinpath(*release_path.split("/"))
            (release / "Submission").mkdir(parents=True)
            (release / "Submission.lean").write_text(
                "import Mathlib\nexample : True := by trivial\n", encoding="utf-8"
            )
            (release / "Submission" / "Helper.lean").write_text(
                "def helper : Nat := 4\n", encoding="utf-8"
            )
            (release / "LICENSE").write_text(
                "Apache-2.0 fixture\n", encoding="utf-8"
            )
            archive_payload = events[2]["payload"]
            metadata = {
                "schema_version": 1,
                "generated_at": "2026-10-20T06:07:05.000Z",
                "result": {
                    "result_id": result_id,
                    "problem_id": "two_plus_two",
                    "statement_revision": 1,
                    "commit": "e" * 40,
                    "tree_digest": "f" * 64,
                },
                "submission": {
                    "submission_id": submission_id,
                    "owner_login": "kim-em",
                    "declared_model": "Example Model",
                    "production_metadata": {},
                },
                "archive": copy.deepcopy(archive_payload),
                "release": {
                    "accepted_at": "2026-08-20T06:07:05.000Z",
                    "eligible_at": "2026-10-20T06:07:05.000Z",
                    "path": release_path,
                    "license": "Apache-2.0",
                },
                "source_files": [
                    {
                        "path": "Submission.lean",
                        "size_bytes": 45,
                        "sha256": "b" * 64,
                    }
                ],
            }
            self.write_json(release / "metadata.json", metadata)
            release_digest = tree_digest(release)
            bundle_digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
            manifest = {
                "schema_version": 1,
                "release_id": "lean-eval-2026-10-20",
                "generated_at": "2026-10-20T06:07:05.000Z",
                "entries": [
                    {
                        "result_id": result_id,
                        "submission_id": submission_id,
                        "accepted_at": "2026-08-20T06:07:05.000Z",
                        "eligible_at": "2026-10-20T06:07:05.000Z",
                        "archive_repository": archive_payload["archive_repository"],
                        "archive_commit": archive_payload["archive_commit"],
                        "archive_path": archive_payload["archive_path"],
                        "archive_ciphertext_sha256": archive_payload[
                            "archive_ciphertext_sha256"
                        ],
                        "bundle_sha256": bundle_digest,
                        "bundle_path": bundle_path,
                        "release_tree_sha256": release_digest,
                        "release_path": release_path,
                        "license": "Apache-2.0",
                    }
                ],
            }
            self.write_json(release_root / "release-manifest.json", manifest)
            self.git(release_root, "add", ".")
            self.git(release_root, "commit", "-m", "Publish integration fixture")
            release_commit = self.git(release_root, "rev-parse", "HEAD")

            published["payload"] = {
                "attempt": 1,
                "repository_commit": release_commit,
                "tree_digest": release_digest,
                "path": release_path,
            }
            shutil.rmtree(state_root / "events")
            if (state_root / "views").exists():
                shutil.rmtree(state_root / "views")
            for event in events:
                event_id = str(event["event_id"])
                self.write_json(
                    state_root
                    / "events"
                    / event_id.replace("-", "")[:2]
                    / f"{event_id}.json",
                    event,
                )
            evidence_path = f"docs/incidents/{INCIDENT_ID}.json"
            evidence_raw = self.write_json(
                state_root / evidence_path,
                {"private_case": "pinned consumer integration; source omitted"},
            )
            self.git(state_root, "add", "-A", "--", "events", "docs")
            materialized = parent / "materialized"
            self.materialize_operational_views(state_root, materialized)
            shutil.copytree(materialized / "views", state_root / "views")
            self.git(state_root, "add", "--", "views")
            self.git(state_root, "commit", "-m", "Record integration publication")
            state_commit = self.git(state_root, "rev-parse", "HEAD")
            subprocess.run(
                [
                    sys.executable,
                    str(state_root / "scripts" / "validate_state.py"),
                    "--root",
                    str(state_root),
                    "--protected-main-commit",
                    state_commit,
                ],
                cwd=state_root,
                check=True,
                capture_output=True,
                timeout=60,
            )

            published_id = str(published["event_id"])
            published_path = (
                f"events/{published_id.replace('-', '')[:2]}/{published_id}.json"
            )
            published_raw = (state_root / published_path).read_bytes()
            request = {
                "schema_version": 1,
                "incident_id": INCIDENT_ID,
                "planned_at": "2026-10-20T06:08:00.000Z",
                "classification": "erroneous_publication",
                "release_repository": RELEASE_REPOSITORY,
                "base_commit": release_commit,
                "published_events": [
                    {
                        "repository": STATE_REPOSITORY,
                        "commit": state_commit,
                        "path": published_path,
                        "sha256": hashlib.sha256(published_raw).hexdigest(),
                    }
                ],
                "evidence": {
                    "repository": STATE_REPOSITORY,
                    "commit": state_commit,
                    "path": evidence_path,
                    "sha256": hashlib.sha256(evidence_raw).hexdigest(),
                },
            }
            plan = plan_removal(
                repository_root=release_root,
                state_repository_roots={STATE_REPOSITORY: state_root},
                evidence_repository_root=state_root,
                request_value=request,
                remote_main_commits={
                    RELEASE_REPOSITORY: release_commit,
                    STATE_REPOSITORY: state_commit,
                },
            )
            binding = finalize_release_containment(
                plan, release_root, message="Remove integration release"
            )
            cas = finalize_state_corrections(
                plan,
                release_root,
                binding["commit"],
                [
                    {
                        "subject_id": result_id,
                        "event_id": REMOVAL_EVENT_ID,
                        "occurred_at": "2026-10-20T06:09:00.000Z",
                    }
                ],
                state_root,
                state_commit,
                message="Record integration release removal",
            )
            self.assertFalse(cas["push_prohibited"])
            self.assertTrue(cas["remote_update_permitted"])
            self.assertEqual(cas["release_repository_commit"], binding["commit"])
            self.assertEqual(cas["release_repository_tree"], binding["tree"])
            self.assertEqual(len(cas["event_paths"]), 1)
            self.assertEqual(len(cas["status_paths"]), 1)


if __name__ == "__main__":
    unittest.main()
