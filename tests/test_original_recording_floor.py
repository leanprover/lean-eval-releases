from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from embargo import eligible_at  # noqa: E402
from original_recording_floor import RecordingFloorError, admit, recording_floor  # noqa: E402
from release_orchestrator import plan_next  # noqa: E402
from release_qualification import build_qualification  # noqa: E402


class OriginalRecordingFloorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.state = self.root / "state"
        self.results = self.root / "results"
        for path, repository in ((self.state, "lean-eval-state"),
                                 (self.results, "lean-eval-submissions")):
            path.mkdir()
            self.git(path, "init", "-q", "-b", "main")
            self.git(path, "config", "user.name", "Fixture")
            self.git(path, "config", "user.email", "fixture@example.invalid")
            self.git(path, "remote", "add", "origin", f"https://github.com/leanprover/{repository}.git")
        self.queue = json.loads((ROOT / "tests/fixtures/release-queue-v1.json").read_text())
        self.task = self.queue["tasks"][0]
        self.task.update(accepted_at="2026-12-31T01:00:00.002Z",
                         release_at="2027-02-28T01:00:00.002Z")
        self.submission = self.task["submission_id"]
        self.row = {
            "result_id": self.task["result_id"], "accepted_at": "2026-12-31T03:00:00Z",
            "benchmark_commit": "d" * 40, "declared_model": self.task["declared_model"],
            "problem_id": self.task["problem_id"], "statement_revision": 1,
            "intake": {"kind": "server", "submission_id": self.submission},
            "submission": {"kind": "github_repo", "repo": "owner/private",
                           "ref": "e" * 40, "public": False},
        }
        self.events = [
            self.event(1, "submission.received", self.submission, {
                "declared_model": self.task["declared_model"], "problem_id": self.task["problem_id"],
                "statement_revision": 1, "source_repository": "owner/private",
                "source_commit": "e" * 40, "source_visibility": "private",
            }),
            self.event(2, "evaluation.started", self.submission, {
                "attempt": 1, "benchmark_commit": "d" * 40, "toolchain": "leanprover/lean4:v4.35.0",
            }),
            self.event(3, "evaluation.accepted", self.submission, {
                "attempt": 1, "evaluator_version": "f" * 40,
            }, cause=2, occurred_at=self.task["accepted_at"]),
            self.event(4, "result.recorded", self.task["result_id"], {}, cause=3,
                       occurred_at="2026-12-31T03:00:02.500Z"),
        ]
        self.events[0]["actor"] = {"kind": "github", "login": self.task["owner_login"]}
        self.write_original()

    def git(self, root: pathlib.Path, *args: str) -> str:
        return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.PIPE).decode().strip()

    def commit(self, root: pathlib.Path) -> str:
        self.git(root, "add", ".")
        self.git(root, "commit", "-qm", "fixture")
        head = self.git(root, "rev-parse", "HEAD")
        self.git(root, "update-ref", "refs/remotes/origin/main", head)
        return head

    def event(self, number: int, kind: str, subject: str, payload: dict,
              cause: int | None = None, occurred_at: str = "2026-12-31T00:00:00.000Z") -> dict:
        return {"schema_version": 1, "event_id": self.identifier(number), "event_type": kind,
                "subject_id": subject, "actor": {"kind": "system"}, "payload": payload,
                "causation_event_id": None if cause is None else self.identifier(cause),
                "occurred_at": occurred_at}

    def identifier(self, number: int) -> str:
        return f"0198abcd-0000-7000-8000-{number:012d}"

    def sync_state(self) -> None:
        directory = self.state / "events" / "01"
        directory.mkdir(parents=True, exist_ok=True)
        for event in self.events:
            (directory / (event["event_id"] + ".json")).write_text(json.dumps(event))
        self.state_commit = self.commit(self.state)

    def write_original(self) -> None:
        path = f"results/{self.task['owner_login']}.json"
        raw = (json.dumps({"schema_version": 2, "user": self.task["owner_login"],
                           "results": [self.row]}, sort_keys=True) + "\n").encode()
        destination = self.results / path
        destination.parent.mkdir(exist_ok=True)
        destination.write_bytes(raw)
        self.task["result_commit"] = self.commit(self.results)
        entries = [{"path": path, "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}]
        self.task["result_tree_digest"] = hashlib.sha256(b"lean-eval-result-tree-v1\0" + json.dumps(
            entries, sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()
        self.events[3]["payload"] = {
            "submission_id": self.submission, "problem_id": self.task["problem_id"],
            "statement_revision": 1, "result_commit": self.task["result_commit"],
            "tree_digest": self.task["result_tree_digest"],
        }
        self.sync_state()

    def qualification(self) -> dict:
        contract = json.loads((ROOT / "configuration/release-controller-credential-contract-v1.json").read_text())
        snapshot = json.loads((ROOT / "tests/fixtures/release-acceptance-snapshot-v1.json").read_text())
        return build_qualification(contract, self.queue, snapshot, environment="production",
                                   publication_enabled="true", mode="publication",
                                   release_commit="a" * 40, state_commit=self.state_commit)

    def plan(self) -> dict:
        return plan_next(self.queue, "2027-03-01T00:00:00.000Z", self.qualification())

    def floor(self, plan: dict | None = None) -> str:
        return recording_floor(plan or self.plan(), state_root=self.state, results_root=self.results)

    def test_month_clamp_and_exact_boundary_preserve_canonical_plan_and_retry(self) -> None:
        plan = self.plan()
        before = copy.deepcopy(plan)
        self.assertEqual(plan["request"]["release"]["eligible_at"], "2027-02-28T01:00:00.002Z")
        self.assertEqual(self.floor(plan), "2027-02-28T03:00:02.500Z")
        kwargs = {"state_root": self.state, "results_root": self.results}
        held = admit(plan, "2027-02-28T03:00:02.499Z", **kwargs)
        self.assertEqual(held, {"schema_version": 1, "kind": "not_due",
                               "next_release_at": "2027-02-28T03:00:02.500Z"})
        self.assertIs(admit(plan, "2027-02-28T03:00:02.500Z", **kwargs), plan)
        self.assertEqual(plan, before)
        self.assertEqual(plan["started_transition"]["payload"], {"attempt": 2})
        self.assertEqual(self.task["attempt"], 1)

    def test_later_canonical_schedule_wins(self) -> None:
        plan = self.plan()
        plan["request"]["release"]["eligible_at"] = "2027-04-01T00:00:00.000Z"
        self.assertEqual(self.floor(plan), "2027-04-01T00:00:00.000Z")

    def test_mutable_current_result_clock_is_never_authority(self) -> None:
        plan = self.plan()
        path = self.results / "results/kim-em.json"
        path.write_text('{"untrusted_current_row":true}\n')
        self.commit(self.results)
        self.assertEqual(self.floor(plan), "2027-02-28T03:00:02.500Z")

    def test_wrong_commit_or_digest_fails_before_admission(self) -> None:
        for field, value in (("commit", "0" * 40), ("tree_digest", "0" * 64)):
            with self.subTest(field=field):
                plan = self.plan()
                plan["request"]["result"][field] = value
                with self.assertRaises(RecordingFloorError):
                    self.floor(plan)

    def test_digest_is_checked_even_when_state_and_plan_agree(self) -> None:
        self.task["result_tree_digest"] = "0" * 64
        self.events[3]["payload"]["tree_digest"] = "0" * 64
        self.sync_state()
        with self.assertRaisesRegex(RecordingFloorError, "tree digest"):
            self.floor()

    def test_original_commit_cannot_substitute_another_results_path(self) -> None:
        original = self.results / "results/kim-em.json"
        original.rename(self.results / "results/another.json")
        commit = self.commit(self.results)
        self.task["result_commit"] = commit
        self.events[3]["payload"]["result_commit"] = commit
        self.sync_state()
        with self.assertRaisesRegex(RecordingFloorError, "immutable Git evidence"):
            self.floor()

    def test_original_uuid_issue_provenance_source_and_benchmark_fail_closed(self) -> None:
        original = copy.deepcopy(self.row)
        changes = [
            ("intake", {"kind": "server", "submission_id": self.identifier(99)}),
            ("intake", {"kind": "issue", "issue_number": 1926}),
            ("submission", {"kind": "github_repo", "repo": "other/repo", "ref": "e" * 40, "public": False}),
            ("submission", {"kind": "github_repo", "repo": "owner/private", "ref": "a" * 40, "public": False}),
            ("submission", {"kind": "github_repo", "repo": "owner/private", "ref": "e" * 40, "public": True}),
            ("benchmark_commit", "c" * 40),
        ]
        for key, value in changes:
            with self.subTest(key=key, value=value):
                self.row = copy.deepcopy(original)
                self.row[key] = value
                self.write_original()
                with self.assertRaisesRegex(RecordingFloorError, "provenance"):
                    self.floor()

    def test_original_recording_upper_second_bound_is_required(self) -> None:
        self.events[3]["occurred_at"] = "2026-12-31T03:00:00.999Z"
        self.sync_state()
        with self.assertRaisesRegex(RecordingFloorError, "bound original recording"):
            self.floor()

    def test_wrong_causation_actor_or_acceptance_clock_is_held(self) -> None:
        for change in ("causation", "actor", "clock"):
            with self.subTest(change=change):
                original = copy.deepcopy(self.events)
                if change == "causation":
                    self.events[3]["causation_event_id"] = self.identifier(99)
                elif change == "actor":
                    self.events[3]["actor"] = {"kind": "github", "login": "kim-em"}
                else:
                    self.events[2]["occurred_at"] = "2026-12-31T01:01:00.002Z"
                self.sync_state()
                with self.assertRaises(RecordingFloorError):
                    self.floor()
                self.events = original

    def test_retraction_cannot_be_readmitted_by_old_queue(self) -> None:
        self.events.append(self.event(5, "result.retracted", self.task["result_id"], {}))
        self.sync_state()
        with self.assertRaisesRegex(RecordingFloorError, "retracted"):
            self.floor()

    def test_empty_and_exhausted_queue_do_not_need_new_provenance(self) -> None:
        self.queue["tasks"] = []
        self.assertEqual(admit(plan_next(self.queue, "2027-03-01T00:00:00.000Z"),
                               "2027-03-01T00:00:00.000Z"), {"schema_version": 1, "kind": "empty"})
        self.task["attempt"] = 4
        self.queue["tasks"] = [self.task]
        plan = plan_next(self.queue, "2027-03-01T00:00:00.000Z")
        self.assertIs(admit(plan, "2027-03-01T00:00:00.000Z"), plan)
        self.assertEqual(plan["kind"], "stalled")

    def test_production_cli_requires_guard_and_outputs_hold_without_started_transition(self) -> None:
        queue = self.root / "queue.json"
        queue.write_text(json.dumps(self.queue))
        qualification = self.root / "qualification.json"
        qualification.write_text(json.dumps(self.qualification()))
        output = self.root / "output.json"
        command = [sys.executable, "-B", str(ROOT / "scripts/release_orchestrator.py"), str(queue),
                   "--trusted-as-of", "2027-02-28T01:00:00.002Z", "--output", str(output)]
        refused = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(refused.returncode, 1, refused.stderr)
        self.assertFalse(output.exists())
        guarded = subprocess.run(command + ["--controller-qualification", str(qualification),
            "--require-controller-qualification", "--state-root", str(self.state),
            "--original-results-root", str(self.results)], capture_output=True, text=True)
        self.assertEqual(guarded.returncode, 0, guarded.stderr)
        self.assertEqual(json.loads(output.read_text()), {"schema_version": 1, "kind": "not_due",
                         "next_release_at": "2027-02-28T03:00:02.500Z"})
        self.assertEqual(self.git(self.state, "status", "--porcelain"), "")
        self.assertEqual(self.git(self.state, "rev-parse", "HEAD"), self.state_commit)

    def test_workflow_original_history_is_read_only_after_recovery_before_admission(self) -> None:
        workflow = (ROOT / ".github/workflows/release-controller.yml").read_text()
        checkout = workflow.index("      - name: Check out public original Results history")
        planning = workflow.index("      - name: Plan at the trusted workflow clock")
        self.assertLess(workflow.index("      - name: Reconcile an interrupted release"), checkout)
        block = workflow[checkout:planning]
        self.assertIn("if: steps.recovery.outputs.kind == 'none'", block)
        self.assertIn("repository: leanprover/lean-eval-submissions", block)
        self.assertIn("fetch-depth: 0", block)
        self.assertIn("persist-credentials: false", block)
        self.assertNotIn("secrets.", block)
        plan_block = workflow[planning:workflow.index("      - name:", planning + 20)]
        self.assertIn("--state-root state", plan_block)
        self.assertIn("--original-results-root original-results", plan_block)

    def test_actual_synthetic_staging_plan_step_still_runs_without_production_authority(self) -> None:
        import os
        import textwrap

        workflow = (ROOT / ".github/workflows/reconstruct-staging.yml").read_text()
        start = workflow.index("      - name: Build one due execution plan")
        end = workflow.index("      - name:", start + 20)
        body = textwrap.dedent(workflow[start:end].split("        run: |\n", 1)[1])
        environment = dict(os.environ, RUNNER_TEMP=str(self.root))
        # Exercise the authored workflow shell, including its fixture copy and
        # CLI, rather than duplicating that preparation in this regression.
        completed = subprocess.run(["bash", "-e", "-c", body], cwd=ROOT,
                                   env=environment, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads((self.root / "staging-release-queue.json").read_text())["environment"], "staging")
        plan = json.loads((self.root / "release-plan.json").read_text())
        self.assertEqual(plan["kind"], "execution")
        self.assertNotIn("controller", plan["request"])
        self.assertEqual(json.loads((ROOT / "tests/fixtures/release-queue-v1.json").read_text())["environment"], "production")


if __name__ == "__main__":
    unittest.main()
