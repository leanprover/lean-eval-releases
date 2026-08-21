from __future__ import annotations

import copy
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "scripts"))

from release_orchestrator import (  # noqa: E402
    ReleaseError,
    canonical_release_path,
    plan_next,
    validate_release_queue,
)


ROOT = pathlib.Path(__file__).parents[1]


class ReleaseOrchestratorTests(unittest.TestCase):
    def queue(self) -> dict[str, object]:
        return json.loads(
            (ROOT / "tests/fixtures/release-queue-v1.json").read_text(encoding="utf-8")
        )

    def task(self, queue: dict[str, object]) -> dict[str, object]:
        tasks = queue["tasks"]
        assert isinstance(tasks, list)
        task = tasks[0]
        assert isinstance(task, dict)
        return task

    def test_tracked_queue_is_valid_and_due_retry_is_exact(self) -> None:
        queue = self.queue()
        self.assertIs(validate_release_queue(queue), queue)
        task = self.task(queue)
        plan = plan_next(queue, "2026-10-20T06:07:05.000Z")
        self.assertEqual(plan["kind"], "execution")
        self.assertEqual(plan["started_transition"], {
            "event_type": "release.started",
            "subject_id": task["result_id"],
            "causation_event_id": task["event_id"],
            "payload": {"attempt": 2},
        })
        request = plan["request"]
        self.assertEqual(request["archive"]["archive_path"], task["archive_path"])
        self.assertTrue(request["archive"]["encrypted"])
        self.assertEqual(
            request["release"]["path"],
            canonical_release_path(task["result_id"], task["release_at"]),
        )
        self.assertEqual(request["release"]["license"], "Apache-2.0")

    def test_empty_and_not_due_are_nonexecuting(self) -> None:
        queue = self.queue()
        self.assertEqual(
            plan_next(queue, "2026-10-20T06:07:04.999Z"),
            {
                "schema_version": 1,
                "kind": "not_due",
                "next_release_at": "2026-10-20T06:07:05.000Z",
            },
        )
        queue["tasks"] = []
        self.assertEqual(
            plan_next(queue, "2026-10-20T06:07:05.000Z"),
            {"schema_version": 1, "kind": "empty"},
        )

    def test_identity_archive_embargo_and_consent_are_recomputed(self) -> None:
        mutations = (
            ("result_id", "r2_" + "0" * 64, "deterministic identity"),
            ("archive_path", "archives/ff/wrong.tar.age", "submission_id"),
            ("release_at", "2026-10-20T06:07:04.999Z", "two UTC calendar months"),
            ("publication_choice", "withheld", "must be scheduled"),
        )
        for field, value, message in mutations:
            with self.subTest(field=field):
                queue = self.queue()
                self.task(queue)[field] = value
                with self.assertRaisesRegex(ReleaseError, message):
                    validate_release_queue(queue)

    def test_status_fields_and_order_are_strict(self) -> None:
        queue = self.queue()
        task = self.task(queue)
        task["status"] = "scheduled"
        with self.assertRaisesRegex(ReleaseError, "fields are not canonical"):
            validate_release_queue(queue)

        queue = self.queue()
        task = self.task(queue)
        task["status"] = "scheduled"
        task.pop("reason_code")
        task.pop("retryable")
        self.assertIs(validate_release_queue(queue), queue)
        self.assertEqual(
            plan_next(queue, "2026-10-20T06:07:05.000Z")["started_transition"]["payload"],
            {"attempt": 2},
        )

        queue = self.queue()
        second = copy.deepcopy(self.task(queue))
        tasks = queue["tasks"]
        assert isinstance(tasks, list)
        tasks.append(second)
        with self.assertRaisesRegex(ReleaseError, "unique and sorted"):
            validate_release_queue(queue)

    def test_metadata_is_closed_and_bounded(self) -> None:
        queue = self.queue()
        self.task(queue)["production_metadata"] = {"unknown": "value"}
        with self.assertRaisesRegex(ReleaseError, "unknown fields"):
            validate_release_queue(queue)

        queue = self.queue()
        self.task(queue)["production_metadata"] = {"notes": "bad\u0000text"}
        with self.assertRaisesRegex(ReleaseError, "control-free"):
            validate_release_queue(queue)


if __name__ == "__main__":
    unittest.main()
