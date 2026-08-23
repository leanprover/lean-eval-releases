from __future__ import annotations

import base64
import copy
import datetime as dt
import hashlib
import json
import pathlib
import tempfile
import unittest

from scripts.release_controller import (
    ControllerError,
    archive_key_id,
    capability_digest,
    prepare_unwrap,
    recover_running,
    staging_smoke_plan,
    started_event,
    terminal_event,
    unwrap_identity,
    uuid7,
)
from scripts.release_orchestrator import plan_next


ROOT = pathlib.Path(__file__).parents[1]
NOW = "2026-10-20T06:07:05.000Z"


class ReleaseControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        queue = json.loads(
            (ROOT / "tests/fixtures/release-queue-v1.json").read_text(encoding="utf-8")
        )
        self.plan = plan_next(queue, NOW)
        self.ciphertext = b"one exact encrypted archive"
        digest = hashlib.sha256(self.ciphertext).hexdigest()
        self.plan["request"]["archive"]["archive_ciphertext_sha256"] = digest
        recipient = "age1" + "q" * 40
        submission_id = self.plan["request"]["submission"]["submission_id"]
        self.envelope = {
            "schema_version": 1,
            "submission_id": submission_id,
            "archive_ciphertext_sha256": digest,
            "data_key_id": archive_key_id(submission_id, recipient),
            "age_recipient": recipient,
            "adapter": "aws-kms-v1",
            "wrapped_identity": base64.b64encode(b"wrapped identity").decode("ascii"),
        }
        self.sidecar = {
            "schema_version": 3,
            "submission_id": submission_id,
            "submission_repo": "kim-em/private-solution",
            "submission_ref": "1" * 40,
            "submission_kind": "github_repo",
            "submission_public": False,
            "submitter": "kim-em",
            "model": "Example Model",
            "size_bytes_plaintext_tar": 123,
            "sha256_plaintext_tar": "2" * 64,
            "sha256_ciphertext": digest,
            "size_bytes_ciphertext": len(self.ciphertext),
            "archived_at": "2026-08-20T06:08:00Z",
            "benchmark_commit": "3" * 40,
            "archiver_workflow_run": (
                "https://github.com/leanprover/lean-eval-submissions/actions/runs/123456"
            ),
            "key_envelope": self.envelope,
        }

    def test_automatic_workflow_is_gated_scoped_and_source_artifact_free(self) -> None:
        workflow = (ROOT / ".github/workflows/release-controller.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("cron: '23 4 * * *'", workflow)
        self.assertIn("vars.PUBLICATION_ENABLED == 'true'", workflow)
        self.assertIn("environment: release-production", workflow)
        self.assertIn("id-token: write", workflow)
        self.assertIn("secrets.RELEASE_PUBLISH_KEY", workflow)
        self.assertIn("secrets.PRODUCTION_STATE_CONTROLLER_KEY", workflow)
        self.assertIn("secrets.AUDIT_READ_KEY", workflow)
        self.assertIn("vars.AWS_RELEASE_UNWRAP_ROLE_ARN", workflow)
        self.assertIn("repository: leanprover/lean-eval-audit", workflow)
        self.assertIn("ref: ${{ steps.plan.outputs.archive_commit }}", workflow)
        self.assertIn("lean-eval-archive-unwrap-production", workflow)
        self.assertIn("state-event started", workflow)
        self.assertIn("state-event published", workflow)
        self.assertIn("state-event failed", workflow)
        self.assertNotIn("upload-artifact", workflow)
        self.assertNotIn("actions/download-artifact", workflow)

    def test_staging_release_smoke_is_exact_decrypt_only_and_source_artifact_free(self) -> None:
        workflow = (
            ROOT / ".github/workflows/credentialed-release-staging-smoke.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("environment: release-staging", workflow)
        self.assertIn("repository: leanprover/lean-eval-state-staging", workflow)
        self.assertIn("repository: leanprover/lean-eval-audit", workflow)
        self.assertIn("ref: ${{ steps.plan.outputs.archive_commit }}", workflow)
        self.assertIn("secrets.STAGING_STATE_READ_KEY", workflow)
        self.assertIn("secrets.AUDIT_READ_KEY", workflow)
        self.assertIn("lean-eval-archive-unwrap-staging", workflow)
        self.assertIn("staging-smoke-plan", workflow)
        self.assertIn("sha256sum", workflow)
        self.assertNotIn("RELEASE_PUBLISH_KEY", workflow)
        self.assertNotIn("state-event", workflow)
        self.assertNotIn("git push", workflow)
        self.assertNotIn("upload-artifact", workflow)
        self.assertNotIn("reconstruct_release.py", workflow)

    def request(self) -> dict[str, object]:
        return prepare_unwrap(
            self.plan,
            self.sidecar,
            self.ciphertext,
            NOW,
            random_bytes=bytes(range(10)),
            runner_nonce="a" * 64,
        )

    def test_uuid7_has_frozen_timestamp_version_and_variant(self) -> None:
        timestamp = dt.datetime(2026, 10, 20, 6, 7, 5, tzinfo=dt.timezone.utc)
        self.assertEqual(
            uuid7(timestamp, bytes(range(10))),
            "01a157eb-ab28-7001-8203-040506070809",
        )

    def test_prepare_unwrap_binds_exact_plan_sidecar_and_ciphertext(self) -> None:
        request = self.request()
        self.assertEqual(request["expected_purpose"], "lean-eval-release")
        self.assertEqual(request["expected_runner_nonce"], "a" * 64)
        capability = request["capability"]
        self.assertEqual(capability["issued_at"], NOW)
        self.assertEqual(capability["expires_at"], "2026-10-20T06:12:05.000Z")
        self.assertEqual(capability["max_uses"], 1)
        self.assertEqual(capability["archive_commit"], "b" * 40)

    def test_staging_smoke_selects_one_scheduled_submission_without_changing_embargo(self) -> None:
        queue = json.loads(
            (ROOT / "tests/fixtures/release-queue-v1.json").read_text(encoding="utf-8")
        )
        submission_id = queue["tasks"][0]["submission_id"]
        with self.assertRaisesRegex(ControllerError, "staging release queue"):
            staging_smoke_plan(queue, submission_id)
        queue["environment"] = "staging"
        plan = staging_smoke_plan(queue, submission_id)
        self.assertEqual(plan["kind"], "execution")
        self.assertEqual(plan["request"]["submission"]["submission_id"], submission_id)
        self.assertEqual(
            plan["request"]["release"]["eligible_at"],
            queue["tasks"][0]["release_at"],
        )
        with self.assertRaisesRegex(ControllerError, "exactly one"):
            staging_smoke_plan(queue, "0198abcd-0000-7000-8000-000000000099")

    def test_prepare_unwrap_rejects_each_binding_layer(self) -> None:
        changed = copy.deepcopy(self.sidecar)
        changed["sha256_ciphertext"] = "0" * 64
        with self.assertRaisesRegex(ControllerError, "sidecar ciphertext digest"):
            prepare_unwrap(self.plan, changed, self.ciphertext, NOW)

        changed = copy.deepcopy(self.sidecar)
        changed["key_envelope"]["submission_id"] = (
            "0198abcd-0000-7000-8000-000000000003"
        )
        with self.assertRaisesRegex(ControllerError, "data_key_id"):
            prepare_unwrap(self.plan, changed, self.ciphertext, NOW)

        with self.assertRaisesRegex(ControllerError, "ciphertext bytes digest"):
            prepare_unwrap(
                self.plan,
                self.sidecar,
                b"X" + self.ciphertext[1:],
                NOW,
            )

        changed = copy.deepcopy(self.sidecar)
        changed["unexpected"] = True
        with self.assertRaisesRegex(ControllerError, "fields are not canonical"):
            prepare_unwrap(self.plan, changed, self.ciphertext, NOW)

        changed = copy.deepcopy(self.sidecar)
        changed["size_bytes_ciphertext"] += 1
        with self.assertRaisesRegex(ControllerError, "ciphertext size"):
            prepare_unwrap(self.plan, changed, self.ciphertext, NOW)

    def test_unwrap_response_is_exactly_bound_and_returns_one_identity(self) -> None:
        request = self.request()
        identity = b"# created by age-keygen\nAGE-SECRET-KEY-1EXAMPLE\n"
        response = {
            "schema_version": 1,
            "adapter": request["adapter"],
            "request_id": request["capability"]["request_id"],
            "data_key_id": request["envelope"]["data_key_id"],
            "capability_digest": capability_digest(request["capability"]),
            "plaintext_identity_base64": base64.b64encode(identity).decode("ascii"),
        }
        self.assertEqual(unwrap_identity(request, response, {"StatusCode": 200}), identity)
        changed = {**response, "request_id": "0198abcd-0000-7000-8000-000000000099"}
        with self.assertRaisesRegex(ControllerError, "exact request"):
            unwrap_identity(request, changed, {"StatusCode": 200})
        with self.assertRaisesRegex(ControllerError, "successful invocation"):
            unwrap_identity(
                request,
                response,
                {"StatusCode": 200, "FunctionError": "Unhandled"},
            )

    def test_state_events_preserve_causation_attempt_and_publication_evidence(self) -> None:
        started = started_event(
            self.plan,
            NOW,
            random_bytes=bytes(range(10)),
        )
        self.assertEqual(started["event_type"], "release.started")
        self.assertEqual(started["causation_event_id"], self.plan["started_transition"]["causation_event_id"])
        self.assertEqual(started["payload"], {"attempt": 2})

        published = terminal_event(
            started,
            "2026-10-20T06:07:06.000Z",
            "published",
            repository_commit="1" * 40,
            tree_digest="2" * 64,
            release_path=self.plan["request"]["release"]["path"],
            random_bytes=bytes(range(10, 20)),
        )
        self.assertEqual(published["causation_event_id"], started["event_id"])
        self.assertEqual(published["payload"]["attempt"], 2)
        self.assertEqual(published["payload"]["repository_commit"], "1" * 40)

        failed = terminal_event(
            started,
            "2026-10-20T06:07:06.000Z",
            "failed",
            reason_code="provider_error",
            retryable=True,
            random_bytes=bytes(range(10, 20)),
        )
        self.assertEqual(failed["payload"], {
            "attempt": 2,
            "reason_code": "provider_error",
            "retryable": True,
        })

    def test_interrupted_release_recovery_is_fail_closed_and_idempotent(self) -> None:
        task = copy.deepcopy(
            json.loads(
                (ROOT / "tests/fixtures/release-queue-v1.json").read_text(
                    encoding="utf-8"
                )
            )["tasks"][0]
        )
        task.update(
            status="running",
            event_id="0198abcd-0000-7000-8000-000000000099",
            occurred_at="2026-10-20T04:00:00.000Z",
            attempt=2,
        )
        domain = {"release_tasks": [task]}
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            failed = recover_running(domain, root, NOW)
            self.assertEqual(failed["kind"], "failed")
            self.assertEqual(failed["reason_code"], "controller_interrupted")

            release_root = root.joinpath(*(
                f"releases/2026/10/{task['result_id']}".split("/")
            ))
            release_root.mkdir(parents=True)
            for name, content in (
                ("Submission.lean", b"example : True := by trivial\n"),
                ("metadata.json", b"{}\n"),
                ("LICENSE", b"test license\n"),
            ):
                path = release_root / name
                path.write_bytes(content)
                path.chmod(0o644)
            published = recover_running(domain, root, NOW)
            self.assertEqual(published["kind"], "published")
            self.assertEqual(published["release_path"], f"releases/2026/10/{task['result_id']}")
            self.assertRegex(published["tree_digest"], r"^[0-9a-f]{64}$")

            recent = copy.deepcopy(domain)
            recent["release_tasks"][0]["occurred_at"] = "2026-10-20T05:30:00.000Z"
            self.assertEqual(recover_running(recent, root, NOW)["kind"], "busy")


if __name__ == "__main__":
    unittest.main()
