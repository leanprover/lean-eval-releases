from __future__ import annotations

import base64
import copy
import datetime as dt
import hashlib
import json
import pathlib
import re
import subprocess
import tempfile
import unittest

from scripts.release_controller import (
    ControllerError,
    archive_key_id,
    canonical_json,
    capability_digest,
    plan_release_state_transition,
    prepare_unwrap,
    recover_running,
    result_release_status_path,
    stage_release_state_transition,
    staging_smoke_plan,
    started_event,
    terminal_event,
    unwrap_identity,
    uuid7,
    verify_staged_release_state_transition,
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
        self.assertIn("github.repository == 'leanprover/lean-eval-releases'", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("vars.PUBLICATION_ENABLED == 'true'", workflow)
        self.assertIn("environment: release-production", workflow)
        self.assertIn("id-token: write", workflow)
        self.assertIn("secrets.RELEASE_PUBLISH_KEY", workflow)
        self.assertIn("secrets.PRODUCTION_STATE_CONTROLLER_KEY", workflow)
        self.assertIn("secrets.AUDIT_READ_KEY", workflow)
        self.assertIn("vars.AWS_RELEASE_UNWRAP_ROLE_ARN", workflow)
        self.assertRegex(
            workflow,
            re.compile(
                r"- uses: actions/checkout@[0-9a-f]{40}\n"
                r"        with:\n"
                r"          ref: main\n"
                r"          fetch-depth: 0\n"
                r"          persist-credentials: true"
            ),
        )
        self.assertIn("scripts/release_qualification.py", workflow)
        self.assertIn("scripts/verify_release_state_contract.py", workflow)
        self.assertIn("--environment production", workflow)
        self.assertLess(
            workflow.index("scripts/verify_release_state_contract.py"),
            workflow.index("state/scripts/state.py"),
        )
        self.assertIn("--mode publication", workflow)
        self.assertIn("--controller-qualification", workflow)
        self.assertIn("--require-controller-qualification", workflow)
        self.assertIn(".request.controller.mode", workflow)
        self.assertIn(".request.controller.environment", workflow)
        self.assertIn(
            "configuration/release-controller-credential-contract-v1.json",
            workflow,
        )
        self.assertIn("repository: leanprover/lean-eval-audit", workflow)
        self.assertIn("ref: ${{ steps.plan.outputs.archive_commit }}", workflow)
        self.assertIn("lean-eval-archive-unwrap-production", workflow)
        self.assertIn("--max-filesize 16777216", workflow)
        self.assertIn("state-event started", workflow)
        self.assertIn("state-event published", workflow)
        self.assertIn("state-event failed", workflow)
        self.assertNotIn("upload-artifact", workflow)
        self.assertNotIn("actions/download-artifact", workflow)
        self.assertIn("scripts/classify_release_publication.py", workflow)
        self.assertIn("--history-only", workflow)
        self.assertIn("publishing-manifest.json", workflow)
        self.assertIn("jq -er .repository_commit", workflow)
        self.assertIn("jq -er --arg result", workflow)
        self.assertNotIn("git log --diff-filter=A --format=%H -1", workflow)
        self.assertEqual(
            workflow.count("release_controller.py stage-state-transition"), 4
        )
        self.assertEqual(
            workflow.count("release_controller.py verify-staged-state-transition"), 4
        )
        self.assertEqual(workflow.count("--protected-main-commit"), 4)
        self.assertNotIn("state.py --root state append", workflow)
        self.assertNotIn("git -C state rebase", workflow)

    def assert_release_invoke_session_boundary(
        self,
        workflow: str,
        *,
        environment: str,
        function_name: str,
        session_name: str,
    ) -> None:
        role_arn = (
            "arn:aws:iam::161072922960:role/"
            f"lean-eval-release-unwrap-invoker-{environment}"
        )
        function_arn = (
            "arn:aws:lambda:us-east-1:161072922960:function:"
            f"{function_name}:live"
        )
        role_guard = (
            'test "$CONFIGURED_ROLE_ARN" = \\\n'
            f"            {role_arn}"
        )
        self.assertIn(
            "CONFIGURED_ROLE_ARN: ${{ vars.AWS_RELEASE_UNWRAP_ROLE_ARN }}",
            workflow,
        )
        self.assertIn(role_guard, workflow)
        self.assertIn(
            "role-to-assume: ${{ vars.AWS_RELEASE_UNWRAP_ROLE_ARN }}", workflow
        )
        self.assertIn("role-duration-seconds: 900", workflow)
        self.assertIn(f"role-session-name: {session_name}", workflow)
        self.assertIn("retry-max-attempts: 4", workflow)
        self.assertIn("allowed-account-ids: 161072922960", workflow)
        self.assertIn("output-credentials: false", workflow)
        self.assertIn("output-env-credentials: true", workflow)
        self.assertIn("unset-current-credentials: true", workflow)
        self.assertEqual(workflow.count("inline-session-policy: >-"), 1)
        self.assertEqual(workflow.count('"Action":"lambda:InvokeFunction"'), 1)
        self.assertEqual(
            workflow.count('"Resource":"arn:aws:lambda:'),
            1,
        )
        self.assertNotIn('"Action":"lambda:*"', workflow)
        self.assertIn(
            '"Effect":"Allow","Action":"lambda:InvokeFunction",'
            f'"Resource":"{function_arn}"',
            workflow,
        )
        self.assertIn(
            '"Effect":"Allow","Action":"sts:GetCallerIdentity",'
            '"Resource":"*"',
            workflow,
        )
        self.assertLess(
            workflow.index(role_guard),
            workflow.index("uses: aws-actions/configure-aws-credentials@"),
        )
        self.assertLess(
            workflow.index("uses: aws-actions/configure-aws-credentials@"),
            workflow.index(f"--function-name {function_name}"),
        )

    def assert_final_authority_step(
        self,
        workflow: str,
        *,
        final_step_name: str,
        final_condition: str,
        function_name: str,
    ) -> None:
        action = "uses: aws-actions/configure-aws-credentials@"
        action_index = workflow.index(action)
        authority_tail = workflow[action_index:]
        authored_steps = re.findall(
            r"^      - (?:name|uses|run): (.+)$", authority_tail, re.MULTILINE
        )
        self.assertEqual(authored_steps, [final_step_name])
        self.assertIn(f"      - name: {final_step_name}\n", authority_tail)
        self.assertIn(f"        if: {final_condition}\n", authority_tail)
        self.assertIn(
            "id: aws\n"
            "        uses: aws-actions/configure-aws-credentials@",
            workflow,
        )
        self.assertIn("AWS_STEP_OUTCOME: ${{ steps.aws.outcome }}", authority_tail)
        self.assertRegex(authority_tail, r"trap (?:cleanup|finish) EXIT")
        self.assertIn(
            "GitHub injects a fresh OIDC request handle into every step",
            authority_tail,
        )
        oidc_drop = authority_tail.index(
            'clear_oidc\n          if [ "$AWS_STEP_OUTCOME" != success ]'
        )
        invoke = authority_tail.index(f"--function-name {function_name}")
        authority_drop = authority_tail.index("          clear_authority\n", invoke)
        decrypt = authority_tail.index('"$RUNNER_TEMP/age-bin" --decrypt', invoke)
        self.assertLess(oidc_drop, invoke)
        self.assertLess(invoke, authority_drop)
        self.assertLess(authority_drop, decrypt)
        for variable in (
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_URL",
        ):
            with self.subTest(variable=variable):
                self.assertRegex(
                    authority_tail,
                    rf"unset [^\n]*\b{re.escape(variable)}\b",
                )
                self.assertIn(f"echo '{variable}='", authority_tail)
                self.assertIn(f'test -z "${{{variable}:-}}"', authority_tail)

    def assert_later_authority_step_is_rejected(
        self,
        workflow: str,
        *,
        final_step_name: str,
        final_condition: str,
        function_name: str,
    ) -> None:
        hostile = workflow.rstrip() + "\n\n      - run: env\n"
        with self.assertRaises(AssertionError):
            self.assert_final_authority_step(
                hostile,
                final_step_name=final_step_name,
                final_condition=final_condition,
                function_name=function_name,
            )

    def test_automatic_workflow_closes_the_aws_session_boundary(self) -> None:
        workflow = (ROOT / ".github/workflows/release-controller.yml").read_text(
            encoding="utf-8"
        )
        self.assert_release_invoke_session_boundary(
            workflow,
            environment="production",
            function_name="lean-eval-archive-unwrap-production",
            session_name="lean-eval-release-controller",
        )
        final_step_name = (
            "Consume capability and finish one release under one authority boundary"
        )
        final_condition = "always() && steps.started.outputs.recorded == 'true'"
        self.assert_final_authority_step(
            workflow,
            final_step_name=final_step_name,
            final_condition=final_condition,
            function_name="lean-eval-archive-unwrap-production",
        )
        authority_tail = workflow[
            workflow.index("uses: aws-actions/configure-aws-credentials@") :
        ]
        invoke = authority_tail.index(
            "--function-name lean-eval-archive-unwrap-production"
        )
        authority_drop = authority_tail.index("          clear_authority\n", invoke)
        for command in (
            "scripts/reconstruct_release.py",
            "scripts/classify_release_publication.py",
            "state-event published",
        ):
            with self.subTest(command=command):
                self.assertGreater(authority_tail.index(command), authority_drop)
        self.assertIn(
            "clear_authority\n"
            '            if [ "$status" -ne 0 ] && '
            '[ "$publication_recorded" = false ]; then\n'
            "              record_retryable_failure",
            authority_tail,
        )
        self.assert_later_authority_step_is_rejected(
            workflow,
            final_step_name=final_step_name,
            final_condition=final_condition,
            function_name="lean-eval-archive-unwrap-production",
        )

    def test_production_credential_preflight_is_manual_and_nonmutating(self) -> None:
        workflow = (
            ROOT / ".github/workflows/verify-production-controller-credentials.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("schedule:", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn("push:\n", workflow)
        self.assertNotIn("workflow_call:", workflow)
        self.assertNotIn("secrets[", workflow)
        self.assertNotIn("toJSON(secrets", workflow)
        self.assertNotIn("secrets: inherit", workflow)
        self.assertIn("github.repository == 'leanprover/lean-eval-releases'", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("inputs.confirm_publication_disabled == true", workflow)
        self.assertIn("environment: release-production", workflow)
        self.assertIn("group: lean-eval-release-controller-production", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("contents: read", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("id-token: write", workflow)
        self.assertIn("secrets.RELEASE_PUBLISH_KEY", workflow)
        self.assertIn("secrets.PRODUCTION_STATE_CONTROLLER_KEY", workflow)
        self.assertNotIn("secrets.AUDIT_READ_KEY", workflow)
        self.assertIn("PUBLICATION_ENABLED must remain absent or false", workflow)
        self.assertIn("python state/scripts/state.py --root state validate", workflow)
        self.assertIn('--output "$RUNNER_TEMP/state-views"', workflow)
        self.assertGreaterEqual(workflow.count("fetch-depth: 0"), 2)
        self.assertIn("scripts/release_qualification.py", workflow)
        self.assertIn("scripts/verify_release_state_contract.py", workflow)
        self.assertIn("--environment production", workflow)
        self.assertLess(
            workflow.index("scripts/verify_release_state_contract.py"),
            workflow.index("state/scripts/state.py"),
        )
        self.assertIn("--mode preflight", workflow)
        self.assertEqual(workflow.count("push --dry-run --porcelain"), 1)
        push_lines = [
            line for line in workflow.splitlines() if re.search(r"\bgit\b.*\bpush\b", line)
        ]
        self.assertEqual(len(push_lines), 1)
        self.assertIn("--dry-run", push_lines[0])
        self.assertIn("':(exclude)state'", workflow)
        self.assertNotIn("git commit", workflow)
        self.assertNotIn("state.py --root state append", workflow)
        self.assertNotIn("release_controller.py", workflow)
        self.assertNotIn("release_orchestrator.py", workflow)
        self.assertNotIn("configure-aws-credentials", workflow)
        self.assertNotIn("aws ", workflow)
        self.assertNotIn("upload-artifact", workflow)

    def test_production_audit_read_preflight_is_isolated_and_nonmutating(
        self,
    ) -> None:
        workflow = (
            ROOT
            / ".github/workflows/verify-production-audit-read-credential.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("schedule:", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn("push:\n", workflow)
        self.assertIn("DISPATCH_REPOSITORY: ${{ github.repository }}", workflow)
        self.assertIn("DISPATCH_REF: ${{ github.ref }}", workflow)
        self.assertIn(
            "CONFIRM_PUBLICATION_DISABLED: ${{ inputs.confirm_publication_disabled }}",
            workflow,
        )
        self.assertIn(
            'test "$DISPATCH_REPOSITORY" = leanprover/lean-eval-releases', workflow
        )
        self.assertIn('test "$DISPATCH_REF" = refs/heads/main', workflow)
        self.assertIn('test "$CONFIRM_PUBLICATION_DISABLED" = true', workflow)
        self.assertIn("needs: authorize", workflow)
        self.assertIn("github.repository == 'leanprover/lean-eval-releases'", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("inputs.confirm_publication_disabled == true", workflow)
        self.assertIn("environment: release-production", workflow)
        self.assertIn(
            "group: lean-eval-release-controller-production-audit-read-preflight",
            workflow,
        )
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertEqual(workflow.count("runs-on:"), 2)
        self.assertIn("contents: read", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("id-token: write", workflow)
        self.assertEqual(
            set(re.findall(r"secrets\.([A-Z0-9_]+)", workflow)),
            {"AUDIT_READ_KEY"},
        )
        self.assertNotIn("RELEASE_PUBLISH_KEY", workflow)
        self.assertNotIn("PRODUCTION_STATE_CONTROLLER_KEY", workflow)
        self.assertNotIn("STAGING_STATE_READ_KEY", workflow)
        self.assertIn("repository: leanprover/lean-eval-audit", workflow)
        self.assertNotIn("repository: leanprover/lean-eval-state", workflow)
        self.assertIn("PUBLICATION_ENABLED must remain absent or false", workflow)
        self.assertIn("persist-credentials: true", workflow)
        self.assertIn("fetch-depth: 1", workflow)
        self.assertIn("/.audit-read-proof", workflow)
        self.assertIn("sparse-checkout-cone-mode: false", workflow)
        self.assertIn("filter: blob:none", workflow)
        self.assertIn("test ! -e audit-proof/archives", workflow)
        self.assertIn("test ! -e audit-proof/audit", workflow)
        self.assertIn("GIT_NO_LAZY_FETCH=1", workflow)
        self.assertIn("--batch-all-objects", workflow)
        self.assertIn('grep -Fxq commit <<<"$object_types"', workflow)
        self.assertIn('grep -Fxq tree <<<"$object_types"', workflow)
        self.assertEqual(workflow.count("ls-remote --exit-code"), 1)
        self.assertEqual(workflow.count("before=$(read_main)"), 1)
        self.assertEqual(workflow.count("after=$(read_main)"), 1)
        self.assertEqual(workflow.count("push --dry-run --porcelain"), 1)
        self.assertIn(
            "The key you are authenticating with has been marked as read only.",
            workflow,
        )
        self.assertIn(
            "ERROR: Permission to leanprover/lean-eval-audit.git denied to ",
            workflow,
        )
        self.assertIn("Write access to repository not granted.", workflow)
        push_lines = [
            line for line in workflow.splitlines() if re.search(r"\bgit\b.*\bpush\b", line)
        ]
        self.assertEqual(len(push_lines), 1)
        self.assertIn("--dry-run", push_lines[0])
        for forbidden in (
            "git commit",
            "state.py",
            "release_controller.py",
            "release_orchestrator.py",
            "configure-aws-credentials",
            "aws ",
            "upload-artifact",
            "download-artifact",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, workflow)
        self.assertTrue(workflow.rstrip().endswith('} >> "$GITHUB_STEP_SUMMARY"'))
        self.assertNotIn("- exact audit main:", workflow)
        self.assertEqual(
            re.findall(r"^      - name: (.+)$", workflow, re.MULTILINE),
            [
                "Require an exact protected publication-disabled dispatch",
                "Require the publication latch to remain off",
                "Authenticate to audit without materializing the private corpus",
                "Prove stable read access and denied receive-pack access",
            ],
        )
        self.assertEqual(workflow.count("\n      - "), 4)

        contract = json.loads(
            (
                ROOT
                / "configuration/release-controller-credential-contract-v1.json"
            ).read_text(encoding="utf-8")
        )
        audit_contract = contract["audit"]
        self.assertEqual(audit_contract["credential"], "AUDIT_READ_KEY")
        self.assertEqual(audit_contract["permission"], "contents-read")
        self.assertIn(f"repository: {audit_contract['repository']}", workflow)
        self.assertIn(
            f"git@github.com:{audit_contract['repository']}.git",
            workflow,
        )

    def test_production_audit_read_preflight_rejects_hostile_authority_drift(
        self,
    ) -> None:
        workflow = (
            ROOT
            / ".github/workflows/verify-production-audit-read-credential.yml"
        ).read_text(encoding="utf-8")

        def validate_closed_boundary(candidate: str) -> None:
            self.assertEqual(
                set(re.findall(r"secrets\.([A-Z0-9_]+)", candidate)),
                {"AUDIT_READ_KEY"},
            )
            self.assertIn("permissions: {}", candidate)
            self.assertIn("    permissions:\n      contents: read", candidate)
            self.assertNotIn("id-token: write", candidate)
            self.assertNotIn("workflow_call:", candidate)
            self.assertNotIn("secrets[", candidate)
            self.assertNotIn("toJSON(secrets", candidate)
            self.assertNotIn("secrets: inherit", candidate)
            self.assertIn(
                'test "$DISPATCH_REPOSITORY" = leanprover/lean-eval-releases',
                candidate,
            )
            self.assertIn('test "$DISPATCH_REF" = refs/heads/main', candidate)
            self.assertIn(
                'test "$CONFIRM_PUBLICATION_DISABLED" = true', candidate
            )
            self.assertEqual(candidate.count("runs-on:"), 2)
            self.assertEqual(candidate.count("\n      - "), 4)
            self.assertEqual(candidate.count("uses: actions/checkout@"), 1)
            self.assertIn("repository: leanprover/lean-eval-audit", candidate)
            self.assertNotIn("repository: leanprover/lean-eval-state", candidate)
            self.assertIn("fetch-depth: 1", candidate)
            self.assertNotIn("fetch-depth: 0", candidate)
            self.assertIn("filter: blob:none", candidate)
            self.assertIn(
                "sparse-checkout: |\n            /.audit-read-proof", candidate
            )
            self.assertIn("sparse-checkout-cone-mode: false", candidate)
            self.assertIn("push --dry-run --porcelain", candidate)
            self.assertNotIn("push --porcelain", candidate)

        validate_closed_boundary(workflow)
        hostile_changes = (
            (
                "ssh-key: ${{ secrets.AUDIT_READ_KEY }}",
                "ssh-key: ${{ secrets.RELEASE_PUBLISH_KEY }}",
            ),
            (
                "    permissions:\n      contents: read",
                "    permissions:\n      contents: write",
            ),
            (
                "    permissions:\n      contents: read",
                "    permissions:\n      contents: read\n      id-token: write",
            ),
            (
                "repository: leanprover/lean-eval-audit",
                "repository: leanprover/lean-eval-state",
            ),
            (
                "sparse-checkout: |\n            /.audit-read-proof",
                "sparse-checkout: |\n            /archives",
            ),
            ("sparse-checkout-cone-mode: false", "sparse-checkout-cone-mode: true"),
            ("filter: blob:none", "filter: blob:limit=1m"),
            ("fetch-depth: 1", "fetch-depth: 0"),
            ("push --dry-run --porcelain", "push --porcelain"),
            ("    runs-on: ubuntu-latest", "    runs-on: ubuntu-latest\n    runs-on: other"),
            (
                "      - name: Prove stable read access and denied receive-pack access",
                (
                    "      - uses: actions/checkout@"
                    "0000000000000000000000000000000000000000\n"
                    "      - name: Prove stable read access and denied receive-pack access"
                ),
            ),
            (
                "on:\n  workflow_dispatch:",
                "on:\n  workflow_dispatch:\n  workflow_call:",
            ),
            (
                "ssh-key: ${{ secrets.AUDIT_READ_KEY }}",
                "ssh-key: ${{ secrets['AUDIT_READ_KEY'] }}",
            ),
            (
                "      - name: Prove stable read access and denied receive-pack access",
                (
                    "      - run: env\n"
                    "      - name: Prove stable read access and denied receive-pack access"
                ),
            ),
        )
        for old, new in hostile_changes:
            with self.subTest(change=new):
                self.assertIn(old, workflow)
                with self.assertRaises(AssertionError):
                    validate_closed_boundary(workflow.replace(old, new, 1))

    def test_production_release_oidc_preflight_is_trust_only(self) -> None:
        workflow = (
            ROOT / ".github/workflows/verify-production-release-oidc.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("schedule:", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn("push:\n", workflow)
        self.assertNotIn("workflow_call:", workflow)
        self.assertIn("permissions: {}", workflow)
        self.assertIn(
            "    permissions:\n"
            "      id-token: write\n"
            "    environment: release-production\n",
            workflow,
        )
        self.assertNotIn("contents:", workflow)
        self.assertEqual(workflow.count("id-token: write"), 1)
        self.assertEqual(workflow.count("runs-on:"), 3)
        self.assertIn("needs: authorize", workflow)
        self.assertIn("github.repository == 'leanprover/lean-eval-releases'", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("inputs.confirm_publication_disabled == true", workflow)
        self.assertIn("environment: release-production", workflow)
        self.assertIn(
            "group: lean-eval-release-controller-production-oidc-preflight",
            workflow,
        )
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("PUBLICATION_ENABLED must remain absent or false", workflow)
        self.assertEqual(re.findall(r"secrets\.([A-Z0-9_]+)", workflow), [])
        self.assertNotIn("secrets[", workflow)
        self.assertNotIn("toJSON(secrets", workflow)
        self.assertNotIn("secrets: inherit", workflow)
        expected_role = (
            "arn:aws:iam::161072922960:role/"
            "lean-eval-release-unwrap-invoker-production"
        )
        expected_caller = (
            "arn:aws:sts::161072922960:assumed-role/"
            "lean-eval-release-unwrap-invoker-production/"
            "lean-eval-release-production-oidc-preflight"
        )
        self.assertIn("role-to-assume: ${{ vars.AWS_RELEASE_UNWRAP_ROLE_ARN }}", workflow)
        self.assertIn(expected_role, workflow)
        self.assertIn(expected_caller, workflow)
        self.assertIn("role-duration-seconds: 900", workflow)
        self.assertIn(
            "role-session-name: lean-eval-release-production-oidc-preflight",
            workflow,
        )
        self.assertIn("retry-max-attempts: 4", workflow)
        self.assertIn("allowed-account-ids: 161072922960", workflow)
        self.assertIn("output-credentials: false", workflow)
        self.assertIn("output-env-credentials: true", workflow)
        self.assertIn("unset-current-credentials: true", workflow)
        self.assertIn(
            '"Effect":"Allow","Action":"sts:GetCallerIdentity",'
            '"Resource":"*"',
            workflow,
        )
        self.assertEqual(workflow.count("uses:"), 1)
        self.assertRegex(
            workflow,
            re.compile(
                r"uses: aws-actions/configure-aws-credentials@[0-9a-f]{40}"
            ),
        )
        self.assertEqual(workflow.count("aws sts get-caller-identity"), 2)
        self.assertEqual(workflow.count("aws "), 2)
        self.assertIn("*:lean-eval-release-production-oidc-preflight", workflow)
        for variable in (
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_URL",
        ):
            with self.subTest(variable=variable):
                self.assertIn(f"unset {variable}", workflow)
                self.assertIn(f"echo '{variable}='", workflow)
                self.assertIn(f'test -z "${{{variable}:-}}"', workflow)
        self.assertIn(
            'rm -f "$RUNNER_TEMP/production-release-caller-identity.json"',
            workflow,
        )
        self.assertIn("trap cleanup EXIT", workflow)
        self.assertIn("trap - EXIT", workflow)
        self.assertIn("export AWS_EC2_METADATA_DISABLED=true", workflow)
        self.assertIn("AWS authority survived cleanup", workflow)
        self.assertIn("  summarize:\n    needs: oidc-trust\n    permissions: {}", workflow)
        self.assertEqual(workflow.count("\n      - "), 5)
        self.assertEqual(
            re.findall(r"^      - name: (.+)$", workflow, re.MULTILINE),
            [
                "Require an exact protected publication-disabled dispatch",
                "Require the publication latch and role boundary",
                "Assume only the production release Invoke role",
                "Prove exact caller identity and discard all authority handles",
                "Record a source-free trust proof",
            ],
        )
        for forbidden in (
            "actions/checkout",
            "repository:",
            "git ",
            "aws lambda",
            "lean-eval-archive-unwrap",
            "state.py",
            "release_controller.py",
            "release_orchestrator.py",
            "upload-artifact",
            "download-artifact",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, workflow)

    def test_production_release_oidc_preflight_rejects_authority_drift(
        self,
    ) -> None:
        workflow = (
            ROOT / ".github/workflows/verify-production-release-oidc.yml"
        ).read_text(encoding="utf-8")

        def validate_closed_boundary(candidate: str) -> None:
            self.assertIn("permissions: {}", candidate)
            self.assertIn(
                "    permissions:\n"
                "      id-token: write\n"
                "    environment: release-production\n",
                candidate,
            )
            self.assertEqual(candidate.count("id-token: write"), 1)
            self.assertNotIn("contents:", candidate)
            self.assertNotIn("workflow_call:", candidate)
            self.assertEqual(candidate.count("runs-on:"), 3)
            self.assertEqual(candidate.count("uses:"), 1)
            self.assertEqual(
                re.findall(r"secrets\.([A-Z0-9_]+)", candidate), []
            )
            self.assertIn(
                "arn:aws:iam::161072922960:role/"
                "lean-eval-release-unwrap-invoker-production",
                candidate,
            )
            self.assertEqual(candidate.count("aws sts get-caller-identity"), 2)
            self.assertNotIn("aws lambda", candidate)
            self.assertNotIn("actions/checkout", candidate)
            self.assertIn("trap cleanup EXIT", candidate)
            self.assertIn("trap - EXIT", candidate)
            self.assertIn("ACTIONS_ID_TOKEN_REQUEST_TOKEN=", candidate)
            self.assertIn("AWS_SESSION_TOKEN=", candidate)
            self.assertIn("output-credentials: false", candidate)
            self.assertIn("output-env-credentials: true", candidate)
            self.assertIn(
                '"Effect":"Allow","Action":"sts:GetCallerIdentity",'
                '"Resource":"*"',
                candidate,
            )
            self.assertIn("AWS authority survived cleanup", candidate)
            self.assertIn(
                "  summarize:\n    needs: oidc-trust\n    permissions: {}",
                candidate,
            )
            self.assertEqual(candidate.count("\n      - "), 5)
            self.assertEqual(
                re.findall(r"^      - name: (.+)$", candidate, re.MULTILINE),
                [
                    "Require an exact protected publication-disabled dispatch",
                    "Require the publication latch and role boundary",
                    "Assume only the production release Invoke role",
                    "Prove exact caller identity and discard all authority handles",
                    "Record a source-free trust proof",
                ],
            )

        validate_closed_boundary(workflow)
        hostile_changes = (
            (
                "    permissions:\n      id-token: write",
                "    permissions:\n      contents: read\n      id-token: write",
            ),
            (
                "      id-token: write\n    environment: release-production",
                (
                    "      id-token: write\n      actions: write\n"
                    "    environment: release-production"
                ),
            ),
            (
                "on:\n  workflow_dispatch:",
                "on:\n  workflow_dispatch:\n  workflow_call:",
            ),
            (
                "      - name: Record a source-free trust proof",
                "      - uses: actions/checkout@" + "0" * 40 + "\n"
                "      - name: Record a source-free trust proof",
            ),
            (
                "      - name: Prove exact caller identity and discard all authority handles",
                (
                    "      - run: env\n"
                    "      - name: Prove exact caller identity and discard all authority handles"
                ),
            ),
            (
                "lean-eval-release-unwrap-invoker-production",
                "AdministratorAccess",
            ),
            (
                "aws sts get-caller-identity",
                "aws lambda list-functions",
            ),
            ("trap cleanup EXIT", "trap - EXIT"),
            ("trap - EXIT", "true # keep the EXIT trap"),
            ("ACTIONS_ID_TOKEN_REQUEST_TOKEN=", "OIDC_TOKEN_RETAINED=true"),
            ("AWS_SESSION_TOKEN=", "AWS_SESSION_RETAINED=true"),
            ("output-credentials: false", "output-credentials: true"),
            ("output-env-credentials: true", "output-env-credentials: false"),
            (
                (
                    '"Effect":"Allow","Action":"sts:GetCallerIdentity",'
                    '"Resource":"*"'
                ),
                '"Effect":"Allow","Action":"lambda:*","Resource":"*"',
            ),
            ("AWS authority survived cleanup", "AWS authority retained"),
        )
        for old, new in hostile_changes:
            with self.subTest(change=new):
                self.assertIn(old, workflow)
                with self.assertRaises(AssertionError):
                    validate_closed_boundary(workflow.replace(old, new, 1))

    def test_staging_release_smoke_is_exact_decrypt_only_and_source_artifact_free(
        self,
    ) -> None:
        workflow = (
            ROOT / ".github/workflows/credentialed-release-staging-smoke.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("github.repository == 'leanprover/lean-eval-releases'", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("inputs.confirm_staging_smoke == true", workflow)
        self.assertIn("environment: release-staging", workflow)
        self.assertIn("repository: leanprover/lean-eval-state-staging", workflow)
        self.assertIn("repository: leanprover/lean-eval-audit", workflow)
        self.assertIn("ref: ${{ steps.plan.outputs.archive_commit }}", workflow)
        self.assertIn("secrets.STAGING_STATE_READ_KEY", workflow)
        self.assertIn("secrets.AUDIT_READ_KEY", workflow)
        self.assertIn("lean-eval-archive-unwrap-staging", workflow)
        self.assertIn("staging-smoke-plan", workflow)
        self.assertGreaterEqual(workflow.count("fetch-depth: 0"), 2)
        self.assertRegex(
            workflow,
            re.compile(
                r"- uses: actions/checkout@[0-9a-f]{40}\n"
                r"        with:\n"
                r"          ref: \$\{\{ github\.sha \}\}\n"
                r"          fetch-depth: 0\n"
                r"          persist-credentials: false"
            ),
        )
        self.assertIn('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"', workflow)
        self.assertIn("scripts/verify_release_state_contract.py", workflow)
        self.assertIn("--environment staging", workflow)
        self.assertLess(
            workflow.index("scripts/verify_release_state_contract.py"),
            workflow.index("state/scripts/state.py"),
        )
        self.assertIn("--max-filesize 16777216", workflow)
        self.assertIn("sha256sum", workflow)
        self.assertNotIn("RELEASE_PUBLISH_KEY", workflow)
        self.assertNotIn("state-event", workflow)
        self.assertNotIn("git push", workflow)
        self.assertNotIn("upload-artifact", workflow)
        self.assertNotIn("reconstruct_release.py", workflow)
        self.assert_release_invoke_session_boundary(
            workflow,
            environment="staging",
            function_name="lean-eval-archive-unwrap-staging",
            session_name="lean-eval-release-staging-smoke",
        )
        final_step_name = "Consume one capability, drop authority, and verify plaintext"
        self.assert_final_authority_step(
            workflow,
            final_step_name=final_step_name,
            final_condition="always()",
            function_name="lean-eval-archive-unwrap-staging",
        )
        self.assert_later_authority_step_is_rejected(
            workflow,
            final_step_name=final_step_name,
            final_condition="always()",
            function_name="lean-eval-archive-unwrap-staging",
        )

    def test_every_external_action_is_pinned_to_a_full_commit(self) -> None:
        action = re.compile(r"^\s*(?:- )?uses:\s*([^\s#]+)", re.MULTILINE)
        references: list[str] = []
        for path in sorted((ROOT / ".github/workflows").glob("*.y*ml")):
            workflow = path.read_text(encoding="utf-8")
            workflow_references = action.findall(workflow)
            references.extend(workflow_references)
            for reference in workflow_references:
                with self.subTest(workflow=path.name, reference=reference):
                    if reference.startswith("./"):
                        continue
                    self.assertRegex(reference, r"^[^@]+@[0-9a-f]{40}$")
        self.assertEqual(len(references), 23)

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

    def test_staging_smoke_selects_one_scheduled_submission_without_changing_embargo(
        self,
    ) -> None:
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
        self.assertEqual(
            unwrap_identity(request, response, {"StatusCode": 200}), identity
        )
        changed = {**response, "request_id": "0198abcd-0000-7000-8000-000000000099"}
        with self.assertRaisesRegex(ControllerError, "exact request"):
            unwrap_identity(request, changed, {"StatusCode": 200})
        with self.assertRaisesRegex(ControllerError, "successful invocation"):
            unwrap_identity(
                request,
                response,
                {"StatusCode": 200, "FunctionError": "Unhandled"},
            )

    def test_state_events_preserve_causation_attempt_and_publication_evidence(
        self,
    ) -> None:
        started = started_event(
            self.plan,
            NOW,
            random_bytes=bytes(range(10)),
        )
        self.assertEqual(started["event_type"], "release.started")
        self.assertEqual(
            started["causation_event_id"],
            self.plan["started_transition"]["causation_event_id"],
        )
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
        self.assertEqual(
            failed["payload"],
            {
                "attempt": 2,
                "reason_code": "provider_error",
                "retryable": True,
            },
        )

    def release_status(self) -> dict[str, object]:
        task = json.loads(
            (ROOT / "tests/fixtures/release-queue-v1.json").read_text(encoding="utf-8")
        )["tasks"][0]
        return {
            "schema_version": 2,
            "result_id": task["result_id"],
            "authority_event_id": "0198abcd-0000-7000-8000-000000000006",
            "status": task["status"],
            "release_event_id": task["event_id"],
            "release_revision": 1,
            "supersedes_release_event_id": None,
        }

    def test_release_state_transition_replaces_exact_targeted_status(self) -> None:
        started = started_event(
            self.plan,
            NOW,
            random_bytes=bytes(range(10)),
        )
        transition = plan_release_state_transition(
            self.release_status(), started, "1" * 40
        )
        result_id = started["subject_id"]
        self.assertEqual(
            transition["status_path"],
            result_release_status_path(result_id).as_posix(),
        )
        self.assertEqual(
            transition["event_path"],
            f"events/01/{started['event_id']}.json",
        )
        self.assertEqual(transition["protected_state_head"], "1" * 40)
        self.assertEqual(transition["status_after"]["status"], "running")
        self.assertEqual(
            transition["status_after"]["release_event_id"], started["event_id"]
        )
        self.assertEqual(transition["status_after"]["release_revision"], 2)
        self.assertEqual(
            transition["status_after"]["supersedes_release_event_id"],
            self.release_status()["release_event_id"],
        )
        self.assertEqual(
            transition["status_after"]["authority_event_id"],
            self.release_status()["authority_event_id"],
        )

        published = terminal_event(
            started,
            "2026-10-20T06:07:06.000Z",
            "published",
            repository_commit="1" * 40,
            tree_digest="2" * 64,
            release_path=self.plan["request"]["release"]["path"],
            random_bytes=bytes(range(10, 20)),
        )
        terminal = plan_release_state_transition(
            transition["status_after"], published, "2" * 40
        )
        self.assertEqual(terminal["status_after"]["status"], "published")
        self.assertEqual(
            terminal["status_after"]["release_event_id"], published["event_id"]
        )
        self.assertEqual(terminal["status_after"]["release_revision"], 3)
        self.assertEqual(
            terminal["status_after"]["supersedes_release_event_id"],
            started["event_id"],
        )

        failed = terminal_event(
            started,
            "2026-10-20T06:07:06.000Z",
            "failed",
            reason_code="provider_error",
            retryable=True,
            random_bytes=bytes(range(20, 30)),
        )
        failed_transition = plan_release_state_transition(
            transition["status_after"], failed, "2" * 40
        )
        self.assertEqual(failed_transition["status_after"]["status"], "failed")
        self.assertEqual(
            failed_transition["status_after"]["release_event_id"],
            failed["event_id"],
        )

    def test_release_state_transition_fails_closed_on_status_mismatch(self) -> None:
        started = started_event(
            self.plan,
            NOW,
            random_bytes=bytes(range(10)),
        )
        mutations = []
        missing = copy.deepcopy(self.release_status())
        missing.pop("release_event_id")
        mutations.append((missing, "fields are not canonical"))
        wrong_cause = copy.deepcopy(self.release_status())
        wrong_cause["release_event_id"] = "0198abcd-0000-7000-8000-000000000099"
        mutations.append((wrong_cause, "cause does not match"))
        wrong_result = copy.deepcopy(self.release_status())
        wrong_result["result_id"] = "r2_" + "0" * 64
        mutations.append((wrong_result, "subject does not match"))
        running = copy.deepcopy(self.release_status())
        running["status"] = "running"
        mutations.append((running, "cannot follow status"))
        legacy = copy.deepcopy(self.release_status())
        legacy["schema_version"] = 1
        mutations.append((legacy, "schema_version is invalid"))
        wrong_revision = copy.deepcopy(self.release_status())
        wrong_revision["release_revision"] = 0
        mutations.append((wrong_revision, "revision must be positive"))
        wrong_predecessor = copy.deepcopy(self.release_status())
        wrong_predecessor["supersedes_release_event_id"] = (
            "0198abcd-0000-7000-8000-000000000098"
        )
        mutations.append((wrong_predecessor, "must not name a predecessor"))
        missing_predecessor = copy.deepcopy(self.release_status())
        missing_predecessor["release_revision"] = 2
        mutations.append((missing_predecessor, "supersedes_release_event_id"))
        for revision in (True, -1, 9_007_199_254_740_992, "1"):
            invalid_revision = copy.deepcopy(self.release_status())
            invalid_revision["release_revision"] = revision
            mutations.append((invalid_revision, "revision is invalid"))
        invalid_initial = copy.deepcopy(self.release_status())
        invalid_initial.update(
            status="not_scheduled",
            release_event_id=None,
            release_revision=1,
            supersedes_release_event_id=None,
        )
        mutations.append((invalid_initial, "revision-zero head"))
        exhausted = copy.deepcopy(self.release_status())
        exhausted["release_revision"] = 9_007_199_254_740_991
        exhausted["supersedes_release_event_id"] = (
            "0198abcd-0000-7000-8000-000000000098"
        )
        for current, message in mutations:
            with self.subTest(current=current), self.assertRaisesRegex(
                ControllerError, message
            ):
                plan_release_state_transition(current, started, "1" * 40)
        with self.assertRaisesRegex(ControllerError, "revision is exhausted"):
            plan_release_state_transition(exhausted, started, "1" * 40)

    def test_stages_event_and_status_from_one_exact_state_head(self) -> None:
        started = started_event(
            self.plan,
            NOW,
            random_bytes=bytes(range(10)),
        )
        current = self.release_status()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            relative_status = result_release_status_path(started["subject_id"])
            status_path = root.joinpath(*relative_status.parts)
            status_path.parent.mkdir(parents=True)
            status_path.write_text(canonical_json(current), encoding="utf-8")
            subprocess.run(["git", "init", "-q", "-b", "main", root], check=True)
            subprocess.run(
                ["git", "-C", root, "config", "user.email", "test@example.invalid"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", root, "config", "user.name", "Test"], check=True
            )
            subprocess.run(["git", "-C", root, "add", "."], check=True)
            subprocess.run(
                ["git", "-C", root, "commit", "-q", "-m", "base"], check=True
            )
            head = subprocess.run(
                ["git", "-C", root, "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            transition = stage_release_state_transition(root, started, head)
            staged = subprocess.run(
                ["git", "-C", root, "diff", "--cached", "--name-only"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.splitlines()
            self.assertEqual(
                staged,
                sorted([transition["event_path"], transition["status_path"]]),
            )
            self.assertEqual(
                json.loads(status_path.read_text(encoding="utf-8")),
                transition["status_after"],
            )
            verify_staged_release_state_transition(root, started, transition)
            with self.assertRaisesRegex(ControllerError, "not clean"):
                stage_release_state_transition(root, started, head)

            tampered = copy.deepcopy(transition["status_after"])
            tampered["status"] = "published"
            status_path.write_text(canonical_json(tampered), encoding="utf-8")
            subprocess.run(
                ["git", "-C", root, "add", transition["status_path"]], check=True
            )
            with self.assertRaisesRegex(ControllerError, "cached bytes"):
                verify_staged_release_state_transition(root, started, transition)

            status_path.write_text(
                canonical_json(transition["status_after"]), encoding="utf-8"
            )
            subprocess.run(
                ["git", "-C", root, "add", transition["status_path"]], check=True
            )
            tampered_revision = copy.deepcopy(transition["status_after"])
            tampered_revision["release_revision"] += 1
            status_path.write_text(
                canonical_json(tampered_revision), encoding="utf-8"
            )
            subprocess.run(
                ["git", "-C", root, "add", transition["status_path"]], check=True
            )
            with self.assertRaisesRegex(ControllerError, "cached bytes"):
                verify_staged_release_state_transition(root, started, transition)

            status_path.write_text(
                canonical_json(transition["status_after"]), encoding="utf-8"
            )
            subprocess.run(
                ["git", "-C", root, "add", transition["status_path"]], check=True
            )
            extra = root / "unexpected"
            extra.write_text("unexpected\n", encoding="utf-8")
            subprocess.run(["git", "-C", root, "add", "unexpected"], check=True)
            with self.assertRaisesRegex(ControllerError, "exact event/status pair"):
                verify_staged_release_state_transition(root, started, transition)

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

            release_root = root.joinpath(
                *(f"releases/2026/10/{task['result_id']}".split("/"))
            )
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
            self.assertEqual(
                published["release_path"], f"releases/2026/10/{task['result_id']}"
            )
            self.assertEqual(published["submission_id"], task["submission_id"])
            self.assertRegex(published["tree_digest"], r"^[0-9a-f]{64}$")

            recent = copy.deepcopy(domain)
            recent["release_tasks"][0]["occurred_at"] = "2026-10-20T05:30:00.000Z"
            self.assertEqual(recover_running(recent, root, NOW)["kind"], "busy")


if __name__ == "__main__":
    unittest.main()
