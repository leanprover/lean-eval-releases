from __future__ import annotations

import base64
import copy
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import signal
import stat
import subprocess
import tempfile
import textwrap
import time
import unittest

from scripts import release_provider_literal
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


def workflow_job_steps(workflow: str, job_name: str) -> list[dict[str, object]]:
    """Parse the exact step mappings for one job in this workflow subset."""
    lines = workflow.splitlines()
    job_header = f"  {job_name}:"
    try:
        job_start = lines.index(job_header)
    except ValueError as error:
        raise AssertionError(f"missing workflow job: {job_name}") from error
    job_end = len(lines)
    for index in range(job_start + 1, len(lines)):
        line = lines[index]
        if line and not line.startswith(" "):
            job_end = index
            break
        if re.match(r"^  [A-Za-z0-9_-]+:\s*$", line):
            job_end = index
            break
    try:
        steps_start = lines.index("    steps:", job_start + 1, job_end)
    except ValueError as error:
        raise AssertionError(f"missing steps for workflow job: {job_name}") from error

    starts = [
        index
        for index in range(steps_start + 1, job_end)
        if re.match(r"^      -(?:\s|$)", lines[index])
    ]
    steps: list[dict[str, object]] = []
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else job_end
        block = lines[start:end]
        keys: dict[str, str] = {}
        first = re.match(r"^      -\s*([A-Za-z0-9_-]+):\s*(.*)$", block[0])
        if first:
            keys[first.group(1)] = first.group(2)
        for line in block[1:]:
            match = re.match(r"^        ([A-Za-z0-9_-]+):\s*(.*)$", line)
            if match:
                key = match.group(1)
                if key in keys:
                    raise AssertionError(f"duplicate step key {key!r} in {job_name}")
                keys[key] = match.group(2)
        steps.append({"keys": keys, "text": "\n".join(block) + "\n"})
    return steps


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
        self.assertIn("ref: ${{ needs.prepare-one.outputs.archive_commit }}", workflow)
        self.assertIn("lean-eval-archive-unwrap-production", workflow)
        self.assertIn("--max-filesize 16777216", workflow)
        self.assertIn("state-event started", workflow)
        started_step = workflow[
            workflow.index("      - name: Append release.started") :
            workflow.index("  unwrap-publish:")
        ]
        self.assertIn("state_commit=$(git -C state rev-parse HEAD)", started_step)
        self.assertIn('"state_commit=$state_commit"', started_step)
        self.assertNotIn("upload-artifact", workflow)
        self.assertNotIn("actions/download-artifact", workflow)
        self.assertIn("--history-only", workflow)
        self.assertIn("jq -er .repository_commit", workflow)
        self.assertNotIn("git log --diff-filter=A --format=%H -1", workflow)
        tail = (ROOT / "scripts/release_authority_tail.sh").read_text(encoding="utf-8")
        controller = workflow + tail
        self.assertIn("state-event published", controller)
        self.assertIn("state-event failed", controller)
        self.assertIn("scripts/classify_release_publication.py", controller)
        self.assertIn("publishing-manifest.json", controller)
        self.assertIn("jq -er --arg result", controller)
        self.assertEqual(controller.count("release_controller.py stage-state-transition"), 4)
        self.assertEqual(
            controller.count("release_controller.py verify-staged-state-transition"),
            4,
        )
        self.assertEqual(controller.count("--protected-main-commit"), 4)
        self.assertNotIn("state.py --root state append", workflow)
        self.assertNotIn("git -C state rebase", workflow)

    def assert_release_invoke_session_boundary(
        self,
        workflow: str,
        *,
        job_name: str,
        environment: str,
        function_name: str,
        session_name: str,
        check_hostile: bool = True,
    ) -> None:
        steps = workflow_job_steps(workflow, job_name)
        configure = [
            index
            for index, step in enumerate(steps)
            if str(step["keys"].get("uses", "")).startswith(
                "aws-actions/configure-aws-credentials@"
            )
        ]
        self.assertEqual(configure, [len(steps) - 2])
        configure_index = configure[0]
        configure_text = str(steps[configure_index]["text"])
        before = steps[:configure_index]
        after = steps[configure_index + 1 :]
        self.assertEqual(len(after), 1)
        self.assertEqual(
            after[0]["keys"],
            {
                "name": (
                    "Invoke once and exec the sanitized release tail"
                    if environment == "production"
                    else "Invoke once and exec the sanitized staging tail"
                ),
                "if": "always()",
                "shell": (
                    "/usr/bin/setsid --wait /usr/bin/bash "
                    "--noprofile --norc -e {0}"
                ),
                "env": "",
                "run": "|",
            },
        )

        allowed_actions = {
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
        }
        for step in before:
            keys = step["keys"]
            text = str(step["text"])
            if "uses" in keys:
                self.assertIn(keys["uses"], allowed_actions)
                continue
            self.assertIn(keys.get("name"), {
                "Stage exact encrypted inputs without executing checked-out code",
                f"Require the exact {environment} release Invoke role",
            })
            self.assertIn("run", keys)
            for executable in (
                "python scripts/",
                "python state/",
                "bash scripts/",
                "sh scripts/",
                "source scripts/",
                "./scripts/",
                '"$RUNNER_TEMP/age-bin" --',
            ):
                self.assertNotIn(executable, text)
            for line in text.splitlines():
                if "audit/" not in line:
                    continue
                self.assertRegex(
                    line.strip(),
                    r'^(?:test -f|cp) "audit/\$(?:archive_path|sidecar_path)"',
                )

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
        self.assertEqual(configure_text.count("inline-session-policy: >-"), 1)
        self.assertEqual(configure_text.count('"Action":"lambda:InvokeFunction"'), 1)
        self.assertEqual(
            configure_text.count('"Resource":"arn:aws:lambda:'),
            1,
        )
        self.assertNotIn('"Action":"lambda:*"', workflow)
        self.assertIn(
            '"Effect":"Allow","Action":"lambda:InvokeFunction",'
            f'"Resource":"{function_arn}"',
            configure_text,
        )
        self.assertIn(
            '"Effect":"Allow","Action":"sts:GetCallerIdentity",'
            '"Resource":"*"',
            configure_text,
        )
        self.assertLess(
            workflow.index(role_guard),
            workflow.index("uses: aws-actions/configure-aws-credentials@"),
        )
        final_text = str(after[0]["text"])
        self.assertIn("AWS_STEP_OUTCOME: ${{ steps.aws.outcome }}", final_text)
        self.assertIn(f"--function-name {function_name}", final_text)
        self.assertIn("exec -c /usr/bin/bash", final_text)
        provider, tail = final_text.split("exec -c /usr/bin/bash", 1)
        for checkout_executable in (
            "scripts/",
            "state/",
            "audit/",
            '"$RUNNER_TEMP/age-bin" --',
        ):
            self.assertNotIn(checkout_executable, provider)
        self.assertIn("scripts/release_authority_tail.sh", tail)

        if not check_hostile:
            return
        hostile_execution = workflow.replace(
            "          set -euo pipefail\n          umask 077",
            "          set -euo pipefail\n          sh scripts/hostile.sh\n          umask 077",
            1,
        )
        with self.assertRaises(AssertionError):
            self.assert_release_invoke_session_boundary(
                hostile_execution,
                job_name=job_name,
                environment=environment,
                function_name=function_name,
                session_name=session_name,
                check_hostile=False,
            )
        for first_key in ("run", "if", "id"):
            if first_key == "run":
                hostile_step = "      - run: env\n"
            elif first_key == "if":
                hostile_step = "      - if: always()\n        run: env\n"
            else:
                hostile_step = "      - id: hostile\n        run: env\n"
            hostile = workflow.rstrip() + "\n\n" + hostile_step
            with (
                self.subTest(hostile_first_key=first_key),
                self.assertRaises(AssertionError),
            ):
                self.assert_release_invoke_session_boundary(
                    hostile,
                    job_name=job_name,
                    environment=environment,
                    function_name=function_name,
                    session_name=session_name,
                    check_hostile=False,
                )

    def test_automatic_workflow_closes_the_aws_session_boundary(self) -> None:
        workflow = (ROOT / ".github/workflows/release-controller.yml").read_text(
            encoding="utf-8"
        )
        self.assert_release_invoke_session_boundary(
            workflow,
            job_name="unwrap-publish",
            environment="production",
            function_name="lean-eval-archive-unwrap-production",
            session_name="lean-eval-release-controller",
        )
        prepare = workflow[
            workflow.index("  prepare-one:") : workflow.index("  unwrap-publish:")
        ]
        privileged = workflow[workflow.index("  unwrap-publish:") :]
        self.assertNotIn("id-token: write", prepare)
        self.assertIn(
            "permissions:\n      contents: read\n      id-token: write",
            privileged,
        )

        sanitizer = (ROOT / "scripts/release_sanitizer_literal.sh").read_text(
            encoding="utf-8"
        )
        proof = sanitizer.index('for proc in "/proc/$$/environ"')
        self.assertIn('"/proc/$$/environ" "/proc/$PPID/environ"', sanitizer)
        self.assertLess(sanitizer.index("trap 'status=$?"), proof)
        proof_complete = sanitizer.index("trap - EXIT", proof)
        checkout_tail = sanitizer.index(
            "scripts/release_authority_tail.sh", proof_complete
        )
        self.assertLess(proof_complete, checkout_tail)
        authority_tail = (ROOT / "scripts/release_authority_tail.sh").read_text(
            encoding="utf-8"
        )
        for command in (
            "scripts/reconstruct_release.py",
            "scripts/classify_release_publication.py",
            "state-event published",
        ):
            with self.subTest(command=command):
                self.assertIn(command, authority_tail)
        self.assertIn(
            'if [ "$status" -ne 0 ] && [ "$publication_recorded" = false ]; then\n'
            "    remove_sensitive_scratch\n"
            "    record_retryable_failure",
            authority_tail,
        )
        self.assertIn("cmp \"$RUNNER_TEMP/release-started-event.json\"", authority_tail)
        self.assertIn("scripts/classify_release_publication.py", authority_tail)
        self.assertEqual(authority_tail.count("expected_plaintext=$(jq"), 2)
        self.assertEqual(authority_tail.count("actual_plaintext=$(sha256sum"), 2)
        for private_path in (
            "unwrap-request.json",
            "unwrap-response.json",
            "unwrap-metadata.json",
            "identity.age",
            "source.tar.gz",
        ):
            self.assertEqual(
                authority_tail.count(
                    f'require_private_regular "$RUNNER_TEMP/{private_path}"'
                ),
                2,
                private_path,
            )
        self.assertIn('"$PYTHON_BIN" -I -c', authority_tail)
        self.assertNotIn('"$PYTHON_BIN" scripts/', authority_tail)
        self.assertNotIn("PYTHONPATH=", authority_tail)
        self.assertIn(
            'test -z "$(git status --porcelain --untracked-files=all)"',
            sanitizer,
        )
        production_decrypt = authority_tail.rindex(
            '"$RUNNER_TEMP/age-bin" --decrypt'
        )
        production_digest = authority_tail.index(
            "expected_plaintext=$(jq -er",
            production_decrypt,
        )
        production_reconstruct = authority_tail.index(
            "scripts/reconstruct_release.py",
            production_digest,
        )
        self.assertLess(production_decrypt, production_digest)
        self.assertLess(production_digest, production_reconstruct)
        self.assertIn("len(expected) != 2 or actual != expected", workflow)
        self.assertIn("audit SSH key was not synchronously removed", workflow)
        validate = (ROOT / ".github/workflows/validate.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("bash -n scripts/release_authority_tail.sh", validate)
        self.assertIn("shellcheck scripts/release_authority_tail.sh", validate)
        self.assertIn("bash -n scripts/release_sanitizer_literal.sh", validate)
        self.assertIn("shellcheck scripts/release_sanitizer_literal.sh", validate)
        contract = (ROOT / "docs/release-controller-contract.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("explicit publication-launch blocker", contract)
        self.assertRegex(
            contract,
            r"read back and record the environment protection\s+rules again",
        )

    def test_sanitized_exec_erases_process_start_authority(self) -> None:
        tail = ROOT / "scripts/release_sanitizer_literal.sh"
        authority = {
            "AWS_ACCESS_KEY_ID": "hostile-access-key",
            "AWS_SECRET_ACCESS_KEY": "hostile-secret-key",
            "AWS_SESSION_TOKEN": "hostile-session-token",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "hostile-oidc-token",
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://hostile.invalid/oidc",
        }
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = pathlib.Path(temporary)
            home = temporary_path / "home"
            runner = temporary_path / "runner"
            home.mkdir()
            runner.mkdir()
            clean = {
                "PATH": os.environ["PATH"],
                "HOME": str(home),
                "RUNNER_TEMP": str(runner),
            }
            rejected = subprocess.run(
                ["bash", str(tail), "probe"],
                check=False,
                capture_output=True,
                text=True,
                env={**clean, **authority},
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("authority variable survived", rejected.stderr)

            assignments = " ".join(
                f"{name}={value}" for name, value in authority.items()
            )
            command = (
                f"{assignments} bash -c 'exec env -i PATH=\"$PATH\" "
                "HOME=\"$2\" RUNNER_TEMP=\"$3\" bash --noprofile --norc "
                "\"$1\" probe' authority-child \"$1\" \"$2\" \"$3\""
            )
            accepted = subprocess.run(
                [
                    "env",
                    "-i",
                    f"PATH={clean['PATH']}",
                    "bash",
                    "-c",
                    command,
                    "authority-parent",
                    str(tail),
                    str(home),
                    str(runner),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

            parent_command = (
                "env -i PATH=\"$PATH\" HOME=\"$2\" RUNNER_TEMP=\"$3\" "
                "bash --noprofile --norc \"$1\" probe; status=$?; :; exit $status"
            )
            contaminated_parent = subprocess.run(
                [
                    "bash",
                    "-c",
                    parent_command,
                    "authority-parent",
                    str(tail),
                    str(home),
                    str(runner),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={**clean, **authority},
            )
            self.assertNotEqual(contaminated_parent.returncode, 0)
            self.assertIn("process-readable", contaminated_parent.stderr)

    def test_literal_sanitizer_is_the_only_gate_into_checkout_code(self) -> None:
        sanitizer = ROOT / "scripts/release_sanitizer_literal.sh"
        bash = shutil.which("bash")
        rm = shutil.which("rm")
        self.assertIsNotNone(bash)
        self.assertIsNotNone(rm)
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            test_sanitizer = root / "release-sanitizer.sh"
            sanitizer_source = sanitizer.read_text(encoding="utf-8")
            self.assertEqual(
                sanitizer_source.count("PATH=/usr/local/bin:/usr/bin:/bin"),
                1,
            )
            test_sanitizer.write_text(
                sanitizer_source.replace(
                    "PATH=/usr/local/bin:/usr/bin:/bin",
                    f"PATH={os.environ['PATH']}",
                ).replace("/usr/bin/rm", str(rm)),
                encoding="utf-8",
            )
            python_bin = root / "python-bin"
            python_bin.write_text("#!/bin/sh\necho 3.11\n", encoding="utf-8")
            python_bin.chmod(0o555)
            checkout = root / "checkout"
            scripts = checkout / "scripts"
            runner = root / "runner"
            home = root / "home"
            scripts.mkdir(parents=True)
            runner.mkdir()
            home.mkdir()
            fake_tail = scripts / "release_authority_tail.sh"
            fake_tail.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                'test "$LITERAL_AUTHORITY_PROOF" = '
                "release-authority-sanitized-v1\n"
                'touch "$RUNNER_TEMP/tail-ran"\n',
                encoding="utf-8",
            )
            subprocess.run(["git", "init", "-q", checkout], check=True)
            subprocess.run(
                ["git", "-C", checkout, "config", "user.name", "Test"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", checkout, "config", "user.email", "test@example.com"],
                check=True,
            )
            subprocess.run(["git", "-C", checkout, "add", "."], check=True)
            subprocess.run(
                ["git", "-C", checkout, "commit", "-qm", "fixture"],
                check=True,
            )

            inputs = {
                "release-plan.json": b"{}\n",
                "archive-sidecar.json": b"{}\n",
                "archive.tar.age": b"ciphertext",
                "age-bin": b"#!/bin/sh\nexit 0\n",
            }
            for name, content in inputs.items():
                path = runner / name
                path.write_bytes(content)
                if name == "age-bin":
                    path.chmod(0o555)
            release_commit = subprocess.run(
                ["git", "-C", checkout, "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            tail_blob = subprocess.run(
                [
                    "git",
                    "-C",
                    checkout,
                    "rev-parse",
                    "HEAD:scripts/release_authority_tail.sh",
                ],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

            def digest(name: str) -> str:
                return hashlib.sha256((runner / name).read_bytes()).hexdigest()

            proof = {
                "schema_version": 1,
                "mode": "staging",
                "release_commit": release_commit,
                "state_commit": "",
                "authority_tail_blob": tail_blob,
                "plan_sha256": digest("release-plan.json"),
                "started_event_sha256": "",
                "archive_sidecar_sha256": digest("archive-sidecar.json"),
                "archive_ciphertext_sha256": digest("archive.tar.age"),
                "age_binary_sha256": digest("age-bin"),
            }
            proof_path = runner / "pre-authority-stage.json"
            def run(mode: str = "staging") -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [
                        str(bash),
                        str(test_sanitizer),
                        mode,
                        str(home),
                        str(python_bin),
                        str(runner),
                        str(root / "summary.md"),
                        "0198abcd-0000-7000-8000-000000000002",
                    ],
                    cwd=checkout,
                    check=False,
                    capture_output=True,
                    text=True,
                    env={},
                )

            proof_path.write_text(json.dumps(proof) + "\n", encoding="utf-8")
            accepted = run()
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            (runner / "tail-ran").unlink()

            proof_path.write_text(json.dumps(proof) + "\n", encoding="utf-8")
            (runner / "release-plan.json").write_text("tampered\n", encoding="utf-8")
            rejected = run()
            self.assertNotEqual(rejected.returncode, 0)
            self.assertFalse((runner / "tail-ran").exists())

            for name, content in inputs.items():
                path = runner / name
                path.write_bytes(content)
                if name == "age-bin":
                    path.chmod(0o555)
            proof_path.write_text(json.dumps(proof) + "\n", encoding="utf-8")
            fake_tail.write_text("touch should-not-run\n", encoding="utf-8")
            rejected = run()
            self.assertNotEqual(rejected.returncode, 0)
            self.assertFalse((runner / "tail-ran").exists())
            self.assertFalse((checkout / "should-not-run").exists())

            subprocess.run(
                ["git", "-C", str(checkout), "restore", "scripts/release_authority_tail.sh"],
                check=True,
            )
            for name, content in inputs.items():
                path = runner / name
                path.write_bytes(content)
                if name == "age-bin":
                    path.chmod(0o555)
            proof_path.write_text(json.dumps(proof) + "\n", encoding="utf-8")
            hostile_import = scripts / "json.py"
            hostile_import.write_text(
                'raise SystemExit("untracked import shadow executed")\n',
                encoding="utf-8",
            )
            rejected = run()
            self.assertNotEqual(rejected.returncode, 0)
            self.assertFalse((runner / "tail-ran").exists())
            hostile_import.unlink()

            # Production intentionally nests the separately pinned and
            # separately clean State checkout under the release checkout.
            # Excluding exactly that path must not mask any other dirt.
            state = checkout / "state"
            state.mkdir()
            subprocess.run(["git", "init", "-q", state], check=True)
            subprocess.run(
                ["git", "-C", state, "config", "user.name", "Test"], check=True
            )
            subprocess.run(
                ["git", "-C", state, "config", "user.email", "test@example.com"],
                check=True,
            )
            (state / "state.json").write_text("{}\n", encoding="utf-8")
            subprocess.run(["git", "-C", state, "add", "."], check=True)
            subprocess.run(
                ["git", "-C", state, "commit", "-qm", "state fixture"],
                check=True,
            )
            state_commit = subprocess.run(
                ["git", "-C", state, "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            for name, content in inputs.items():
                path = runner / name
                path.write_bytes(content)
                if name == "age-bin":
                    path.chmod(0o555)
            started = runner / "release-started-event.json"
            started.write_text("{}\n", encoding="utf-8")
            production_proof = {
                **proof,
                "mode": "production",
                "state_commit": state_commit,
                "started_event_sha256": hashlib.sha256(
                    started.read_bytes()
                ).hexdigest(),
            }
            proof_path.write_text(
                json.dumps(production_proof) + "\n", encoding="utf-8"
            )
            accepted = run("production")
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            (runner / "tail-ran").unlink()

            proof_path.write_text(
                json.dumps(production_proof) + "\n", encoding="utf-8"
            )
            (checkout / "other-untracked").write_text("hostile\n", encoding="utf-8")
            rejected = run("production")
            self.assertNotEqual(rejected.returncode, 0)
            self.assertFalse((runner / "tail-ran").exists())
            (checkout / "other-untracked").unlink()

    def test_final_authority_cleanup_covers_early_and_handoff_failure(self) -> None:
        bash = shutil.which("bash")
        kill = shutil.which("kill")
        rm = shutil.which("rm")
        setsid = shutil.which("setsid")
        sleep = shutil.which("sleep")
        self.assertIsNotNone(bash)
        self.assertIsNotNone(kill)
        self.assertIsNotNone(rm)
        self.assertIsNotNone(setsid)
        self.assertIsNotNone(sleep)
        for workflow_name, job_name in (
            ("release-controller.yml", "unwrap-publish"),
            ("credentialed-release-staging-smoke.yml", "unwrap-one"),
        ):
            workflow = (ROOT / ".github/workflows" / workflow_name).read_text(
                encoding="utf-8"
            )
            final = str(workflow_job_steps(workflow, job_name)[-1]["text"])
            body = final.split("        run: |\n", 1)[1]
            self.assertTrue(
                body.startswith(
                    "          # shellcheck disable=SC2154  # Assigned inside "
                    "this first-command EXIT trap.\n"
                    "          trap 'status=$?\n"
                )
            )
            umask_line = "          umask 077\n"
            prologue_end = body.index(umask_line) + len(umask_line)
            prologue = textwrap.dedent(body[:prologue_end]).replace(
                "/usr/bin/rm", str(rm)
            )
            supervisor_start = body.index(
                'IFS= read -r parent_stat < "/proc/$$/stat"'
            )
            provider_start = body.index("python_bin=")
            authority_unset = body.index(
                "unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN"
            )
            handoff = body.index(
                "exec -c /usr/bin/bash --noprofile --norc -s --",
                authority_unset,
            )
            self.assertLess(authority_unset, handoff)
            self.assertNotIn("exec 9", body)
            self.assertIn("coproc RELEASE_CLEANUP_SUPERVISOR", body)
            self.assertIn("exec -c /usr/bin/setsid /usr/bin/bash", body)
            self.assertIn('test "$parent_group" = "$$"', body)
            self.assertIn('test "$parent_session" = "$$"', body)
            self.assertIn("' EXIT INT TERM", body[:prologue_end])
            self.assertLess(supervisor_start, provider_start)
            self.assertLess(provider_start, authority_unset)
            self.assertLess(supervisor_start, body.index('"$python_bin" -I -'))
            self.assertLess(supervisor_start, body.index("aws lambda invoke"))
            self.assertNotIn(
                "scripts/release_authority_tail.sh",
                body[prologue_end:handoff],
            )
            supervisor_boundary = textwrap.dedent(
                body[supervisor_start:provider_start]
            )
            for source, target in (
                ("/usr/bin/bash", bash),
                ("/usr/bin/kill", kill),
                ("/usr/bin/rm", rm),
                ("/usr/bin/setsid", setsid),
                ("/usr/bin/sleep", sleep),
            ):
                supervisor_boundary = supervisor_boundary.replace(
                    source, str(target)
                )

            def isolated_command(script: str) -> list[str]:
                return [str(setsid), "--wait", str(bash), "-c", script]

            with tempfile.TemporaryDirectory() as temporary:
                runner = pathlib.Path(temporary) / "runner"
                runner.mkdir()
                private_files = (
                    "release-plan.json",
                    "release-started-event.json",
                    "unwrap-request.json",
                    "unwrap-response.json",
                    "unwrap-metadata.json",
                    "identity.age",
                    "source.tar.gz",
                    "archive.tar.age",
                    "archive-sidecar.json",
                    "age-bin",
                    "pre-authority-stage.json",
                )

                def populate(
                    cleanup_root: pathlib.Path = runner,
                    cleanup_files: tuple[str, ...] = private_files,
                ) -> None:
                    for name in cleanup_files:
                        (cleanup_root / name).write_text(
                            "plaintext_identity_base64=PRIVATE\n",
                            encoding="utf-8",
                        )
                    (cleanup_root / "reconstructed").mkdir()
                    (cleanup_root / ".reconstructed-private").mkdir()
                    (cleanup_root / "state-views").mkdir()

                def assert_clean(
                    cleanup_root: pathlib.Path = runner,
                    cleanup_files: tuple[str, ...] = private_files,
                ) -> None:
                    for name in cleanup_files:
                        self.assertFalse((cleanup_root / name).exists(), name)
                    self.assertFalse((cleanup_root / "reconstructed").exists())
                    self.assertEqual(
                        list(cleanup_root.glob(".reconstructed-*")), []
                    )
                    self.assertFalse((cleanup_root / "state-views").exists())

                for label, failure in (
                    ("early", prologue + "false\n"),
                    (
                        "handoff",
                        prologue
                        + supervisor_boundary
                        + "exec /definitely/missing/lean-eval-bash\n",
                    ),
                ):
                    with self.subTest(
                        workflow=workflow_name,
                        failure=label,
                    ):
                        populate()
                        failed = subprocess.run(
                            isolated_command(failure),
                            check=False,
                            capture_output=True,
                            text=True,
                            env={"RUNNER_TEMP": str(runner)},
                        )
                        self.assertNotEqual(failed.returncode, 0)
                        deadline = time.monotonic() + 5
                        while any(
                            (runner / name).exists() for name in private_files
                        ) and time.monotonic() < deadline:
                            time.sleep(0.01)
                        assert_clean()

                mode_probe = prologue + textwrap.dedent(
                    f"""\
                    : > "$RUNNER_TEMP/unwrap-response.json"
                    exec -c {bash} --noprofile --norc -c '
                      : > "$1/identity.age"
                      : > "$1/source.tar.gz"
                    ' private-mode-probe "$RUNNER_TEMP"
                    """
                )
                private_modes = subprocess.run(
                    [str(bash), "-c", mode_probe],
                    check=False,
                    capture_output=True,
                    text=True,
                    env={"RUNNER_TEMP": str(runner)},
                )
                self.assertEqual(private_modes.returncode, 0, private_modes.stderr)
                for name in (
                    "unwrap-response.json",
                    "identity.age",
                    "source.tar.gz",
                ):
                    self.assertEqual(
                        stat.S_IMODE((runner / name).stat().st_mode),
                        0o600,
                        name,
                    )

                authority = {
                    "AWS_ACCESS_KEY_ID": "hostile-access-key",
                    "AWS_SECRET_ACCESS_KEY": "hostile-secret-key",
                    "AWS_SESSION_TOKEN": "hostile-session-token",
                    "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "hostile-oidc-token",
                    "ACTIONS_ID_TOKEN_REQUEST_URL": "https://hostile.invalid/oidc",
                    "UNRELATED_SECRET": "hostile-unrelated-secret",
                }
                supervisor_probe = supervisor_boundary + textwrap.dedent(
                    f"""\
                    exec -c {bash} --noprofile --norc -s -- {runner} <<'CHECKOUT'
                    expected_runner=$1
                    supervisor=
                    for attempt in {{1..10000}}; do
                      for cmdline in /proc/[0-9]*/cmdline; do
                        [ -r "$cmdline" ] || continue
                        marked=false
                        while IFS= read -r -d '' argument; do
                          if [ "$marked" = true ] && [ "$argument" = "$expected_runner" ]; then
                            supervisor=${{cmdline%/cmdline}}
                            break 3
                          fi
                          [ "$argument" = lean-eval-release-cleanup-supervisor-v1 ] && \
                            marked=true || marked=false
                        done < "$cmdline" 2>/dev/null || :
                      done
                    done
                    [ -n "$supervisor" ]
                    count=0
                    while IFS= read -r -d '' entry; do
                      count=$((count + 1))
                      case "$entry" in
                        AWS_ACCESS_KEY_ID=*|AWS_SECRET_ACCESS_KEY=*|AWS_SESSION_TOKEN=*|ACTIONS_ID_TOKEN_REQUEST_TOKEN=*|ACTIONS_ID_TOKEN_REQUEST_URL=*|UNRELATED_SECRET=*)
                          exit 1
                          ;;
                        *=hostile-access-key|*=hostile-secret-key|*=hostile-session-token|*=hostile-oidc-token|*=https://hostile.invalid/oidc|*=hostile-unrelated-secret)
                          exit 1
                          ;;
                      esac
                    done < "$supervisor/environ"
                    [ "$count" -eq 0 ]
                    CHECKOUT
                    """
                )
                clean_supervisor = subprocess.run(
                    isolated_command(supervisor_probe),
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    env={"RUNNER_TEMP": str(runner), **authority},
                )
                self.assertEqual(
                    clean_supervisor.returncode,
                    0,
                    clean_supervisor.stderr,
                )

                pre_exec = runner / "supervisor-pre-exec"
                allow_exec = runner / "allow-supervisor-exec"
                checkout_started = runner / "checkout-started"
                delayed_boundary = supervisor_boundary.replace(
                    f"exec -c {setsid} {bash}",
                    textwrap.dedent(
                        f"""\
                        printf '%s\\n' "$BASHPID" > {pre_exec}
                        while [ ! -e {allow_exec} ]; do :; done
                        exec -c {setsid} {bash}
                        """
                    ).rstrip(),
                    1,
                )
                delayed_probe = delayed_boundary + textwrap.dedent(
                    f"""\
                    exec -c {bash} --noprofile --norc -c \
                      ': > "$1/checkout-started"' checkout-probe {runner}
                    """
                )
                delayed = subprocess.Popen(
                    isolated_command(delayed_probe),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                    env={"RUNNER_TEMP": str(runner), **authority},
                )
                deadline = time.monotonic() + 5
                while (
                    not pre_exec.exists()
                    and delayed.poll() is None
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.01)
                self.assertTrue(pre_exec.exists())
                pre_exec_pid = int(pre_exec.read_text(encoding="ascii").strip())
                inherited_environment = (
                    pathlib.Path("/proc") / str(pre_exec_pid) / "environ"
                ).read_bytes()
                self.assertIn(
                    b"UNRELATED_SECRET=hostile-unrelated-secret\0",
                    inherited_environment,
                )
                self.assertFalse(checkout_started.exists())
                allow_exec.write_text("continue\n", encoding="utf-8")
                _, delayed_stderr = delayed.communicate(timeout=10)
                self.assertEqual(delayed.returncode, 0, delayed_stderr)
                self.assertTrue(checkout_started.exists())

                # Killing the exact parent before the supervisor reports ready
                # must still permit the already-forked supervisor to sanitize.
                populate()
                pre_ready = runner / "pre-ready"
                allow_ready = runner / "allow-ready"
                pre_ready_boundary = supervisor_boundary.replace(
                    f"exec -c {setsid} {bash}",
                    textwrap.dedent(
                        f"""\
                        printf '%s\\n' "$BASHPID" > {pre_ready}
                        while [ ! -e {allow_ready} ]; do :; done
                        exec -c {setsid} {bash}
                        """
                    ).rstrip(),
                    1,
                )
                pre_ready_process = subprocess.Popen(
                    isolated_command(
                        prologue + pre_ready_boundary + "while :; do :; done\n"
                    ),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env={"RUNNER_TEMP": str(runner)},
                )
                deadline = time.monotonic() + 5
                while not pre_ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(pre_ready.exists())
                os.kill(pre_ready_process.pid, signal.SIGKILL)
                self.assertNotEqual(pre_ready_process.wait(timeout=5), 0)
                allow_ready.write_text("continue\n", encoding="utf-8")
                deadline = time.monotonic() + 5
                while any(
                    (runner / name).exists() for name in private_files
                ) and time.monotonic() < deadline:
                    time.sleep(0.01)
                assert_clean()

                for signal_value in (
                    signal.SIGINT,
                    signal.SIGTERM,
                    signal.SIGKILL,
                ):
                    with self.subTest(
                        workflow=workflow_name,
                        signal=signal_value,
                    ):
                        for name in (
                            "unwrap-response.json",
                            "identity.age",
                            "source.tar.gz",
                        ):
                            (runner / name).unlink(missing_ok=True)
                        populate()
                        child_pid_path = runner / "surviving-child-pid"
                        child_pid_path.unlink(missing_ok=True)
                        signaled_script = prologue + supervisor_boundary + textwrap.dedent(
                            f"""\
                            {sleep} 30 &
                            child=$!
                            printf '%s\n' "$child" > {child_pid_path}
                            while :; do :; done
                            """
                        )
                        signaled = subprocess.Popen(
                            isolated_command(signaled_script),
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            text=True,
                            env={"RUNNER_TEMP": str(runner)},
                        )
                        deadline = time.monotonic() + 5
                        while (
                            not child_pid_path.exists()
                            and signaled.poll() is None
                            and time.monotonic() < deadline
                        ):
                            time.sleep(0.01)
                        self.assertTrue(child_pid_path.exists())
                        child_pid = int(
                            child_pid_path.read_text(encoding="ascii").strip()
                        )
                        os.kill(signaled.pid, signal_value)
                        self.assertNotEqual(signaled.wait(timeout=5), 0)
                        deadline = time.monotonic() + 5
                        while any(
                            (runner / name).exists() for name in private_files
                        ) and time.monotonic() < deadline:
                            time.sleep(0.01)
                        assert_clean()
                        deadline = time.monotonic() + 5
                        while (
                            pathlib.Path(f"/proc/{child_pid}").exists()
                            and time.monotonic() < deadline
                        ):
                            time.sleep(0.01)

                # A surviving foreground writer must be terminated, and a
                # write racing the first scrub must be removed by the repeated
                # cleanup pass before the supervisor exits.
                populate()
                writer_ready = runner / "writer-ready"
                allow_writer = runner / "allow-writer"
                writer_ran = runner / "writer-ran"
                writer_code = textwrap.dedent(
                    f"""\
                    import pathlib
                    import signal
                    import time

                    signal.signal(signal.SIGTERM, signal.SIG_IGN)
                    pathlib.Path({str(writer_ready)!r}).write_text("ready")
                    allow = pathlib.Path({str(allow_writer)!r})
                    while not allow.exists():
                        time.sleep(0.01)
                    target = pathlib.Path({str(runner / 'reconstructed/source')!r})
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text("PRIVATE")
                    pathlib.Path({str(writer_ran)!r}).write_text("ran")
                    while True:
                        time.sleep(1)
                    """
                )
                writer_script = (
                    prologue
                    + supervisor_boundary
                    + f"{shutil.which('python')} -c {shlex.quote(writer_code)}\n"
                    + "true\n"
                )
                writer_parent = subprocess.Popen(
                    isolated_command(writer_script),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env={"RUNNER_TEMP": str(runner)},
                )
                deadline = time.monotonic() + 5
                while not writer_ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(writer_ready.exists())
                os.kill(writer_parent.pid, signal.SIGKILL)
                self.assertNotEqual(writer_parent.wait(timeout=5), 0)
                deadline = time.monotonic() + 5
                while (runner / "source.tar.gz").exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                allow_writer.write_text("continue\n", encoding="utf-8")
                deadline = time.monotonic() + 8
                while (
                    (not writer_ran.exists() or (runner / "reconstructed").exists())
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.01)
                self.assertTrue(writer_ran.exists())
                assert_clean()

                # The supervisor has its own session, so killing the entire
                # authority process group cannot suppress cleanup.
                populate()
                group_ready = runner / "group-ready"
                group_script = (
                    prologue
                    + supervisor_boundary
                    + f"printf ready > {group_ready}\nwhile :; do :; done\n"
                )
                grouped = subprocess.Popen(
                    isolated_command(group_script),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env={"RUNNER_TEMP": str(runner)},
                )
                deadline = time.monotonic() + 5
                while not group_ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(group_ready.exists())
                os.killpg(os.getpgid(grouped.pid), signal.SIGKILL)
                self.assertNotEqual(grouped.wait(timeout=5), 0)
                deadline = time.monotonic() + 5
                while any(
                    (runner / name).exists() for name in private_files
                ) and time.monotonic() < deadline:
                    time.sleep(0.01)
                assert_clean()

    def test_production_failure_scrubs_before_retryable_recovery(self) -> None:
        authority_tail = (
            ROOT / "scripts/release_authority_tail.sh"
        ).read_text(encoding="utf-8")
        definitions_start = authority_tail.index("remove_sensitive_scratch() {")
        definitions_end = authority_tail.index(
            "trap - EXIT INT TERM\nif [ \"$mode\" = production ]",
            definitions_start,
        )
        definitions = authority_tail[definitions_start:definitions_end]
        bash = shutil.which("bash")
        self.assertIsNotNone(bash)
        with tempfile.TemporaryDirectory() as temporary:
            runner = pathlib.Path(temporary) / "runner"
            runner.mkdir()
            sensitive = (
                "release-plan.json",
                "unwrap-request.json",
                "unwrap-response.json",
                "unwrap-metadata.json",
                "identity.age",
                "source.tar.gz",
                "archive.tar.age",
                "archive-sidecar.json",
                "age-bin",
                "pre-authority-stage.json",
            )
            for name in (*sensitive, "release-started-event.json"):
                (runner / name).write_text("private\n", encoding="utf-8")
            (runner / "reconstructed").mkdir()
            (runner / ".reconstructed-private").mkdir()
            (runner / "state-views").mkdir()
            recovery_entered = runner / "recovery-entered"
            allow_recovery = runner / "allow-recovery"
            sensitive_checks = "\n".join(
                f'  [ ! -e "$RUNNER_TEMP/{name}" ]' for name in sensitive
            )
            script = (
                "set +e\n"
                "authority_proven=true\n"
                "publication_recorded=false\n"
                + definitions
                + "record_retryable_failure() {\n"
                + sensitive_checks
                + "\n  [ ! -e \"$RUNNER_TEMP/reconstructed\" ]\n"
                + "  [ ! -e \"$RUNNER_TEMP/state-views\" ]\n"
                + "  [ -f \"$RUNNER_TEMP/release-started-event.json\" ]\n"
                + f"  : > {recovery_entered}\n"
                + f"  while [ ! -e {allow_recovery} ]; do :; done\n"
                + "}\n"
                + "false\nfinish_production\n"
            )
            recovery = subprocess.Popen(
                [str(bash), "-c", script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                env={
                    "PATH": os.environ["PATH"],
                    "RUNNER_TEMP": str(runner),
                },
            )
            deadline = time.monotonic() + 5
            while (
                not recovery_entered.exists()
                and recovery.poll() is None
                and time.monotonic() < deadline
            ):
                time.sleep(0.01)
            self.assertTrue(recovery_entered.exists())
            self.assertIsNone(recovery.poll())
            for name in sensitive:
                self.assertFalse((runner / name).exists(), name)
            self.assertFalse((runner / "reconstructed").exists())
            self.assertEqual(list(runner.glob(".reconstructed-*")), [])
            self.assertFalse((runner / "state-views").exists())
            self.assertTrue((runner / "release-started-event.json").exists())
            allow_recovery.write_text("continue\n", encoding="utf-8")
            _, recovery_stderr = recovery.communicate(timeout=10)
            self.assertNotEqual(recovery.returncode, 0, recovery_stderr)
            self.assertFalse((runner / "release-started-event.json").exists())

    def test_literal_provider_is_exact_and_prepare_unwrap_equivalent(self) -> None:
        source = (ROOT / "scripts/release_provider_literal.py").read_text(
            encoding="utf-8"
        )
        sanitizer_source = (
            ROOT / "scripts/release_sanitizer_literal.sh"
        ).read_text(encoding="utf-8")
        workflows = (
            ("release-controller.yml", "unwrap-publish"),
            ("credentialed-release-staging-smoke.yml", "unwrap-one"),
        )
        for workflow_name, job_name in workflows:
            workflow = (ROOT / ".github/workflows" / workflow_name).read_text(
                encoding="utf-8"
            )
            final = workflow_job_steps(workflow, job_name)[-1]
            run = str(final["text"])
            start = run.index("<<'PY'\n") + len("<<'PY'\n")
            end = run.index("          PY\n", start)
            literal_lines = run[start:end].splitlines()
            self.assertTrue(literal_lines)
            self.assertTrue(
                all(not line or line.startswith("          ") for line in literal_lines)
            )
            literal = "\n".join(
                line[10:] if line else "" for line in literal_lines
            ) + "\n"
            self.assertEqual(literal, source)
            sanitizer_start = run.index("<<'SANITIZED'\n") + len(
                "<<'SANITIZED'\n"
            )
            sanitizer_end = run.index("          SANITIZED\n", sanitizer_start)
            sanitizer_lines = run[sanitizer_start:sanitizer_end].splitlines()
            self.assertTrue(sanitizer_lines)
            self.assertTrue(
                all(
                    not line or line.startswith("          ")
                    for line in sanitizer_lines
                )
            )
            sanitizer_literal = "\n".join(
                line[10:] if line else "" for line in sanitizer_lines
            ) + "\n"
            self.assertEqual(sanitizer_literal, sanitizer_source)
            run_body = run.split("        run: |\n", 1)[1]
            self.assertNotIn("${{", run_body)
            provider_end = run.index("          PY\n", start)
            failure_gate = run.index(
                'if [ "$provider_status" -ne 0 ]; then', provider_end
            )
            sanitized_exec = run.index("exec -c /usr/bin/bash", failure_gate)
            self.assertLess(failure_gate, sanitized_exec)
            self.assertNotIn(
                "scripts/release_authority_tail.sh",
                run[provider_end:sanitized_exec],
            )
            proof = sanitizer_literal.index('for proc in "/proc/$$/environ"')
            checkout = sanitizer_literal.index(
                "scripts/release_authority_tail.sh", proof
            )
            self.assertLess(proof, checkout)

        trusted = dt.datetime.fromisoformat(NOW.replace("Z", "+00:00"))
        random_bytes = bytes(range(10))
        nonce = "a" * 64
        expected = prepare_unwrap(
            self.plan,
            self.sidecar,
            self.ciphertext,
            NOW,
            random_bytes=random_bytes,
            runner_nonce=nonce,
        )
        actual = release_provider_literal.build_request(
            self.plan,
            self.sidecar,
            self.ciphertext,
            trusted,
            random_bytes=random_bytes,
            runner_nonce=nonce,
        )
        self.assertEqual(actual, expected)

        hostile_values: list[tuple[dict[str, object], bytes]] = []
        for change in (
            lambda value: value.update(unexpected=True),
            lambda value: value.update(schema_version=True),
            lambda value: value.update(size_bytes_ciphertext=999),
            lambda value: value.update(archiver_workflow_run="https://invalid.test/1"),
        ):
            changed = copy.deepcopy(self.sidecar)
            change(changed)
            hostile_values.append((changed, self.ciphertext))
        for change in (
            lambda value: value.update(unexpected=True),
            lambda value: value.update(schema_version=True),
            lambda value: value.update(age_recipient="age1invalid"),
            lambda value: value.update(wrapped_identity=""),
            lambda value: value.update(wrapped_identity="YQ="),
            lambda value: value.update(wrapped_identity="YQ==" * 5000),
        ):
            changed = copy.deepcopy(self.sidecar)
            change(changed["key_envelope"])
            hostile_values.append((changed, self.ciphertext))

        for sidecar, ciphertext in hostile_values:
            with self.subTest(sidecar=sidecar):
                with self.assertRaises(ControllerError):
                    prepare_unwrap(self.plan, sidecar, ciphertext, NOW)
                with self.assertRaises(release_provider_literal.ProviderError):
                    release_provider_literal.build_request(
                        self.plan,
                        sidecar,
                        ciphertext,
                        trusted,
                        random_bytes=random_bytes,
                        runner_nonce=nonce,
                    )

    def test_literal_provider_has_field_by_field_plan_rejection_parity(self) -> None:
        plan = copy.deepcopy(self.plan)
        plan["request"]["controller"] = {
            "schema_version": 1,
            "environment": "production",
            "mode": "publication",
            "release_repository": "leanprover/lean-eval-releases",
            "release_commit": "4" * 40,
            "state_repository": "leanprover/lean-eval-state",
            "state_commit": "5" * 40,
            "state_contract_commit": "a53c658a2de2188675134dc2890285fbaa17cf5a",
            "state_source_event_count": 1,
            "state_source_digest": "6" * 64,
            "release_queue_sha256": "7" * 64,
            "acceptance_snapshot_sha256": "8" * 64,
        }
        plan["request"]["submission"]["production_metadata"] = {
            "credit_identity": "Example credit",
            "component_models": ["Example component"],
            "harness": "Example harness",
            "human_involvement": "None",
            "web_access": False,
            "wall_time_seconds": 12.5,
            "input_tokens": 10,
            "output_tokens": 20,
            "cost_usd": 0.5,
            "billing_mode": "api",
            "prompt": "Example prompt",
            "notes": "Example notes",
        }
        trusted = dt.datetime.fromisoformat(NOW.replace("Z", "+00:00"))

        def accepted(candidate: object, *, literal: bool) -> bool:
            try:
                if literal:
                    release_provider_literal.build_request(
                        candidate,
                        self.sidecar,
                        self.ciphertext,
                        trusted,
                        random_bytes=bytes(range(10)),
                        runner_nonce="a" * 64,
                    )
                else:
                    prepare_unwrap(
                        candidate,
                        self.sidecar,
                        self.ciphertext,
                        NOW,
                        random_bytes=bytes(range(10)),
                        runner_nonce="a" * 64,
                    )
            except (ControllerError, release_provider_literal.ProviderError):
                return False
            return True

        self.assertTrue(accepted(plan, literal=False))
        self.assertTrue(accepted(plan, literal=True))
        mutations: list[tuple[str, object]] = []

        def replace_at(value: object, path: tuple[object, ...], replacement: object) -> object:
            changed = copy.deepcopy(value)
            if not path:
                return replacement
            parent = changed
            for component in path[:-1]:
                parent = parent[component]  # type: ignore[index]
            parent[path[-1]] = replacement  # type: ignore[index]
            return changed

        def walk(value: object, path: tuple[object, ...] = ()) -> None:
            if path:
                mutations.append((f"replace {path}", replace_at(plan, path, None)))
            if isinstance(value, dict):
                extra = copy.deepcopy(value)
                extra["__unexpected"] = True
                mutations.append(
                    (f"extra field {path}", replace_at(plan, path, extra))
                )
                for key, item in value.items():
                    missing = copy.deepcopy(value)
                    del missing[key]
                    mutations.append(
                        (f"missing {path + (key,)}", replace_at(plan, path, missing))
                    )
                    walk(item, path + (key,))
            elif isinstance(value, list):
                extended = copy.deepcopy(value)
                extended.append(None)
                mutations.append(
                    (f"extended {path}", replace_at(plan, path, extended))
                )
                for index, item in enumerate(value):
                    walk(item, path + (index,))

        walk(plan)
        mutations.extend(
            (
                ("NaN schema", {**copy.deepcopy(plan), "schema_version": float("nan")}),
                (
                    "infinite wall time",
                    replace_at(
                        plan,
                        (
                            "request",
                            "submission",
                            "production_metadata",
                            "wall_time_seconds",
                        ),
                        float("inf"),
                    ),
                ),
            )
        )
        rejected = 0
        for label, candidate in mutations:
            with self.subTest(mutation=label):
                prepared = accepted(candidate, literal=False)
                literal = accepted(candidate, literal=True)
                self.assertEqual(literal, prepared)
                rejected += int(not prepared)
        self.assertGreaterEqual(len(mutations), 100)
        self.assertGreaterEqual(rejected, 100)

    def test_literal_provider_scans_runner_authority_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            runner = root / "runner"
            home = root / "home"
            commands = runner / "_runner_file_commands"
            aws = home / ".aws"
            commands.mkdir(parents=True)
            aws.mkdir(parents=True)
            environment = {
                "RUNNER_TEMP": str(runner),
                "HOME": str(home),
                "AWS_ACCESS_KEY_ID": "temporary-exact-access-key",
            }
            (commands / "safe").write_text("PATH=/usr/bin\n", encoding="utf-8")
            release_provider_literal.scan_authority_files(environment)
            (commands / "credential").write_text(
                "temporary-exact-access-key\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                release_provider_literal.ProviderError,
                "authority remains",
            ):
                release_provider_literal.scan_authority_files(environment)
            (commands / "credential").unlink()
            (aws / "credentials").write_text(
                "aws_secret_access_key = residual\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                release_provider_literal.ProviderError,
                "authority remains",
            ):
                release_provider_literal.scan_authority_files(environment)

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
        self.assertIn("ref: ${{ needs.prepare-one.outputs.archive_commit }}", workflow)
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
            job_name="unwrap-one",
            environment="staging",
            function_name="lean-eval-archive-unwrap-staging",
            session_name="lean-eval-release-staging-smoke",
        )
        prepare = workflow[
            workflow.index("  prepare-one:") : workflow.index("  unwrap-one:")
        ]
        privileged = workflow[workflow.index("  unwrap-one:") :]
        self.assertNotIn("id-token: write", prepare)
        self.assertIn(
            "permissions:\n      contents: read\n      id-token: write",
            privileged,
        )
        tail = (ROOT / "scripts/release_authority_tail.sh").read_text(
            encoding="utf-8"
        )
        sanitizer = (ROOT / "scripts/release_sanitizer_literal.sh").read_text(
            encoding="utf-8"
        )
        proof = sanitizer.index('for proc in "/proc/$$/environ"')
        checkout_tail = sanitizer.index(
            "scripts/release_authority_tail.sh", proof
        )
        tail = (ROOT / "scripts/release_authority_tail.sh").read_text(
            encoding="utf-8"
        )
        self.assertGreater(checkout_tail, proof)
        self.assertIn('if [ "$mode" = staging ]', tail)
        self.assertIn('"$RUNNER_TEMP/age-bin" --decrypt', tail)
        self.assertIn("audit SSH key was not synchronously removed", workflow)

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
        self.assertEqual(len(references), 28)

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
