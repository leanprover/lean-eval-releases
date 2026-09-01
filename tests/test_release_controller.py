from __future__ import annotations

import base64
import copy
import datetime as dt
import hashlib
import io
import json
import os
import pathlib
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time
import unittest

from scripts import release_provider_literal
from scripts.reconstruct_release_plan import ReconstructionError, reconstruct
from scripts.release_controller import (
    ControllerError,
    archive_key_id,
    authority_descriptor,
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
    verify_unwrap_reuse_refusal,
    verify_staged_release_state_transition,
)
from scripts.release_orchestrator import plan_next, result_id
from scripts.release_qualification import build_qualification

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


def workflow_jobs(workflow: str) -> dict[str, str]:
    """Return exact top-level job blocks from this workflow subset."""
    lines = workflow.splitlines()
    jobs_start = lines.index("jobs:")
    starts = [
        index
        for index in range(jobs_start + 1, len(lines))
        if re.match(r"^  [A-Za-z0-9_-]+:\s*$", lines[index])
    ]
    jobs: dict[str, str] = {}
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(lines)
        name = lines[start].strip().removesuffix(":")
        jobs[name] = "\n".join(lines[start:end]) + "\n"
    return jobs


def workflow_job_condition(job: str) -> str:
    """Return one folded, conjunctive job condition."""
    lines = job.splitlines()
    condition_start = lines.index("    if: >-") + 1
    condition: list[str] = []
    for line in lines[condition_start:]:
        if line and not line.startswith("      "):
            break
        if line:
            condition.append(line.strip())
    if not condition:
        raise AssertionError("job condition is empty")
    return " ".join(condition)


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
        self.assertIn(
            "needs.authorize-publication.outputs.publication_enabled == 'true'",
            workflow,
        )
        self.assertIn(
            "PUBLICATION_ENABLED: ${{ vars.PUBLICATION_ENABLED }}", workflow
        )
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
                r"          ref: \$\{\{ needs\.prepare-one\.outputs\.release_commit \}\}\n"
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
        self.assertIn(
            "release_controller.py authority-descriptor",
            started_step,
        )
        self.assertNotIn("base64", started_step)
        self.assertNotIn("plan_base64", workflow)
        self.assertNotIn("started_event_base64", workflow)
        self.assertNotIn("upload-artifact", workflow)
        self.assertNotIn("actions/download-artifact", workflow)
        self.assertIn("--history-only", workflow)
        self.assertIn("jq -er .repository_commit", workflow)
        self.assertNotIn("git log --diff-filter=A --format=%H -1", workflow)
        tail = (ROOT / "scripts/release_authority_tail.sh").read_text(encoding="utf-8")
        controller = workflow + tail
        self.assertIn("git -C state config user.name lean-eval-release-controller", tail)
        self.assertIn(
            "lean-eval-release-controller@users.noreply.github.com", tail
        )
        self.assertLess(
            tail.index("git -C state config user.name"),
            tail.index("run_exact_python_quiet authority-contract"),
        )
        self.assertIn('--expected-head "$expected_state_head"', tail)
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
        self.assertEqual(controller.count("--protected-main-commit"), 10)
        self.assertNotIn("state.py --root state append", workflow)
        self.assertNotIn("git -C state rebase", workflow)

    def test_cross_job_handoff_discloses_no_private_plan_metadata(self) -> None:
        queue = json.loads(
            (ROOT / "tests/fixtures/release-queue-v1.json").read_text(
                encoding="utf-8"
            )
        )
        task = queue["tasks"][0]
        sentinels = (
            "private-owner",
            "PRIVATE_MODEL_SENTINEL",
            "PRIVATE_PROMPT_SENTINEL",
            "PRIVATE_NOTES_SENTINEL",
        )
        task["owner_login"] = sentinels[0]
        task["declared_model"] = sentinels[1]
        task["production_metadata"] = {
            "prompt": sentinels[2],
            "notes": sentinels[3],
        }
        task["result_id"] = result_id(
            task["owner_login"],
            task["declared_model"],
            task["problem_id"],
            task["statement_revision"],
        )
        plan = plan_next(queue, NOW)
        started = started_event(plan, NOW, random_bytes=bytes(range(10)))
        descriptor = authority_descriptor(
            plan,
            "9" * 40,
            "4" * 40,
            "production",
            started,
        )
        serialized = canonical_json(descriptor)
        self.assertEqual(set(descriptor), release_provider_literal.AUTHORITY_DESCRIPTOR_FIELDS)
        for sentinel in sentinels:
            self.assertNotIn(sentinel, serialized)
        with tempfile.TemporaryDirectory() as temporary:
            scratch = pathlib.Path(temporary)
            plan_path = scratch / "private-plan.json"
            started_path = scratch / "private-started.json"
            output_path = scratch / "authority.json"
            plan_path.write_text(canonical_json(plan), encoding="utf-8")
            started_path.write_text(canonical_json(started), encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable,
                    "scripts/release_controller.py",
                    "authority-descriptor",
                    "--plan",
                    str(plan_path),
                    "--state-commit",
                    "9" * 40,
                    "--release-commit",
                    "4" * 40,
                    "--environment",
                    "production",
                    "--started-event",
                    str(started_path),
                    "--output",
                    str(output_path),
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            observable = completed.stdout + completed.stderr + output_path.read_text(
                encoding="utf-8"
            )
            for sentinel in sentinels:
                self.assertNotIn(sentinel, observable)

        for path in (
            ROOT / ".github/workflows/release-controller.yml",
            ROOT / ".github/workflows/credentialed-release-staging-smoke.yml",
        ):
            workflow = path.read_text(encoding="utf-8")
            authority_job = (
                "unwrap-publish" if path.name == "release-controller.yml" else "unwrap-one"
            )
            prepare_outputs = workflow.split("    outputs:\n", 1)[1].split(
                "    steps:\n", 1
            )[0]
            for private_name in (
                "plan_base64",
                "started_event_base64",
                "production_metadata",
                "owner_login",
                "declared_model",
                "prompt",
                "notes",
            ):
                self.assertNotIn(private_name, prepare_outputs)
            self.assertNotIn("upload-artifact", workflow)
            self.assertNotIn("actions/upload-artifact", workflow)
            self.assertNotRegex(workflow, r"(?:cat|echo|jq \.)(?:[^\n]*release-plan)")
            for step in workflow_job_steps(workflow, authority_job):
                env_surface = str(step["text"]).split("        run: |\n", 1)[0]
                for private_name in (
                    "production_metadata",
                    "owner_login",
                    "declared_model",
                    "prompt",
                    "notes",
                    "PLAN_BASE64",
                    "STARTED_EVENT_BASE64",
                ):
                    self.assertNotIn(private_name, env_surface)

        tail = (ROOT / "scripts/release_authority_tail.sh").read_text(
            encoding="utf-8"
        )
        summary = tail[tail.index("  {\n", tail.index("GITHUB_STEP_SUMMARY")) :]
        summary = summary[: summary.index('  } >> "$GITHUB_STEP_SUMMARY"')]
        for private_name in ("owner", "model", "prompt", "notes"):
            self.assertNotIn(private_name, summary)
        self.assertIn("run_exact_python_quiet()", tail)
        self.assertLess(
            tail.index("scripts/verify_release_state_contract.py"),
            tail.index("scripts/reconstruct_release_plan.py"),
        )
        self.assertIn(
            "run_exact_python_quiet state-materialization",
            tail,
        )
        reconstruction = (
            ROOT / "scripts/reconstruct_release_plan.py"
        ).read_text(encoding="utf-8")
        self.assertGreaterEqual(reconstruction.count("capture_output=True"), 5)

    def test_release_plan_module_imports_without_pythonpath(self) -> None:
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "from scripts.reconstruct_release_plan import reconstruct; "
                    "assert callable(reconstruct)"
                ),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            env=environment,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        with tempfile.TemporaryDirectory() as temporary:
            scratch = pathlib.Path(temporary)
            authority = authority_descriptor(
                self.plan,
                "5" * 40,
                "4" * 40,
                "staging",
            )
            private_field = "PRIVATE_PLAN_FIELD_SENTINEL"
            authority[private_field] = "private value"
            authority_path = scratch / "authority.json"
            authority_path.write_text(canonical_json(authority), encoding="utf-8")
            plan_output = scratch / "plan.json"
            failed = subprocess.run(
                [
                    sys.executable,
                    "scripts/reconstruct_release_plan.py",
                    "--authority",
                    str(authority_path),
                    "--state-root",
                    str(ROOT),
                    "--release-root",
                    str(ROOT),
                    "--scratch-root",
                    str(scratch),
                    "--output",
                    str(plan_output),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(failed.returncode, 0)
            self.assertEqual(failed.stdout, "")
            self.assertEqual(
                failed.stderr, "release plan reconstruction failed closed\n"
            )
            self.assertNotIn(private_field, failed.stderr)
            self.assertFalse(plan_output.exists())

    def test_private_archive_failures_never_log_hostile_member_names(self) -> None:
        sentinel = "PRIVATE_SOURCE_MEMBER_NAME_SENTINEL"
        with tempfile.TemporaryDirectory() as temporary:
            scratch = pathlib.Path(temporary)
            plaintext = scratch / "source.tar.gz"
            with tarfile.open(plaintext, mode="w:gz") as archive:
                member = tarfile.TarInfo(f"source/Submission/{sentinel}.lean")
                member.type = tarfile.SYMTYPE
                member.linkname = "Submission.lean"
                archive.addfile(member)

            plan_path = scratch / "release-plan.json"
            plan_path.write_text(canonical_json(self.plan), encoding="utf-8")
            commands = (
                (
                    "source-validation",
                    [
                        "scripts/validate_release_source_archive.py",
                        "--plaintext-tar",
                        str(plaintext),
                    ],
                    "release source validation failed closed\n",
                ),
                (
                    "source-reconstruction",
                    [
                        "scripts/reconstruct_release.py",
                        str(plan_path),
                        "--plaintext-tar",
                        str(plaintext),
                        "--trusted-as-of",
                        NOW,
                        "--state-acceptance-snapshot",
                        "tests/fixtures/release-acceptance-snapshot-v1.json",
                        "--output-root",
                        str(scratch / "reconstructed"),
                    ],
                    "release source reconstruction failed closed\n",
                ),
            )
            for phase, arguments, expected_stderr in commands:
                with self.subTest(phase=phase):
                    completed = subprocess.run(
                        [sys.executable, *arguments],
                        cwd=ROOT,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertEqual(completed.stdout, "")
                    self.assertEqual(completed.stderr, expected_stderr)
                    self.assertNotIn(sentinel, completed.stderr)

            tail = (ROOT / "scripts/release_authority_tail.sh").read_text(
                encoding="utf-8"
            )
            functions = tail[
                tail.index("run_exact_python() {") : tail.index(
                    "require_private_regular() {"
                )
            ]
            bash = shutil.which("bash")
            self.assertIsNotNone(bash)
            wrapped = subprocess.run(
                [
                    str(bash),
                    "-c",
                    functions
                    + "\nrun_exact_python_quiet source-validation "
                    + "scripts/validate_release_source_archive.py "
                    + '"$1" "$2"\n',
                    "release-private-log-test",
                    "--plaintext-tar",
                    str(plaintext),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                env={"PYTHON_BIN": sys.executable},
                check=False,
            )
            self.assertNotEqual(wrapped.returncode, 0)
            self.assertEqual(
                wrapped.stderr,
                "private release failed closed: source-validation\n",
            )
            self.assertNotIn(sentinel, wrapped.stderr)

    def test_private_publication_never_logs_valid_member_paths_or_content(
        self,
    ) -> None:
        filename_sentinel = "PRIVATE_VALID_MEMBER_FILENAME_SENTINEL"
        content_sentinel = "PRIVATE_VALID_SOURCE_CONTENT_SENTINEL"
        snapshot = ROOT / "tests/fixtures/release-acceptance-snapshot-v1.json"
        queue = json.loads(
            (ROOT / "tests/fixtures/release-queue-v1.json").read_text(
                encoding="utf-8"
            )
        )
        private_plan = plan_next(queue, NOW)
        release_path = private_plan["request"]["release"]["path"]
        submission_id = private_plan["request"]["submission"]["submission_id"]

        def command(*arguments: str, cwd: pathlib.Path = ROOT) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                list(arguments),
                cwd=cwd,
                check=True,
                capture_output=True,
                text=True,
            )

        def prepare(
            root: pathlib.Path,
            source: bytes,
            source_name: str = filename_sentinel + ".lean",
        ) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path]:
            plaintext = root / "source.tar.gz"
            with tarfile.open(plaintext, mode="w:gz") as archive:
                for name, content in (
                    (
                        "source/Submission.lean",
                        b"import Mathlib\nexample : True := by trivial\n",
                    ),
                    (
                        f"source/Submission/{source_name}",
                        source,
                    ),
                ):
                    member = tarfile.TarInfo(name)
                    member.size = len(content)
                    archive.addfile(member, io.BytesIO(content))
            plan = root / "release-plan.json"
            plan.write_text(canonical_json(private_plan), encoding="utf-8")
            reconstructed = root / "reconstructed"

            validation = subprocess.run(
                [
                    sys.executable,
                    "scripts/validate_release_source_archive.py",
                    "--plaintext-tar",
                    str(plaintext),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(validation.returncode, 0, validation.stderr)
            self.assertEqual(validation.stdout, "")
            self.assertEqual(validation.stderr, "")
            reconstruction = subprocess.run(
                [
                    sys.executable,
                    "scripts/reconstruct_release.py",
                    str(plan),
                    "--plaintext-tar",
                    str(plaintext),
                    "--trusted-as-of",
                    NOW,
                    "--state-acceptance-snapshot",
                    str(snapshot),
                    "--output-root",
                    str(reconstructed),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(reconstruction.returncode, 0, reconstruction.stderr)
            self.assertNotIn(filename_sentinel, reconstruction.stdout)
            self.assertNotIn(content_sentinel, reconstruction.stdout)
            self.assertEqual(reconstruction.stderr, "")

            manifest_validation = subprocess.run(
                [
                    sys.executable,
                    "scripts/validate_manifest.py",
                    str(reconstructed / "release-manifest.json"),
                    "--trusted-as-of",
                    NOW,
                    "--state-acceptance-snapshot",
                    str(snapshot),
                    "--bundle-root",
                    str(reconstructed),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(
                manifest_validation.returncode, 0, manifest_validation.stderr
            )
            self.assertNotIn(filename_sentinel, manifest_validation.stdout)
            self.assertNotIn(content_sentinel, manifest_validation.stdout)
            self.assertEqual(manifest_validation.stderr, "")

            release = root / "release"
            remote = root / "remote.git"
            command(
                "git", "init", "--initial-branch=main", str(release)
            )
            command("git", "init", "--bare", "--initial-branch=main", str(remote))
            (release / "README.md").write_text("release repository\n", encoding="utf-8")
            (release / ".gitignore").write_text(
                "dist/\n__pycache__/\n*.pyc\n", encoding="utf-8"
            )
            command("git", "config", "user.name", "release test", cwd=release)
            command(
                "git", "config", "user.email", "release@example.invalid", cwd=release
            )
            command("git", "add", "README.md", ".gitignore", cwd=release)
            command("git", "commit", "--quiet", "-m", "Initial", cwd=release)
            command("git", "remote", "add", "origin", str(remote), cwd=release)
            command("git", "push", "--quiet", "-u", "origin", "main", cwd=release)

            classification = root / "classification.json"
            classified = subprocess.run(
                [
                    sys.executable,
                    "scripts/classify_release_publication.py",
                    "--release-root",
                    str(release),
                    "--reconstructed-root",
                    str(reconstructed),
                    "--release-path",
                    release_path,
                    "--submission-id",
                    submission_id,
                    "--output",
                    str(classification),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(classified.returncode, 0, classified.stderr)
            self.assertEqual(classified.stdout, "")
            self.assertEqual(classified.stderr, "")
            return release, remote, reconstructed, classification

        def publication_arguments(
            release: pathlib.Path,
            reconstructed: pathlib.Path,
            classification: pathlib.Path,
            output: pathlib.Path,
        ) -> list[str]:
            return [
                "scripts/publish_release.py",
                "--release-root",
                str(release),
                "--reconstructed-root",
                str(reconstructed),
                "--release-path",
                release_path,
                "--submission-id",
                submission_id,
                "--classification",
                str(classification),
                "--trusted-as-of",
                NOW,
                "--state-acceptance-snapshot",
                str(snapshot),
                "--output",
                str(output),
            ]

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            diagnostic = root / "diagnostic"
            diagnostic.mkdir()
            diagnostic_release, _, diagnostic_reconstructed, _ = prepare(
                diagnostic,
                (
                    f"theorem {content_sentinel} : True := by\n  trivial\n"
                ).encode(),
            )
            private_source = (
                diagnostic_reconstructed
                / release_path
                / "Submission"
                / f"{filename_sentinel}.lean"
            )
            private_source.chmod(0o755)
            manifest_failure = subprocess.run(
                [
                    sys.executable,
                    "scripts/validate_manifest.py",
                    str(diagnostic_reconstructed / "release-manifest.json"),
                    "--trusted-as-of",
                    NOW,
                    "--state-acceptance-snapshot",
                    str(snapshot),
                    "--bundle-root",
                    str(diagnostic_reconstructed),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(manifest_failure.returncode, 0)
            self.assertEqual(manifest_failure.stdout, "")
            self.assertEqual(
                manifest_failure.stderr,
                "release manifest validation failed closed\n",
            )
            self.assertNotIn(filename_sentinel, manifest_failure.stderr)
            private_source.unlink()
            private_source.symlink_to("../Submission.lean")
            classification_failure = subprocess.run(
                [
                    sys.executable,
                    "scripts/classify_release_publication.py",
                    "--release-root",
                    str(diagnostic_release),
                    "--reconstructed-root",
                    str(diagnostic_reconstructed),
                    "--release-path",
                    release_path,
                    "--submission-id",
                    submission_id,
                    "--output",
                    str(diagnostic / "failed-classification.json"),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(classification_failure.returncode, 0)
            self.assertEqual(classification_failure.stdout, "")
            self.assertEqual(
                classification_failure.stderr,
                "release publication classification failed closed\n",
            )
            self.assertNotIn(filename_sentinel, classification_failure.stderr)

            whitespace = root / "whitespace"
            whitespace.mkdir()
            private_line = (
                f"theorem {content_sentinel} : True := by   \n  trivial\n"
            ).encode()
            release, _, reconstructed, classification = prepare(
                whitespace, private_line
            )
            output = whitespace / "publication-result.json"
            direct = subprocess.run(
                [
                    sys.executable,
                    *publication_arguments(
                        release, reconstructed, classification, output
                    ),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(direct.returncode, 0, direct.stderr)
            self.assertEqual(direct.stdout, "")
            self.assertEqual(direct.stderr, "")
            self.assertTrue(output.is_file())

            wrapped_root = root / "wrapped"
            wrapped_root.mkdir()
            wrapped_release, _, wrapped_reconstructed, wrapped_classification = prepare(
                wrapped_root, private_line
            )
            wrapped_output = wrapped_root / "publication-result.json"
            tail = (ROOT / "scripts/release_authority_tail.sh").read_text(
                encoding="utf-8"
            )
            functions = tail[
                tail.index("run_exact_python() {") : tail.index(
                    "require_private_regular() {"
                )
            ]
            bash = shutil.which("bash")
            self.assertIsNotNone(bash)
            wrapped = subprocess.run(
                [
                    str(bash),
                    "-c",
                    functions
                    + "\nrun_exact_python_quiet publication-write \"$@\"\n",
                    "release-private-publication-test",
                    *publication_arguments(
                        wrapped_release,
                        wrapped_reconstructed,
                        wrapped_classification,
                        wrapped_output,
                    ),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                env={"PATH": os.environ["PATH"], "PYTHON_BIN": sys.executable},
                check=False,
            )
            self.assertEqual(wrapped.returncode, 0, wrapped.stderr)
            self.assertEqual(wrapped.stdout, "")
            self.assertEqual(wrapped.stderr, "")
            self.assertTrue(wrapped_output.is_file())

            filtered_root = root / "filtered"
            filtered_root.mkdir()
            filtered_release, filtered_remote, filtered_reconstructed, filtered_classification = prepare(
                filtered_root,
                private_line,
            )
            (filtered_release / ".gitattributes").write_text(
                "*.lean filter=release-test-filter\n", encoding="utf-8"
            )
            command(
                "git",
                "config",
                "filter.release-test-filter.clean",
                "sed s/trivial/filtered/g",
                cwd=filtered_release,
            )
            command("git", "add", ".gitattributes", cwd=filtered_release)
            command(
                "git", "commit", "--quiet", "-m", "Add test clean filter", cwd=filtered_release
            )
            command("git", "push", "--quiet", "origin", "main", cwd=filtered_release)
            filtered_remote_before = command(
                "git", "--git-dir", str(filtered_remote), "rev-parse", "main"
            ).stdout.strip()
            filtered_output = filtered_root / "publication-result.json"
            filtered = subprocess.run(
                [
                    sys.executable,
                    *publication_arguments(
                        filtered_release,
                        filtered_reconstructed,
                        filtered_classification,
                        filtered_output,
                    ),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(filtered.returncode, 0)
            self.assertEqual(filtered.stdout, "")
            self.assertEqual(
                filtered.stderr, "release publication failed closed\n"
            )
            self.assertFalse(filtered_output.exists())
            self.assertEqual(
                command(
                    "git", "--git-dir", str(filtered_remote), "rev-parse", "main"
                ).stdout.strip(),
                filtered_remote_before,
            )

            successful = root / "successful"
            successful.mkdir()
            clean_line = (
                f"theorem {content_sentinel} : True := by\n  trivial\n"
            ).encode()
            clean_release, clean_remote, clean_reconstructed, clean_classification = (
                prepare(
                    successful,
                    clean_line,
                    source_name=f"dist/{filename_sentinel}.lean",
                )
            )
            clean_output = successful / "publication-result.json"
            published = subprocess.run(
                [
                    sys.executable,
                    *publication_arguments(
                        clean_release,
                        clean_reconstructed,
                        clean_classification,
                        clean_output,
                    ),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(published.returncode, 0, published.stderr)
            self.assertEqual(published.stdout, "")
            self.assertEqual(published.stderr, "")
            result_bytes = clean_output.read_bytes()
            self.assertNotIn(filename_sentinel.encode("utf-8"), result_bytes)
            self.assertNotIn(content_sentinel.encode("utf-8"), result_bytes)
            self.assertEqual(stat.S_IMODE(clean_output.stat().st_mode), 0o600)
            result = json.loads(result_bytes)
            self.assertRegex(result["repository_commit"], r"^[0-9a-f]{40}$")
            self.assertRegex(result["release_tree_sha256"], r"^[0-9a-f]{64}$")
            remote_head = command(
                "git", "--git-dir", str(clean_remote), "rev-parse", "main"
            ).stdout.strip()
            self.assertEqual(remote_head, result["repository_commit"])
            published_paths = command(
                "git",
                "--git-dir",
                str(clean_remote),
                "ls-tree",
                "-r",
                "--name-only",
                "main",
            ).stdout.splitlines()
            self.assertIn(
                f"{release_path}/Submission/dist/{filename_sentinel}.lean",
                published_paths,
            )

    def test_staging_plan_reconstructs_only_from_exact_state_and_descriptor(
        self,
    ) -> None:
        queue = json.loads(
            (ROOT / "tests/fixtures/release-queue-v1.json").read_text(
                encoding="utf-8"
            )
        )
        queue["environment"] = "staging"
        submission_id = queue["tasks"][0]["submission_id"]
        plan = staging_smoke_plan(queue, submission_id)
        release_commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = pathlib.Path(temporary)
            state = temporary_root / "state"
            (state / "scripts").mkdir(parents=True)
            (state / "queue.json").write_text(
                canonical_json(queue), encoding="utf-8"
            )
            (state / "snapshot.json").write_text("{}\n", encoding="utf-8")
            (state / "scripts/state.py").write_text(
                textwrap.dedent(
                    """\
                    import pathlib
                    import shutil
                    import subprocess
                    import sys

                    root = pathlib.Path(sys.argv[sys.argv.index("--root") + 1])
                    protected = sys.argv[
                        sys.argv.index("--protected-main-commit") + 1
                    ]
                    actual = subprocess.run(
                        ["git", "-C", root, "rev-parse", "HEAD"],
                        check=True,
                        capture_output=True,
                        text=True,
                    ).stdout.strip()
                    if protected != actual:
                        raise SystemExit("protected State head is not exact")
                    if "materialize" in sys.argv:
                        output = pathlib.Path(sys.argv[sys.argv.index("--output") + 1])
                        output.mkdir(parents=True)
                        shutil.copyfile(root / "queue.json", output / "release-queue.json")
                        shutil.copyfile(root / "snapshot.json", output / "release-acceptance-snapshot.json")
                    """
                ),
                encoding="utf-8",
            )
            subprocess.run(["git", "init", "-q", state], check=True)
            subprocess.run(
                ["git", "-C", state, "config", "user.name", "Test"], check=True
            )
            subprocess.run(
                ["git", "-C", state, "config", "user.email", "test@example.com"],
                check=True,
            )
            subprocess.run(["git", "-C", state, "add", "."], check=True)
            subprocess.run(["git", "-C", state, "commit", "-qm", "fixture"], check=True)
            state_commit = subprocess.run(
                ["git", "-C", state, "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            descriptor = authority_descriptor(
                plan,
                state_commit,
                release_commit,
                "staging",
            )
            scratch = temporary_root / "scratch"
            scratch.mkdir()
            reconstructed, reconstructed_started = reconstruct(
                descriptor,
                state_root=state,
                release_root=ROOT,
                scratch_root=scratch,
            )
            self.assertEqual(reconstructed, plan)
            self.assertIsNone(reconstructed_started)
            self.assertFalse((scratch / "state-views").exists())
            changed = copy.deepcopy(descriptor)
            changed["plan_sha256"] = "0" * 64
            with self.assertRaisesRegex(
                ReconstructionError, "plan digest changed"
            ):
                reconstruct(
                    changed,
                    state_root=state,
                    release_root=ROOT,
                    scratch_root=scratch,
                )

    def test_production_plan_reconstructs_from_exact_started_state_commit(
        self,
    ) -> None:
        queue = json.loads(
            (ROOT / "tests/fixtures/release-queue-v1.json").read_text(
                encoding="utf-8"
            )
        )
        snapshot = json.loads(
            (ROOT / "tests/fixtures/release-acceptance-snapshot-v1.json").read_text(
                encoding="utf-8"
            )
        )
        contract = json.loads(
            (
                ROOT
                / "configuration/release-controller-credential-contract-v1.json"
            ).read_text(encoding="utf-8")
        )
        release_commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = pathlib.Path(temporary)
            state = temporary_root / "state"
            (state / "scripts").mkdir(parents=True)
            (state / "queue.json").write_text(
                canonical_json(queue), encoding="utf-8"
            )
            (state / "snapshot.json").write_text(
                canonical_json(snapshot), encoding="utf-8"
            )
            (state / "scripts/state.py").write_text(
                textwrap.dedent(
                    """\
                    import pathlib
                    import shutil
                    import subprocess
                    import sys

                    root = pathlib.Path(sys.argv[sys.argv.index("--root") + 1])
                    protected = sys.argv[
                        sys.argv.index("--protected-main-commit") + 1
                    ]
                    actual = subprocess.run(
                        ["git", "-C", root, "rev-parse", "HEAD"],
                        check=True,
                        capture_output=True,
                        text=True,
                    ).stdout.strip()
                    if protected != actual:
                        raise SystemExit("protected State head is not exact")
                    if "materialize" in sys.argv:
                        output = pathlib.Path(sys.argv[sys.argv.index("--output") + 1])
                        output.mkdir(parents=True)
                        shutil.copyfile(root / "queue.json", output / "release-queue.json")
                        shutil.copyfile(root / "snapshot.json", output / "release-acceptance-snapshot.json")
                    """
                ),
                encoding="utf-8",
            )
            subprocess.run(["git", "init", "-q", state], check=True)
            subprocess.run(
                ["git", "-C", state, "config", "user.name", "Test"], check=True
            )
            subprocess.run(
                ["git", "-C", state, "config", "user.email", "test@example.com"],
                check=True,
            )
            subprocess.run(["git", "-C", state, "add", "."], check=True)
            subprocess.run(["git", "-C", state, "commit", "-qm", "source"], check=True)
            source_state_commit = subprocess.run(
                ["git", "-C", state, "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            qualification = build_qualification(
                contract,
                queue,
                snapshot,
                environment="production",
                publication_enabled="true",
                mode="publication",
                release_commit=release_commit,
                state_commit=source_state_commit,
            )
            plan = plan_next(queue, NOW, qualification)
            started = started_event(plan, NOW, random_bytes=bytes(range(10)))
            event_id = started["event_id"]
            event_path = state / "events" / event_id[:2] / f"{event_id}.json"
            result_id_value = started["subject_id"]
            status_path = (
                state
                / "views/result-release-status"
                / result_id_value[3:5]
                / f"{result_id_value}.json"
            )
            event_path.parent.mkdir(parents=True)
            status_path.parent.mkdir(parents=True)
            event_path.write_text(canonical_json(started), encoding="utf-8")
            status_path.write_text("{}\n", encoding="utf-8")
            subprocess.run(["git", "-C", state, "add", "."], check=True)
            subprocess.run(["git", "-C", state, "commit", "-qm", "started"], check=True)
            started_state_commit = subprocess.run(
                ["git", "-C", state, "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            descriptor = authority_descriptor(
                plan,
                started_state_commit,
                release_commit,
                "production",
                started,
            )
            scratch = temporary_root / "scratch"
            scratch.mkdir()
            reconstructed, reconstructed_started = reconstruct(
                descriptor,
                state_root=state,
                release_root=ROOT,
                scratch_root=scratch,
            )
            self.assertEqual(reconstructed, plan)
            self.assertEqual(reconstructed_started, started)
            self.assertFalse((scratch / "state-views").exists())

    def test_every_publication_capable_job_has_cached_latch_guard(self) -> None:
        workflow = (ROOT / ".github/workflows/release-controller.yml").read_text(
            encoding="utf-8"
        )
        jobs = workflow_jobs(workflow)
        publication_markers = (
            "git -C state push origin HEAD:main",
            "id-token: write",
            "secrets.RELEASE_PUBLISH_KEY",
        )
        publication_jobs = {
            name
            for name, block in jobs.items()
            if any(marker in block for marker in publication_markers)
        }
        self.assertEqual(publication_jobs, {"prepare-one", "unwrap-publish"})

        latch = (
            "needs.authorize-publication.outputs.publication_enabled == 'true'"
        )
        for name in sorted(publication_jobs):
            with self.subTest(job=name):
                condition = workflow_job_condition(jobs[name])
                self.assertEqual(condition.count(latch), 1)

        gate = jobs["authorize-publication"]
        gate_condition = workflow_job_condition(gate)
        self.assertIn(
            "github.repository == 'leanprover/lean-eval-releases'",
            gate_condition,
        )
        self.assertIn("github.ref == 'refs/heads/main'", gate_condition)
        self.assertIn("inputs.confirm_publication == true", gate_condition)
        self.assertIn("environment: release-production", gate)
        self.assertIn("permissions: {}", gate)
        self.assertIn("timeout-minutes: 1", gate)
        self.assertIn("PUBLICATION_ENABLED: ${{ vars.PUBLICATION_ENABLED }}", gate)
        self.assertIn('""|false) enabled=false', gate)
        self.assertIn("true) enabled=true", gate)
        self.assertNotIn("secrets.", gate)

        for name, block in jobs.items():
            with self.subTest(job_level_environment_variable=name):
                if "\n    if:" in block:
                    self.assertNotIn(
                        "vars.PUBLICATION_ENABLED",
                        workflow_job_condition(block),
                    )
        self.assertEqual(workflow.count("vars.PUBLICATION_ENABLED"), 1)
        self.assertIn(
            "PUBLICATION_ENABLED: "
            "${{ needs.authorize-publication.outputs.publication_enabled }}",
            jobs["prepare-one"],
        )
        controller_test_commands = [
            line.strip()
            for line in jobs["prepare-one"].splitlines()
            if "python -m unittest discover -s tests -v" in line
        ]
        self.assertEqual(
            controller_test_commands,
            ["PUBLICATION_ENABLED=false python -m unittest discover -s tests -v"],
        )

        documentation = "\n".join(
            (ROOT / path).read_text(encoding="utf-8")
            for path in ("README.md", "docs/release-controller-contract.md")
        )
        self.assertIn("workflow run context", documentation)
        self.assertRegex(
            documentation,
            r"cancel\s+every queued or running controller run",
        )
        self.assertIn("`Variables` repository permission (read)", documentation)
        self.assertNotIn("fresh repository Actions-variable API", documentation)

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
                    else (
                        "Invoke once, require reuse refusal, and exec the "
                        "sanitized staging tail"
                    )
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
            self.assertIn(
                keys.get("name"),
                {
                    "Stage exact encrypted inputs without executing checked-out code",
                    f"Require the exact {environment} release Invoke role",
                },
            )
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
                    r'^(?:test -f|cp) "audit/\$(?:ARCHIVE_PATH|sidecar_path)"',
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
        for phase in (
            "provider-runner-command-scan",
            "provider-aws-home-scan",
            "provider-runner-state-validation",
            "provider-input-validation",
            "provider-output-write",
        ):
            self.assertIn(phase, final_text)
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
        proof = sanitizer.index('proc="/proc/self/environ"')
        self.assertNotIn("PPID", sanitizer)
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
            "scripts/publish_release.py",
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
        self.assertIn("run_exact_python_quiet publication-write", authority_tail)
        self.assertNotIn("git diff --cached --check", authority_tail)
        self.assertNotIn('git commit -m "Publish delayed source', authority_tail)
        self.assertNotIn('cp -a "$RUNNER_TEMP/reconstructed', authority_tail)
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
        self.assertIn(". ':(exclude)state'", sanitizer)
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
        self.assertIn("deliberately use the hosted\n        # ShellCheck", validate)
        self.assertIn("actionlint -shellcheck= -pyflakes=", validate)
        contract = (ROOT / "docs/release-controller-contract.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "execution plan and `release.started` body never cross a job-output",
            contract,
        )
        self.assertRegex(contract, r"Base64 is not\s+treated\s+as confidentiality")
        self.assertIn("production_metadata.prompt", contract)
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
                )
                .replace("/usr/bin/rm", str(rm))
                .replace("/usr/bin/bash", str(bash)),
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
                "release-authority.json": b"{}\n",
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
            subprocess.run(["git", "-C", state, "commit", "-qm", "fixture"], check=True)
            state_commit = subprocess.run(
                ["git", "-C", state, "rev-parse", "HEAD"],
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
                "state_commit": state_commit,
                "authority_tail_blob": tail_blob,
                "authority_descriptor_sha256": digest("release-authority.json"),
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
            (runner / "release-authority.json").write_text(
                "tampered\n", encoding="utf-8"
            )
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

            # Both modes intentionally nest the separately pinned and clean
            # State checkout. Excluding exactly it must not mask other dirt.
            for name, content in inputs.items():
                path = runner / name
                path.write_bytes(content)
                if name == "age-bin":
                    path.chmod(0o555)
            production_proof = {
                **proof,
                "mode": "production",
            }
            proof_path.write_text(
                json.dumps(production_proof) + "\n", encoding="utf-8"
            )
            accepted = run("production")
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            (runner / "tail-ran").unlink()

            (state / "state.json").write_text("dirty\n", encoding="utf-8")
            proof_path.write_text(
                json.dumps(production_proof) + "\n", encoding="utf-8"
            )
            rejected = run("production")
            self.assertNotEqual(rejected.returncode, 0)
            self.assertFalse((runner / "tail-ran").exists())
            subprocess.run(
                ["git", "-C", state, "restore", "state.json"], check=True
            )

            for name, content in inputs.items():
                path = runner / name
                path.write_bytes(content)
                if name == "age-bin":
                    path.chmod(0o555)
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
                    "unwrap-reuse-response.json",
                    "unwrap-reuse-metadata.json",
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
                    cleanup_paths = [
                        *(cleanup_root / name for name in cleanup_files),
                        cleanup_root / "reconstructed",
                        cleanup_root / ".reconstructed-private",
                        cleanup_root / "state-views",
                    ]
                    deadline = time.monotonic() + 10
                    while (
                        any(path.exists() for path in cleanup_paths)
                        and time.monotonic() < deadline
                    ):
                        time.sleep(0.01)
                    for name in cleanup_files:
                        self.assertFalse((cleanup_root / name).exists(), name)
                    self.assertFalse((cleanup_root / "reconstructed").exists())
                    self.assertEqual(
                        list(cleanup_root.glob(".reconstructed-*")), []
                    )
                    self.assertFalse((cleanup_root / "state-views").exists())

                def process_start(pid: int) -> str:
                    process_stat = pathlib.Path(f"/proc/{pid}/stat").read_text(
                        encoding="ascii"
                    )
                    return process_stat.rsplit(") ", 1)[1].split()[19]

                def assert_process_terminated(pid: int, expected_start: str) -> None:
                    stat_path = pathlib.Path(f"/proc/{pid}/stat")
                    deadline = time.monotonic() + 2
                    state = ""
                    while time.monotonic() < deadline:
                        try:
                            process_stat = stat_path.read_text(encoding="ascii")
                        except FileNotFoundError:
                            return
                        fields = process_stat.rsplit(") ", 1)[1].split()
                        state = fields[0]
                        if fields[19] != expected_start:
                            return
                        if state == "Z":
                            return
                        time.sleep(0.01)
                    self.fail(f"process {pid} remained live in state {state!r}")

                def assert_supervisor_terminated(
                    current_runner: pathlib.Path = runner,
                ) -> None:
                    marker = b"lean-eval-release-cleanup-supervisor-v1"
                    expected_runner = os.fsencode(current_runner)
                    deadline = time.monotonic() + 30
                    live: list[int] = []
                    while time.monotonic() < deadline:
                        live = []
                        for cmdline in pathlib.Path("/proc").glob("[0-9]*/cmdline"):
                            try:
                                arguments = cmdline.read_bytes().split(b"\0")
                            except (
                                FileNotFoundError,
                                PermissionError,
                                ProcessLookupError,
                            ):
                                continue
                            if any(
                                argument == marker
                                and index + 1 < len(arguments)
                                and arguments[index + 1] == expected_runner
                                for index, argument in enumerate(arguments)
                            ):
                                live.append(int(cmdline.parent.name))
                        if not live:
                            return
                        time.sleep(0.01)
                    self.fail(f"cleanup supervisors remained live: {live}")

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

                supervisor_arguments = (
                    '"$RUNNER_TEMP" "$$" "$parent_start" "$parent_group"'
                )
                for identity, replacement in (
                    (
                        "pid",
                        (
                            '"$RUNNER_TEMP" 99999999 "$parent_start" '
                            '"$parent_group"'
                        ),
                    ),
                    (
                        "start-time",
                        (
                            '"$RUNNER_TEMP" "$$" "$((parent_start + 1))" '
                            '"$parent_group"'
                        ),
                    ),
                ):
                    with self.subTest(
                        workflow=workflow_name,
                        supervisor_identity=identity,
                    ):
                        populate()
                        corrupted_boundary = supervisor_boundary.replace(
                            supervisor_arguments,
                            replacement,
                            1,
                        )
                        self.assertNotEqual(
                            corrupted_boundary,
                            supervisor_boundary,
                        )
                        after_supervisor = runner / "after-supervisor"
                        rejected_identity = subprocess.run(
                            isolated_command(
                                prologue
                                + corrupted_boundary
                                + f": > {after_supervisor}\n"
                            ),
                            check=False,
                            capture_output=True,
                            text=True,
                            timeout=10,
                            env={"RUNNER_TEMP": str(runner)},
                        )
                        self.assertNotEqual(rejected_identity.returncode, 0)
                        self.assertFalse(after_supervisor.exists())
                        assert_clean()
                        assert_supervisor_terminated()

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
                assert_supervisor_terminated()

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
                        child_start = process_start(child_pid)
                        os.kill(signaled.pid, signal_value)
                        self.assertNotEqual(signaled.wait(timeout=5), 0)
                        deadline = time.monotonic() + 5
                        while any(
                            (runner / name).exists() for name in private_files
                        ) and time.monotonic() < deadline:
                            time.sleep(0.01)
                        assert_clean()
                        assert_supervisor_terminated()
                        assert_process_terminated(child_pid, child_start)

                # A surviving foreground writer must be terminated, and a
                # write racing the first scrub must be removed by the repeated
                # cleanup pass before the supervisor exits.
                populate()
                writer_ready = runner / "writer-ready"
                allow_writer = runner / "allow-writer"
                writer_ran = runner / "writer-ran"
                writer_pid_path = runner / "writer-pid"
                writer_code = textwrap.dedent(
                    f"""\
                    import os
                    import pathlib
                    import signal
                    import time

                    signal.signal(signal.SIGTERM, signal.SIG_IGN)
                    pathlib.Path({str(writer_pid_path)!r}).write_text(str(os.getpid()))
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
                writer_pid = int(writer_pid_path.read_text(encoding="ascii"))
                writer_start = process_start(writer_pid)
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
                assert_supervisor_terminated()
                assert_process_terminated(writer_pid, writer_start)

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
                assert_supervisor_terminated()

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
            self.assertIn(
                '"$RUNNER_TEMP/unwrap-request.json" >/dev/null 2>&1 <<\'PY\'',
                run,
            )
            self.assertIn('> "$RUNNER_TEMP/unwrap-metadata.json" 2>/dev/null', run)
            self.assertIn(
                'echo "private release failed closed: $provider_phase" >&2',
                run,
            )
            proof = sanitizer_literal.index('proc="/proc/self/environ"')
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
        descriptor = authority_descriptor(
            self.plan,
            "5" * 40,
            "4" * 40,
            "production",
            started_event(self.plan, NOW, random_bytes=bytes(range(10))),
        )
        actual = release_provider_literal.build_request_from_authority(
            descriptor,
            self.sidecar,
            self.ciphertext,
            trusted,
            random_bytes=random_bytes,
            runner_nonce=nonce,
        )
        self.assertEqual(actual, expected)

        with tempfile.TemporaryDirectory() as temporary:
            scratch = pathlib.Path(temporary)
            home = scratch / "home"
            runner = scratch / "runner"
            home.mkdir()
            runner.mkdir()
            authority_path = scratch / "authority.json"
            sidecar_path = scratch / "sidecar.json"
            ciphertext_path = scratch / "archive.tar.age"
            output_path = scratch / "unwrap-request.json"
            authority_path.write_text(canonical_json(descriptor), encoding="utf-8")
            hostile_sidecar = copy.deepcopy(self.sidecar)
            hostile_field = "PRIVATE_SIDECAR_FIELD_SENTINEL"
            hostile_sidecar[hostile_field] = "private value"
            sidecar_path.write_text(
                canonical_json(hostile_sidecar), encoding="utf-8"
            )
            ciphertext_path.write_bytes(self.ciphertext)
            environment = os.environ.copy()
            environment.update(
                HOME=str(home),
                RUNNER_TEMP=str(runner),
                AWS_ACCESS_KEY_ID="temporary-exact-access-key",
                AWS_SECRET_ACCESS_KEY="temporary-exact-secret-key",
                AWS_SESSION_TOKEN="temporary-exact-session-token",
                AWS_REGION="us-east-1",
                AWS_DEFAULT_REGION="us-east-1",
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    "scripts/release_provider_literal.py",
                    str(authority_path),
                    str(sidecar_path),
                    str(ciphertext_path),
                    str(output_path),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                env=environment,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(completed.returncode, 13)
            self.assertEqual(completed.stdout, "")
            self.assertEqual(completed.stderr, "literal provider failed closed\n")
            self.assertNotIn(hostile_field, completed.stderr)
            self.assertFalse(output_path.exists())

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
                    release_provider_literal.build_request_from_authority(
                        descriptor,
                        sidecar,
                        ciphertext,
                        trusted,
                        random_bytes=random_bytes,
                        runner_nonce=nonce,
                    )

    def test_legacy_full_plan_validators_retain_rejection_parity(self) -> None:
        plan = copy.deepcopy(self.plan)
        plan["request"]["controller"] = {
            "schema_version": 1,
            "environment": "production",
            "mode": "publication",
            "release_repository": "leanprover/lean-eval-releases",
            "release_commit": "4" * 40,
            "state_repository": "leanprover/lean-eval-state",
            "state_commit": "5" * 40,
            "state_contract_commit": "7ffb7ffb78d79847137785c65df25770f41b62ef",
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

    def test_literal_provider_rejects_every_authority_descriptor_field_drift(
        self,
    ) -> None:
        descriptor = authority_descriptor(
            self.plan,
            "5" * 40,
            "4" * 40,
            "production",
            started_event(self.plan, NOW, random_bytes=bytes(range(10))),
        )
        trusted = dt.datetime.fromisoformat(NOW.replace("Z", "+00:00"))
        self.assertEqual(
            set(descriptor), release_provider_literal.AUTHORITY_DESCRIPTOR_FIELDS
        )
        for field in sorted(descriptor):
            with self.subTest(field=field):
                missing = copy.deepcopy(descriptor)
                del missing[field]
                with self.assertRaises(release_provider_literal.ProviderError):
                    release_provider_literal.build_request_from_authority(
                        missing, self.sidecar, self.ciphertext, trusted
                    )
                changed = copy.deepcopy(descriptor)
                changed[field] = None
                with self.assertRaises(release_provider_literal.ProviderError):
                    release_provider_literal.build_request_from_authority(
                        changed, self.sidecar, self.ciphertext, trusted
                    )
        extra = {**descriptor, "production_metadata": {"prompt": "private"}}
        with self.assertRaises(release_provider_literal.ProviderError):
            release_provider_literal.build_request_from_authority(
                extra, self.sidecar, self.ciphertext, trusted
            )

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
                "AWS_SECRET_ACCESS_KEY": "temporary-exact-secret-key",
                "AWS_SESSION_TOKEN": "temporary-exact-session-token",
                "AWS_REGION": "us-east-1",
                "AWS_DEFAULT_REGION": "us-east-1",
            }
            (commands / "safe").write_text("PATH=/usr/bin\n", encoding="utf-8")
            release_provider_literal.scan_authority_files(environment)
            (commands / "credential").write_text(
                "temporary-exact-access-key\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                release_provider_literal.ProviderError,
                "authority file scan failed",
            ) as rejected:
                release_provider_literal.scan_authority_files(environment)
            self.assertEqual(rejected.exception.diagnostic, "runner-command-scan")
            (commands / "credential").unlink()
            records = [
                ("AWS_ACCESS_KEY_ID", ""),
                ("AWS_SECRET_ACCESS_KEY", ""),
                ("AWS_SESSION_TOKEN", ""),
                ("AWS_REGION", ""),
                ("AWS_DEFAULT_REGION", ""),
                ("AWS_DEFAULT_REGION", "us-east-1"),
                ("AWS_REGION", "us-east-1"),
                ("AWS_ACCESS_KEY_ID", "temporary-exact-access-key"),
                ("AWS_SECRET_ACCESS_KEY", "temporary-exact-secret-key"),
                ("AWS_SESSION_TOKEN", "temporary-exact-session-token"),
            ]

            def serialized_export(values: list[tuple[str, str]]) -> str:
                chunks = []
                for index, (name, value) in enumerate(values, start=1):
                    delimiter = (
                        "ghadelimiter_00000000-0000-0000-0000-"
                        f"{index:012x}"
                    )
                    chunks.append(f"{name}<<{delimiter}\n{value}\n{delimiter}\n")
                return "".join(chunks)

            export = commands / "set_env_12345678-1234-1234-1234-123456789abc"
            export.write_text(serialized_export(records), encoding="utf-8")
            release_provider_literal.remove_expected_aws_credential_export(
                environment
            )
            self.assertFalse(export.exists())
            self.assertTrue((commands / "safe").is_file())
            release_provider_literal.scan_authority_files(environment)
            malformed = commands / "unexpected-export"
            malformed.write_text(
                "AWS_ACCESS_KEY_ID=temporary-exact-access-key\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                release_provider_literal.ProviderError,
                "credential export cleanup failed",
            ) as rejected:
                release_provider_literal.remove_expected_aws_credential_export(
                    environment
                )
            self.assertEqual(rejected.exception.diagnostic, "runner-command-scan")
            self.assertTrue(malformed.is_file())
            malformed.unlink()

            extra_authority = commands / (
                "set_env_23456789-2345-2345-2345-23456789abcd"
            )
            extra_authority.write_text(
                serialized_export(
                    records
                    + [("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "retained-authority")]
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                release_provider_literal.ProviderError,
                "credential export cleanup failed",
            ) as rejected:
                release_provider_literal.remove_expected_aws_credential_export(
                    environment
                )
            self.assertEqual(rejected.exception.diagnostic, "runner-command-scan")
            self.assertTrue(extra_authority.is_file())
            extra_authority.unlink()

            swapped = records.copy()
            swapped[-3] = ("AWS_ACCESS_KEY_ID", "temporary-exact-secret-key")
            swapped[-2] = ("AWS_SECRET_ACCESS_KEY", "temporary-exact-access-key")
            swapped_export = commands / (
                "set_env_3456789a-3456-3456-3456-3456789abcde"
            )
            swapped_export.write_text(serialized_export(swapped), encoding="utf-8")
            with self.assertRaises(release_provider_literal.ProviderError):
                release_provider_literal.remove_expected_aws_credential_export(
                    environment
                )
            self.assertTrue(swapped_export.is_file())
            swapped_export.unlink()

            linked_export = commands / (
                "set_env_456789ab-4567-4567-4567-456789abcdef"
            )
            linked_export.write_text(serialized_export(records), encoding="utf-8")
            linked_copy = commands / "linked-export"
            os.link(linked_export, linked_copy)
            with self.assertRaises(release_provider_literal.ProviderError):
                release_provider_literal.remove_expected_aws_credential_export(
                    environment
                )
            self.assertTrue(linked_export.is_file())
            self.assertTrue(linked_copy.is_file())
            linked_copy.unlink()
            linked_export.unlink()

            symlink_target = root / "symlink-target"
            symlink_target.write_text(serialized_export(records), encoding="utf-8")
            symlink_export = commands / (
                "set_env_4abcdef0-4567-4567-4567-456789abcdef"
            )
            symlink_export.symlink_to(symlink_target)
            with self.assertRaises(release_provider_literal.ProviderError):
                release_provider_literal.remove_expected_aws_credential_export(
                    environment
                )
            self.assertTrue(symlink_export.is_symlink())
            symlink_export.unlink()
            symlink_target.unlink()

            nested = commands / "nested"
            nested.mkdir()
            nested_export = nested / (
                "set_env_4bcdef01-4567-4567-4567-456789abcdef"
            )
            nested_export.write_text(serialized_export(records), encoding="utf-8")
            with self.assertRaises(release_provider_literal.ProviderError):
                release_provider_literal.remove_expected_aws_credential_export(
                    environment
                )
            self.assertTrue(nested_export.is_file())
            nested_export.unlink()
            nested.rmdir()

            first = commands / "set_env_56789abc-5678-5678-5678-56789abcdef0"
            second = commands / "set_env_6789abcd-6789-6789-6789-6789abcdef01"
            first.write_text(serialized_export(records), encoding="utf-8")
            second.write_text(serialized_export(records), encoding="utf-8")
            with self.assertRaisesRegex(
                release_provider_literal.ProviderError,
                "not unique",
            ):
                release_provider_literal.remove_expected_aws_credential_export(
                    environment
                )
            self.assertTrue(first.is_file())
            self.assertTrue(second.is_file())
            first.unlink()
            second.unlink()

            (aws / "credentials").write_text(
                "aws_secret_access_key = residual\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                release_provider_literal.ProviderError,
                "authority file scan failed",
            ) as rejected:
                release_provider_literal.scan_authority_files(environment)
            self.assertEqual(rejected.exception.diagnostic, "aws-home-scan")

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
        self.assertIn(
            "python state/scripts/state.py --root state \\\n"
            '            --protected-main-commit "$state_head" validate',
            workflow,
        )
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

    def test_production_noop_preflight_is_disabled_write_free_and_exact(self) -> None:
        workflow = (
            ROOT / ".github/workflows/verify-production-release-noop.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("schedule:", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn("push:\n", workflow)
        self.assertNotIn("workflow_call:", workflow)
        self.assertIn("inputs.confirm_publication_disabled == true", workflow)
        self.assertIn("environment: release-production", workflow)
        self.assertIn("group: lean-eval-release-controller-production", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("PUBLICATION_ENABLED must remain absent or false", workflow)
        self.assertIn("--mode preflight", workflow)
        self.assertIn("scripts/release_qualification.py", workflow)
        self.assertIn("scripts/release_controller.py recover", workflow)
        self.assertIn("scripts/release_orchestrator.py", workflow)
        self.assertIn('. == {schema_version: 1, kind: "none"}', workflow)
        self.assertIn("empty|not_due", workflow)
        self.assertEqual(
            set(re.findall(r"secrets\.([A-Z0-9_]+)", workflow)),
            {"PRODUCTION_STATE_CONTROLLER_KEY"},
        )
        self.assertEqual(workflow.count("persist-credentials: false"), 3)
        self.assertEqual(workflow.count("repository: leanprover/lean-eval-state"), 2)
        self.assertIn("contents: read", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("id-token: write", workflow)
        self.assertNotIn("RELEASE_PUBLISH_KEY", workflow)
        self.assertNotIn("AUDIT_READ_KEY", workflow)
        for forbidden in (
            "git commit",
            "git push",
            "state.py --root state append",
            "configure-aws-credentials",
            "aws ",
            "upload-artifact",
            "download-artifact",
            "repository: leanprover/lean-eval-audit",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, workflow)

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
        self.assertIn("expected_release_commit:", workflow)
        self.assertRegex(
            workflow,
            re.compile(
                r"expected_release_commit:\n"
                r"\s+description: Exact reviewed protected-main release workflow "
                r"commit\n"
                r"\s+required: true\n"
                r"\s+type: string"
            ),
        )
        self.assertIn(
            "    permissions:\n"
            "      id-token: write\n"
            "    environment: release-production\n",
            workflow,
        )
        self.assertNotIn("contents:", workflow)
        self.assertEqual(workflow.count("id-token: write"), 1)
        self.assertEqual(workflow.count("runs-on:"), 3)
        jobs = workflow_jobs(workflow)
        self.assertEqual(set(jobs), {"authorize", "oidc-trust", "summarize"})
        authorization = jobs["authorize"]
        self.assertIn("permissions: {}", authorization)
        self.assertNotIn("environment:", authorization)
        self.assertNotIn("\n    if:", authorization)
        self.assertIn(
            'test "$EVENT_REPOSITORY" = leanprover/lean-eval-releases',
            authorization,
        )
        self.assertIn('test "$EVENT_REF" = refs/heads/main', authorization)
        self.assertIn('test "$EVENT_REF_PROTECTED" = true', authorization)
        self.assertIn(
            '[[ "$EXPECTED_RELEASE_COMMIT" =~ ^[0-9a-f]{40}$ ]]',
            authorization,
        )
        self.assertIn(
            'test "$EXPECTED_RELEASE_COMMIT" = "$EVENT_SHA"',
            authorization,
        )
        self.assertIn(
            'test "$CONFIRM_PUBLICATION_DISABLED" = true', authorization
        )
        oidc = jobs["oidc-trust"]
        self.assertIn("needs: authorize", oidc)
        self.assertNotIn("\n    if:", oidc)
        summary = jobs["summarize"]
        self.assertIn("needs: oidc-trust", summary)
        self.assertNotIn("\n    if:", summary)
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
            self.assertIn("expected_release_commit:", candidate)
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
            jobs = workflow_jobs(candidate)
            self.assertEqual(set(jobs), {"authorize", "oidc-trust", "summarize"})
            authorization = jobs["authorize"]
            self.assertIn("permissions: {}", authorization)
            self.assertNotIn("environment:", authorization)
            self.assertNotIn("\n    if:", authorization)
            self.assertIn(
                'test "$EVENT_REPOSITORY" = leanprover/lean-eval-releases',
                authorization,
            )
            self.assertIn('test "$EVENT_REF" = refs/heads/main', authorization)
            self.assertIn(
                'test "$EVENT_REF_PROTECTED" = true', authorization
            )
            self.assertIn(
                '[[ "$EXPECTED_RELEASE_COMMIT" =~ ^[0-9a-f]{40}$ ]]',
                authorization,
            )
            self.assertIn(
                'test "$EXPECTED_RELEASE_COMMIT" = "$EVENT_SHA"',
                authorization,
            )
            self.assertIn(
                'test "$CONFIRM_PUBLICATION_DISABLED" = true', authorization
            )
            self.assertIn("needs: authorize", jobs["oidc-trust"])
            self.assertNotIn("\n    if:", jobs["oidc-trust"])
            self.assertIn("needs: oidc-trust", jobs["summarize"])
            self.assertNotIn("\n    if:", jobs["summarize"])
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
                "      expected_release_commit:\n",
                "      unbound_release_commit:\n",
            ),
            (
                '          test "$EVENT_REF_PROTECTED" = true',
                '          test "$EVENT_REF_PROTECTED" = false',
            ),
            (
                '          [[ "$EXPECTED_RELEASE_COMMIT" =~ ^[0-9a-f]{40}$ ]]',
                '          test -n "$EXPECTED_RELEASE_COMMIT"',
            ),
            (
                '          test "$EXPECTED_RELEASE_COMMIT" = "$EVENT_SHA"',
                '          test "$EXPECTED_RELEASE_COMMIT" != "$EVENT_SHA"',
            ),
            (
                "  oidc-trust:\n    needs: authorize",
                "  oidc-trust:\n    if: always()\n    needs: authorize",
            ),
            (
                "  summarize:\n    needs: oidc-trust",
                "  summarize:\n    if: always()\n    needs: oidc-trust",
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

    def test_staging_release_smoke_reuses_once_reconstructs_and_leaves_no_artifact(
        self,
    ) -> None:
        workflow = (
            ROOT / ".github/workflows/credentialed-release-staging-smoke.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "run-name: Reconstruct staging submission ${{ inputs.submission_id }}",
            workflow,
        )
        self.assertIn("expected_release_commit:", workflow)
        jobs = workflow_jobs(workflow)
        authorization = jobs["authorize-manual"]
        self.assertIn("permissions: {}", authorization)
        self.assertIn("timeout-minutes: 1", authorization)
        self.assertIn(
            'test "$EVENT_REPOSITORY" = leanprover/lean-eval-releases',
            authorization,
        )
        self.assertIn('test "$EVENT_REF" = refs/heads/main', authorization)
        self.assertIn('test "$EVENT_REF_PROTECTED" = true', authorization)
        self.assertIn('test "$CONFIRM_STAGING_SMOKE" = true', authorization)
        self.assertIn(
            'test "$EXPECTED_RELEASE_COMMIT" = "$EVENT_SHA"', authorization
        )
        self.assertNotIn("environment:", authorization)
        self.assertNotIn("secrets.", authorization)
        prepare = jobs["prepare-one"]
        self.assertIn("needs: authorize-manual", prepare)
        self.assertNotIn("\n    if:", prepare)
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
        self.assertEqual(workflow.count("aws lambda invoke"), 2)
        self.assertEqual(
            workflow.count(
                '--payload "fileb://$RUNNER_TEMP/unwrap-request.json"'
            ),
            2,
        )
        self.assertIn("unwrap_request_sha256=$(sha256sum", workflow)
        self.assertGreaterEqual(
            workflow.count('!= "$unwrap_request_sha256"'),
            2,
        )
        provider = workflow[workflow.index("provider_phase=provider-invocation") :]
        self.assertLess(
            provider.index('"$RUNNER_TEMP/unwrap-response.json"'),
            provider.index('"$RUNNER_TEMP/unwrap-reuse-response.json"'),
        )
        self.assertLess(
            provider.index("unwrap-reuse-response.json"),
            provider.index("unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY"),
        )
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
        self.assertIn("scripts/reconstruct_release_plan.py", tail)
        sanitizer = (ROOT / "scripts/release_sanitizer_literal.sh").read_text(
            encoding="utf-8"
        )
        proof = sanitizer.index('proc="/proc/self/environ"')
        checkout_tail = sanitizer.index(
            "scripts/release_authority_tail.sh", proof
        )
        tail = (ROOT / "scripts/release_authority_tail.sh").read_text(
            encoding="utf-8"
        )
        self.assertGreater(checkout_tail, proof)
        self.assertIn('if [ "$mode" = staging ]', tail)
        self.assertIn('"$RUNNER_TEMP/age-bin" --decrypt', tail)
        self.assertIn("verify-unwrap-reuse-refusal", tail)
        self.assertIn("scripts/reconstruct_release.py", tail)
        self.assertIn("scripts/validate_manifest.py", tail)
        self.assertIn("release-acceptance-snapshot.json", tail)
        self.assertIn('test ! -e "$RUNNER_TEMP/reconstructed"', tail)
        self.assertIn("audit SSH key was not synchronously removed", workflow)

    def test_every_state_consumer_binds_the_exact_protected_head(self) -> None:
        shell_consumers = {
            ".github/workflows/credentialed-release-staging-smoke.yml": 2,
            ".github/workflows/release-controller.yml": 4,
            ".github/workflows/verify-production-controller-credentials.yml": 2,
            "scripts/release_authority_tail.sh": 6,
        }
        invocation = re.compile(
            r"state/scripts/state\.py --root state \\\n"
            r"\s+--protected-main-commit \"\$[A-Za-z_][A-Za-z0-9_]*\" "
            r"(?:validate|materialize)"
        )
        for relative, expected in shell_consumers.items():
            with self.subTest(consumer=relative):
                source = (ROOT / relative).read_text(encoding="utf-8")
                self.assertEqual(source.count("state/scripts/state.py"), expected)
                self.assertEqual(len(invocation.findall(source)), expected)

        reconstruction = (
            ROOT / "scripts/reconstruct_release_plan.py"
        ).read_text(encoding="utf-8")
        self.assertEqual(
            reconstruction.count('worktree / "scripts/state.py"'),
            2,
        )
        self.assertEqual(
            reconstruction.count(
                '"--protected-main-commit",\n            state_commit,'
            ),
            2,
        )

    def test_staging_summary_uses_plan_bound_submission_id(self) -> None:
        workflow = (
            ROOT / ".github/workflows/credentialed-release-staging-smoke.yml"
        ).read_text(encoding="utf-8")
        tail = (ROOT / "scripts/release_authority_tail.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "submission_id=$(jq -er .request.submission.submission_id",
            tail,
        )
        self.assertIn('echo "- submission: \\`$submission_id\\`"', tail)
        self.assertNotIn("SUBMISSION_ID", tail)
        authority_step = str(
            workflow_job_steps(workflow, "unwrap-one")[-1]["text"]
        )
        self.assertNotIn("inputs.submission_id", authority_step)
        self.assertNotIn("SUBMISSION_ID", authority_step)

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
        self.assertEqual(len(references), 33)

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

    def test_staging_smoke_isolates_requested_task_from_earlier_competitor(
        self,
    ) -> None:
        queue = json.loads(
            (ROOT / "tests/fixtures/release-queue-v1.json").read_text(
                encoding="utf-8"
            )
        )
        queue["environment"] = "staging"
        requested = queue["tasks"][0]
        competing = copy.deepcopy(requested)
        competing.update(
            event_id="0198abcd-0000-7000-8000-00000000000d",
            owner_login="aaron",
            submission_id="0198abcd-0000-7000-8000-000000000003",
        )
        competing["archive_path"] = (
            "archives/01/0198abcd-0000-7000-8000-000000000003.tar.age"
        )
        competing["result_id"] = result_id(
            competing["owner_login"],
            competing["declared_model"],
            competing["problem_id"],
            competing["statement_revision"],
        )
        queue["tasks"].append(competing)
        queue["tasks"].sort(key=lambda task: task["result_id"])
        self.assertLess(competing["result_id"], requested["result_id"])
        queue_before = copy.deepcopy(queue)

        plan = staging_smoke_plan(queue, requested["submission_id"])

        self.assertEqual(queue, queue_before)
        self.assertEqual(plan["kind"], "execution")
        self.assertEqual(
            plan["request"]["submission"]["submission_id"],
            requested["submission_id"],
        )
        self.assertEqual(
            plan["request"]["result"]["result_id"], requested["result_id"]
        )
        self.assertEqual(
            plan["request"]["release"]["eligible_at"], requested["release_at"]
        )

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

    def test_identical_unwrap_reuse_requires_exact_consumed_refusal(self) -> None:
        verify_unwrap_reuse_refusal(
            {
                "errorMessage": "capability has already been consumed",
                "errorType": "AwsAdapterError",
                "requestId": "12345678-1234-1234-1234-123456789abc",
                "stackTrace": ["  File /var/task/aws_key_adapter.py, line 1"],
            },
            {"StatusCode": 200, "FunctionError": "Unhandled"},
        )
        canonical_response = {
            "errorMessage": "capability has already been consumed",
            "errorType": "AwsAdapterError",
            "requestId": "12345678-1234-1234-1234-123456789abc",
            "stackTrace": ["  File /var/task/aws_key_adapter.py, line 1"],
        }
        for response, metadata, message in (
            (
                {**canonical_response, "errorMessage": "provider unavailable"},
                {"StatusCode": 200, "FunctionError": "Unhandled"},
                "unexpected reason",
            ),
            (
                canonical_response,
                {"StatusCode": 200},
                "Lambda function error",
            ),
            (
                {
                    **canonical_response,
                    "plaintext_identity_base64": "QUdFLVNFQ1JFVC1LRVkt",
                },
                {"StatusCode": 200, "FunctionError": "Unhandled"},
                "fields are not canonical",
            ),
            (
                {**canonical_response, "errorType": "RuntimeError"},
                {"StatusCode": 200, "FunctionError": "Unhandled"},
                "error type",
            ),
            (
                {**canonical_response, "requestId": "not-a-request-id"},
                {"StatusCode": 200, "FunctionError": "Unhandled"},
                "requestId",
            ),
            (
                {**canonical_response, "stackTrace": "not-a-list"},
                {"StatusCode": 200, "FunctionError": "Unhandled"},
                "stack trace",
            ),
            (
                {
                    **canonical_response,
                    "stackTrace": ["AGE-SECRET-KEY-1PRIVATE"],
                },
                {"StatusCode": 200, "FunctionError": "Unhandled"},
                "private identity",
            ),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(ControllerError, message):
                    verify_unwrap_reuse_refusal(response, metadata)

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
