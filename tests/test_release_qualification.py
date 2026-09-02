from __future__ import annotations

import copy
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import plan_release_removal as removal_module  # noqa: E402
from release_orchestrator import (  # noqa: E402
    STAGING_STATE_RELEASE_CONTRACT_COMMIT,
    STAGING_STATE_RELEASE_CONTRACT_TREES,
    STATE_RELEASE_CONTRACT_COMMIT,
    STATE_RELEASE_CONTRACT_TREES,
    ReleaseError,
    canonical_json_digest,
    plan_next,
)
from release_qualification import (  # noqa: E402
    QualificationError,
    build_qualification,
    qualify_repository,
    validate_contract,
)
from verify_release_state_contract import STATE_CONTRACTS  # noqa: E402


class ReleaseQualificationTests(unittest.TestCase):
    def contract(self) -> dict[str, object]:
        return json.loads(
            (
                ROOT / "configuration/release-controller-credential-contract-v1.json"
            ).read_text(encoding="utf-8")
        )

    def queue(self) -> dict[str, object]:
        return json.loads(
            (ROOT / "tests/fixtures/release-queue-v1.json").read_text(encoding="utf-8")
        )

    def snapshot(self) -> dict[str, object]:
        return json.loads(
            (ROOT / "tests/fixtures/release-acceptance-snapshot-v1.json").read_text(
                encoding="utf-8"
            )
        )

    def test_closed_credential_contract_names_only_minimum_authority(self) -> None:
        contract = validate_contract(self.contract())
        self.assertEqual(contract["publication_latch"], "PUBLICATION_ENABLED")
        self.assertEqual(contract["audit"]["permission"], "contents-read")
        self.assertEqual(contract["release"]["credential"], "RELEASE_PUBLISH_KEY")
        self.assertEqual(
            contract["state"]["credential"], "PRODUCTION_STATE_CONTROLLER_KEY"
        )

    def test_state_contract_pins_are_consistent(self) -> None:
        contract_commit = self.contract()["state"]["minimum_contract_commit"]
        release_plan_schema = json.loads(
            (ROOT / "schema/release-plan-v1.schema.json").read_text(encoding="utf-8")
        )
        schema_commit = release_plan_schema["$defs"]["controllerQualification"][
            "properties"
        ]["state_contract_commit"]["const"]
        self.assertEqual(
            STATE_RELEASE_CONTRACT_COMMIT,
            "7ffb7ffb78d79847137785c65df25770f41b62ef",
        )
        self.assertEqual(contract_commit, STATE_RELEASE_CONTRACT_COMMIT)
        self.assertEqual(schema_commit, STATE_RELEASE_CONTRACT_COMMIT)
        self.assertEqual(
            removal_module.STATE_REMOVAL_CONTRACT_COMMIT,
            STATE_RELEASE_CONTRACT_COMMIT,
        )
        self.assertEqual(
            removal_module.STATE_REMOVAL_CONTRACT_TREES,
            STATE_RELEASE_CONTRACT_TREES,
        )
        self.assertEqual(
            STATE_RELEASE_CONTRACT_TREES,
            {
                "schema": "4cfe7363c7d8ab2d8ebf0cb2c4e26697c27ab680",
                "scripts": "34abea8751e17bd6d65a0bcbdc4837540b6fd84e",
            },
        )
        self.assertEqual(
            STATE_CONTRACTS["production"],
            (
                "leanprover/lean-eval-state",
                STATE_RELEASE_CONTRACT_COMMIT,
                STATE_RELEASE_CONTRACT_TREES,
            ),
        )
        self.assertEqual(
            STATE_CONTRACTS["staging"],
            (
                "leanprover/lean-eval-state-staging",
                STAGING_STATE_RELEASE_CONTRACT_COMMIT,
                STAGING_STATE_RELEASE_CONTRACT_TREES,
            ),
        )
        self.assertEqual(
            STAGING_STATE_RELEASE_CONTRACT_COMMIT,
            "6105a6255ec40409bcce66c6cf6b6764e0e93ed4",
        )
        self.assertEqual(
            STAGING_STATE_RELEASE_CONTRACT_TREES,
            {
                "schema": "5d3218039b1c4079d751fb54a30b1516917a81cd",
                "scripts": "6527eafbad98ed43206e9e26f1731ae16d4fc995",
            },
        )

    def test_preflight_qualification_binds_exact_materialized_inputs(self) -> None:
        queue = self.queue()
        snapshot = self.snapshot()
        qualification = build_qualification(
            self.contract(),
            queue,
            snapshot,
            environment="production",
            publication_enabled="false",
            mode="preflight",
            release_commit="a" * 40,
            state_commit="b" * 40,
        )
        self.assertEqual(
            qualification["release_queue_sha256"],
            canonical_json_digest(queue, "release-queue"),
        )
        self.assertEqual(
            qualification["acceptance_snapshot_sha256"],
            canonical_json_digest(snapshot, "acceptance-snapshot"),
        )
        self.assertEqual(qualification["mode"], "preflight")
        with self.assertRaisesRegex(ReleaseError, "identity is invalid"):
            plan_next(queue, "2026-10-20T06:07:05.000Z", qualification)
        qualification = build_qualification(
            self.contract(),
            queue,
            snapshot,
            environment="production",
            publication_enabled="true",
            mode="publication",
            release_commit="a" * 40,
            state_commit="b" * 40,
        )
        plan = plan_next(queue, "2026-10-20T06:07:05.000Z", qualification)
        self.assertEqual(plan["request"]["controller"], qualification)

        changed = copy.deepcopy(queue)
        changed["source_digest"] = "0" * 64
        with self.assertRaisesRegex(ReleaseError, "exact production queue"):
            plan_next(changed, "2026-10-20T06:07:05.000Z", qualification)

    def test_materialization_digest_vector_is_domain_separated(self) -> None:
        value = {"unicode": "λ", "nested": [True, None, 7]}
        self.assertEqual(
            canonical_json_digest(value, "release-queue"),
            "304584c69fdc10cfe13901b6d07991963b70768698aed161133ba90012bd0795",
        )
        self.assertEqual(
            canonical_json_digest(value, "acceptance-snapshot"),
            "fcbb37b5ac98438d718eba72a8624437723f49dc3b5ad069f0f4668bdabc5bf1",
        )
        with self.assertRaisesRegex(ReleaseError, "digest domain"):
            canonical_json_digest(value, "other")

    def test_modes_and_environment_fail_closed(self) -> None:
        for mode, enabled, environment in (
            ("preflight", "true", "production"),
            ("publication", "false", "production"),
            ("publication", "true", "staging"),
        ):
            with (
                self.subTest(mode=mode, enabled=enabled, environment=environment),
                self.assertRaises(QualificationError),
            ):
                build_qualification(
                    self.contract(),
                    self.queue(),
                    self.snapshot(),
                    environment=environment,
                    publication_enabled=enabled,
                    mode=mode,
                    release_commit="a" * 40,
                    state_commit="b" * 40,
                )

    def test_contract_rejects_credential_or_state_pin_broadening(self) -> None:
        for path, value in (
            (("audit", "permission"), "contents-read-write"),
            (("release", "ref"), "refs/heads/other"),
            (("state", "minimum_contract_commit"), "0" * 40),
        ):
            with self.subTest(path=path):
                contract = copy.deepcopy(self.contract())
                contract[path[0]][path[1]] = value
                with self.assertRaises(QualificationError):
                    validate_contract(contract)

    def test_local_repository_must_be_exact_origin_main_and_descend_from_pin(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            subprocess.run(["git", "init", "-q", "-b", "main", root], check=True)
            subprocess.run(
                ["git", "-C", root, "config", "user.email", "test@example.com"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", root, "config", "user.name", "Test"], check=True
            )
            (root / "schema").mkdir()
            (root / "schema" / "status.json").write_text("{}\n", encoding="utf-8")
            (root / "scripts").mkdir()
            (root / "scripts" / "validate.py").write_text("pass\n", encoding="utf-8")
            (root / "contract").write_text("one\n", encoding="utf-8")
            (root / ".gitignore").write_text("ignored.py\n", encoding="utf-8")
            subprocess.run(["git", "-C", root, "add", "."], check=True)
            subprocess.run(["git", "-C", root, "commit", "-qm", "contract"], check=True)
            minimum = subprocess.check_output(
                ["git", "-C", root, "rev-parse", "HEAD"], text=True
            ).strip()
            contract_trees = {
                path: subprocess.check_output(
                    ["git", "-C", root, "rev-parse", f"{minimum}:{path}"],
                    text=True,
                ).strip()
                for path in ("schema", "scripts")
            }
            (root / "runtime").write_text("two\n", encoding="utf-8")
            subprocess.run(["git", "-C", root, "add", "runtime"], check=True)
            subprocess.run(["git", "-C", root, "commit", "-qm", "runtime"], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    root,
                    "remote",
                    "add",
                    "origin",
                    "https://github.com/leanprover/lean-eval-state.git",
                ],
                check=True,
            )
            subprocess.run(
                ["git", "-C", root, "update-ref", "refs/remotes/origin/main", "HEAD"],
                check=True,
            )
            head = qualify_repository(
                root,
                "leanprover/lean-eval-state",
                minimum,
                contract_trees,
            )
            self.assertEqual(
                head,
                subprocess.check_output(
                    ["git", "-C", root, "rev-parse", "HEAD"], text=True
                ).strip(),
            )
            drifted_trees = {**contract_trees, "schema": "0" * 40}
            with self.assertRaisesRegex(QualificationError, "tree has drifted"):
                qualify_repository(
                    root,
                    "leanprover/lean-eval-state",
                    minimum,
                    drifted_trees,
                )
            status_schema = root / "schema" / "status.json"
            status_schema.write_text('{"drifted":true}\n', encoding="utf-8")
            subprocess.run(["git", "-C", root, "add", "schema/status.json"], check=True)
            subprocess.run(
                ["git", "-C", root, "commit", "-qm", "drift schema"], check=True
            )
            subprocess.run(
                ["git", "-C", root, "update-ref", "refs/remotes/origin/main", "HEAD"],
                check=True,
            )
            with self.assertRaisesRegex(QualificationError, "tree has drifted"):
                qualify_repository(
                    root,
                    "leanprover/lean-eval-state",
                    minimum,
                    contract_trees,
                )
            status_schema.write_text("{}\n", encoding="utf-8")
            subprocess.run(["git", "-C", root, "add", "schema/status.json"], check=True)
            subprocess.run(
                ["git", "-C", root, "commit", "-qm", "restore schema"], check=True
            )
            subprocess.run(
                ["git", "-C", root, "update-ref", "refs/remotes/origin/main", "HEAD"],
                check=True,
            )
            head = qualify_repository(
                root,
                "leanprover/lean-eval-state",
                minimum,
                contract_trees,
            )
            (root / "runtime").write_text("dirty\n", encoding="utf-8")
            with self.assertRaisesRegex(QualificationError, "tracked changes"):
                qualify_repository(
                    root,
                    "leanprover/lean-eval-state",
                    minimum,
                    contract_trees,
                )

            (root / "runtime").write_text("two\n", encoding="utf-8")
            (root / "untracked.py").write_text("raise SystemExit\n", encoding="utf-8")
            with self.assertRaisesRegex(QualificationError, "untracked files"):
                qualify_repository(
                    root,
                    "leanprover/lean-eval-state",
                    minimum,
                    contract_trees,
                    reject_untracked=True,
                )
            (root / "untracked.py").unlink()
            (root / "ignored.py").write_text("raise SystemExit\n", encoding="utf-8")
            with self.assertRaisesRegex(QualificationError, "untracked files"):
                qualify_repository(
                    root,
                    "leanprover/lean-eval-state",
                    minimum,
                    contract_trees,
                    reject_untracked=True,
                )
            (root / "ignored.py").unlink()
            subprocess.run(
                [
                    "git",
                    "-C",
                    root,
                    "remote",
                    "set-url",
                    "origin",
                    "https://github.com/attacker/lean-eval-state.git",
                ],
                check=True,
            )
            with self.assertRaisesRegex(QualificationError, "origin is invalid"):
                qualify_repository(
                    root,
                    "leanprover/lean-eval-state",
                    minimum,
                    contract_trees,
                )
            subprocess.run(
                [
                    "git",
                    "-C",
                    root,
                    "remote",
                    "set-url",
                    "origin",
                    "git@github.com:leanprover/lean-eval-state.git",
                ],
                check=True,
            )
            (root / "later").write_text("not fetched main\n", encoding="utf-8")
            subprocess.run(["git", "-C", root, "add", "later"], check=True)
            subprocess.run(["git", "-C", root, "commit", "-qm", "later"], check=True)
            with self.assertRaisesRegex(QualificationError, "not exact origin/main"):
                qualify_repository(
                    root,
                    "leanprover/lean-eval-state",
                    minimum,
                    contract_trees,
                )
            subprocess.run(
                ["git", "-C", root, "update-ref", "refs/remotes/origin/main", "HEAD"],
                check=True,
            )
            with self.assertRaisesRegex(QualificationError, "does not descend"):
                qualify_repository(
                    root,
                    "leanprover/lean-eval-state",
                    "0" * 40,
                    contract_trees,
                )

            pinned_head = subprocess.check_output(
                ["git", "-C", root, "rev-parse", "HEAD"], text=True
            ).strip()
            (root / "advanced").write_text("concurrent main append\n", encoding="utf-8")
            subprocess.run(["git", "-C", root, "add", "advanced"], check=True)
            subprocess.run(
                ["git", "-C", root, "commit", "-qm", "advance remote main"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", root, "update-ref", "refs/remotes/origin/main", "HEAD"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", root, "checkout", "--detach", "--quiet", pinned_head],
                check=True,
            )
            self.assertEqual(
                qualify_repository(
                    root,
                    "leanprover/lean-eval-state",
                    minimum,
                    contract_trees,
                    expected_head=pinned_head,
                ),
                pinned_head,
            )
            with self.assertRaisesRegex(QualificationError, "not exact origin/main"):
                qualify_repository(
                    root,
                    "leanprover/lean-eval-state",
                    minimum,
                    contract_trees,
                )

            shallow = root / ".git" / "shallow"
            shallow.write_text(head + "\n", encoding="ascii")
            with self.assertRaisesRegex(QualificationError, "complete history"):
                qualify_repository(
                    root,
                    "leanprover/lean-eval-state",
                    minimum,
                    contract_trees,
                )


if __name__ == "__main__":
    unittest.main()
