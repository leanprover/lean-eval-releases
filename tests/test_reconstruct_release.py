from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import pathlib
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "scripts"))

from reconstruct_release import (
    ReconstructionError,
    reconstruct_one,
)
from release_orchestrator import canonical_json_digest, plan_next
from release_tree import DOMAIN, projected_digest
from validate_manifest import ManifestError

ROOT = pathlib.Path(__file__).parents[1]
TRUSTED_AS_OF = "2026-10-20T06:07:05.000Z"


class ReconstructionTests(unittest.TestCase):
    def queue(self) -> dict[str, object]:
        return json.loads(
            (ROOT / "tests/fixtures/release-queue-v1.json").read_text(encoding="utf-8")
        )

    def plan(self) -> dict[str, object]:
        return plan_next(self.queue(), TRUSTED_AS_OF)

    def qualified_plan(self) -> dict[str, object]:
        queue = self.queue()
        qualification = {
            "schema_version": 1,
            "environment": "production",
            "mode": "publication",
            "release_repository": "leanprover/lean-eval-releases",
            "release_commit": "a" * 40,
            "state_repository": "leanprover/lean-eval-state",
            "state_commit": "b" * 40,
            "state_contract_commit": "c6a4bb67b55609ae7215bdd3cac2378b2db42a0a",
            "state_source_event_count": queue["source_event_count"],
            "state_source_digest": queue["source_digest"],
            "release_queue_sha256": canonical_json_digest(queue, "release-queue"),
            "acceptance_snapshot_sha256": canonical_json_digest(
                self.state(), "acceptance-snapshot"
            ),
        }
        return plan_next(queue, TRUSTED_AS_OF, qualification)

    def state(self) -> dict[str, object]:
        return json.loads(
            (ROOT / "tests/fixtures/release-acceptance-snapshot-v1.json").read_text(
                encoding="utf-8"
            )
        )

    def archive(
        self,
        directory: pathlib.Path,
        *,
        files: dict[str, bytes] | None = None,
        link: tuple[str, str] | None = None,
    ) -> pathlib.Path:
        path = directory / "source.tar.gz"
        members = files or {
            "source/Submission.lean": b"import Mathlib\nexample : 2 + 2 = 4 := by norm_num\n",
            "source/Submission/Helper.lean": b"def helper : Nat := 4\n",
            "source/README.md": b"private repository prose\n",
            "source/secrets.txt": b"must never be published\n",
        }
        with tarfile.open(path, "w:gz") as archive:
            for name, content in members.items():
                member = tarfile.TarInfo(name=name)
                member.size = len(content)
                member.mode = 0o600
                archive.addfile(member, io.BytesIO(content))
            if link is not None:
                member = tarfile.TarInfo(name=link[0])
                member.type = tarfile.SYMTYPE
                member.linkname = link[1]
                archive.addfile(member)
        return path

    def test_reconstructs_exact_public_layout_deterministically(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            archive = self.archive(root)
            outputs = [root / "first", root / "second"]
            manifests = [
                reconstruct_one(
                    plan_value=self.plan(),
                    plaintext_tar=archive,
                    trusted_as_of=TRUSTED_AS_OF,
                    state_snapshot_value=self.state(),
                    output_root=output,
                )
                for output in outputs
            ]
            self.assertEqual(manifests[0], manifests[1])
            entry = manifests[0]["entries"][0]
            release = outputs[0] / entry["release_path"]
            self.assertEqual(
                sorted(
                    path.relative_to(release).as_posix()
                    for path in release.rglob("*")
                    if path.is_file()
                ),
                [
                    "LICENSE",
                    "Submission.lean",
                    "Submission/Helper.lean",
                    "metadata.json",
                ],
            )
            self.assertFalse((release / "README.md").exists())
            self.assertFalse((release / "secrets.txt").exists())
            self.assertEqual(
                (outputs[0] / entry["bundle_path"]).read_bytes(),
                (outputs[1] / entry["bundle_path"]).read_bytes(),
            )
            metadata = json.loads(
                (release / "metadata.json").read_text(encoding="utf-8")
            )
            self.assertEqual(metadata["result"]["result_id"], entry["result_id"])
            self.assertEqual(
                metadata["release"]["accepted_at"], "2026-08-20T06:07:05.000Z"
            )
            self.assertEqual(
                [item["path"] for item in metadata["source_files"]],
                ["Submission.lean", "Submission/Helper.lean"],
            )

    def test_refuses_links_traversal_duplicates_and_invalid_utf8(self) -> None:
        cases = (
            (
                {"source/Submission.lean": b"example : True := by trivial\n"},
                ("source/Submission/Link.lean", "../Submission.lean"),
                "link or special",
            ),
            (
                {
                    "source/Submission.lean": b"example : True := by trivial\n",
                    "../escape": b"bad",
                },
                None,
                "escapes its root",
            ),
            (
                {
                    "source/Submission.lean": b"example : True := by trivial\n",
                    "source/Submission/.GiT./Hidden.lean": b"def hidden := 1\n",
                },
                None,
                "Git-reserved path",
            ),
            ({"source/Submission.lean": b"\xff"}, None, "not UTF-8"),
        )
        for files, link, message in cases:
            with (
                self.subTest(message=message),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = pathlib.Path(temporary)
                archive = self.archive(root, files=files, link=link)
                output = root / "out"
                with self.assertRaisesRegex(ReconstructionError, message):
                    reconstruct_one(
                        plan_value=self.plan(),
                        plaintext_tar=archive,
                        trusted_as_of=TRUSTED_AS_OF,
                        state_snapshot_value=self.state(),
                        output_root=output,
                    )
                self.assertFalse(output.exists())

    def test_refuses_noncanonical_plan_early_release_and_state_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            archive = self.archive(root)
            plan = self.plan()
            plan["request"]["release"]["path"] = "releases/elsewhere"
            with self.assertRaisesRegex(ReconstructionError, "path is not canonical"):
                reconstruct_one(
                    plan_value=plan,
                    plaintext_tar=archive,
                    trusted_as_of=TRUSTED_AS_OF,
                    state_snapshot_value=self.state(),
                    output_root=root / "bad-plan",
                )

            with self.assertRaisesRegex(ReconstructionError, "embargo has not expired"):
                reconstruct_one(
                    plan_value=self.plan(),
                    plaintext_tar=archive,
                    trusted_as_of="2026-10-20T06:07:04.999Z",
                    state_snapshot_value=self.state(),
                    output_root=root / "early",
                )

            state = copy.deepcopy(self.state())
            submission = next(iter(state["submissions"].values()))
            submission["archive_commit"] = "d" * 40
            with self.assertRaisesRegex(ManifestError, "archive_commit differs"):
                reconstruct_one(
                    plan_value=self.plan(),
                    plaintext_tar=archive,
                    trusted_as_of=TRUSTED_AS_OF,
                    state_snapshot_value=state,
                    output_root=root / "state-mismatch",
                )
            self.assertFalse((root / "state-mismatch").exists())

    def test_qualified_plan_refuses_a_different_acceptance_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            archive = self.archive(root)
            state = copy.deepcopy(self.state())
            submission = next(iter(state["submissions"].values()))
            submission["archive_commit"] = "d" * 40
            with self.assertRaisesRegex(
                ReconstructionError, "exact acceptance snapshot"
            ):
                reconstruct_one(
                    plan_value=self.qualified_plan(),
                    plaintext_tar=archive,
                    trusted_as_of=TRUSTED_AS_OF,
                    state_snapshot_value=state,
                    output_root=root / "wrong-qualified-state",
                )

    def test_refuses_overwrite_and_missing_submission(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            archive = self.archive(root, files={"source/README.md": b"no proof"})
            with self.assertRaisesRegex(ReconstructionError, "Submission.lean"):
                reconstruct_one(
                    plan_value=self.plan(),
                    plaintext_tar=archive,
                    trusted_as_of=TRUSTED_AS_OF,
                    state_snapshot_value=self.state(),
                    output_root=root / "missing",
                )
            output = root / "exists"
            output.mkdir()
            archive = self.archive(root)
            with self.assertRaisesRegex(ReconstructionError, "must not already exist"):
                reconstruct_one(
                    plan_value=self.plan(),
                    plaintext_tar=archive,
                    trusted_as_of=TRUSTED_AS_OF,
                    state_snapshot_value=self.state(),
                    output_root=output,
                )

    def test_staging_workflow_is_manual_read_only_and_nonpublishing(self) -> None:
        workflow = (ROOT / ".github/workflows/reconstruct-staging.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("push:", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertIn("environment: release-staging", workflow)
        self.assertIn("contents: read", workflow)
        self.assertNotIn("id-token: write", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("upload-artifact", workflow)
        self.assertNotIn("git push", workflow)
        self.assertIn('--output-root "$RUNNER_TEMP/reconstructed"', workflow)

    def test_all_schema_documents_parse(self) -> None:
        schemas = sorted((ROOT / "schema").glob("*.json"))
        self.assertGreaterEqual(len(schemas), 5)
        for schema in schemas:
            with self.subTest(schema=schema.name):
                value = json.loads(schema.read_text(encoding="utf-8"))
                self.assertEqual(
                    value["$schema"], "https://json-schema.org/draft/2020-12/schema"
                )

                pending: list[object] = [value]
                while pending:
                    current = pending.pop()
                    if isinstance(current, dict):
                        reference = current.get("$ref")
                        if reference is not None:
                            self.assertIsInstance(reference, str)
                            self.assertTrue(
                                reference.startswith("#/"),
                                f"{schema.name} has a non-local $ref: {reference}",
                            )
                        pending.extend(current.values())
                    elif isinstance(current, list):
                        pending.extend(current)

    def test_release_tree_digest_language_neutral_vector(self) -> None:
        vector = json.loads(
            (ROOT / "tests/fixtures/release-tree-digest-v1.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(vector["schema_version"], 1)
        self.assertEqual(base64.b64decode(vector["domain_utf8_base64"]), DOMAIN)
        entries: list[tuple[str, bytes]] = []
        for item in vector["files"]:
            content = base64.b64decode(item["content_base64"], validate=True)
            self.assertEqual(len(content), item["size_bytes"])
            self.assertEqual(hashlib.sha256(content).hexdigest(), item["sha256"])
            entries.append((item["path"], content))
        self.assertEqual(projected_digest(entries), vector["tree_sha256"])


if __name__ == "__main__":
    unittest.main()
