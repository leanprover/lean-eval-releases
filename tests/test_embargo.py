from __future__ import annotations

import copy
import hashlib
import pathlib
import sys
import tempfile
import unittest
from typing import ClassVar

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "scripts"))

from embargo import eligible_at, is_eligible
from release_tree import tree_digest
from validate_manifest import (
    ManifestError,
    load_state_snapshot,
    validate_manifest,
)


class EmbargoTests(unittest.TestCase):
    def test_two_ordinary_months(self) -> None:
        self.assertEqual(
            eligible_at("2026-08-20T06:07:08.000Z"),
            "2026-10-20T06:07:08.000Z",
        )

    def test_clamps_to_last_target_day(self) -> None:
        self.assertEqual(
            eligible_at("2026-12-31T12:00:00.000Z"),
            "2027-02-28T12:00:00.000Z",
        )
        self.assertEqual(
            eligible_at("2027-12-31T12:00:00.000Z"),
            "2028-02-29T12:00:00.000Z",
        )

    def test_boundary_is_inclusive(self) -> None:
        self.assertFalse(
            is_eligible("2026-08-20T06:07:08.000Z", "2026-10-20T06:07:07.999Z")
        )
        self.assertTrue(
            is_eligible("2026-08-20T06:07:08.000Z", "2026-10-20T06:07:08.000Z")
        )


class ManifestTests(unittest.TestCase):
    SUBMISSION_ID = "018f7777-2ea8-7f55-9f7c-4f099ef55e4e"
    RESULT_ID = "r2_" + "d" * 64
    TRUSTED_AS_OF = "2026-10-21T00:00:00.000Z"
    TRUSTED_SUBMISSIONS: ClassVar[dict[str, dict[str, str]]] = {
        SUBMISSION_ID: {
            "accepted_at": "2026-08-20T06:07:08.000Z",
            "archive_repository": "leanprover/lean-eval-audit",
            "archive_commit": "c" * 40,
            "archive_path": f"archives/01/{SUBMISSION_ID}.tar.age",
            "archive_ciphertext_sha256": "a" * 64,
        }
    }

    def manifest(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "release_id": "lean-eval-2026-10-21",
            "generated_at": "2026-10-21T00:00:00.000Z",
            "entries": [
                {
                    "result_id": self.RESULT_ID,
                    "submission_id": self.SUBMISSION_ID,
                    "accepted_at": "2026-08-20T06:07:08.000Z",
                    "eligible_at": "2026-10-20T06:07:08.000Z",
                    "archive_repository": "leanprover/lean-eval-audit",
                    "archive_commit": "c" * 40,
                    "archive_path": f"archives/01/{self.SUBMISSION_ID}.tar.age",
                    "archive_ciphertext_sha256": "a" * 64,
                    "bundle_sha256": "b" * 64,
                    "bundle_path": f"sources/{self.SUBMISSION_ID}.tar.gz",
                    "release_tree_sha256": "e" * 64,
                    "release_path": f"releases/2026/10/{self.RESULT_ID}",
                    "license": "Apache-2.0",
                }
            ],
        }

    def test_valid_manifest(self) -> None:
        self.assertEqual(
            validate_manifest(
                self.manifest(),
                trusted_as_of=self.TRUSTED_AS_OF,
                trusted_submissions=self.TRUSTED_SUBMISSIONS,
            ),
            1,
        )

    def test_refuses_early_release(self) -> None:
        manifest = self.manifest()
        manifest["release_id"] = "lean-eval-2026-10-20"
        manifest["generated_at"] = "2026-10-20T06:07:07.999Z"
        with self.assertRaisesRegex(ManifestError, "embargo had not expired"):
            validate_manifest(
                manifest,
                trusted_as_of="2026-10-20T06:07:07.999Z",
                trusted_submissions=self.TRUSTED_SUBMISSIONS,
            )

    def test_refuses_forged_eligibility(self) -> None:
        manifest = self.manifest()
        entries = manifest["entries"]
        assert isinstance(entries, list)
        assert isinstance(entries[0], dict)
        entries[0]["eligible_at"] = "2026-10-19T06:07:08.000Z"
        with self.assertRaisesRegex(ManifestError, "two calendar months"):
            validate_manifest(
                manifest,
                trusted_as_of=self.TRUSTED_AS_OF,
                trusted_submissions=self.TRUSTED_SUBMISSIONS,
            )

    def test_refuses_self_declared_future_generation_time(self) -> None:
        manifest = self.manifest()
        manifest["generated_at"] = "2099-10-21T00:00:00.000Z"
        manifest["release_id"] = "lean-eval-2099-10-21"
        with self.assertRaisesRegex(ManifestError, "trusted workflow as-of"):
            validate_manifest(
                manifest,
                trusted_as_of=self.TRUSTED_AS_OF,
                trusted_submissions=self.TRUSTED_SUBMISSIONS,
            )

    def test_refuses_acceptance_not_proven_by_state(self) -> None:
        manifest = self.manifest()
        entries = manifest["entries"]
        assert isinstance(entries, list)
        assert isinstance(entries[0], dict)
        entries[0]["accepted_at"] = "2026-08-19T06:07:08.000Z"
        with self.assertRaisesRegex(ManifestError, "trusted State"):
            validate_manifest(
                manifest,
                trusted_as_of=self.TRUSTED_AS_OF,
                trusted_submissions=self.TRUSTED_SUBMISSIONS,
            )

    def test_state_snapshot_version_is_not_boolean(self) -> None:
        snapshot = {
            "schema_version": True,
            "submissions": self.TRUSTED_SUBMISSIONS,
        }
        with self.assertRaisesRegex(ManifestError, "schema version 1"):
            load_state_snapshot(snapshot)

    def test_state_snapshot_preserves_archive_retrieval_locator(self) -> None:
        snapshot = {
            "schema_version": 1,
            "submissions": copy.deepcopy(self.TRUSTED_SUBMISSIONS),
        }
        self.assertEqual(load_state_snapshot(snapshot), self.TRUSTED_SUBMISSIONS)

    def test_archive_path_rejects_traversal_legacy_names_and_wrong_prefix(self) -> None:
        for unsafe_path in (
            "../ciphertext.tar.age",
            "audit/alice-99-deadbeef.tar.age",
            f"archives/ff/{self.SUBMISSION_ID}.tar.age",
        ):
            with self.subTest(archive_path=unsafe_path):
                snapshot = {
                    "schema_version": 1,
                    "submissions": copy.deepcopy(self.TRUSTED_SUBMISSIONS),
                }
                snapshot["submissions"][self.SUBMISSION_ID]["archive_path"] = unsafe_path
                with self.assertRaisesRegex(ManifestError, "archive path is not canonical"):
                    load_state_snapshot(snapshot)

                manifest = self.manifest()
                entries = manifest["entries"]
                assert isinstance(entries, list)
                assert isinstance(entries[0], dict)
                entries[0]["archive_path"] = unsafe_path
                with self.assertRaisesRegex(ManifestError, "archive_path is not canonical"):
                    validate_manifest(
                        manifest,
                        trusted_as_of=self.TRUSTED_AS_OF,
                        trusted_submissions=self.TRUSTED_SUBMISSIONS,
                    )

    def test_archive_locator_must_match_state(self) -> None:
        manifest = self.manifest()
        entries = manifest["entries"]
        assert isinstance(entries, list)
        assert isinstance(entries[0], dict)
        entries[0]["archive_commit"] = "d" * 40
        with self.assertRaisesRegex(ManifestError, "archive_commit differs"):
            validate_manifest(
                manifest,
                trusted_as_of=self.TRUSTED_AS_OF,
                trusted_submissions=self.TRUSTED_SUBMISSIONS,
            )

    def test_ambiguous_archive_digest_field_is_rejected(self) -> None:
        snapshot = {
            "schema_version": 1,
            "submissions": {
                self.SUBMISSION_ID: {
                    "accepted_at": "2026-08-20T06:07:08.000Z",
                    "archive_repository": "leanprover/lean-eval-audit",
                    "archive_commit": "c" * 40,
                    "archive_path": f"archives/01/{self.SUBMISSION_ID}.tar.age",
                    "archive_sha256": "a" * 64,
                }
            },
        }
        with self.assertRaisesRegex(ManifestError, "fields are not canonical"):
            load_state_snapshot(snapshot)

        manifest = self.manifest()
        entries = manifest["entries"]
        assert isinstance(entries, list)
        assert isinstance(entries[0], dict)
        digest = entries[0].pop("archive_ciphertext_sha256")
        entries[0]["archive_sha256"] = digest
        with self.assertRaisesRegex(ManifestError, "fields do not match"):
            validate_manifest(
                manifest,
                trusted_as_of=self.TRUSTED_AS_OF,
                trusted_submissions=self.TRUSTED_SUBMISSIONS,
            )

    def test_ciphertext_digest_must_match_state(self) -> None:
        manifest = self.manifest()
        entries = manifest["entries"]
        assert isinstance(entries, list)
        assert isinstance(entries[0], dict)
        entries[0]["archive_ciphertext_sha256"] = "c" * 64
        with self.assertRaisesRegex(ManifestError, "archive digest differs"):
            validate_manifest(
                manifest,
                trusted_as_of=self.TRUSTED_AS_OF,
                trusted_submissions=self.TRUSTED_SUBMISSIONS,
            )

    def test_refuses_impossible_release_date_and_unsafe_submission_id(self) -> None:
        manifest = self.manifest()
        manifest["release_id"] = "lean-eval-2026-99-99"
        with self.assertRaisesRegex(ManifestError, "real calendar date"):
            validate_manifest(
                manifest,
                trusted_as_of=self.TRUSTED_AS_OF,
                trusted_submissions=self.TRUSTED_SUBMISSIONS,
            )

    def test_verifies_bundle_bytes_and_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            sources = root / "sources"
            sources.mkdir()
            bundle = sources / f"{self.SUBMISSION_ID}.tar.gz"
            bundle.write_bytes(b"bundle bytes")
            release = root / "releases" / "2026" / "10" / self.RESULT_ID
            release.mkdir(parents=True)
            (release / "Submission.lean").write_text("example", encoding="utf-8")
            (release / "metadata.json").write_text("{}\n", encoding="utf-8")
            (release / "LICENSE").write_text("Apache-2.0\n", encoding="utf-8")
            manifest = self.manifest()
            entries = manifest["entries"]
            assert isinstance(entries, list)
            assert isinstance(entries[0], dict)
            entries[0]["bundle_sha256"] = hashlib.sha256(b"bundle bytes").hexdigest()
            entries[0]["release_tree_sha256"] = tree_digest(release)
            self.assertEqual(
                validate_manifest(
                    manifest,
                    trusted_as_of=self.TRUSTED_AS_OF,
                    trusted_submissions=self.TRUSTED_SUBMISSIONS,
                    bundle_root=root,
                ),
                1,
            )
            target = root / "real.tar.gz"
            bundle.rename(target)
            bundle.symlink_to(target)
            with self.assertRaisesRegex(ManifestError, "symlink"):
                validate_manifest(
                    manifest,
                    trusted_as_of=self.TRUSTED_AS_OF,
                    trusted_submissions=self.TRUSTED_SUBMISSIONS,
                    bundle_root=root,
                )

    def test_release_tree_digest_and_allowlist_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            sources = root / "sources"
            sources.mkdir()
            bundle = sources / f"{self.SUBMISSION_ID}.tar.gz"
            bundle.write_bytes(b"bundle bytes")
            release = root / "releases" / "2026" / "10" / self.RESULT_ID
            release.mkdir(parents=True)
            (release / "Submission.lean").write_text("example", encoding="utf-8")
            (release / "metadata.json").write_text("{}\n", encoding="utf-8")
            (release / "LICENSE").write_text("Apache-2.0\n", encoding="utf-8")
            manifest = self.manifest()
            entry = manifest["entries"][0]
            entry["bundle_sha256"] = hashlib.sha256(b"bundle bytes").hexdigest()
            entry["release_tree_sha256"] = tree_digest(release)
            (release / "secret.txt").write_text("must not publish", encoding="utf-8")
            with self.assertRaisesRegex(ManifestError, "file set is not canonical"):
                validate_manifest(
                    manifest,
                    trusted_as_of=self.TRUSTED_AS_OF,
                    trusted_submissions=self.TRUSTED_SUBMISSIONS,
                    bundle_root=root,
                )

    def test_manifest_is_unique_by_result_not_submission(self) -> None:
        manifest = self.manifest()
        first = manifest["entries"][0]
        second = copy.deepcopy(first)
        second["result_id"] = "r2_" + "f" * 64
        second["release_path"] = f"releases/2026/10/{second['result_id']}"
        manifest["entries"].append(second)
        self.assertEqual(
            validate_manifest(
                manifest,
                trusted_as_of=self.TRUSTED_AS_OF,
                trusted_submissions=self.TRUSTED_SUBMISSIONS,
            ),
            2,
        )
        manifest = self.manifest()
        entries = manifest["entries"]
        assert isinstance(entries, list)
        assert isinstance(entries[0], dict)
        entries[0]["submission_id"] = "../../escape"
        with self.assertRaisesRegex(ManifestError, "not canonical"):
            validate_manifest(
                manifest,
                trusted_as_of=self.TRUSTED_AS_OF,
                trusted_submissions=self.TRUSTED_SUBMISSIONS,
            )


if __name__ == "__main__":
    unittest.main()
