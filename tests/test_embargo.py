from __future__ import annotations

import hashlib
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "scripts"))

from embargo import eligible_at, is_eligible  # noqa: E402
from validate_manifest import (  # noqa: E402
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
    TRUSTED_AS_OF = "2026-10-21T00:00:00.000Z"
    TRUSTED_SUBMISSIONS = {
        SUBMISSION_ID: {
            "accepted_at": "2026-08-20T06:07:08.000Z",
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
                    "submission_id": self.SUBMISSION_ID,
                    "accepted_at": "2026-08-20T06:07:08.000Z",
                    "eligible_at": "2026-10-20T06:07:08.000Z",
                    "archive_ciphertext_sha256": "a" * 64,
                    "bundle_sha256": "b" * 64,
                    "bundle_path": f"sources/{self.SUBMISSION_ID}.tar.gz",
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

    def test_ambiguous_archive_digest_field_is_rejected(self) -> None:
        snapshot = {
            "schema_version": 1,
            "submissions": {
                self.SUBMISSION_ID: {
                    "accepted_at": "2026-08-20T06:07:08.000Z",
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
            manifest = self.manifest()
            entries = manifest["entries"]
            assert isinstance(entries, list)
            assert isinstance(entries[0], dict)
            entries[0]["bundle_sha256"] = hashlib.sha256(b"bundle bytes").hexdigest()
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
