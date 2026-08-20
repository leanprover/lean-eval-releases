from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "scripts"))

from embargo import eligible_at, is_eligible  # noqa: E402
from validate_manifest import ManifestError, validate_manifest  # noqa: E402


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
    def manifest(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "release_id": "lean-eval-2026-10-21",
            "generated_at": "2026-10-21T00:00:00.000Z",
            "entries": [
                {
                    "submission_id": "submission_123",
                    "accepted_at": "2026-08-20T06:07:08.000Z",
                    "eligible_at": "2026-10-20T06:07:08.000Z",
                    "archive_sha256": "a" * 64,
                    "bundle_sha256": "b" * 64,
                    "bundle_path": "sources/submission_123.tar.gz",
                    "license": "Apache-2.0",
                }
            ],
        }

    def test_valid_manifest(self) -> None:
        self.assertEqual(validate_manifest(self.manifest()), 1)

    def test_refuses_early_release(self) -> None:
        manifest = self.manifest()
        manifest["generated_at"] = "2026-10-20T06:07:07.999Z"
        with self.assertRaisesRegex(ManifestError, "embargo had not expired"):
            validate_manifest(manifest)

    def test_refuses_forged_eligibility(self) -> None:
        manifest = self.manifest()
        entries = manifest["entries"]
        assert isinstance(entries, list)
        assert isinstance(entries[0], dict)
        entries[0]["eligible_at"] = "2026-10-19T06:07:08.000Z"
        with self.assertRaisesRegex(ManifestError, "two calendar months"):
            validate_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
