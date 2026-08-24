from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from classify_release_publication import (
    PublicationClassificationError,
    classify_existing_publication_history,
    classify_publication,
)

RESULT_ID = "r2_" + "a" * 64
SECOND_RESULT_ID = "r2_" + "b" * 64
SUBMISSION_ID = "0198abcd-0000-7000-8000-000000000001"


class ReleasePublicationTests(unittest.TestCase):
    def git(self, root: pathlib.Path, *args: str) -> str:
        return subprocess.check_output(["git", "-C", root, *args], text=True).strip()

    def release_tree(
        self,
        root: pathlib.Path,
        result_id: str,
        *,
        generated_at: str,
        license_text: str,
    ) -> pathlib.Path:
        path = root / "releases" / "2026" / "10" / result_id
        path.mkdir(parents=True)
        (path / "Submission.lean").write_text(
            "example : True := by trivial\n", encoding="utf-8"
        )
        (path / "metadata.json").write_text(
            json.dumps(
                {
                    "generated_at": generated_at,
                    "problem_id": "example",
                    "statement_revision": 1,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        (path / "LICENSE").write_text(license_text, encoding="utf-8")
        for file_path in path.iterdir():
            file_path.chmod(0o644)
        return path

    def bundle(self, root: pathlib.Path, content: bytes = b"stable bundle") -> None:
        path = root / "sources" / f"{SUBMISSION_ID}.tar.gz"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def test_existing_release_ignores_run_clock_and_license_but_binds_source(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "release"
            reconstructed = pathlib.Path(directory) / "reconstructed"
            subprocess.run(["git", "init", "-q", "-b", "main", root], check=True)
            self.git(root, "config", "user.name", "Test")
            self.git(root, "config", "user.email", "test@example.com")
            self.release_tree(
                root,
                RESULT_ID,
                generated_at="2026-10-20T06:00:00.000Z",
                license_text="old license\n",
            )
            self.bundle(root)
            self.git(root, "add", ".")
            self.git(root, "commit", "-qm", "publish")
            publishing_commit = self.git(root, "rev-parse", "HEAD")

            self.release_tree(
                reconstructed,
                RESULT_ID,
                generated_at="2026-10-21T06:00:00.000Z",
                license_text="new license\n",
            )
            self.bundle(reconstructed)
            result = classify_publication(
                root,
                reconstructed,
                f"releases/2026/10/{RESULT_ID}",
                SUBMISSION_ID,
            )
            self.assertEqual(result["kind"], "existing")
            self.assertEqual(result["repository_commit"], publishing_commit)

            (
                reconstructed
                / "releases"
                / "2026"
                / "10"
                / RESULT_ID
                / "Submission.lean"
            ).write_text("example : False := by sorry\n", encoding="utf-8")
            with self.assertRaisesRegex(
                PublicationClassificationError, "stable allowlist"
            ):
                classify_publication(
                    root,
                    reconstructed,
                    f"releases/2026/10/{RESULT_ID}",
                    SUBMISSION_ID,
                )

    def test_shared_bundle_does_not_block_a_second_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "release"
            reconstructed = pathlib.Path(directory) / "reconstructed"
            subprocess.run(["git", "init", "-q", "-b", "main", root], check=True)
            self.git(root, "config", "user.name", "Test")
            self.git(root, "config", "user.email", "test@example.com")
            self.bundle(root)
            self.git(root, "add", ".")
            self.git(root, "commit", "-qm", "shared source")
            self.release_tree(
                reconstructed,
                SECOND_RESULT_ID,
                generated_at="2026-10-21T06:00:00.000Z",
                license_text="license\n",
            )
            self.bundle(reconstructed)
            result = classify_publication(
                root,
                reconstructed,
                f"releases/2026/10/{SECOND_RESULT_ID}",
                SUBMISSION_ID,
            )
            self.assertEqual(result["kind"], "new")
            self.assertTrue(result["bundle_exists"])

    def test_removed_release_is_never_republished(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "release"
            reconstructed = pathlib.Path(directory) / "reconstructed"
            subprocess.run(["git", "init", "-q", "-b", "main", root], check=True)
            self.git(root, "config", "user.name", "Test")
            self.git(root, "config", "user.email", "test@example.com")
            published = self.release_tree(
                root,
                RESULT_ID,
                generated_at="2026-10-20T06:00:00.000Z",
                license_text="license\n",
            )
            self.bundle(root)
            self.git(root, "add", ".")
            self.git(root, "commit", "-qm", "publish")
            for file_path in published.iterdir():
                file_path.unlink()
            published.rmdir()
            self.git(root, "add", "-A")
            self.git(root, "commit", "-qm", "remove")
            self.release_tree(
                reconstructed,
                RESULT_ID,
                generated_at="2026-10-21T06:00:00.000Z",
                license_text="license\n",
            )
            self.bundle(reconstructed)
            with self.assertRaisesRegex(
                PublicationClassificationError, "refusing republication"
            ):
                classify_publication(
                    root,
                    reconstructed,
                    f"releases/2026/10/{RESULT_ID}",
                    SUBMISSION_ID,
                )

            self.release_tree(
                root,
                RESULT_ID,
                generated_at="2026-10-20T06:00:00.000Z",
                license_text="license\n",
            )
            self.git(root, "add", ".")
            self.git(root, "commit", "-qm", "unsafe re-add")
            with self.assertRaisesRegex(
                PublicationClassificationError, "deletion history"
            ):
                classify_publication(
                    root,
                    reconstructed,
                    f"releases/2026/10/{RESULT_ID}",
                    SUBMISSION_ID,
                )

    def test_removed_shared_bundle_is_never_republished(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "release"
            reconstructed = pathlib.Path(directory) / "reconstructed"
            subprocess.run(["git", "init", "-q", "-b", "main", root], check=True)
            self.git(root, "config", "user.name", "Test")
            self.git(root, "config", "user.email", "test@example.com")
            self.bundle(root)
            self.git(root, "add", ".")
            self.git(root, "commit", "-qm", "publish shared source")
            self.git(root, "rm", f"sources/{SUBMISSION_ID}.tar.gz")
            self.git(root, "commit", "-qm", "remove shared source")
            self.release_tree(
                reconstructed,
                SECOND_RESULT_ID,
                generated_at="2026-10-21T06:00:00.000Z",
                license_text="license\n",
            )
            self.bundle(reconstructed)
            with self.assertRaisesRegex(
                PublicationClassificationError, "source bundle has deletion history"
            ):
                classify_publication(
                    root,
                    reconstructed,
                    f"releases/2026/10/{SECOND_RESULT_ID}",
                    SUBMISSION_ID,
                )

            self.bundle(root)
            self.git(root, "add", ".")
            self.git(root, "commit", "-qm", "unsafe source re-add")
            with self.assertRaisesRegex(
                PublicationClassificationError, "source bundle has deletion history"
            ):
                classify_publication(
                    root,
                    reconstructed,
                    f"releases/2026/10/{SECOND_RESULT_ID}",
                    SUBMISSION_ID,
                )

    def test_history_only_recovers_oldest_add_and_rejects_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "release"
            subprocess.run(["git", "init", "-q", "-b", "main", root], check=True)
            self.git(root, "config", "user.name", "Test")
            self.git(root, "config", "user.email", "test@example.com")
            published = self.release_tree(
                root,
                RESULT_ID,
                generated_at="2026-10-20T06:00:00.000Z",
                license_text="license\n",
            )
            self.bundle(root)
            self.git(root, "add", ".")
            self.git(root, "commit", "-qm", "publish")
            publishing_commit = self.git(root, "rev-parse", "HEAD")
            nested = published / "Submission" / "Later.lean"
            nested.parent.mkdir()
            nested.write_text("example : True := by trivial\n", encoding="utf-8")
            nested.chmod(0o644)
            self.git(root, "add", ".")
            self.git(root, "commit", "-qm", "later addition")

            result = classify_existing_publication_history(
                root,
                f"releases/2026/10/{RESULT_ID}",
                SUBMISSION_ID,
            )
            self.assertEqual(result["repository_commit"], publishing_commit)

            nested.unlink()
            self.git(root, "add", "-A")
            self.git(root, "commit", "-qm", "delete later source")
            with self.assertRaisesRegex(
                PublicationClassificationError, "deletion history"
            ):
                classify_existing_publication_history(
                    root,
                    f"releases/2026/10/{RESULT_ID}",
                    SUBMISSION_ID,
                )

    def test_history_only_requires_one_unique_oldest_add(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "release"
            subprocess.run(["git", "init", "-q", "-b", "main", root], check=True)
            self.git(root, "config", "user.name", "Test")
            self.git(root, "config", "user.email", "test@example.com")
            self.bundle(root)
            self.git(root, "add", ".")
            self.git(root, "commit", "-qm", "shared source")

            self.git(root, "checkout", "-qb", "first")
            self.release_tree(
                root,
                RESULT_ID,
                generated_at="2026-10-20T06:00:00.000Z",
                license_text="license\n",
            )
            self.git(root, "add", ".")
            self.git(root, "commit", "-qm", "first publication")

            self.git(root, "checkout", "-q", "main")
            self.git(root, "checkout", "-qb", "second")
            self.release_tree(
                root,
                RESULT_ID,
                generated_at="2026-10-20T06:00:00.000Z",
                license_text="license\n",
            )
            self.git(root, "add", ".")
            self.git(root, "commit", "-qm", "parallel publication")
            self.git(root, "merge", "-q", "--no-ff", "first", "-m", "merge")

            with self.assertRaisesRegex(
                PublicationClassificationError, "no unique oldest adding commit"
            ):
                classify_existing_publication_history(
                    root,
                    f"releases/2026/10/{RESULT_ID}",
                    SUBMISSION_ID,
                )


if __name__ == "__main__":
    unittest.main()
