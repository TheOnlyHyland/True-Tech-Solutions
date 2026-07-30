"""Static contract for the permanent App repository and signing identity."""

from __future__ import annotations

import json
from pathlib import Path
import unittest

from scripts import release_identity


ROOT = Path(__file__).parents[1]
CANONICAL_URL = "https://github.com/TheOnlyHyland/True-Tech-Solutions"
FULL_SLUG = "8c9c720e_true_family_journal"


class ReleaseIdentityTests(unittest.TestCase):
    def test_supervisor_hash_matches_upstream_known_example(self) -> None:
        identity = release_identity.derive_identity(
            "https://github.com/home-assistant/apps-example"
        )
        self.assertEqual(identity["repository_slug"], "eaf7b348")

    def test_permanent_identity_is_exact_and_deterministic(self) -> None:
        identity = release_identity.derive_identity(CANONICAL_URL)
        self.assertEqual(identity["repository_slug"], "8c9c720e")
        self.assertEqual(identity["full_app_slug"], FULL_SLUG)
        self.assertEqual(identity["hostname"], "8c9c720e-true-family-journal")
        self.assertEqual(
            identity["image"], "ghcr.io/theonlyhyland/true-family-journal"
        )

    def test_case_does_not_change_supervisor_hash(self) -> None:
        lower = release_identity.derive_identity(CANONICAL_URL.lower())
        canonical = release_identity.derive_identity(CANONICAL_URL)
        self.assertEqual(lower["repository_slug"], canonical["repository_slug"])

    def test_repository_aliases_are_rejected(self) -> None:
        for suffix in (".git", "/", "?tab=readme", "#main"):
            with self.subTest(suffix=suffix):
                with self.assertRaises(release_identity.ReleaseIdentityError):
                    release_identity.derive_identity(f"{CANONICAL_URL}{suffix}")

    def test_credentials_and_non_github_urls_are_rejected(self) -> None:
        for url in (
            "https://token@github.com/TheOnlyHyland/True-Tech-Solutions",
            "http://github.com/TheOnlyHyland/True-Tech-Solutions",
            "https://gitlab.com/TheOnlyHyland/True-Tech-Solutions",
        ):
            with self.subTest(url=url):
                with self.assertRaises(release_identity.ReleaseIdentityError):
                    release_identity.derive_identity(url)

    def test_persisted_identity_and_all_source_surfaces_agree(self) -> None:
        identity = release_identity.validate_project(ROOT, require_bound=True)
        persisted = json.loads(
            (ROOT / "release" / "identity.json").read_text(encoding="utf-8")
        )
        self.assertEqual(identity, persisted)

    def test_local_and_temporary_app_identities_are_not_trusted(self) -> None:
        source = (
            ROOT
            / "custom_components"
            / "true_family"
            / "reference_journal_remote.py"
        ).read_text(encoding="utf-8")
        self.assertIn(FULL_SLUG, source)
        self.assertNotIn("local_true_family_journal", source)
        self.assertNotIn("8c22f541_true_family_journal", source)

    def test_workflow_is_manual_immutable_and_keyless_signed(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "release-app.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch", workflow)
        self.assertIn("Reject an existing version tag", workflow)
        self.assertIn('group: "true-family-journal-release"', workflow)
        self.assertIn("fromJSON(steps.info.outputs.image)", workflow)
        self.assertIn(
            'version: "${{ steps.normalize.outputs.version }}"', workflow
        )
        self.assertIn("${arch}-${IMAGE##*/}:${VERSION}", workflow)
        self.assertIn('context: "./true_family_journal"', workflow)
        self.assertIn("uv run --frozen python -m unittest discover", workflow)
        self.assertIn("uv sync --locked", workflow)
        self.assertIn('version: "0.11.33"', workflow)
        self.assertIn("git ls-remote --exit-code --tags", workflow)
        self.assertIn('"refs/tags/${VERSION}"', workflow)
        self.assertIn('case "${inspection,,}" in', workflow)
        self.assertIn("Unable to prove version tag", workflow)
        self.assertIn('cosign: "true"', workflow)
        self.assertIn("id-token: write", workflow)
        self.assertNotIn('image-tags: "latest"', workflow)
        self.assertNotRegex(workflow, r"(?m)^\s+latest\s*$")

    def test_public_source_has_the_approved_proprietary_licence(self) -> None:
        license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("True Tech Solutions. All rights reserved.", license_text)
        self.assertIn("No permission is granted", license_text)


if __name__ == "__main__":
    unittest.main()
