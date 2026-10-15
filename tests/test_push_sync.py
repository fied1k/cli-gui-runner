import os
import sys
import unittest
import tempfile
import re

# Add scripts directory to path to test push.py functions
SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from push import (
    calculate_next_version,
    parse_semver,
    determine_bump_from_commits,
    categorize_commits,
    generate_changelog_section,
    update_readme,
    update_changelog,
)


class TestPushSync(unittest.TestCase):

    def test_parse_semver(self):
        self.assertEqual(parse_semver("1.2.3"), [1, 2, 3])
        self.assertEqual(parse_semver("0.7.3"), [0, 7, 3])
        with self.assertRaises(ValueError):
            parse_semver("invalid")

    def test_calculate_next_version(self):
        self.assertEqual(calculate_next_version("0.7.3", "patch"), "0.7.4")
        self.assertEqual(calculate_next_version("0.7.3", "minor"), "0.8.0")
        self.assertEqual(calculate_next_version("0.7.3", "major"), "1.0.0")

    def test_determine_bump_from_commits(self):
        self.assertEqual(determine_bump_from_commits(["feat: add auto-fill variables"]), "minor")
        self.assertEqual(determine_bump_from_commits(["fix: correct parsing issue"]), "patch")
        self.assertEqual(determine_bump_from_commits(["feat!: breaking api change"]), "major")
        self.assertEqual(determine_bump_from_commits(["BREAKING CHANGE: revamp structure"]), "major")
        self.assertEqual(determine_bump_from_commits(["chore: clean up temp files"]), "patch")
        self.assertEqual(determine_bump_from_commits(["random commit message"]), "patch")

    def test_categorize_commits(self):
        commits = [
            "feat: add export button",
            "fix: resolve null pointer in parser",
            "perf: optimize table rendering",
            "docs: update installation instructions",
            "chore: bump dependencies"
        ]
        categorized = categorize_commits(commits)
        self.assertIn("add export button", categorized["Added"])
        self.assertIn("resolve null pointer in parser", categorized["Fixed"])
        self.assertIn("optimize table rendering", categorized["Performance"])
        self.assertIn("update installation instructions", categorized["Documentation"])
        self.assertIn("bump dependencies", categorized["Maintenance"])

    def test_generate_changelog_section(self):
        commits = [
            "feat: add search filter",
            "fix: handle special characters"
        ]
        section = generate_changelog_section("0.8.0", commits)
        self.assertIn("## [0.8.0] - ", section)
        self.assertIn("### Added", section)
        self.assertIn("- Add search filter", section)
        self.assertIn("### Fixed", section)
        self.assertIn("- Handle special characters", section)

    def test_update_readme_in_place(self):
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".md", encoding="utf-8") as tmp:
            tmp.write(
                "# Title\n\n"
                "[![Release](https://img.shields.io/github/v/release/foo/bar)](...)\n"
                "Description here.\n\n"
                "## Key Features\n"
                "- Feature 1\n"
            )
            tmp_path = tmp.name

        try:
            # Monkeypatch README_FILE
            import push
            original_readme_file = push.README_FILE
            push.README_FILE = tmp_path

            update_readme("0.8.5")

            with open(tmp_path, "r", encoding="utf-8") as f:
                content = f.read()

            self.assertIn("version-v0.8.5-blue.svg", content)
            self.assertIn("<!-- RELEASE_INFO_START -->", content)
            self.assertIn("### Latest Release: v0.8.5", content)
            self.assertIn("<!-- RELEASE_INFO_END -->", content)

            # Update again to next version
            update_readme("0.8.6")
            with open(tmp_path, "r", encoding="utf-8") as f:
                content2 = f.read()

            self.assertIn("version-v0.8.6-blue.svg", content2)
            self.assertIn("### Latest Release: v0.8.6", content2)
            self.assertNotIn("0.8.5", content2)
        finally:
            push.README_FILE = original_readme_file
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
