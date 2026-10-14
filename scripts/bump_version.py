#!/usr/bin/env python3
"""Local Semantic Versioning and Changelog Automation Script.

Usage:
    python scripts/bump_version.py --bump patch
    python scripts/bump_version.py --bump minor
    python scripts/bump_version.py --bump major
    python scripts/bump_version.py --auto
    python scripts/bump_version.py --set 1.2.0
"""

import argparse
import datetime
import os
import re
import subprocess
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERSION_FILE = os.path.join(ROOT_DIR, "cli_gui_runner.py")
PYPROJECT_FILE = os.path.join(ROOT_DIR, "pyproject.toml")
CHANGELOG_FILE = os.path.join(ROOT_DIR, "CHANGELOG.md")


def get_current_version():
    with open(VERSION_FILE, "r", encoding="utf-8") as f:
        content = f.read()
    match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
    if not match:
        raise ValueError("Could not find __version__ in cli_gui_runner.py")
    return match.group(1)


def parse_semver(version_str):
    parts = version_str.split(".")
    if len(parts) != 3:
        raise ValueError(f"Version string '{version_str}' is not valid SemVer (expected X.Y.Z)")
    return [int(p) for p in parts]


def determine_bump_from_commits():
    try:
        # Get latest tag
        latest_tag = subprocess.check_output(
            ["git", "describe", "--tags", "--abbrev=0"],
            cwd=ROOT_DIR,
            stderr=subprocess.DEVNULL
        ).decode().strip()
        commit_range = f"{latest_tag}..HEAD"
    except Exception:
        commit_range = "HEAD"

    try:
        log = subprocess.check_output(
            ["git", "log", commit_range, "--oneline"],
            cwd=ROOT_DIR,
            stderr=subprocess.DEVNULL
        ).decode()
    except Exception:
        return "patch"

    lines = log.strip().splitlines()
    bump = "patch"
    for line in lines:
        if "BREAKING CHANGE" in line or "!:" in line:
            return "major"
        if re.search(r"^\w+\s+feat(\([^\)]+\))?:", line):
            bump = "minor"
    return bump


def calculate_next_version(current_version, bump_type):
    major, minor, patch = parse_semver(current_version)
    if bump_type == "major":
        return f"{major + 1}.0.0"
    elif bump_type == "minor":
        return f"{major}.{minor + 1}.0"
    elif bump_type == "patch":
        return f"{major}.{minor}.{patch + 1}"
    else:
        raise ValueError(f"Unknown bump type: {bump_type}")


def update_file_version(filepath, pattern, replacement):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    new_content, count = re.subn(pattern, replacement, content)
    if count == 0:
        raise ValueError(f"Failed to match pattern in {filepath}")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(new_content)


def update_changelog(new_version):
    today = datetime.date.today().isoformat()
    with open(CHANGELOG_FILE, "r", encoding="utf-8") as f:
        content = f.read()

    new_section = (
        f"## [Unreleased]\n\n"
        f"## [{new_version}] - {today}\n"
    )

    if "## [Unreleased]" in content:
        content = content.replace("## [Unreleased]", new_section, 1)
    else:
        # Prepend after header
        lines = content.splitlines(True)
        insert_idx = 0
        for i, line in enumerate(lines):
            if line.startswith("## "):
                insert_idx = i
                break
        if insert_idx > 0:
            lines.insert(insert_idx, new_section + "\n")
            content = "".join(lines)

    with open(CHANGELOG_FILE, "w", encoding="utf-8") as f:
        f.write(content)


def main():
    parser = argparse.ArgumentParser(description="Bump project version and update changelog.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--bump", choices=["major", "minor", "patch"], help="Bump type")
    group.add_argument("--auto", action="store_true", help="Auto-determine bump from git commits")
    group.add_argument("--set", dest="exact_version", help="Explicit version (X.Y.Z)")

    args = parser.parse_args()

    curr_ver = get_current_version()
    print(f"Current version: {curr_ver}")

    if args.exact_version:
        next_ver = args.exact_version
    elif args.auto:
        bump = determine_bump_from_commits()
        print(f"Auto-detected bump level: {bump}")
        next_ver = calculate_next_version(curr_ver, bump)
    else:
        next_ver = calculate_next_version(curr_ver, args.bump)

    print(f"Bumping version to: {next_ver}")

    # 1. Update cli_gui_runner.py
    update_file_version(
        VERSION_FILE,
        r'__version__\s*=\s*["\'][^"\']+["\']',
        f'__version__ = "{next_ver}"'
    )
    print(f"Updated {os.path.basename(VERSION_FILE)}")

    # 2. Update pyproject.toml
    update_file_version(
        PYPROJECT_FILE,
        r'version\s*=\s*["\'][^"\']+["\']',
        f'version = "{next_ver}"'
    )
    print(f"Updated {os.path.basename(PYPROJECT_FILE)}")

    # 3. Update CHANGELOG.md
    update_changelog(next_ver)
    print(f"Updated {os.path.basename(CHANGELOG_FILE)}")

    print(f"\nSuccessfully bumped to v{next_ver}!")
    print("Next steps:")
    print(f"  git commit -am 'chore(release): v{next_ver}'")
    print(f"  git tag -a v{next_ver} -m 'Release v{next_ver}'")
    print("  git push --follow-tags")


if __name__ == "__main__":
    main()
