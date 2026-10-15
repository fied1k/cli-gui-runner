#!/usr/bin/env python3
"""Local Semantic Versioning, README and Changelog Automation Script.

Usage:
    python scripts/bump_version.py --bump patch
    python scripts/bump_version.py --bump minor
    python scripts/bump_version.py --bump major
    python scripts/bump_version.py --auto
    python scripts/bump_version.py --set 1.2.0
"""

import argparse
import os
import sys

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from push import (
    get_current_version,
    calculate_next_version,
    determine_bump_from_commits,
    update_file_version,
    update_changelog,
    update_readme,
    VERSION_FILE,
    PYPROJECT_FILE,
    CHANGELOG_FILE,
    README_FILE,
    ROOT_DIR,
)


def main():
    parser = argparse.ArgumentParser(description="Bump project version and update changelog & README.")
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
        next_ver = calculate_next_version(curr_ver, bump)
    else:
        next_ver = calculate_next_version(curr_ver, args.bump)

    print(f"Bumping version to: {next_ver}")
    update_file_version(VERSION_FILE, r'__version__\s*=\s*["\'][^"\']+["\']', f'__version__ = "{next_ver}"')
    update_file_version(PYPROJECT_FILE, r'version\s*=\s*["\'][^"\']+["\']', f'version = "{next_ver}"')
    update_changelog(next_ver)
    update_readme(next_ver)
    print(f"Successfully bumped files to v{next_ver}!")


if __name__ == "__main__":
    main()
