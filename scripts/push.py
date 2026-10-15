#!/usr/bin/env python3
"""Unified Push & Synchronize Tool.

Ensures that whenever code is pushed:
1. Local folder files (cli_gui_runner.py, pyproject.toml, CHANGELOG.md) are updated with the latest SemVer and changelog entries.
2. The local git repository creates the version tag.
3. The remote repository and tags are updated simultaneously.
4. Remote changes and tags are synchronized back to the local folder.

Usage:
    python scripts/push.py
    python scripts/push.py -m "feat: add search filter to command list"
    python scripts/push.py --bump minor
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


def run(cmd, check=True, capture=False):
    """Run a shell command within the repository root."""
    if capture:
        result = subprocess.run(cmd, cwd=ROOT_DIR, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if check and result.returncode != 0:
            raise RuntimeError(f"Command failed ({result.returncode}): {' '.join(cmd)}\n{result.stderr}")
        return result.stdout.strip()
    else:
        return subprocess.run(cmd, cwd=ROOT_DIR, check=check)


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


def calculate_next_version(current_version, bump_type):
    major, minor, patch = parse_semver(current_version)
    if bump_type == "major":
        return f"{major + 1}.0.0"
    elif bump_type == "minor":
        return f"{major}.{minor + 1}.0"
    elif bump_type == "patch":
        return f"{major}.{minor}.{patch + 1}"
    return current_version


def determine_bump_from_commits():
    try:
        latest_tag = run(["git", "describe", "--tags", "--abbrev=0"], capture=True)
        commit_range = f"{latest_tag}..HEAD"
    except Exception:
        commit_range = "HEAD"

    try:
        log = run(["git", "log", commit_range, "--oneline"], capture=True)
    except Exception:
        return None

    if not log.strip():
        return None

    bump = "patch"
    for line in log.strip().splitlines():
        if "BREAKING CHANGE" in line or "!:" in line:
            return "major"
        if re.search(r"^\w+\s+feat(\([^\)]+\))?:", line):
            bump = "minor"
    return bump


def update_file_version(filepath, pattern, replacement):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    new_content, count = re.subn(pattern, replacement, content)
    if count == 0:
        raise ValueError(f"Failed to match pattern in {filepath}")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(new_content)


def update_changelog(new_version, summary_lines=None):
    today = datetime.date.today().isoformat()
    with open(CHANGELOG_FILE, "r", encoding="utf-8") as f:
        content = f.read()

    details = ""
    if summary_lines:
        details = "\n### Changes\n" + "\n".join(f"- {s}" for s in summary_lines) + "\n"

    new_section = (
        f"## [Unreleased]\n\n"
        f"## [{new_version}] - {today}\n{details}"
    )

    if "## [Unreleased]" in content:
        content = content.replace("## [Unreleased]", new_section, 1)
    else:
        lines = content.splitlines(True)
        insert_idx = 0
        for i, line in enumerate(lines):
            if line.startswith("## "):
                insert_idx = i
                break
        if insert_idx > 0:
            lines.insert(insert_idx, new_section + "\n")
            content = "".join(lines)

    # Update compare link references at the bottom if present
    unreleased_pattern = r"\[Unreleased\]:\s*(https://[^\s]+/compare/v([0-9]+\.[0-9]+\.[0-9]+)\.\.\.HEAD)"
    match = re.search(unreleased_pattern, content)
    if match:
        prev_ver = match.group(2)
        base_url = match.group(1).rsplit("/compare/", 1)[0]
        unreleased_link = f"[Unreleased]: {base_url}/compare/v{new_version}...HEAD"
        new_version_link = f"[{new_version}]: {base_url}/compare/v{prev_ver}...v{new_version}"
        content = re.sub(unreleased_pattern, f"{unreleased_link}\n{new_version_link}", content, count=1)

    with open(CHANGELOG_FILE, "w", encoding="utf-8") as f:
        f.write(content)


def main():
    parser = argparse.ArgumentParser(description="Synchronize local folder and remote repository with auto versioning.")
    parser.add_argument("-m", "--message", help="Optional commit message to stage and commit before pushing.")
    parser.add_argument("--bump", choices=["major", "minor", "patch", "none"], help="Explicitly specify bump level.")
    args = parser.parse_args()

    # If a commit message is provided or unstaged changes exist, stage and commit first
    if args.message:
        print(f"==> 1. Staging and committing changes with message: '{args.message}'...")
        run(["git", "add", "."])
        status = run(["git", "status", "--porcelain"], capture=True)
        if status:
            run(["git", "commit", "-m", args.message])

    print("==> 2. Fetching remote updates and tags...")
    try:
        run(["git", "fetch", "--tags", "origin"])
        run(["git", "pull", "--rebase", "origin", "main"], check=False)
    except Exception as e:
        print(f"    (Note during pull: {e})")

    # Determine bump level
    current_ver = get_current_version()
    bump_type = args.bump
    if not bump_type or bump_type != "none":
        detected = determine_bump_from_commits()
        if not bump_type:
            bump_type = detected

    if bump_type and bump_type != "none":
        next_ver = calculate_next_version(current_ver, bump_type)
        print(f"==> 3. Updating local folder to v{next_ver} (Bump: {bump_type})...")

        # Update local files
        update_file_version(
            VERSION_FILE,
            r'__version__\s*=\s*["\'][^"\']+["\']',
            f'__version__ = "{next_ver}"'
        )
        update_file_version(
            PYPROJECT_FILE,
            r'version\s*=\s*["\'][^"\']+["\']',
            f'version = "{next_ver}"'
        )
        update_changelog(next_ver)

        # Update release-please manifest if it exists
        manifest_file = os.path.join(ROOT_DIR, ".release-please-manifest.json")
        if os.path.exists(manifest_file):
            update_file_version(
                manifest_file,
                r'"\."\s*:\s*"[^"]+"',
                f'"." : "{next_ver}"'
            )

        # Stage and commit version bump in local folder
        run(["git", "add", VERSION_FILE, PYPROJECT_FILE, CHANGELOG_FILE])
        if os.path.exists(manifest_file):
            run(["git", "add", manifest_file])
        run(["git", "commit", "-m", f"chore(release): bump version to v{next_ver} [skip ci]"])
        run(["git", "tag", "-a", f"v{next_ver}", "-m", f"Release v{next_ver}"])
        print(f"    [OK] Local files updated and tagged: v{next_ver}")
    else:
        print("==> 3. No version bump detected. Ready to push.")

    # Push to origin
    print("==> 4. Pushing commits and tags to remote repository...")
    run(["git", "push", "origin", "main"])
    run(["git", "push", "origin", "--tags"])

    print("\n[SUCCESS] Local folder and remote repository are fully updated and synchronized!")


if __name__ == "__main__":
    main()
