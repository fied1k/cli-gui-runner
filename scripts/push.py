#!/usr/bin/env python3
"""Unified Push & Synchronize Tool with Auto-Versioning, README & CHANGELOG Maintenance.

Ensures that whenever code is pushed:
1. Calculates SemVer increment (patch/minor/major) from commit messages or parameter.
2. Updates version in cli_gui_runner.py, pyproject.toml, and .release-please-manifest.json.
3. Automatically generates structured Keep-a-Changelog entries in CHANGELOG.md from git commits.
4. Updates README.md with the latest version badge, executable download links, and release block.
5. Compiles standalone Windows executable (CliGuiRunner.exe) and saves to root folder.
6. Stages, commits, tags, and pushes everything to the remote repository.

Usage:
    python scripts/push.py
    python scripts/push.py -m "feat: add auto-fill variables"
    python scripts/push.py --bump minor
    python scripts/push.py --from-hook
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
README_FILE = os.path.join(ROOT_DIR, "README.md")
TARGET_EXE = os.path.join(ROOT_DIR, "CliGuiRunner.exe")


def run(cmd, check=True, capture=False):
    """Run a shell command within the repository root with SYNC_IN_PROGRESS set."""
    env = dict(os.environ, SYNC_IN_PROGRESS="1")
    if capture:
        result = subprocess.run(cmd, cwd=ROOT_DIR, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        if check and result.returncode != 0:
            raise RuntimeError(f"Command failed ({result.returncode}): {' '.join(cmd)}\n{result.stderr}")
        return result.stdout.strip()
    else:
        return subprocess.run(cmd, cwd=ROOT_DIR, check=check, env=env)


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


def extract_commits_since_last_tag():
    """Extract list of commit subjects since the most recent git tag."""
    try:
        latest_tag = run(["git", "describe", "--tags", "--abbrev=0"], capture=True)
        commit_range = f"{latest_tag}..HEAD"
    except Exception:
        commit_range = "HEAD"

    try:
        log = run(["git", "log", commit_range, "--pretty=format:%s"], capture=True)
    except Exception:
        return []

    lines = [line.strip() for line in log.strip().splitlines() if line.strip()]
    return lines


def determine_bump_from_commits(commits=None):
    if commits is None:
        commits = extract_commits_since_last_tag()

    if not commits:
        return "patch"

    for line in commits:
        if "BREAKING CHANGE" in line or "!:" in line:
            return "major"
        if re.search(r"^\w+\s*(\([^\)]+\))?!?:", line) and re.match(r"^feat", line, re.I):
            return "minor"
    return "patch"


def categorize_commits(commits, extra_message=None):
    """Categorize commit messages into standard Keep-a-Changelog groups."""
    all_msgs = []
    if extra_message:
        all_msgs.append(extra_message)
    if commits:
        all_msgs.extend(commits)

    categorized = {
        "Added": [],
        "Fixed": [],
        "Changed": [],
        "Performance": [],
        "Documentation": [],
        "Maintenance": []
    }

    seen = set()
    for raw in all_msgs:
        msg = raw.strip()
        if not msg or msg.lower() in seen:
            continue
        seen.add(msg.lower())

        # Skip release bump commits
        if re.search(r"chore\(release\):|\[skip ci\]|bump version to", msg, re.I):
            continue

        if re.match(r"^feat(\([^\)]+\))?:\s*", msg, re.I):
            clean = re.sub(r"^feat(\([^\)]+\))?:\s*", "", msg, flags=re.I).strip()
            categorized["Added"].append(clean)
        elif re.match(r"^fix(\([^\)]+\))?:\s*", msg, re.I):
            clean = re.sub(r"^fix(\([^\)]+\))?:\s*", "", msg, flags=re.I).strip()
            categorized["Fixed"].append(clean)
        elif re.match(r"^perf(\([^\)]+\))?:\s*", msg, re.I):
            clean = re.sub(r"^perf(\([^\)]+\))?:\s*", "", msg, flags=re.I).strip()
            categorized["Performance"].append(clean)
        elif re.match(r"^docs(\([^\)]+\))?:\s*", msg, re.I):
            clean = re.sub(r"^docs(\([^\)]+\))?:\s*", "", msg, flags=re.I).strip()
            categorized["Documentation"].append(clean)
        elif re.match(r"^(refactor|style)(\([^\)]+\))?:\s*", msg, re.I):
            clean = re.sub(r"^(refactor|style)(\([^\)]+\))?:\s*", "", msg, flags=re.I).strip()
            categorized["Changed"].append(clean)
        elif re.match(r"^(chore|test|ci|build)(\([^\)]+\))?:\s*", msg, re.I):
            clean = re.sub(r"^(chore|test|ci|build)(\([^\)]+\))?:\s*", "", msg, flags=re.I).strip()
            categorized["Maintenance"].append(clean)
        else:
            categorized["Changed"].append(msg)

    return categorized


def generate_changelog_section(new_version, commits, extra_message=None):
    today = datetime.date.today().isoformat()
    categorized = categorize_commits(commits, extra_message)

    has_entries = any(len(items) > 0 for items in categorized.values())
    if not has_entries:
        categorized["Maintenance"].append(f"Release v{new_version} asset and dependency synchronization.")

    lines = [f"## [{new_version}] - {today}\n"]
    for cat_name, items in categorized.items():
        if items:
            lines.append(f"### {cat_name}")
            for item in items:
                formatted = item[0].upper() + item[1:] if len(item) > 1 else item.upper()
                lines.append(f"- {formatted}")
            lines.append("")

    return "\n".join(lines).strip()


def update_changelog(new_version, commits=None, extra_message=None):
    if not os.path.exists(CHANGELOG_FILE):
        return

    with open(CHANGELOG_FILE, "r", encoding="utf-8") as f:
        content = f.read()

    new_section = generate_changelog_section(new_version, commits, extra_message)
    full_new_block = f"## [Unreleased]\n\n{new_section}\n"

    if "## [Unreleased]" in content:
        content = content.replace("## [Unreleased]", full_new_block, 1)
    else:
        lines = content.splitlines(True)
        insert_idx = 0
        for i, line in enumerate(lines):
            if line.startswith("## "):
                insert_idx = i
                break
        if insert_idx > 0:
            lines.insert(insert_idx, full_new_block + "\n")
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
    print(f"    [OK] Updated {os.path.basename(CHANGELOG_FILE)} with release notes for v{new_version}")


def update_readme(new_version):
    """Automatically update version badge and release info block in README.md."""
    if not os.path.exists(README_FILE):
        return

    with open(README_FILE, "r", encoding="utf-8") as f:
        content = f.read()

    # 1. Update or inject version badge
    version_badge = f"[![Version](https://img.shields.io/badge/version-v{new_version}-blue.svg?style=flat-square)](https://github.com/fied1k/cli-gui-runner/releases/tag/v{new_version})"
    if "img.shields.io/badge/version-v" in content:
        content = re.sub(
            r'\[!\[Version\]\(https://img\.shields\.io/badge/version-v[0-9\.]+-blue\.svg\?style=flat-square\)\]\([^\)]+\)',
            version_badge,
            content
        )
    else:
        # Place right after the Release badge
        content = re.sub(
            r'(\[!\[Release\]\([^\)]+\)\]\([^\)]+\)\n)',
            r'\1' + version_badge + "\n",
            content
        )

    # 2. Update or inject release info section
    release_block = (
        f"<!-- RELEASE_INFO_START -->\n"
        f"### Latest Release: v{new_version}\n\n"
        f"- **Standalone Windows Executable**: Download [`CliGuiRunner.exe`](CliGuiRunner.exe) directly from the repository root or from [GitHub Releases](https://github.com/fied1k/cli-gui-runner/releases/tag/v{new_version}) (Zero installation required).\n"
        f"- **Quick Batch Launcher**: Double-click [`run.bat`](run.bat) to launch in development mode with error pause.\n"
        f"- **Release Notes**: See [CHANGELOG.md](CHANGELOG.md) for full history.\n"
        f"<!-- RELEASE_INFO_END -->"
    )

    if "<!-- RELEASE_INFO_START -->" in content:
        content = re.sub(
            r"<!-- RELEASE_INFO_START -->.*?<!-- RELEASE_INFO_END -->",
            release_block,
            content,
            flags=re.DOTALL
        )
    else:
        # Insert right before "## Key Features"
        content = re.sub(
            r"(## Key Features)",
            f"{release_block}\n\n---\n\n\\1",
            content
        )

    with open(README_FILE, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"    [OK] Updated {os.path.basename(README_FILE)} to v{new_version}")


def update_file_version(filepath, pattern, replacement):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    new_content, count = re.subn(pattern, replacement, content)
    if count == 0:
        raise ValueError(f"Failed to match pattern in {filepath}")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(new_content)


def build_standalone_exe():
    print("==> Compiling standalone Windows executable (CliGuiRunner.exe)...")
    build_script = os.path.join(ROOT_DIR, "scripts", "build_exe.py")
    if os.path.exists(build_script):
        run([sys.executable, build_script])


def main():
    parser = argparse.ArgumentParser(description="Synchronize local folder and remote repository with auto versioning, README & CHANGELOG.")
    parser.add_argument("-m", "--message", help="Optional commit message to stage and commit before pushing.")
    parser.add_argument("--bump", choices=["major", "minor", "patch", "none"], help="Explicitly specify bump level.")
    parser.add_argument("--no-build", action="store_true", help="Skip compiling standalone executable.")
    parser.add_argument("--from-hook", action="store_true", help="Invoked automatically by git pre-push hook.")
    args = parser.parse_args()

    # Set environment variable so hooks know push.py is actively executing
    os.environ["SYNC_IN_PROGRESS"] = "1"

    # Stage any unstaged or untracked changes if commit message is provided or invoked from hook
    if args.message:
        print(f"==> 1. Staging and committing changes with message: '{args.message}'...")
        run(["git", "add", "."])
        status = run(["git", "status", "--porcelain"], capture=True)
        if status:
            run(["git", "commit", "-m", args.message])
    elif args.from_hook:
        status = run(["git", "status", "--porcelain"], capture=True)
        if status:
            print("==> 1. Staging and committing pending changes before hook push...")
            run(["git", "add", "."])
            run(["git", "commit", "-m", "chore: sync working tree changes before push"])

    print("==> 2. Fetching remote updates and tags...")
    try:
        run(["git", "fetch", "--tags", "origin"])
        run(["git", "pull", "--rebase", "origin", "main"], check=False)
    except Exception as e:
        print(f"    (Note during pull: {e})")

    # Gather commits since last tag for auto-bump and changelog generation
    commits_since_tag = extract_commits_since_last_tag()

    current_ver = get_current_version()
    bump_type = args.bump
    if not bump_type:
        bump_type = determine_bump_from_commits(commits_since_tag)

    if bump_type and bump_type != "none":
        next_ver = calculate_next_version(current_ver, bump_type)
        print(f"==> 3. Auto-versioning: Bumping from v{current_ver} -> v{next_ver} (Bump: {bump_type})...")

        # 3.1 Update version in code & configuration
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

        manifest_file = os.path.join(ROOT_DIR, ".release-please-manifest.json")
        if os.path.exists(manifest_file):
            update_file_version(
                manifest_file,
                r'"\."\s*:\s*"[^"]+"',
                f'"." : "{next_ver}"'
            )

        # 3.2 Update CHANGELOG.md with parsed commit highlights
        update_changelog(next_ver, commits=commits_since_tag, extra_message=args.message)

        # 3.3 Update README.md with version badge and release download block
        update_readme(next_ver)

        # 3.4 Compile standalone executable into local folder
        if not args.no_build:
            build_standalone_exe()

        # 3.5 Stage and commit release bump
        files_to_add = [VERSION_FILE, PYPROJECT_FILE, CHANGELOG_FILE, README_FILE]
        if os.path.exists(manifest_file):
            files_to_add.append(manifest_file)
        if os.path.exists(TARGET_EXE):
            files_to_add.append(TARGET_EXE)

        run(["git", "add"] + files_to_add)
        run(["git", "commit", "-m", f"chore(release): bump version to v{next_ver}, update README & CHANGELOG [skip ci]"])
        run(["git", "tag", "-a", f"v{next_ver}", "-m", f"Release v{next_ver}"])
        print(f"    [OK] Local files updated, standalone exe compiled, and tagged: v{next_ver}")
    else:
        print("==> 3. No version bump detected. Compiling executable if requested...")
        if not args.no_build:
            build_standalone_exe()

    # 4. Push to origin
    print("==> 4. Pushing commits and tags to remote repository...")
    run(["git", "push", "origin", "main"])
    run(["git", "push", "origin", "--tags"])

    print("\n[SUCCESS] Local folder and remote repository are fully updated and synchronized!")


if __name__ == "__main__":
    main()
