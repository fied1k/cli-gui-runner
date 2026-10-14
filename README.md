# CLI Quick-Reference GUI Runner

[![Release](https://img.shields.io/github/v/release/fied1k/cli-gui-runner?include_prereleases&style=flat-square&color=blue)](https://github.com/fied1k/cli-gui-runner/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg?style=flat-square)](https://www.python.org/)
[![CI](https://github.com/fied1k/cli-gui-runner/actions/workflows/ci.yml/badge.svg)](https://github.com/fied1k/cli-gui-runner/actions/workflows/ci.yml)
[![Automated Versioning](https://img.shields.io/badge/versioning-release--please-orange.svg?style=flat-square)](https://github.com/googleapis/release-please)

An intuitive, lightweight desktop GUI application that transforms static CLI cheat sheets, runbooks, and command templates into an interactive execution dashboard. Parameterize commands on the fly, stream live terminal output, and easily import command tables or clipboard snippets.

---

```text
+-----------------------------------------------------------------------------------------+
| [Open Cheat Sheet...] [Reload File] [Import PasteCommands.txt] [Quick Paste Editor...]  |
+-----------------------------------------------------------------------------------------+
| Available Commands (Click to Configure & Run)                                           |
| +-------------------------+ +-------------------------+ +-----------------------------+ |
| |        Ping Host        | |    Port Scan (Nmap)     | |     Find Files by Name      | |
| | ping -c 4 <Target>      | | nmap -sV -p <Port> <IP> | | find <Dir> -name "*<Term>*" | |
| +-------------------------+ +-------------------------+ +-----------------------------+ |
| +-------------------------+ +-------------------------+                                 |
| |    Check Disk Space     | |   Custom cURL Request   |                                 |
| | df -h                   | | curl -I -X <Method> URL |                                 |
| +-------------------------+ +-------------------------+                                 |
+-----------------------------------------------------------------------------------------+
| Live Execution Output                                        [Stop Running Command]     |
| $ ping -c 4 1.1.1.1                                                                     |
| PING 1.1.1.1 (1.1.1.1): 56 data bytes                                                   |
| 64 bytes from 1.1.1.1: icmp_seq=0 ttl=58 time=14.2 ms                                   |
| ...                                                                                     |
+-----------------------------------------------------------------------------------------+
```

---

## Key Features

- **Interactive Command Grid**: Automatically renders buttons for each command parsed from cheat sheet text files (`commands.txt`, `.md`, `.conf`).
- **Dynamic Parameter Extraction**: Automatically detects placeholders formatted as `<variable>`, `{variable}`, or `[variable]` and presents a clean modal form to enter parameter values before execution.
- **Direct Execution**: Commands without variables prompt for quick execution confirmation without unnecessary dialogues.
- **Real-Time Live Terminal**: Embedded dark-mode terminal showing real-time streaming `stdout` and `stderr` directly from subprocesses.
- **Process Management**: Safely terminate long-running, hanging, or background commands anytime using the **Stop Running Command** button.
- **Smart Paste Importer**: Ingest unstructured command tables or raw snippets into clean cheat sheet entries:
  - Tab-Separated Tables (TSV copied from docs or websites)
  - Pipe-delimited records (`Label | Command | Description`)
  - Colon or hyphen formats (`Label: Command` or `Label - Command`)
  - Preceding and inline comments (`# Comment \n Command` or `Command # Note`)
  - Automatic prompt stripping (`$ `, `> `)
- **Built-in Quick Paste Editor**: An in-app scratchpad for quickly editing, testing, and formatting raw command snippets directly into your cheat sheet.
- **Zero Heavy Dependencies**: Built exclusively on Python's built-in `tkinter`, `subprocess`, and standard library modules.

---

## Installation & Requirements

- Python 3.8 or newer
- Tkinter (included by default on Windows & macOS; on Linux install `python3-tk`)

### Clone & Run

```bash
git clone https://github.com/fied1k/cli-gui-runner.git
cd cli-gui-runner
python cli_gui_runner.py
```

### Optional: Install as Editable Package

```bash
pip install -e .
cli-gui-runner
```

---

## Cheat Sheet Syntax

Cheat sheets are simple, human-readable text files (default: `commands.txt`).

### Standard Pipe Format
```text
Label | Command Template | Description (Optional)
```

Example:
```text
Ping Host | ping -c 4 <IP_or_Hostname> | Send 4 ICMP echo requests to a target
Port Scan (Nmap) | nmap -sV -p <Port_Range> <Target_IP> | Scan specific ports and detect versions
Check Disk Space | df -h | Show current disk usage
```

### Supported Variable Placeholder Styles
- `<IP_Address>` (Standard angle bracket)
- `{Port_Number}` (Curly brace)
- `[Interface_Name]` (Square bracket)

---

## Importing Raw Commands (`PasteCommands.txt`)

You can quickly convert tables, notes, or scratchpads into executable cheat sheets using **Import PasteCommands.txt** or the **Quick Paste Editor...**.

Supported input formats:

1. **Tab-Separated (TSV) from Documentation:**
   ```tsv
   Action	Command	Description
   List Interfaces	tshark -D	Shows network interfaces
   Live Capture	tshark -i <interface>	Captures live traffic
   ```
2. **Comment Above Command:**
   ```bash
   # Scan open web ports
   nmap -p 80,443 <Target_IP>
   ```
3. **Inline Comment:**
   ```bash
   whois <Domain_Name> # Query WHOIS database
   ```
4. **Prefixed Shell Commands:**
   ```bash
   $ ssh [Username]@<Server_IP> -p {Port}
   ```

---

## Automated Versioning & Releases

This repository uses **Google Release Please** and **Conventional Commits** for fully automated semantic versioning and changelog maintenance.

### Conventional Commits Guide

When contributing or committing, format commit messages as:

| Prefix | Type | SemVer Impact | Example |
| :--- | :--- | :--- | :--- |
| `feat:` | New feature | **Minor** (`0.X.0`) | `feat: add export to json button` |
| `fix:` | Bug fix | **Patch** (`0.0.X`) | `fix: handle whitespace in variable values` |
| `perf:` | Performance improvement | **Patch** (`0.0.X`) | `perf: buffer terminal stream output` |
| `docs:` | Documentation changes | None | `docs: add screenshot and install notes` |
| `refactor:` | Code restructuring | None / Patch | `refactor: extract parser into module` |
| `BREAKING CHANGE:` | Breaking API changes | **Major** (`X.0.0`) | `feat!: redesign cheat sheet file format` |

### How It Works
1. Every push to `main` triggers `.github/workflows/release.yml`.
2. Release Please scans commit history since the last release.
3. If release-worthy commits exist, it creates or updates a release Pull Request that:
   - Updates `CHANGELOG.md` with categorized changes.
   - Bumps the version in `pyproject.toml` and `cli_gui_runner.py`.
4. When the release PR is merged, Release Please creates a Git tag (`vX.Y.Z`) and a GitHub Release.

### Push & Synchronize (Local Folder + Remote Repo)

To ensure that pushing your changes updates **both your local folder files** (`cli_gui_runner.py`, `pyproject.toml`, `CHANGELOG.md`) and the **remote GitHub repository** with the new version and changelog tags simultaneously:

```powershell
# In PowerShell:
.\push.ps1 -Message "feat: add search filter to command list"

# Or using the Git sync alias:
git sync -m "feat: add search filter to command list"

# Or directly with Python:
python scripts/push.py -m "feat: add search filter to command list"
```

This automated push pipeline will:
1. Fetch remote tags and pull any remote updates.
2. Stage and commit your changes.
3. Automatically determine the SemVer increment level (`patch`, `minor`, or `major`) from your commits.
4. Update `__version__` in `cli_gui_runner.py` and `version` in `pyproject.toml`.
5. Prepend the new release section to `CHANGELOG.md`.
6. Commit the version bump and create the Git tag in your local repository.
7. Push both the branch commits and release tags to GitHub.

---

### Local Version Bumping Tool
A zero-dependency helper script is also included if you only want to bump version files without pushing:

```bash
# Auto-detect bump level from git commit history
python scripts/bump_version.py --auto

# Or manually bump
python scripts/bump_version.py --bump patch
python scripts/bump_version.py --bump minor
python scripts/bump_version.py --bump major

# Or set an explicit version
python scripts/bump_version.py --set 1.0.0
```

---

## Testing

Run unit tests locally with `unittest`:

```bash
python -m unittest discover tests
```

Or with `pytest`:

```bash
pip install pytest
pytest
```

---

## License

This project is licensed under the [MIT License](LICENSE).
