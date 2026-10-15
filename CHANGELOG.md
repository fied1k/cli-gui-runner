# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Dynamic Field Re-Mapping**: Interactive column mapping in the verification modal allowing users to assign columns (`Switch`, `Example`, `Description`, `Category`, `Ignore`) on the fly.
- **Adaptive Rule Learning**: Importer automatically learns custom header keywords and structural column signatures, remembering how to parse non-standard tables for future imports.
- **Persistent Rule Registry**: Stored profile mappings (`profiles/learned_mappings.json`) with out-of-the-box support for standard, inverted, action-oriented, doc-style, and two-column layouts.
- **Live Preview Treeview**: Instant visual feedback displaying parsed command templates and switches as column dropdown assignments change.
- **Column Swap Utility**: One-click "Swap Switch & Example" button to invert improperly ordered command columns instantly.

## [0.5.0] - 2026-10-15

### Added
- **Multi-Cheat Sheet Profile Engine**: Dropdown profile selector in the main toolbar supporting dynamic switching between tool suites (`nmap`, `kismet`, `tshark`, `hashcat`, etc.).
- **Interactive Verification Modal**: Review parsed command cards before committing them to profiles, complete with confidence scores and preview grids.
- **Kismet Wireless Suite Profile**: Dedicated profile and command runner tailored for wireless security auditing and RF capture analysis.
- **Automated Profile Compiler**: Script utility to compile raw scraped cheat sheets into native JSON profiles and formatted command reference files.

## [0.4.0] - 2026-10-14

### Added
- **Standalone Web Scraper Tool (`cheatsheet-scraper`)**: Standalone dual CLI & GUI application to scrape online cheat sheets directly from URLs (e.g. Offensive Ramen).
- **Intelligent Switch Synthesizer**: Reconstructs standalone options (e.g. `-sV`, `-p-`) into fully executable command templates (`nmap -sV <target>`).
- **URL & HTML File Input**: Ingest directly from remote HTTP/HTTPS URLs or locally saved HTML cheat sheet files.
- **Anchor & Markdown Cleanup**: Removes anchor artifacts (`#`), URL fragments, and styling tags for clean command generation.

## [0.3.0] - 2026-10-14

### Added
- **Web Command Extractor**: In-app scraping capabilities to extract tabular commands directly from documentation pages.
- **Contextual Command Detection**: Heuristic detection of command context, switches, and parameter placeholders.
- **Comprehensive Nmap Cheat Sheet**: Included rich cheat sheet covering scanning techniques, host discovery, OS detection, and NSE scripts.

## [0.2.0] - 2026-10-14

### Added
- **Unified Push & Sync Tool (`scripts/push.py`)**: One-command release pipeline that runs test suites, bumps SemVer, tags git commits, and updates remote repositories simultaneously.
- **Live Preview Command Editor**: Live preview capability when adding or updating custom command lists.
- **Pre-Push Git Hooks**: Automated local pre-push verification ensuring tests pass before code leaves the local machine.

### Fixed
- **Version Definition Consistency**: Fixed package version discovery and synchronization between `pyproject.toml` and `cli_gui_runner.py`.

## [0.1.0] - 2026-10-14

### Added
- **Interactive Cheat Sheet GUI**: Grid layout of executable command cards automatically generated from text files.
- **Dynamic Parameter Prompting**: Automatically detects variable placeholders (`<param>`, `{param}`, `[param]`) and presents an interactive configuration dialog before command execution.
- **Real-Time Terminal Streaming**: Asynchronous command execution streaming stdout and stderr live into an embedded dark-mode terminal widget.
- **Process Lifecycle Control**: Dedicated stop/terminate button to safely kill long-running or stalled background commands.
- **Multi-Format Command Importer**:
  - Tab-separated tables (TSV / copy-paste from documentation).
  - Pipe-delimited records (`Label | Command | Description`).
  - Colon and dash labeled lines (`Label: Command` or `Label - Command`).
  - Preceding and inline comment extraction (`# Comment \n Command` or `Command # Note`).
  - Raw shell prompts striping (`$`, `>`).
- **Quick Paste Editor Window**: In-app modal text editor for rapid staging, previewing, and importing of commands directly from clipboard or text files.
- **Automated Versioning & Release Pipeline**:
  - Integration with GitHub Actions and Google Release Please for automated SemVer tagging and changelog generation.
  - Conventional Commits support (`feat:`, `fix:`, `docs:`, etc.).
  - Zero-dependency local version bumping script (`scripts/bump_version.py`).
- **Unit Test Suite**: Full test coverage for command parsing, delimiter recognition, placeholder normalization, and TSV extraction.

[Unreleased]: https://github.com/fied1k/cli-gui-runner/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/fied1k/cli-gui-runner/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/fied1k/cli-gui-runner/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/fied1k/cli-gui-runner/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/fied1k/cli-gui-runner/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/fied1k/cli-gui-runner/releases/tag/v0.1.0
