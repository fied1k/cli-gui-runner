# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-10-14


## [0.2.0] - 2026-10-14


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

[Unreleased]: https://github.com/fied1k/cli-gui-runner/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/fied1k/cli-gui-runner/releases/tag/v0.1.0
