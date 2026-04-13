# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.1.1] - 2026-04-13

### Changed

- Renamed binary from `closedshell` to `cs`
- Replaced YAML templates with Cedar-inspired `.csp` policy format
- Embedded built-in templates in the binary (no install step needed)
- Moved audit logs to `~/.closedshell/logs/<encoded-cwd>/`
- TUI overhaul: unified hub view, footer hints, help overlay, activity filter
- Added multicolor syntax highlighting to TUI

### Removed

- Removed `--task`, `--no-motd`, and `--allow` CLI flags

### Fixed

- Fixed CI: gate macOS-specific symlink test with `cfg(target_os)`

## [0.1.0] - 2026-04-12

### Added

- Seatbelt sandbox enforcement for macOS
- HTTPS MITM proxy with SNI-based TLS termination
- Permission tree (Cedar-inspired: forbid-overrides-permit, default deny)
- Deterministic enforcement: template permits → allow, explicit forbids → deny, unknown → block for human approval
- Provider parsers: AWS, GCP, Azure, Kubernetes, GitHub, Anthropic, Exa
- YOLO mode — log all HTTPS traffic, block nothing
- Template system for pre-approved permissions
- TUI for real-time session monitoring and human approval of unknown actions
- Packet filter (pf) as secondary network enforcement layer
