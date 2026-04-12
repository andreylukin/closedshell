# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0] - Unreleased

### Added

- Seatbelt sandbox enforcement for macOS
- HTTPS MITM proxy with SNI-based TLS termination
- Permission tree (Cedar-inspired: forbid-overrides-permit, default deny)
- LLM judge for evaluating unknown network actions against task scope
- Provider parsers: AWS, GCP, Azure, Kubernetes, GitHub, Anthropic, Exa
- YOLO mode — log all HTTPS traffic, block nothing
- Enforcing mode with task-scoped judge evaluation
- Template system for pre-approved permissions
- `ask` binary for in-sandbox permission queries
- TUI for real-time session monitoring
- Packet filter (pf) as secondary network enforcement layer
