# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0] - Unreleased

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
