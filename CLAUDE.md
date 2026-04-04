# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

ClosedShell: a sandbox for AI agents on macOS. Two static Rust binaries — `closedshell` (host daemon/proxy) and `ask` (in-sandbox CLI). Seatbelt + MITM proxy enforce permissions. No root required.

## Build

```bash
cargo build                          # build
cargo test                           # all tests
cargo test <name>                    # single test
cargo test -p <crate>                # one crate's tests
cargo clippy -- -D warnings          # lint
cargo fmt --check                    # format check
```

## Architecture

**Enforcement:** Seatbelt denies all network-outbound except `localhost:8443`. Env-var proxy forces HTTPS through host-side MITM proxy. Proxy terminates TLS (SNI peek → dynamic cert from session CA), parses requests into canonical actions (`aws[profile=dev]:s3:ListBuckets`), checks permission tree, consults judge for unknowns. Proxy holds requests during judge evaluation — agents never retry.

**Permission Tree:** Cedar-inspired (forbid-overrides-permit, default deny). In-memory, session-scoped. Types: `idempotent` (persistent glob), `one-shot` (consumed), `state-dependent` (`when` conditions checked at point-of-use). Templates for cold start. Standalone, no system deps — unit-testable from day one. See `docs/permission-tree.md`.

**Judge:** Single LLM, OpenAI-compatible API. Structured JSON only. Timeout = deny. No fallbacks.

**Provider Parsers:** Pluggable trait. AWS/GCP/Azure/K8s/GitHub built-in, unknown → `net:METHOD:host/path`.

**Crates:** tokio, rustls, rcgen, hyper, reqwest, serde/serde_yaml, clap.

## Build Order

1. Permission Tree + Sandbox/Daemon/Proxy (parallel)
2. Judge Integration
3. Human Approval + `when` Conditions (parallel)

See `README.md` for overview and `docs/` for detailed design.
