# CLAUDE.md

## What This Is

ClosedShell: control the network, let the agent roam free. A macOS sandbox for AI coding agents — two static Rust binaries (`closedshell` + `ask`). Seatbelt + MITM proxy enforce permissions at the network boundary. No root required.

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

**Enforcement:** Seatbelt blocks all outbound except `localhost:8443`. Env-var proxy forces HTTPS through host-side MITM proxy. Proxy terminates TLS (SNI peek → dynamic cert), parses requests into canonical actions (`aws:s3:ListBuckets`), checks permission tree, consults judge for unknowns. Proxy holds requests during judge evaluation — agents never retry.

**Permission Tree:** Cedar-inspired (forbid-overrides-permit, default deny). Persisted to SQLite. Types: `idempotent` (persistent glob), `one-shot` (consumed on use).

**Judge:** Single LLM, OpenAI-compatible API. Structured JSON only. Timeout = deny.

**Provider Parsers:** Pluggable trait. AWS/GCP/Azure/K8s/GitHub built-in, unknown → `net:METHOD:host/path`.

## Project Structure

```
crates/
  closedshell-lib/   # shared library (config, parsers, proxy, audit, tls, sandbox)
  closedshell/       # host binary (CLI + daemon)
  ask/               # in-sandbox binary
docs/                # spec (DO NOT MODIFY — treat as requirements)
```

## Current Phase: YOLO Shell

Log-only sandbox: intercept all HTTPS, parse into actions, log everything, block nothing.

## Build Order

1. **YOLO Shell** (current) — sandbox + proxy + parsers + audit logging
2. Permission Tree
3. Judge Integration
4. TUI + Human Approval
