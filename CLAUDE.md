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

**Permission Tree:** Cedar-inspired (forbid-overrides-permit, default deny). Persisted to SQLite, keyed by working directory. Types: `idempotent` (persistent glob), `one-shot` (consumed on use). Templates for cold start. Standalone, no system deps — unit-testable from day one. See `docs/permission-tree.md`.

**Judge:** Single LLM, OpenAI-compatible API. Structured JSON only. Timeout = deny. No fallbacks.

**Provider Parsers:** Pluggable trait. AWS/GCP/Azure/K8s/GitHub built-in, unknown → `net:METHOD:host/path`.

**Crates:** tokio, rustls, rcgen, hyper, reqwest, serde/serde_yaml, clap.

## Project Structure

```
crates/
  closedshell-lib/   # shared library (config, parsers, proxy, audit, tls, sandbox)
  closedshell/       # host binary (CLI + daemon)
  ask/               # in-sandbox binary (not needed for YOLO phase)
current_tasks/       # agent task tracking (see AGENT_PROMPT.md)
docs/                # spec (DO NOT MODIFY — treat as requirements)
```

## Current Phase: YOLO Shell

Building the log-only sandbox: intercept all HTTPS, parse into actions, log everything, block nothing. See `AGENT_PROMPT.md` for task details and workflow.

## Build Order

1. **YOLO Shell** (current) — sandbox + proxy + parsers + audit logging
2. Permission Tree
3. Judge Integration
4. TUI + Human Approval

See `README.md` for overview and `docs/` for detailed design.
