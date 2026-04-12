# CLAUDE.md

## What This Is

ClosedShell: control the network, let the agent roam free. A macOS sandbox for AI coding agents — two static Rust binaries (`closedshell` + `ask`). Seatbelt + MITM proxy enforce permissions at the network boundary. No root required.

## Build

```bash
make build                           # dev build
make release                         # optimized release build
make test                            # all tests
make lint                            # clippy (fail on warnings)
make fmt                             # check formatting
make fmt-fix                         # fix formatting
make check                           # fmt + lint + test (what CI runs)
make install                         # install both binaries to ~/.cargo/bin
make clean                           # clean build artifacts
```

Single test / single crate:
```bash
cargo test <name>                    # single test
cargo test -p <crate>                # one crate's tests
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
docs/                # architecture spec and design docs
```

## Usage

```bash
# YOLO mode — log everything, block nothing
cs --yolo -- claude

# Enforcing mode — judge evaluates unknown actions against task scope
cs --template anthropic/full --task "describe what the agent should do" -- claude
```

**Templates** pre-approve infra the agent needs to function. Without `--template anthropic/full`, Claude Code's own API calls get blocked by the judge.

Templates live in `~/.closedshell/templates/` and can also be referenced by absolute path. Bundled templates are in `templates/` in the repo — copy them to `~/.closedshell/templates/` or use `make install`.

Available templates:
- `anthropic/full` — permits `api.anthropic.com`, `mcp-proxy.anthropic.com`, `downloads.claude.ai`, Claude Code storage

**`--task`** sets the session task. In enforcing mode, the judge uses it as context to decide whether non-template actions should be allowed. For example, `--task "search for Boston chocolate places"` would cause the judge to deny Exa searches for unrelated topics.

## Modes

| Mode | Flag | Behavior |
|------|------|----------|
| YOLO | `--yolo` | Log all HTTPS, block nothing |
| Enforcing | (default) | Template permits → allow. Explicit forbids → deny. Unknown → judge evaluates against task |

## Build Order

1. ~~YOLO Shell~~ ✓
2. ~~Permission Tree~~ ✓
3. ~~Judge Integration~~ ✓
4. TUI + Human Approval
