# CLAUDE.md

## What This Is

ClosedShell: control the network, let the agent roam free. A macOS sandbox for AI coding agents — one static Rust binary. Seatbelt + MITM proxy enforce permissions at the network boundary. No root required.

## Build

```bash
make build                           # dev build
make release                         # optimized release build
make test                            # all tests
make lint                            # clippy (fail on warnings)
make fmt                             # check formatting
make fmt-fix                         # fix formatting
make check                           # fmt + lint + test (what CI runs)
make install                         # install to ~/.cargo/bin
make clean                           # clean build artifacts
```

Single test / single crate:
```bash
cargo test <name>                    # single test
cargo test -p <crate>                # one crate's tests
```

## Architecture

**Enforcement:** Seatbelt blocks all outbound except `localhost:8443`. Env-var proxy forces HTTPS through host-side MITM proxy. Proxy terminates TLS (SNI peek → dynamic cert), parses requests into canonical actions (`aws:s3:ListBuckets`), checks permission tree. Unknown actions block for human approval via TUI — the proxy holds the connection until the human decides.

**Permission Tree:** Cedar-inspired (forbid-overrides-permit, default deny). Persisted to SQLite. Types: `idempotent` (persistent glob), `one-shot` (consumed on use).

**Provider Parsers:** Pluggable trait. AWS/GCP/Azure/K8s/GitHub built-in, unknown → `net:METHOD:host/path`.

## Project Structure

```
crates/
  closedshell-lib/   # shared library (config, parsers, proxy, audit, tls, sandbox)
  closedshell/       # host binary (CLI + daemon + TUI)
docs/                # architecture spec and design docs
```

## Usage

```bash
# YOLO mode — log everything, block nothing
cs --yolo -- claude

# Enforcing mode — unknown actions block for human approval in the TUI
cs --template anthropic/full --task "describe what the agent should do" -- claude
```

**Templates** pre-approve infra the agent needs to function. Without `--template anthropic/full`, Claude Code's own API calls require manual approval in the TUI.

Templates are resolved in order: absolute/relative path → `~/.closedshell/templates/` → built-in (compiled into the binary). Built-in templates (from `templates/` in the repo) work out of the box with no install step. User templates in `~/.closedshell/templates/` override built-in ones with the same name.

Template commands: `list`, `show`, `validate`, `check`, `init`, `generate`.

Available built-in templates:
- `anthropic/full` — permits `api.anthropic.com`, `mcp-proxy.anthropic.com`, `downloads.claude.ai`, Claude Code storage
- `github/full`, `github/readonly` — GitHub API and git operations
- `exa/full`, `exa/readonly`, `exa/search-only` — Exa search API
- `openai/full` — OpenAI API endpoints

**`--task`** sets the session task. Displayed in the MOTD and audit log.

## Modes

| Mode | Flag | Behavior |
|------|------|----------|
| YOLO | `--yolo` | Log all HTTPS, block nothing |
| Enforcing | (default) | Template permits → allow. Explicit forbids → deny. Unknown → block for human approval in TUI |

## Build Order

1. ~~YOLO Shell~~ ✓
2. ~~Permission Tree~~ ✓
3. ~~Judge → Human Approval~~ ✓
4. ~~TUI + Human Approval~~ ✓
