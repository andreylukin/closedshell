# ClosedShell

[![CI](https://github.com/andreylukin/closedshell/actions/workflows/ci.yml/badge.svg)](https://github.com/andreylukin/closedshell/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)

**Control the network. Let the agent roam free.**

A macOS sandbox for AI coding agents. Instead of restricting what tools an agent can use, ClosedShell controls what leaves your machine — every outbound HTTPS request is intercepted, parsed, and checked before it hits the wire.

The agent gets full access to your local tools, files, and shell. The network is the leash.

No root. No kernel extensions. One static Rust binary.

> **macOS only.** ClosedShell uses macOS Seatbelt for sandboxing. Linux support is not currently planned — contributions welcome.

---

## Install

**Homebrew:**

```bash
brew install andreylukin/tap/closedshell
```

**Pre-built binaries:** Download from [GitHub Releases](https://github.com/andreylukin/closedshell/releases) (Apple Silicon and Intel).

**From source:**

```bash
git clone https://github.com/andreylukin/closedshell.git
cd closedshell
make install    # builds and installs to ~/.cargo/bin
```

---

## How It Works

```
┌──────────────────────────────────┐
│  Sandboxed Shell (Seatbelt)      │
│  Agent runs here — full local    │
│  access, no network except proxy │
└──────────────┬───────────────────┘
               │ localhost:8443
┌──────────────┴───────────────────┐
│  closedshell daemon              │
│  MITM Proxy → Parse → Decide    │
└──────────────────────────────────┘
```

1. Seatbelt blocks all outbound network except `localhost:8443`
2. Env-var proxy forces HTTPS through the host-side MITM proxy
3. Proxy terminates TLS, parses API calls into canonical actions (e.g. `aws:s3:ListBuckets`)
4. Actions are checked against a Cedar-inspired permission tree (forbid overrides permit, default deny)
5. Unknown actions block for human approval via TUI — the proxy holds the request (no agent retries needed)
6. Decisions are persisted to SQLite; a TUI shows live session activity and pending approvals

---

## Quick Start

### YOLO mode — log everything, block nothing

```bash
cs --yolo -- claude
```

### Enforcing mode — unknown actions block for human approval

```bash
# Claude Code
cs --template anthropic/full --task "refactor the auth module" -- claude

# OpenAI Codex CLI
cs --template openai/full --task "add unit tests" -- codex

# Any agent or process
cs --template github/full -- aider --model gpt-4
```

Templates pre-approve infrastructure the agent needs to function. Without a template, the agent's API calls require manual approval in the TUI.

### Works with any agent

ClosedShell sandboxes any process — it's not tied to a specific AI tool. If the process makes HTTPS requests, ClosedShell can intercept and control them.

### TUI — monitor a live session

```bash
closedshell --tui <session-id>
```

---

## Threat Model

**What we stop:** An agent nuking your production fleet, deleting S3 buckets, pushing bad deploys — remote damage at scale.

**What we don't stop:** Local file writes, CPU/memory abuse, reading files on your machine. Annoying, but recoverable. The network is where the catastrophic mistakes happen.

---

## CLI Reference

```
closedshell [OPTIONS] [COMMAND]...

Options:
  --template <TEMPLATE>  Permission template to load (repeatable)
  --task <TASK>          Session task description (shown in MOTD and audit log)
  --yolo                 Log-only mode — no blocking
  --resume               Resume rules from previous session in this directory
  --allow <ALLOW>        Allow actions matching this glob pattern (repeatable)
  --tui <SESSION_ID>     Open the TUI monitor for an existing session
  --no-motd              Suppress MOTD on start
```

---

## Templates

Templates are YAML files that pre-approve known-good endpoints. Bundled templates:

| Template | What it permits |
|----------|----------------|
| `anthropic/full` | `api.anthropic.com`, `mcp-proxy.anthropic.com`, `downloads.claude.ai`, Claude Code storage |
| `openai/full` | `api.openai.com` (all endpoints — GPT, Codex CLI, assistants, files) |
| `github/full` | `api.github.com`, `github.com`, `uploads.github.com` |
| `github/readonly` | `api.github.com` and `github.com` (GET only) |
| `exa/full` | `api.exa.ai` (all endpoints) |
| `exa/readonly` | `api.exa.ai` (read-only) |
| `exa/search-only` | `api.exa.ai` (search only) |

Install bundled templates: `cp -r templates/ ~/.closedshell/templates/`

Or reference by absolute path: `--template /path/to/template.yaml`

---

## Configuration

```yaml
# closedshell.yaml (./closedshell.yaml → ~/.closedshell/config.yaml)

sandbox:
  yolo: false
  passthrough_env:
    - OPENAI_API_KEY
    - GITHUB_TOKEN
    - AWS_ACCESS_KEY_ID
    - AWS_SECRET_ACCESS_KEY
```

---

## Architecture

```
crates/
  closedshell-lib/   # shared library (config, parsers, proxy, audit, tls, sandbox)
  closedshell/       # host binary (CLI + daemon + TUI)
templates/           # bundled permission templates
docs/                # design docs
```

| Doc | Description |
|-----|-------------|
| [architecture.md](docs/architecture.md) | Seatbelt sandbox + proxy design |
| [permission-tree.md](docs/permission-tree.md) | Permission model and evaluation |
| [proxy.md](docs/proxy.md) | HTTPS proxy and provider parsers |
| [development.md](docs/development.md) | Build sections and dependency graph |
