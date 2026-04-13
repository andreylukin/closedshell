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
6. Decisions are persisted to SQLite; the TUI shows live activity, pending approvals, and loaded policy rules

---

## Quick Start

### YOLO mode — log everything, block nothing

```bash
cs --yolo -- claude
```

### Enforcing mode — unknown actions block for human approval

```bash
# Claude Code
cs --template anthropic/full -- claude

# OpenAI Codex CLI
cs --template openai/full -- codex

# Any agent or process
cs --template github/full -- aider --model gpt-4
```

Templates pre-approve infrastructure the agent needs to function. Without a template, the agent's API calls require manual approval in the TUI.

### Works with any agent

ClosedShell sandboxes any process — it's not tied to a specific AI tool. If the process makes HTTPS requests, ClosedShell can intercept and control them.

---

## TUI

### Hub — browse sessions and templates

```bash
cs
```

Running `cs` with no arguments opens the hub — a unified view of all sessions and available templates. Switch between tabs with `Tab`.

- **Sessions tab**: browse past and running sessions with status, workdir, templates used, and decision counts. Press `Enter` to open a session's live monitor.
- **Templates tab**: browse all available templates (built-in and user). Press `Enter` to view the full policy with syntax-highlighted CSP preview.

### Session monitor — watch a live session

```bash
cs --tui <session-id>
```

Three tabs for the active session:

- **Live**: real-time activity feed with decisions (allow/deny), filterable with `f` (cycle All/Allow/Deny), searchable with `/`
- **Policy**: loaded permission rules from templates and human approvals
- **Approvals**: pending requests waiting for human decision (`y` approve, `n` deny)

Press `?` for a help overlay with all keybindings. Context-sensitive key hints are shown in the footer.

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
  --yolo                 Log-only mode — no blocking
  --resume               Resume rules from previous session in this directory
  --pf                   Enable pf (packet filter) as secondary network enforcement layer (requires root)
  --pf-setup             One-time system setup for pf enforcement (creates sandbox user + pf anchor)
  --tui <SESSION_ID>     Open the TUI monitor for an existing session
```

---

## Templates

Templates use a Cedar-inspired `.csp` (ClosedShell Policy) format to pre-approve known-good endpoints. Built-in templates are compiled into the binary — they work immediately after install with no setup.

```
@name("anthropic-full")
@description("Allow all Anthropic API, MCP proxy, and Claude Code infra endpoints")

// Core API
permit (action == "net:*:api.anthropic.com/*");

// MCP proxy
permit (action == "net:*:mcp-proxy.anthropic.com/*");

// Block admin endpoints
forbid (action == "net:*:api.anthropic.com/admin/*")
  reason("admin access blocked");
```

### Built-in templates

| Template | What it permits |
|----------|----------------|
| `anthropic/full` | `api.anthropic.com`, `mcp-proxy.anthropic.com`, `downloads.claude.ai`, Claude Code storage |
| `openai/full` | `api.openai.com` (all endpoints — GPT, Codex CLI, assistants, files) |
| `github/full` | `api.github.com`, `github.com`, `uploads.github.com` |
| `github/readonly` | `api.github.com` and `github.com` (GET only) |
| `exa/full` | `api.exa.ai` (all endpoints) |
| `exa/readonly` | `api.exa.ai` (read-only) |
| `exa/search-only` | `api.exa.ai` (search only) |

### Resolution order

When you pass `--template myservice/full`, ClosedShell looks in order:

1. Exact file path (absolute or relative)
2. `~/.closedshell/templates/myservice/full.csp` (your custom templates)
3. Built-in templates (compiled into the binary)

User templates override built-in ones — drop a file with the same path in `~/.closedshell/templates/` to customize.

### Creating your own templates

```bash
# Scaffold a new template
cs template init myservice
# → creates ~/.closedshell/templates/myservice/full.csp

# Or generate one from observed traffic
cs --yolo -- <command>
cs template generate <session-id> --name myservice-full --save

# Validate your template
cs template validate myservice/full

# Test specific actions against it
cs template check myservice/full "net:GET:api.myservice.com/v1/data"
# → PERMIT — matched: net:*:api.myservice.com/*

cs template check myservice/full "net:DELETE:api.myservice.com/admin"
# → NO MATCH — would block for human approval
```

### Template management

```
cs template list                         Show all templates (built-in and user) with source
cs template show <name>                  Display resolved template content
cs template validate <name>              Validate and show rule summary
cs template check <name> <action>        Test if an action would be permitted/forbidden
cs template init <provider>              Scaffold a new template
cs template generate <session-id>        Generate from a YOLO session's audit log
```

See [templates/CONTRIBUTING.md](templates/CONTRIBUTING.md) for the full format reference.

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
templates/           # bundled permission templates (.csp format)
docs/                # design docs
```

| Doc | Description |
|-----|-------------|
| [architecture.md](docs/architecture.md) | Seatbelt sandbox + proxy design |
| [permission-tree.md](docs/permission-tree.md) | Permission model and evaluation |
| [proxy.md](docs/proxy.md) | HTTPS proxy and provider parsers |
| [development.md](docs/development.md) | Build sections and dependency graph |
