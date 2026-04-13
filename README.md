# ClosedShell

[![CI](https://github.com/andreylukin/closedshell/actions/workflows/ci.yml/badge.svg)](https://github.com/andreylukin/closedshell/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)

**Your AI agent has your AWS keys, your GitHub token, and access to every API on your machine. ClosedShell makes sure it only calls the ones you said it could.**

> **macOS only.** Uses macOS Seatbelt for sandboxing. Linux contributions welcome.

---

## The Problem

AI coding agents like Claude Code, Cursor, Codex, and Aider already ask before reading and writing your files. That part's handled.

But these agents also run `kubectl`, `terraform`, `aws`, `curl` — and call MCP tools that hit arbitrary APIs. **Nobody's checking those.**

Your agent inherits every credential on your machine. AWS keys, GitHub tokens, kubeconfig, gcloud auth — all of it. One bad tool call and you're looking at:

- `kubectl delete deployment production`
- `aws s3 rm s3://prod-backups --recursive`
- An MCP skill calling an API you've never heard of, using your credentials
- A retry loop burning hundreds of dollars in API costs overnight

This isn't hypothetical. A [Replit agent deleted a production database](https://www.reddit.com/r/replit/comments/1l3nnez/replit_agent_deleted_my_entire_database/) after ignoring explicit instructions 11 times. [Amazon Q was compromised](https://www.theregister.com/2025/06/16/amazon_q_developer_attack/) via a poisoned PR that instructed it to terminate EC2 instances and empty S3 buckets. A LangChain agent got stuck in a retry loop and silently ran up $800 in API bills overnight.

**Agents have file permissions. They have zero network permissions.** ClosedShell fills that gap.

---

## What ClosedShell Does

Every outbound HTTPS request from your agent is intercepted before it leaves your machine. Requests are parsed into human-readable actions:

```
aws:s3:DeleteBucket
gcp:compute:instances.delete
net:POST:api.github.com/repos/owner/repo/git/refs
net:DELETE:api.random-service.com/v1/resources
```

You define what's allowed using simple templates. Everything else blocks and asks you in a live terminal UI. The agent keeps full local access — files, shell, tools. The network is the leash.

One binary. No root. No kernel extensions. No setup beyond install.

---

## Quick Start

```bash
# Install
brew install andreylukin/tap/closedshell

# Run Claude Code with pre-approved Anthropic + GitHub access
cs --template anthropic/full --template github/readonly -- claude

# In another terminal, open the TUI to watch live
cs
```

You'll see every API call in real time. Known endpoints (from your templates) flow through automatically. Unknown ones pause and ask you — the proxy holds the connection until you decide, so the agent doesn't retry or error out.

### YOLO mode — log everything, block nothing

If you just want to see what your agent does without blocking anything:

```bash
cs --yolo -- claude
```

This is useful for building trust, auditing traffic, or generating a template from real usage (more on that below).

### Works with any agent

ClosedShell sandboxes any process — it's not tied to a specific AI tool. Claude Code, Cursor, Aider, Codex, or a custom script that calls APIs. If it makes HTTPS requests, ClosedShell can intercept and control them.

```bash
cs --template openai/full -- codex
cs --template github/full -- aider --model gpt-4
cs --template anthropic/full -- python my_agent.py
```

---

## How It Actually Works

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

1. **Sandbox.** Your agent runs inside a macOS Seatbelt sandbox. All outbound network is blocked except `localhost:8443`. Files, shell, and local tools work normally.

2. **Proxy.** Every HTTPS request goes through ClosedShell's MITM proxy on localhost. The proxy terminates TLS (using a locally-generated CA), reads the request, and figures out what the agent is trying to do.

3. **Parse.** The request is converted into a semantic action. `POST s3.amazonaws.com/?delete` becomes `aws:s3:DeleteBucket`. Built-in parsers understand AWS, GCP, Azure, Kubernetes, and GitHub natively. Unknown hosts fall back to `net:METHOD:host/path`.

4. **Decide.** The action is checked against your permission policy. The policy is Cedar-inspired: **forbid overrides permit, default deny.** If a template or prior approval matches, the request flows through. If a forbid rule matches, it's blocked. If nothing matches, the proxy holds the connection and the TUI asks you.

5. **Persist.** Every decision is logged. Permissions you grant are saved to SQLite and carry over when you resume work in the same directory. One-shot approvals are consumed after use.

---

## Templates

Instead of approving every single API call, templates pre-approve the endpoints your agent obviously needs to function. Without `--template anthropic/full`, even Claude Code's own API calls would require manual approval.

### Built-in templates

These ship compiled into the binary — no setup needed.

| Template | What it permits |
|----------|----------------|
| `anthropic/full` | `api.anthropic.com`, `mcp-proxy.anthropic.com`, `downloads.claude.ai`, Claude Code storage |
| `openai/full` | `api.openai.com` (all endpoints — GPT, Codex CLI, assistants, files) |
| `github/full` | `api.github.com`, `github.com`, `uploads.github.com` |
| `github/readonly` | `api.github.com` and `github.com` (GET only) |
| `exa/full` | `api.exa.ai` (all endpoints) |
| `exa/readonly` | `api.exa.ai` (read-only) |
| `exa/search-only` | `api.exa.ai` (search only) |

### Template format

Templates use a Cedar-inspired `.csp` (ClosedShell Policy) format:

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

`forbid` always wins over `permit`. This means you can broadly allow a service and then carve out specific dangerous operations.

### Create your own templates

The easiest way: run your agent in YOLO mode, then generate a template from the traffic you observed.

```bash
# 1. Run in YOLO mode to capture real traffic
cs --yolo -- claude

# 2. Generate a template from what you saw
cs template generate <session-id> --name myservice-full --save

# 3. Review it
cs template show myservice/full

# 4. Use it
cs --template myservice/full -- claude
```

Or scaffold one manually:

```bash
cs template init myservice
# → creates ~/.closedshell/templates/myservice/full.csp
```

### Template resolution

When you pass `--template myservice/full`, ClosedShell looks in order:

1. Exact file path (absolute or relative)
2. `~/.closedshell/templates/myservice/full.csp` (your custom templates)
3. Built-in templates (compiled into the binary)

User templates override built-in ones with the same name.

### Template management

```
cs template list                         Show all templates (built-in and user)
cs template show <name>                  Display resolved template content
cs template validate <name>              Validate and show rule summary
cs template check <name> <action>        Test if an action would be permitted/forbidden
cs template init <provider>              Scaffold a new template
cs template generate <session-id>        Generate from a YOLO session's audit log
```

See [templates/CONTRIBUTING.md](templates/CONTRIBUTING.md) for the full format reference.

---

## The TUI

### Hub — browse sessions and templates

```bash
cs
```

Running `cs` with no arguments opens the hub — a unified view of all your sessions and available templates. Switch between tabs with `Tab`.

- **Sessions tab**: browse past and running sessions with status, workdir, templates used, and decision counts. Press `Enter` to open a session's live monitor.
- **Templates tab**: browse all available templates (built-in and user). Press `Enter` to view the full policy.

### Session monitor — watch a live session

```bash
cs --tui <session-id>
```

Three tabs for the active session:

- **Live**: real-time activity feed — every API call, color-coded by result (allow/deny/pending), filterable with `f`, searchable with `/`
- **Policy**: loaded permission rules from templates and human approvals
- **Approvals**: pending requests waiting for your decision (`y` approve, `n` deny)

Press `?` for a help overlay with all keybindings.

---

## Why Network, Not Files?

**File access** is a solved problem. Claude Code asks before reading and writing files. Cursor has its own permission model. Every major coding agent has some form of local file sandboxing.

**Network calls** are the blind spot. When your agent runs `kubectl delete deployment`, `terraform destroy`, or an MCP tool calls a random API — nothing checks. No agent has a permission model for outbound network traffic. Your credentials flow freely to whatever endpoint the agent decides to hit.

ClosedShell fills this gap. It's templatized network permissions for the tools developers actually use — AWS, GCP, Kubernetes, GitHub, Terraform, and anything else that makes HTTPS calls. It's the missing layer, not a replacement for file-level sandboxing.

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

## CLI Reference

```
closedshell [OPTIONS] [COMMAND]...

Options:
  --template <TEMPLATE>  Permission template to load (repeatable)
  --yolo                 Log-only mode — no blocking
  --resume               Resume rules from previous session in this directory
  --pf                   Enable pf (packet filter) as secondary enforcement (requires root)
  --pf-setup             One-time system setup for pf enforcement
  --tui <SESSION_ID>     Open the TUI monitor for an existing session
```

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
