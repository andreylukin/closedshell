# ClosedShell

[![CI](https://github.com/andreylukin/closedshell/actions/workflows/ci.yml/badge.svg)](https://github.com/andreylukin/closedshell/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)

**Your AI agent has your AWS keys, your GitHub token, and access to every API on your machine. ClosedShell makes sure it only calls the ones you said it could.**

> **macOS only.** Uses macOS Seatbelt for sandboxing. Linux contributions welcome.

---

## The Problem

AI coding agents already ask before reading and writing your files. That part's handled.

But they also run `kubectl`, `terraform`, `aws`, `curl` — and call MCP tools that hit arbitrary APIs. **Nobody's checking those.**

Your agent inherits every credential on your machine. One bad tool call and you're looking at:

- `kubectl delete deployment production`
- `aws s3 rm s3://prod-backups --recursive`
- An MCP skill calling an API you've never heard of, using your credentials
- A retry loop burning hundreds of dollars in API costs overnight

This isn't hypothetical. A [Replit agent deleted a production database](https://www.reddit.com/r/replit/comments/1l3nnez/replit_agent_deleted_my_entire_database/) after ignoring explicit instructions 11 times. [Amazon Q was compromised](https://www.theregister.com/2025/06/16/amazon_q_developer_attack/) via a poisoned PR that instructed it to terminate EC2 instances and empty S3 buckets.

**Agents have file permissions. They have zero network permissions.** ClosedShell fills that gap.

---

## What It Does

Every outbound HTTPS request from your agent is intercepted before it leaves your machine, parsed into a human-readable action, and checked against your policy:

```
aws:s3:DeleteBucket          → DENY (forbid rule)
net:GET:api.anthropic.com/*  → ALLOW (template)
net:POST:api.unknown.com/v1  → BLOCK (asks you in the TUI)
```

You define what's allowed using simple [templates](templates/CONTRIBUTING.md). Everything else blocks and asks you in a live terminal UI. The agent keeps full local access — files, shell, tools. The network is the leash.

One binary. No root. No kernel extensions.

---

## Quick Start

```bash
brew install andreylukin/tap/closedshell

# Run Claude Code with pre-approved Anthropic + GitHub access
cs --template anthropic/full --template github/readonly -- claude

# In another terminal, watch live
cs
```

Known endpoints flow through. Unknown ones pause and ask you — the proxy holds the connection until you decide.

### YOLO mode — just watch

```bash
cs --yolo -- claude
```

Logs everything, blocks nothing. Useful for auditing traffic or [generating a template](templates/CONTRIBUTING.md#observe-then-codify-workflow) from real usage.

### Works with any agent

```bash
cs --template openai/full -- codex
cs --template github/full -- aider --model gpt-4
cs --template anthropic/full -- python my_agent.py
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

1. **Sandbox.** Seatbelt blocks all outbound network except `localhost:8443`. Files and local tools work normally.
2. **Proxy.** MITM proxy terminates TLS, reads the request, figures out what the agent is doing.
3. **Parse.** Requests become semantic actions — `POST s3.amazonaws.com/?delete` → `aws:s3:DeleteBucket`. Built-in parsers for AWS, GCP, Azure, K8s, GitHub. Unknown hosts → `net:METHOD:host/path`.
4. **Decide.** Cedar-inspired policy: **forbid > permit > ask human.** The proxy holds unknown requests while the TUI asks you.
5. **Persist.** Decisions logged, permissions saved to SQLite, rules carry over between sessions.

Deep dive: [architecture.md](docs/architecture.md) | [proxy.md](docs/proxy.md) | [permission-tree.md](docs/permission-tree.md)

---

## Templates

Templates pre-approve endpoints your agent needs. Without `--template anthropic/full`, even Claude Code's own API calls require manual approval.

### Built-in

| Template | What it permits |
|----------|----------------|
| `anthropic/full` | `api.anthropic.com`, `mcp-proxy.anthropic.com`, `downloads.claude.ai`, Claude Code storage |
| `openai/full` | `api.openai.com` (all endpoints) |
| `github/full` | `api.github.com`, `github.com`, `uploads.github.com` |
| `github/readonly` | GitHub (GET only) |
| `exa/full` | `api.exa.ai` (all endpoints) |
| `exa/readonly` | `api.exa.ai` (read-only) |
| `exa/search-only` | `api.exa.ai` (search only) |

### Create your own

Run in YOLO mode, then generate a template from observed traffic:

```bash
cs --yolo -- claude
cs template generate <session-id> --name myservice-full --save
cs template show myservice/full
```

Templates use a Cedar-inspired `.csp` format — `forbid` always overrides `permit`:

```
@name("myservice-full")
permit (action == "net:*:api.myservice.com/*");
forbid (action == "net:*:api.myservice.com/admin/*");
```

Full format reference: [templates/CONTRIBUTING.md](templates/CONTRIBUTING.md)

---

## Install

**Homebrew:**
```bash
brew install andreylukin/tap/closedshell
```

**Pre-built binaries:** [GitHub Releases](https://github.com/andreylukin/closedshell/releases) (Apple Silicon + Intel)

**From source:**
```bash
git clone https://github.com/andreylukin/closedshell.git
cd closedshell && make install
```

---

## Reference

```
cs [OPTIONS] [COMMAND]...

  --template <TEMPLATE>  Permission template (repeatable)
  --yolo                 Log-only mode
  --resume               Resume previous session rules
  --pf                   Enable pf secondary enforcement (requires root)
  --tui <SESSION_ID>     Open TUI for existing session

cs template list|show|validate|check|init|generate
```

Config: `./closedshell.yaml` or `~/.closedshell/config.yaml`

| Doc | |
|-----|-|
| [architecture.md](docs/architecture.md) | Seatbelt sandbox + proxy design |
| [permission-tree.md](docs/permission-tree.md) | Permission model and evaluation |
| [proxy.md](docs/proxy.md) | HTTPS proxy and provider parsers |
| [development.md](docs/development.md) | Building and testing |
