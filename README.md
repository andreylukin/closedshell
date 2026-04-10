# ClosedShell

**Control the network. Let the agent roam free.**

A macOS sandbox for AI coding agents. Instead of restricting what tools an agent can use, ClosedShell controls what leaves your machine — every outbound HTTPS request is intercepted, parsed, and checked before it hits the wire.

The agent gets full access to your local tools, files, and shell. The network is the leash.

No root. No kernel extensions. Two static Rust binaries.

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
5. Unknown actions consult an LLM judge — the proxy holds the request while the judge decides (no agent retries)
6. Decisions are persisted to SQLite; a TUI shows live session activity

---

## Quick Start

```bash
make install    # builds and installs closedshell + ask to ~/.cargo/bin
```

### YOLO mode — log everything, block nothing

```bash
cs --yolo -- claude
```

### Enforcing mode — judge evaluates unknown actions against a task description

```bash
cs --template anthropic/full --task "refactor the auth module" -- claude
```

Templates pre-approve infrastructure the agent needs to function. Without `--template anthropic/full`, Claude Code's own API calls would get blocked by the judge.

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
  --task <TASK>          Session task description for the judge
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
  implicit_ask: true
  yolo: false
  passthrough_env:
    - OPENAI_API_KEY
    - GITHUB_TOKEN
    - AWS_ACCESS_KEY_ID
    - AWS_SECRET_ACCESS_KEY

judge:
  api_base: "http://localhost:11434/v1"
  model: "qwen3:8b"
  timeout_ms: 5000
```

---

## Building from Source

```bash
make build      # dev build
make release    # optimized release build
make test       # all tests
make check      # fmt + lint + test (what CI runs)
```

---

## Architecture

```
crates/
  closedshell-lib/   # shared library (config, parsers, proxy, audit, tls, sandbox)
  closedshell/       # host binary (CLI + daemon + TUI)
  ask/               # in-sandbox binary
templates/           # bundled permission templates
docs/                # design docs
```

| Doc | Description |
|-----|-------------|
| [architecture.md](docs/architecture.md) | Seatbelt sandbox + proxy design |
| [permission-tree.md](docs/permission-tree.md) | Permission model and evaluation |
| [judge.md](docs/judge.md) | LLM judge config and protocol |
| [proxy.md](docs/proxy.md) | HTTPS proxy and provider parsers |
| [development.md](docs/development.md) | Build sections and dependency graph |
| [agent-instructions.md](docs/agent-instructions.md) | Agent instruction injection |
