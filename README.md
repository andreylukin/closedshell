# ClosedShell

**Control the network. Let the agent roam free.**

ClosedShell is a lightweight macOS sandbox for AI coding agents. Instead of restricting what tools an agent can use, it controls what leaves your machine — every outbound HTTPS request is intercepted, parsed, and checked before it hits the wire.

The agent gets full access to your local tools, files, and shell. The network is the leash.

---

## How It Works

A sandboxed shell where all outbound traffic routes through a host-side MITM proxy:

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

1. `closedshell run <cmd>` launches a sandboxed shell
2. Seatbelt blocks all outbound network except `localhost:8443`
3. Env-var proxy forces HTTPS through the host-side MITM proxy
4. Proxy terminates TLS, parses API calls into canonical actions (e.g. `aws:s3:ListBuckets`)
5. Actions are checked against a permission tree — default deny
6. Unknown actions consult a judge (any OpenAI-compatible LLM)

No root. No kernel extensions. Two static Rust binaries.

---

## Threat Model

**What we stop:** An agent nuking your production fleet, deleting S3 buckets, pushing bad deploys — remote damage at scale.

**What we don't care about:** Local file writes, CPU/memory abuse, reading files on your machine. Annoying, but recoverable. The network is where the catastrophic mistakes happen.

---

## Project Status

Currently building the **YOLO Shell** — the log-only foundation: intercept all HTTPS, parse into actions, log everything, block nothing.

### Roadmap

1. **YOLO Shell** (current) — sandbox + proxy + parsers + audit logging
2. Permission Tree — Cedar-inspired forbid-overrides-permit
3. Judge Integration — LLM-based decision engine
4. TUI + Human Approval

---

## Quick Start

```bash
cargo build
cargo test
cargo clippy -- -D warnings
```

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

## Docs

| Doc | Description |
|-----|-------------|
| [architecture.md](docs/architecture.md) | Seatbelt sandbox + proxy design |
| [permission-tree.md](docs/permission-tree.md) | Permission model and evaluation |
| [judge.md](docs/judge.md) | LLM judge config and protocol |
| [proxy.md](docs/proxy.md) | HTTPS proxy and provider parsers |
| [development.md](docs/development.md) | Build sections and dependency graph |
