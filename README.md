# ClosedShell

A lightweight sandbox that lets AI agents discover their own permissions through a CLI, with context-aware, consumable permission tokens enforced at the network and syscall layer.

**No Kubernetes. No cluster. Single binary daemon + single binary CLI.**

---

## How It Works

```
┌─────────────────────────────────────────────┐
│  Sandboxed Shell                            │
│                                             │
│  Agent ←→ `ask` CLI ←→ Unix Socket          │
│                                             │
│  All network traffic intercepted            │
└──────────────┬──────────────────────────────┘
               │
┌──────────────┴──────────────────────────────┐
│  closedshell-daemon (host-side)             │
│                                             │
│  Permission   Judge      HTTPS              │
│  Tree         (LLM)      Proxy              │
│                                             │
│  Credential   Human                         │
│  Vault        Approval                      │
└─────────────────────────────────────────────┘
```

1. Agent runs inside a sandboxed shell (`closedshell create -- claude-code`)
2. All outbound HTTPS is intercepted by a MITM proxy
3. Proxy parses API calls into canonical actions (`aws[profile=dev]:s3:ListBuckets`)
4. Actions are checked against a **permission tree** — forbid-overrides-permit, default deny
5. Unknown actions trigger an **implicit ask** to a judge (any OpenAI-compatible LLM)
6. Judge approves safe actions instantly; dangerous actions escalate to a human
7. Agent never sees the machinery — it just gets responses (or denials with hints)

---

## Core Concepts

### Permission Tree

Cedar-inspired evaluation: **forbid-overrides-permit, default deny, order-independent.** Rules are `permit` or `forbid`. Three permit types: `idempotent`, `one-shot`, `state-dependent`. Glob pattern matching with credential qualifiers (`aws[profile=prod]:ecs:UpdateService`).

### Judge

Single LLM behind any OpenAI-compatible endpoint. BYO model — ollama locally, remote API, litellm proxy. Structured JSON I/O only (no raw agent output). Timeout = deny. Always fail closed.

### `ask` CLI

In-sandbox CLI for agents to discover and request permissions:

```
ask allow <action>            # request single permission
ask plan "<description>"      # batch approval via judge
ask status                    # show current permissions
ask what-can-i "<pattern>"    # query without requesting
```

Most agents don't need `ask` — the proxy handles it automatically via implicit ask.

### Sandbox

Platform-specific isolation (Linux: namespaces + seccomp-bpf, macOS: Seatbelt), unified by the MITM proxy as the enforcement boundary. Credentials mounted in but can't bypass the proxy.

---

## Tech Stack

| Component | Language |
|-----------|----------|
| Daemon + proxy | Rust |
| `ask` CLI | Rust |
| Judge integration | OpenAI-compatible API client (Rust) |
| Provider parsers | Rust (pluggable trait) |

Ships as two static binaries: `closedshell` (host) and `ask` (sandbox).

---

## What This Is Not

- Not a container orchestrator. One sandbox, one agent, one host.
- Not a policy authoring tool. Policies emerge from agent interaction.
- Not cloud-hosted. Runs entirely on your machine.
- Not agent-specific. Any process that can run in a shell works.
- Not married to any model provider. BYO model, BYO inference stack.

---

## Docs

| Doc | What's in it |
|-----|-------------|
| [docs/architecture.md](docs/architecture.md) | Platform sandbox design (macOS Seatbelt + proxy, Linux namespaces) |
| [docs/permission-tree.md](docs/permission-tree.md) | Cedar-inspired permission model, evaluation algorithm, action format, schema |
| [docs/judge.md](docs/judge.md) | Judge config, structured I/O, decision matrix |
| [docs/proxy.md](docs/proxy.md) | HTTPS proxy, provider parsers, credential qualifier format, credential mounts |
| [docs/execution-flows.md](docs/execution-flows.md) | Cold start, implicit ask, plan approval, denial UX, security boundaries |
| [docs/development.md](docs/development.md) | Build sections, dependency graph, recommended build order |

---

## Configuration

```yaml
# closedshell.yaml
sandbox:
  motd: true
  implicit_ask: true
  credentials:
    - type: file
      source: ~/.aws/credentials
      mount: ~/.aws/credentials
      readonly: true
    - type: env
      vars: [OPENAI_API_KEY, GITHUB_TOKEN]

judge:
  api_base: "http://localhost:11434/v1"
  model: "qwen3:8b"
  api_key: ""
  timeout_ms: 5000
  temperature: 0.0

approval:
  auto_approve_timeout:
    moderate: "30s"
    dangerous: null   # never auto-approve
  webhook_url: ""
```

Full config reference in the individual docs above.

---

## Open Questions

1. **Judge training data.** Bootstrap from IAM taxonomy + synthetic sessions, then learn from real usage?
2. **Multi-agent.** Shared permission tree or separate sandboxes with cross-sandbox communication?
3. **Escape hatch.** "YOLO mode" that logs everything but blocks nothing for dev environments?
4. **Plan branching.** "If X then Y else Z" — how does the judge approve conditional plans?
5. **Permission templates.** Pre-built starter sets per workflow type (k8s-debug, aws-deploy, etc.)?
6. **Implicit ask rate limiting.** Circuit breaker that falls back to explicit `ask` only after too many judge calls.
7. **Precondition composition.** Should `when` conditions support AND/OR logic, or keep it flat (all must pass)?
8. **Judge prompt versioning.** System prompt changes alter security behavior. Need versioning + audit trail.
9. **Moderate approval escalation threshold.** Auto-escalate to human after N moderate approvals in a time window.
