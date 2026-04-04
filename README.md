# ClosedShell — Engineering Spec v0.2

**One-liner:** A lightweight sandbox that lets AI agents discover their own permissions through a CLI, with context-aware, consumable permission tokens enforced at the network and syscall layer.

> **Implementation target: macOS (Apple Silicon) via Seatbelt + MITM Proxy.**
> See [docs/architecture.md](docs/architecture.md) for the full architecture decision and interception model.

---

## Architecture

```
┌─────────────────────────────────────────────┐
│  Sandboxed Shell (namespaced, seccomp'd)    │
│                                             │
│  Agent ←→ `ask` CLI ←→ Unix Socket          │
│             ↕                               │
│  All exec() and connect() intercepted       │
└──────────────┬──────────────────────────────┘
               │ seccomp-notify + proxy
┌──────────────┴──────────────────────────────┐
│  closedshell-daemon (host-side)             │
│                                             │
│  ┌────────────┐ ┌──────────┐ ┌───────────┐ │
│  │ Permission  │ │ Judge    │ │ HTTPS     │ │
│  │ Tree        │ │ (model-  │ │ Proxy     │ │
│  │             │ │ agnostic)│ │           │ │
│  └────────────┘ └──────────┘ └───────────┘ │
│  ┌────────────┐ ┌──────────┐               │
│  │ Credential  │ │ Human    │               │
│  │ Vault       │ │ Approval │               │
│  └────────────┘ └──────────┘               │
└─────────────────────────────────────────────┘
```

**No Kubernetes. No cluster. Single binary daemon + single binary CLI.**

---

## Core Components

### 1. Sandboxed Shell

- Linux namespaces (net, pid, mount, user) for isolation
- seccomp-bpf with `SECCOMP_RET_USER_NOTIF` on `execve`, `connect`, `sendto`
- Transparent HTTPS proxy via iptables redirect in network namespace
- Agent enters via: `closedshell create -- <agent command>`

### 2. `ask` CLI (in-sandbox)

Communicates with daemon over a Unix socket mounted read-only into the sandbox.

```
ask allow <action>            # request single permission (pre-flight)
ask plan "<description>"      # batch approval via judge
ask status                    # show permission tree
ask why-denied                # explain last denial
ask revoke <id>               # voluntarily drop permission
ask context <key> <value>     # declare intent/state
ask what-can-i "<pattern>"    # query tree without requesting (discovery)
```

> **Design note:** The `ask` CLI is for pre-flight and planning. Most agents don't need to use it for simple actions — the proxy handles permission requests automatically via **implicit ask** (see §Execution Flows).

### 3. Permission Tree

```yaml
session: "8f3a-29c1"
trust_level: base
permissions:
  - id: "p-001"
    action: "aws[profile=dev]:ec2:Describe*"
    type: idempotent          # idempotent | one-shot | state-dependent
    approved_by: judge
    created: "2026-04-03T14:00:00Z"

  - id: "p-002"
    action: "aws[profile=prod]:ecs:UpdateService"
    type: one-shot
    approved_by: human:@oncall
    preconditions:
      - cmd: "aws ecs describe-services --service api --profile prod"
        jsonpath: ".services[0].runningCount"
        expect: ">= 2"
        max_staleness: "30s"  # cached result valid for 30s
    plan_id: "plan-007"
    consumed: false
    expires: "2026-04-03T16:00:00Z"

  - id: "p-003"
    action: "net:GET:api.github.com/repos/.*"
    type: idempotent
    approved_by: judge
```

#### Permission Types

| Type | Behavior | Revocation |
|------|----------|------------|
| `idempotent` | Persistent for session. Regex match, pass through. | Session end or explicit revoke. |
| `one-shot` | Consumed on use. Removed from tree after execution. | Auto after single use. |
| `state-dependent` | Preconditions verified at point-of-use. Cached results honored within `max_staleness`. | Auto when preconditions fail. |

All permissions are **session-scoped by default.** Promotion to org baseline requires explicit human action outside the session.

#### Precondition Verification Strategy

Preconditions follow a **Design by Contract** model: the proxy is the enforcement boundary, not a background timer.

**Point-of-use verification (primary enforcement):**
- When the proxy matches a `state-dependent` permission, it runs precondition checks *before* forwarding the request.
- Results are cached with a configurable `max_staleness` per precondition (default: 30s).
- If a cached result exists within staleness window, skip re-check. Otherwise, re-run.
- If precondition fails at point-of-use: DENY, auto-revoke permission, log with reason.

**Background sweep (cleanup only):**
- Runs every 60s (configurable). Iterates state-dependent permissions.
- Re-validates preconditions and revokes stale grants proactively.
- Purpose: garbage collection of permissions the agent hasn't tried to use yet but whose preconditions have drifted.
- **Not the enforcement boundary.** If the sweep hasn't run yet, point-of-use still catches it.

**Precondition execution:**
- Precondition commands run on the *host side* with the credential vault, not inside the sandbox.
- Precondition commands have a hard timeout (default: 5s). Timeout = precondition failure.
- Precondition results are structured (jsonpath + expect). No shell interpolation, no agent-controlled input.

### 4. Judge (model-agnostic, host-side)

The judge is a single LLM behind any **OpenAI-compatible API endpoint**. One model. No fallbacks. No routing tiers.

#### Configuration

```yaml
judge:
  # Point at any OpenAI-compatible endpoint.
  # Local: ollama, llama.cpp, vllm, localai
  # Remote: openai, anthropic (via litellm), groq, together, etc.
  # Proxy: litellm proxy for provider abstraction
  api_base: "http://localhost:11434/v1"   # e.g. ollama
  model: "qwen3:8b"                       # whatever you're running
  api_key: ""                              # optional, depends on provider

  # Inference constraints
  max_tokens: 512
  timeout_ms: 5000          # hard timeout — if judge doesn't respond, deny
  temperature: 0.0          # deterministic for reproducibility

  # Structured I/O
  system_prompt_path: "/etc/closedshell/judge-system.txt"
  response_format: "json"   # enforce JSON output via provider support or parsing
```

**Why one model, no fallbacks:** Fallback chains make the security boundary non-deterministic. If model A denies an action and model B would approve it, which is correct? A single model means a single policy surface. If the model is down, the answer is deny — not "try something else."

**Why OpenAI-compatible:** It's the de facto standard. Every local inference server (ollama, vllm, llama.cpp, localai) and every proxy (litellm, portkey) speaks it. Zero coupling to any specific provider or runtime.

#### Judge Input (structured)

```json
{
  "requested_action": "aws[profile=prod]:ecs:UpdateService",
  "current_tree": ["aws[profile=prod]:ecs:Describe*", "aws[profile=prod]:ecs:List*"],
  "session_context": {"task": "investigate 503s in us-east-1"},
  "provider_risk_tier": "moderate",
  "action_taxonomy": "state-change",
  "implicit": true
}
```

The `implicit` field indicates whether this came from an explicit `ask allow` or from an implicit ask via the proxy. The judge may use this signal (e.g., require `ask plan` for dangerous actions even if the agent just tried to run them).

#### Judge Output (structured)

```json
{
  "decision": "escalate_human",
  "risk_level": "moderate",
  "reasoning": "UpdateService is a state change on production ECS",
  "proposed_expansion": ["aws:ecs:UpdateService (one-shot, preconditioned)"],
  "suggested_preconditions": [
    {"cmd": "aws ecs describe-services ...", "expect": "runningCount >= 2", "max_staleness": "30s"}
  ]
}
```

**Judge never sees raw agent output.** Only structured permission requests. Prevents prompt injection from agent.

#### Decision Matrix

| Action Risk | Judge Decision | Behavior |
|---|---|---|
| safe (read) | `approve` | Grant immediately. |
| moderate (write) | `approve` or `escalate_human` | Judge decides based on context + tree. |
| dangerous (delete/terminate) | `escalate_human` | Always routed to human. Judge can't override. |
| context mismatch | `deny_with_hint` | Action doesn't match declared session context. Agent told to `ask context` to update and retry. |
| judge timeout/error | `deny` | Fail closed. Always. |
| already granted | *(skip judge)* | Fast path: tree regex match, forward immediately (~1ms). |

**Latency expectations:** With a local 3-8B model on decent hardware, safe actions resolve in <100ms. Moderate actions in <500ms. These are guidelines, not guarantees — depends entirely on your model and hardware. The hard timeout (`timeout_ms`) is the real contract.

### 5. HTTPS Proxy (host-side)

Transparent MITM proxy. Session-scoped CA cert injected into sandbox at creation.

**Responsibilities:**
- Intercept all outbound HTTPS from sandbox
- Parse cloud provider API calls into structured actions
- Check action against permission tree (fast path: ~1ms regex match for idempotent permissions)
- **For state-dependent permissions:** run point-of-use precondition verification before forwarding
- **For unknown actions:** submit implicit ask to judge (see §Implicit Ask)
- Inject credentials from vault into approved requests
- Log all allow/deny decisions with full request metadata
- Support WebSocket/streaming (no hardcoded timeouts)

#### Provider Parsers

| Provider | Wire Format | Canonical Action |
|----------|-------------|------------------|
| AWS | `POST / Action=TerminateInstances` | `aws[profile=default]:ec2:TerminateInstances` |
| GCP | `DELETE .../instances/{id}` | `gcp[project=myproj]:compute.instances.delete` |
| Azure | `DELETE .../Microsoft.Compute/...` | `az[sub=abc123]:Microsoft.Compute/delete` |
| GitHub | `POST /repos/x/pulls` | `gh[token=GITHUB_TOKEN]:repos/*/pulls:POST` |
| K8s | `PATCH /apis/apps/v1/deployments` | `k8s[ctx=prod]:apps/v1/deployments:PATCH` |
| Generic | `GET https://host/path` | `net:GET:host/path` |

Parsers are pluggable. Unknown APIs fall back to `net:<METHOD>:<host>/<path>`.

**Credential qualifier format:** `provider[key=value]:action`. The qualifier is derived from which credential mount the request uses (AWS profile name, GCP project, K8s context, etc.). This makes the permission tree credential-aware — `aws[profile=dev]:s3:GetObject` and `aws[profile=prod]:s3:GetObject` are distinct actions with distinct permissions. Generic `net:` actions have no qualifier.

#### Baked-in Risk Taxonomy

```yaml
aws:
  safe:      [List*, Describe*, Get*, Head*]
  moderate:  [Create*, Put*, Update*, Start*, Stop*, Tag*]
  dangerous: [Delete*, Terminate*, Remove*, Revoke*, Detach*]
```

Sourced from public IAM/RBAC docs. Embedded in binary. Updatable via config override.

### 6. Credential Mounts

Credentials are mounted directly into the sandbox. The agent can read them, but **cannot use them to bypass the proxy** — seccomp-bpf + iptables force all network traffic through the proxy regardless. The sandbox boundary is the enforcement layer, not credential hiding.

#### Configuration

```yaml
sandbox:
  credentials:
    - type: file
      source: ~/.aws/credentials
      mount: ~/.aws/credentials
      readonly: true

    - type: env
      vars: [OPENAI_API_KEY, GITHUB_TOKEN]

    - type: socket
      source: $SSH_AUTH_SOCK
      mount: /tmp/ssh-agent.sock

    - type: oauth
      provider: gcp
      token_path: ~/.config/gcloud/
      refresh_interval: 45m    # daemon refreshes on host, remounts
```

#### Mount Types

| Type | Example | Behavior |
|------|---------|----------|
| `file` | `~/.aws/credentials`, `~/.kube/config` | Read-only bind mount into sandbox |
| `env` | `OPENAI_API_KEY`, `GITHUB_TOKEN` | Passed as environment variables at sandbox creation |
| `socket` | `SSH_AUTH_SOCK`, Docker socket | Socket mounted into sandbox |
| `oauth` | GCP, Azure AD | Daemon refreshes tokens on host side on `refresh_interval`, remounts into sandbox. Agent always sees a valid token. |

#### Security Model

- Agent tools work naturally — `aws`, `gcloud`, `kubectl` find credentials where they expect them.
- All network traffic still goes through the proxy, which enforces the permission tree.
- Even if the agent reads raw credentials, it cannot make network calls that bypass the proxy.
- OAuth tokens that expire mid-session are refreshed by the daemon on the host side — the agent doesn't know or care.

### 7. Human Approval Interface

- Host CLI: `closedshell approvals` shows pending requests
- Webhook support: Slack / PagerDuty / custom endpoint
- Configurable auto-approve timeout per risk tier (default: 30s moderate, never dangerous)
- Approvals show plan context so humans see intent, not just raw action

---

## Execution Flows

### Cold Start
```
closedshell create -- claude-code
  1. Create namespaces (net, pid, mount, user)
  2. Set up seccomp-bpf with notify on execve/connect
  3. Start transparent proxy, inject CA cert
  4. Mount ask CLI + Unix socket (read-only)
  5. Display MOTD with ask CLI usage
  6. Exec agent command
```

### Implicit Ask (primary path)

This is the default flow. The agent just runs commands. No `ask` needed for the happy path.

```
Agent: aws s3 ls
  1. seccomp-notify fires on execve("aws") → allowed (binary ok)
  2. aws CLI → HTTPS request to s3.amazonaws.com
  3. Proxy parses: aws[profile=dev]:s3:ListBuckets
  4. Tree check: not found
  5. Proxy submits implicit ask to judge:
     {action: "aws[profile=dev]:s3:ListBuckets", implicit: true, risk: "safe", ...}
  6. Judge: approve, expand to aws[profile=dev]:s3:List*
  7. Permission added to tree
  8. Proxy forwards original request (no retry needed)
  9. Agent gets response as if nothing happened
  Total: < 200ms (agent never sees a denial)
```

**Key insight:** The proxy holds the outbound request while the judge evaluates. The agent doesn't need to retry. For safe actions, this adds ~100ms of latency on first access — invisible to most agents.

**When implicit ask is not enough:**
- Judge returns `escalate_human` → proxy returns denial with hint to use `ask plan`
- Judge returns `deny` → proxy returns denial with reason
- Agent wants to pre-approve a batch of actions → use `ask plan`

### Explicit Pre-flight (ask allow)
```
Agent: ask allow "aws[profile=dev]:ec2:DescribeInstances"
  1. ask CLI → Unix socket → daemon
  2. Daemon checks tree → not found
  3. Daemon queries taxonomy → safe (read-only)
  4. Daemon → judge: {action, tree, context, risk, implicit: false}
  5. Judge: approve, expand to aws[profile=dev]:ec2:Describe*
  6. Added to tree → ✓ returned to CLI
  Total: < 200ms
```

Still useful for: agents that want to check before committing to a code path, or to get expanded wildcards upfront.

### Plan Approval (ask plan)
```
Agent: ask plan "Rollback bad ECS deployment"
  1. Judge analyzes plan → proposes permission set
  2. Read-only actions: auto-approved immediately
  3. State-change/destructive: routed to human
  4. Human approves via CLI/Slack
  5. Full set added to tree (one-shots + preconditions)
  6. Agent executes at full speed against pre-approved tree
```

### State-Dependent Execution (point-of-use)
```
Agent: aws ecs update-service --service api --desired-count 4
  1. Proxy parses: aws[profile=prod]:ecs:UpdateService
  2. Tree match: p-002 aws[profile=prod]:ecs:UpdateService (state-dependent, one-shot)
  3. Precondition check:
     a. Cached result for "runningCount >= 2"?
        - If within max_staleness (30s): use cached → PASS
        - If stale or missing: re-run on host side
     b. Run: aws ecs describe-services --service api (timeout: 5s)
     c. Extract .services[0].runningCount via jsonpath
     d. Evaluate: >= 2 → PASS (or FAIL → deny + revoke)
  4. Precondition passed → forward request with injected credentials
  5. Mark p-002 as consumed (one-shot)
  Total: ~50ms (cached) to ~2s (fresh check)
```

### Capability Discovery (ask what-can-i)
```
Agent: ask what-can-i "aws[profile=dev]:s3:*"
  1. Returns current tree entries matching pattern
  2. No permission request submitted
  3. Shows: aws[profile=dev]:s3:List* (idempotent, active)
           aws[profile=dev]:s3:GetObject (idempotent, active)
  4. Agent knows what it has without round-trips
```

### Background Sweep
```
Every 60s (configurable):
  1. Iterate state-dependent permissions
  2. Re-run precondition checks (host-side)
  3. Auto-revoke where preconditions fail
  4. Log revocation with reason
  Purpose: cleanup only. Not the enforcement boundary.
```

---

## Denial UX

### Implicit ask denied (agent just tried to do something)
```
DENIED: aws:ec2:TerminateInstances (i-abc123)

  Risk tier: dangerous (destructive)
  Judge decision: escalate_human

  This action requires human approval.
  Run:  ask plan "describe your goal"
```

### Precondition failure at point-of-use
```
DENIED: aws:ecs:UpdateService (permission p-002 revoked)

  Precondition failed: runningCount >= 2
  Actual value: 1
  Permission auto-revoked.

  To re-request:  ask allow "aws:ecs:UpdateService"
```

---

## Security Boundaries

| Layer | Mechanism | Bypass Resistance |
|-------|-----------|-------------------|
| Process isolation | Linux namespaces (user, pid, net, mount) | Kernel-level |
| Syscall filtering | seccomp-bpf with notify | Kernel-level |
| Network egress | iptables redirect → proxy | No network without proxy |
| API enforcement | L7 proxy parsing + permission tree | Catches all HTTP |
| Precondition enforcement | Point-of-use verification in proxy | No stale-grant window |
| Credential isolation | Vault on host, injected by proxy | Never on sandbox filesystem |
| Judge isolation | Structured input only, single model | Agent can't prompt-inject judge |
| Judge failure mode | Timeout/error = deny | Fail closed, always |

---

## Tech Stack

| Component | Language | Rationale |
|-----------|----------|-----------|
| Daemon + proxy | Rust | seccomp-notify, async proxy, single binary |
| `ask` CLI | Rust | Static binary, no runtime deps |
| Judge integration | OpenAI-compatible API client (Rust) | Any provider, any model, zero coupling |
| Provider parsers | Rust | Pluggable trait, ships with AWS/GCP/Azure/K8s/GitHub |
| Human approval | Terminal + webhooks | No web server dependency |

**Ships as two static binaries:** `closedshell` (host) and `ask` (sandbox).

**Judge model is BYO.** Run ollama locally, point at a remote API, or put litellm in front — the daemon doesn't care. It speaks OpenAI-compatible JSON over HTTP.

---

## Configuration Reference

```yaml
# closedshell.yaml

sandbox:
  motd: true                    # show ask CLI usage on entry
  implicit_ask: true            # auto-request permissions on first access
  credentials:
    - type: file
      source: ~/.aws/credentials
      mount: ~/.aws/credentials
      readonly: true
    - type: env
      vars: [OPENAI_API_KEY, GITHUB_TOKEN]
    - type: socket
      source: $SSH_AUTH_SOCK
      mount: /tmp/ssh-agent.sock
    - type: oauth
      provider: gcp
      token_path: ~/.config/gcloud/
      refresh_interval: 45m

judge:
  api_base: "http://localhost:11434/v1"
  model: "qwen3:8b"
  api_key: ""
  max_tokens: 512
  timeout_ms: 5000
  temperature: 0.0
  system_prompt_path: "/etc/closedshell/judge-system.txt"

preconditions:
  default_max_staleness: "30s"  # cache window for precondition results
  check_timeout: "5s"           # hard timeout per precondition command
  sweep_interval: "60s"         # background cleanup interval

risk_taxonomy:
  # Override or extend the baked-in taxonomy
  custom_rules_path: "/etc/closedshell/risk-overrides.yaml"

approval:
  auto_approve_timeout:
    moderate: "30s"
    dangerous: null             # never auto-approve
  webhook_url: ""               # Slack / PagerDuty / custom
```

---

## Development Sections

The project is broken into independently iterable sections, ordered by dependency.

### Section 1: Sandbox + Daemon + Proxy (the enforcement plane)

Everything that makes the sandbox work end-to-end. This is one integrated deliverable because the namespace setup, daemon IPC, and proxy are tightly coupled — you can't meaningfully test the proxy without the sandbox network namespace, and the daemon/socket is glue between them.

**Scope:**
- Linux namespaces (net, pid, mount, user) for isolation
- seccomp-bpf with `SECCOMP_RET_USER_NOTIF` on execve, connect, sendto
- Host-side daemon process + Unix socket IPC
- `ask` CLI skeleton (read-only commands first: status, why-denied)
- Transparent MITM proxy with session-scoped CA, iptables redirect
- Provider parsers (generic `net:METHOD:host/path` first, then AWS/GCP/etc.)
- Credential mounts (file, env, socket, oauth with daemon-side refresh)
- Tree lookup on every request — unknown = deny (no judge yet)
- `closedshell create -- <cmd>` lifecycle

**Deliverable:** A locked sandbox where all network traffic is intercepted, parsed, and checked against the permission tree. Credentials mounted in, OAuth refreshed by daemon. End-to-end from `closedshell create` to denied/approved request.

### Section 2: Permission Tree

Standalone, fully unit-testable data structure. No system dependencies — can start day one alongside Section 1.

**Scope:**
- In-memory permission store, session-scoped
- Permission types: idempotent, one-shot, state-dependent
- Regex matching, expiry, consumption logic
- CRUD via internal API

**Deliverable:** A well-tested library that Section 1 consumes for tree lookups.

### Section 3: Judge Integration

Plugs into the proxy to make real permission decisions.

**Scope:**
- OpenAI-compatible API client (structured JSON I/O)
- Risk taxonomy (baked-in + config override)
- Decision matrix (safe→approve, dangerous→escalate, timeout→deny)
- Implicit ask flow (proxy holds request while judge evaluates)
- Explicit `ask allow` and `ask plan` flows

**Deliverable:** Judge makes real decisions. Implicit ask works end-to-end — agent runs a command, proxy intercepts, judge evaluates, permission granted or denied transparently.

### Section 4: Human Approval

Escalation path for actions the judge won't auto-approve.

**Scope:**
- Pending approval queue in daemon
- `closedshell approvals` host-side CLI
- Auto-approve timeouts per risk tier
- Webhook support (Slack, PagerDuty, custom endpoint)
- Plan context shown to approvers

**Deliverable:** `escalate_human` decisions route to a human and block until resolved.

### Section 5: Preconditions

The most complex permission type — touches proxy, tree, and host-side execution.

**Scope:**
- Point-of-use verification in proxy (before forwarding request)
- Cached results with configurable `max_staleness`
- Background sweep for cleanup (not enforcement)
- Host-side precondition command execution with hard timeout
- Auto-revoke on precondition failure

**Deliverable:** State-dependent permissions fully enforced. Preconditions verified at point-of-use, cached intelligently, cleaned up in background.

### Dependency Graph

```
Section 2 (permission tree) ── starts day one, consumed by Section 1

Section 1 (sandbox+daemon+proxy) ──→ Section 3 (judge) ──→ Section 5 (preconditions)
                                 ──→ Section 4 (human approval)
```

### Recommended Build Order (solo dev)

1. **Section 1 + Section 2** in parallel
2. **Section 3** (judge — proxy becomes useful)
3. **Section 4 + Section 5** in parallel

---

## What This Is Not

- Not a container orchestrator. One sandbox, one agent, one host.
- Not a policy authoring tool. Policies emerge from agent interaction.
- Not cloud-hosted. Runs entirely on your machine.
- Not agent-specific. Any process that can run in a shell works.
- Not married to any model provider. BYO model, BYO inference stack.

---

## Open Questions

1. **Judge training data.** Bootstrap from IAM taxonomy + synthetic sessions, then learn from real usage?
2. **Multi-agent.** Shared permission tree or separate sandboxes with cross-sandbox communication?
3. **Escape hatch.** "YOLO mode" that logs everything but blocks nothing for dev environments?
4. **Non-Linux.** seccomp is Linux-only. macOS needs Endpoint Security framework. Windows TBD.
5. **Plan branching.** "If X then Y else Z" — how does the judge approve conditional plans?
6. **Permission templates.** Pre-built starter sets per workflow type (k8s-debug, aws-deploy, etc.)?
7. **Implicit ask rate limiting.** If an agent hammers unknown endpoints, the judge gets flooded. Need per-session rate limits on implicit asks, with a circuit breaker that falls back to explicit `ask` only.
8. **Precondition composition.** Should preconditions support AND/OR logic, or keep it flat (all must pass)?
9. **Judge prompt versioning.** System prompt changes alter security behavior. Need versioning + audit trail for judge prompt changes.
10. **Moderate approval escalation threshold.** If the judge approves N moderate (state-changing) actions within a time window, should it auto-escalate to human review? A single model call approving unbounded writes is a lot of trust — a circuit breaker (e.g., >5 moderate approvals in 10 minutes → escalate next one) would cap exposure without slowing down normal usage.
