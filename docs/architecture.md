# ClosedShell macOS Architecture — Seatbelt + Proxy

**Decision:** Use macOS Seatbelt (`sandbox-exec`) for process isolation and a host-side MITM proxy for network interception. No root, no System Extensions, no Apple entitlements.

---

## Overview

```
┌─────────────────────────────────────────────────────────┐
│  macOS Host                                             │
│                                                         │
│  closedshell daemon (Rust)                              │
│  ┌────────────┐ ┌──────────┐ ┌───────────────────────┐ │
│  │ Permission  │ │ Judge    │ │ MITM Proxy            │ │
│  │ Tree        │ │ (OpenAI  │ │ (rustls + hyper)      │ │
│  │             │ │  compat) │ │                       │ │
│  │ allow/deny  │ │ approve/ │ │ SNI peek → dynamic    │ │
│  │ + implicit  │ │ escalate/│ │ cert → parse API call │ │
│  │   ask       │ │ deny     │ │ → check permissions   │ │
│  └──────┬─────┘ └────┬─────┘ └───────────┬───────────┘ │
│         │            │                    │             │
│         └────────────┴────────────────────┘             │
│                       ▲                                 │
│              Unix socket + localhost:8443                │
│                       │                                 │
│  ┌────────────────────┴────────────────────────────────┐│
│  │  Sandboxed Shell (sandbox-exec)                     ││
│  │                                                     ││
│  │  Seatbelt profile enforces:                         ││
│  │  • deny network-outbound (except localhost:8443)    ││
│  │                                                     ││
│  │  HTTP_PROXY / HTTPS_PROXY → localhost:8443          ││
│  │                                                     ││
│  │  Agent ←→ `ask` CLI ←→ Unix Socket (read-only)     ││
│  └─────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────┘
```

---

## Why Seatbelt + Proxy

| Option Considered | Verdict | Reason |
|---|---|---|
| **Seatbelt + Proxy** | **Chosen** | Zero deps, no root, instant startup, all API calls forced through proxy |
| Endpoint Security Framework | Rejected (for now) | Requires System Extension, Apple notarization, root, user approval dialog |
| Network Extension (NETransparentProxy) | Rejected (for now) | Same System Extension pain, overkill when env-var proxy works |
| Apple Containers (Virtualization.fwk) | Deferred to "hardened mode" | VM-level isolation is stronger but heavier (~1-2s boot, ~100MB RAM, Linux-only guest) |

---

## Interception Model

### Network (primary enforcement boundary)

All outbound HTTPS is forced through the host proxy via two mechanisms:

1. **Seatbelt profile** — denies all `network-outbound` except `localhost:8443`
2. **Environment variables** — `HTTP_PROXY` / `HTTPS_PROXY` set to `http://localhost:8443`

The proxy then:
1. Accepts the connection
2. Peeks at TLS `ClientHello` → extracts SNI (target hostname)
3. Generates a leaf cert for that hostname, signed by the persistent CA (see [§ TLS Trust Model](#tls-trust-model))
4. Terminates TLS → reads HTTP request
5. Parses the request into a canonical action (`aws:s3:ListBuckets`, `gh:repos/*/pulls:POST`, etc.)
6. Checks the permission tree
7. If unknown → implicit ask to judge → approve/escalate/deny
8. If approved → establishes upstream TLS, forwards request as-is (credentials pass through), relays response

```
Agent runs: aws s3 ls
  │
  ├─ aws CLI honors HTTPS_PROXY → connects to localhost:8443
  │
  ├─ Proxy: TLS terminate → parse → aws:s3:ListBuckets
  │   ├─ Tree hit? → forward (fast path, ~1ms)
  │   └─ Tree miss? → implicit ask → judge → approve → add to tree → forward
  │
  └─ Agent gets response. Total added latency: ~1ms (cached) / ~100ms (first access)
```

### Process Execution (future phase)

Process-exec allowlisting via seatbelt `process-exec` rules is planned for a future phase. Currently the seatbelt profile only enforces network rules — the proxy is the real enforcement boundary.

---

## TLS Trust Model

The MITM proxy needs sandboxed processes to trust its dynamically generated leaf certificates. This requires a CA that the system's TLS stack recognizes.

**Why a persistent CA, not per-session:** A per-session CA means adding a new trusted cert on every launch — which on macOS triggers a keychain password prompt each time. That's a dealbreaker for a tool you start dozens of times a day. Instead, ClosedShell generates one CA on first run, stores it at `~/.closedshell/ca.pem`, and adds it to the macOS user trust store once (no admin password required). Every subsequent session reuses this CA — zero prompts, instant startup.

**Two trust paths cover all clients:**

1. **`SSL_CERT_FILE`** — set inside the sandbox to a bundle containing the ClosedShell CA + system roots. This covers most CLI tools: curl, Python, Node, Ruby, and Go with `GODEBUG=x509usefallbackroots=1`.
2. **macOS user trust store** — the CA is registered on first run via Security.framework. This covers Go binaries that use cgo and any other tool that ignores `SSL_CERT_FILE` and goes straight to the system trust store.

**Why not `security add-trusted-cert`:** On modern macOS (Big Sur 11.3+), `security add-trusted-cert` always prompts for a password — even when writing to the user domain. There is no flag to suppress it. Instead, ClosedShell compiles a small Swift helper on first run that calls `SecTrustSettingsSetTrustSettings` directly with the `.user` domain, which does not require authentication. The compiled helper is cached at `~/.closedshell/trust-cert` and reused if the CA is ever regenerated.

**Leaf certs are still per-hostname, per-session.** The persistent CA only means the *root of trust* doesn't change — individual leaf certs are generated on-the-fly when the proxy sees a new SNI hostname, cached in memory for the session, and discarded on exit.

**Security note:** The CA private key lives at `~/.closedshell/ca-key.pem`. Anyone with access to this file can generate trusted certs for any hostname on your machine. This is acceptable because ClosedShell's threat model is about protecting *remote* systems from your agent, not protecting your machine from local attackers. If someone has access to your home directory, you have bigger problems.

---

## Session Lifecycle

```
closedshell <agent-command>

1. Lookup working directory in sessions.db → resume or create session
2. Load persistent CA from ~/.closedshell/ca.pem (or generate + trust on first run)
3. Write combined trust store (CA + system roots) to sandbox tmpdir
4. Generate seatbelt profile (.sb file)
5. Start MITM proxy on localhost:8443
6. Start Unix socket listener for `ask` CLI
7. Exec:
   sandbox-exec -f /tmp/closedshell-XXXX/profile.sb \
     env HTTPS_PROXY=http://localhost:8443 \
         HTTP_PROXY=http://localhost:8443 \
         SSL_CERT_FILE=/tmp/closedshell-XXXX/ca.pem \
         CLOSEDSHELL_SOCKET=/tmp/closedshell-XXXX/ask.sock \
     -- <agent-command>
8. Print MOTD (if enabled)
9. Open audit log: $PWD/closedshell-$SESSION_ID.log
10. Agent runs. All HTTPS → proxy. `ask` CLI → Unix socket.
11. On exit: tear down proxy, remove tmpdir. Permission tree + session metadata persisted to SQLite.
   Log file persists.
```

---

## Session Management

Sessions are identified by **working directory**. When `closedshell <cmd>` runs, it looks up the working directory in the session database. If a session exists for that directory, its permission tree is restored. If not, a new session is created.

This maps to how coding agents like Pi work — sessions are per-project, and resuming a session in the same directory should feel like picking up where you left off, permissions included.

### Storage

```
~/.closedshell/sessions.db    (SQLite)
```

```sql
CREATE TABLE sessions (
    id          TEXT PRIMARY KEY,       -- "8f3a-29c1"
    workdir     TEXT NOT NULL UNIQUE,   -- working directory (one session per dir)
    command     TEXT NOT NULL,          -- "pi", "claude-code", etc.
    task        TEXT,                   -- current session task
    status      TEXT NOT NULL,          -- "running", "stopped"
    templates   TEXT,                   -- JSON array: ["aws-debug"]
    pid         INTEGER,               -- daemon PID (detect crashes)
    port        INTEGER NOT NULL,      -- proxy port
    log_path    TEXT NOT NULL,          -- audit log path
    created_at  TEXT NOT NULL,
    last_used   TEXT NOT NULL,
    total_decisions INTEGER DEFAULT 0,
    total_denied    INTEGER DEFAULT 0
);

CREATE TABLE rules (
    id          TEXT PRIMARY KEY,       -- rule ID: "p-001"
    session_id  TEXT NOT NULL REFERENCES sessions(id),
    effect      TEXT NOT NULL,          -- "permit" or "forbid"
    action      TEXT NOT NULL,          -- glob pattern
    type        TEXT,                   -- "idempotent" or "one-shot"
    rule_json   TEXT NOT NULL,          -- full rule as JSON
    created_at  TEXT NOT NULL
);
```

### Lifecycle

```
closedshell pi                         # start or resume
  1. Hash $PWD → lookup in sessions.db
  2. Existing session found?
     YES → restore permission tree from rules table, reuse session ID, append to existing log
     NO  → create new session, empty tree (+ templates if configured)
  3. Start sandbox, proxy, socket (as before)
  4. On exit:
     - Persist current permission tree to rules table
     - Update last_used, total_decisions, total_denied
     - Set status = "stopped"
     - Tear down proxy, remove tmpdir
     - Log file persists
```

### CLI

Three modes based on arguments:

```
closedshell                                     # TUI — session manager
closedshell 8f3a                                # TUI — jump to specific session
closedshell pi                                  # run agent in sandbox
closedshell --task "fix bug" pi                 # with session task
closedshell --template aws-debug pi             # with templates
```

Alias: `cs` (configured by user, not shipped).

**How disambiguation works:** if the argument matches a known session ID prefix, open the TUI for that session. Otherwise, treat it as a command to sandbox. Session IDs are short hex strings — no collision with real commands.

### Sandbox flags

```
closedshell [flags] <command> [args...]
```

| Flag | Description |
|------|-------------|
| `--task <text>` | Set session task (used by judge for scope detection) |
| `--template <name>` | Load permission template (repeatable) |
| `--yolo` | Log-only mode — no blocking (see [§ YOLO Mode](#yolo-mode)) |
| `--no-motd` | Suppress MOTD on start |
| `--fresh` | Ignore existing session for this directory, start clean (new session ID, empty tree) |

### TUI

The TUI is the management interface. It runs in a separate terminal from the sandboxed agent.

#### Session list (no args)

```
┌─ closedshell ─────────────────────────────────────────────┐
│ Sessions                                                  │
│  ● 8f3a  ~/repos/myproject     pi    2m ago   12 decisions│
│  ○ c91b  ~/repos/other         pi    3h ago   47 decisions│
│                                                           │
│ [enter] select  [n] new  [d] delete  [r] reset  [q] quit │
└───────────────────────────────────────────────────────────┘
```

`●` = running, `○` = stopped. Sorted by last activity.

#### Session detail (select or `closedshell 8f3a`)

Tabs: **live**, **rules**, **approvals**, **history**

**Live tab** — streaming decisions in real time:

```
┌─ 8f3a ~/repos/myproject ──────────────────────────────────┐
│ [l]ive  [r]ules  [a]pprovals  [h]istory                   │
├───────────────────────────────────────────────────────────┤
│ 14:32:01 ✓ aws[profile=dev]:s3:ListBuckets      template │
│ 14:32:03 ✓ aws[profile=dev]:ec2:Describe*        judge   │
│ 14:32:05 ✗ aws[profile=prod]:ec2:Terminate*      forbid  │
│ 14:32:08 ? aws[profile=prod]:ecs:UpdateService   pending │
│                                                           │
│ [y] approve  [n] deny  [f] forbid  [e] edit rules        │
└───────────────────────────────────────────────────────────┘
```

**Rules tab** — current permission tree:

```
┌─ 8f3a rules ──────────────────────────────────────────────┐
│ FORBID                                                    │
│  f-001  aws[profile=prod]:*:Delete*       (session policy)│
│  f-002  aws[profile=prod]:*:Terminate*    (session policy)│
│                                                           │
│ PERMIT                                                    │
│  p-001  aws[profile=*]:*:Describe*        idempotent      │
│  p-002  aws[profile=*]:*:List*            idempotent      │
│  p-003  aws[profile=prod]:ecs:Update*     one-shot (used) │
│                                                           │
│ [e] edit in $EDITOR  [f] add forbid  [d] delete rule      │
└───────────────────────────────────────────────────────────┘
```

**Approvals tab** — pending human approvals:

```
┌─ 8f3a approvals ──────────────────────────────────────────┐
│ PENDING (1)                                               │
│  → aws[profile=prod]:ecs:UpdateService                    │
│    risk: moderate | judge: escalate_human                  │
│    plan: "rollback ECS deployment" (plan-013)              │
│    waiting: 45s                                            │
│                                                           │
│ [y] approve  [n] deny  [i] inspect plan                   │
└───────────────────────────────────────────────────────────┘
```

**History tab** — scrollable audit log:

```
┌─ 8f3a history ────────────────────────────────────────────┐
│ 14:30:00 session_start  pi  templates: [aws-debug]        │
│ 14:32:01 ✓ aws[profile=dev]:s3:ListBuckets      1ms      │
│ 14:32:03 ✓ aws[profile=dev]:ec2:Describe*        87ms    │
│ 14:32:05 ✗ aws[profile=prod]:ec2:Terminate*      0ms     │
│ 14:32:08 ? aws[profile=prod]:ecs:UpdateService   pending │
│                                                           │
│ [/] search  [↑↓] scroll  [enter] detail                   │
└───────────────────────────────────────────────────────────┘
```

#### Rule editing

Pressing `e` on the rules tab opens `~/.closedshell/sessions/<id>/rules.yaml` in `$EDITOR`. The daemon watches the file and hot-reloads on save:

1. User presses `e` → TUI writes current tree to `rules.yaml`, opens `$EDITOR`
2. User edits rules (add forbids, remove permits, adjust globs)
3. User saves and exits `$EDITOR`
4. Daemon detects file change → validates against schema
5. Valid → tree replaced, TUI shows updated rules
6. Invalid → TUI shows validation errors, tree unchanged, offers to re-edit

Forbid rules from org baseline or templates cannot be removed via edit — they're marked `# locked` in the file and the daemon rejects edits that remove them.

#### TUI keybindings

| Key | Context | Action |
|-----|---------|--------|
| `l` | session | switch to live tab |
| `r` | session | switch to rules tab |
| `a` | session | switch to approvals tab |
| `h` | session | switch to history tab |
| `y` | live/approvals | approve pending request |
| `n` | live/approvals | deny pending request |
| `f` | live/rules | add forbid rule (inline prompt) |
| `e` | rules | edit rules in `$EDITOR` |
| `d` | rules/sessions | delete rule / delete session |
| `/` | history | search |
| `q` | any | back / quit |

### Crash recovery

On startup, check for rows where `status = "running"` but `pid` is dead. Mark them `"stopped"`. Next `closedshell <cmd>` in that directory resumes normally.

### One-shot rules across sessions

One-shot rules that were consumed are deleted from the `rules` table on persist. Only unconsumed rules survive a session restart. Forbid rules and idempotent permits carry over.

---

## YOLO Mode

`yolo: true` in config or `closedshell --yolo pi` on the command line. The proxy still intercepts and parses every request, but **never blocks**. All decisions are logged as `allow (yolo)`. The judge is not consulted. Forbid rules are still evaluated and logged as `would_deny (yolo)` but don't block.

Use case: dev environments where you want visibility into what the agent is doing without friction. You can review the audit log after the fact and use it to build templates for production sessions.

MOTD shows `[closedshell] mode: yolo` when active.

---

## MOTD

Printed to stderr on sandbox start when `motd: true` (default). Tells the human (or agent) what's active:

```
[closedshell] session 8f3a-29c1 (resumed)
[closedshell] task: investigate 503s in us-east-1
[closedshell] templates: aws-debug, github-readonly
[closedshell] permits: 6 | forbids: 2
[closedshell] log: ./closedshell-8f3a-29c1.log
```

New sessions show `(new)` instead of `(resumed)`. Kept terse — one line per fact, no box drawing, no instructions. Agents that parse stderr can ignore the `[closedshell]` prefix.

---

## IPC Protocol (`ask` ↔ daemon)

Unix socket, newline-delimited JSON. One request, one response. No streaming, no multiplexing.

### Request

```json
{"type": "status"}
{"type": "what_can_i", "pattern": "aws[profile=*]:s3:*"}
{"type": "why_denied"}
{"type": "allow", "action": "aws[profile=dev]:ec2:DescribeInstances"}
{"type": "plan", "description": "rollback ECS deployment in us-east-1"}
{"type": "context", "task": "now rolling back ECS deployment"}
{"type": "read", "path": "/Users/alice/repos/myproject/src/main.rs"}
{"type": "write", "path": "/Users/alice/repos/myproject/out.json", "content": "..."}
```

### Response

```json
{"ok": true, "data": ...}
{"ok": false, "error": "not_permitted", "message": "no matching permission", "hint": "ask plan \"describe your goal\""}
```

`data` varies by request type:
- `status` → `{"rules": [...]}` (current permission tree)
- `what_can_i` → `{"matches": [...]}` (matching rules, no side effects)
- `why_denied` → `{"action": "...", "reason": "...", "risk_tier": "...", "hint": "..."}`
- `allow` → `{"rule": {...}}` (the granted rule) or error
- `plan` → `{"plan_id": "...", "auto_approved": [...], "pending_human": [...]}`
- `context` → `{"task": "..."}` (updated session context)
- `read` → `{"content": "..."}` or error
- `write` → `{"bytes_written": N}` or error

### Error codes

| Code | Meaning |
|------|---------|
| `not_permitted` | Permission tree denied the action |
| `pending_approval` | Queued for human approval, not yet resolved |
| `invalid_request` | Malformed request |
| `internal_error` | Daemon-side failure |

---

## Audit Log

Newline-delimited JSON file written to the working directory: `closedshell-<session-id>.log`. Persists after session ends. One line per event.

The agent can read this file (seatbelt allows reads) — that's fine per the threat model.

### Events

Every proxy decision and `ask` CLI interaction produces a log entry. Common envelope:

```json
{
  "ts": "2026-04-04T14:32:01.003Z",
  "session": "8f3a-29c1",
  "event": "...",
  ...
}
```

### Event types

**`decision`** — every allow/deny through the proxy or `ask` CLI:

```json
{
  "ts": "2026-04-04T14:32:01.003Z",
  "session": "8f3a-29c1",
  "event": "decision",
  "action": "aws[profile=dev]:s3:ListBuckets",
  "result": "allow",
  "decided_by": "template:aws-debug",
  "rule_id": "p-001",
  "latency_ms": 1,
  "request": {
    "method": "GET",
    "host": "s3.amazonaws.com",
    "path": "/"
  }
}
```

```json
{
  "ts": "2026-04-04T14:32:05.187Z",
  "session": "8f3a-29c1",
  "event": "decision",
  "action": "aws[profile=prod]:ec2:TerminateInstances",
  "result": "deny",
  "decided_by": "forbid:f-002",
  "reason": "session policy: no production terminates",
  "request": {
    "method": "POST",
    "host": "ec2.amazonaws.com",
    "path": "/",
    "params": {"Action": "TerminateInstances", "InstanceId.1": "i-abc123"}
  }
}
```

**`judge`** — every judge invocation (implicit ask or explicit):

```json
{
  "ts": "2026-04-04T14:32:03.450Z",
  "session": "8f3a-29c1",
  "event": "judge",
  "action": "aws[profile=dev]:ec2:DescribeInstances",
  "decision": "approve",
  "risk_tier": "safe",
  "latency_ms": 87,
  "implicit": true
}
```

**`plan`** — plan submitted and processed:

```json
{
  "ts": "2026-04-04T14:35:00.000Z",
  "session": "8f3a-29c1",
  "event": "plan",
  "plan_id": "plan-013",
  "description": "rollback ECS deployment",
  "auto_approved": 2,
  "pending_human": 1
}
```

**`context`** — session task updated via `ask context`:

```json
{
  "ts": "2026-04-04T14:40:00.000Z",
  "session": "8f3a-29c1",
  "event": "context",
  "old_task": "investigate 503s in us-east-1",
  "new_task": "rollback ECS deployment"
}
```

**`lifecycle`** — session start/end:

```json
{"ts": "...", "session": "8f3a-29c1", "event": "session_start", "command": "claude-code", "templates": ["aws-debug"]}
{"ts": "...", "session": "8f3a-29c1", "event": "session_end", "duration_s": 1823, "total_decisions": 47, "denied": 3}
```

**`file_io`** — `ask read` / `ask write` operations:

```json
{
  "ts": "2026-04-04T14:33:00.000Z",
  "session": "8f3a-29c1",
  "event": "file_io",
  "op": "write",
  "path": "/Users/alice/repos/myproject/out.json",
  "result": "allow",
  "bytes": 1024,
  "decided_by": "p-003"
}
```

### What's NOT logged

- Request/response bodies (storage/privacy concern — add in a future `verbose` mode if needed)
- Direct file reads by the agent (`cat`, etc.) — seatbelt allows these, they bypass the daemon entirely
- Sandbox-internal activity (tmpdir writes, process execution)

---

## Crate Stack

| Crate | Role |
|---|---|
| `tokio` | Async runtime for proxy + daemon |
| `rustls` | TLS termination + upstream TLS |
| `rcgen` | Persistent CA + dynamic leaf cert generation per SNI |
| `hyper` | HTTP parsing in the proxy |
| `reqwest` | Judge client (OpenAI-compatible API calls) |
| `serde` / `serde_yaml` | Config, permission tree serialization |
| `clap` | CLI argument parsing for both binaries |

No special crate for seatbelt — the profile is a generated `.sb` file passed to `sandbox-exec` via `std::process::Command`.

---

## Binaries

```
closedshell    (host-side daemon + proxy + CLI)
ask            (in-sandbox CLI, talks to daemon over Unix socket)
```

---

## What We Trade Off vs Linux

| Capability | Linux (seccomp-notify) | macOS (seatbelt) |
|---|---|---|
| Runtime exec interception | Supervisor callback per execve | Not enforced (proxy is the boundary) |
| Namespace isolation (pid/mount/net) | Full | None (process-level sandbox) |
| Network interception | iptables + transparent proxy | Env-var proxy + seatbelt deny |
| File isolation | Mount namespace + overlayfs | Not enforced (proxy is the boundary) |
| Credential isolation | Never in sandbox filesystem | Never in sandbox filesystem |
| Deployment friction | Needs Linux | No root, no extensions, ships with macOS |

The proxy is the real enforcement boundary, and it works identically on both platforms.

---

## Future: Hardened Mode (Apple Containers)

For untrusted agents requiring VM-level isolation, launch inside an Apple Container (Virtualization.framework). Same proxy, same judge, same `ask` CLI — just swap the process wrapper. The agent runs in a lightweight Linux VM with full namespace/seccomp support internally.

This is deferred. The seatbelt path covers the primary use case.

---

## Success Criteria

Each criterion is a test you can run. Section 1 is done when all sandbox + proxy criteria pass. Later sections add their own.

### Sandbox Isolation

| # | Test | Pass condition |
|---|------|---------------|
| S1 | Process inside sandbox runs `curl https://example.com` | Connection refused or timeout — seatbelt blocks outbound |
| S2 | Process inside sandbox runs `curl http://localhost:8443` | Connection succeeds — proxy is reachable |
| S3 | Process inside sandbox runs `/bin/sh` | Exec succeeds — no process-exec restrictions in YOLO phase |

### Proxy + TLS

| # | Test | Pass condition |
|---|------|---------------|
| P1 | Agent runs `curl https://httpbin.org/get` through proxy | Proxy intercepts: TLS terminated with persistent CA, request logged, action parsed as `net:GET:httpbin.org/get` |
| P2 | Agent runs `aws s3 ls` through proxy (no permission in tree) | Proxy parses `aws[profile=...]:s3:ListBuckets`, returns deny (no judge yet in Section 1) |
| P3 | Manually add `permit aws[profile=*]:s3:List*` to tree, re-run `aws s3 ls` | Proxy matches permit, forwards request, agent gets bucket list |
| P4 | Agent makes request to unknown host | Proxy parses as `net:METHOD:host/path`, returns deny |
| P5 | Verify CA is persistent | Two `closedshell` invocations reuse the same CA from `~/.closedshell/ca.pem` |
| P6 | Verify upstream TLS works | Proxy connects to real upstream with system trust store (not ClosedShell CA) |

### Session Lifecycle

| # | Test | Pass condition |
|---|------|---------------|
| L1 | `closedshell /bin/sh` | Sandbox starts, proxy listening, Unix socket exists, MOTD displayed |
| L2 | Agent exits | Proxy stops, tmpdir removed, socket gone |
| L3 | `closedshell pi` with `passthrough_env` in config | Configured env vars available inside sandbox |
| L4 | Kill daemon while agent is running | Agent's next network call fails cleanly (connection refused, not hang) |

### `ask` CLI + IPC

| # | Test | Pass condition |
|---|------|---------------|
| A1 | `ask status` inside sandbox | Returns current permission tree (empty initially) as formatted output |
| A2 | `ask status` outside sandbox (no socket) | Clean error: "not running inside closedshell" |
| A3 | `ask what-can-i "aws[profile=*]:s3:*"` | Returns matching rules from tree, no permission request submitted |
| A4 | `ask why-denied` after a denial | Returns last denial reason with action, risk tier, and hint |

### Permission Tree (unit tests, no sandbox needed)

| # | Test | Pass condition |
|---|------|---------------|
| T1 | Forbid `aws[profile=prod]:*:Delete*`, permit `aws[profile=prod]:s3:Delete*` → evaluate `aws[profile=prod]:s3:DeleteBucket` | DENY (forbid overrides permit) |
| T2 | No rules → evaluate any action | DENY (default deny) |
| T3 | Permit `aws[profile=dev]:ec2:Describe*` (idempotent) → evaluate twice | ALLOW both times, rule still in tree |
| T4 | Permit one-shot → evaluate twice | First ALLOW, second DENY (consumed) |
| T5 | One-shot consumed → same action re-evaluated | DENY (consumed) |
| T8 | Glob `aws[profile=*]:s3:List*` matches `aws[profile=dev]:s3:ListBuckets` | Match |
| T9 | Glob `aws[profile=dev]:s3:List*` does NOT match `aws[profile=prod]:s3:ListBuckets` | No match |
| T10 | Template merge: two templates loaded, forbid from first cannot be removed by second | Forbid persists |
| T11 | Plan revocation: revoke plan-id removes all rules with that plan_id | All child rules gone |
| T12 | Forbid `file:read:/Users/*/.ssh/*`, evaluate `file:read:/Users/alice/.ssh/id_rsa` | DENY |
| T13 | Permit `file:write:/Users/alice/repos/*`, evaluate `file:write:/Users/alice/repos/foo.txt` | ALLOW |
| T14 | No permit for `file:write:/etc/passwd`, evaluate | DENY (default deny) |

### File I/O

| # | Test | Pass condition |
|---|------|---------------|
| F1 | Agent runs `ask write /Users/alice/repos/test.txt "hello"` with matching permit | Daemon writes file on host side, agent gets confirmation |
| F2 | Agent runs `ask write /Users/alice/.ssh/config "..."` with forbid on dotfiles | DENY, file not written |
| F3 | Agent runs `echo hi > /Users/alice/repos/test.txt` directly (no `ask`) | Succeeds — file-write restrictions deferred to future phase |
| F4 | Agent runs `cat /Users/alice/repos/test.txt` directly | Succeeds — Seatbelt allows reads |
| F5 | Agent runs `ask read /Users/alice/.ssh/id_rsa` with forbid on `.ssh/*` | DENY, content not returned |
| F6 | Agent runs `cat /Users/alice/.ssh/id_rsa` directly | Succeeds (Seatbelt allows reads) — this is the audit gap we accept |

### End-to-End (requires all sections)

| # | Test | Pass condition |
|---|------|---------------|
| E1 | Agent runs `aws s3 ls` in fresh session with `aws-debug` template | Template permits `List*` → proxy forwards → agent gets response, < 5ms added latency |
| E2 | Agent runs `aws s3 rm s3://bucket/key` in session with `aws-debug` template | Template forbids `Delete*` → DENY with reason, judge never consulted |
| E3 | Agent runs `aws ec2 describe-instances` (no template, implicit ask enabled) | Proxy holds request → judge approves → permit added → agent gets response, < 200ms |
| E4 | Agent runs `aws ec2 terminate-instances` (implicit ask) | Judge returns `escalate_human` → DENY with hint to `ask plan` |
| E5 | Agent runs `ask plan "investigate 503s"` → human approves | Plan rules added to tree, agent runs approved commands at full speed |
| E6 | One-shot consumed → agent retries same action | Second attempt denied, agent told to re-request |

---

## Security Boundaries

| Layer | Mechanism | Bypass Resistance |
|-------|-----------|-------------------|
| Process isolation | Platform-specific (namespaces / seatbelt) | Kernel-level |
| Syscall filtering | seccomp-bpf (Linux) / seatbelt (macOS) | Kernel-level |
| Network egress | All traffic forced through proxy | No network without proxy |
| API enforcement | L7 proxy parsing + permission tree | Catches all HTTP |
| Credential isolation | Mounted in sandbox, but proxy enforces | Agent can't bypass proxy |
| Judge isolation | Structured input only, single model | Agent can't prompt-inject judge |
| Judge failure mode | Timeout/error = deny | Fail closed, always |
