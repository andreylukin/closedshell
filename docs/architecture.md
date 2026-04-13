# ClosedShell macOS Architecture — Seatbelt + Proxy

**Decision:** Use macOS Seatbelt (`sandbox-exec`) for process isolation and a host-side MITM proxy for network interception. No root, no System Extensions, no Apple entitlements.

---

## Overview

```
┌─────────────────────────────────────────────────────────┐
│  macOS Host                                             │
│                                                         │
│  cs daemon (Rust)                                       │
│  ┌────────────┐ ┌───────────────────────┐               │
│  │ Permission  │ │ MITM Proxy            │               │
│  │ Tree        │ │ (rustls + hyper)      │               │
│  │             │ │                       │               │
│  │ allow/deny  │ │ SNI peek → dynamic    │               │
│  │ + human     │ │ cert → parse API call │               │
│  │   approval  │ │ → check permissions   │               │
│  └──────┬─────┘ └───────────┬───────────┘               │
│         │                    │                           │
│         └────────────────────┘                           │
│                       ▲                                  │
│              Unix socket + localhost:8443                 │
│                       │                                  │
│  ┌────────────────────┴────────────────────────────────┐│
│  │  Sandboxed Shell (sandbox-exec)                     ││
│  │                                                     ││
│  │  Seatbelt profile enforces:                         ││
│  │  • deny network-outbound (except localhost:8443)    ││
│  │                                                     ││
│  │  HTTP_PROXY / HTTPS_PROXY → localhost:8443          ││
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
7. If permitted → forward. If forbidden → deny. If unknown → block for human approval via TUI.
8. If approved → adds rule to tree, establishes upstream TLS, forwards request as-is (credentials pass through), relays response

```
Agent runs: aws s3 ls
  │
  ├─ aws CLI honors HTTPS_PROXY → connects to localhost:8443
  │
  ├─ Proxy: TLS terminate → parse → aws:s3:ListBuckets
  │   ├─ Tree permit? → forward (fast path, ~1ms)
  │   ├─ Tree forbid? → deny (hard block)
  │   └─ No match? → block for human approval in TUI → approve → add to tree → forward
  │
  └─ Agent gets response. Total added latency: ~1ms (cached) / human approval time (first access)
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
cs [flags] -- <agent-command>

1. Load config, merge CLI flags
2. Open sessions.db, crash recovery (mark dead PIDs as stopped)
3. If --resume: restore permission tree from previous session in this directory
4. Load persistent CA from ~/.closedshell/ca.pem (or generate + trust on first run)
5. Write combined trust store (CA + system roots) to sandbox tmpdir
6. Start MITM proxy on localhost:8443 (falls back to OS-assigned port if taken)
7. Load templates into permission tree
8. Generate seatbelt profile (.sb file)
9. Start Unix socket listener for TUI IPC (enforcing mode only)
10. Print MOTD, log session_start event, register session in DB
11. Exec:
    sandbox-exec -f /tmp/closedshell-XXXX/profile.sb \
      env HTTPS_PROXY=http://localhost:$PORT \
          HTTP_PROXY=http://localhost:$PORT \
          SSL_CERT_FILE=/tmp/closedshell-XXXX/ca.pem \
          CLOSEDSHELL_SOCKET=/tmp/closedshell-XXXX/cs.sock \
          CLOSEDSHELL_SESSION=$SESSION_ID \
      -- <agent-command>
12. Agent runs. All HTTPS → proxy. TUI connects via Unix socket.
13. On exit: log session_end, persist permission tree + session metadata to SQLite,
    tear down proxy, remove tmpdir. Log file persists.
```

---

## Session Management

Sessions are identified by **working directory**. When `cs --resume -- <cmd>` runs, it looks up the working directory in the session database. If a previous session exists for that directory, its permission tree rules are restored into a new session. Without `--resume`, every invocation starts a fresh session with an empty tree (plus any templates).

This maps to how coding agents work — sessions are per-project, and resuming a session in the same directory should feel like picking up where you left off, permissions included.

### Storage

```
~/.closedshell/sessions.db    (SQLite)
```

```sql
CREATE TABLE sessions (
    id          TEXT PRIMARY KEY,
    workdir     TEXT NOT NULL,
    command     TEXT NOT NULL,
    task        TEXT,
    status      TEXT NOT NULL DEFAULT 'running',
    templates   TEXT NOT NULL DEFAULT '[]',
    pid         INTEGER NOT NULL,
    port        INTEGER NOT NULL,
    log_path    TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    last_used   TEXT NOT NULL,
    total_decisions INTEGER NOT NULL DEFAULT 0,
    total_denied    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE rules (
    id          TEXT NOT NULL,
    session_id  TEXT NOT NULL,
    effect      TEXT NOT NULL,
    action      TEXT NOT NULL,
    rule_type   TEXT,
    rule_json   TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (id, session_id),
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);
```

### Lifecycle

```
cs -- claude                               # start (or resume with --resume)
  1. Lookup $PWD in sessions.db
  2. --resume flag set and existing session found?
     YES → restore permission tree from rules table, generate fresh session ID
     NO  → create new session, empty tree (+ templates if configured)
  3. Start sandbox, proxy, socket (as before)
  4. On exit:
     - Persist current permission tree to rules table
     - Update last_used, total_decisions, total_denied
     - Set status = "ended"
     - Tear down proxy, remove tmpdir
     - Log file persists
```

### CLI

Three modes based on arguments:

```
cs                                              # TUI — hub (sessions + templates)
cs --tui 8f3a                                   # TUI — attach to specific session
cs -- claude                                    # run agent in sandbox
cs --template anthropic/full -- claude          # with templates
```

The binary is `cs`. Homebrew and `make install` both install it as `cs`.

**How disambiguation works:** `cs` with no arguments opens the hub. `cs --tui <id>` opens the TUI for a specific session. Everything else (after `--`) is treated as a command to sandbox.

### Sandbox flags

```
cs [flags] <command> [args...]
```

| Flag | Description |
|------|-------------|
| `--template <name>` | Load permission template (repeatable) |
| `--yolo` | Log-only mode — no blocking (see [§ YOLO Mode](#yolo-mode)) |
| `--resume` | Resume rules from previous session in this directory |
| `--pf` | Enable pf secondary enforcement (requires root) |
| `--pf-setup` | One-time system setup for pf enforcement (creates sandbox user + pf anchor) |
| `--tui <SESSION_ID>` | Open TUI for existing session |

### TUI

The TUI is the management interface. It runs in a separate terminal from the sandboxed agent.

#### Hub view (no args)

The hub has two tabs: **Sessions** and **Templates**, switchable via `Tab` or `1`/`2`.

```
┌─ closedshell ─────────────────────────────────────────────┐
│ Sessions                                                  │
│  ● 8f3a  ~/repos/myproject     pi    2m ago   12 decisions│
│  ○ c91b  ~/repos/other         pi    3h ago   47 decisions│
│                                                           │
│ [enter] select  [d] delete  [tab] templates  [q] quit    │
└───────────────────────────────────────────────────────────┘
```

`●` = running, `○` = stopped. Sorted by last activity.

#### Session detail (`cs --tui 8f3a` or select from hub)

Tabs: **Live**, **Policy**, **Approvals**

**Live tab** — streaming decisions in real time:

```
┌─ 8f3a ~/repos/myproject ──────────────────────────────────┐
│ [l]ive  [r] policy  [a]pprovals                            │
├───────────────────────────────────────────────────────────┤
│ 14:32:01 ✓ aws[profile=dev]:s3:ListBuckets      tree     │
│ 14:32:03 ✓ aws[profile=dev]:ec2:Describe*        tree     │
│ 14:32:05 ✗ aws[profile=prod]:ec2:Terminate*      tree     │
│ 14:32:08 ? aws[profile=prod]:ecs:UpdateService   pending  │
│                                                           │
│ [f] filter  [/] search  [?] help                         │
└───────────────────────────────────────────────────────────┘
```

**Policy tab** — current permission tree:

```
┌─ 8f3a policy ─────────────────────────────────────────────┐
│ FORBID                                                    │
│  f-001  aws[profile=prod]:*:Delete*       (session policy)│
│  f-002  aws[profile=prod]:*:Terminate*    (session policy)│
│                                                           │
│ PERMIT                                                    │
│  p-001  aws[profile=*]:*:Describe*        idempotent      │
│  p-002  aws[profile=*]:*:List*            idempotent      │
│  p-003  aws[profile=prod]:ecs:Update*     one-shot (used) │
│                                                           │
│ [e] edit in $EDITOR  [d] delete rule                      │
└───────────────────────────────────────────────────────────┘
```

**Approvals tab** — pending human approvals:

```
┌─ 8f3a approvals ──────────────────────────────────────────┐
│ PENDING (1)                                               │
│  → aws[profile=prod]:ecs:UpdateService                    │
│    risk: moderate                                          │
│    waiting: 45s                                            │
│                                                           │
│ [y] approve  [n] deny                                     │
└───────────────────────────────────────────────────────────┘
```

#### Rule editing

Pressing `e` on the Policy tab opens the session rules in `$EDITOR` as a `.csp` file:

1. User presses `e` → TUI writes current tree to a temp `.csp` file, opens `$EDITOR`
2. User edits rules (add forbids, remove permits, adjust globs)
3. User saves and exits `$EDITOR`
4. TUI parses the updated `.csp` file
5. Valid → rules reloaded via IPC, TUI shows updated policy
6. Invalid → changes discarded

#### TUI keybindings

| Key | Context | Action |
|-----|---------|--------|
| `l` / `1` | session | switch to Live tab |
| `r` / `2` | session | switch to Policy tab |
| `a` / `3` | session | switch to Approvals tab |
| `Tab` | session/hub | cycle tabs |
| `y` | approvals | approve pending request |
| `n` | approvals | deny pending request |
| `f` | live | cycle activity filter (all/allow/deny) |
| `e` | policy | edit rules in `$EDITOR` |
| `d` | policy/hub | delete rule / delete session |
| `/` | live | search activity |
| `?` | session | help overlay |
| `j`/`k` | any | scroll down/up |
| `g`/`G` | session | jump to top/bottom |
| `q` / `Esc` | any | back / quit |

### Crash recovery

On startup, check for rows where `status = "running"` but `pid` is dead. Mark them `"crashed"`. Next `cs --resume -- <cmd>` in that directory resumes normally.

### One-shot rules across sessions

One-shot rules that were consumed are deleted from the `rules` table on persist. Only unconsumed rules survive a session restart. Forbid rules and idempotent permits carry over.

---

## YOLO Mode

`cs --yolo -- <cmd>` on the command line (or `yolo: true` in config YAML). The proxy still intercepts and parses every request, but **never blocks**. All decisions are logged as `allow (yolo)`. Forbid rules are still evaluated and logged as `would_deny (yolo)` but don't block.

Use case: dev environments where you want visibility into what the agent is doing without friction. You can review the audit log after the fact and use it to build templates for production sessions.

MOTD shows `[closedshell] mode: yolo` when active.

---

## MOTD

Printed to stderr on sandbox start when `motd: true` (default). Tells the human (or agent) what's active:

```
[closedshell] session 8f3a29c1 (resumed)
[closedshell] templates: aws-debug, github-readonly
[closedshell] mode: enforcing
[closedshell] log: ./closedshell-8f3a29c1.log
```

New sessions show `(new)` instead of `(resumed)`. Kept terse — one line per fact, no box drawing, no instructions. Agents that parse stderr can ignore the `[closedshell]` prefix.

---

## IPC Protocol (TUI ↔ daemon)

Unix socket, newline-delimited JSON. One request, one response. No streaming, no multiplexing.

### Request

```json
{"type": "status"}
{"type": "pending_approvals"}
{"type": "approve", "id": "..."}
{"type": "deny", "id": "...", "reason": "optional reason"}
{"type": "delete_rule", "rule_id": "..."}
```

### Response

```json
{"ok": true, "data": ...}
{"ok": false, "error": "not_found", "message": "...", "hint": "..."}
```

`data` varies by request type:
- `status` → `{"rules": [...]}` (current permission tree)
- `pending_approvals` → `{"pending": [...]}` (actions waiting for human review)
- `approve` → `{"approved": true, "action": "..."}`
- `deny` → `{"denied": true, "action": "..."}`
- `delete_rule` → `{"deleted": true, "rule_id": "..."}`

### Error codes

| Code | Meaning |
|------|---------|
| `not_found` | Rule or approval ID not found |
| `parse_error` | Malformed request |

---

## Audit Log

Newline-delimited JSON file written to `~/.closedshell/logs/<encoded-cwd>/closedshell-<session-id>.log`. Persists after session ends. One line per event.

The agent can read this file (seatbelt allows reads) — that's fine per the threat model.

### Events

Every proxy decision produces a log entry. Common envelope:

```json
{
  "ts": "2026-04-04T14:32:01.003Z",
  "session": "8f3a-29c1",
  "event": "...",
  ...
}
```

### Event types

**`decision`** — every allow/deny through the proxy:

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

**`human_approval`** — human approved or denied an action via TUI:

```json
{
  "ts": "2026-04-04T14:32:03.450Z",
  "session": "8f3a-29c1",
  "event": "human_approval",
  "action": "aws[profile=dev]:ec2:DescribeInstances",
  "verdict": "approved",
  "risk_tier": "safe",
  "wait_ms": 2340
}
```

**`lifecycle`** — session start/end:

```json
{"ts": "...", "session": "8f3a-29c1", "event": "session_start", "command": "claude-code", "templates": ["aws-debug"]}
{"ts": "...", "session": "8f3a-29c1", "event": "session_end", "duration_s": 1823, "total_decisions": 47, "denied": 3}
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
| `serde` / `serde_json` / `serde_yaml` | Config (YAML), permission tree + IPC + audit (JSON) |
| `clap` | CLI argument parsing |
| `ratatui` / `crossterm` | Terminal UI |

No special crate for seatbelt — the profile is a generated `.sb` file passed to `sandbox-exec` via `std::process::Command`.

---

## Binaries

```
cs             (host-side daemon + proxy + CLI + TUI)
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

For untrusted agents requiring VM-level isolation, launch inside an Apple Container (Virtualization.framework). Same proxy, same permission tree — just swap the process wrapper. The agent runs in a lightweight Linux VM with full namespace/seccomp support internally.

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
| P2 | Agent runs `aws s3 ls` through proxy (no permission in tree) | Proxy parses `aws[profile=...]:s3:ListBuckets`, blocks for human approval |
| P3 | Manually add `permit aws[profile=*]:s3:List*` to tree, re-run `aws s3 ls` | Proxy matches permit, forwards request, agent gets bucket list |
| P4 | Agent makes request to unknown host | Proxy parses as `net:METHOD:host/path`, returns deny |
| P5 | Verify CA is persistent | Two `cs` invocations reuse same CA from `~/.closedshell/ca.pem` |
| P6 | Verify upstream TLS works | Proxy connects to real upstream with system trust store (not ClosedShell CA) |

### Session Lifecycle

| # | Test | Pass condition |
|---|------|---------------|
| L1 | `cs -- /bin/sh` | Sandbox starts, proxy listening, Unix socket exists, MOTD displayed |
| L2 | Agent exits | Proxy stops, tmpdir removed, socket gone |
| L3 | `cs -- claude` with `passthrough_env` in config | Configured env vars available inside sandbox |
| L4 | Kill daemon while agent is running | Agent's next network call fails cleanly (connection refused, not hang) |

### TUI + IPC

| # | Test | Pass condition |
|---|------|---------------|
| A1 | TUI connects to running session | Shows current rules and live activity |
| A2 | Unknown action triggers pending approval | Action appears in TUI approvals tab, proxy blocks |
| A3 | Human approves in TUI | Rule added to tree, proxy forwards request |
| A4 | Human denies in TUI | Proxy returns 403 to agent |

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
| T11 | Expired idempotent rule → evaluate action | DENY (expired rule skipped) |
| T12 | Two templates loaded, second adds permit overlapping first's forbid | Forbid wins (forbid-overrides-permit) |

### End-to-End (requires all sections)

| # | Test | Pass condition |
|---|------|---------------|
| E1 | Agent runs `aws s3 ls` in fresh session with `aws-debug` template | Template permits `List*` → proxy forwards → agent gets response, < 5ms added latency |
| E2 | Agent runs `aws s3 rm s3://bucket/key` in session with `aws-debug` template | Template forbids `Delete*` → DENY, hard block |
| E3 | Agent runs `aws ec2 describe-instances` (no template) | Proxy holds request → appears in TUI → human approves → permit added → agent gets response |
| E4 | Agent runs `aws ec2 terminate-instances` → human denies in TUI | DENY returned to agent |
| E5 | One-shot consumed → agent retries same action | Second attempt denied, agent told to re-request |

---

## Security Boundaries

| Layer | Mechanism | Bypass Resistance |
|-------|-----------|-------------------|
| Process isolation | Platform-specific (namespaces / seatbelt) | Kernel-level |
| Syscall filtering | seccomp-bpf (Linux) / seatbelt (macOS) | Kernel-level |
| Network egress | All traffic forced through proxy | No network without proxy |
| API enforcement | L7 proxy parsing + permission tree | Catches all HTTP |
| Credential isolation | Mounted in sandbox, but proxy enforces | Agent can't bypass proxy |
| Human approval | Unknown actions block until human decides in TUI | Deterministic, no AI in the loop |
