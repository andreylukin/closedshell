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
│  │   ask       │ │ deny     │ │ → inject credentials  │ │
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
│  │  • deny file-write* (except sandbox tmpdir)         ││
│  │  • process-exec allowlist                           ││
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
3. Generates a leaf cert for that hostname, signed by session-scoped CA
4. Terminates TLS → reads HTTP request
5. Parses the request into a canonical action (`aws:s3:ListBuckets`, `gh:repos/*/pulls:POST`, etc.)
6. Checks the permission tree
7. If unknown → implicit ask to judge → approve/escalate/deny
8. If approved → establishes upstream TLS, injects credentials from vault, relays

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

### Process Execution (seatbelt, static)

Seatbelt controls which binaries can execute via `process-exec` rules. This is a static allowlist — no runtime supervisor callback like Linux's seccomp-notify.

```scheme
(allow process-exec
  (literal "/bin/sh")
  (literal "/bin/bash")
  (literal "/usr/bin/env")
  (literal "/usr/local/bin/aws")
  (literal "/usr/local/bin/ask")
  ;; ... agent-specific binaries
)
```

### File System (seatbelt, static)

```scheme
(allow file-read*)                                    ; read anything
(deny file-write*)                                    ; deny writes by default
(allow file-write* (subpath "/tmp/closedshell-XXXX")) ; except sandbox tmpdir
```

---

## Session Lifecycle

```
closedshell create -- <agent-command>

1. Generate session ID + session-scoped CA cert/key
2. Write CA cert to sandbox tmpdir
3. Generate seatbelt profile (.sb file)
4. Start MITM proxy on localhost:8443
5. Start Unix socket listener for `ask` CLI
6. Exec:
   sandbox-exec -f /tmp/closedshell-XXXX/profile.sb \
     env HTTPS_PROXY=http://localhost:8443 \
         HTTP_PROXY=http://localhost:8443 \
         SSL_CERT_FILE=/tmp/closedshell-XXXX/ca.pem \
         CLOSEDSHELL_SOCKET=/tmp/closedshell-XXXX/ask.sock \
     -- <agent-command>
7. Agent runs. All HTTPS → proxy. `ask` CLI → Unix socket.
8. On exit: tear down proxy, remove tmpdir, clear permission tree.
```

---

## Crate Stack

| Crate | Role |
|---|---|
| `tokio` | Async runtime for proxy + daemon |
| `rustls` | TLS termination + upstream TLS |
| `rcgen` | Session CA + dynamic cert generation per SNI |
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
| Runtime exec interception | Supervisor callback per execve | Static allowlist only |
| Namespace isolation (pid/mount/net) | Full | None (process-level sandbox) |
| Network interception | iptables + transparent proxy | Env-var proxy + seatbelt deny |
| File isolation | Mount namespace + overlayfs | Seatbelt path rules |
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
| S3 | Process inside sandbox runs `touch /tmp/outside-sandbox/file` | Permission denied — seatbelt blocks writes outside tmpdir |
| S4 | Process inside sandbox runs `touch $SANDBOX_TMPDIR/file` | Succeeds — tmpdir is writable |
| S5 | Process inside sandbox runs `/usr/bin/python3` (not in allowlist) | Exec denied by seatbelt |
| S6 | Process inside sandbox runs `/bin/sh` (in allowlist) | Exec succeeds |

### Proxy + TLS

| # | Test | Pass condition |
|---|------|---------------|
| P1 | Agent runs `curl https://httpbin.org/get` through proxy | Proxy intercepts: TLS terminated with session CA, request logged, action parsed as `net:GET:httpbin.org/get` |
| P2 | Agent runs `aws s3 ls` through proxy (no permission in tree) | Proxy parses `aws[profile=...]:s3:ListBuckets`, returns deny (no judge yet in Section 1) |
| P3 | Manually add `permit aws[profile=*]:s3:List*` to tree, re-run `aws s3 ls` | Proxy matches permit, forwards request, agent gets bucket list |
| P4 | Agent makes request to unknown host | Proxy parses as `net:METHOD:host/path`, returns deny |
| P5 | Verify session CA is unique per session | Two `closedshell create` invocations produce different CA fingerprints |
| P6 | Verify upstream TLS works | Proxy connects to real upstream with system trust store (not session CA) |

### Session Lifecycle

| # | Test | Pass condition |
|---|------|---------------|
| L1 | `closedshell create -- /bin/sh` | Sandbox starts, proxy listening, Unix socket exists, MOTD displayed |
| L2 | Agent exits | Proxy stops, tmpdir removed, socket gone |
| L3 | `closedshell create` with credential mounts | `~/.aws/credentials` readable inside sandbox, env vars set |
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
| T5 | State-dependent with `when` condition → condition passes | ALLOW |
| T6 | State-dependent with `when` condition → condition fails | DENY, rule auto-revoked |
| T7 | `when` condition with cached result within `max_staleness` | Uses cache, no re-execution |
| T8 | Glob `aws[profile=*]:s3:List*` matches `aws[profile=dev]:s3:ListBuckets` | Match |
| T9 | Glob `aws[profile=dev]:s3:List*` does NOT match `aws[profile=prod]:s3:ListBuckets` | No match |
| T10 | Template merge: two templates loaded, forbid from first cannot be removed by second | Forbid persists |
| T11 | Plan revocation: revoke plan-id removes all rules with that plan_id | All child rules gone |
| T12 | Forbid `file:read:/Users/*/.ssh/*`, evaluate `file:read:/Users/andrey/.ssh/id_rsa` | DENY |
| T13 | Permit `file:write:/Users/andrey/repos/*`, evaluate `file:write:/Users/andrey/repos/foo.txt` | ALLOW |
| T14 | No permit for `file:write:/etc/passwd`, evaluate | DENY (default deny) |

### File I/O

| # | Test | Pass condition |
|---|------|---------------|
| F1 | Agent runs `ask write /Users/andrey/repos/test.txt "hello"` with matching permit | Daemon writes file on host side, agent gets confirmation |
| F2 | Agent runs `ask write /Users/andrey/.ssh/config "..."` with forbid on dotfiles | DENY, file not written |
| F3 | Agent runs `echo hi > /Users/andrey/repos/test.txt` directly (no `ask`) | Permission denied — Seatbelt blocks writes outside tmpdir |
| F4 | Agent runs `cat /Users/andrey/repos/test.txt` directly | Succeeds — Seatbelt allows reads |
| F5 | Agent runs `ask read /Users/andrey/.ssh/id_rsa` with forbid on `.ssh/*` | DENY, content not returned |
| F6 | Agent runs `cat /Users/andrey/.ssh/id_rsa` directly | Succeeds (Seatbelt allows reads) — this is the audit gap we accept |

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
| `when` condition enforcement | Point-of-use verification in proxy | No stale-grant window |
| Credential isolation | Mounted in sandbox, but proxy enforces | Agent can't bypass proxy |
| Judge isolation | Structured input only, single model | Agent can't prompt-inject judge |
| Judge failure mode | Timeout/error = deny | Fail closed, always |
