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
