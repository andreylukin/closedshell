# Development Sections

The project is broken into independently iterable sections, ordered by dependency.

---

## Section 1: Sandbox + Daemon + Proxy (the enforcement plane)

Everything that makes the sandbox work end-to-end. This is one integrated deliverable because the sandbox setup, daemon IPC, and proxy are tightly coupled.

**Scope:**
- Platform sandbox (Linux: namespaces + seccomp-bpf, macOS: seatbelt) — see [architecture.md](architecture.md)
- Host-side daemon process + Unix socket IPC
- `ask` CLI skeleton (read-only commands first: status, why-denied)
- Transparent MITM proxy with session-scoped CA
- Provider parsers (generic `net:METHOD:host/path` first, then AWS/GCP/etc.) — see [proxy.md](proxy.md)
- Credential mounts (file, env, socket, oauth with daemon-side refresh) — see [proxy.md](proxy.md)
- Tree lookup on every request — unknown = deny (no judge yet)
- `closedshell <cmd>` lifecycle + session persistence (SQLite)

**Deliverable:** A locked sandbox where all network traffic is intercepted, parsed, and checked against the permission tree. End-to-end from `closedshell pi` to denied/approved request.

---

## Section 2: Permission Tree

Standalone, fully unit-testable data structure. No system dependencies — can start day one alongside Section 1. Design: [permission-tree.md](permission-tree.md).

**Scope:**
- In-memory permission store, session-scoped
- Cedar-inspired evaluation: forbid-overrides-permit, default deny
- Permission types: idempotent, one-shot
- Glob matching, expiry, consumption logic
- Schema validation against risk taxonomy
- CRUD via internal API

**Deliverable:** A well-tested library that Section 1 consumes for tree lookups.

---

## Section 3: Judge Integration

Plugs into the proxy to make real permission decisions. Design: [judge.md](judge.md).

**Scope:**
- OpenAI-compatible API client (structured JSON I/O)
- Risk taxonomy (baked-in + config override)
- Decision matrix (safe→approve, dangerous→escalate, timeout→deny)
- Implicit ask flow (proxy holds request while judge evaluates)
- Explicit `ask allow` and `ask plan` flows

**Deliverable:** Judge makes real decisions. Implicit ask works end-to-end — agent runs a command, proxy intercepts, judge evaluates, permission granted or denied transparently.

---

## Section 4: TUI + Human Approval

The management interface and escalation path. The TUI replaces ad-hoc host-side CLI commands. See [architecture.md § TUI](architecture.md#tui).

**Scope:**
- TUI with session list + session detail (live, rules, approvals, history tabs)
- Pending approval queue in daemon, surfaced in TUI approvals tab
- Approve/deny pending requests from TUI
- Rule editing via `$EDITOR` with hot-reload
- Add forbid rules inline from TUI
- Auto-approve timeouts per risk tier
- Webhook support (Slack, PagerDuty, custom endpoint)
- Plan context shown to approvers

**Deliverable:** `closedshell` (no args) opens a TUI. Human can watch decisions live, approve/deny escalations, and edit rules. `escalate_human` decisions block until resolved via TUI or webhook.

---

## Dependency Graph

```
Section 2 (permission tree) ── starts day one, consumed by Section 1

Section 1 (sandbox+daemon+proxy) ──→ Section 3 (judge)
                                 ──→ Section 4 (TUI + human approval)
```

## Recommended Build Order (solo dev)

1. **Section 1 + Section 2** in parallel
2. **Section 3** (judge — proxy becomes useful)
3. **Section 4** (TUI + human approval)
