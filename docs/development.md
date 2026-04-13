# Development Sections

The project is broken into independently iterable sections, ordered by dependency.

---

## Section 1: Sandbox + Daemon + Proxy (the enforcement plane)

Everything that makes the sandbox work end-to-end. This is one integrated deliverable because the sandbox setup, daemon IPC, and proxy are tightly coupled.

**Scope:**
- Platform sandbox (macOS: seatbelt) — see [architecture.md](architecture.md)
- Host-side daemon process + Unix socket IPC
- Transparent MITM proxy with session-scoped CA
- Provider parsers (generic `net:METHOD:host/path` first, then AWS/GCP/etc.) — see [proxy.md](proxy.md)
- Environment variable passthrough for credentials — see [proxy.md](proxy.md)
- Tree lookup on every request — unknown = block for human approval
- `closedshell <cmd>` lifecycle + session persistence (SQLite)

**Deliverable:** A locked sandbox where all network traffic is intercepted, parsed, and checked against the permission tree. End-to-end from `closedshell claude` to denied/approved request.

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

## Section 3: Enforcing Mode + Human Approval

Unknown actions block for human approval in the TUI. Deterministic — no AI in the decision loop.

**Scope:**
- EnforcingDecider: tree permit → allow, tree forbid → hard deny, no match → block for human
- Approval queue with oneshot channels (proxy holds connection)
- Risk classification (safe/moderate/dangerous) for TUI display

**Deliverable:** Enforcing mode works end-to-end — unknown actions appear in TUI, human approves/denies, proxy forwards or blocks.

---

## Section 4: TUI

The management interface and escalation path. See [architecture.md § TUI](architecture.md#tui).

**Scope:**
- TUI with session list + session detail (live, rules, approvals tabs)
- Pending approval queue surfaced in TUI approvals tab
- Approve/deny pending requests from TUI
- Rule editing via `$EDITOR` with hot-reload
- Add forbid rules inline from TUI

**Deliverable:** `closedshell` (no args) opens a TUI. Human can watch decisions live, approve/deny pending actions, and edit rules.

---

## Dependency Graph

```
Section 2 (permission tree) ── starts day one, consumed by Section 1

Section 1 (sandbox+daemon+proxy) ──→ Section 3 (enforcing + human approval)
                                 ──→ Section 4 (TUI)
```

## Recommended Build Order (solo dev)

1. **Section 1 + Section 2** in parallel
2. **Section 3** (enforcing mode + approval queue)
3. **Section 4** (TUI)
