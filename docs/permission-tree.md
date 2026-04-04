# Permission Tree Design — Cedar-Inspired Model

**Decision:** Adopt Cedar's evaluation semantics (forbid-overrides-permit, default deny, order-independent) with ClosedShell-specific extensions for one-shot tokens and credential qualifiers.

---

## Why Cedar

We evaluated AWS IAM, Cedar, Kubernetes RBAC, Zanzibar/SpiceDB, OPA/Rego, and capability-based systems (Capsicum, seL4, WASI). Cedar wins because:

| Property | Cedar | Why it matters for ClosedShell |
|---|---|---|
| **Forbid-overrides-permit** | Built-in, non-negotiable | Safety rails the judge can't override |
| **Default deny** | Built-in | Fail closed — no permission = denied |
| **Order-independent** | Policies are a set, not a chain | No subtle ordering bugs |
| **Typed entities + schema** | Static validation before runtime | Catch bad permissions before they're used |
| **No wildcards in entity IDs** | Deliberate restriction | Fast matching, analyzable |
| **Conditions (when/unless)** | First-class | Not used — judge re-evaluates per request instead |

What we don't take from Cedar: its policy *language*. We don't need a DSL — permissions are created programmatically by the judge, human approvals, and the `ask` CLI. We take Cedar's **evaluation model** and **data model**.

---

## Permission Format

Every permission in the tree is a **rule** with an effect:

```yaml
session: "8f3a-29c1"
rules:
  # Forbid rules — evaluated first, override everything
  - id: "f-001"
    effect: forbid
    action: "aws[profile=prod]:*:Delete*"
    reason: "session policy: no production deletes"

  - id: "f-002"
    effect: forbid
    action: "aws[profile=prod]:*:Terminate*"
    reason: "session policy: no production terminates"

  # Permit rules — only checked if no forbid matches
  - id: "p-001"
    effect: permit
    action: "aws[profile=dev]:ec2:Describe*"
    type: idempotent
    approved_by: judge
    created: "2026-04-03T14:00:00Z"

  - id: "p-002"
    effect: permit
    action: "aws[profile=prod]:ecs:UpdateService"
    type: one-shot
    approved_by: human:@oncall
    plan_id: "plan-007"
    consumed: false
    expires: "2026-04-03T16:00:00Z"

  - id: "p-003"
    effect: permit
    action: "net:GET:api.github.com/repos/.*"
    type: idempotent
    approved_by: judge
```

### Key differences from current spec

1. **`effect` field** — every rule is explicitly `permit` or `forbid` (Cedar's model). No implicit "everything is a permit."
2. **Two permit types only** — `idempotent` (persistent) and `one-shot` (consumed on use). No `state-dependent` type — if the judge wants to be conservative, it grants a one-shot and the agent re-asks when needed.
3. **Forbid rules are first-class** — not just a deny response from the judge, but durable rules in the tree that can't be overridden.

---

## Evaluation Algorithm

Cedar-style, adapted for ClosedShell's real-time proxy context:

```
evaluate(action) -> ALLOW | DENY(reason)

1. FORBID CHECK
   For each rule where effect == forbid:
     If action matches rule.action pattern:
       → return DENY(rule.reason)

2. PERMIT CHECK (fast path)
   For each rule where effect == permit:
     If action matches rule.action pattern:
       a. If rule.type == idempotent:
            If expired → skip
            → return ALLOW

       b. If rule.type == one-shot:
            If rule.consumed → skip
            If expired → skip
            Mark rule.consumed = true
            → return ALLOW

3. NO MATCH (implicit ask or default deny)
   If implicit_ask enabled:
     Hold request → submit to judge
     Judge returns: approve | deny | escalate_human
     If approve → add new permit rule to tree → return ALLOW
     If deny → return DENY(reason)
     If escalate_human → return DENY("requires human approval, use: ask plan")
   Else:
     → return DENY("no matching permission")
```

### Properties (inherited from Cedar)

- **Forbid always wins.** A forbid rule cannot be overridden by a permit, by the judge, or by human approval. It's a hard safety rail.
- **Default deny.** No matching rule = denied.
- **Order-independent.** Rules are evaluated as a set. The first matching forbid denies. Among permits, the first match wins (but any forbid would have already fired).
- **Fail closed.** Judge timeout, any error = deny.

---

## Action Format

Actions use a structured string format with credential qualifiers:

```
provider[qualifier]:service:operation
```

### Components

| Component | Description | Examples |
|---|---|---|
| `provider` | Cloud/API provider | `aws`, `gcp`, `az`, `gh`, `k8s`, `net` |
| `qualifier` | Credential context (key=value) | `profile=dev`, `project=myproj`, `ctx=prod` |
| `service` | Provider service/API group | `ec2`, `s3`, `ecs`, `compute`, `repos` |
| `operation` | Specific API action | `DescribeInstances`, `ListBuckets`, `DELETE` |

### Matching

Action matching uses **glob patterns** (not regex):

| Pattern | Matches | Doesn't match |
|---|---|---|
| `aws[profile=dev]:ec2:Describe*` | `aws[profile=dev]:ec2:DescribeInstances` | `aws[profile=prod]:ec2:DescribeInstances` |
| `aws[profile=prod]:*:Delete*` | `aws[profile=prod]:s3:DeleteBucket` | `aws[profile=dev]:s3:DeleteBucket` |
| `net:GET:api.github.com/*` | `net:GET:api.github.com/repos/foo` | `net:POST:api.github.com/repos/foo` |
| `aws[profile=*]:s3:List*` | `aws[profile=dev]:s3:ListBuckets` | `gcp[project=x]:storage:ListBuckets` |

**Why glob, not regex:** Glob is sufficient for hierarchical action matching and is statically analyzable — you can determine if two patterns overlap, if one subsumes another, or if a forbid makes a permit unreachable. Full regex makes these analyses undecidable. The `*` wildcard matches any characters within a single segment or at the end of a pattern. No `.*`, no `[a-z]+`, no lookahead.

### Generic actions

Non-cloud HTTP falls back to `net:METHOD:host/path`:

```
net:GET:api.github.com/repos/foo/bar
net:POST:hooks.slack.com/services/T00/B00/xxx
```

### File I/O actions

File access through `ask read` / `ask write` uses the `file` provider:

```
file:read:/Users/andrey/repos/myproject/src/main.rs
file:write:/Users/andrey/repos/myproject/output.json
file:read:/etc/hosts
```

Same glob matching as network actions:

| Pattern | Matches |
|---|---|
| `file:read:/Users/andrey/repos/*` | Any file read under repos/ |
| `file:write:$SANDBOX_TMPDIR/*` | Writes to sandbox tmpdir |
| `file:read:*` | Read anything (template: dev-readonly) |

---

## File I/O Model (audit + control)

ClosedShell's threat model focuses on remote damage (cloud API abuse), not local mischief. File access reflects this:

| Operation | Enforcement | Mechanism |
|---|---|---|
| **Writes outside tmpdir** | **Enforced** | Seatbelt denies `file-write*` except tmpdir. Only way to write elsewhere is `ask write` → daemon writes on host side after permission check. |
| **Reads** | **Audited** | Agent can `cat` files directly (Seatbelt allows `file-read*`). `ask read` is the audited path — goes through permission tree, logged, judge can reason about it. |
| **Writes inside tmpdir** | **Unrestricted** | Agent's scratch space. No permission needed. |

### `ask read <path>`

1. `ask` CLI sends read request over Unix socket → daemon
2. Daemon evaluates `file:read:<path>` against permission tree (forbid → permit → implicit ask)
3. If permitted: daemon reads file on host side, returns content to agent
4. Logged with full path and timestamp

Agent can also `cat` the file directly — Seatbelt allows reads. But `ask read` gives the judge visibility and lets forbid rules block sensitive reads (e.g., `forbid file:read:/Users/*/.ssh/*`).

### `ask write <path> [content]`

1. `ask` CLI sends write request over Unix socket → daemon
2. Daemon evaluates `file:write:<path>` against permission tree
3. If permitted: daemon writes file on host side, confirms to agent
4. Logged with full path, size, and timestamp

This is the **only** way to write outside the sandbox tmpdir. Seatbelt enforces this — `deny file-write*` with tmpdir exception means the agent literally cannot write elsewhere on its own.

### Example rules

```yaml
# Template: dev-workspace
- effect: forbid
  action: "file:write:/Users/*/.*"
  reason: "no writing dotfiles (.ssh, .aws, .gitconfig, etc.)"

- effect: forbid
  action: "file:read:/Users/*/.ssh/*"
  reason: "no reading SSH keys"

- effect: permit
  action: "file:read:*"
  type: idempotent
  approved_by: template:dev-workspace

- effect: permit
  action: "file:write:/Users/andrey/repos/myproject/*"
  type: idempotent
  approved_by: template:dev-workspace
```

### Why not enforce reads too?

Enforcing reads (Seatbelt `deny file-read*`) would break every CLI tool — `aws`, `git`, `python`, `node` all read config files, shared libraries, and certificates. The tradeoff: reads are observable via `ask read` and blockable via forbid rules, but the agent *can* bypass them with direct file access. This matches the threat model — an agent reading your `.bashrc` is annoying, an agent `aws s3 rm --recursive` is catastrophic.

---

## Rule Types

### `idempotent`

Persistent for the session. Once granted, matches on every subsequent request. Safe reads, listing operations.

```yaml
- effect: permit
  action: "aws[profile=dev]:s3:List*"
  type: idempotent
  approved_by: judge
```

### `one-shot`

Consumed on first use. Automatically removed from the tree after a single successful match. For state-changing operations where you want explicit, single-use authorization.

```yaml
- effect: permit
  action: "aws[profile=prod]:ecs:UpdateService"
  type: one-shot
  approved_by: human:@oncall
  plan_id: "plan-007"
```

### `forbid`

Hard deny. No type field — forbids are always active for the session (or until explicitly removed by the operator, not the agent).

```yaml
- effect: forbid
  action: "aws[profile=prod]:*:Delete*"
  reason: "org policy: no production deletes in automated sessions"
  source: org_baseline  # or: session_policy, human:@admin
```

---

## Forbid Rule Sources

Forbid rules can come from multiple sources, in order of authority:

1. **Org baseline** — Baked into config. Applied to every session. Cannot be removed within a session.
2. **Session policy** — Set at `closedshell` start time via flags or config. Cannot be modified by the agent.
3. **Human operator** — Added via `closedshell forbid` on the host side during a session.
4. **Judge** — The judge can propose forbid rules (e.g., "this agent keeps trying to delete things, add a forbid"). Requires human confirmation.

The agent **cannot** create forbid rules via `ask`. This is deliberate — the agent shouldn't be able to restrict its own permissions in a way that prevents recovery.

### Org Baseline

Forbid rules that apply to every session. Defined in the global config file (`~/.closedshell/config.yaml`) under `baseline_forbids`:

```yaml
# ~/.closedshell/config.yaml
baseline_forbids:
  - action: "aws[profile=prod]:*:Delete*"
    reason: "org policy: no production deletes"
  - action: "aws[profile=prod]:*:Terminate*"
    reason: "org policy: no production terminates"
```

These are loaded before templates, cannot be removed by templates, the judge, the TUI rule editor, or the agent. They're tagged `source: org_baseline` and marked `# locked` in the editable rules file.

---

## Rule Metadata

### `approved_by` format

Tracks who authorized a permit rule:

| Format | Meaning | Example |
|--------|---------|---------|
| `judge` | Auto-approved by judge | `approved_by: judge` |
| `human:<id>` | Approved by a human operator | `approved_by: human:andrey` |
| `template:<name>` | Loaded from a template | `approved_by: template:aws-debug` |

The `<id>` in `human:<id>` is a free-form string set in config (`operator_id: andrey`). Defaults to the system username. Used for audit trail only — no auth system behind it.

### `source` format (forbid rules)

| Format | Meaning | Removable? |
|--------|---------|------------|
| `org_baseline` | From global config | No |
| `session_policy` | From session flags/config | No |
| `template:<name>` | From a template | No |
| `human:<id>` | Added by operator during session | Yes (by operator only) |
| `judge` | Proposed by judge, confirmed by human | Yes (by operator only) |

---

## Plan Derivation and Revocation

When a plan is approved (`ask plan`), it creates a set of permit rules linked by `plan_id`. Revoking a plan revokes all derived rules:

```
ask plan "rollback ECS deployment"
  → judge proposes permissions
  → human approves
  → tree gains:
      p-010: permit aws[profile=prod]:ecs:DescribeServices  (idempotent, plan-012)
      p-011: permit aws[profile=prod]:ecs:UpdateService     (one-shot, plan-012)
      p-012: permit aws[profile=prod]:ecs:DescribeTaskDefinition (idempotent, plan-012)

closedshell revoke-plan plan-012
  → removes p-010, p-011, p-012
```

This follows seL4's capability derivation tree model: revoking a parent revokes all children.

---

## Schema (compile-time validation)

The permission tree validates rules against a schema derived from the risk taxonomy:

```yaml
providers:
  aws:
    qualifiers: [profile]
    services:
      ec2:
        safe:      [Describe*, List*, Get*]
        moderate:  [Create*, Start*, Stop*, Update*, Tag*]
        dangerous: [Delete*, Terminate*, Remove*, Revoke*, Detach*]
      s3:
        safe:      [List*, Get*, Head*]
        moderate:  [Put*, Create*]
        dangerous: [Delete*]
      # ...
  gcp:
    qualifiers: [project]
    services:
      compute:
        safe:      [list, get, aggregatedList]
        moderate:  [insert, patch, update, start, stop]
        dangerous: [delete]
      # ...
  net:
    qualifiers: []
    methods: [GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS]
```

Validation checks:
- Action string parses correctly (provider, qualifier, service, operation)
- Provider exists in schema
- Qualifier keys are valid for that provider
- Operation matches at least one known pattern (warning if not — could be a new API)
- Forbid rules on `dangerous` tier operations are flagged as expected
- Permit rules on `dangerous` tier operations require `approved_by: human:<id>`

---

## Evaluation Complexity

| Operation | Cost | Notes |
|---|---|---|
| Forbid check | O(F) where F = forbid rule count | Typically < 10 rules. Linear scan is fine. |
| Permit match (idempotent) | O(P) where P = permit rule count | Typically < 50 rules. Linear scan is fine. Index by provider prefix if needed. |
| Implicit ask (judge) | O(judge_latency) | Bounded by `timeout_ms` (default 5s) |

For the expected session sizes (< 100 rules), linear scan with string matching is fast enough. No need for a trie or compiled regex engine. If sessions grow larger, index rules by `provider:service` prefix.

---

## Templates

Templates are reusable rule sets that merge into the session tree at cold start. They provide a starting permission baseline so the judge doesn't have to re-derive common patterns from scratch every session.

```yaml
# templates/aws-debug.yaml
name: aws-debug
description: "Read-only AWS access for investigation workflows"
rules:
  - effect: forbid
    action: "aws[profile=prod]:*:Delete*"
    reason: "template: no production deletes"
  - effect: forbid
    action: "aws[profile=prod]:*:Terminate*"
    reason: "template: no production terminates"
  - effect: permit
    action: "aws[profile=*]:*:Describe*"
    type: idempotent
  - effect: permit
    action: "aws[profile=*]:*:List*"
    type: idempotent
  - effect: permit
    action: "aws[profile=*]:*:Get*"
    type: idempotent
```

```yaml
# templates/github-readonly.yaml
name: github-readonly
description: "Read-only GitHub API access"
rules:
  - effect: permit
    action: "gh[*]:repos/*/GET"
    type: idempotent
  - effect: permit
    action: "gh[*]:repos/*/pulls:GET"
    type: idempotent
```

### Storage

Templates are YAML files in `~/.closedshell/templates/` (configurable via `templates_dir` in config). Each file is a template. The filename (minus `.yaml`) is the template name used with `--template`.

### Usage

Templates are specified at session creation and merged in order:

```
closedshell \
  --template aws-debug \
  --template github-readonly \
  pi
```

Merge rules:
- Templates are applied in order. Later templates can add rules but **cannot remove forbids** from earlier templates.
- Forbid rules from templates are tagged `source: template:<name>` and cannot be removed by the agent or judge within the session.
- Permit rules from templates are tagged `approved_by: template:<name>` and behave like any other permit (can be revoked, can expire).
- If two templates define conflicting permits for the same action pattern, both are added (harmless — first match wins, and forbid-overrides-permit ensures safety).

Templates are the answer to cold start latency: instead of the judge re-approving `Describe*` on every session, the template pre-loads it. The judge still handles everything outside the template.

---

## Flows

These walkthroughs show the evaluation algorithm in action.

### Implicit Ask (primary path)

The default flow. The agent just runs commands. No `ask` needed for the happy path.

```
Agent: aws s3 ls
  1. aws CLI → HTTPS request to s3.amazonaws.com
  2. Proxy parses: aws[profile=dev]:s3:ListBuckets
  3. Forbid check: no forbid matches
  4. Permit check: no permit matches (or template hit → ALLOW immediately)
  5. Implicit ask → judge: {action, risk: "safe", ...}
  6. Judge: approve → new permit rule: aws[profile=dev]:s3:List*
  7. Proxy forwards original request (no retry needed)
  8. Agent gets response as if nothing happened
  Total: < 200ms (agent never sees a denial)
```

**Key insight:** The proxy holds the outbound request while the judge evaluates. The agent doesn't need to retry. For safe actions, this adds ~100ms of latency on first access — invisible to most agents. With templates, common actions hit step 4 and skip the judge entirely.

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
  6. Added to tree → returned to CLI
  Total: < 200ms
```

### Plan Approval (ask plan)

The agent sends a free-text description. The judge — not the agent's LLM — decomposes it into a minimal permission set. See [judge.md § Plan Evaluation](judge.md#plan-evaluation-ask-plan) for judge I/O format.

```
Agent: ask plan "Rollback bad ECS deployment"
  1. ask CLI → daemon: {type: "plan", description: "Rollback bad ECS deployment"}
  2. Daemon → judge: {plan_description, current_tree, session_context, credentials_available}
  3. Judge returns: proposed rules (permits with types and risk levels)
  4. Daemon validates rules against schema + existing forbids
  5. Safe actions → auto-approved, added to tree immediately
  6. Moderate/dangerous → queued for human approval
  7. Daemon → ask CLI: {plan_id: "plan-013", auto_approved: [...], pending_human: [...]}
  8. Agent starts working with auto-approved permissions immediately
  9. Human approves remaining via CLI/Slack → rules added to tree
  10. Implicit ask fills gaps at runtime if the plan didn't anticipate every action
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

### Denial UX

**Implicit ask denied:**
```
DENIED: aws:ec2:TerminateInstances (i-abc123)

  Risk tier: dangerous (destructive)
  Judge decision: escalate_human

  This action requires human approval.
  Run:  ask plan "describe your goal"
```

**One-shot consumed:**
```
DENIED: aws:ecs:UpdateService (permission p-002 consumed)

  This was a one-shot permission and has been used.

  To re-request:  ask allow "aws:ecs:UpdateService"
```

---

## Comparison with Previous Design

| Aspect | Previous (v0.2) | New (Cedar-inspired) |
|---|---|---|
| Effects | Allow-only (implicit) | Explicit `permit` / `forbid` |
| Safety rails | Judge decides everything | Forbid rules are hard limits |
| Action matching | Regex | Glob |
| Conditions | `preconditions` | Removed — judge re-evaluates on each request |
| Plan revocation | Not specified | Derivation tree — revoke plan = revoke all children |
| Schema validation | Not specified | Compile-time validation against risk taxonomy |
| Evaluation model | Check tree → ask judge → deny | Forbid check → permit check → implicit ask → deny |
