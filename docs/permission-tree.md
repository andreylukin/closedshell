# Permission Tree Design — Cedar-Inspired Model

**Decision:** Adopt Cedar's evaluation semantics (forbid-overrides-permit, default deny, order-independent) with ClosedShell-specific extensions for one-shot tokens and credential qualifiers.

---

## Why Cedar

We evaluated AWS IAM, Cedar, Kubernetes RBAC, Zanzibar/SpiceDB, OPA/Rego, and capability-based systems (Capsicum, seL4, WASI). Cedar wins because:

| Property | Cedar | Why it matters for ClosedShell |
|---|---|---|
| **Forbid-overrides-permit** | Built-in, non-negotiable | Safety rails that can't be overridden |
| **Default deny** | Built-in | Fail closed — no permission = denied |
| **Order-independent** | Policies are a set, not a chain | No subtle ordering bugs |
| **Typed entities + schema** | Static validation before runtime | Catch bad permissions before they're used |
| **No wildcards in entity IDs** | Deliberate restriction | Fast matching, analyzable |
| **Conditions (when/unless)** | First-class | Not used — permissions are re-evaluated per request |

What we don't take from Cedar: its policy *language*. We don't need a DSL — permissions are created by templates, human approvals via the TUI, and the operator CLI. We take Cedar's **evaluation model** and **data model**.

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
    approved_by: template:aws-debug
    created: "2026-04-03T14:00:00Z"

  - id: "p-002"
    effect: permit
    action: "aws[profile=prod]:ecs:UpdateService"
    type: one-shot
    approved_by: human:@oncall
    consumed: false
    expires: "2026-04-03T16:00:00Z"

  - id: "p-003"
    effect: permit
    action: "net:GET:api.github.com/repos/.*"
    type: idempotent
    approved_by: human:andrey
```

### Key differences from current spec

1. **`effect` field** — every rule is explicitly `permit` or `forbid` (Cedar's model). No implicit "everything is a permit."
2. **Two permit types only** — `idempotent` (persistent) and `one-shot` (consumed on use).
3. **Forbid rules are first-class** — durable rules in the tree that can't be overridden by any permit.

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

3. NO MATCH (block for human approval)
   Hold request → submit to approval queue
   Request appears in TUI approvals tab
   Human approves → add new permit rule to tree → return ALLOW
   Human denies → return DENY(reason)
   Timeout → return DENY("approval timeout")
```

### Properties (inherited from Cedar)

- **Forbid always wins.** A forbid rule cannot be overridden by a permit or by human approval. It's a hard safety rail.
- **Default deny.** No matching rule = denied (blocked for human approval).
- **Order-independent.** Rules are evaluated as a set. The first matching forbid denies. Among permits, the first match wins (but any forbid would have already fired).
- **Fail closed.** Approval timeout, any error = deny.

---

## Action Format

Actions use a structured string format with provider qualifiers:

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

---

## Rule Types

### `idempotent`

Persistent for the session. Once granted, matches on every subsequent request. Safe reads, listing operations.

```yaml
- effect: permit
  action: "aws[profile=dev]:s3:List*"
  type: idempotent
  approved_by: template:aws-debug
```

### `one-shot`

Consumed on first use. Automatically removed from the tree after a single successful match. For state-changing operations where you want explicit, single-use authorization.

```yaml
- effect: permit
  action: "aws[profile=prod]:ecs:UpdateService"
  type: one-shot
  approved_by: human:@oncall
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
3. **Human operator** — Added via TUI rule editor or `closedshell forbid` on the host side during a session.
4. **Template** — Loaded from template files. Cannot be removed within a session.

The agent **cannot** create forbid rules. This is deliberate — the agent shouldn't be able to restrict its own permissions in a way that prevents recovery.

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

These are loaded before templates, cannot be removed by templates, the TUI rule editor, or the agent. They're tagged `source: org_baseline` and marked `# locked` in the editable rules file.

---

## Rule Metadata

### `approved_by` format

Tracks who authorized a permit rule:

| Format | Meaning | Example |
|--------|---------|---------|
| `human:<id>` | Approved by a human operator via TUI | `approved_by: human:andrey` |
| `template:<name>` | Loaded from a template | `approved_by: template:aws-debug` |

The `<id>` in `human:<id>` is a free-form string set in config (`operator_id: andrey`). Defaults to the system username. Used for audit trail only — no auth system behind it.

### `source` format (forbid rules)

| Format | Meaning | Removable? |
|--------|---------|------------|
| `org_baseline` | From global config | No |
| `session_policy` | From session flags/config | No |
| `template:<name>` | From a template | No |
| `human:<id>` | Added by operator during session | Yes (by operator only) |

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
| Human approval | O(human_latency) | Bounded by approval timeout (default 5 min) |

For the expected session sizes (< 100 rules), linear scan with string matching is fast enough. No need for a trie or compiled regex engine. If sessions grow larger, index rules by `provider:service` prefix.

---

## Templates

Templates are reusable rule sets that merge into the session tree at cold start. They provide a starting permission baseline so common actions don't require per-request human approval.

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
  -- claude
```

Merge rules:
- Templates are applied in order. Later templates can add rules but **cannot remove forbids** from earlier templates.
- Forbid rules from templates are tagged `source: template:<name>` and cannot be removed within the session.
- Permit rules from templates are tagged `approved_by: template:<name>` and behave like any other permit (can be revoked, can expire).
- If two templates define conflicting permits for the same action pattern, both are added (harmless — first match wins, and forbid-overrides-permit ensures safety).

Templates eliminate cold start latency: instead of the human approving `Describe*` on every session, the template pre-loads it.

---

## Flows

These walkthroughs show the evaluation algorithm in action.

### Template Hit (fast path)

The agent runs a command that matches a template rule. No human involvement.

```
Agent: aws s3 ls
  1. aws CLI → HTTPS request to s3.amazonaws.com
  2. Proxy parses: aws[profile=dev]:s3:ListBuckets
  3. Forbid check: no forbid matches
  4. Permit check: template rule matches aws[profile=*]:*:List* → ALLOW
  5. Proxy forwards original request
  6. Agent gets response as if nothing happened
  Total: < 5ms added latency
```

### Unknown Action (human approval path)

The agent runs a command with no matching rule.

```
Agent: aws ec2 terminate-instances --instance-ids i-abc123
  1. aws CLI → HTTPS request
  2. Proxy parses: aws[profile=dev]:ec2:TerminateInstances
  3. Forbid check: no forbid matches
  4. Permit check: no permit matches
  5. No match → proxy holds connection, submits to approval queue
  6. TUI shows pending approval with risk tier: dangerous
  7. Human reviews in TUI approvals tab → approves (or denies)
  8. If approved → permit rule added to tree → proxy forwards request
  9. If denied → proxy returns 403 to agent
```

### Forbid Block (hard deny)

The agent tries an action blocked by a forbid rule.

```
Agent: aws s3 rm s3://bucket/key
  1. aws CLI → HTTPS request
  2. Proxy parses: aws[profile=prod]:s3:DeleteObject
  3. Forbid check: matches "aws[profile=prod]:*:Delete*" → DENY
  4. Proxy returns 403 immediately (no approval queue, no human review)
  5. Agent sees denial with reason: "session policy: no production deletes"
```

### Denial UX

**Unknown action (pending approval):**
```
HTTP/1.1 403 Forbidden
X-ClosedShell-Denied: true

{
  "error": "denied",
  "action": "aws:ec2:TerminateInstances",
  "risk_tier": "dangerous",
  "hint": "pending human review in TUI"
}
```

**One-shot consumed:**
```
HTTP/1.1 403 Forbidden
X-ClosedShell-Denied: true

{
  "error": "denied",
  "action": "aws:ecs:UpdateService",
  "reason": "permission p-002 consumed (one-shot)",
  "hint": "pending human review in TUI"
}
```

---

## Comparison with Previous Design

| Aspect | Previous (v0.2) | Current (Cedar-inspired) |
|---|---|---|
| Effects | Allow-only (implicit) | Explicit `permit` / `forbid` |
| Safety rails | Flat allow list | Forbid rules are hard limits |
| Action matching | Regex | Glob |
| Unknown actions | Default deny | Block for human approval via TUI |
| Schema validation | Not specified | Compile-time validation against risk taxonomy |
| Evaluation model | Check tree → deny | Forbid check → permit check → human approval → deny |
