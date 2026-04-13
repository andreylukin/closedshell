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

What we don't take from Cedar: its full policy *language*. We use a lightweight Cedar-inspired DSL (`.csp` files) for templates, plus human approvals via the TUI. We take Cedar's **evaluation model** and **data model**.

---

## Permission Format

Every permission in the tree is a **rule** (`Rule` struct in `permission.rs`) with an effect:

```
Rules in a session:

  # Forbid rules — evaluated first, override everything
  id: "f-001"
  effect: Forbid
  action: "aws[profile=prod]:*:Delete*"
  reason: "session policy: no production deletes"
  source: "template:restrict-prod"

  id: "f-002"
  effect: Forbid
  action: "aws[profile=prod]:*:Terminate*"
  reason: "session policy: no production terminates"
  source: "template:restrict-prod"

  # Permit rules — only checked if no forbid matches
  id: "template:aws-debug:0"
  effect: Permit
  action: "aws[profile=dev]:ec2:Describe*"
  rule_type: Idempotent
  source: "template:aws-debug"

  id: "p-002"
  effect: Permit
  action: "aws[profile=prod]:ecs:UpdateService"
  rule_type: OneShot { consumed: false }
  approved_by: "human"
  expires: "2026-04-03T16:00:00Z"

  id: "p-003"
  effect: Permit
  action: "net:GET:api.github.com/repos/*"
  rule_type: Idempotent
  approved_by: "human"
```

### Key properties

1. **`effect` field** — every rule is explicitly `Permit` or `Forbid` (Cedar's model). No implicit "everything is a permit."
2. **Two permit types only** — `Idempotent` (persistent) and `OneShot` (consumed on use). Stored in the `rule_type` field.
3. **Forbid rules are first-class** — durable rules in the tree that can't be overridden by any permit.
4. **`source`** — tracks origin (e.g. `template:anthropic-full`). Set for template-loaded rules.
5. **`approved_by`** — tracks who authorized a permit (e.g. `human`). Set for human-approved rules.

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

**Why glob, not regex:** Glob is sufficient for hierarchical action matching and is statically analyzable — you can determine if two patterns overlap, if one subsumes another, or if a forbid makes a permit unreachable. Full regex makes these analyses undecidable. The `*` wildcard matches any characters including `/` separators (internally promoted to `**` for cross-segment matching). No `.*`, no `[a-z]+`, no lookahead.

### Generic actions

Non-cloud HTTP falls back to `net:METHOD:host/path`:

```
net:GET:api.github.com/repos/foo/bar
net:POST:hooks.slack.com/services/T00/B00/xxx
```

---

## Rule Types

### `Idempotent`

Persistent for the session. Once granted, matches on every subsequent request. Safe reads, listing operations. Template-loaded permits are always `Idempotent`.

```
effect: Permit
action: "aws[profile=dev]:s3:List*"
rule_type: Idempotent
source: "template:aws-debug"
```

### `OneShot`

Consumed on first use. Skipped on subsequent evaluations (the `consumed` flag flips to `true`). For state-changing operations where you want explicit, single-use authorization.

```
effect: Permit
action: "aws[profile=prod]:ecs:UpdateService"
rule_type: OneShot { consumed: false }
approved_by: "human"
```

### `Forbid`

Hard deny. No `rule_type` field — forbids are always active for the session (or until explicitly removed by the operator, not the agent).

```
effect: Forbid
action: "aws[profile=prod]:*:Delete*"
reason: "org policy: no production deletes in automated sessions"
source: "template:restrict-prod"
```

---

## Forbid Rule Sources

Forbid rules can come from multiple sources:

1. **Template** — Loaded from `.csp` template files at session start. Tagged `source: template:<name>`.
2. **Human operator** — Added via TUI during a session.

The agent **cannot** create forbid rules. This is deliberate — the agent shouldn't be able to restrict its own permissions in a way that prevents recovery.

---

## Rule Metadata

### `approved_by`

Tracks who authorized a permit rule. Currently set to `"human"` for rules approved via the TUI. Template-loaded rules leave this `None` (they use `source` instead).

### `source`

Tracks where a rule came from. Template-loaded rules are tagged `"template:<name>"` (e.g. `"template:anthropic-full"`). Used for both permit and forbid rules loaded from templates.

---

## Risk Classification

Actions are classified at runtime into risk tiers (`safe`, `moderate`, `dangerous`) by the `risk::classify_risk` function. This classification is used for display in the TUI and in denial responses — it does not affect evaluation. The permission tree itself does not validate rules against a schema; any well-formed action glob is accepted.

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

Templates use the `.csp` (ClosedShell Policy) format — a Cedar-inspired declarative syntax:

```
# templates/anthropic/full.csp
@name("anthropic-full")
@description("Allow all Anthropic API, MCP proxy, and Claude Code infra endpoints")

permit (action == "net:*:api.anthropic.com/*");
permit (action == "net:*:mcp-proxy.anthropic.com/*");

forbid (action == "net:*:api.anthropic.com/admin/*")
  reason("admin access blocked");
```

```
# templates/github/readonly.csp
@name("github-readonly")
@description("Allow read-only GitHub API access (GET only)")

permit (action == "net:GET:api.github.com/*");
permit (action == "net:GET:github.com/*");
```

### Storage

Built-in templates are compiled into the binary from the `templates/` directory. User templates live in `~/.closedshell/templates/` and override built-in ones with the same name. See [templates/CONTRIBUTING.md](../templates/CONTRIBUTING.md) for the full format reference.

### Usage

Templates are specified at session creation and merged in order:

```
cs \
  --template aws-debug \
  --template github-readonly \
  -- claude
```

Merge rules:
- Templates are applied in order. Later templates can add rules but **cannot remove forbids** from earlier templates.
- Forbid rules from templates are tagged `source: template:<name>` and cannot be removed within the session.
- Permit rules from templates are tagged `source: template:<name>` and behave like any other permit.
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

All denials return a 403 with structured JSON and headers:

```
HTTP/1.1 403 Forbidden
Content-Type: application/json
X-ClosedShell-Denied: true
X-ClosedShell-Action: aws:ec2:TerminateInstances
X-ClosedShell-Reason: no matching permission
X-ClosedShell-Hint: pending human review in TUI

{
  "error": "denied_by_closedshell",
  "action": "aws:ec2:TerminateInstances",
  "reason": "no matching permission",
  "risk_tier": "dangerous",
  "denied_by": "decider",
  "hint": "pending human review in TUI",
  "message": "[ClosedShell] Denied aws:ec2:TerminateInstances — no matching permission. pending human review in TUI"
}
```

