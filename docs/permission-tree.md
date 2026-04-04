# Permission Tree Design — Cedar-Inspired Model

**Decision:** Adopt Cedar's evaluation semantics (forbid-overrides-permit, default deny, order-independent) with ClosedShell-specific extensions for one-shot tokens, preconditions, and credential qualifiers.

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
| **Conditions (when/unless)** | First-class | Maps directly to preconditions |

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
    when:
      - cmd: "aws ecs describe-services --service api --profile prod"
        jsonpath: ".services[0].runningCount"
        expect: ">= 2"
        max_staleness: "30s"
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
2. **`when` replaces `preconditions`** — aligns with Cedar's `when` clause terminology. Same semantics: conditions that must hold at point-of-use.
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
            If rule.when conditions exist → verify (see §3)
            Mark rule.consumed = true
            → return ALLOW

       c. If rule.type == state-dependent:
            If expired → skip
            Verify rule.when conditions (see §3)
            → return ALLOW

3. WHEN VERIFICATION (point-of-use)
   For each condition in rule.when:
     Check cache: if result exists and age < max_staleness → use cached
     Otherwise: execute cmd on host side (timeout: 5s)
     Extract value via jsonpath
     Evaluate expect expression
     If any condition fails:
       Auto-revoke the rule
       → return DENY("precondition failed: {detail}")

4. NO MATCH (implicit ask or default deny)
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
- **Fail closed.** Judge timeout, precondition timeout, any error = deny.

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

### `state-dependent`

Like idempotent, but with `when` conditions verified at point-of-use. Cached within `max_staleness` window. Auto-revoked if conditions fail.

```yaml
- effect: permit
  action: "aws[profile=prod]:ecs:UpdateService"
  type: state-dependent
  when:
    - cmd: "aws ecs describe-services --service api --profile prod"
      jsonpath: ".services[0].runningCount"
      expect: ">= 2"
      max_staleness: "30s"
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
2. **Session policy** — Set at `closedshell create` time via flags or config. Cannot be modified by the agent.
3. **Human operator** — Added via `closedshell forbid` on the host side during a session.
4. **Judge** — The judge can propose forbid rules (e.g., "this agent keeps trying to delete things, add a forbid"). Requires human confirmation.

The agent **cannot** create forbid rules via `ask`. This is deliberate — the agent shouldn't be able to restrict its own permissions in a way that prevents recovery.

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
- Permit rules on `dangerous` tier operations require `approved_by: human:*`

---

## Evaluation Complexity

| Operation | Cost | Notes |
|---|---|---|
| Forbid check | O(F) where F = forbid rule count | Typically < 10 rules. Linear scan is fine. |
| Permit match (idempotent) | O(P) where P = permit rule count | Typically < 50 rules. Linear scan is fine. Index by provider prefix if needed. |
| Precondition check (cached) | O(1) | Hash lookup on condition key |
| Precondition check (fresh) | O(timeout) | Bounded by `check_timeout` (default 5s) |
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

### Usage

Templates are specified at session creation and merged in order:

```
closedshell create \
  --template aws-debug \
  --template github-readonly \
  -- claude-code
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

```
Agent: ask plan "Rollback bad ECS deployment"
  1. Judge analyzes plan → proposes permission set
  2. Read-only actions: auto-approved immediately
  3. State-change/destructive: routed to human
  4. Human approves via CLI/Slack
  5. Full set added to tree (one-shots + when conditions)
  6. Agent executes at full speed against pre-approved tree
```

### State-Dependent Execution (point-of-use)

```
Agent: aws ecs update-service --service api --desired-count 4
  1. Proxy parses: aws[profile=prod]:ecs:UpdateService
  2. Forbid check: no forbid matches
  3. Permit match: p-002 (one-shot, has `when` conditions)
  4. Verify `when` conditions (cached or fresh)
  5. Conditions pass → forward request → mark p-002 consumed
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

Runs every 60s (configurable). Iterates state-dependent permissions, re-validates `when` conditions, auto-revokes stale grants. Cleanup only — not the enforcement boundary (point-of-use verification is).

### Denial UX

**Implicit ask denied:**
```
DENIED: aws:ec2:TerminateInstances (i-abc123)

  Risk tier: dangerous (destructive)
  Judge decision: escalate_human

  This action requires human approval.
  Run:  ask plan "describe your goal"
```

**Precondition failure at point-of-use:**
```
DENIED: aws:ecs:UpdateService (permission p-002 revoked)

  Precondition failed: runningCount >= 2
  Actual value: 1
  Permission auto-revoked.

  To re-request:  ask allow "aws:ecs:UpdateService"
```

---

## Comparison with Previous Design

| Aspect | Previous (v0.2) | New (Cedar-inspired) |
|---|---|---|
| Effects | Allow-only (implicit) | Explicit `permit` / `forbid` |
| Safety rails | Judge decides everything | Forbid rules are hard limits |
| Action matching | Regex | Glob |
| Conditions | `preconditions` | `when` (Cedar terminology) |
| Plan revocation | Not specified | Derivation tree — revoke plan = revoke all children |
| Schema validation | Not specified | Compile-time validation against risk taxonomy |
| Evaluation model | Check tree → ask judge → deny | Forbid check → permit check → implicit ask → deny |
