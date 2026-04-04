# Execution Flows

---

## Cold Start

```
closedshell create -- claude-code
  1. Set up platform sandbox (Linux: namespaces + seccomp, macOS: seatbelt)
  2. Start transparent proxy, inject session-scoped CA cert
  3. Mount ask CLI + Unix socket (read-only)
  4. Display MOTD with ask CLI usage
  5. Exec agent command
```

See [architecture.md](architecture.md) for platform-specific details.

---

## Implicit Ask (primary path)

The default flow. The agent just runs commands. No `ask` needed for the happy path.

```
Agent: aws s3 ls
  1. aws CLI → HTTPS request to s3.amazonaws.com
  2. Proxy parses: aws[profile=dev]:s3:ListBuckets
  3. Forbid check: no forbid matches
  4. Permit check: no permit matches
  5. Implicit ask → judge: {action, risk: "safe", ...}
  6. Judge: approve → new permit rule: aws[profile=dev]:s3:List*
  7. Proxy forwards original request (no retry needed)
  8. Agent gets response as if nothing happened
  Total: < 200ms (agent never sees a denial)
```

**Key insight:** The proxy holds the outbound request while the judge evaluates. The agent doesn't need to retry. For safe actions, this adds ~100ms of latency on first access — invisible to most agents.

**When implicit ask is not enough:**
- Judge returns `escalate_human` → proxy returns denial with hint to use `ask plan`
- Judge returns `deny` → proxy returns denial with reason
- Agent wants to pre-approve a batch of actions → use `ask plan`

---

## Explicit Pre-flight (ask allow)

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

Still useful for: agents that want to check before committing to a code path, or to get expanded wildcards upfront.

---

## Plan Approval (ask plan)

```
Agent: ask plan "Rollback bad ECS deployment"
  1. Judge analyzes plan → proposes permission set
  2. Read-only actions: auto-approved immediately
  3. State-change/destructive: routed to human
  4. Human approves via CLI/Slack
  5. Full set added to tree (one-shots + when conditions)
  6. Agent executes at full speed against pre-approved tree
```

See [permission-tree.md § Plan Derivation](permission-tree.md#plan-derivation-and-revocation) for revocation semantics.

---

## State-Dependent Execution (point-of-use)

```
Agent: aws ecs update-service --service api --desired-count 4
  1. Proxy parses: aws[profile=prod]:ecs:UpdateService
  2. Forbid check: no forbid matches
  3. Permit match: p-002 (one-shot, has `when` conditions)
  4. Verify `when` conditions (cached or fresh)
  5. Conditions pass → forward request → mark p-002 consumed
  Total: ~50ms (cached) to ~2s (fresh check)
```

See [permission-tree.md § Evaluation Algorithm](permission-tree.md#evaluation-algorithm) for full verification logic.

---

## Capability Discovery (ask what-can-i)

```
Agent: ask what-can-i "aws[profile=dev]:s3:*"
  1. Returns current tree entries matching pattern
  2. No permission request submitted
  3. Shows: aws[profile=dev]:s3:List* (idempotent, active)
           aws[profile=dev]:s3:GetObject (idempotent, active)
  4. Agent knows what it has without round-trips
```

---

## Background Sweep

Runs every 60s (configurable). Iterates state-dependent permissions, re-validates `when` conditions, auto-revokes stale grants. Cleanup only — not the enforcement boundary (point-of-use verification is).

---

## Denial UX

### Implicit ask denied

```
DENIED: aws:ec2:TerminateInstances (i-abc123)

  Risk tier: dangerous (destructive)
  Judge decision: escalate_human

  This action requires human approval.
  Run:  ask plan "describe your goal"
```

### Precondition failure at point-of-use

```
DENIED: aws:ecs:UpdateService (permission p-002 revoked)

  Precondition failed: runningCount >= 2
  Actual value: 1
  Permission auto-revoked.

  To re-request:  ask allow "aws:ecs:UpdateService"
```

---

## Security Boundaries

| Layer | Mechanism | Bypass Resistance |
|-------|-----------|-------------------|
| Process isolation | Platform-specific (namespaces / seatbelt) | Kernel-level |
| Syscall filtering | seccomp-bpf (Linux) / seatbelt (macOS) | Kernel-level |
| Network egress | All traffic forced through proxy | No network without proxy |
| API enforcement | L7 proxy parsing + permission tree | Catches all HTTP |
| Precondition enforcement | Point-of-use verification in proxy | No stale-grant window |
| Credential isolation | Mounted in sandbox, but proxy enforces | Agent can't bypass proxy |
| Judge isolation | Structured input only, single model | Agent can't prompt-inject judge |
| Judge failure mode | Timeout/error = deny | Fail closed, always |
