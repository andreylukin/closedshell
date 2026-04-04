# Judge — Model-Agnostic Permission Evaluator

The judge is a single LLM behind any **OpenAI-compatible API endpoint**. One model. No fallbacks. No routing tiers.

---

## Configuration

```yaml
judge:
  # Point at any OpenAI-compatible endpoint.
  # Local: ollama, llama.cpp, vllm, localai
  # Remote: openai, anthropic (via litellm), groq, together, etc.
  # Proxy: litellm proxy for provider abstraction
  api_base: "http://localhost:11434/v1"   # e.g. ollama
  model: "qwen3:8b"                       # whatever you're running
  api_key: ""                              # optional, depends on provider

  # Inference constraints
  max_tokens: 512
  timeout_ms: 5000          # hard timeout — if judge doesn't respond, deny
  temperature: 0.0          # deterministic for reproducibility

  # Structured I/O
  system_prompt_path: "/etc/closedshell/judge-system.txt"
  response_format: "json"   # enforce JSON output via provider support or parsing
```

**Why one model, no fallbacks:** Fallback chains make the security boundary non-deterministic. If model A denies an action and model B would approve it, which is correct? A single model means a single policy surface. If the model is down, the answer is deny — not "try something else."

**Why OpenAI-compatible:** It's the de facto standard. Every local inference server (ollama, vllm, llama.cpp, localai) and every proxy (litellm, portkey) speaks it. Zero coupling to any specific provider or runtime.

---

## Judge Context

Every judge call includes the same context envelope. The daemon builds this — the agent never touches it.

### Session context

Set at `closedshell --task "investigate 503s" pi`. Updated by the agent via `ask context "now rolling back ECS"`. The judge uses this to detect scope creep — an agent investigating 503s shouldn't be deleting S3 buckets.

```json
"session_context": {
  "task": "investigate 503s in us-east-1",
  "created": "2026-04-04T10:00:00Z",
  "credentials_available": ["aws:profile=prod", "aws:profile=dev"]
}
```

### `ask context` behavior

When the agent runs `ask context "new task description"`:

1. Daemon updates the session task field
2. Logged as a `context` event in the audit log (old and new task)
3. All future judge calls include the updated task

Context updates are **informational only**. Existing permits are not re-evaluated or revoked. The judge sees the new context on its next invocation and can factor it into future decisions — but the tree stays as-is. If existing permissions no longer make sense, that's a host-side action (`closedshell revoke-plan` or adding a forbid).

This keeps the design simple: `ask context` is a cheap metadata update, not a tree mutation trigger.

### Current tree

The full set of active permit and forbid rules. Lets the judge see what's already been granted and avoid redundant approvals.

### Decision history

Last 20 decisions, compact format. Gives the judge signal for pattern detection — escalation sequences, scope creep, repeated denial attempts.

```json
"history": [
  {"action": "aws[profile=dev]:s3:List*", "decision": "approve", "by": "judge", "t": -300},
  {"action": "aws[profile=dev]:ec2:Describe*", "decision": "approve", "by": "judge", "t": -240},
  {"action": "aws[profile=prod]:ecs:UpdateService", "decision": "escalate_human", "by": "judge", "t": -60},
  {"action": "aws[profile=prod]:s3:DeleteBucket", "decision": "deny", "by": "judge", "t": -30}
]
```

- `t` — seconds relative to now (negative = past). Avoids clock sync issues, cheap to compute.
- `by` — who made the decision: `judge`, `human:@oncall`, `template:aws-debug`, `forbid`.
- Capped at 20 entries. Oldest dropped first. If sessions need deeper history, the audit log has everything — the judge gets a rolling window.

**What the judge can infer from history:**
- Progressive escalation (dev → prod, read → write → delete)
- Repeated denial variants (agent keeps trying `Delete*` with different resources)
- Velocity (15 approvals in 5 minutes vs 2 in an hour)
- Context drift (started with S3, now touching ECS, IAM, Lambda)

**What history is NOT:** a trust score. The judge doesn't "warm up" to an agent. Each decision is independent, informed by history but not determined by it.

---

## Judge Input (structured)

```json
{
  "requested_action": "aws[profile=prod]:ecs:UpdateService",
  "current_tree": ["aws[profile=prod]:ecs:Describe*", "aws[profile=prod]:ecs:List*"],
  "session_context": {"task": "investigate 503s in us-east-1"},
  "history": [
    {"action": "aws[profile=dev]:s3:List*", "decision": "approve", "by": "judge", "t": -300},
    {"action": "aws[profile=dev]:ec2:Describe*", "decision": "approve", "by": "judge", "t": -240}
  ],
  "risk_tier": "moderate",
  "implicit": true
}
```

Fields:
- `risk_tier` — `safe`, `moderate`, or `dangerous`. Derived from the baked-in risk taxonomy (see [proxy.md § Risk Taxonomy](proxy.md#baked-in-risk-taxonomy)). Tells the judge the provider's own classification of this action.
- `implicit` — whether this came from an explicit `ask allow` or from an implicit ask via the proxy. The judge may use this signal (e.g., require `ask plan` for dangerous actions even if the agent just tried to run them).
- `credentials_available` in `session_context` — derived from credential mounts in config. Tells the judge which providers/profiles are available, so it can scope permits correctly.

---

## Judge Output (structured)

```json
{
  "decision": "escalate_human",
  "risk_level": "moderate",
  "reasoning": "UpdateService is a state change on production ECS",
  "proposed_expansion": ["aws[profile=prod]:ecs:UpdateService (one-shot)"]
}
```

**Judge never sees raw agent output.** Only structured permission requests. Prevents prompt injection from agent.

---

## Decision Matrix

| Action Risk | Judge Decision | Behavior |
|---|---|---|
| safe (read) | `approve` | Grant immediately. |
| moderate (write) | `approve` or `escalate_human` | Judge decides based on context + tree. |
| dangerous (delete/terminate) | `escalate_human` | Always routed to human. Judge can't override. |
| context mismatch | `deny_with_hint` | Action doesn't match declared session context. Agent told to `ask context` to update and retry. |
| judge timeout/error | `deny` | Fail closed. Always. |
| already granted | *(skip judge)* | Fast path: tree glob match, forward immediately (~1ms). |

---

## Plan Evaluation (`ask plan`)

The judge decomposes a free-text plan description into a minimal permission set. The agent's LLM never writes permissions directly — the judge is the authority on what actions a plan requires and how to scope them.

### Input

Same context envelope as all judge calls, plus the plan description:

```json
{
  "type": "plan",
  "description": "rollback ECS deployment in us-east-1",
  "current_tree": ["aws[profile=prod]:ecs:Describe*", "aws[profile=prod]:ecs:List*"],
  "session_context": {"task": "investigate 503s in us-east-1", "credentials_available": ["aws:profile=prod", "aws:profile=dev"]},
  "history": [...]
}
```

### Output

```json
{
  "plan_id": "plan-013",
  "rules": [
    {
      "effect": "permit",
      "action": "aws[profile=prod]:ecs:DescribeServices",
      "type": "idempotent",
      "risk_level": "safe"
    },
    {
      "effect": "permit",
      "action": "aws[profile=prod]:ecs:DescribeTaskDefinition",
      "type": "idempotent",
      "risk_level": "safe"
    },
    {
      "effect": "permit",
      "action": "aws[profile=prod]:ecs:UpdateService",
      "type": "one-shot",
      "risk_level": "moderate",
    }
  ],
  "reasoning": "rollback requires reading current state (Describe) and updating the service to a previous task definition (UpdateService). Scoped to one-shot with running count guard."
}
```

### Daemon processing

1. Receive judge's proposed rules
2. Validate each rule against the permission tree schema
3. Check against existing forbid rules — drop any proposed permits that would be overridden (warn the agent)
4. Classify by risk tier:
   - `safe` → auto-approve, add to tree immediately
   - `moderate` / `dangerous` → queue for human approval
5. Return to agent: `{plan_id, auto_approved: [...], pending_human: [...]}`

The plan isn't a straitjacket. Implicit ask still fills gaps at runtime if the agent needs actions the plan didn't anticipate. The plan gives the agent a head start — pre-approved permissions so common actions don't block on judge latency.

---

**Latency expectations:** With a local 3-8B model on decent hardware, safe actions resolve in <100ms. Moderate actions in <500ms. These are guidelines, not guarantees — depends entirely on your model and hardware. The hard timeout (`timeout_ms`) is the real contract.
