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

## Judge Input (structured)

```json
{
  "requested_action": "aws[profile=prod]:ecs:UpdateService",
  "current_tree": ["aws[profile=prod]:ecs:Describe*", "aws[profile=prod]:ecs:List*"],
  "session_context": {"task": "investigate 503s in us-east-1"},
  "provider_risk_tier": "moderate",
  "action_taxonomy": "state-change",
  "implicit": true
}
```

The `implicit` field indicates whether this came from an explicit `ask allow` or from an implicit ask via the proxy. The judge may use this signal (e.g., require `ask plan` for dangerous actions even if the agent just tried to run them).

---

## Judge Output (structured)

```json
{
  "decision": "escalate_human",
  "risk_level": "moderate",
  "reasoning": "UpdateService is a state change on production ECS",
  "proposed_expansion": ["aws[profile=prod]:ecs:UpdateService (one-shot, with when conditions)"],
  "suggested_when": [
    {"cmd": "aws ecs describe-services ...", "expect": "runningCount >= 2", "max_staleness": "30s"}
  ]
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

```json
{
  "type": "plan",
  "description": "rollback ECS deployment in us-east-1",
  "current_tree": ["aws[profile=prod]:ecs:Describe*", "aws[profile=prod]:ecs:List*"],
  "session_context": {"task": "investigate 503s in us-east-1"},
  "credentials_available": ["aws:profile=prod", "aws:profile=dev"]
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
      "suggested_when": [
        {"cmd": "aws ecs describe-services --service api --profile prod", "jsonpath": ".services[0].runningCount", "expect": ">= 2", "max_staleness": "30s"}
      ]
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
