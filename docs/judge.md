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
  "proposed_expansion": ["aws:ecs:UpdateService (one-shot, preconditioned)"],
  "suggested_preconditions": [
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

**Latency expectations:** With a local 3-8B model on decent hardware, safe actions resolve in <100ms. Moderate actions in <500ms. These are guidelines, not guarantees — depends entirely on your model and hardware. The hard timeout (`timeout_ms`) is the real contract.
