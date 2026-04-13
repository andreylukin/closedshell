# HTTPS Proxy

Transparent MITM proxy. Session-scoped CA cert injected into sandbox at creation. The proxy is the primary enforcement boundary — it works identically on both Linux and macOS.

---

## Responsibilities

- Intercept all outbound HTTPS from sandbox
- Parse cloud provider API calls into structured actions
- Check action against permission tree (forbid → permit → block for human approval). See [permission-tree.md § Evaluation Algorithm](permission-tree.md#evaluation-algorithm).
- Forward approved requests with credentials as-is (passthrough)
- Log all decisions to audit log (see [architecture.md § Audit Log](architecture.md#audit-log))
- Support HTTP streaming (chunked, SSE) — see [§ Streaming and WebSocket](#streaming-and-websocket)

---

## Provider Parsers

| Provider | Wire Format | Canonical Action |
|----------|-------------|------------------|
| AWS | `POST / Action=TerminateInstances` | `aws[profile=AKID]:ec2:TerminateInstances` |
| GCP | `DELETE .../instances/{id}` | `gcp[project=myproj]:compute:instances.delete` |
| Azure | `DELETE .../Microsoft.Compute/...` | `az[subscription=abc123]:Compute:virtualMachines.delete` |
| GitHub | `POST /repos/x/pulls` | `gh:repos/x/pulls:POST` |
| K8s | `DELETE /apis/apps/v1/namespaces/prod/deployments/web` | `k8s[ns=prod]:deployments:delete` |
| Generic | `GET https://host/path` | `net:GET:host/path` |

Parsers are pluggable. Unknown APIs fall back to `net:<METHOD>:<host>/<path>`.

---

## Credential Qualifier Format

`provider[key=value]:service:operation`. The qualifier is derived from request context (AWS access key ID from SigV4 Authorization header, GCP project from URL path, Azure subscription or account from URL, K8s namespace from path). This makes the permission tree credential-aware — `aws[profile=AKIAEXAMPLE1]:s3:GetObject` and `aws[profile=AKIAEXAMPLE2]:s3:GetObject` are distinct actions with distinct permissions. GitHub and generic `net:` actions have no qualifier.

---

## Baked-in Risk Taxonomy

Safe/moderate/dangerous classification based on the operation name in the canonical action string. Uses prefix matching (e.g., `Describe`/`List`/`Get`/`Head` → safe, `Delete`/`Terminate`/`Remove` → dangerous, `Create`/`Put`/`Start`/`Stop`/`Update` → moderate) plus lowercase keyword matching for non-AWS styles (e.g., `insert`, `patch`, `POST` → moderate). Unknown operations default to moderate. Used for TUI risk display.

---

## Streaming and WebSocket

The proxy makes the allow/deny decision on the **initial request only**, then becomes a dumb pipe for the data phase.

### HTTP streaming (chunked, SSE)

1. Proxy intercepts the request, parses action, checks permission tree — same as any other request
2. If denied → return 403 immediately, no upstream connection
3. If allowed → establish upstream connection, stream response chunks through to the agent untouched
4. No per-chunk inspection or re-checking

### WebSocket

WebSocket upgrades are not currently supported. The proxy only handles HTTP/1.1 request/response cycles. A WebSocket `Upgrade` request would be parsed and permission-checked like any other request, but the upgrade handshake would not be completed.

### Revocation during a stream

If a permission is revoked (one-shot consumed by another request) while a streaming connection is already open, **the existing connection is not interrupted**. The revocation takes effect on the next connection attempt.

---

## Denial Response Format

When the proxy denies a request, it returns an HTTP response directly to the agent — no upstream connection is made.

```
HTTP/1.1 403 Forbidden
Content-Type: application/json
X-ClosedShell-Denied: true
X-ClosedShell-Action: aws[profile=AKID]:ec2:TerminateInstances
X-ClosedShell-Reason: no allow rule matched
X-ClosedShell-Hint: pending human review in TUI

{
  "error": "denied_by_closedshell",
  "action": "aws[profile=AKID]:ec2:TerminateInstances",
  "reason": "no allow rule matched",
  "risk_tier": "dangerous",
  "denied_by": "decider",
  "hint": "pending human review in TUI",
  "message": "[ClosedShell] Denied aws[profile=AKID]:ec2:TerminateInstances — no allow rule matched. pending human review in TUI"
}
```

The `X-ClosedShell-Denied` header lets agents programmatically distinguish proxy denials from upstream 403s. The `X-ClosedShell-Action`, `X-ClosedShell-Reason`, and `X-ClosedShell-Hint` headers provide structured denial details without requiring JSON parsing.

---

## Credential Passthrough

Credentials are **passed through**, not injected. The agent's tools (aws, gcloud, kubectl) pick up credentials from environment variables and filesystem (seatbelt allows all reads) and include them in outbound requests normally. The proxy forwards these as-is.

The proxy does not strip, replace, or add credentials. All network traffic is forced through the proxy regardless — the agent can hold credentials but can only use them through the proxy's permission checks.

### Configuration

Environment variables are forwarded to the sandbox via `passthrough_env`:

```yaml
sandbox:
  passthrough_env:
    - OPENAI_API_KEY
    - GITHUB_TOKEN
    - AWS_ACCESS_KEY_ID
    - AWS_SECRET_ACCESS_KEY
```

The seatbelt profile allows all file reads, so credential files like `~/.aws/credentials` and `~/.kube/config` are accessible to the agent without special configuration.
