# HTTPS Proxy

Transparent MITM proxy. Session-scoped CA cert injected into sandbox at creation. The proxy is the primary enforcement boundary — it works identically on both Linux and macOS.

---

## Responsibilities

- Intercept all outbound HTTPS from sandbox
- Parse cloud provider API calls into structured actions
- Check action against permission tree (forbid → permit → implicit ask → deny). See [permission-tree.md § Evaluation Algorithm](permission-tree.md#evaluation-algorithm).
- For unknown actions: submit implicit ask to judge
- Forward approved requests with credentials as-is (passthrough)
- Log all decisions to audit log (see [architecture.md § Audit Log](architecture.md#audit-log))
- Support WebSocket/streaming (see [§ Streaming and WebSocket](#streaming-and-websocket))

---

## Provider Parsers

| Provider | Wire Format | Canonical Action |
|----------|-------------|------------------|
| AWS | `POST / Action=TerminateInstances` | `aws[profile=default]:ec2:TerminateInstances` |
| GCP | `DELETE .../instances/{id}` | `gcp[project=myproj]:compute.instances.delete` |
| Azure | `DELETE .../Microsoft.Compute/...` | `az[sub=abc123]:Microsoft.Compute/delete` |
| GitHub | `POST /repos/x/pulls` | `gh[token=GITHUB_TOKEN]:repos/*/pulls:POST` |
| K8s | `PATCH /apis/apps/v1/deployments` | `k8s[ctx=prod]:apps/v1/deployments:PATCH` |
| Generic | `GET https://host/path` | `net:GET:host/path` |

Parsers are pluggable. Unknown APIs fall back to `net:<METHOD>:<host>/<path>`.

---

## Credential Qualifier Format

`provider[key=value]:action`. The qualifier is derived from request context (AWS profile name from signing headers, GCP project from URL, K8s context, etc.). This makes the permission tree credential-aware — `aws[profile=dev]:s3:GetObject` and `aws[profile=prod]:s3:GetObject` are distinct actions with distinct permissions. Generic `net:` actions have no qualifier.

---

## Baked-in Risk Taxonomy

Safe/moderate/dangerous classification per provider, sourced from public IAM/RBAC docs. Embedded in binary, updatable via config override. Used for both judge input and permission tree schema validation.

See [permission-tree.md § Schema](permission-tree.md#schema-compile-time-validation) for the full taxonomy format.

---

## Streaming and WebSocket

The proxy makes the allow/deny decision on the **initial request only**, then becomes a dumb pipe for the data phase.

### HTTP streaming (chunked, SSE)

1. Proxy intercepts the request, parses action, checks permission tree — same as any other request
2. If denied → return 403 immediately, no upstream connection
3. If allowed → establish upstream connection, stream response chunks through to the agent untouched
4. No per-chunk inspection or re-checking

### WebSocket

1. Proxy intercepts the HTTP `Upgrade` request, parses action from the URL/headers
2. Permission check on the upgrade request — one check at connect time
3. If denied → return 403, no upgrade
4. If allowed → complete the upgrade, then relay frames bidirectionally without inspection

### Revocation during a stream

If a permission is revoked (plan revoked, one-shot consumed by another request) while a streaming connection or WebSocket is already open, **the existing connection is not interrupted**. The revocation takes effect on the next connection attempt.

This is an acceptable gap. The alternative — tracking all open connections per rule and tearing them down on revocation — adds significant complexity for marginal security benefit. Long-lived connections are rare in the cloud API use case (most are short request/response), and WebSocket connections get a fresh check on reconnect.

---

## Denial Response Format

When the proxy denies a request, it returns an HTTP response directly to the agent — no upstream connection is made.

```
HTTP/1.1 403 Forbidden
Content-Type: application/json
X-ClosedShell-Denied: true

{
  "error": "denied",
  "action": "aws[profile=prod]:ec2:TerminateInstances",
  "reason": "session policy: no production terminates",
  "risk_tier": "dangerous",
  "hint": "ask plan \"describe your goal\""
}
```

The `X-ClosedShell-Denied` header lets agents programmatically distinguish proxy denials from upstream 403s.

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
