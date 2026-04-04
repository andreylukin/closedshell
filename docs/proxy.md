# HTTPS Proxy + Credential Mounts

Transparent MITM proxy. Session-scoped CA cert injected into sandbox at creation. The proxy is the primary enforcement boundary — it works identically on both Linux and macOS.

---

## Responsibilities

- Intercept all outbound HTTPS from sandbox
- Parse cloud provider API calls into structured actions
- Check action against permission tree (forbid → permit → implicit ask → deny). See [permission-tree.md § Evaluation Algorithm](permission-tree.md#evaluation-algorithm).
- For state-dependent permissions: run point-of-use [`when` condition verification](permission-tree.md#evaluation-algorithm) before forwarding (cached within `max_staleness`, host-side execution, timeout = deny)
- For unknown actions: submit implicit ask to judge
- Inject credentials from vault into approved requests
- Log all allow/deny decisions with full request metadata
- Support WebSocket/streaming (no hardcoded timeouts)

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

`provider[key=value]:action`. The qualifier is derived from which credential mount the request uses (AWS profile name, GCP project, K8s context, etc.). This makes the permission tree credential-aware — `aws[profile=dev]:s3:GetObject` and `aws[profile=prod]:s3:GetObject` are distinct actions with distinct permissions. Generic `net:` actions have no qualifier.

---

## Baked-in Risk Taxonomy

Safe/moderate/dangerous classification per provider, sourced from public IAM/RBAC docs. Embedded in binary, updatable via config override. Used for both judge input and permission tree schema validation.

See [permission-tree.md § Schema](permission-tree.md#schema-compile-time-validation) for the full taxonomy format.

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

Credentials are **passed through**, not injected. The agent's tools (aws, gcloud, kubectl) pick up credentials from the mounted files and environment variables and include them in outbound requests normally. The proxy forwards these as-is.

The proxy does not strip, replace, or add credentials. The sandbox boundary (seatbelt + proxy) ensures the agent can't use credentials to bypass the proxy — all network traffic is forced through it regardless.

---

## Credential Mounts

Credentials are mounted directly into the sandbox. The agent can read them, but **cannot use them to bypass the proxy** — the sandbox boundary forces all network traffic through the proxy regardless.

### Configuration

```yaml
sandbox:
  credentials:
    - type: file
      source: ~/.aws/credentials
      mount: ~/.aws/credentials
      readonly: true

    - type: env
      vars: [OPENAI_API_KEY, GITHUB_TOKEN]

    - type: socket
      source: $SSH_AUTH_SOCK
      mount: /tmp/ssh-agent.sock

    - type: oauth
      provider: gcp
      token_path: ~/.config/gcloud/
      refresh_interval: 45m    # daemon refreshes on host, remounts
```

### Mount Types

| Type | Example | Behavior |
|------|---------|----------|
| `file` | `~/.aws/credentials`, `~/.kube/config` | Read-only bind mount into sandbox |
| `env` | `OPENAI_API_KEY`, `GITHUB_TOKEN` | Passed as environment variables at sandbox creation |
| `socket` | `SSH_AUTH_SOCK`, Docker socket | Socket mounted into sandbox |
| `oauth` | GCP, Azure AD | Daemon refreshes tokens on host side on `refresh_interval`, remounts into sandbox. Agent always sees a valid token. |

### Security Model

- Agent tools work naturally — `aws`, `gcloud`, `kubectl` find credentials where they expect them.
- All network traffic still goes through the proxy, which enforces the permission tree.
- Even if the agent reads raw credentials, it cannot make network calls that bypass the proxy.
- OAuth tokens that expire mid-session are refreshed by the daemon on the host side — the agent doesn't know or care.
