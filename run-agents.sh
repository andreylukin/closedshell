#!/bin/bash
set -euo pipefail

# Overnight agent runner for ClosedShell
# Spawns parallel Claude Code agents, each in its own git worktree.
# Prompts are written to files to avoid shell quoting issues.

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENTS_DIR="/tmp/closedshell-agents"
LOG_DIR="$AGENTS_DIR/logs"
PROMPT_DIR="$AGENTS_DIR/prompts"
BASE_BRANCH="$(git -C "$REPO_DIR" rev-parse HEAD)"

mkdir -p "$LOG_DIR" "$PROMPT_DIR"

# Cleanup old worktrees
echo "Cleaning up old worktrees..."
for wt in "$AGENTS_DIR"/agent-*; do
  [ -d "$wt" ] && git -C "$REPO_DIR" worktree remove --force "$wt" 2>/dev/null || true
done

PIDS=()
NAMES=()

# Append PR instructions to a prompt file
write_pr_suffix() {
  cat >> "$1" << 'PRSUFFIX'

## IMPORTANT: After implementation is complete, tests pass, and you have committed:

1. Push your branch:
   git push -u origin HEAD

2. Open a PR against main using gh CLI:
   gh pr create --title "<short descriptive title>" --body "$(cat <<'PREOF'
## Summary
<1-3 bullet points describing what this PR adds>

## Test plan
- [ ] cargo build succeeds
- [ ] cargo test passes (new + existing tests)
- [ ] cargo clippy -- -D warnings clean
- [ ] cargo fmt --check clean

Generated with [Claude Code](https://claude.ai/code)
PREOF
)"

This is mandatory. The PR must be opened before you finish.
PRSUFFIX
}

launch_agent() {
  local name="$1"
  local prompt_file="$PROMPT_DIR/$name.md"
  local branch="agent/$name"
  local worktree="$AGENTS_DIR/agent-$name"
  local logfile="$LOG_DIR/$name.log"

  # Append PR instructions to prompt
  write_pr_suffix "$prompt_file"

  # Remove stale worktree/branch if they exist
  git -C "$REPO_DIR" worktree remove --force "$worktree" 2>/dev/null || true
  git -C "$REPO_DIR" branch -D "$branch" 2>/dev/null || true

  # Create worktree from current HEAD
  git -C "$REPO_DIR" worktree add "$worktree" -b "$branch" "$BASE_BRANCH"

  echo "[$(date '+%H:%M:%S')] Starting agent: $name -> $logfile"

  (
    cd "$worktree"
    claude --dangerously-skip-permissions \
      -p "$(cat "$prompt_file")" \
      --verbose \
      > "$logfile" 2>&1
  ) &

  PIDS+=($!)
  NAMES+=("$name")
}

# ─────────────────────────────────────────────────────────────────
# Write prompt files
# ─────────────────────────────────────────────────────────────────

# AGENT 1: Permission Tree
cat > "$PROMPT_DIR/permission-tree.md" << 'PROMPT'
You are contributing to ClosedShell, a macOS sandbox for AI agents. Your task: implement the Permission Tree module.

## Context
ClosedShell intercepts all HTTPS via a MITM proxy. The proxy uses a DecisionMaker trait to allow/deny requests. Currently only YoloDecider (allow all) and PatternDecider (glob allow list) exist. You need to build the real Cedar-inspired permission tree.

## What to build
Create `crates/closedshell-lib/src/permission.rs` and register it in `lib.rs`.

### Data structures
```rust
pub struct PermissionTree {
    rules: Vec<Rule>,
}

pub struct Rule {
    pub id: String,
    pub effect: Effect,        // Permit or Forbid
    pub action: String,        // glob pattern like "aws[profile=dev]:ec2:Describe*"
    pub rule_type: Option<RuleType>,  // Some(Idempotent) or Some(OneShot { consumed: bool }) for permits, None for forbids
    pub approved_by: Option<String>,
    pub source: Option<String>,       // for forbids: org_baseline, session_policy, template:name, human:id
    pub plan_id: Option<String>,
    pub reason: Option<String>,       // for forbids
    pub expires: Option<chrono::DateTime<chrono::Utc>>,
}

pub enum Effect { Permit, Forbid }
pub enum RuleType { Idempotent, OneShot { consumed: bool } }
```

### Evaluation algorithm (Cedar semantics)
1. FORBID CHECK: scan all forbid rules. If any glob matches the action's canonical string -> DENY(reason).
2. PERMIT CHECK: scan all permit rules. If glob matches:
   - Idempotent: if not expired -> ALLOW
   - OneShot: if not consumed and not expired -> mark consumed=true -> ALLOW
3. NO MATCH: return DENY("no matching permission")

Key properties: forbid-overrides-permit, default deny, order-independent.

Use `glob_match::glob_match` (already a dependency) for pattern matching.

### Methods to implement
- `PermissionTree::new() -> Self`
- `evaluate(&mut self, action_canonical: &str) -> TreeVerdict` (Allow or Deny{reason})
- `add_rule(&mut self, rule: Rule)`
- `remove_rule(&mut self, rule_id: &str) -> bool`
- `revoke_plan(&mut self, plan_id: &str) -> usize` (remove all rules with that plan_id, return count)
- `load_template(&mut self, yaml_str: &str) -> Result<()>` (parse YAML template, add rules tagged with template source)
- `rules(&self) -> &[Rule]` (read access)
- `matching_rules(&self, pattern: &str) -> Vec<&Rule>` (for what-can-i queries)

### Implement DecisionMaker for PermissionTree
```rust
impl DecisionMaker for PermissionTree {
    fn evaluate(&self, action: &Action) -> Verdict {
        // delegate to self.evaluate(action.canonical())
    }
}
```
Note: DecisionMaker::evaluate takes &self not &mut self. For one-shot consumption you'll need interior mutability (Mutex or RwLock on the rules vec).

### Template YAML format
```yaml
name: aws-debug
description: "Read-only AWS access"
rules:
  - effect: forbid
    action: "aws[profile=prod]:*:Delete*"
    reason: "no production deletes"
  - effect: permit
    action: "aws[profile=*]:*:Describe*"
    type: idempotent
```

### Unit tests to write (from the spec)
- T1: Forbid overrides permit (forbid aws[profile=prod]:*:Delete*, permit aws[profile=prod]:s3:Delete* -> evaluate aws[profile=prod]:s3:DeleteBucket -> DENY)
- T2: Empty tree -> any action -> DENY
- T3: Idempotent permit -> evaluate twice -> ALLOW both
- T4: OneShot permit -> evaluate twice -> first ALLOW, second DENY
- T5: Consumed one-shot -> re-evaluate -> DENY
- T8: Glob aws[profile=*]:s3:List* matches aws[profile=dev]:s3:ListBuckets
- T9: Glob aws[profile=dev]:s3:List* does NOT match aws[profile=prod]:s3:ListBuckets
- T10: Two templates loaded, forbid from first survives
- T11: revoke_plan removes all rules with that plan_id
- T12: Forbid file:read:/Users/*/.ssh/* denies file:read:/Users/andrey/.ssh/id_rsa
- T13: Permit file:write:/Users/andrey/repos/* allows file:write:/Users/andrey/repos/foo.txt
- T14: No permit for file:write:/etc/passwd -> DENY
- Test expiry (expired permit skipped)
- Test add_rule and remove_rule
- Test matching_rules for what-can-i

## Build commands
```bash
cargo build 2>&1
cargo test -p closedshell-lib 2>&1
cargo clippy -- -D warnings 2>&1
cargo fmt --check 2>&1
```

Run all four after implementation. Fix any errors. Commit when green.
PROMPT

# AGENT 2: Judge Client
cat > "$PROMPT_DIR/judge-client.md" << 'PROMPT'
You are contributing to ClosedShell, a macOS sandbox for AI agents. Your task: implement the Judge Client module.

## Context
ClosedShell intercepts HTTPS via a MITM proxy and checks permissions. When no rule matches, it needs to consult a "judge" — a single LLM behind an OpenAI-compatible API. The judge evaluates whether to approve, deny, or escalate to human.

The config already has JudgeConfig in `crates/closedshell-lib/src/config.rs`:
```rust
pub struct JudgeConfig {
    pub api_base: String,      // e.g. "http://localhost:11434/v1"
    pub model: String,         // e.g. "qwen3:8b"
    pub api_key: String,
    pub timeout_ms: u64,       // hard timeout, default 5000
    pub temperature: f32,
    pub system_prompt_path: Option<String>,
}
```

## What to build
Create `crates/closedshell-lib/src/judge.rs` and register it in `lib.rs`.

### JudgeClient struct
```rust
pub struct JudgeClient {
    http: reqwest::Client,
    config: JudgeConfig,
    system_prompt: String,
}
```

### Judge request/response types
```rust
#[derive(Serialize)]
pub struct JudgeRequest {
    pub requested_action: String,
    pub current_tree: Vec<String>,
    pub session_context: SessionContext,
    pub history: Vec<HistoryEntry>,
    pub risk_tier: String,
    pub implicit: bool,
}

#[derive(Serialize)]
pub struct SessionContext {
    pub task: Option<String>,
}

#[derive(Serialize)]
pub struct HistoryEntry {
    pub action: String,
    pub decision: String,
    pub by: String,
    pub t: i64,
}

#[derive(Deserialize)]
pub struct JudgeResponse {
    pub decision: String,       // "approve", "deny", "escalate_human"
    pub risk_level: String,
    pub reasoning: String,
    #[serde(default)]
    pub proposed_expansion: Option<Vec<String>>,
    #[serde(default)]
    pub deny_reason: Option<String>,
}

pub enum JudgeDecision {
    Approve,
    Deny { reason: String },
    EscalateHuman,
}
```

### Plan evaluation types
```rust
#[derive(Serialize)]
pub struct PlanRequest {
    pub description: String,
    pub current_tree: Vec<String>,
    pub session_context: SessionContext,
    pub history: Vec<HistoryEntry>,
}

#[derive(Deserialize)]
pub struct PlanResponse {
    pub plan_id: String,
    pub rules: Vec<ProposedRule>,
    pub reasoning: String,
}

#[derive(Deserialize)]
pub struct ProposedRule {
    pub effect: String,
    pub action: String,
    pub rule_type: String,
    pub risk_level: String,
}
```

### Methods
- `JudgeClient::new(config: JudgeConfig) -> Result<Self>` — create client, load system prompt from file if configured, otherwise use built-in default
- `async evaluate_action(&self, req: JudgeRequest) -> JudgeDecision` — call OpenAI-compatible chat completions endpoint, parse structured JSON response. On timeout or error -> Deny.
- `async evaluate_plan(&self, req: PlanRequest) -> Result<PlanResponse>` — similar but for plan decomposition

### OpenAI-compatible API call
POST to `{api_base}/chat/completions` with:
```json
{
  "model": "...",
  "messages": [
    {"role": "system", "content": "..."},
    {"role": "user", "content": "<serialized JudgeRequest>"}
  ],
  "temperature": 0.0,
  "max_tokens": 512,
  "response_format": {"type": "json_object"}
}
```

Parse response.choices[0].message.content as JSON.

### Default system prompt
Include a reasonable default system prompt that explains the judge's role: evaluate permission requests for a sandboxed AI agent, return structured JSON with decision/risk_level/reasoning/proposed_expansion.

### Risk taxonomy helper
Add a function:
```rust
pub fn classify_risk(action_canonical: &str) -> &'static str
```
That returns "safe", "moderate", or "dangerous" based on the operation name:
- safe: Describe*, List*, Get*, Head*, read
- moderate: Create*, Put*, Start*, Stop*, Update*, Tag*, insert, patch, write, POST
- dangerous: Delete*, Terminate*, Remove*, Revoke*, Detach*
- default: "moderate"

### Tests
- Test risk classification for various action strings
- Test JudgeResponse deserialization from JSON
- Test timeout handling (use a mock that sleeps longer than timeout -> should get Deny)
- Test malformed JSON response -> Deny
- Test plan response deserialization

Note: reqwest is already a dev-dependency. You may need to add it as a regular dependency in closedshell-lib/Cargo.toml for the judge client. It's in the workspace.

## Build commands
```bash
cargo build 2>&1
cargo test -p closedshell-lib 2>&1
cargo clippy -- -D warnings 2>&1
cargo fmt --check 2>&1
```

Run all four after implementation. Fix any errors. Commit when green.
PROMPT

# AGENT 3: Azure Provider Parser
cat > "$PROMPT_DIR/parser-azure.md" << 'PROMPT'
You are contributing to ClosedShell, a macOS sandbox for AI agents. Your task: add an Azure provider parser.

## Context
ClosedShell intercepts HTTPS and parses requests into canonical action strings. The parser module is at `crates/closedshell-lib/src/parser.rs`. It currently has parsers for AWS, GCP, and GitHub. You're adding Azure.

## The existing pattern
Look at the existing parsers in parser.rs. Each is a function `try_parse_X(req: &RequestInfo) -> Option<Action>`. The main `parse_action` function tries each parser in order, falling back to `parse_generic`.

The Action struct:
```rust
pub struct Action {
    pub provider: String,         // "az" for Azure
    pub qualifier: HashMap<String, String>,  // e.g. {"subscription": "my-sub"}
    pub service: String,
    pub operation: String,
    pub raw: String,             // canonical: "az[subscription=my-sub]:compute:virtualMachines.get"
}
```

RequestInfo gives you: method, host, path, headers, query_params, body_peek.

## What to build
Add `fn try_parse_azure(req: &RequestInfo) -> Option<Action>` and wire it into `parse_action`.

### Azure REST API patterns
Azure management plane: `management.azure.com`
- Path format: `/subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vmName}`
- Extract subscription from path
- Service = provider namespace without "Microsoft." prefix (e.g., "Compute", "Storage", "Network")
- Resource type = the resource path segment (e.g., "virtualMachines", "storageAccounts")
- Operation = resource_type.method_verb (e.g., "virtualMachines.get", "virtualMachines.delete")

Azure data plane hosts:
- `*.blob.core.windows.net` -> service: "storage.blob"
- `*.table.core.windows.net` -> service: "storage.table"
- `*.queue.core.windows.net` -> service: "storage.queue"
- `*.vault.azure.net` -> service: "keyvault"
- `*.database.windows.net` -> service: "sql"
- `*.documents.azure.com` -> service: "cosmosdb"

### Canonical format
`az[subscription={sub}]:{service}:{operation}`

For data plane where subscription isn't in the path, use the account name from the hostname as qualifier:
`az[account={name}]:{service}:{operation}`

### Method verb mapping
Same as GCP: GET->get, POST->create, PUT->update, PATCH->patch, DELETE->delete

### Unit tests to add (in the existing #[cfg(test)] mod tests block)
- test_azure_management_compute_get: GET management.azure.com /subscriptions/sub123/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1
- test_azure_management_storage_delete: DELETE management.azure.com /subscriptions/sub456/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1
- test_azure_blob_storage: GET myaccount.blob.core.windows.net /container/blob
- test_azure_keyvault: GET myvault.vault.azure.net /secrets/mysecret
- test_non_azure_not_matched: GET azure.microsoft.com /something -> net provider

## Important
- Add try_parse_azure call in parse_action() BEFORE the generic fallback, after try_parse_github
- Don't modify existing parser functions or tests
- Match the code style of existing parsers

## Build commands
```bash
cargo build 2>&1
cargo test -p closedshell-lib 2>&1
cargo clippy -- -D warnings 2>&1
cargo fmt --check 2>&1
```

Run all four after implementation. Fix any errors. Commit when green.
PROMPT

# AGENT 4: Kubernetes Provider Parser
cat > "$PROMPT_DIR/parser-k8s.md" << 'PROMPT'
You are contributing to ClosedShell, a macOS sandbox for AI agents. Your task: add a Kubernetes provider parser.

## Context
ClosedShell intercepts HTTPS and parses requests into canonical action strings. The parser module is at `crates/closedshell-lib/src/parser.rs`. It currently has parsers for AWS, GCP, and GitHub. You're adding Kubernetes.

## The existing pattern
Look at the existing parsers in parser.rs. Each is a function `try_parse_X(req: &RequestInfo) -> Option<Action>`. The main `parse_action` function tries each parser in order, falling back to `parse_generic`.

The Action struct:
```rust
pub struct Action {
    pub provider: String,         // "k8s" for Kubernetes
    pub qualifier: HashMap<String, String>,  // e.g. {"ns": "default"}
    pub service: String,          // resource type: "pods", "deployments", etc.
    pub operation: String,        // verb: "get", "list", "create", "delete", "watch"
    pub raw: String,              // canonical: "k8s[ns=default]:pods:list"
}
```

## What to build
Add `fn try_parse_k8s(req: &RequestInfo) -> Option<Action>` and wire it into `parse_action`.

### Kubernetes API patterns
K8s API servers don't have a fixed hostname. Detection heuristic: check for K8s-style paths.

Path patterns:
- `/api/v1/namespaces/{ns}/pods/{name}` -> core API
- `/api/v1/pods` -> list all pods
- `/api/v1/namespaces/{ns}/services`
- `/apis/apps/v1/namespaces/{ns}/deployments/{name}`
- `/apis/batch/v1/namespaces/{ns}/jobs`
- `/api/v1/nodes`

Detection: path starts with `/api/` or `/apis/`

### Parsing rules
1. Detect: path starts with /api/ or /apis/
2. Extract resource type (the plural resource name): pods, services, deployments, etc.
3. Map HTTP method to K8s verb:
   - GET on collection (no name) -> "list"
   - GET on specific resource (has name) -> "get"
   - GET with ?watch=true -> "watch"
   - POST -> "create"
   - PUT -> "update"
   - PATCH -> "patch"
   - DELETE -> "delete"
4. Extract namespace if present
5. No qualifier for now (context detection requires kubeconfig parsing, deferred)

### Canonical format
`k8s:{resource}:{verb}` e.g., `k8s:pods:list`, `k8s:deployments:delete`

With namespace: `k8s[ns={namespace}]:{resource}:{verb}`

### Unit tests to add (in the existing #[cfg(test)] mod tests block)
- test_k8s_list_pods: GET /api/v1/namespaces/default/pods -> k8s[ns=default]:pods:list
- test_k8s_get_pod: GET /api/v1/namespaces/default/pods/my-pod -> k8s[ns=default]:pods:get
- test_k8s_delete_deployment: DELETE /apis/apps/v1/namespaces/prod/deployments/web -> k8s[ns=prod]:deployments:delete
- test_k8s_create_service: POST /api/v1/namespaces/default/services -> k8s[ns=default]:services:create
- test_k8s_list_nodes: GET /api/v1/nodes -> k8s:nodes:list (no namespace)
- test_k8s_watch_pods: GET /api/v1/namespaces/default/pods?watch=true -> k8s[ns=default]:pods:watch
- test_non_k8s_not_matched: a request to a random host with /api/v1/ should NOT match. Use a heuristic: require known K8s resource types (pods, services, deployments, replicasets, statefulsets, daemonsets, jobs, cronjobs, configmaps, secrets, nodes, namespaces, ingresses, networkpolicies, persistentvolumeclaims, serviceaccounts, roles, rolebindings, clusterroles, clusterrolebindings)

## Important
- Add try_parse_k8s call in parse_action() BEFORE the generic fallback, after the last try_parse_* call
- Don't modify existing parser functions or tests
- Match the code style of existing parsers

## Build commands
```bash
cargo build 2>&1
cargo test -p closedshell-lib 2>&1
cargo clippy -- -D warnings 2>&1
cargo fmt --check 2>&1
```

Run all four after implementation. Fix any errors. Commit when green.
PROMPT

# AGENT 5: ask CLI + IPC
cat > "$PROMPT_DIR/ask-cli.md" << 'PROMPT'
You are contributing to ClosedShell, a macOS sandbox for AI agents. Your task: implement the `ask` CLI binary — the in-sandbox tool agents use to interact with the ClosedShell daemon.

## Context
ClosedShell runs agents inside a macOS sandbox. The `ask` binary lives at `crates/ask/src/main.rs` (currently a stub). It communicates with the daemon over a Unix socket using newline-delimited JSON.

The socket path comes from the environment variable `CLOSEDSHELL_SOCKET`.

## What to build

### 1. IPC client module
Create `crates/ask/src/ipc.rs` with a simple Unix socket client:

```rust
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

pub struct IpcClient {
    socket_path: String,
}

impl IpcClient {
    pub fn from_env() -> anyhow::Result<Self> {
        let socket_path = std::env::var("CLOSEDSHELL_SOCKET")
            .map_err(|_| anyhow::anyhow!("not running inside closedshell (CLOSEDSHELL_SOCKET not set)"))?;
        Ok(Self { socket_path })
    }

    pub fn send(&self, request: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let mut stream = UnixStream::connect(&self.socket_path)?;
        let mut req_str = serde_json::to_string(request)?;
        req_str.push('\n');
        stream.write_all(req_str.as_bytes())?;
        stream.flush()?;

        let mut reader = BufReader::new(&stream);
        let mut response = String::new();
        reader.read_line(&mut response)?;
        Ok(serde_json::from_str(&response)?)
    }
}
```

### 2. Main CLI with clap subcommands
Rewrite `crates/ask/src/main.rs` with these subcommands:

**ask status** - show current permission tree
Sends: {"type": "status"}, Prints: formatted rule list (forbids first, then permits)

**ask what-can-i <pattern>** - query matching rules
Sends: {"type": "what_can_i", "pattern": "<pattern>"}, Prints: matching rules

**ask why-denied** - explain last denial
Sends: {"type": "why_denied"}, Prints: action, reason, risk tier, hint

**ask allow <action>** - request permission for an action
Sends: {"type": "allow", "action": "<action>"}, Prints: granted rule or denial reason

**ask plan <description>** - submit a plan for approval
Sends: {"type": "plan", "description": "<desc>"}, Prints: plan_id, auto-approved, pending

**ask context <task>** - update session context
Sends: {"type": "context", "task": "<task>"}, Prints: updated task

**ask read <path>** - read a file through permission system
Sends: {"type": "read", "path": "<path>"}, Prints: file contents or denial

**ask write <path> <content>** - write a file through permission system
Sends: {"type": "write", "path": "<path>", "content": "<content>"}, Prints: bytes written or denial

### 3. Response handling
All responses have this shape:
```json
{"ok": true, "data": ...}
{"ok": false, "error": "not_permitted", "message": "...", "hint": "..."}
```

On error, print a human-friendly message to stderr with the hint if present, and exit 1.
On success, print the data formatted for humans.

### 4. Error handling
- If CLOSEDSHELL_SOCKET is not set: print "ask: not running inside closedshell" to stderr, exit 1
- If socket connection fails: print "ask: cannot connect to closedshell daemon" to stderr, exit 1
- If response is malformed: print the raw response and exit 1

### Dependencies
The ask crate already depends on: closedshell-lib, clap, serde_json, anyhow.
Use synchronous std::os::unix::net::UnixStream.

Add to crates/ask/Cargo.toml:
```toml
serde = { workspace = true }
```

### Output formatting
Keep it terse and terminal-friendly.

## Build commands
```bash
cargo build 2>&1
cargo test -p ask 2>&1
cargo clippy -- -D warnings 2>&1
cargo fmt --check 2>&1
```

Run all four after implementation. Fix any errors. Commit when green.
PROMPT

# AGENT 6: Additional E2E Tests
cat > "$PROMPT_DIR/e2e-tests.md" << 'PROMPT'
You are contributing to ClosedShell, a macOS sandbox for AI agents. Your task: add more integration tests.

## Context
ClosedShell has a MITM proxy that intercepts HTTPS, parses requests into canonical actions, and allows/denies based on a DecisionMaker. The existing e2e tests are in `crates/closedshell-lib/tests/e2e_proxy.rs` with helpers in `crates/closedshell-lib/tests/helpers/mod.rs`.

Read both files thoroughly to understand the test harness before writing new tests.

## What to build
Add more e2e tests to `e2e_proxy.rs`. The test harness spins up a real proxy with a test CA, makes HTTPS requests through it, and verifies behavior.

### Tests to add

1. **test_multiple_hosts_same_connection_strategy** - make requests to different hosts sequentially, verify each gets correct action parsing.

2. **test_large_response_body** - upstream returns a large response (>64KB), verify it's fully relayed without truncation.

3. **test_concurrent_requests** - spawn multiple tokio tasks making requests through the same proxy simultaneously. Verify all get correct responses and decision counter matches.

4. **test_post_with_body** - POST request with a JSON body, verify it reaches upstream intact.

5. **test_custom_decider_with_mixed_rules** - PatternDecider that allows some patterns and denies others. Verify correct allow/deny for each.

6. **test_audit_log_entries** - after several requests, read the audit log file and verify the NDJSON entries contain correct fields.

7. **test_proxy_handles_connection_close_gracefully** - client connects, sends one request, then drops the connection. Proxy should not panic.

8. **test_unknown_host_action_parsing** - request to a completely unknown host, verify it parses as net:METHOD:host/path.

9. **test_aws_with_auth_header** - AWS request with an Authorization header containing Credential=, verify the profile qualifier is extracted.

10. **test_keepalive_with_different_methods** - GET then POST on the same keepalive connection, verify both are independently parsed.

## Important
- Read the existing test harness first - use the same patterns
- Each test should be independent
- Use #[tokio::test] for async tests
- Tests must pass with `cargo test -p closedshell-lib`
- Don't modify existing tests

## Build commands
```bash
cargo test -p closedshell-lib 2>&1
cargo clippy -- -D warnings 2>&1
cargo fmt --check 2>&1
```

Run all three after implementation. Fix any errors. Commit when green.
PROMPT

# AGENT 7: IPC Socket Server
cat > "$PROMPT_DIR/ipc-server.md" << 'PROMPT'
You are contributing to ClosedShell, a macOS sandbox for AI agents. Your task: implement the Unix socket IPC server that the daemon runs, so the `ask` CLI inside the sandbox can communicate with the host.

## Context
ClosedShell's daemon (at crates/closedshell/src/main.rs) runs a MITM proxy and manages the sandbox. The `ask` CLI inside the sandbox needs to communicate with the daemon over a Unix socket. The socket path is set via CLOSEDSHELL_SOCKET env var (already passed through in main.rs).

## What to build

### 1. IPC server module
Create `crates/closedshell-lib/src/ipc.rs` and register it in `lib.rs`.

```rust
use tokio::net::UnixListener;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Request types from the ask CLI
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum IpcRequest {
    Status,
    WhatCanI { pattern: String },
    WhyDenied,
    Allow { action: String },
    Plan { description: String },
    Context { task: String },
    Read { path: String },
    Write { path: String, content: String },
}

/// Response back to ask CLI
#[derive(Debug, Serialize)]
pub struct IpcResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

impl IpcResponse {
    pub fn ok(data: serde_json::Value) -> Self { ... }
    pub fn err(error: &str, message: &str, hint: Option<&str>) -> Self { ... }
}

/// Handler trait for processing IPC requests
pub trait IpcHandler: Send + Sync + 'static {
    fn handle(&self, request: IpcRequest) -> IpcResponse;
}

/// The IPC server
pub struct IpcServer {
    socket_path: String,
    handler: Arc<dyn IpcHandler>,
}
```

### 2. Server implementation
IpcServer::new(socket_path, handler) and start() that:
- Removes stale socket file
- Binds UnixListener
- Spawns accept loop
- Each connection: read one JSON line -> deserialize -> call handler -> serialize response -> write line -> close
- Returns JoinHandle

### 3. A basic handler for YOLO mode
Implement a `YoloIpcHandler` that returns placeholder responses:
- status: returns empty rules list
- what_can_i: returns empty matches
- why_denied: returns "no denials in yolo mode"
- allow: returns ok (everything allowed in yolo)
- plan: returns a mock plan_id
- context: returns ok with the new task
- read: reads the file and returns content (real implementation)
- write: writes the file and returns bytes_written (real implementation)

### 4. Tests
- Test IpcRequest deserialization from JSON strings
- Test IpcResponse serialization
- Test actual Unix socket round-trip: start server, connect client, send request, get response
- Test invalid JSON input returns error response
- Test file read/write through IPC

## Build commands
```bash
cargo build 2>&1
cargo test -p closedshell-lib 2>&1
cargo clippy -- -D warnings 2>&1
cargo fmt --check 2>&1
```

Run all four after implementation. Fix any errors. Commit when green.
PROMPT

# ─────────────────────────────────────────────────────────────────
# Launch all agents
# ─────────────────────────────────────────────────────────────────
launch_agent "permission-tree"
launch_agent "judge-client"
launch_agent "parser-azure"
launch_agent "parser-k8s"
launch_agent "ask-cli"
launch_agent "e2e-tests"
launch_agent "ipc-server"

# ─────────────────────────────────────────────────────────────────
echo ""
echo "================================================"
echo "  All ${#PIDS[@]} agents launched!"
echo "================================================"
echo ""
echo "Agents:"
for i in "${!NAMES[@]}"; do
  echo "  ${NAMES[$i]} (PID: ${PIDS[$i]}) -> $LOG_DIR/${NAMES[$i]}.log"
done
echo ""
echo "Monitor all:  tail -f $LOG_DIR/*.log"
echo "Monitor one:  tail -f $LOG_DIR/<name>.log"
echo "Check status: ps -p ${PIDS[*]} -o pid,etime,command"
echo ""

# Wait for all agents
echo "Waiting for all agents to finish..."
FAILED=0
for i in "${!PIDS[@]}"; do
  wait "${PIDS[$i]}" && STATUS=0 || STATUS=$?
  if [ "$STATUS" -eq 0 ]; then
    echo "[$(date '+%H:%M:%S')] OK ${NAMES[$i]}"
  else
    echo "[$(date '+%H:%M:%S')] FAIL ${NAMES[$i]} (exit: $STATUS)"
    FAILED=$((FAILED + 1))
  fi
done

echo ""
echo "================================================"
echo "  Done! $((${#PIDS[@]} - FAILED))/${#PIDS[@]} succeeded."
echo "================================================"
echo ""
echo "Check PRs:"
echo "  gh pr list --author @me --state open"
echo ""
echo "To cleanup worktrees:"
echo "  git worktree prune"
