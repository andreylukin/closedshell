# Contributing Templates

Templates pre-approve network actions so agents can function without per-request human approval. This directory contains community-contributed templates that are embedded into the binary at compile time — no install step required.

Users can override any built-in template by placing a file with the same name in `~/.closedshell/templates/`.

## Structure

```
templates/
  <provider>/
    full.yaml          # allow everything for this provider
    readonly.yaml      # read-only access
    <profile>.yaml     # custom profile
```

## Template Format

```yaml
name: <provider>-<profile>
description: "Human-readable description of what this template allows"
rules:
  - effect: permit          # or "forbid"
    action: "net:*:api.example.com/*"
    type: idempotent         # or "one-shot"

  - effect: forbid
    action: "net:*:api.example.com/admin/*"
    reason: "admin endpoints not allowed"
```

### Required Fields

| Field | Description |
|-------|-------------|
| `name` | Unique identifier, format `<provider>-<profile>` |
| `description` | What this template permits (shown in `cs template list`) |
| `rules` | Array of permission rules |

### Rule Fields

| Field | Required | Values |
|-------|----------|--------|
| `effect` | yes | `permit` or `forbid` |
| `action` | yes | Action glob pattern |
| `type` | for permits | `idempotent` (persistent) or `one-shot` (consumed on use) |
| `reason` | for forbids | Why this action is blocked |

### Action Patterns

- Generic HTTP: `net:METHOD:host/path` (e.g., `net:*:api.github.com/*`)
- AWS: `aws[profile=*]:service:operation` (e.g., `aws[profile=*]:s3:List*`)
- GCP: `gcp[project=*]:service:operation`
- `*` matches any segment including `/` separators

## Guidelines

- One template per use case (full, readonly, minimal)
- Put forbid rules before permit rules for clarity
- Use the most specific patterns possible
- All bundled templates must pass `cs template validate` with no warnings

## Authoring Workflow

```bash
# 1. Scaffold
cs template init myservice
# → creates ~/.closedshell/templates/myservice/full.yaml

# 2. Edit the YAML
$EDITOR ~/.closedshell/templates/myservice/full.yaml

# 3. Validate — checks structure, flags missing reasons on forbids, bad types, etc.
cs template validate myservice/full

# 4. Test specific actions
cs template check myservice/full "net:GET:api.myservice.com/v1/data"
# → PERMIT — matched: net:*:api.myservice.com/*

cs template check myservice/full "net:DELETE:api.myservice.com/admin"
# → NO MATCH — would block for human approval

# 5. Test in a real session
cs --template myservice/full -- <command>
```

### Observe-then-codify workflow

If you're not sure which endpoints a provider uses, let ClosedShell observe the traffic first:

```bash
# Run in YOLO mode to capture all traffic
cs --yolo -- <command>

# Generate a template from the session and save it
cs template generate <session-id> --name myservice-full --save
# → saved to ~/.closedshell/templates/myservice/full.yaml

# Review and validate
cs template validate myservice/full
cs template show myservice/full
```

## Useful Commands

```
cs template list                         Show all templates with source (built-in vs user)
cs template show <name>                  Display resolved template YAML
cs template validate <name>              Validate and show permit/forbid summary
cs template check <name> <action>        Test if an action matches
cs template init <provider>              Scaffold a new template
cs template generate <session-id>        Generate from audit log (add --save to write to disk)
```

## Examples

See `anthropic/full.yaml` and `exa/` for reference implementations.
