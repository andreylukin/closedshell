# Contributing Templates

Templates pre-approve network actions so agents can function without per-request human approval. This directory contains community-contributed templates.

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
- Test with `cs --template <path> -- <command>` before submitting

## Quick Start

```bash
# Scaffold a new template
cs template init myservice

# List available templates
cs template list

# Generate from a YOLO session
cs --yolo -- <command>
cs template generate <session-id> --name myservice-full
```

## Examples

See `anthropic/full.yaml` and `exa/` for reference implementations.
