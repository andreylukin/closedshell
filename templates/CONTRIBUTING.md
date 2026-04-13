# Contributing Templates

Templates pre-approve network actions so agents can function without per-request human approval. This directory contains built-in templates that are embedded into the binary at compile time — no install step required.

Users can override any built-in template by placing a file with the same name in `~/.closedshell/templates/`.

## Structure

```
templates/
  <provider>/
    full.csp             # allow everything for this provider
    readonly.csp         # read-only access
    <profile>.csp        # custom profile
```

## Template Format (CSP)

Templates use a Cedar-inspired `.csp` (ClosedShell Policy) format:

```
@name("myservice-full")
@description("Allow all MyService API endpoints")

// Broad access
permit (action == "net:*:api.myservice.com/*");

// Block admin endpoints
forbid (action == "net:*:api.myservice.com/admin/*")
  reason("admin endpoints not allowed");
```

### Annotations

| Annotation | Required | Description |
|------------|----------|-------------|
| `@name("...")` | yes | Unique identifier, format `<provider>-<profile>` |
| `@description("...")` | yes | What this template permits (shown in `cs template list`) |

### Rules

Each rule is a single statement:

```
permit (action == "<pattern>");

forbid (action == "<pattern>")
  reason("<why>");
```

- `permit` — allow matching actions. Persistent for the session (idempotent).
- `forbid` — hard deny. Always overrides permit. Must include a `reason(...)`.
- Comments: `//` for line comments.

### Action Patterns

Patterns use glob matching (`*` matches any characters):

| Pattern | Matches |
|---------|---------|
| `net:*:api.github.com/*` | Any method to any GitHub API path |
| `net:GET:api.github.com/*` | GET only to GitHub API |
| `aws[profile=*]:s3:List*` | Any AWS profile, S3 list operations |
| `gcp[project=*]:compute:*` | Any GCP project, all compute operations |

Generic HTTP: `net:METHOD:host/path`
AWS: `aws[profile=*]:service:operation`
GCP: `gcp[project=*]:service:operation`

`forbid` always wins over `permit` — you can broadly allow a service and carve out dangerous operations.

## Guidelines

- One template per use case (full, readonly, minimal)
- Put forbid rules before permit rules for clarity
- Use the most specific patterns possible
- All bundled templates must pass `cs template validate` with no warnings

## Authoring Workflow

```bash
# 1. Scaffold
cs template init myservice
# → creates ~/.closedshell/templates/myservice/full.csp

# 2. Edit
$EDITOR ~/.closedshell/templates/myservice/full.csp

# 3. Validate
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

If you're not sure which endpoints a service uses, let ClosedShell observe the traffic first:

```bash
# Run in YOLO mode to capture all traffic
cs --yolo -- <command>

# Generate a template from the session and save it
cs template generate <session-id> --name myservice-full --save
# → saved to ~/.closedshell/templates/myservice/full.csp

# Review and validate
cs template validate myservice/full
cs template show myservice/full
```

## Template Commands

```
cs template list                         Show all templates with source (built-in vs user)
cs template show <name>                  Display resolved template content
cs template validate <name>              Validate and show permit/forbid summary
cs template check <name> <action>        Test if an action matches
cs template init <provider>              Scaffold a new template
cs template generate <session-id>        Generate from audit log (add --save to write to disk)
```

## Resolution Order

When you pass `--template myservice/full`, ClosedShell looks in order:

1. Exact file path (absolute or relative)
2. `~/.closedshell/templates/myservice/full.csp` (your custom templates)
3. Built-in templates (compiled into the binary)

User templates override built-in ones with the same name.

## Examples

See `anthropic/full.csp` and `github/readonly.csp` for reference implementations.
