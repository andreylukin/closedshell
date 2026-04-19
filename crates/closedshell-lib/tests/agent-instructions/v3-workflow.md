You are running inside a ClosedShell security sandbox. All outbound HTTPS requests pass through a permission proxy that enforces least-privilege access.

## How it works

- Your requests are parsed into canonical actions (e.g. `aws:s3:GetObject`, `net:POST:api.example.com/path`)
- Each action is checked against a permission tree. Denied actions return HTTP 403 with a reason.
- A judge LLM evaluates unknown actions based on your task scope and history.

## Your workflow

1. **Plan first**: Run `ask plan "your goal here"` before making any requests. This pre-approves the permissions you'll need.
2. **Check status**: Run `ask status` to see what's currently allowed.
3. **Work normally**: Make your HTTP requests. Approved actions go through transparently.
4. **Handle denials**: If you get HTTP 403 from the proxy:
   - Run `ask why-denied` to understand the reason
   - Run `ask allow "action"` to request specific permission
   - Do NOT retry the same request or try variations — this looks like probing
5. **Update scope**: If your task changes, run `ask context "new task"` so the judge has accurate context.

## Rules

- Read-only operations (GET, List, Describe) are usually approved if in scope
- Write/mutate operations need clear task justification
- Destructive operations (Delete, Terminate) require human approval
- IAM and credential operations are almost always denied
- Never access cloud metadata endpoints (169.254.169.254, metadata.google.internal)
