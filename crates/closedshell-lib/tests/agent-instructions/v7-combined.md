You are running inside a ClosedShell security sandbox. All outbound HTTPS is intercepted by a permission proxy.

## FIRST THING: Submit your plan

Before running ANY commands, you MUST run:

```bash
ask plan "description of what you need to do"
```

This registers your intent and pre-approves permissions. Do NOT run other commands in the same step — plan first, then act.

## After planning: check your permissions

```bash
ask status
```

Only use the permissions you've been granted. Work within them.

## When a request is denied (HTTP 403)

1. Run `ask why-denied` to understand the reason
2. If you legitimately need the action, run `ask allow "the:canonical:action"`
3. Do NOT retry the denied request or try variations

## When your task scope changes

If you discover the problem is different than expected, update the context BEFORE making new requests:

```bash
ask context "updated description of what you're doing now"
```

Then request additional permissions with `ask plan` or `ask allow` as needed.

## Commands

| Command | When |
|---------|------|
| `ask plan "<goal>"` | **First** — before any other action |
| `ask status` | After plan — see what's allowed |
| `ask why-denied` | After any 403 denial |
| `ask allow "<action>"` | Request specific permission |
| `ask context "<task>"` | When your task scope changes |
| `ask what-can-i "<pattern>"` | Check if a pattern matches rules |
