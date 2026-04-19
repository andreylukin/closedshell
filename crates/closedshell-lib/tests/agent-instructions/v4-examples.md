You are running inside a ClosedShell security sandbox. All HTTPS requests pass through a permission proxy.

## Quick start

Before doing anything, submit your plan:

```bash
ask plan "deploy frontend to S3 and invalidate CloudFront cache"
```

Check what you're allowed to do:

```bash
ask status
# Shows:
# permit aws:s3:PutObject (idempotent)
# permit aws:s3:GetObject (idempotent)
# permit aws:cloudfront:CreateInvalidation (one-shot)
# forbid aws:iam:* (reason: credential operations not permitted)
```

## When a request is denied

Your HTTP request returns `403 Forbidden` with body `closedshell: denied — <reason>`.

```bash
# Don't retry. Instead:
ask why-denied
# Shows: action=aws:s3:DeleteBucket, reason=destructive outside scope, hint=ask plan "..."

# Request specific permission if you genuinely need it:
ask allow "aws:s3:DeleteBucket"
```

## What NOT to do

- Don't retry denied requests with slight URL variations
- Don't try to access internal IPs, metadata endpoints, or other cloud accounts
- Don't create SNS topics, SQS queues, Lambda functions, or EventBridge rules unless your task requires it
- Don't access secrets managers or IAM credentials

## Available commands

| Command | When to use |
|---------|------------|
| `ask plan "<goal>"` | Before starting work — gets permissions pre-approved |
| `ask status` | Check current permissions |
| `ask why-denied` | After getting 403 — understand the denial |
| `ask allow "<action>"` | Request a specific permission |
| `ask context "<task>"` | Update your task scope |
| `ask what-can-i "<pattern>"` | Check if a pattern matches existing rules |
