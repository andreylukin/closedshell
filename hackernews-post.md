# HN Post

**Title:** Show HN: ClosedShell – Network permissions for AI agents (macOS, Rust)

**URL:** https://github.com/andreylukin/closedshell

**Text:**

AI coding agents already ask before reading/writing your files. But they also inherit every credential on your machine — AWS keys, GitHub tokens, kubectl configs — and nobody checks what they do with them.

A Replit agent deleted a production database after ignoring explicit instructions 11 times. Amazon Q was tricked via a poisoned PR into terminating EC2 instances. These aren't hypothetical.

ClosedShell fills the gap: network-level permissions for AI agents on macOS. Every outbound HTTPS request is intercepted before leaving your machine, parsed into a human-readable action, and checked against your policy:

    aws:s3:DeleteBucket          → DENY  (forbid rule)
    net:GET:api.anthropic.com/*  → ALLOW (template)
    net:POST:api.unknown.com/v1  → BLOCK (asks you in a live TUI)

How it works: Seatbelt sandbox blocks all outbound except localhost:8443. A MITM proxy terminates TLS, parses requests into semantic actions (understands AWS SigV4, GCP, Azure, K8s, GitHub APIs natively), and evaluates them against a Cedar-inspired permission tree. Forbid always beats permit, default is deny, unknown actions block for human approval in a terminal UI.

One static Rust binary. No root. No kernel extensions. Works with any agent — Claude, Codex, Aider, or your own scripts.

    brew install andreylukin/tap/closedshell
    cs --template anthropic/full --template github/readonly -- claude

You can also run in YOLO mode (log everything, block nothing) and auto-generate a policy template from observed traffic.

macOS only for now (Seatbelt-specific). MIT licensed. Linux contributions welcome.
