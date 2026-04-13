# HN Post

**Title:** Show HN: ClosedShell – Network permissions for AI agents (macOS, Rust)

**URL:** https://github.com/andreylukin/closedshell

**Text:**

Agents inherit every credential on your machine. AWS keys, GitHub tokens, kubectl configs. And nobody checks what they do with them. A Replit agent deleted a production database after ignoring instructions 11 times. Amazon Q was tricked via a poisoned PR into terminating EC2 instances.

ClosedShell is a macOS sandbox that intercepts every outbound HTTPS request from your agent, parses it into a human-readable action, and checks it against your policy. One Rust binary, no root, no kernel extensions.

You define what's allowed using simple policy templates in a Cedar-inspired format. Templates ship for common providers (Anthropic, OpenAI, GitHub, Exa) and you can stack them to build the exact permission surface you want. Give Claude access to its own API but restrict GitHub to read-only. Give Codex full OpenAI and full GitHub. Restrict a search API to just the search endpoint while blocking its other routes. The format is just permit/forbid rules with glob patterns.

Forbid always beats permit. Everything not explicitly permitted blocks and asks you in a live terminal UI. The proxy holds the connection until you decide.

If you don't know what your agent calls yet, you can run in YOLO mode (log everything, block nothing) and then auto-generate a template from observed traffic. Observe first, enforce later.

macOS only (uses Seatbelt for sandboxing). MIT licensed. Linux contributions welcome.
