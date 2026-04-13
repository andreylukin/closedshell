# HN Post

**Title:** Show HN: ClosedShell – Network permissions for AI agents (macOS, Rust)

**URL:** https://github.com/andreylukin/closedshell

**Text:**

Agents inherit every credential on your machine — AWS keys, GitHub tokens, kubectl configs — and nobody checks what they do with them. A Replit agent deleted a production database after ignoring instructions 11 times. Amazon Q was tricked via a poisoned PR into terminating EC2 instances.

ClosedShell is a macOS sandbox that intercepts every outbound HTTPS request from your agent, parses it into a human-readable action, and checks it against your policy. One Rust binary, no root, no kernel extensions.

    brew install andreylukin/tap/closedshell
    cs --template anthropic/full --template github/readonly -- claude

Policies are simple templates using a Cedar-inspired format. Stack them to build the exact permission surface you want:

    # Let Claude talk to its own API, but let it only read GitHub
    cs --template anthropic/full --template github/readonly -- claude

    # Give Codex full OpenAI + full GitHub access
    cs --template openai/full --template github/full -- codex

What a template looks like — github/readonly:

    permit (action == "net:GET:api.github.com/*");
    permit (action == "net:GET:github.com/*");

Or restrict an API to specific endpoints — exa/search-only:

    forbid (action == "net:*:api.exa.ai/contents");
    forbid (action == "net:*:api.exa.ai/findSimilar");
    permit (action == "net:*:api.exa.ai/search");

Forbid always beats permit. Everything not explicitly permitted blocks and asks you in a live TUI. The proxy holds the connection until you decide.

Don't know what your agent calls? Run YOLO mode first, then generate a template from observed traffic:

    cs --yolo -- claude
    cs template generate <session-id> --name myservice --save

macOS only (uses Seatbelt). MIT licensed. Linux contributions welcome.
