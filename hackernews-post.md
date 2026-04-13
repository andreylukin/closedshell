# HN Post

**Title:** Show HN: ClosedShell – A MITM proxy that parses your AI agent's API calls and asks before allowing them

**URL:** https://github.com/andreylukin/closedshell

**Text (post body):**

Most agent sandboxes focus on the filesystem. ClosedShell focuses on the network. It intercepts every outbound HTTPS request, terminates TLS, and parses the request into a semantic action. An S3 delete becomes `aws:s3:DeleteBucket`. A GitHub push becomes `gh:repos/org/repo:POST`. Built-in parsers for AWS (reads SigV4 headers), GCP, Azure, K8s, and GitHub. Unknown hosts fall back to `net:METHOD:host/path`.

You write permit/forbid policies using a Cedar-inspired format and stack templates per provider. Forbid always beats permit, default is deny, and anything not covered blocks in a live terminal UI until you approve or reject it. The proxy holds the connection while you decide.

If you don't know what your agent calls yet, run in observe mode (log everything, block nothing) and auto-generate a policy from the traffic.

One Rust binary, no root, no kernel extensions. macOS only (Seatbelt + MITM proxy). MIT licensed.

---

**Intro comment (post as first reply to your own submission):**

I built this because file-level sandboxing felt like half the picture. My agent can't overwrite /etc/passwd, great. But it still has my AWS keys, my GitHub token, and my kubectl context. One bad tool call and it's making API calls I never intended, with my credentials, against production infrastructure.

Existing sandboxes mostly stop at the filesystem or block entire hosts. I wanted something that understands what the agent is actually doing at the API level. When my agent calls S3, I want to know if it's listing buckets or deleting them, and I want different policies for each.

The proxy parses requests into structured actions using provider-specific logic (AWS SigV4 signatures, GCP REST paths, etc.), then evaluates them against a permission tree. Templates ship for Anthropic, OpenAI, GitHub, and Exa so you can get started without approving every single request manually.

Happy to answer any questions about the design or take feedback on the policy format.
