# HN Post

**Title:** Show HN: ClosedShell - single Rust binary that intercepts your AI agent's API calls at L7 (macOS)

**URL:** https://github.com/andreylukin/closedshell

**Text field:** leave blank (URL post, body goes in first comment)

---

**First comment (post immediately after submitting):**

I've been using Claude Code to do Terraform and set up a new AWS region from scratch. I want to move fast and let the agent do its thing, but I also want to define the edges. Reads are fine. Writes need a second look. Deletes should never happen without me saying so.

Most agent sandboxes solve this at the filesystem or syscall level. That's useful, but it doesn't help when the agent is making HTTP calls to cloud APIs using your credentials. ClosedShell sits at the network layer instead. It intercepts every outbound HTTPS request, terminates TLS, and parses the actual API call. An S3 request becomes `aws:s3:DeleteBucket` or `aws:s3:ListBuckets`, not just "a POST to s3.amazonaws.com". Built-in parsers for AWS (reads SigV4 headers), GCP, Azure, K8s, and GitHub.

You pre-approve what you know is fine using stackable templates (ship with Anthropic, OpenAI, GitHub, Exa built-in). Everything else blocks in a live TUI and the proxy holds the connection until you decide. Forbid always beats permit, default is deny.

If you don't know what your agent calls yet, run in observe mode first, then auto-generate a policy from the traffic.

Single Rust binary, no root, no kernel extensions, just Seatbelt + a local MITM proxy. macOS only for now. MIT licensed, Linux contributions welcome.

Happy to answer questions about the proxy design or the policy format.
