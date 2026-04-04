# Agent Instructions

You are implementing the YOLO shell for ClosedShell — a sandbox for AI agents on macOS.

## What is the YOLO shell?

The YOLO shell wraps a command (like `pi` or `claude-code`) in a macOS Seatbelt sandbox with an MITM proxy. All outbound HTTPS is intercepted, parsed into canonical actions, and logged — but **never blocked**. It's the observability-only foundation that later phases will add enforcement to.

## Your workflow

1. Check `current_tasks/` for unclaimed tasks (no `.lock` file with another agent's name)
2. Pick the highest-priority task you can work on (respect dependency order: 001 → 006)
3. Create a lock file: `current_tasks/<task>.lock` containing your agent ID
4. Read the task description carefully
5. Read the relevant spec docs in `docs/` for context
6. Implement the code
7. Run `cargo test` to verify your changes pass
8. Run `cargo clippy -- -D warnings` to check for lint issues
9. If tests pass: `git add`, `git commit`, `git push`
10. Remove your lock file
11. Start over from step 1

## Rules

- **Read before you write.** Always read existing code in the file before modifying it. Understand what's there.
- **Run tests before committing.** `cargo test` must pass. `cargo clippy -- -D warnings` must pass.
- **Small commits.** One logical change per commit. Don't bundle unrelated changes.
- **Pull before pushing.** `git pull --rebase` before `git push` to avoid conflicts.
- **If a test fails, fix it.** Don't skip tests or comment them out.
- **If you're stuck, document what you tried.** Write a note in the task file about what failed and why, then move to another task.
- **Don't modify CLAUDE.md, README.md, or docs/.** Those are the spec — treat them as requirements, not suggestions.
- **Don't add dependencies** not already in `Cargo.toml`. If you think you need one, document why in the task file.

## Project structure

```
crates/
  closedshell-lib/src/   # shared library
    config.rs             # config parsing (partially done)
    parser.rs             # provider parsers (partially done)
    audit.rs              # audit logging (done)
    tls.rs                # session CA + certs (TODO)
    proxy.rs              # MITM proxy (TODO)
    sandbox.rs            # seatbelt profile gen (TODO)
  closedshell/src/
    main.rs               # CLI + daemon lifecycle (TODO)
  ask/src/
    main.rs               # in-sandbox CLI (not needed for YOLO phase)
```

## What "done" looks like

The YOLO shell is done when you can run:

```bash
closedshell --yolo /bin/sh
```

And inside that shell:
1. Direct `curl https://example.com` is blocked by seatbelt (connection refused)
2. `curl https://httpbin.org/get` works through the proxy (env var forces it)
3. `aws s3 ls` works through the proxy
4. The audit log at `./closedshell-<session-id>.log` contains NDJSON entries for every request
5. Each entry has a parsed canonical action (e.g., `aws[profile=default]:s3:ListBuckets`)
6. Exiting the shell cleans up the tmpdir and stops the proxy

## Key specs

- Architecture: `docs/architecture.md`
- Proxy: `docs/proxy.md`
- Config example: see `README.md` § Configuration
