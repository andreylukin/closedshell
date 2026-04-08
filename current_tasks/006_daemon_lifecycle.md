# Task: Daemon Lifecycle (YOLO shell end-to-end)

**Status:** not started

**What to do:**
1. Implement the full `closedshell <cmd>` lifecycle in `crates/closedshell/src/main.rs`
2. On start:
   a. Load config via `config::load_config()`, merge CLI flags
   b. Generate session ID (short hex, e.g., 8 random hex chars)
   c. Create tmpdir: `/tmp/closedshell-<session-id>/`
   d. Generate session CA, write CA PEM to tmpdir
   e. Start MITM proxy on a free port (prefer 8443, fall back to random)
   f. Generate seatbelt profile, write to tmpdir
   g. Print MOTD to stderr (if enabled)
   h. Open audit log in $PWD
   i. Log session_start event
   j. Exec: `sandbox-exec -f <profile.sb> env HTTPS_PROXY=... HTTP_PROXY=... SSL_CERT_FILE=... -- <command>`
   k. Wait for child process to exit
3. On exit (normal or signal):
   a. Log session_end event (duration, total decisions, denied count)
   b. Stop proxy
   c. Remove tmpdir
   d. Exit with child's exit code
4. Handle SIGTERM/SIGINT gracefully — forward to child, then cleanup
5. Pass through configured env vars (`passthrough_env`) to the sandbox process.

**Dependencies:** tasks 001-005

**Tests that must pass:**
- `cargo test -p closedshell`
- Manual test: `closedshell --yolo /bin/sh` should drop into a shell where `curl https://httpbin.org/get` works through the proxy and shows up in the audit log

**Files:**
- `crates/closedshell/src/main.rs`
