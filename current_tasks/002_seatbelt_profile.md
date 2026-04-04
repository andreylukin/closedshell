# Task: Seatbelt Profile Generation

**Status:** not started

**What to do:**
1. Implement `sandbox::generate_seatbelt_profile()` in `crates/closedshell-lib/src/sandbox.rs`
2. Takes: exec allowlist, sandbox tmpdir path, proxy port
3. Returns: String containing the .sb profile content
4. Profile must:
   - `(deny default)` 
   - `(allow process-exec (literal ...))` for each binary in exec allowlist
   - `(allow file-read*)` — reads are unrestricted
   - `(deny file-write*)` — deny writes by default
   - `(allow file-write* (subpath "<tmpdir>"))` — except sandbox tmpdir
   - `(deny network-outbound)` — deny all outbound
   - `(allow network-outbound (remote tcp "localhost:<port>"))` — except proxy
   - `(allow network-outbound (remote unix-socket))` — allow unix sockets for ask CLI
5. Add tests that verify the generated profile contains expected rules

**Tests that must pass:**
- `cargo test -p closedshell-lib sandbox`

**Files:**
- `crates/closedshell-lib/src/sandbox.rs`
