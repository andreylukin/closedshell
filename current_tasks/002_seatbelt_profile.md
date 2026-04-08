# Task: Seatbelt Profile Generation

**Status:** not started

**What to do:**
1. Implement `sandbox::generate_seatbelt_profile()` in `crates/closedshell-lib/src/sandbox.rs`
2. Takes: proxy port
3. Returns: String containing the .sb profile content
4. Profile must:
   - `(allow default)` — allow everything by default
   - `(deny network*)` — deny all network
   - `(allow network-outbound (remote tcp "localhost:<port>"))` — except proxy
   - `(allow network-outbound (remote unix-socket))` — allow unix sockets for ask CLI
   - `(allow network-inbound (local tcp "localhost:*"))` — allow local dev servers
5. Add tests that verify the generated profile contains expected rules

**Tests that must pass:**
- `cargo test -p closedshell-lib sandbox`

**Files:**
- `crates/closedshell-lib/src/sandbox.rs`
