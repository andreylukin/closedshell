# Task: Session CA and Dynamic Cert Generation

**Status:** not started

**What to do:**
1. Implement TLS cert generation in `crates/closedshell-lib/src/tls.rs` using `rcgen`
2. `SessionCA::new()` — generate a self-signed CA cert + key pair, valid for 24h
3. `SessionCA::generate_leaf_cert(hostname: &str)` — generate a leaf cert for a given hostname, signed by the session CA. Must include the hostname as a SAN (Subject Alternative Name).
4. `SessionCA::ca_pem()` — return the CA cert in PEM format (for writing to sandbox tmpdir as SSL_CERT_FILE)
5. Add a cert cache (HashMap<String, cert>) so we don't regenerate for the same hostname. Cache is session-scoped (lives as long as SessionCA).
6. Verify that two `SessionCA::new()` calls produce different CA fingerprints (test P5 in architecture.md)

**Tests that must pass:**
- `cargo test -p closedshell-lib tls`

**Files:**
- `crates/closedshell-lib/src/tls.rs`
