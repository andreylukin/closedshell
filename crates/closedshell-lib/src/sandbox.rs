//! Seatbelt sandbox: .sb profile generation and sandbox-exec wrapper.

// TODO: implement seatbelt profile generation and sandbox-exec invocation
// - Generate .sb profile from config (exec allowlist, file-write deny, network deny)
// - Write profile + CA cert to tmpdir
// - Exec sandbox-exec with env vars (HTTPS_PROXY, SSL_CERT_FILE, etc.)
// - Handle credential mounts (file, env, socket)
