//! Seatbelt sandbox: .sb profile generation and sandbox-exec wrapper.

/// Generate a seatbelt (.sb) profile string.
///
/// Strategy: allow everything by default, deny only network and sensitive files.
/// Network is the real enforcement layer — all outbound goes through the MITM proxy.
/// File writes are reviewable/reversible via git.
///
/// `ipc_socket_path`: absolute path to the IPC socket (e.g. /tmp/closedshell-XXXX/ask.sock).
/// `ca_key_path`: absolute path to the CA private key to deny agent access.
pub fn generate_seatbelt_profile(
    proxy_port: u16,
    ipc_socket_path: &str,
    ca_key_path: &str,
) -> String {
    let mut sb = String::new();
    sb.push_str("(version 1)\n");
    sb.push_str("(allow default)\n\n");

    // Deny agent access to the CA private key — prevents cert forgery
    sb.push_str(";; Protect CA private key from sandboxed process\n");
    sb.push_str(&format!(
        "(deny file-read* (literal \"{}\"))\n\n",
        ca_key_path
    ));

    // Network: deny all, then allow only proxy + IPC socket + DNS
    sb.push_str(";; Network: only localhost proxy, IPC socket, and DNS\n");
    sb.push_str("(deny network*)\n");
    sb.push_str("(allow network-outbound (literal \"/private/var/run/mDNSResponder\"))\n");
    // Only allow the specific IPC socket, not all unix sockets
    sb.push_str(&format!(
        "(allow network-outbound (literal \"{}\"))\n",
        ipc_socket_path
    ));
    sb.push_str(&format!(
        "(allow network-outbound (remote tcp \"localhost:{}\"))\n",
        proxy_port
    ));
    // Allow inbound on localhost (dev servers, LSPs, etc.)
    sb.push_str("(allow network-inbound (local tcp \"localhost:*\"))\n");

    sb
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOCKET: &str = "/tmp/closedshell-test/ask.sock";
    const CA_KEY: &str = "/Users/test/.closedshell/ca-key.pem";

    fn profile(port: u16) -> String {
        generate_seatbelt_profile(port, SOCKET, CA_KEY)
    }

    #[test]
    fn test_profile_allow_default() {
        let p = profile(8443);
        assert!(p.contains("(version 1)"));
        assert!(p.contains("(allow default)"));
    }

    #[test]
    fn test_profile_network_denied() {
        let p = profile(8443);
        assert!(p.contains("(deny network*)"));
    }

    #[test]
    fn test_profile_network_proxy_allowed() {
        let p = profile(8443);
        assert!(p.contains("(allow network-outbound (remote tcp \"localhost:8443\"))"));
    }

    #[test]
    fn test_profile_ipc_socket_allowed() {
        let p = profile(8443);
        assert!(p.contains(&format!(
            "(allow network-outbound (literal \"{}\"))",
            SOCKET
        )));
    }

    #[test]
    fn test_profile_no_blanket_unix_socket() {
        let p = profile(8443);
        assert!(!p.contains("(allow network-outbound (remote unix-socket))"));
    }

    #[test]
    fn test_profile_ca_key_denied() {
        let p = profile(8443);
        assert!(p.contains(&format!("(deny file-read* (literal \"{}\"))", CA_KEY)));
    }

    #[test]
    fn test_profile_dns_allowed() {
        let p = profile(8443);
        assert!(p.contains("mDNSResponder"));
    }

    #[test]
    fn test_profile_localhost_inbound_allowed() {
        let p = profile(8443);
        assert!(p.contains("(allow network-inbound (local tcp \"localhost:*\"))"));
    }

    #[test]
    fn test_profile_custom_port() {
        let p = profile(9999);
        assert!(p.contains("(allow network-outbound (remote tcp \"localhost:9999\"))"));
        assert!(!p.contains("8443"));
    }
}
