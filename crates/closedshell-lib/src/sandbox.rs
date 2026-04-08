//! Seatbelt sandbox: .sb profile generation and sandbox-exec wrapper.

/// Generate a seatbelt (.sb) profile string.
///
/// Strategy: allow everything by default, deny only network.
/// Network is the real enforcement layer — all outbound goes through the MITM proxy.
/// File writes are reviewable/reversible via git.
pub fn generate_seatbelt_profile(proxy_port: u16) -> String {
    let mut sb = String::new();
    sb.push_str("(version 1)\n");
    sb.push_str("(allow default)\n\n");

    // Network: deny all, then allow only proxy + unix sockets + DNS
    sb.push_str(";; Network: only localhost proxy, unix sockets, and DNS\n");
    sb.push_str("(deny network*)\n");
    sb.push_str("(allow network-outbound (literal \"/private/var/run/mDNSResponder\"))\n");
    sb.push_str("(allow network-outbound (remote unix-socket))\n");
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

    #[test]
    fn test_profile_allow_default() {
        let profile = generate_seatbelt_profile(8443);
        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(allow default)"));
    }

    #[test]
    fn test_profile_network_denied() {
        let profile = generate_seatbelt_profile(8443);
        assert!(profile.contains("(deny network*)"));
    }

    #[test]
    fn test_profile_network_proxy_allowed() {
        let profile = generate_seatbelt_profile(8443);
        assert!(profile.contains("(allow network-outbound (remote tcp \"localhost:8443\"))"));
        assert!(profile.contains("(allow network-outbound (remote unix-socket))"));
    }

    #[test]
    fn test_profile_dns_allowed() {
        let profile = generate_seatbelt_profile(8443);
        assert!(profile.contains("mDNSResponder"));
    }

    #[test]
    fn test_profile_localhost_inbound_allowed() {
        let profile = generate_seatbelt_profile(8443);
        assert!(profile.contains("(allow network-inbound (local tcp \"localhost:*\"))"));
    }

    #[test]
    fn test_profile_custom_port() {
        let profile = generate_seatbelt_profile(9999);
        assert!(profile.contains("(allow network-outbound (remote tcp \"localhost:9999\"))"));
        assert!(!profile.contains("8443"));
    }
}
