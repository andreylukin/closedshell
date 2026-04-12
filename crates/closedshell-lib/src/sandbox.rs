//! Seatbelt sandbox: .sb profile generation and sandbox-exec wrapper.

/// Escape special regex characters in a path for use in Seatbelt regex rules.
fn regex_escape(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        match c {
            '.' | '(' | ')' | '[' | ']' | '{' | '}' | '*' | '+' | '?' | '|' | '^' | '$' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// Generate a seatbelt (.sb) profile string.
///
/// Strategy: allow everything by default, deny network + sensitive file access.
/// Network is the real enforcement layer — all outbound goes through the MITM proxy.
/// File denies prevent persistence attacks (shell rc injection) and credential theft.
///
/// `home`: user's home directory (e.g. /Users/alice).
/// `ipc_socket_path`: absolute path to the IPC socket (e.g. /tmp/closedshell-XXXX/ask.sock).
/// `ca_key_path`: absolute path to the CA private key to deny agent access.
pub fn generate_seatbelt_profile(
    proxy_port: u16,
    home: &str,
    ipc_socket_path: &str,
    ca_key_path: &str,
) -> String {
    let mut sb = String::new();
    sb.push_str("(version 1)\n");
    sb.push_str("(allow default)\n\n");

    // -- File protection: deny writes to shell config and sensitive directories --
    //
    // Using regex instead of literal because tools like Claude Code bypass literal
    // denies via hardlink creation (link temp → .zshrc.new) + rename chains.
    // The regex catches the canonical path and any suffixed variants (.zshrc.new, etc.)
    sb.push_str(";; Prevent persistence attacks via shell rc injection\n");
    sb.push_str(";; Uses regex to catch hardlink/rename bypass (temp.new → .zshrc)\n");
    for rc in &[
        ".bashrc",
        ".bash_profile",
        ".bash_login",
        ".profile",
        ".zshrc",
        ".zprofile",
        ".zshenv",
        ".zlogin",
    ] {
        // Deny writes to the file itself AND any suffixed variant (e.g. .zshrc.new, .zshrc.tmp)
        sb.push_str(&format!(
            "(deny file-write* (regex \"^{}/{}(\\..+)?$\"))\n",
            regex_escape(home),
            regex_escape(rc)
        ));
    }
    sb.push('\n');

    sb.push_str(";; Protect credential stores — deny all access (read + write)\n");
    for dir in &[".ssh", ".gnupg", ".closedshell"] {
        sb.push_str(&format!(
            "(deny file-read* file-write* (subpath \"{}/{}\"))\n",
            home, dir
        ));
    }
    // AWS credentials: deny the secrets, allow config (region/profile names are harmless)
    sb.push_str(&format!(
        "(deny file-read* file-write* (regex \"^{}/\\.aws/(credentials|sso/cache)$\"))\n",
        regex_escape(home)
    ));
    sb.push('\n');

    // Deny agent access to the CA private key — prevents cert forgery
    // (redundant with .closedshell subpath deny above, but explicit for defense-in-depth)
    sb.push_str(";; Protect CA private key from sandboxed process\n");
    sb.push_str(&format!(
        "(deny file-read* (literal \"{}\"))\n\n",
        ca_key_path
    ));

    // -- Network: deny all, then allow only proxy + IPC socket + DNS --
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

    const HOME: &str = "/Users/test";
    const SOCKET: &str = "/tmp/closedshell-test/ask.sock";
    const CA_KEY: &str = "/Users/test/.closedshell/ca-key.pem";

    fn profile(port: u16) -> String {
        generate_seatbelt_profile(port, HOME, SOCKET, CA_KEY)
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

    #[test]
    fn test_profile_denies_shell_rc_writes_via_regex() {
        let p = profile(8443);
        // Regex-based deny catches hardlink/rename bypass patterns
        for rc in &[".bashrc", ".zshrc", ".zprofile", ".profile", ".zshenv"] {
            let escaped_home = super::regex_escape(HOME);
            let escaped_rc = super::regex_escape(rc);
            // The profile contains literal regex: (\..+)? — one backslash in the output
            let expected = format!(
                "(deny file-write* (regex \"^{}/{}(\\..+)?$\"))",
                escaped_home, escaped_rc
            );
            assert!(
                p.contains(&expected),
                "should deny writes to {}: expected '{}' in profile:\n{}",
                rc,
                expected,
                p
            );
        }
    }

    #[test]
    fn test_profile_denies_credential_dirs() {
        let p = profile(8443);
        for dir in &[".ssh", ".gnupg", ".closedshell"] {
            assert!(
                p.contains(&format!(
                    "(deny file-read* file-write* (subpath \"{}/{}\")",
                    HOME, dir
                )),
                "should deny access to {}",
                dir
            );
        }
    }

    #[test]
    fn test_profile_denies_aws_credentials() {
        let p = profile(8443);
        assert!(p.contains(".aws/(credentials|sso/cache)"));
    }

    #[test]
    fn test_regex_escape() {
        assert_eq!(super::regex_escape("/Users/test"), "/Users/test");
        assert_eq!(
            super::regex_escape("/path.with.dots"),
            "/path\\.with\\.dots"
        );
        assert_eq!(super::regex_escape("a(b)c"), "a\\(b\\)c");
    }
}
