//! Seatbelt sandbox: .sb profile generation and sandbox-exec wrapper.

use std::path::Path;

/// Generate a seatbelt (.sb) profile string.
///
/// The profile:
/// - Denies everything by default
/// - Allows process-exec for binaries in the exec allowlist
/// - Allows all file reads
/// - Denies all file writes except to the sandbox tmpdir
/// - Denies all network outbound except localhost on the proxy port and unix sockets
pub fn generate_seatbelt_profile(
    exec_allowlist: &[String],
    tmpdir: &Path,
    proxy_port: u16,
) -> String {
    let mut sb = String::new();
    sb.push_str("(version 1)\n");
    sb.push_str("(deny default)\n\n");

    // Process execution: allow only allowlisted binaries
    sb.push_str(";; Process execution allowlist\n");
    if !exec_allowlist.is_empty() {
        sb.push_str("(allow process-exec\n");
        for bin in exec_allowlist {
            sb.push_str(&format!("  (literal \"{}\")\n", bin));
        }
        sb.push_str(")\n");
    }
    sb.push('\n');

    // Allow process-fork so child processes work
    sb.push_str("(allow process-fork)\n\n");

    // File reads: unrestricted
    sb.push_str(";; File reads: unrestricted\n");
    sb.push_str("(allow file-read*)\n\n");

    // File writes: deny by default, allow sandbox tmpdir
    sb.push_str(";; File writes: deny by default, allow sandbox tmpdir\n");
    sb.push_str("(deny file-write*)\n");
    sb.push_str(&format!(
        "(allow file-write* (subpath \"{}\"))\n\n",
        tmpdir.display()
    ));

    // Network: deny all outbound except proxy port and unix sockets
    sb.push_str(";; Network: deny all outbound except proxy and unix sockets\n");
    sb.push_str("(deny network-outbound)\n");
    sb.push_str(&format!(
        "(allow network-outbound (remote tcp \"localhost:{}\"))\n",
        proxy_port
    ));
    sb.push_str("(allow network-outbound (remote unix-socket))\n");

    sb
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_profile_contains_version_and_deny_default() {
        let profile = generate_seatbelt_profile(&[], Path::new("/tmp/cs-test"), 8443);
        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default)"));
    }

    #[test]
    fn test_profile_exec_allowlist() {
        let allowlist = vec![
            "/bin/sh".to_string(),
            "/bin/bash".to_string(),
            "/usr/bin/env".to_string(),
        ];
        let profile = generate_seatbelt_profile(&allowlist, Path::new("/tmp/cs-test"), 8443);
        assert!(profile.contains("(allow process-exec"));
        assert!(profile.contains("(literal \"/bin/sh\")"));
        assert!(profile.contains("(literal \"/bin/bash\")"));
        assert!(profile.contains("(literal \"/usr/bin/env\")"));
    }

    #[test]
    fn test_profile_empty_allowlist() {
        let profile = generate_seatbelt_profile(&[], Path::new("/tmp/cs-test"), 8443);
        // Should not have process-exec allow when allowlist is empty
        assert!(!profile.contains("(allow process-exec"));
    }

    #[test]
    fn test_profile_file_read_allowed() {
        let profile = generate_seatbelt_profile(&[], Path::new("/tmp/cs-test"), 8443);
        assert!(profile.contains("(allow file-read*)"));
    }

    #[test]
    fn test_profile_file_write_rules() {
        let profile = generate_seatbelt_profile(&[], Path::new("/tmp/closedshell-abc123"), 8443);
        assert!(profile.contains("(deny file-write*)"));
        assert!(profile.contains("(allow file-write* (subpath \"/tmp/closedshell-abc123\"))"));
    }

    #[test]
    fn test_profile_network_rules() {
        let profile = generate_seatbelt_profile(&[], Path::new("/tmp/cs-test"), 8443);
        assert!(profile.contains("(deny network-outbound)"));
        assert!(profile.contains("(allow network-outbound (remote tcp \"localhost:8443\"))"));
        assert!(profile.contains("(allow network-outbound (remote unix-socket))"));
    }

    #[test]
    fn test_profile_custom_port() {
        let profile = generate_seatbelt_profile(&[], Path::new("/tmp/cs-test"), 9999);
        assert!(profile.contains("(allow network-outbound (remote tcp \"localhost:9999\"))"));
        assert!(!profile.contains("8443"));
    }

    #[test]
    fn test_profile_process_fork_allowed() {
        let profile = generate_seatbelt_profile(&[], Path::new("/tmp/cs-test"), 8443);
        assert!(profile.contains("(allow process-fork)"));
    }

    #[test]
    fn test_full_profile_snapshot() {
        let allowlist = vec!["/bin/sh".to_string()];
        let profile = generate_seatbelt_profile(
            &allowlist,
            &PathBuf::from("/tmp/closedshell-deadbeef"),
            8443,
        );
        // Verify ordering: version, deny default, then rules
        let version_pos = profile.find("(version 1)").unwrap();
        let deny_pos = profile.find("(deny default)").unwrap();
        let exec_pos = profile.find("(allow process-exec").unwrap();
        assert!(version_pos < deny_pos);
        assert!(deny_pos < exec_pos);
    }
}
