//! macOS pf (packet filter) enforcement — secondary network control layer.
//!
//! When enabled via `--pf`, loads per-session pf anchor rules that block direct
//! outbound HTTP/HTTPS from the sandboxed user. This provides defense-in-depth:
//! even if the Seatbelt sandbox is bypassed, pf prevents the agent from reaching
//! external hosts without going through the MITM proxy.
//!
//! Requires a one-time `--pf-setup` to create the `_closedshell` system user
//! and register the pf anchor. Both operations need root.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Default system user for sandboxed processes.
pub const DEFAULT_PF_USER: &str = "_closedshell";

/// Top-level pf anchor name. Session anchors nest under this.
const ANCHOR_ROOT: &str = "com.closedshell";

/// Manages pf anchor lifecycle for a single session.
pub struct PfEnforcer {
    anchor: String,
    rules_path: PathBuf,
}

impl PfEnforcer {
    /// Create a new enforcer, write rules to `tmpdir/pf.rules`, but don't load yet.
    pub fn new(
        session_id: &str,
        proxy_port: u16,
        sandbox_uid: u32,
        tmpdir: &Path,
    ) -> anyhow::Result<Self> {
        let iface = detect_default_interface()?;
        let rules = generate_rules(proxy_port, sandbox_uid, &iface);
        let rules_path = tmpdir.join("pf.rules");
        std::fs::write(&rules_path, &rules)?;

        Ok(Self {
            anchor: format!("{}/{}", ANCHOR_ROOT, session_id),
            rules_path,
        })
    }

    /// Load the rules into the pf anchor. Requires root.
    pub fn load(&self) -> anyhow::Result<()> {
        // Ensure pf is enabled
        enable_pf()?;

        let output = Command::new("pfctl")
            .arg("-a")
            .arg(&self.anchor)
            .arg("-f")
            .arg(&self.rules_path)
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("pfctl load failed: {}", stderr.trim());
        }

        tracing::info!(anchor = %self.anchor, "pf anchor loaded");
        Ok(())
    }

    /// Flush all rules from the session anchor.
    pub fn flush(&self) -> anyhow::Result<()> {
        let output = Command::new("pfctl")
            .arg("-a")
            .arg(&self.anchor)
            .arg("-F")
            .arg("all")
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("pfctl flush failed: {}", stderr.trim());
        }

        tracing::info!(anchor = %self.anchor, "pf anchor flushed");
        Ok(())
    }

    /// The anchor name (e.g. "com.closedshell/a1b2c3d4").
    pub fn anchor(&self) -> &str {
        &self.anchor
    }
}

impl Drop for PfEnforcer {
    fn drop(&mut self) {
        if let Err(e) = self.flush() {
            tracing::warn!(anchor = %self.anchor, error = %e, "failed to flush pf anchor on drop");
        }
    }
}

/// Generate pf rules for a session anchor.
///
/// The rules allow the sandboxed user to reach the local proxy, but block
/// direct outbound HTTP/HTTPS to any other destination.
pub fn generate_rules(proxy_port: u16, sandbox_uid: u32, interface: &str) -> String {
    format!(
        "\
# closedshell pf rules — defense-in-depth for sandbox escape
# Allow sandboxed user to reach the MITM proxy on localhost
pass out quick on {iface} proto tcp from any to 127.0.0.1 port {port} user {uid}
pass out quick on lo0 proto tcp from any to 127.0.0.1 port {port} user {uid}
# Block sandboxed user's direct outbound HTTP/HTTPS
block return out quick on {iface} proto tcp from any to any port 80 user {uid}
block return out quick on {iface} proto tcp from any to any port 443 user {uid}
",
        iface = interface,
        port = proxy_port,
        uid = sandbox_uid,
    )
}

/// Detect the default network interface by parsing `route -n get default`.
pub fn detect_default_interface() -> anyhow::Result<String> {
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()?;

    if !output.status.success() {
        anyhow::bail!("route -n get default failed");
    }

    parse_interface_from_route(&String::from_utf8_lossy(&output.stdout))
}

/// Parse the interface name from `route -n get default` output.
fn parse_interface_from_route(output: &str) -> anyhow::Result<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(iface) = trimmed.strip_prefix("interface:") {
            return Ok(iface.trim().to_string());
        }
    }
    anyhow::bail!("could not find 'interface:' in route output")
}

/// Enable pf if not already enabled. Requires root.
fn enable_pf() -> anyhow::Result<()> {
    // pfctl -e returns exit code 0 if newly enabled, or 1 if already enabled
    // (with "pf already enabled" on stderr). Both are fine.
    let output = Command::new("pfctl").arg("-e").output()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() && !stderr.contains("already enabled") {
        anyhow::bail!("pfctl -e failed: {}", stderr.trim());
    }
    Ok(())
}

/// Check whether the root pf anchor is configured in the system pf.conf.
pub fn check_anchor_configured() -> anyhow::Result<bool> {
    let pf_conf = std::fs::read_to_string("/etc/pf.conf").unwrap_or_default();
    let anchor_line = format!("anchor \"{}/*\"", ANCHOR_ROOT);
    Ok(pf_conf.contains(&anchor_line))
}

/// Resolve a username to its UID.
pub fn resolve_uid(username: &str) -> anyhow::Result<u32> {
    let output = Command::new("id").arg("-u").arg(username).output()?;

    if !output.status.success() {
        anyhow::bail!(
            "user '{}' not found — run `sudo closedshell --pf-setup` first",
            username
        );
    }

    let uid_str = String::from_utf8_lossy(&output.stdout);
    uid_str
        .trim()
        .parse::<u32>()
        .map_err(|e| anyhow::anyhow!("failed to parse UID for '{}': {}", username, e))
}

/// One-time system setup: create the sandbox user and register the pf anchor.
/// Requires root.
pub fn setup_system(username: &str) -> anyhow::Result<()> {
    // 1. Create system user if it doesn't exist
    if resolve_uid(username).is_err() {
        create_system_user(username)?;
        eprintln!("[closedshell] created system user '{}'", username);
    } else {
        eprintln!("[closedshell] system user '{}' already exists", username);
    }

    // 2. Add pf anchor to /etc/pf.conf if not present
    if !check_anchor_configured()? {
        add_anchor_to_pf_conf()?;
        eprintln!("[closedshell] added pf anchor to /etc/pf.conf");
    } else {
        eprintln!("[closedshell] pf anchor already configured");
    }

    // 3. Reload pf with the updated config
    let output = Command::new("pfctl")
        .args(["-f", "/etc/pf.conf"])
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("pfctl reload failed: {}", stderr.trim());
    }
    eprintln!("[closedshell] pf configuration reloaded");

    // 4. Enable pf
    enable_pf()?;
    eprintln!("[closedshell] pf enabled");

    eprintln!("[closedshell] pf setup complete");
    Ok(())
}

/// Create a macOS system user via dscl.
fn create_system_user(username: &str) -> anyhow::Result<()> {
    let uid = find_available_system_uid()?;
    let uid_str = uid.to_string();
    let user_path = format!("/Users/{}", username);

    let steps: &[(&[&str], &str)] = &[
        (&[".", "-create", &user_path], "create user record"),
        (
            &[".", "-create", &user_path, "UserShell", "/usr/bin/false"],
            "set shell",
        ),
        (
            &[".", "-create", &user_path, "UniqueID", &uid_str],
            "set UID",
        ),
        (
            &[".", "-create", &user_path, "PrimaryGroupID", "20"],
            "set GID",
        ),
        (
            &[
                ".",
                "-create",
                &user_path,
                "RealName",
                "ClosedShell Sandbox",
            ],
            "set real name",
        ),
        (
            &[".", "-create", &user_path, "NFSHomeDirectory", "/var/empty"],
            "set home",
        ),
    ];

    for (args, desc) in steps {
        let output = Command::new("dscl").args(*args).output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("dscl {} failed: {}", desc, stderr.trim());
        }
    }

    Ok(())
}

/// Find an unused UID in the system range (300-399).
fn find_available_system_uid() -> anyhow::Result<u32> {
    let output = Command::new("dscl")
        .args([".", "-list", "/Users", "UniqueID"])
        .output()?;

    if !output.status.success() {
        anyhow::bail!("dscl list users failed");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let used_uids: Vec<u32> = stdout
        .lines()
        .filter_map(|line| line.split_whitespace().last()?.parse().ok())
        .collect();

    for uid in 300..400 {
        if !used_uids.contains(&uid) {
            return Ok(uid);
        }
    }

    anyhow::bail!("no available UID in system range 300-399")
}

/// Append the closedshell anchor line to /etc/pf.conf.
fn add_anchor_to_pf_conf() -> anyhow::Result<()> {
    let mut contents = std::fs::read_to_string("/etc/pf.conf")?;
    contents.push_str(&format!(
        "\n# ClosedShell sandbox enforcement\nanchor \"{}/*\"\n",
        ANCHOR_ROOT
    ));
    std::fs::write("/etc/pf.conf", contents)?;
    Ok(())
}

/// Flush any orphaned closedshell pf anchors (crash recovery).
pub fn flush_orphaned_anchors() -> anyhow::Result<()> {
    let output = Command::new("pfctl")
        .args(["-a", ANCHOR_ROOT, "-s", "Anchors"])
        .output()?;

    if !output.status.success() {
        // No anchors or pf not configured — nothing to clean up
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let anchor_name = line.trim();
        if !anchor_name.is_empty() {
            let full_anchor = format!("{}/{}", ANCHOR_ROOT, anchor_name);
            let _ = Command::new("pfctl")
                .args(["-a", &full_anchor, "-F", "all"])
                .output();
            tracing::info!(anchor = %full_anchor, "flushed orphaned pf anchor");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_rules_format() {
        let rules = generate_rules(8443, 350, "en0");
        assert!(
            rules.contains(
                "pass out quick on en0 proto tcp from any to 127.0.0.1 port 8443 user 350"
            )
        );
        assert!(
            rules.contains(
                "pass out quick on lo0 proto tcp from any to 127.0.0.1 port 8443 user 350"
            )
        );
        assert!(
            rules.contains(
                "block return out quick on en0 proto tcp from any to any port 80 user 350"
            )
        );
        assert!(
            rules.contains(
                "block return out quick on en0 proto tcp from any to any port 443 user 350"
            )
        );
    }

    #[test]
    fn test_generate_rules_custom_port() {
        let rules = generate_rules(9999, 301, "en1");
        assert!(rules.contains("port 9999"));
        assert!(rules.contains("user 301"));
        assert!(rules.contains("on en1"));
        assert!(!rules.contains("en0"));
    }

    #[test]
    fn test_parse_interface_from_route() {
        let output = "\
   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount
       0         0         0         0         0         0";

        let iface = parse_interface_from_route(output).unwrap();
        assert_eq!(iface, "en0");
    }

    #[test]
    fn test_parse_interface_en1() {
        let output = "  interface: en1\n";
        let iface = parse_interface_from_route(output).unwrap();
        assert_eq!(iface, "en1");
    }

    #[test]
    fn test_parse_interface_missing() {
        let output = "some output without interface line\n";
        assert!(parse_interface_from_route(output).is_err());
    }

    #[test]
    fn test_anchor_name_format() {
        let enforcer = PfEnforcer {
            anchor: format!("{}/{}", ANCHOR_ROOT, "a1b2c3d4"),
            rules_path: PathBuf::from("/tmp/test/pf.rules"),
        };
        assert_eq!(enforcer.anchor(), "com.closedshell/a1b2c3d4");
    }

    #[test]
    fn test_rules_block_both_http_and_https() {
        let rules = generate_rules(8443, 350, "en0");
        assert!(rules.contains("port 80"));
        assert!(rules.contains("port 443"));
    }
}
