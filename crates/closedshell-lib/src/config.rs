//! Configuration loading and parsing.
//!
//! Lookup order: ./closedshell.yaml → ~/.closedshell/config.yaml
//! CLI flags override both.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub sandbox: SandboxConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    #[serde(default = "default_true")]
    pub motd: bool,
    #[serde(default)]
    pub yolo: bool,
    /// Environment variables to pass through to the sandboxed process.
    #[serde(default)]
    pub passthrough_env: Vec<String>,
    #[serde(default = "default_templates_dir")]
    pub templates_dir: String,
    /// Enable pf (packet filter) as secondary network enforcement layer.
    /// Requires one-time `--pf-setup` (root). Scopes rules by sandbox user UID.
    #[serde(default)]
    pub pf: bool,
    /// System user for pf-scoped sandboxing. Default: "_closedshell".
    #[serde(default = "default_pf_user")]
    pub pf_user: String,
}

fn default_true() -> bool {
    true
}
fn default_templates_dir() -> String {
    "~/.closedshell/templates".to_string()
}
fn default_pf_user() -> String {
    "_closedshell".to_string()
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            motd: true,
            yolo: false,
            passthrough_env: vec![],
            templates_dir: default_templates_dir(),
            pf: false,
            pf_user: default_pf_user(),
        }
    }
}

/// Resolve `~` prefix in a path to the user's home directory.
pub fn resolve_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        format!("{}/{}", home, rest)
    } else if path == "~" {
        std::env::var("HOME").unwrap_or_else(|_| "/tmp".into())
    } else {
        path.to_string()
    }
}

/// CLI flags that can override config values.
pub struct CliFlags {
    pub yolo: bool,
    pub templates: Vec<String>,
}

impl Config {
    /// Merge CLI flags onto this config. CLI flags override file config.
    pub fn merge_cli_flags(&mut self, flags: &CliFlags) {
        if flags.yolo {
            self.sandbox.yolo = true;
        }
        if !flags.templates.is_empty() {
            self.sandbox.templates_dir = resolve_tilde(&self.sandbox.templates_dir);
        }
    }

    /// Resolve all `~` paths in the config.
    pub fn resolve_paths(&mut self) {
        self.sandbox.templates_dir = resolve_tilde(&self.sandbox.templates_dir);
    }
}

/// Load config from disk. Checks ./closedshell.yaml first, then ~/.closedshell/config.yaml.
/// Returns default config if neither exists. Paths with `~` are resolved.
pub fn load_config() -> anyhow::Result<Config> {
    let candidates = [
        std::path::PathBuf::from("closedshell.yaml"),
        dirs_config_path(),
    ];

    for path in &candidates {
        if path.exists() {
            let contents = std::fs::read_to_string(path)?;
            let mut config: Config = serde_yaml::from_str(&contents)?;
            config.resolve_paths();
            return Ok(config);
        }
    }

    let mut config = Config::default();
    config.resolve_paths();
    Ok(config)
}

fn dirs_config_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    std::path::PathBuf::from(home)
        .join(".closedshell")
        .join("config.yaml")
}

/// Compute the log directory for a given working directory.
///
/// If `CLOSEDSHELL_LOG_DIR` is set, returns that path directly (for testing).
/// Otherwise returns `~/.closedshell/logs/<encoded-cwd>/` where the cwd is
/// encoded by replacing `/` with `_` and stripping the leading `_`.
/// Example: `/Users/alice/repos/myproject` → `Users_alice_repos_myproject`
///
/// The path is canonicalized to resolve symlinks (e.g., `/var` → `/private/var`
/// on macOS) so the same physical directory always maps to the same log dir.
pub fn log_dir_for_cwd(cwd: &std::path::Path) -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("CLOSEDSHELL_LOG_DIR") {
        return std::path::PathBuf::from(dir);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let canonical = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());
    let encoded = canonical
        .to_string_lossy()
        .replace('/', "_")
        .trim_start_matches('_')
        .to_string();
    std::path::PathBuf::from(home)
        .join(".closedshell")
        .join("logs")
        .join(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.sandbox.motd);
        assert!(!config.sandbox.yolo);
    }

    #[test]
    fn test_parse_minimal_yaml() {
        let yaml = "sandbox:\n  yolo: true\n";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.sandbox.yolo);
        assert!(config.sandbox.motd); // default
    }

    #[test]
    fn test_resolve_tilde() {
        let home = std::env::var("HOME").unwrap();
        assert_eq!(resolve_tilde("~/foo/bar"), format!("{}/foo/bar", home));
        assert_eq!(resolve_tilde("~"), home);
        assert_eq!(resolve_tilde("/absolute/path"), "/absolute/path");
        assert_eq!(resolve_tilde("relative/path"), "relative/path");
    }

    #[test]
    fn test_merge_cli_flags_yolo() {
        let mut config = Config::default();
        assert!(!config.sandbox.yolo);

        let flags = CliFlags {
            yolo: true,
            templates: vec![],
        };
        config.merge_cli_flags(&flags);

        assert!(config.sandbox.yolo);
    }

    #[test]
    fn test_merge_cli_flags_no_override_when_false() {
        let mut config = Config::default();
        config.sandbox.yolo = true;

        let flags = CliFlags {
            yolo: false,
            templates: vec![],
        };
        config.merge_cli_flags(&flags);

        // Flags are false, so config values should remain unchanged
        assert!(config.sandbox.yolo);
    }

    #[test]
    fn test_resolve_paths_templates_dir() {
        let mut config = Config::default();
        assert!(config.sandbox.templates_dir.starts_with("~"));
        config.resolve_paths();
        let home = std::env::var("HOME").unwrap();
        assert!(config.sandbox.templates_dir.starts_with(&home));
    }

    #[test]
    fn test_log_dir_for_cwd() {
        let home = std::env::var("HOME").unwrap();
        let dir = log_dir_for_cwd(std::path::Path::new("/Users/alice/repos/myproject"));
        assert_eq!(
            dir,
            std::path::PathBuf::from(&home).join(".closedshell/logs/Users_alice_repos_myproject")
        );
    }

    #[test]
    fn test_log_dir_for_root() {
        let home = std::env::var("HOME").unwrap();
        let dir = log_dir_for_cwd(std::path::Path::new("/"));
        assert_eq!(
            dir,
            std::path::PathBuf::from(&home).join(".closedshell/logs/")
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_log_dir_resolves_symlinks() {
        // /var → /private/var on macOS; both should produce the same log dir
        let via_var = log_dir_for_cwd(std::path::Path::new("/var"));
        let via_private = log_dir_for_cwd(std::path::Path::new("/private/var"));
        assert_eq!(via_var, via_private);
    }

    #[test]
    fn test_load_config_cwd_precedence() {
        // When no config file exists, should return default
        let config = load_config().unwrap();
        assert!(!config.sandbox.yolo);
        assert!(config.sandbox.motd);
    }

    #[test]
    fn test_parse_full_yaml() {
        let yaml = r#"
sandbox:
  motd: false
  yolo: true
  passthrough_env:
    - OPENAI_API_KEY
    - GITHUB_TOKEN
    - AWS_ACCESS_KEY_ID
    - AWS_SECRET_ACCESS_KEY
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(!config.sandbox.motd);
        assert!(config.sandbox.yolo);
        assert_eq!(config.sandbox.passthrough_env.len(), 4);
    }
}
