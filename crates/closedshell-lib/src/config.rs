//! Configuration loading and parsing.
//!
//! Lookup order: ./closedshell.yaml → ~/.closedshell/config.yaml
//! CLI flags override both.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub sandbox: SandboxConfig,
    #[serde(default)]
    pub judge: JudgeConfig,
    #[serde(default)]
    pub approval: ApprovalConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    #[serde(default = "default_true")]
    pub motd: bool,
    #[serde(default = "default_true")]
    pub implicit_ask: bool,
    #[serde(default)]
    pub yolo: bool,
    /// Environment variables to pass through to the sandboxed process.
    #[serde(default)]
    pub passthrough_env: Vec<String>,
    #[serde(default = "default_templates_dir")]
    pub templates_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgeConfig {
    /// API provider: "openai" (default) or "anthropic"
    #[serde(default = "default_provider")]
    pub provider: String,
    #[serde(default = "default_api_base")]
    pub api_base: String,
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub temperature: f32,
    #[serde(default)]
    pub system_prompt_path: Option<String>,
    /// Require TLS for the judge API endpoint.
    /// Default: true for non-localhost endpoints, false for localhost.
    /// When true, the judge client will refuse to connect over plain HTTP to
    /// remote endpoints, preventing MITM of judge responses.
    #[serde(default)]
    pub require_tls: Option<bool>,
    /// Optional path to a CA certificate (PEM) used to verify the judge API.
    /// Enables certificate pinning for the judge connection.
    #[serde(default)]
    pub tls_ca_cert: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApprovalConfig {
    #[serde(default)]
    pub auto_approve_timeout: AutoApproveTimeout,
    #[serde(default)]
    pub webhook_url: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AutoApproveTimeout {
    #[serde(default = "default_moderate_timeout")]
    pub moderate: Option<String>,
    #[serde(default)]
    pub dangerous: Option<String>,
}

fn default_true() -> bool {
    true
}
fn default_templates_dir() -> String {
    "~/.closedshell/templates".to_string()
}
fn default_provider() -> String {
    "openai".to_string()
}
fn default_api_base() -> String {
    "http://localhost:11434/v1".to_string()
}
fn default_model() -> String {
    "qwen3:8b".to_string()
}
fn default_timeout() -> u64 {
    5000
}
fn default_moderate_timeout() -> Option<String> {
    Some("30s".into())
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            motd: true,
            implicit_ask: true,
            yolo: false,
            passthrough_env: vec![],
            templates_dir: default_templates_dir(),
        }
    }
}

impl Default for JudgeConfig {
    fn default() -> Self {
        Self {
            provider: default_provider(),
            api_base: default_api_base(),
            model: default_model(),
            api_key: String::new(),
            timeout_ms: default_timeout(),
            temperature: 0.0,
            system_prompt_path: None,
            require_tls: None,
            tls_ca_cert: None,
        }
    }
}

impl JudgeConfig {
    /// Whether TLS is required for the judge endpoint.
    /// Explicit config takes precedence; otherwise require TLS for non-localhost endpoints.
    pub fn tls_required(&self) -> bool {
        if let Some(explicit) = self.require_tls {
            return explicit;
        }
        // Auto-detect: localhost endpoints don't need TLS
        let url = self.api_base.to_lowercase();
        let is_localhost = url.contains("://localhost")
            || url.contains("://127.0.0.1")
            || url.contains("://[::1]");
        !is_localhost
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
    pub no_motd: bool,
    pub task: Option<String>,
    pub templates: Vec<String>,
}

impl Config {
    /// Merge CLI flags onto this config. CLI flags override file config.
    pub fn merge_cli_flags(&mut self, flags: &CliFlags) {
        if flags.yolo {
            self.sandbox.yolo = true;
        }
        if flags.no_motd {
            self.sandbox.motd = false;
        }
        if !flags.templates.is_empty() {
            self.sandbox.templates_dir = resolve_tilde(&self.sandbox.templates_dir);
        }
    }

    /// Resolve all `~` paths in the config.
    pub fn resolve_paths(&mut self) {
        self.sandbox.templates_dir = resolve_tilde(&self.sandbox.templates_dir);
        if let Some(ref path) = self.judge.system_prompt_path {
            self.judge.system_prompt_path = Some(resolve_tilde(path));
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.sandbox.motd);
        assert!(config.sandbox.implicit_ask);
        assert!(!config.sandbox.yolo);
        assert_eq!(config.judge.timeout_ms, 5000);
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
        assert!(config.sandbox.motd);

        let flags = CliFlags {
            yolo: true,
            no_motd: true,
            task: None,
            templates: vec![],
        };
        config.merge_cli_flags(&flags);

        assert!(config.sandbox.yolo);
        assert!(!config.sandbox.motd);
    }

    #[test]
    fn test_merge_cli_flags_no_override_when_false() {
        let mut config = Config::default();
        config.sandbox.yolo = true;
        config.sandbox.motd = false;

        let flags = CliFlags {
            yolo: false,
            no_motd: false,
            task: None,
            templates: vec![],
        };
        config.merge_cli_flags(&flags);

        // Flags are false, so config values should remain unchanged
        assert!(config.sandbox.yolo);
        assert!(!config.sandbox.motd);
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
  implicit_ask: true
  yolo: true
  passthrough_env:
    - OPENAI_API_KEY
    - GITHUB_TOKEN
    - AWS_ACCESS_KEY_ID
    - AWS_SECRET_ACCESS_KEY

judge:
  api_base: "http://localhost:11434/v1"
  model: "qwen3:8b"
  timeout_ms: 3000

approval:
  webhook_url: "https://hooks.slack.com/xxx"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(!config.sandbox.motd);
        assert!(config.sandbox.yolo);
        assert_eq!(config.sandbox.passthrough_env.len(), 4);
        assert_eq!(config.judge.timeout_ms, 3000);
    }

    #[test]
    fn test_tls_required_auto_detect() {
        // Localhost: TLS not required
        let config = JudgeConfig {
            api_base: "http://localhost:11434/v1".into(),
            ..Default::default()
        };
        assert!(!config.tls_required());

        // 127.0.0.1: TLS not required
        let config = JudgeConfig {
            api_base: "http://127.0.0.1:11434/v1".into(),
            ..Default::default()
        };
        assert!(!config.tls_required());

        // Remote: TLS required
        let config = JudgeConfig {
            api_base: "http://judge.example.com/v1".into(),
            ..Default::default()
        };
        assert!(config.tls_required());
    }

    #[test]
    fn test_tls_required_explicit_override() {
        let config = JudgeConfig {
            api_base: "http://localhost:11434/v1".into(),
            require_tls: Some(true),
            ..Default::default()
        };
        assert!(config.tls_required());

        let config = JudgeConfig {
            api_base: "http://judge.example.com/v1".into(),
            require_tls: Some(false),
            ..Default::default()
        };
        assert!(!config.tls_required());
    }

    #[test]
    fn test_parse_judge_tls_config_yaml() {
        let yaml = r#"
judge:
  api_base: "https://judge.example.com/v1"
  require_tls: true
  tls_ca_cert: "/etc/ssl/judge-ca.pem"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.judge.require_tls, Some(true));
        assert_eq!(
            config.judge.tls_ca_cert.as_deref(),
            Some("/etc/ssl/judge-ca.pem")
        );
    }
}
