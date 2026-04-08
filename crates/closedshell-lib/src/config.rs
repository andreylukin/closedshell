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
    #[serde(default)]
    pub exec_allowlist: Vec<String>,
    #[serde(default)]
    pub credentials: Vec<CredentialMount>,
    #[serde(default = "default_templates_dir")]
    pub templates_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialMount {
    #[serde(rename = "type")]
    pub mount_type: CredentialType,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub mount: Option<String>,
    #[serde(default)]
    pub readonly: bool,
    #[serde(default)]
    pub vars: Vec<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub token_path: Option<String>,
    #[serde(default)]
    pub refresh_interval: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialType {
    File,
    Env,
    Socket,
    OAuth,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgeConfig {
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
            exec_allowlist: vec![],
            credentials: vec![],
            templates_dir: default_templates_dir(),
        }
    }
}

impl Default for JudgeConfig {
    fn default() -> Self {
        Self {
            api_base: default_api_base(),
            model: default_model(),
            api_key: String::new(),
            timeout_ms: default_timeout(),
            temperature: 0.0,
            system_prompt_path: None,
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
        for cred in &mut self.sandbox.credentials {
            if let Some(ref source) = cred.source {
                cred.source = Some(resolve_tilde(source));
            }
            if let Some(ref mount) = cred.mount {
                cred.mount = Some(resolve_tilde(mount));
            }
            if let Some(ref tp) = cred.token_path {
                cred.token_path = Some(resolve_tilde(tp));
            }
        }
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
    fn test_resolve_paths_credentials() {
        let yaml = r#"
sandbox:
  credentials:
    - type: file
      source: ~/.aws/credentials
      mount: ~/.aws/credentials
      readonly: true
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.resolve_paths();

        let home = std::env::var("HOME").unwrap();
        let cred = &config.sandbox.credentials[0];
        assert_eq!(cred.source.as_deref().unwrap(), format!("{}/.aws/credentials", home));
        assert_eq!(cred.mount.as_deref().unwrap(), format!("{}/.aws/credentials", home));
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
  exec_allowlist:
    - /bin/sh
    - /usr/local/bin/aws
  credentials:
    - type: file
      source: ~/.aws/credentials
      mount: ~/.aws/credentials
      readonly: true
    - type: env
      vars: [OPENAI_API_KEY, GITHUB_TOKEN]

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
        assert_eq!(config.sandbox.credentials.len(), 2);
        assert_eq!(config.judge.timeout_ms, 3000);
    }
}
