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
            exec_allowlist: vec![
                "/bin/sh".into(),
                "/bin/bash".into(),
                "/usr/bin/env".into(),
            ],
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


/// Load config from disk. Checks ./closedshell.yaml first, then ~/.closedshell/config.yaml.
/// Returns default config if neither exists.
pub fn load_config() -> anyhow::Result<Config> {
    let candidates = [
        std::path::PathBuf::from("closedshell.yaml"),
        dirs_config_path(),
    ];

    for path in &candidates {
        if path.exists() {
            let contents = std::fs::read_to_string(path)?;
            let config: Config = serde_yaml::from_str(&contents)?;
            return Ok(config);
        }
    }

    Ok(Config::default())
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
