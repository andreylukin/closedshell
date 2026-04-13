//! Template management: init, list, generate, validate, and check operations.

use anyhow::{Context, Result, bail};
use include_dir::{Dir, include_dir};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::BufRead;
use std::path::{Path, PathBuf};

use crate::permission::action_glob_match;

/// Bundled templates embedded at compile time from the repo's templates/ directory.
static BUNDLED_TEMPLATES: Dir = include_dir!("$CARGO_MANIFEST_DIR/../../templates");

/// Where a template came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateSource {
    BuiltIn,
    User,
}

impl std::fmt::Display for TemplateSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TemplateSource::BuiltIn => write!(f, "built-in"),
            TemplateSource::User => write!(f, "user"),
        }
    }
}

/// Info about a discovered template (returned by `list`).
#[derive(Debug)]
pub struct TemplateInfo {
    pub name: String,
    pub description: String,
    pub path: PathBuf,
    pub rule_count: usize,
    pub source: TemplateSource,
}

/// Scaffold a new template for the given provider.
///
/// Creates `<templates_dir>/<provider>/full.yaml` with provider-specific
/// action patterns. Returns the path of the created file.
pub fn init(templates_dir: &Path, provider: &str) -> Result<PathBuf> {
    let dir = templates_dir.join(provider);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create directory {}", dir.display()))?;

    let path = dir.join("full.yaml");
    if path.exists() {
        bail!(
            "template already exists: {}\nEdit it directly or remove it first.",
            path.display()
        );
    }

    let yaml = scaffold_yaml(provider);
    std::fs::write(&path, &yaml).with_context(|| format!("failed to write {}", path.display()))?;

    Ok(path)
}

/// List all templates from both user directory and bundled sources.
///
/// User templates override bundled ones with the same name.
/// Returns results sorted by name.
pub fn list(templates_dir: &Path) -> Result<Vec<TemplateInfo>> {
    let mut by_name: BTreeMap<String, TemplateInfo> = BTreeMap::new();

    // 1. Load bundled templates first (will be overridden by user templates)
    collect_bundled_dir(&BUNDLED_TEMPLATES, &mut by_name);

    // 2. Load user templates (override bundled by name)
    if templates_dir.exists() {
        walk_yaml_files(templates_dir, &mut |path| {
            match parse_template_info(&path) {
                Ok(mut info) => {
                    info.source = if by_name.contains_key(&info.name) {
                        // User is overriding a built-in
                        TemplateSource::User
                    } else {
                        TemplateSource::User
                    };
                    by_name.insert(info.name.clone(), info);
                }
                Err(e) => {
                    eprintln!("[closedshell] warning: skipping {}: {}", path.display(), e);
                }
            }
        })?;
    }

    let mut results: Vec<TemplateInfo> = by_name.into_values().collect();
    results.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(results)
}

/// Resolve a template name to its YAML contents.
///
/// Resolution order:
/// 1. Absolute/relative path on disk
/// 2. User templates dir (`~/.closedshell/templates/<name>.yaml`)
/// 3. Bundled (compiled-in) templates
///
/// Returns the YAML string and the source description for logging.
pub fn resolve(name: &str, templates_dir: &Path) -> Result<(String, String)> {
    let raw = Path::new(name);

    // 1. Direct path
    if raw.exists() {
        let yaml = std::fs::read_to_string(raw)
            .with_context(|| format!("failed to read template {}", raw.display()))?;
        return Ok((yaml, raw.display().to_string()));
    }
    if raw.with_extension("yaml").exists() {
        let p = raw.with_extension("yaml");
        let yaml = std::fs::read_to_string(&p)
            .with_context(|| format!("failed to read template {}", p.display()))?;
        return Ok((yaml, p.display().to_string()));
    }

    // 2. User templates dir
    let user_path = templates_dir.join(format!("{}.yaml", name));
    if user_path.exists() {
        let yaml = std::fs::read_to_string(&user_path)
            .with_context(|| format!("failed to read template {}", user_path.display()))?;
        return Ok((yaml, user_path.display().to_string()));
    }

    // 3. Bundled templates
    let bundled_path = format!("{}.yaml", name);
    if let Some(file) = BUNDLED_TEMPLATES.get_file(&bundled_path) {
        if let Some(contents) = file.contents_utf8() {
            return Ok((contents.to_string(), format!("built-in:{}", name)));
        }
    }

    // Not found — build a helpful error
    bail!(
        "template '{}' not found\n\nsearched:\n  {}  (not found)\n  built-in templates  (not found)\n\navailable templates: cs template list\ncreate a new one:   cs template init <provider>",
        name,
        user_path.display()
    );
}

/// Result of validating a template.
#[derive(Debug)]
pub struct ValidateResult {
    pub name: String,
    pub description: String,
    pub permits: Vec<String>,
    pub forbids: Vec<String>,
    pub warnings: Vec<String>,
}

/// Validate a template's YAML and return a structured summary.
///
/// Checks: valid YAML, required fields, valid effect/type values, non-empty action patterns.
pub fn validate(yaml: &str) -> Result<ValidateResult> {
    let tpl: FullTemplate =
        serde_yaml::from_str(yaml).context("invalid YAML: failed to parse template")?;

    let mut permits = Vec::new();
    let mut forbids = Vec::new();
    let mut warnings = Vec::new();

    if tpl.name.is_empty() {
        warnings.push("template name is empty".to_string());
    }
    if tpl.rules.is_empty() {
        warnings.push("template has no rules".to_string());
    }

    for (i, rule) in tpl.rules.iter().enumerate() {
        let idx = i + 1;
        match rule.effect.as_str() {
            "permit" => {
                if let Some(ref rt) = rule.rule_type {
                    if rt != "idempotent" && rt != "one-shot" && rt != "oneshot" {
                        warnings.push(format!(
                            "rule {}: unknown type '{}' (expected 'idempotent' or 'one-shot')",
                            idx, rt
                        ));
                    }
                }
                permits.push(rule.action.clone());
            }
            "forbid" => {
                if rule.reason.is_none() {
                    warnings.push(format!("rule {}: forbid rule has no reason", idx));
                }
                forbids.push(rule.action.clone());
            }
            other => {
                warnings.push(format!(
                    "rule {}: unknown effect '{}' (expected 'permit' or 'forbid')",
                    idx, other
                ));
            }
        }
        if rule.action.is_empty() {
            warnings.push(format!("rule {}: action pattern is empty", idx));
        }
    }

    Ok(ValidateResult {
        name: tpl.name,
        description: tpl.description.unwrap_or_default(),
        permits,
        forbids,
        warnings,
    })
}

/// The verdict for a single action checked against a template.
#[derive(Debug, PartialEq, Eq)]
pub enum CheckVerdict {
    Permit(String), // the matching pattern
    Forbid(String), // the matching pattern
    NoMatch,
}

/// Check whether an action would be permitted, forbidden, or unmatched by a template.
///
/// Uses the same Cedar-inspired semantics as the runtime: forbid overrides permit.
pub fn check(yaml: &str, action: &str) -> Result<CheckVerdict> {
    let tpl: FullTemplate =
        serde_yaml::from_str(yaml).context("invalid YAML: failed to parse template")?;

    // Phase 1: any forbid match → deny
    for rule in &tpl.rules {
        if rule.effect == "forbid" && action_glob_match(&rule.action, action) {
            return Ok(CheckVerdict::Forbid(rule.action.clone()));
        }
    }

    // Phase 2: any permit match → allow
    for rule in &tpl.rules {
        if rule.effect == "permit" && action_glob_match(&rule.action, action) {
            return Ok(CheckVerdict::Permit(rule.action.clone()));
        }
    }

    // Phase 3: no match
    Ok(CheckVerdict::NoMatch)
}

/// Full template struct for validate/check (includes all fields).
#[derive(Deserialize)]
struct FullTemplate {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    rules: Vec<FullTemplateRule>,
}

#[derive(Deserialize)]
struct FullTemplateRule {
    effect: String,
    action: String,
    #[serde(rename = "type")]
    rule_type: Option<String>,
    reason: Option<String>,
}

/// Generate a template from a YOLO session's audit log.
///
/// Reads the NDJSON log, extracts allowed actions, deduplicates and groups
/// them, then emits a YAML template string.
pub fn generate(log_path: &Path, name: Option<&str>) -> Result<String> {
    let file = std::fs::File::open(log_path)
        .with_context(|| format!("failed to open log: {}", log_path.display()))?;
    let reader = std::io::BufReader::new(file);

    // Collect unique allowed actions
    let mut actions = BTreeSet::new();
    for line in reader.lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let event: LogEvent = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(_) => continue, // skip unparseable lines
        };
        if event.event == "decision"
            && event.result.as_deref().is_some_and(|r| r.contains("allow"))
            && let Some(action) = event.action
        {
            actions.insert(action);
        }
    }

    if actions.is_empty() {
        bail!("no allowed actions found in {}", log_path.display());
    }

    // Group and collapse actions into template rules
    let rules = collapse_actions(&actions);

    // Build YAML output
    let template_name = name.unwrap_or("generated");
    let mut yaml = String::new();
    yaml.push_str(&format!("name: {}\n", template_name));
    yaml.push_str(&format!(
        "description: \"Auto-generated from session log ({})\"\n",
        log_path.file_name().unwrap_or_default().to_string_lossy()
    ));
    yaml.push_str("rules:\n");
    for action in &rules {
        yaml.push_str("  - effect: permit\n");
        yaml.push_str(&format!("    action: \"{}\"\n", action));
        yaml.push_str("    type: idempotent\n");
        yaml.push_str('\n'.to_string().as_str());
    }

    Ok(yaml)
}

// ── Internal helpers ────────────────────────────────────────────────────────

/// Minimal audit log event for deserialization (only the fields we need).
#[derive(Deserialize)]
struct LogEvent {
    event: String,
    action: Option<String>,
    result: Option<String>,
}

/// Recursively collect bundled `.yaml` templates from an embedded directory.
fn collect_bundled_dir(dir: &Dir, out: &mut BTreeMap<String, TemplateInfo>) {
    for file in dir.files() {
        if file.path().extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        let Some(contents) = file.contents_utf8() else {
            continue;
        };
        let Ok(meta) = serde_yaml::from_str::<TemplateMeta>(contents) else {
            continue;
        };
        out.insert(
            meta.name.clone(),
            TemplateInfo {
                name: meta.name,
                description: meta.description.unwrap_or_default(),
                path: PathBuf::from("(built-in)"),
                rule_count: meta.rules.len(),
                source: TemplateSource::BuiltIn,
            },
        );
    }
    for subdir in dir.dirs() {
        collect_bundled_dir(subdir, out);
    }
}

/// Walk a directory recursively, calling `f` for each `.yaml` file.
fn walk_yaml_files(dir: &Path, f: &mut dyn FnMut(PathBuf)) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("failed to read directory {}", dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk_yaml_files(&path, f)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
            f(path);
        }
    }
    Ok(())
}

/// Parse a YAML template file to extract metadata.
#[derive(Deserialize)]
struct TemplateMeta {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    rules: Vec<serde_yaml::Value>,
}

fn parse_template_info(path: &Path) -> Result<TemplateInfo> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let meta: TemplateMeta = serde_yaml::from_str(&contents)
        .with_context(|| format!("invalid YAML in {}", path.display()))?;
    Ok(TemplateInfo {
        name: meta.name,
        description: meta.description.unwrap_or_default(),
        path: path.to_path_buf(),
        rule_count: meta.rules.len(),
        source: TemplateSource::User,
    })
}

/// Collapse a set of action strings into grouped glob patterns.
///
/// - `net:METHOD:host/path` actions are grouped by host. Multiple paths → `net:*:host/*`.
/// - Provider actions (`aws:service:op`, `gcp:service:op`) are grouped by
///   `provider:service` → `provider:service:*`.
/// - Other actions pass through as-is.
fn collapse_actions(actions: &BTreeSet<String>) -> Vec<String> {
    // net actions: group by host
    let mut net_hosts: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    // provider actions: group by provider:service
    let mut provider_services: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    // anything else
    let mut other: BTreeSet<String> = BTreeSet::new();

    for action in actions {
        if action.starts_with("net:") {
            // Format: net:METHOD:host/path
            if let Some((host, path)) = parse_net_action(action) {
                net_hosts.entry(host).or_default().insert(path);
            } else {
                other.insert(action.clone());
            }
        } else if let Some((prefix, _op)) = parse_provider_action(action) {
            provider_services
                .entry(prefix)
                .or_default()
                .insert(action.clone());
        } else {
            other.insert(action.clone());
        }
    }

    let mut rules = Vec::new();

    // Collapse net actions
    for (host, paths) in &net_hosts {
        if paths.len() > 1 {
            rules.push(format!("net:*:{}/*", host));
        } else {
            let path = paths.iter().next().unwrap();
            if path == "/" || path == "/*" {
                rules.push(format!("net:*:{}/*", host));
            } else {
                rules.push(format!("net:*:{}{}", host, path));
            }
        }
    }

    // Collapse provider actions
    for (prefix, ops) in &provider_services {
        if ops.len() > 1 {
            rules.push(format!("{}:*", prefix));
        } else {
            rules.push(ops.iter().next().unwrap().clone());
        }
    }

    // Pass through other actions
    for action in &other {
        rules.push(action.clone());
    }

    rules
}

/// Parse `net:METHOD:host/path` → `(host, /path)`.
fn parse_net_action(action: &str) -> Option<(String, String)> {
    // Strip "net:" prefix
    let rest = action.strip_prefix("net:")?;
    // Skip METHOD up to the next ":"
    let colon = rest.find(':')?;
    let host_path = &rest[colon + 1..];
    // Split host from path at first "/"
    if let Some(slash) = host_path.find('/') {
        let host = &host_path[..slash];
        let path = &host_path[slash..];
        Some((host.to_string(), path.to_string()))
    } else {
        Some((host_path.to_string(), "/".to_string()))
    }
}

/// Parse provider action into `(prefix, operation)`.
///
/// Handles both `provider:service:op` and `provider[qualifier]:service:op`.
/// Only matches known provider prefixes (aws, gcp, azure, k8s).
fn parse_provider_action(action: &str) -> Option<(String, String)> {
    let known_providers = ["aws", "gcp", "azure", "k8s"];
    for provider in &known_providers {
        if !action.starts_with(provider) {
            continue;
        }
        let after_provider = &action[provider.len()..];
        // Must be followed by ':' or '[' (qualifier)
        if !after_provider.starts_with(':') && !after_provider.starts_with('[') {
            continue;
        }
        // Find the last ":" to split prefix:operation
        if let Some(last_colon) = action.rfind(':') {
            if last_colon == 0 {
                continue;
            }
            let prefix = &action[..last_colon];
            let op = &action[last_colon + 1..];
            if !op.is_empty() {
                return Some((prefix.to_string(), op.to_string()));
            }
        }
    }
    None
}

/// Generate scaffold YAML for a provider.
fn scaffold_yaml(provider: &str) -> String {
    match provider {
        "aws" => r#"name: aws-full
description: "Allow common AWS service endpoints"
rules:
  - effect: permit
    action: "aws[profile=*]:s3:*"
    type: idempotent

  - effect: permit
    action: "aws[profile=*]:ec2:Describe*"
    type: idempotent

  - effect: permit
    action: "aws[profile=*]:sts:*"
    type: idempotent
"#
        .to_string(),
        "gcp" => r#"name: gcp-full
description: "Allow common GCP service endpoints"
rules:
  - effect: permit
    action: "gcp[project=*]:storage:*"
    type: idempotent

  - effect: permit
    action: "gcp[project=*]:compute:*"
    type: idempotent
"#
        .to_string(),
        "azure" => r#"name: azure-full
description: "Allow Azure management plane endpoints"
rules:
  - effect: permit
    action: "net:*:management.azure.com/*"
    type: idempotent

  - effect: permit
    action: "net:*:login.microsoftonline.com/*"
    type: idempotent
"#
        .to_string(),
        "github" => r#"name: github-full
description: "Allow GitHub API endpoints"
rules:
  - effect: permit
    action: "net:*:api.github.com/*"
    type: idempotent

  - effect: permit
    action: "net:*:github.com/*"
    type: idempotent
"#
        .to_string(),
        provider => format!(
            r#"name: {provider}-full
description: "Allow all {provider} endpoints"
rules:
  - effect: permit
    action: "net:*:{provider}.com/*"
    type: idempotent
"#
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_creates_template() {
        let dir = tempfile::tempdir().unwrap();
        let path = init(dir.path(), "myservice").unwrap();

        assert!(path.exists());
        assert!(path.ends_with("myservice/full.yaml"));

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("name: myservice-full"));
        assert!(contents.contains("net:*:myservice.com/*"));
    }

    #[test]
    fn test_init_known_provider() {
        let dir = tempfile::tempdir().unwrap();
        let path = init(dir.path(), "aws").unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("name: aws-full"));
        assert!(contents.contains("aws[profile=*]:s3:*"));
    }

    #[test]
    fn test_init_refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        init(dir.path(), "test").unwrap();

        let result = init(dir.path(), "test");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    #[test]
    fn test_list_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let results = list(dir.path()).unwrap();
        // Should still contain bundled templates
        assert!(!results.is_empty());
        assert!(results.iter().all(|t| t.source == TemplateSource::BuiltIn));
    }

    #[test]
    fn test_list_finds_user_templates() {
        let dir = tempfile::tempdir().unwrap();
        init(dir.path(), "svc1").unwrap();

        let results = list(dir.path()).unwrap();
        let user_templates: Vec<_> = results
            .iter()
            .filter(|t| t.source == TemplateSource::User)
            .collect();
        assert_eq!(user_templates.len(), 1);
        assert_eq!(user_templates[0].name, "svc1-full");
    }

    #[test]
    fn test_list_user_overrides_builtin() {
        let dir = tempfile::tempdir().unwrap();
        // Create a user template with same name as a bundled one
        let anthropic_dir = dir.path().join("anthropic");
        std::fs::create_dir_all(&anthropic_dir).unwrap();
        std::fs::write(
            anthropic_dir.join("full.yaml"),
            "name: anthropic-full\ndescription: \"Custom override\"\nrules: []\n",
        )
        .unwrap();

        let results = list(dir.path()).unwrap();
        let anthropic = results.iter().find(|t| t.name == "anthropic-full").unwrap();
        assert_eq!(anthropic.source, TemplateSource::User);
        assert_eq!(anthropic.description, "Custom override");
    }

    #[test]
    fn test_list_nonexistent_dir() {
        let results = list(Path::new("/nonexistent/path")).unwrap();
        // Should still return bundled templates
        assert!(!results.is_empty());
    }

    #[test]
    fn test_list_includes_bundled() {
        let dir = tempfile::tempdir().unwrap();
        let results = list(dir.path()).unwrap();
        let names: Vec<_> = results.iter().map(|t| t.name.as_str()).collect();
        assert!(
            names.contains(&"anthropic-full"),
            "should include anthropic-full"
        );
    }

    #[test]
    fn test_resolve_bundled() {
        let dir = tempfile::tempdir().unwrap();
        let (yaml, source) = resolve("anthropic/full", dir.path()).unwrap();
        assert!(yaml.contains("name: anthropic-full"));
        assert!(source.contains("built-in"));
    }

    #[test]
    fn test_resolve_user_overrides_bundled() {
        let dir = tempfile::tempdir().unwrap();
        let anthropic_dir = dir.path().join("anthropic");
        std::fs::create_dir_all(&anthropic_dir).unwrap();
        std::fs::write(
            anthropic_dir.join("full.yaml"),
            "name: anthropic-full\ndescription: \"User override\"\nrules: []\n",
        )
        .unwrap();

        let (yaml, source) = resolve("anthropic/full", dir.path()).unwrap();
        assert!(yaml.contains("User override"));
        assert!(!source.contains("built-in"));
    }

    #[test]
    fn test_resolve_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let result = resolve("nonexistent/template", dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not found"));
        assert!(err.contains("cs template list"));
    }

    #[test]
    fn test_generate_from_log() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test.log");

        // Write sample NDJSON audit log
        let log_content = r#"{"ts":"2025-01-01T00:00:00Z","session":"abc","event":"session_start","command":"curl","yolo":true}
{"ts":"2025-01-01T00:00:01Z","session":"abc","event":"decision","action":"net:GET:api.example.com/v1/users","result":"allow (yolo)","decided_by":"yolo","latency_ms":0,"request":{"method":"GET","host":"api.example.com","path":"/v1/users"}}
{"ts":"2025-01-01T00:00:02Z","session":"abc","event":"decision","action":"net:POST:api.example.com/v1/data","result":"allow (yolo)","decided_by":"yolo","latency_ms":0,"request":{"method":"POST","host":"api.example.com","path":"/v1/data"}}
{"ts":"2025-01-01T00:00:03Z","session":"abc","event":"decision","action":"net:GET:cdn.other.io/assets/logo.png","result":"allow (yolo)","decided_by":"yolo","latency_ms":0,"request":{"method":"GET","host":"cdn.other.io","path":"/assets/logo.png"}}
{"ts":"2025-01-01T00:00:04Z","session":"abc","event":"decision","action":"net:GET:api.blocked.com/secret","result":"deny","decided_by":"tree","latency_ms":0,"request":{"method":"GET","host":"api.blocked.com","path":"/secret"}}
"#;
        std::fs::write(&log_path, log_content).unwrap();

        let yaml = generate(&log_path, Some("test-template")).unwrap();

        // Should contain the template name
        assert!(yaml.contains("name: test-template"));

        // api.example.com had multiple paths → should be collapsed to wildcard
        assert!(yaml.contains("net:*:api.example.com/*"));

        // cdn.other.io had a single path → should keep the specific path
        assert!(yaml.contains("net:*:cdn.other.io/assets/logo.png"));

        // Denied action should NOT appear
        assert!(!yaml.contains("api.blocked.com"));
    }

    #[test]
    fn test_generate_empty_log() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("empty.log");
        std::fs::write(&log_path, "").unwrap();

        let result = generate(&log_path, None);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("no allowed actions")
        );
    }

    #[test]
    fn test_generate_provider_actions() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("provider.log");

        let log_content = r#"{"ts":"2025-01-01T00:00:01Z","session":"abc","event":"decision","action":"aws[profile=dev]:s3:ListBuckets","result":"allow (tree)","decided_by":"tree","latency_ms":0,"request":{"method":"GET","host":"s3.amazonaws.com","path":"/"}}
{"ts":"2025-01-01T00:00:02Z","session":"abc","event":"decision","action":"aws[profile=dev]:s3:GetObject","result":"allow (tree)","decided_by":"tree","latency_ms":0,"request":{"method":"GET","host":"s3.amazonaws.com","path":"/bucket/key"}}
"#;
        std::fs::write(&log_path, log_content).unwrap();

        let yaml = generate(&log_path, Some("aws-observed")).unwrap();

        // Two aws:s3 ops should collapse to aws[profile=dev]:s3:*
        assert!(yaml.contains("aws[profile=dev]:s3:*"));
    }

    #[test]
    fn test_collapse_single_net_action() {
        let mut actions = BTreeSet::new();
        actions.insert("net:GET:api.exa.ai/search".to_string());

        let rules = collapse_actions(&actions);
        assert_eq!(rules, vec!["net:*:api.exa.ai/search"]);
    }

    #[test]
    fn test_collapse_multiple_net_paths() {
        let mut actions = BTreeSet::new();
        actions.insert("net:GET:api.exa.ai/search".to_string());
        actions.insert("net:POST:api.exa.ai/contents".to_string());

        let rules = collapse_actions(&actions);
        assert_eq!(rules, vec!["net:*:api.exa.ai/*"]);
    }

    #[test]
    fn test_parse_net_action() {
        let (host, path) = parse_net_action("net:GET:api.example.com/v1/users").unwrap();
        assert_eq!(host, "api.example.com");
        assert_eq!(path, "/v1/users");
    }

    #[test]
    fn test_parse_net_action_no_path() {
        let (host, path) = parse_net_action("net:GET:example.com").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(path, "/");
    }

    #[test]
    fn test_parse_provider_action() {
        let (prefix, op) = parse_provider_action("aws[profile=dev]:s3:ListBuckets").unwrap();
        assert_eq!(prefix, "aws[profile=dev]:s3");
        assert_eq!(op, "ListBuckets");
    }

    #[test]
    fn test_parse_provider_action_not_known() {
        assert!(parse_provider_action("net:GET:example.com").is_none());
        assert!(parse_provider_action("unknown:service:op").is_none());
    }

    #[test]
    fn test_scaffold_yaml_valid() {
        // Verify all scaffolds produce valid YAML that matches the template schema
        for provider in &["aws", "gcp", "azure", "github", "myservice"] {
            let yaml = scaffold_yaml(provider);
            let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml)
                .unwrap_or_else(|e| panic!("invalid YAML for {}: {}", provider, e));
            assert!(parsed["name"].is_string(), "missing name for {}", provider);
            assert!(
                parsed["rules"].is_sequence(),
                "missing rules for {}",
                provider
            );
        }
    }

    #[test]
    fn test_validate_valid_template() {
        let yaml = r#"
name: test-full
description: "Test template"
rules:
  - effect: permit
    action: "net:*:api.example.com/*"
    type: idempotent
  - effect: forbid
    action: "net:*:api.example.com/admin/*"
    reason: "admin endpoints blocked"
"#;
        let result = validate(yaml).unwrap();
        assert_eq!(result.name, "test-full");
        assert_eq!(result.permits.len(), 1);
        assert_eq!(result.forbids.len(), 1);
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_validate_warnings() {
        let yaml = r#"
name: ""
description: "Bad template"
rules:
  - effect: permit
    action: ""
    type: badtype
  - effect: forbid
    action: "net:*:evil.com/*"
  - effect: nope
    action: "net:*:x.com/*"
"#;
        let result = validate(yaml).unwrap();
        assert!(result.warnings.len() >= 3); // empty name, empty action, bad type, no reason, bad effect
    }

    #[test]
    fn test_validate_invalid_yaml() {
        let result = validate("not: valid: yaml: [");
        assert!(result.is_err());
    }

    #[test]
    fn test_check_permit() {
        let yaml = r#"
name: test
rules:
  - effect: permit
    action: "net:*:api.example.com/*"
    type: idempotent
"#;
        let verdict = check(yaml, "net:GET:api.example.com/v1/users").unwrap();
        assert_eq!(
            verdict,
            CheckVerdict::Permit("net:*:api.example.com/*".to_string())
        );
    }

    #[test]
    fn test_check_forbid_overrides_permit() {
        let yaml = r#"
name: test
rules:
  - effect: permit
    action: "net:*:api.example.com/*"
    type: idempotent
  - effect: forbid
    action: "net:*:api.example.com/admin/*"
    reason: "no admin"
"#;
        let verdict = check(yaml, "net:POST:api.example.com/admin/delete").unwrap();
        assert_eq!(
            verdict,
            CheckVerdict::Forbid("net:*:api.example.com/admin/*".to_string())
        );
    }

    #[test]
    fn test_check_no_match() {
        let yaml = r#"
name: test
rules:
  - effect: permit
    action: "net:*:api.example.com/*"
    type: idempotent
"#;
        let verdict = check(yaml, "net:GET:api.other.com/foo").unwrap();
        assert_eq!(verdict, CheckVerdict::NoMatch);
    }

    #[test]
    fn test_validate_bundled_templates() {
        // All bundled templates should validate without warnings.
        // Walk the embedded dir directly to get the YAML contents.
        fn check_dir(dir: &Dir) {
            for file in dir.files() {
                if file.path().extension().and_then(|e| e.to_str()) != Some("yaml") {
                    continue;
                }
                let contents = file.contents_utf8().unwrap();
                let result = validate(contents)
                    .unwrap_or_else(|e| panic!("failed to validate {:?}: {}", file.path(), e));
                assert!(
                    result.warnings.is_empty(),
                    "bundled template {:?} has warnings: {:?}",
                    file.path(),
                    result.warnings
                );
            }
            for subdir in dir.dirs() {
                check_dir(subdir);
            }
        }
        check_dir(&BUNDLED_TEMPLATES);
    }
}
