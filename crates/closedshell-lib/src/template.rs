//! Template management: init, list, generate, validate, and check operations.
//!
//! Templates use a Cedar-inspired `.csp` (ClosedShell Policy) format:
//!
//! ```text
//! @name("anthropic-full")
//! @description("Allow all Anthropic API endpoints")
//!
//! // Core API
//! permit (action == "net:*:api.anthropic.com/*");
//!
//! // Block admin
//! forbid (action == "net:*:api.anthropic.com/admin/*")
//!   reason("admin access blocked");
//! ```

use anyhow::{Context, Result, bail};
use include_dir::{Dir, include_dir};
use std::collections::{BTreeMap, BTreeSet};
use std::io::BufRead;
use std::path::{Path, PathBuf};

use crate::permission::action_glob_match;

/// Bundled templates embedded at compile time from the repo's templates/ directory.
static BUNDLED_TEMPLATES: Dir = include_dir!("$CARGO_MANIFEST_DIR/../../templates");

// ── CSP format: parser ─────────────────────────────────────────────────────

/// A parsed `.csp` policy file.
#[derive(Debug, Clone)]
pub struct Policy {
    pub name: String,
    pub description: String,
    pub statements: Vec<Statement>,
}

/// A single permit or forbid statement.
#[derive(Debug, Clone)]
pub struct Statement {
    pub effect: Effect,
    pub action: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Permit,
    Forbid,
}

impl std::fmt::Display for Effect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Effect::Permit => write!(f, "permit"),
            Effect::Forbid => write!(f, "forbid"),
        }
    }
}

/// Parse a `.csp` policy string into a `Policy`.
///
/// Grammar:
/// ```text
/// file       = { annotation | statement | comment | blank }
/// annotation = "@" IDENT "(" STRING ")"
/// statement  = effect "(" "action" [ "==" STRING ] ")" { clause } ";"
/// effect     = "permit" | "forbid"
/// clause     = "reason" "(" STRING ")"
/// comment    = "//" ...
/// ```
pub fn parse(input: &str) -> Result<Policy> {
    let mut parser = Parser::new(input);
    parser.parse_file()
}

/// Emit a `Policy` as a `.csp` string.
pub fn emit(policy: &Policy) -> String {
    let mut out = String::new();
    if !policy.name.is_empty() {
        out.push_str(&format!("@name(\"{}\")\n", escape_string(&policy.name)));
    }
    if !policy.description.is_empty() {
        out.push_str(&format!(
            "@description(\"{}\")\n",
            escape_string(&policy.description)
        ));
    }
    if !policy.name.is_empty() || !policy.description.is_empty() {
        out.push('\n');
    }
    for stmt in &policy.statements {
        out.push_str(&format!(
            "{} (action == \"{}\"){};\n",
            stmt.effect,
            escape_string(&stmt.action),
            match &stmt.reason {
                Some(r) => format!("\n  reason(\"{}\")", escape_string(r)),
                None => String::new(),
            }
        ));
    }
    out
}

fn escape_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

struct Parser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn parse_file(&mut self) -> Result<Policy> {
        let mut name = String::new();
        let mut description = String::new();
        let mut statements = Vec::new();

        loop {
            self.skip_whitespace_and_comments();
            if self.pos >= self.input.len() {
                break;
            }

            if self.peek_char() == Some('@') {
                let (key, value) = self.parse_annotation()?;
                match key.as_str() {
                    "name" => name = value,
                    "description" => description = value,
                    other => bail!("unknown annotation @{} at position {}", other, self.pos),
                }
            } else if self.starts_with("permit") || self.starts_with("forbid") {
                statements.push(self.parse_statement()?);
            } else {
                let snippet = &self.input[self.pos..self.input.len().min(self.pos + 30)];
                bail!("unexpected input at position {}: {:?}", self.pos, snippet);
            }
        }

        Ok(Policy {
            name,
            description,
            statements,
        })
    }

    fn parse_annotation(&mut self) -> Result<(String, String)> {
        self.expect_char('@')?;
        let key = self.parse_ident()?;
        self.skip_whitespace();
        self.expect_char('(')?;
        let value = self.parse_string()?;
        self.skip_whitespace();
        self.expect_char(')')?;
        Ok((key, value))
    }

    fn parse_statement(&mut self) -> Result<Statement> {
        let effect = if self.consume_keyword("permit") {
            Effect::Permit
        } else if self.consume_keyword("forbid") {
            Effect::Forbid
        } else {
            bail!("expected 'permit' or 'forbid' at position {}", self.pos);
        };

        self.skip_whitespace();
        self.expect_char('(')?;
        self.skip_whitespace();

        // Parse scope: "action" or "action == <string>"
        if !self.consume_keyword("action") {
            bail!("expected 'action' at position {}", self.pos);
        }
        self.skip_whitespace();

        let action = if self.starts_with("==") {
            self.pos += 2;
            self.skip_whitespace();
            self.parse_string()?
        } else {
            // bare "action" means match everything
            "*".to_string()
        };

        self.skip_whitespace();
        self.expect_char(')')?;

        // Parse optional clauses before semicolon
        let mut reason = None;
        loop {
            self.skip_whitespace_and_comments();
            if self.peek_char() == Some(';') {
                self.pos += 1;
                break;
            }
            if self.starts_with("reason") {
                self.pos += 6; // "reason"
                self.skip_whitespace();
                self.expect_char('(')?;
                reason = Some(self.parse_string()?);
                self.skip_whitespace();
                self.expect_char(')')?;
            } else if self.pos >= self.input.len() {
                bail!("unexpected end of input: expected ';'");
            } else {
                let snippet = &self.input[self.pos..self.input.len().min(self.pos + 20)];
                bail!(
                    "unexpected token before ';' at position {}: {:?}",
                    self.pos,
                    snippet
                );
            }
        }

        Ok(Statement {
            effect,
            action,
            reason,
        })
    }

    fn parse_string(&mut self) -> Result<String> {
        self.skip_whitespace();
        self.expect_char('"')?;
        let mut s = String::new();
        loop {
            match self.next_char() {
                Some('"') => return Ok(s),
                Some('\\') => match self.next_char() {
                    Some('"') => s.push('"'),
                    Some('\\') => s.push('\\'),
                    Some('n') => s.push('\n'),
                    Some(c) => {
                        s.push('\\');
                        s.push(c);
                    }
                    None => bail!("unexpected end of input in escape sequence"),
                },
                Some(c) => s.push(c),
                None => bail!("unterminated string starting at position {}", self.pos),
            }
        }
    }

    fn parse_ident(&mut self) -> Result<String> {
        let start = self.pos;
        while self.pos < self.input.len() {
            let c = self.input.as_bytes()[self.pos] as char;
            if c.is_ascii_alphanumeric() || c == '_' {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == start {
            bail!("expected identifier at position {}", self.pos);
        }
        Ok(self.input[start..self.pos].to_string())
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.input.len() {
            let c = self.input.as_bytes()[self.pos] as char;
            if c.is_ascii_whitespace() {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn skip_whitespace_and_comments(&mut self) {
        loop {
            self.skip_whitespace();
            if self.starts_with("//") {
                // Skip to end of line
                while self.pos < self.input.len() && self.input.as_bytes()[self.pos] != b'\n' {
                    self.pos += 1;
                }
            } else {
                break;
            }
        }
    }

    fn peek_char(&self) -> Option<char> {
        self.input.as_bytes().get(self.pos).map(|&b| b as char)
    }

    fn next_char(&mut self) -> Option<char> {
        let c = self.peek_char()?;
        self.pos += 1;
        Some(c)
    }

    fn expect_char(&mut self, expected: char) -> Result<()> {
        match self.next_char() {
            Some(c) if c == expected => Ok(()),
            Some(c) => bail!(
                "expected '{}' but got '{}' at position {}",
                expected,
                c,
                self.pos - 1
            ),
            None => bail!("expected '{}' but reached end of input", expected),
        }
    }

    fn starts_with(&self, s: &str) -> bool {
        self.input[self.pos..].starts_with(s)
    }

    fn consume_keyword(&mut self, keyword: &str) -> bool {
        if self.starts_with(keyword) {
            let after = self.pos + keyword.len();
            // Must be followed by non-alphanumeric (word boundary)
            if after >= self.input.len() || !self.input.as_bytes()[after].is_ascii_alphanumeric() {
                self.pos = after;
                return true;
            }
        }
        false
    }
}

// ── Template source ────────────────────────────────────────────────────────

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

// ── Public API ─────────────────────────────────────────────────────────────

/// Scaffold a new template for the given provider.
///
/// Creates `<templates_dir>/<provider>/full.csp` with provider-specific
/// action patterns. Returns the path of the created file.
pub fn init(templates_dir: &Path, provider: &str) -> Result<PathBuf> {
    let dir = templates_dir.join(provider);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create directory {}", dir.display()))?;

    let path = dir.join("full.csp");
    if path.exists() {
        bail!(
            "template already exists: {}\nEdit it directly or remove it first.",
            path.display()
        );
    }

    let csp = scaffold_csp(provider);
    std::fs::write(&path, &csp).with_context(|| format!("failed to write {}", path.display()))?;

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
        walk_csp_files(
            templates_dir,
            &mut |path| match parse_template_info(&path) {
                Ok(mut info) => {
                    info.source = TemplateSource::User;
                    by_name.insert(info.name.clone(), info);
                }
                Err(e) => {
                    eprintln!("[closedshell] warning: skipping {}: {}", path.display(), e);
                }
            },
        )?;
    }

    let mut results: Vec<TemplateInfo> = by_name.into_values().collect();
    results.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(results)
}

/// Resolve a template name to its CSP contents.
///
/// Resolution order:
/// 1. Absolute/relative path on disk
/// 2. User templates dir (`~/.closedshell/templates/<name>.csp`)
/// 3. Bundled (compiled-in) templates
///
/// Returns the CSP string and the source description for logging.
pub fn resolve(name: &str, templates_dir: &Path) -> Result<(String, String)> {
    let raw = Path::new(name);

    // 1. Direct path
    if raw.exists() {
        let csp = std::fs::read_to_string(raw)
            .with_context(|| format!("failed to read template {}", raw.display()))?;
        return Ok((csp, raw.display().to_string()));
    }
    if raw.with_extension("csp").exists() {
        let p = raw.with_extension("csp");
        let csp = std::fs::read_to_string(&p)
            .with_context(|| format!("failed to read template {}", p.display()))?;
        return Ok((csp, p.display().to_string()));
    }

    // 2. User templates dir
    let user_path = templates_dir.join(format!("{}.csp", name));
    if user_path.exists() {
        let csp = std::fs::read_to_string(&user_path)
            .with_context(|| format!("failed to read template {}", user_path.display()))?;
        return Ok((csp, user_path.display().to_string()));
    }

    // 3. Bundled templates
    let bundled_path = format!("{}.csp", name);
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

/// Validate a template's CSP source and return a structured summary.
pub fn validate(csp: &str) -> Result<ValidateResult> {
    let policy = parse(csp).context("failed to parse template")?;

    let mut permits = Vec::new();
    let mut forbids = Vec::new();
    let mut warnings = Vec::new();

    if policy.name.is_empty() {
        warnings.push("template has no @name annotation".to_string());
    }
    if policy.statements.is_empty() {
        warnings.push("template has no rules".to_string());
    }

    for (i, stmt) in policy.statements.iter().enumerate() {
        let idx = i + 1;
        match stmt.effect {
            Effect::Permit => permits.push(stmt.action.clone()),
            Effect::Forbid => {
                if stmt.reason.is_none() {
                    warnings.push(format!("rule {}: forbid rule has no reason", idx));
                }
                forbids.push(stmt.action.clone());
            }
        }
        if stmt.action.is_empty() {
            warnings.push(format!("rule {}: action pattern is empty", idx));
        }
    }

    Ok(ValidateResult {
        name: policy.name,
        description: policy.description,
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
pub fn check(csp: &str, action: &str) -> Result<CheckVerdict> {
    let policy = parse(csp).context("failed to parse template")?;

    // Phase 1: any forbid match → deny
    for stmt in &policy.statements {
        if stmt.effect == Effect::Forbid && action_glob_match(&stmt.action, action) {
            return Ok(CheckVerdict::Forbid(stmt.action.clone()));
        }
    }

    // Phase 2: any permit match → allow
    for stmt in &policy.statements {
        if stmt.effect == Effect::Permit && action_glob_match(&stmt.action, action) {
            return Ok(CheckVerdict::Permit(stmt.action.clone()));
        }
    }

    // Phase 3: no match
    Ok(CheckVerdict::NoMatch)
}

/// Generate a template from a YOLO session's audit log.
///
/// Reads the NDJSON log, extracts allowed actions, deduplicates and groups
/// them, then emits a `.csp` template string.
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
            Err(_) => continue,
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

    let template_name = name.unwrap_or("generated");
    let policy = Policy {
        name: template_name.to_string(),
        description: format!(
            "Auto-generated from session log ({})",
            log_path.file_name().unwrap_or_default().to_string_lossy()
        ),
        statements: rules
            .into_iter()
            .map(|action| Statement {
                effect: Effect::Permit,
                action,
                reason: None,
            })
            .collect(),
    };

    Ok(emit(&policy))
}

// ── Internal helpers ────────────────────────────────────────────────────────

/// Minimal audit log event for deserialization (only the fields we need).
#[derive(serde::Deserialize)]
struct LogEvent {
    event: String,
    action: Option<String>,
    result: Option<String>,
}

/// Recursively collect bundled `.csp` templates from an embedded directory.
fn collect_bundled_dir(dir: &Dir, out: &mut BTreeMap<String, TemplateInfo>) {
    for file in dir.files() {
        if file.path().extension().and_then(|e| e.to_str()) != Some("csp") {
            continue;
        }
        let Some(contents) = file.contents_utf8() else {
            continue;
        };
        let Ok(policy) = parse(contents) else {
            continue;
        };
        out.insert(
            policy.name.clone(),
            TemplateInfo {
                name: policy.name,
                description: policy.description,
                path: PathBuf::from("(built-in)"),
                rule_count: policy.statements.len(),
                source: TemplateSource::BuiltIn,
            },
        );
    }
    for subdir in dir.dirs() {
        collect_bundled_dir(subdir, out);
    }
}

/// Walk a directory recursively, calling `f` for each `.csp` file.
fn walk_csp_files(dir: &Path, f: &mut dyn FnMut(PathBuf)) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("failed to read directory {}", dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk_csp_files(&path, f)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("csp") {
            f(path);
        }
    }
    Ok(())
}

fn parse_template_info(path: &Path) -> Result<TemplateInfo> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let policy = parse(&contents).with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(TemplateInfo {
        name: policy.name,
        description: policy.description,
        path: path.to_path_buf(),
        rule_count: policy.statements.len(),
        source: TemplateSource::User,
    })
}

/// Collapse a set of action strings into grouped glob patterns.
///
/// - `net:METHOD:host/path` actions are grouped by host → `net:*:host/*`.
/// - Provider actions (`aws:service:op`, `gcp:service:op`) are grouped by
///   `provider:service` → `provider:service:*`.
/// - Other actions pass through as-is.
fn collapse_actions(actions: &BTreeSet<String>) -> Vec<String> {
    let mut net_hosts: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut provider_services: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut other: BTreeSet<String> = BTreeSet::new();

    for action in actions {
        if action.starts_with("net:") {
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

    // Collapse net actions — always wildcard to host/*
    for host in net_hosts.keys() {
        rules.push(format!("net:*:{}/*", host));
    }

    // Collapse provider actions
    for (prefix, ops) in &provider_services {
        if ops.len() > 1 {
            rules.push(format!("{}:*", prefix));
        } else {
            rules.push(ops.iter().next().unwrap().clone());
        }
    }

    for action in &other {
        rules.push(action.clone());
    }

    rules
}

/// Parse `net:METHOD:host/path` → `(host, /path)`.
fn parse_net_action(action: &str) -> Option<(String, String)> {
    let rest = action.strip_prefix("net:")?;
    let colon = rest.find(':')?;
    let host_path = &rest[colon + 1..];
    if let Some(slash) = host_path.find('/') {
        let host = &host_path[..slash];
        let path = &host_path[slash..];
        Some((host.to_string(), path.to_string()))
    } else {
        Some((host_path.to_string(), "/".to_string()))
    }
}

/// Parse provider action into `(prefix, operation)`.
fn parse_provider_action(action: &str) -> Option<(String, String)> {
    let known_providers = ["aws", "gcp", "azure", "k8s"];
    for provider in &known_providers {
        if !action.starts_with(provider) {
            continue;
        }
        let after_provider = &action[provider.len()..];
        if !after_provider.starts_with(':') && !after_provider.starts_with('[') {
            continue;
        }
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

/// Generate scaffold CSP for a provider.
fn scaffold_csp(provider: &str) -> String {
    match provider {
        "aws" => "\
@name(\"aws-full\")\n\
@description(\"Allow common AWS service endpoints\")\n\
\n\
permit (action == \"aws[profile=*]:s3:*\");\n\
permit (action == \"aws[profile=*]:ec2:Describe*\");\n\
permit (action == \"aws[profile=*]:sts:*\");\n"
            .to_string(),
        "gcp" => "\
@name(\"gcp-full\")\n\
@description(\"Allow common GCP service endpoints\")\n\
\n\
permit (action == \"gcp[project=*]:storage:*\");\n\
permit (action == \"gcp[project=*]:compute:*\");\n"
            .to_string(),
        "azure" => "\
@name(\"azure-full\")\n\
@description(\"Allow Azure management plane endpoints\")\n\
\n\
permit (action == \"net:*:management.azure.com/*\");\n\
permit (action == \"net:*:login.microsoftonline.com/*\");\n"
            .to_string(),
        "github" => "\
@name(\"github-full\")\n\
@description(\"Allow GitHub API endpoints\")\n\
\n\
permit (action == \"net:*:api.github.com/*\");\n\
permit (action == \"net:*:github.com/*\");\n"
            .to_string(),
        provider => format!(
            "@name(\"{provider}-full\")\n\
             @description(\"Allow all {provider} endpoints\")\n\
             \n\
             permit (action == \"net:*:{provider}.com/*\");\n"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Parser tests ───────────────────────────────────────────────────────

    #[test]
    fn test_parse_minimal() {
        let csp = r#"permit (action == "net:*:api.example.com/*");"#;
        let policy = parse(csp).unwrap();
        assert_eq!(policy.statements.len(), 1);
        assert_eq!(policy.statements[0].effect, Effect::Permit);
        assert_eq!(policy.statements[0].action, "net:*:api.example.com/*");
    }

    #[test]
    fn test_parse_full() {
        let csp = r#"
@name("test-full")
@description("A test template")

// Core API
permit (action == "net:*:api.example.com/*");

// Block admin
forbid (action == "net:*:api.example.com/admin/*")
  reason("admin access blocked");
"#;
        let policy = parse(csp).unwrap();
        assert_eq!(policy.name, "test-full");
        assert_eq!(policy.description, "A test template");
        assert_eq!(policy.statements.len(), 2);
        assert_eq!(policy.statements[0].effect, Effect::Permit);
        assert_eq!(policy.statements[1].effect, Effect::Forbid);
        assert_eq!(
            policy.statements[1].reason.as_deref(),
            Some("admin access blocked")
        );
    }

    #[test]
    fn test_parse_bare_action() {
        let csp = r#"permit (action);"#;
        let policy = parse(csp).unwrap();
        assert_eq!(policy.statements[0].action, "*");
    }

    #[test]
    fn test_parse_escaped_string() {
        let csp = r#"permit (action == "net:*:api.example.com/\"path\"");"#;
        let policy = parse(csp).unwrap();
        assert_eq!(
            policy.statements[0].action,
            "net:*:api.example.com/\"path\""
        );
    }

    #[test]
    fn test_parse_error_unterminated_string() {
        let result = parse(r#"permit (action == "unterminated);"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_error_missing_semicolon() {
        let result = parse(r#"permit (action == "foo")"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_error_unknown_annotation() {
        let result = parse(r#"@unknown("foo") permit (action);"#);
        assert!(result.is_err());
    }

    // ── Emit tests ─────────────────────────────────────────────────────────

    #[test]
    fn test_emit_roundtrip() {
        let policy = Policy {
            name: "test".to_string(),
            description: "A test".to_string(),
            statements: vec![
                Statement {
                    effect: Effect::Permit,
                    action: "net:*:api.example.com/*".to_string(),
                    reason: None,
                },
                Statement {
                    effect: Effect::Forbid,
                    action: "net:*:api.example.com/admin/*".to_string(),
                    reason: Some("blocked".to_string()),
                },
            ],
        };
        let csp = emit(&policy);
        let parsed = parse(&csp).unwrap();
        assert_eq!(parsed.name, "test");
        assert_eq!(parsed.statements.len(), 2);
        assert_eq!(parsed.statements[1].reason.as_deref(), Some("blocked"));
    }

    // ── Init tests ─────────────────────────────────────────────────────────

    #[test]
    fn test_init_creates_template() {
        let dir = tempfile::tempdir().unwrap();
        let path = init(dir.path(), "myservice").unwrap();

        assert!(path.exists());
        assert!(path.ends_with("myservice/full.csp"));

        let contents = std::fs::read_to_string(&path).unwrap();
        let policy = parse(&contents).unwrap();
        assert_eq!(policy.name, "myservice-full");
    }

    #[test]
    fn test_init_known_provider() {
        let dir = tempfile::tempdir().unwrap();
        let path = init(dir.path(), "aws").unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let policy = parse(&contents).unwrap();
        assert_eq!(policy.name, "aws-full");
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

    // ── List tests ─────────────────────────────────────────────────────────

    #[test]
    fn test_list_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let results = list(dir.path()).unwrap();
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
        let anthropic_dir = dir.path().join("anthropic");
        std::fs::create_dir_all(&anthropic_dir).unwrap();
        std::fs::write(
            anthropic_dir.join("full.csp"),
            "@name(\"anthropic-full\")\n@description(\"Custom override\")\n\npermit (action == \"net:*:api.anthropic.com/*\");\n",
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
        assert!(!results.is_empty());
    }

    #[test]
    fn test_list_includes_bundled() {
        let dir = tempfile::tempdir().unwrap();
        let results = list(dir.path()).unwrap();
        let names: Vec<_> = results.iter().map(|t| t.name.as_str()).collect();
        assert!(
            names.contains(&"anthropic-full"),
            "should include anthropic-full, got: {:?}",
            names
        );
    }

    // ── Resolve tests ──────────────────────────────────────────────────────

    #[test]
    fn test_resolve_bundled() {
        let dir = tempfile::tempdir().unwrap();
        let (csp, source) = resolve("anthropic/full", dir.path()).unwrap();
        let policy = parse(&csp).unwrap();
        assert_eq!(policy.name, "anthropic-full");
        assert!(source.contains("built-in"));
    }

    #[test]
    fn test_resolve_user_overrides_bundled() {
        let dir = tempfile::tempdir().unwrap();
        let anthropic_dir = dir.path().join("anthropic");
        std::fs::create_dir_all(&anthropic_dir).unwrap();
        std::fs::write(
            anthropic_dir.join("full.csp"),
            "@name(\"anthropic-full\")\n@description(\"User override\")\npermit (action);\n",
        )
        .unwrap();

        let (csp, source) = resolve("anthropic/full", dir.path()).unwrap();
        assert!(csp.contains("User override"));
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

    // ── Validate tests ─────────────────────────────────────────────────────

    #[test]
    fn test_validate_valid_template() {
        let csp = r#"
@name("test-full")
@description("Test template")

permit (action == "net:*:api.example.com/*");
forbid (action == "net:*:api.example.com/admin/*")
  reason("admin endpoints blocked");
"#;
        let result = validate(csp).unwrap();
        assert_eq!(result.name, "test-full");
        assert_eq!(result.permits.len(), 1);
        assert_eq!(result.forbids.len(), 1);
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_validate_warnings_no_name() {
        let csp = r#"
forbid (action == "net:*:evil.com/*");
"#;
        let result = validate(csp).unwrap();
        assert!(result.warnings.iter().any(|w| w.contains("@name")));
        assert!(result.warnings.iter().any(|w| w.contains("no reason")));
    }

    #[test]
    fn test_validate_invalid_syntax() {
        let result = validate("not valid csp at all {{{");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_bundled_templates() {
        fn check_dir(dir: &Dir) {
            for file in dir.files() {
                if file.path().extension().and_then(|e| e.to_str()) != Some("csp") {
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

    // ── Check tests ────────────────────────────────────────────────────────

    #[test]
    fn test_check_permit() {
        let csp = r#"
@name("test")
permit (action == "net:*:api.example.com/*");
"#;
        let verdict = check(csp, "net:GET:api.example.com/v1/users").unwrap();
        assert_eq!(
            verdict,
            CheckVerdict::Permit("net:*:api.example.com/*".to_string())
        );
    }

    #[test]
    fn test_check_forbid_overrides_permit() {
        let csp = r#"
@name("test")
permit (action == "net:*:api.example.com/*");
forbid (action == "net:*:api.example.com/admin/*")
  reason("no admin");
"#;
        let verdict = check(csp, "net:POST:api.example.com/admin/delete").unwrap();
        assert_eq!(
            verdict,
            CheckVerdict::Forbid("net:*:api.example.com/admin/*".to_string())
        );
    }

    #[test]
    fn test_check_no_match() {
        let csp = r#"
@name("test")
permit (action == "net:*:api.example.com/*");
"#;
        let verdict = check(csp, "net:GET:api.other.com/foo").unwrap();
        assert_eq!(verdict, CheckVerdict::NoMatch);
    }

    // ── Generate tests ─────────────────────────────────────────────────────

    #[test]
    fn test_generate_from_log() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test.log");

        let log_content = r#"{"ts":"2025-01-01T00:00:00Z","session":"abc","event":"session_start","command":"curl","yolo":true}
{"ts":"2025-01-01T00:00:01Z","session":"abc","event":"decision","action":"net:GET:api.example.com/v1/users","result":"allow (yolo)","decided_by":"yolo","latency_ms":0,"request":{"method":"GET","host":"api.example.com","path":"/v1/users"}}
{"ts":"2025-01-01T00:00:02Z","session":"abc","event":"decision","action":"net:POST:api.example.com/v1/data","result":"allow (yolo)","decided_by":"yolo","latency_ms":0,"request":{"method":"POST","host":"api.example.com","path":"/v1/data"}}
{"ts":"2025-01-01T00:00:03Z","session":"abc","event":"decision","action":"net:GET:cdn.other.io/assets/logo.png","result":"allow (yolo)","decided_by":"yolo","latency_ms":0,"request":{"method":"GET","host":"cdn.other.io","path":"/assets/logo.png"}}
{"ts":"2025-01-01T00:00:04Z","session":"abc","event":"decision","action":"net:GET:api.blocked.com/secret","result":"deny","decided_by":"tree","latency_ms":0,"request":{"method":"GET","host":"api.blocked.com","path":"/secret"}}
"#;
        std::fs::write(&log_path, log_content).unwrap();

        let csp = generate(&log_path, Some("test-template")).unwrap();

        // Should be valid CSP
        let policy = parse(&csp).unwrap();
        assert_eq!(policy.name, "test-template");

        // api.example.com had multiple paths → collapsed to wildcard
        assert!(csp.contains("net:*:api.example.com/*"));

        // cdn.other.io had a single path → still wildcards to host/*
        assert!(csp.contains("net:*:cdn.other.io/*"));

        // Denied action should NOT appear
        assert!(!csp.contains("api.blocked.com"));
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

        let csp = generate(&log_path, Some("aws-observed")).unwrap();
        assert!(csp.contains("aws[profile=dev]:s3:*"));
    }

    // ── Collapse tests ─────────────────────────────────────────────────────

    #[test]
    fn test_collapse_single_net_action() {
        let mut actions = BTreeSet::new();
        actions.insert("net:GET:api.exa.ai/search".to_string());

        let rules = collapse_actions(&actions);
        assert_eq!(rules, vec!["net:*:api.exa.ai/*"]);
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
    fn test_scaffold_csp_valid() {
        for provider in &["aws", "gcp", "azure", "github", "myservice"] {
            let csp = scaffold_csp(provider);
            let policy =
                parse(&csp).unwrap_or_else(|e| panic!("invalid CSP for {}: {}", provider, e));
            assert!(!policy.name.is_empty(), "missing name for {}", provider);
            assert!(
                !policy.statements.is_empty(),
                "no statements for {}",
                provider
            );
        }
    }
}
