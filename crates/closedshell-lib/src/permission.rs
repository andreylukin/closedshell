use std::sync::RwLock;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::parser::Action;
use crate::proxy::{DecisionMaker, Verdict};

/// Cedar-inspired permission effect.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Effect {
    Permit,
    Forbid,
}

/// Rule type for permits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RuleType {
    Idempotent,
    OneShot { consumed: bool },
}

/// A single permission rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub effect: Effect,
    pub action: String,
    pub rule_type: Option<RuleType>,
    pub approved_by: Option<String>,
    pub source: Option<String>,
    pub plan_id: Option<String>,
    pub reason: Option<String>,
    pub expires: Option<DateTime<Utc>>,
}

/// Result of evaluating an action against the permission tree.
#[derive(Debug, Clone, PartialEq)]
pub enum TreeVerdict {
    Allow,
    Deny { reason: String },
}

/// Cedar-inspired permission tree: forbid-overrides-permit, default deny.
pub struct PermissionTree {
    rules: RwLock<Vec<Rule>>,
}

impl PermissionTree {
    pub fn new() -> Self {
        Self {
            rules: RwLock::new(Vec::new()),
        }
    }

    /// Evaluate an action canonical string against the tree.
    pub fn evaluate(&self, action_canonical: &str) -> TreeVerdict {
        let mut rules = self.rules.write().unwrap();
        let now = Utc::now();

        // Phase 1: FORBID CHECK — any matching forbid -> DENY
        for rule in rules.iter() {
            if rule.effect != Effect::Forbid {
                continue;
            }
            if is_expired(rule, now) {
                continue;
            }
            if action_glob_match(&rule.action, action_canonical) {
                let reason = rule
                    .reason
                    .clone()
                    .unwrap_or_else(|| format!("forbidden by rule {}", rule.id));
                return TreeVerdict::Deny { reason };
            }
        }

        // Phase 2: PERMIT CHECK — first matching permit wins
        for rule in rules.iter_mut() {
            if rule.effect != Effect::Permit {
                continue;
            }
            if is_expired(rule, now) {
                continue;
            }
            if !action_glob_match(&rule.action, action_canonical) {
                continue;
            }
            match &mut rule.rule_type {
                Some(RuleType::Idempotent) => return TreeVerdict::Allow,
                Some(RuleType::OneShot { consumed }) => {
                    if !*consumed {
                        *consumed = true;
                        return TreeVerdict::Allow;
                    }
                    // consumed one-shot: skip, keep looking
                }
                None => return TreeVerdict::Allow,
            }
        }

        // Phase 3: NO MATCH -> DENY
        TreeVerdict::Deny {
            reason: "no matching permission".to_string(),
        }
    }

    pub fn add_rule(&self, rule: Rule) {
        self.rules.write().unwrap().push(rule);
    }

    pub fn remove_rule(&self, rule_id: &str) -> bool {
        let mut rules = self.rules.write().unwrap();
        let len_before = rules.len();
        rules.retain(|r| r.id != rule_id);
        rules.len() < len_before
    }

    /// Remove all rules with a given plan_id, return count removed.
    pub fn revoke_plan(&self, plan_id: &str) -> usize {
        let mut rules = self.rules.write().unwrap();
        let len_before = rules.len();
        rules.retain(|r| r.plan_id.as_deref() != Some(plan_id));
        len_before - rules.len()
    }

    /// Load rules from a YAML template string.
    pub fn load_template(&self, yaml_str: &str) -> Result<()> {
        let tpl: Template =
            serde_yaml::from_str(yaml_str).context("failed to parse permission template")?;
        let source = format!("template:{}", tpl.name);
        let mut rules = self.rules.write().unwrap();
        for (i, tr) in tpl.rules.into_iter().enumerate() {
            let effect = match tr.effect.as_str() {
                "permit" => Effect::Permit,
                "forbid" => Effect::Forbid,
                other => anyhow::bail!("unknown effect: {}", other),
            };
            let rule_type = if effect == Effect::Forbid {
                None
            } else {
                match tr.rule_type.as_deref() {
                    Some("idempotent") | None => Some(RuleType::Idempotent),
                    Some("one-shot") | Some("oneshot") => {
                        Some(RuleType::OneShot { consumed: false })
                    }
                    Some(other) => anyhow::bail!("unknown rule type: {}", other),
                }
            };
            rules.push(Rule {
                id: format!("{}:{}", source, i),
                effect,
                action: tr.action,
                rule_type,
                approved_by: None,
                source: Some(source.clone()),
                plan_id: None,
                reason: tr.reason,
                expires: None,
            });
        }
        Ok(())
    }

    /// Returns true if any non-expired forbid rule matches the action.
    /// Used by JudgeDecider to distinguish "forbidden" (hard deny) from "no permit" (consult judge).
    pub fn has_forbid(&self, action_canonical: &str) -> bool {
        let rules = self.rules.read().unwrap();
        let now = Utc::now();
        rules.iter().any(|r| {
            r.effect == Effect::Forbid
                && !is_expired(r, now)
                && action_glob_match(&r.action, action_canonical)
        })
    }

    /// Replace all rules atomically (used for DB restore and hot-reload).
    pub fn replace_rules(&self, rules: Vec<Rule>) {
        *self.rules.write().unwrap() = rules;
    }

    pub fn rules(&self) -> Vec<Rule> {
        self.rules.read().unwrap().clone()
    }

    /// Return all rules whose action pattern matches the given pattern (for what-can-i queries).
    pub fn matching_rules(&self, action: &str) -> Vec<Rule> {
        self.rules
            .read()
            .unwrap()
            .iter()
            .filter(|r| action_glob_match(&r.action, action))
            .cloned()
            .collect()
    }
}

impl Default for PermissionTree {
    fn default() -> Self {
        Self::new()
    }
}

impl DecisionMaker for PermissionTree {
    fn evaluate(&self, action: &Action) -> Verdict {
        match self.evaluate(&action.canonical()) {
            TreeVerdict::Allow => Verdict::Allow,
            TreeVerdict::Deny { reason } => Verdict::Deny { reason },
        }
    }
}

fn is_expired(rule: &Rule, now: DateTime<Utc>) -> bool {
    rule.expires.is_some_and(|exp| exp <= now)
}

/// Escape square brackets so `glob_match` treats them as literal characters
/// rather than character-class delimiters. Replaces `[` and `]` with
/// placeholder bytes that are not special to the glob engine.
fn escape_brackets(s: &str) -> String {
    s.replace('[', "\x01").replace(']', "\x02")
}

fn action_glob_match(pattern: &str, input: &str) -> bool {
    // In action strings (not filesystem paths), a single `*` should match across
    // `/` separators. The `glob_match` crate treats `*` as non-`/`-crossing, so
    // we promote every lone `*` to `**` which matches everything including `/`.
    let promoted = promote_stars(&escape_brackets(pattern));
    glob_match::glob_match(&promoted, &escape_brackets(input))
}

/// Replace every `*` that isn't already part of `**` with `**`.
fn promote_stars(pattern: &str) -> String {
    let bytes = pattern.as_bytes();
    let mut result = String::with_capacity(pattern.len() + 8);
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'*' {
            // Count consecutive stars
            let start = i;
            while i < bytes.len() && bytes[i] == b'*' {
                i += 1;
            }
            let count = i - start;
            if count >= 2 {
                // Already ** or more — keep as-is
                for _ in 0..count {
                    result.push('*');
                }
            } else {
                // Single * → **
                result.push_str("**");
            }
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }
    result
}

// --- YAML template deserialization ---

#[derive(Deserialize)]
struct Template {
    name: String,
    #[allow(dead_code)] // present in YAML schema, consumed by serde
    description: Option<String>,
    rules: Vec<TemplateRule>,
}

#[derive(Deserialize)]
struct TemplateRule {
    effect: String,
    action: String,
    #[serde(rename = "type")]
    rule_type: Option<String>,
    reason: Option<String>,
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    fn permit(id: &str, action: &str, rt: RuleType) -> Rule {
        Rule {
            id: id.to_string(),
            effect: Effect::Permit,
            action: action.to_string(),
            rule_type: Some(rt),
            approved_by: None,
            source: None,
            plan_id: None,
            reason: None,
            expires: None,
        }
    }

    fn forbid(id: &str, action: &str, reason: &str) -> Rule {
        Rule {
            id: id.to_string(),
            effect: Effect::Forbid,
            action: action.to_string(),
            rule_type: None,
            approved_by: None,
            source: None,
            plan_id: None,
            reason: Some(reason.to_string()),
            expires: None,
        }
    }

    // T1: Forbid overrides permit
    #[test]
    fn forbid_overrides_permit() {
        let tree = PermissionTree::new();
        tree.add_rule(forbid(
            "f1",
            "aws[profile=prod]:*:Delete*",
            "no prod deletes",
        ));
        tree.add_rule(permit(
            "p1",
            "aws[profile=prod]:s3:Delete*",
            RuleType::Idempotent,
        ));

        let v = tree.evaluate("aws[profile=prod]:s3:DeleteBucket");
        assert_eq!(
            v,
            TreeVerdict::Deny {
                reason: "no prod deletes".to_string()
            }
        );
    }

    // T2: Empty tree -> DENY
    #[test]
    fn empty_tree_denies() {
        let tree = PermissionTree::new();
        let v = tree.evaluate("aws[profile=dev]:s3:ListBuckets");
        assert_eq!(
            v,
            TreeVerdict::Deny {
                reason: "no matching permission".to_string()
            }
        );
    }

    // T3: Idempotent permit -> evaluate twice -> ALLOW both
    #[test]
    fn idempotent_allows_repeatedly() {
        let tree = PermissionTree::new();
        tree.add_rule(permit(
            "p1",
            "aws[profile=dev]:s3:List*",
            RuleType::Idempotent,
        ));

        assert_eq!(
            tree.evaluate("aws[profile=dev]:s3:ListBuckets"),
            TreeVerdict::Allow
        );
        assert_eq!(
            tree.evaluate("aws[profile=dev]:s3:ListBuckets"),
            TreeVerdict::Allow
        );
    }

    // T4: OneShot -> first ALLOW, second DENY
    #[test]
    fn oneshot_consumed_after_use() {
        let tree = PermissionTree::new();
        tree.add_rule(permit(
            "p1",
            "aws[profile=dev]:s3:PutObject",
            RuleType::OneShot { consumed: false },
        ));

        assert_eq!(
            tree.evaluate("aws[profile=dev]:s3:PutObject"),
            TreeVerdict::Allow
        );
        assert_eq!(
            tree.evaluate("aws[profile=dev]:s3:PutObject"),
            TreeVerdict::Deny {
                reason: "no matching permission".to_string()
            }
        );
    }

    // T5: Consumed one-shot -> re-evaluate -> DENY
    #[test]
    fn consumed_oneshot_denies() {
        let tree = PermissionTree::new();
        tree.add_rule(permit(
            "p1",
            "aws:s3:PutObject",
            RuleType::OneShot { consumed: true },
        ));

        assert_eq!(
            tree.evaluate("aws:s3:PutObject"),
            TreeVerdict::Deny {
                reason: "no matching permission".to_string()
            }
        );
    }

    // T8: Glob with wildcard qualifier matches
    #[test]
    fn glob_wildcard_qualifier_matches() {
        let tree = PermissionTree::new();
        tree.add_rule(permit(
            "p1",
            "aws[profile=*]:s3:List*",
            RuleType::Idempotent,
        ));

        assert_eq!(
            tree.evaluate("aws[profile=dev]:s3:ListBuckets"),
            TreeVerdict::Allow
        );
    }

    // T9: Glob with specific qualifier does NOT match different value
    #[test]
    fn glob_specific_qualifier_no_cross_match() {
        let tree = PermissionTree::new();
        tree.add_rule(permit(
            "p1",
            "aws[profile=dev]:s3:List*",
            RuleType::Idempotent,
        ));

        assert_eq!(
            tree.evaluate("aws[profile=prod]:s3:ListBuckets"),
            TreeVerdict::Deny {
                reason: "no matching permission".to_string()
            }
        );
    }

    // T10: Two templates loaded, forbid from first survives
    #[test]
    fn two_templates_forbid_survives() {
        let tree = PermissionTree::new();
        let tpl1 = r#"
name: restrict-prod
description: "Block prod deletes"
rules:
  - effect: forbid
    action: "aws[profile=prod]:*:Delete*"
    reason: "no production deletes"
"#;
        let tpl2 = r#"
name: allow-s3
description: "Allow S3 access"
rules:
  - effect: permit
    action: "aws[profile=prod]:s3:*"
    type: idempotent
"#;
        tree.load_template(tpl1).unwrap();
        tree.load_template(tpl2).unwrap();

        // Forbid from tpl1 overrides permit from tpl2
        assert_eq!(
            tree.evaluate("aws[profile=prod]:s3:DeleteBucket"),
            TreeVerdict::Deny {
                reason: "no production deletes".to_string()
            }
        );
        // Non-delete operation allowed by tpl2
        assert_eq!(
            tree.evaluate("aws[profile=prod]:s3:ListBuckets"),
            TreeVerdict::Allow
        );
    }

    #[test]
    fn glob_matches_multi_segment_paths() {
        // Verify * matches across / in action strings
        assert!(action_glob_match(
            "net:*:api.anthropic.com/*",
            "net:POST:api.anthropic.com/v1/messages"
        ));
        assert!(action_glob_match(
            "net:*:api.anthropic.com/*",
            "net:GET:api.anthropic.com/api/oauth/account/settings"
        ));
        assert!(!action_glob_match(
            "net:*:api.exa.ai/search",
            "net:POST:api.exa.ai/contents"
        ));
    }

    // T11: revoke_plan removes all rules with that plan_id
    #[test]
    fn revoke_plan_removes_matching() {
        let tree = PermissionTree::new();
        let mut r1 = permit("p1", "aws:s3:*", RuleType::Idempotent);
        r1.plan_id = Some("plan-42".to_string());
        let mut r2 = permit("p2", "aws:ec2:*", RuleType::Idempotent);
        r2.plan_id = Some("plan-42".to_string());
        let r3 = permit("p3", "aws:iam:*", RuleType::Idempotent);

        tree.add_rule(r1);
        tree.add_rule(r2);
        tree.add_rule(r3);

        let removed = tree.revoke_plan("plan-42");
        assert_eq!(removed, 2);
        assert_eq!(tree.rules().len(), 1);
        assert_eq!(tree.rules()[0].id, "p3");
    }

    // T12: Forbid file path pattern
    #[test]
    fn forbid_ssh_key_access() {
        let tree = PermissionTree::new();
        tree.add_rule(forbid(
            "f1",
            "file:read:/Users/*/.ssh/*",
            "ssh key access denied",
        ));

        assert_eq!(
            tree.evaluate("file:read:/Users/alice/.ssh/id_rsa"),
            TreeVerdict::Deny {
                reason: "ssh key access denied".to_string()
            }
        );
    }

    // T13: Permit file write under repos
    #[test]
    fn permit_file_write_repos() {
        let tree = PermissionTree::new();
        tree.add_rule(permit(
            "p1",
            "file:write:/Users/alice/repos/*",
            RuleType::Idempotent,
        ));

        assert_eq!(
            tree.evaluate("file:write:/Users/alice/repos/foo.txt"),
            TreeVerdict::Allow
        );
    }

    // T14: No permit for /etc/passwd -> DENY
    #[test]
    fn no_permit_etc_passwd() {
        let tree = PermissionTree::new();
        tree.add_rule(permit(
            "p1",
            "file:write:/Users/alice/repos/*",
            RuleType::Idempotent,
        ));

        assert_eq!(
            tree.evaluate("file:write:/etc/passwd"),
            TreeVerdict::Deny {
                reason: "no matching permission".to_string()
            }
        );
    }

    // Expired permit is skipped
    #[test]
    fn expired_permit_skipped() {
        let tree = PermissionTree::new();
        let mut rule = permit("p1", "aws:s3:ListBuckets", RuleType::Idempotent);
        rule.expires = Some(Utc::now() - chrono::Duration::hours(1));
        tree.add_rule(rule);

        assert_eq!(
            tree.evaluate("aws:s3:ListBuckets"),
            TreeVerdict::Deny {
                reason: "no matching permission".to_string()
            }
        );
    }

    // add_rule and remove_rule
    #[test]
    fn add_and_remove_rule() {
        let tree = PermissionTree::new();
        tree.add_rule(permit("p1", "aws:s3:*", RuleType::Idempotent));
        assert_eq!(tree.rules().len(), 1);

        assert!(tree.remove_rule("p1"));
        assert_eq!(tree.rules().len(), 0);

        // removing non-existent returns false
        assert!(!tree.remove_rule("p1"));
    }

    // matching_rules for what-can-i queries
    #[test]
    fn matching_rules_query() {
        let tree = PermissionTree::new();
        tree.add_rule(permit("p1", "aws:s3:*", RuleType::Idempotent));
        tree.add_rule(permit("p2", "aws:ec2:*", RuleType::Idempotent));
        tree.add_rule(forbid("f1", "aws:s3:Delete*", "no deletes"));

        let matches = tree.matching_rules("aws:s3:ListBuckets");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id, "p1");

        let matches = tree.matching_rules("aws:s3:DeleteBucket");
        assert_eq!(matches.len(), 2); // p1 and f1 both match
    }

    // DecisionMaker trait integration
    #[test]
    fn decision_maker_integration() {
        use std::collections::HashMap;

        let tree = PermissionTree::new();
        tree.add_rule(permit("p1", "aws:s3:ListBuckets", RuleType::Idempotent));

        let action = Action {
            provider: "aws".to_string(),
            qualifier: HashMap::new(),
            service: "s3".to_string(),
            operation: "ListBuckets".to_string(),
            raw: "aws:s3:ListBuckets".to_string(),
        };

        let verdict = DecisionMaker::evaluate(&tree, &action);
        assert!(matches!(verdict, Verdict::Allow));
    }
}
