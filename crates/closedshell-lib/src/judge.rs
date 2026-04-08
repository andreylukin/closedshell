//! Judge client — consults an LLM via OpenAI-compatible API for permission decisions.

use crate::config::JudgeConfig;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, warn};

const DEFAULT_SYSTEM_PROMPT: &str = r#"You are the permission judge for ClosedShell, a security sandbox for AI agents on macOS.

Your job: evaluate whether a sandboxed agent's requested action should be approved, denied, or escalated to a human operator.

You receive a JSON object with:
- requested_action: canonical action string (e.g. "aws:s3:GetObject", "net:POST:api.example.com/v1/chat")
- current_tree: list of existing permission rules
- session_context: task description and metadata
- history: recent decisions with timestamps
- risk_tier: pre-classified risk level ("safe", "moderate", "dangerous")
- implicit: whether this is an implicit sub-action of an approved parent

Respond with a JSON object containing exactly these fields:
- decision: one of "approve", "deny", "escalate_human"
- risk_level: "safe", "moderate", or "dangerous"
- reasoning: brief explanation of your decision
- proposed_expansion: (optional) array of glob patterns to add as persistent rules if approving
- deny_reason: (optional) human-readable reason if denying

Guidelines:
- Safe read-only operations (List, Get, Describe, Head) from established services: lean approve
- Write/mutate operations: approve only if clearly within the task scope
- Destructive operations (Delete, Terminate, Remove, Revoke): escalate or deny unless explicitly in scope
- When implicit=true, the parent action was already approved — be more lenient
- When in doubt, escalate to human rather than deny outright
- Never approve actions that could exfiltrate credentials or modify IAM/permissions"#;

pub struct JudgeClient {
    http: reqwest::Client,
    config: JudgeConfig,
    system_prompt: String,
}

// -- Request/response types --

#[derive(Debug, Serialize)]
pub struct JudgeRequest {
    pub requested_action: String,
    pub current_tree: Vec<String>,
    pub session_context: SessionContext,
    pub history: Vec<HistoryEntry>,
    pub risk_tier: String,
    pub implicit: bool,
}

#[derive(Debug, Serialize)]
pub struct SessionContext {
    pub task: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HistoryEntry {
    pub action: String,
    pub decision: String,
    pub by: String,
    pub t: i64,
}

#[derive(Debug, Deserialize)]
pub struct JudgeResponse {
    pub decision: String,
    pub risk_level: String,
    pub reasoning: String,
    #[serde(default)]
    pub proposed_expansion: Option<Vec<String>>,
    #[serde(default)]
    pub deny_reason: Option<String>,
}

#[derive(Debug, PartialEq)]
pub enum JudgeDecision {
    Approve,
    Deny { reason: String },
    EscalateHuman,
}

// -- Plan evaluation types --

#[derive(Debug, Serialize)]
pub struct PlanRequest {
    pub description: String,
    pub current_tree: Vec<String>,
    pub session_context: SessionContext,
    pub history: Vec<HistoryEntry>,
}

#[derive(Debug, Deserialize)]
pub struct PlanResponse {
    pub plan_id: String,
    pub rules: Vec<ProposedRule>,
    pub reasoning: String,
}

#[derive(Debug, Deserialize)]
pub struct ProposedRule {
    pub effect: String,
    pub action: String,
    pub rule_type: String,
    pub risk_level: String,
}

// -- OpenAI-compatible API types (internal) --

#[derive(Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    temperature: f32,
    max_tokens: u32,
    response_format: ResponseFormat,
}

#[derive(Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Serialize)]
struct ResponseFormat {
    r#type: String,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: ChoiceMessage,
}

#[derive(Deserialize)]
struct ChoiceMessage {
    content: String,
}

impl JudgeClient {
    /// Create a new judge client. Loads system prompt from file if configured.
    ///
    /// Validates TLS requirements:
    /// - Non-localhost endpoints must use HTTPS (unless `require_tls: false` in config)
    /// - Optional certificate pinning via `tls_ca_cert` config
    pub fn new(config: JudgeConfig) -> anyhow::Result<Self> {
        // Enforce TLS for non-localhost endpoints
        if config.tls_required() && config.api_base.starts_with("http://") {
            anyhow::bail!(
                "judge API endpoint '{}' uses plain HTTP but TLS is required for non-localhost endpoints. \
                 Use an https:// URL, or set judge.require_tls: false in config to override (not recommended).",
                config.api_base
            );
        }

        let system_prompt = match &config.system_prompt_path {
            Some(path) => std::fs::read_to_string(path).map_err(|e| {
                anyhow::anyhow!("failed to read system prompt from {}: {}", path, e)
            })?,
            None => DEFAULT_SYSTEM_PROMPT.to_string(),
        };

        let mut http_builder =
            reqwest::Client::builder().timeout(Duration::from_millis(config.timeout_ms));

        // Certificate pinning: if a CA cert is configured, use only that for TLS verification
        if let Some(ref ca_path) = config.tls_ca_cert {
            let ca_pem = std::fs::read(ca_path).map_err(|e| {
                anyhow::anyhow!("failed to read judge TLS CA cert from {}: {}", ca_path, e)
            })?;
            let cert = reqwest::Certificate::from_pem(&ca_pem)?;
            http_builder = http_builder
                .add_root_certificate(cert)
                .tls_built_in_root_certs(false);
            debug!("judge client: TLS pinned to CA from {}", ca_path);
        }

        let http = http_builder.build()?;

        Ok(Self {
            http,
            config,
            system_prompt,
        })
    }

    /// Evaluate a single action. Returns Deny on any error or timeout.
    pub async fn evaluate_action(&self, req: JudgeRequest) -> JudgeDecision {
        let user_content = match serde_json::to_string(&req) {
            Ok(s) => s,
            Err(e) => {
                warn!("failed to serialize judge request: {}", e);
                return JudgeDecision::Deny {
                    reason: "internal: failed to serialize request".into(),
                };
            }
        };

        let chat_req = self.build_chat_request(&user_content);

        let result = self.post_chat_completions(&chat_req).await;

        match result {
            Ok(body) => self.parse_action_response(&body),
            Err(e) => {
                warn!("judge call failed: {}", e);
                JudgeDecision::Deny {
                    reason: format!("judge unavailable: {}", e),
                }
            }
        }
    }

    /// Evaluate a plan. Returns error on failure (caller decides fallback).
    pub async fn evaluate_plan(&self, req: PlanRequest) -> anyhow::Result<PlanResponse> {
        let user_content = serde_json::to_string(&req)?;
        let chat_req = self.build_chat_request(&user_content);
        let body = self.post_chat_completions(&chat_req).await?;
        let resp: PlanResponse = serde_json::from_str(&body).map_err(|e| {
            anyhow::anyhow!("failed to parse plan response: {} (body: {})", e, body)
        })?;
        Ok(resp)
    }

    fn build_chat_request(&self, user_content: &str) -> ChatRequest {
        ChatRequest {
            model: self.config.model.clone(),
            messages: vec![
                ChatMessage {
                    role: "system".into(),
                    content: self.system_prompt.clone(),
                },
                ChatMessage {
                    role: "user".into(),
                    content: user_content.to_string(),
                },
            ],
            temperature: self.config.temperature,
            max_tokens: 512,
            response_format: ResponseFormat {
                r#type: "json_object".into(),
            },
        }
    }

    async fn post_chat_completions(&self, chat_req: &ChatRequest) -> anyhow::Result<String> {
        let url = format!(
            "{}/chat/completions",
            self.config.api_base.trim_end_matches('/')
        );
        debug!("POST {}", url);

        let mut req_builder = self.http.post(&url).json(chat_req);

        if !self.config.api_key.is_empty() {
            req_builder = req_builder.bearer_auth(&self.config.api_key);
        }

        let resp = req_builder.send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("judge API returned {}: {}", status, body);
        }

        let chat_resp: ChatResponse = resp.json().await?;
        let content = chat_resp
            .choices
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("judge returned empty choices"))?
            .message
            .content;

        Ok(content)
    }

    fn parse_action_response(&self, body: &str) -> JudgeDecision {
        let resp: JudgeResponse = match serde_json::from_str(body) {
            Ok(r) => r,
            Err(e) => {
                warn!("failed to parse judge response: {} (body: {})", e, body);
                return JudgeDecision::Deny {
                    reason: "judge returned malformed response".into(),
                };
            }
        };

        debug!(
            "judge decision={} risk={} reasoning={}",
            resp.decision, resp.risk_level, resp.reasoning
        );

        match resp.decision.as_str() {
            "approve" => JudgeDecision::Approve,
            "escalate_human" => JudgeDecision::EscalateHuman,
            "deny" => JudgeDecision::Deny {
                reason: resp.deny_reason.unwrap_or_else(|| resp.reasoning.clone()),
            },
            other => {
                warn!("judge returned unknown decision: {}", other);
                JudgeDecision::Deny {
                    reason: format!("unknown judge decision: {}", other),
                }
            }
        }
    }
}

/// Classify risk tier based on the canonical action string.
pub fn classify_risk(action_canonical: &str) -> &'static str {
    // Extract the operation name — last segment after ':'
    let op = action_canonical
        .rsplit(':')
        .next()
        .unwrap_or(action_canonical);

    // Check prefixes for known patterns
    let safe_prefixes = ["Describe", "List", "Get", "Head"];
    let dangerous_prefixes = ["Delete", "Terminate", "Remove", "Revoke", "Detach"];
    let moderate_prefixes = ["Create", "Put", "Start", "Stop", "Update", "Tag"];

    // Also check lowercase keywords (for non-AWS styles like net:POST:...)
    let safe_keywords = ["read"];
    let dangerous_keywords: [&str; 0] = [];
    let moderate_keywords = ["insert", "patch", "write", "POST"];

    for prefix in &safe_prefixes {
        if op.starts_with(prefix) {
            return "safe";
        }
    }
    for kw in &safe_keywords {
        if op.eq_ignore_ascii_case(kw) {
            return "safe";
        }
    }

    for prefix in &dangerous_prefixes {
        if op.starts_with(prefix) {
            return "dangerous";
        }
    }
    for kw in &dangerous_keywords {
        if op.eq_ignore_ascii_case(kw) {
            return "dangerous";
        }
    }

    for prefix in &moderate_prefixes {
        if op.starts_with(prefix) {
            return "moderate";
        }
    }
    for kw in &moderate_keywords {
        if op.eq_ignore_ascii_case(kw) {
            return "moderate";
        }
    }

    "moderate"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_risk_safe() {
        assert_eq!(classify_risk("aws:s3:ListBuckets"), "safe");
        assert_eq!(classify_risk("aws:ec2:DescribeInstances"), "safe");
        assert_eq!(classify_risk("aws:s3:GetObject"), "safe");
        assert_eq!(classify_risk("aws:s3:HeadObject"), "safe");
        assert_eq!(classify_risk("fs:read"), "safe");
    }

    #[test]
    fn test_classify_risk_moderate() {
        assert_eq!(classify_risk("aws:s3:PutObject"), "moderate");
        assert_eq!(classify_risk("aws:ec2:CreateInstance"), "moderate");
        assert_eq!(classify_risk("aws:ec2:StartInstances"), "moderate");
        assert_eq!(classify_risk("aws:ec2:StopInstances"), "moderate");
        assert_eq!(classify_risk("aws:ec2:UpdateStack"), "moderate");
        assert_eq!(classify_risk("aws:ec2:TagResource"), "moderate");
        assert_eq!(classify_risk("net:POST:example.com/api"), "moderate");
    }

    #[test]
    fn test_classify_risk_dangerous() {
        assert_eq!(classify_risk("aws:s3:DeleteBucket"), "dangerous");
        assert_eq!(classify_risk("aws:ec2:TerminateInstances"), "dangerous");
        assert_eq!(
            classify_risk("aws:iam:RemoveRoleFromInstanceProfile"),
            "dangerous"
        );
        assert_eq!(
            classify_risk("aws:iam:RevokeSecurityGroupIngress"),
            "dangerous"
        );
        assert_eq!(classify_risk("aws:ec2:DetachVolume"), "dangerous");
    }

    #[test]
    fn test_classify_risk_default() {
        assert_eq!(classify_risk("aws:s3:SomeUnknownAction"), "moderate");
        assert_eq!(classify_risk("net:PATCH:example.com/api"), "moderate");
    }

    #[test]
    fn test_judge_response_deserialize_approve() {
        let json = r#"{
            "decision": "approve",
            "risk_level": "safe",
            "reasoning": "read-only S3 operation",
            "proposed_expansion": ["aws:s3:Get*"]
        }"#;
        let resp: JudgeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.decision, "approve");
        assert_eq!(resp.risk_level, "safe");
        assert_eq!(resp.proposed_expansion.unwrap(), vec!["aws:s3:Get*"]);
        assert!(resp.deny_reason.is_none());
    }

    #[test]
    fn test_judge_response_deserialize_deny() {
        let json = r#"{
            "decision": "deny",
            "risk_level": "dangerous",
            "reasoning": "attempting to delete production bucket",
            "deny_reason": "destructive action outside task scope"
        }"#;
        let resp: JudgeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.decision, "deny");
        assert_eq!(
            resp.deny_reason.unwrap(),
            "destructive action outside task scope"
        );
    }

    #[test]
    fn test_judge_response_deserialize_minimal() {
        let json = r#"{
            "decision": "escalate_human",
            "risk_level": "moderate",
            "reasoning": "ambiguous scope"
        }"#;
        let resp: JudgeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.decision, "escalate_human");
        assert!(resp.proposed_expansion.is_none());
        assert!(resp.deny_reason.is_none());
    }

    #[test]
    fn test_plan_response_deserialize() {
        let json = r#"{
            "plan_id": "plan-001",
            "rules": [
                {
                    "effect": "permit",
                    "action": "aws:s3:GetObject",
                    "rule_type": "idempotent",
                    "risk_level": "safe"
                },
                {
                    "effect": "permit",
                    "action": "aws:s3:PutObject",
                    "rule_type": "one-shot",
                    "risk_level": "moderate"
                }
            ],
            "reasoning": "task requires reading and writing S3 objects"
        }"#;
        let resp: PlanResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.plan_id, "plan-001");
        assert_eq!(resp.rules.len(), 2);
        assert_eq!(resp.rules[0].action, "aws:s3:GetObject");
        assert_eq!(resp.rules[1].rule_type, "one-shot");
    }

    #[test]
    fn test_parse_action_response_approve() {
        let client = make_test_client();
        let body = r#"{"decision":"approve","risk_level":"safe","reasoning":"ok"}"#;
        assert_eq!(client.parse_action_response(body), JudgeDecision::Approve);
    }

    #[test]
    fn test_parse_action_response_deny() {
        let client = make_test_client();
        let body = r#"{"decision":"deny","risk_level":"dangerous","reasoning":"nope","deny_reason":"bad"}"#;
        assert_eq!(
            client.parse_action_response(body),
            JudgeDecision::Deny {
                reason: "bad".into()
            }
        );
    }

    #[test]
    fn test_parse_action_response_escalate() {
        let client = make_test_client();
        let body = r#"{"decision":"escalate_human","risk_level":"moderate","reasoning":"unclear"}"#;
        assert_eq!(
            client.parse_action_response(body),
            JudgeDecision::EscalateHuman
        );
    }

    #[test]
    fn test_parse_action_response_malformed() {
        let client = make_test_client();
        let result = client.parse_action_response("not json at all");
        assert!(matches!(result, JudgeDecision::Deny { .. }));
    }

    #[test]
    fn test_parse_action_response_unknown_decision() {
        let client = make_test_client();
        let body = r#"{"decision":"maybe","risk_level":"safe","reasoning":"idk"}"#;
        let result = client.parse_action_response(body);
        assert!(matches!(result, JudgeDecision::Deny { .. }));
    }

    #[tokio::test]
    async fn test_timeout_returns_deny() {
        // Start a TCP listener that accepts but never responds
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Accept connections in background but don't respond
        tokio::spawn(async move {
            loop {
                let (_socket, _) = listener.accept().await.unwrap();
                // Hold the connection open, never send data
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });

        let config = JudgeConfig {
            api_base: format!("http://{}", addr),
            timeout_ms: 200, // very short timeout
            ..Default::default()
        };
        let client = JudgeClient::new(config).unwrap();

        let req = JudgeRequest {
            requested_action: "aws:s3:GetObject".into(),
            current_tree: vec![],
            session_context: SessionContext { task: None },
            history: vec![],
            risk_tier: "safe".into(),
            implicit: false,
        };

        let decision = client.evaluate_action(req).await;
        assert!(matches!(decision, JudgeDecision::Deny { .. }));
    }

    #[tokio::test]
    async fn test_malformed_json_response_returns_deny() {
        use std::io::Write;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // Respond with valid HTTP but invalid JSON in the chat completions format
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                // Read the request
                let mut buf = [0u8; 4096];
                let _ = std::io::Read::read(&mut stream, &mut buf);

                let body = r#"{"choices":[{"message":{"content":"this is not json object"}}]}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });

        let config = JudgeConfig {
            api_base: format!("http://{}", addr),
            timeout_ms: 2000,
            ..Default::default()
        };
        let client = JudgeClient::new(config).unwrap();

        let req = JudgeRequest {
            requested_action: "aws:s3:GetObject".into(),
            current_tree: vec![],
            session_context: SessionContext { task: None },
            history: vec![],
            risk_tier: "safe".into(),
            implicit: false,
        };

        let decision = client.evaluate_action(req).await;
        assert!(matches!(decision, JudgeDecision::Deny { .. }));
    }

    #[test]
    fn test_tls_required_for_remote_http() {
        let config = JudgeConfig {
            api_base: "http://judge.example.com/v1".into(),
            ..Default::default()
        };
        let err = JudgeClient::new(config).err().expect("should fail");
        assert!(err.to_string().contains("TLS is required"));
    }

    #[test]
    fn test_tls_not_required_for_localhost() {
        let config = JudgeConfig {
            api_base: "http://localhost:11434/v1".into(),
            ..Default::default()
        };
        assert!(JudgeClient::new(config).is_ok());
    }

    #[test]
    fn test_tls_not_required_for_127() {
        let config = JudgeConfig {
            api_base: "http://127.0.0.1:11434/v1".into(),
            ..Default::default()
        };
        assert!(JudgeClient::new(config).is_ok());
    }

    #[test]
    fn test_tls_override_allows_remote_http() {
        let config = JudgeConfig {
            api_base: "http://judge.example.com/v1".into(),
            require_tls: Some(false),
            ..Default::default()
        };
        assert!(JudgeClient::new(config).is_ok());
    }

    #[test]
    fn test_tls_override_requires_localhost_https() {
        let config = JudgeConfig {
            api_base: "http://localhost:11434/v1".into(),
            require_tls: Some(true),
            ..Default::default()
        };
        let err = JudgeClient::new(config).err().expect("should fail");
        assert!(err.to_string().contains("TLS is required"));
    }

    #[test]
    fn test_tls_ca_cert_nonexistent_file() {
        let config = JudgeConfig {
            api_base: "https://judge.example.com/v1".into(),
            tls_ca_cert: Some("/nonexistent/ca.pem".into()),
            ..Default::default()
        };
        let err = JudgeClient::new(config).err().expect("should fail");
        assert!(err.to_string().contains("failed to read judge TLS CA cert"));
    }

    fn make_test_client() -> JudgeClient {
        JudgeClient {
            http: reqwest::Client::new(),
            config: JudgeConfig::default(),
            system_prompt: DEFAULT_SYSTEM_PROMPT.to_string(),
        }
    }
}
