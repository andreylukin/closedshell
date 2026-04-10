use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::task::JoinHandle;

use crate::approval::{ApprovalQueue, ApprovalVerdict};
use crate::judge::HistoryEntry;

// -- Session state: shared between proxy decider and IPC handler --

const MAX_HISTORY: usize = 20;

/// Last denial info, returned by `ask why-denied`.
#[derive(Debug, Clone)]
pub struct DenialInfo {
    pub action: String,
    pub reason: String,
    pub risk_tier: String,
    pub hint: String,
}

/// Shared mutable session state.
pub struct SessionState {
    task: Mutex<Option<String>>,
    last_denial: Mutex<Option<DenialInfo>>,
    history: Mutex<VecDeque<HistoryEntry>>,
}

impl Default for SessionState {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionState {
    pub fn new() -> Self {
        Self {
            task: Mutex::new(None),
            last_denial: Mutex::new(None),
            history: Mutex::new(VecDeque::with_capacity(MAX_HISTORY)),
        }
    }

    pub fn set_task(&self, task: String) -> Option<String> {
        let mut t = self.task.lock().unwrap();
        let old = t.take();
        *t = Some(task);
        old
    }

    pub fn snapshot_task(&self) -> Option<String> {
        self.task.lock().unwrap().clone()
    }

    pub fn record_decision(&self, action: &str, decision: &str, by: &str) {
        let mut history = self.history.lock().unwrap();
        if history.len() >= MAX_HISTORY {
            history.pop_front();
        }
        history.push_back(HistoryEntry {
            action: action.to_string(),
            decision: decision.to_string(),
            by: by.to_string(),
            t: chrono::Utc::now().timestamp(),
        });
    }

    pub fn record_denial(&self, info: DenialInfo) {
        *self.last_denial.lock().unwrap() = Some(info);
    }

    pub fn last_denial(&self) -> Option<DenialInfo> {
        self.last_denial.lock().unwrap().clone()
    }

    pub fn snapshot_history(&self) -> Vec<HistoryEntry> {
        self.history.lock().unwrap().iter().cloned().collect()
    }
}

/// Request types from the ask CLI
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum IpcRequest {
    Status,
    WhatCanI { pattern: String },
    WhyDenied,
    Allow { action: String },
    Plan { description: String },
    Context { task: String },
    Read { path: String },
    Write { path: String, content: String },
    PendingApprovals,
    Approve { id: String },
    Deny { id: String, reason: Option<String> },
    DeleteRule { rule_id: String },
}

/// Response back to ask CLI
#[derive(Debug, Serialize, Deserialize)]
pub struct IpcResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

impl IpcResponse {
    pub fn ok(data: serde_json::Value) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error: None,
            message: None,
            hint: None,
        }
    }

    pub fn err(error: &str, message: &str, hint: Option<&str>) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(error.to_string()),
            message: Some(message.to_string()),
            hint: hint.map(|s| s.to_string()),
        }
    }
}

/// Handler trait for processing IPC requests
pub trait IpcHandler: Send + Sync + 'static {
    fn handle(&self, request: IpcRequest) -> IpcResponse;
}

/// The IPC server
pub struct IpcServer {
    socket_path: String,
    handler: Arc<dyn IpcHandler>,
}

impl IpcServer {
    pub fn new(socket_path: impl Into<String>, handler: Arc<dyn IpcHandler>) -> Self {
        Self {
            socket_path: socket_path.into(),
            handler,
        }
    }

    /// Start the IPC server. Returns a JoinHandle for the accept loop.
    pub fn start(&self) -> anyhow::Result<JoinHandle<()>> {
        // Remove stale socket file
        let _ = std::fs::remove_file(&self.socket_path);

        let listener = UnixListener::bind(&self.socket_path)?;
        let handler = self.handler.clone();

        tracing::info!(socket = %self.socket_path, "IPC server listening");

        let handle = tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(e) => {
                        tracing::warn!("IPC accept error: {}", e);
                        continue;
                    }
                };

                let handler = handler.clone();
                tokio::spawn(async move {
                    let (reader, mut writer) = stream.into_split();
                    let mut reader = BufReader::new(reader);
                    let mut line = String::new();

                    let response = match reader.read_line(&mut line).await {
                        Ok(0) => return, // EOF
                        Ok(_) => match serde_json::from_str::<IpcRequest>(line.trim()) {
                            Ok(req) => handler.handle(req),
                            Err(e) => IpcResponse::err(
                                "parse_error",
                                &format!("invalid request: {}", e),
                                Some("send a JSON object with a \"type\" field"),
                            ),
                        },
                        Err(e) => {
                            tracing::warn!("IPC read error: {}", e);
                            return;
                        }
                    };

                    let mut buf = serde_json::to_vec(&response).unwrap_or_default();
                    buf.push(b'\n');
                    let _ = writer.write_all(&buf).await;
                });
            }
        });

        Ok(handle)
    }
}

/// YOLO mode handler — everything allowed, no denials.
pub struct YoloIpcHandler;

impl IpcHandler for YoloIpcHandler {
    fn handle(&self, request: IpcRequest) -> IpcResponse {
        match request {
            IpcRequest::Status => IpcResponse::ok(serde_json::json!({
                "mode": "yolo",
                "rules": [],
            })),
            IpcRequest::WhatCanI { pattern: _ } => IpcResponse::ok(serde_json::json!({
                "matches": [],
                "mode": "yolo",
                "note": "everything is allowed in yolo mode",
            })),
            IpcRequest::WhyDenied => IpcResponse::ok(serde_json::json!({
                "message": "no denials in yolo mode",
            })),
            IpcRequest::Allow { action: _ } => IpcResponse::ok(serde_json::json!({
                "granted": true,
            })),
            IpcRequest::Plan { description: _ } => IpcResponse::ok(serde_json::json!({
                "plan_id": "yolo-plan-001",
            })),
            IpcRequest::Context { ref task } => IpcResponse::ok(serde_json::json!({
                "task": task,
                "accepted": true,
            })),
            IpcRequest::Read { ref path } => match std::fs::read_to_string(path) {
                Ok(content) => IpcResponse::ok(serde_json::json!({
                    "content": content,
                })),
                Err(e) => IpcResponse::err(
                    "read_error",
                    &format!("failed to read {}: {}", path, e),
                    None,
                ),
            },
            IpcRequest::Write {
                ref path,
                ref content,
            } => match std::fs::write(path, content) {
                Ok(()) => IpcResponse::ok(serde_json::json!({
                    "bytes_written": content.len(),
                })),
                Err(e) => IpcResponse::err(
                    "write_error",
                    &format!("failed to write {}: {}", path, e),
                    None,
                ),
            },
            IpcRequest::PendingApprovals => IpcResponse::ok(serde_json::json!({ "pending": [] })),
            IpcRequest::Approve { .. } | IpcRequest::Deny { .. } => {
                IpcResponse::err("no_queue", "no approval queue in yolo mode", None)
            }
            IpcRequest::DeleteRule { .. } => {
                IpcResponse::err("no_rules", "no rules in yolo mode", None)
            }
        }
    }
}

/// Production handler — backed by permission tree, judge, and session state.
pub struct ProductionIpcHandler {
    pub tree: Arc<crate::permission::PermissionTree>,
    pub judge: Arc<crate::judge::JudgeClient>,
    pub state: Arc<SessionState>,
    pub audit: Arc<crate::audit::AuditLog>,
    pub approval_queue: Option<Arc<ApprovalQueue>>,
}

impl IpcHandler for ProductionIpcHandler {
    fn handle(&self, request: IpcRequest) -> IpcResponse {
        match request {
            IpcRequest::Status => {
                let rules: Vec<serde_json::Value> = self
                    .tree
                    .rules()
                    .iter()
                    .map(|r| {
                        let effect = match r.effect {
                            crate::permission::Effect::Permit => "permit",
                            crate::permission::Effect::Forbid => "forbid",
                        };
                        let rule_type = r.rule_type.as_ref().map(|rt| match rt {
                            crate::permission::RuleType::Idempotent => "idempotent",
                            crate::permission::RuleType::OneShot { .. } => "one-shot",
                        });
                        serde_json::json!({
                            "id": r.id,
                            "effect": effect,
                            "pattern": r.action,
                            "source": r.source,
                            "rule_type": rule_type,
                            "reason": r.reason,
                        })
                    })
                    .collect();
                IpcResponse::ok(serde_json::json!({ "rules": rules }))
            }

            IpcRequest::WhatCanI { ref pattern } => {
                let matches: Vec<serde_json::Value> = self
                    .tree
                    .matching_rules(pattern)
                    .iter()
                    .map(|r| {
                        let effect = match r.effect {
                            crate::permission::Effect::Permit => "permit",
                            crate::permission::Effect::Forbid => "forbid",
                        };
                        serde_json::json!({
                            "effect": effect,
                            "pattern": r.action,
                        })
                    })
                    .collect();
                IpcResponse::ok(serde_json::json!(matches))
            }

            IpcRequest::WhyDenied => match self.state.last_denial() {
                Some(info) => IpcResponse::ok(serde_json::json!({
                    "action": info.action,
                    "reason": info.reason,
                    "risk_tier": info.risk_tier,
                    "hint": info.hint,
                })),
                None => IpcResponse::ok(serde_json::json!({
                    "message": "no recent denials",
                })),
            },

            IpcRequest::Allow { ref action } => {
                // Consult judge for explicit permission request
                let result = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        let risk_tier = crate::judge::classify_risk(action);
                        let req = crate::judge::JudgeRequest {
                            requested_action: action.clone(),
                            current_tree: self
                                .tree
                                .rules()
                                .iter()
                                .map(|r| {
                                    let effect = match r.effect {
                                        crate::permission::Effect::Permit => "permit",
                                        crate::permission::Effect::Forbid => "forbid",
                                    };
                                    format!("{} {}", effect, r.action)
                                })
                                .collect(),
                            session_context: crate::judge::SessionContext {
                                task: self.state.snapshot_task(),
                            },
                            history: self.state.snapshot_history(),
                            risk_tier: risk_tier.to_string(),
                            implicit: false,
                        };

                        let start = std::time::Instant::now();
                        let decision = self.judge.evaluate_action(req).await;
                        let latency_ms = start.elapsed().as_millis() as u64;

                        let decision_str = match &decision {
                            crate::judge::JudgeDecision::Approve => "approve",
                            crate::judge::JudgeDecision::Deny { .. } => "deny",
                            crate::judge::JudgeDecision::EscalateHuman => "escalate_human",
                        };

                        let _ = self.audit.log(crate::audit::AuditPayload::Judge {
                            action: action.clone(),
                            decision: decision_str.to_string(),
                            risk_tier: risk_tier.to_string(),
                            latency_ms,
                            implicit: false,
                        });

                        decision
                    })
                });

                match result {
                    crate::judge::JudgeDecision::Approve => {
                        self.tree.add_rule(crate::permission::Rule {
                            id: format!("ask-{}", chrono::Utc::now().timestamp_millis()),
                            effect: crate::permission::Effect::Permit,
                            action: action.clone(),
                            rule_type: Some(crate::permission::RuleType::Idempotent),
                            approved_by: Some("judge".into()),
                            source: Some("ask-allow".into()),
                            plan_id: None,
                            reason: None,
                            expires: None,
                        });
                        self.state.record_decision(action, "allow", "judge");
                        IpcResponse::ok(serde_json::json!({
                            "granted": true,
                            "pattern": action,
                        }))
                    }
                    crate::judge::JudgeDecision::Deny { reason } => {
                        self.state.record_denial(DenialInfo {
                            action: action.clone(),
                            reason: reason.clone(),
                            risk_tier: crate::judge::classify_risk(action).to_string(),
                            hint: "ask plan \"describe your goal\"".to_string(),
                        });
                        IpcResponse::ok(serde_json::json!({
                            "granted": false,
                            "reason": reason,
                        }))
                    }
                    crate::judge::JudgeDecision::EscalateHuman => {
                        IpcResponse::ok(serde_json::json!({
                            "granted": false,
                            "reason": "escalated to human approval",
                        }))
                    }
                }
            }

            IpcRequest::Plan { ref description } => {
                let result = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        let req = crate::judge::PlanRequest {
                            description: description.clone(),
                            current_tree: self
                                .tree
                                .rules()
                                .iter()
                                .map(|r| format!("{:?} {}", r.effect, r.action))
                                .collect(),
                            session_context: crate::judge::SessionContext {
                                task: self.state.snapshot_task(),
                            },
                            history: self.state.snapshot_history(),
                        };
                        self.judge.evaluate_plan(req).await
                    })
                });

                match result {
                    Ok(plan) => {
                        let mut auto_approved = 0u32;
                        let mut pending_human = 0u32;

                        for rule in &plan.rules {
                            let effect = match rule.effect.as_str() {
                                "forbid" => crate::permission::Effect::Forbid,
                                _ => crate::permission::Effect::Permit,
                            };
                            let rule_type = match rule.rule_type.as_str() {
                                "one-shot" | "oneshot" => {
                                    Some(crate::permission::RuleType::OneShot { consumed: false })
                                }
                                _ => Some(crate::permission::RuleType::Idempotent),
                            };

                            // Safe rules auto-approved, moderate/dangerous flagged
                            if rule.risk_level == "safe" {
                                self.tree.add_rule(crate::permission::Rule {
                                    id: format!("{}:{}", plan.plan_id, auto_approved),
                                    effect,
                                    action: rule.action.clone(),
                                    rule_type,
                                    approved_by: Some("judge".into()),
                                    source: Some(format!("plan:{}", plan.plan_id)),
                                    plan_id: Some(plan.plan_id.clone()),
                                    reason: None,
                                    expires: None,
                                });
                                auto_approved += 1;
                            } else {
                                pending_human += 1;
                            }
                        }

                        let _ = self.audit.log(crate::audit::AuditPayload::Plan {
                            plan_id: plan.plan_id.clone(),
                            description: description.clone(),
                            auto_approved,
                            pending_human,
                        });

                        IpcResponse::ok(serde_json::json!({
                            "plan_id": plan.plan_id,
                            "status": "processed",
                            "auto_approved": auto_approved,
                            "pending_human": pending_human,
                        }))
                    }
                    Err(e) => IpcResponse::err(
                        "plan_error",
                        &format!("judge plan evaluation failed: {}", e),
                        Some("try a simpler plan description"),
                    ),
                }
            }

            IpcRequest::Context { ref task } => {
                let old_task = self.state.set_task(task.clone());
                let _ = self.audit.log(crate::audit::AuditPayload::Context {
                    old_task,
                    new_task: task.clone(),
                });
                IpcResponse::ok(serde_json::json!({
                    "task": task,
                    "accepted": true,
                }))
            }

            // File I/O — evaluated against permission tree
            IpcRequest::Read { ref path } => {
                let canonical = format!("file:read:{}", path);
                match self.check_file_permission(&canonical) {
                    Ok(()) => {
                        let _ = self.audit.log(crate::audit::AuditPayload::FileIo {
                            action: canonical,
                            result: "allow".into(),
                            decided_by: "tree".into(),
                            bytes: None,
                        });
                        match std::fs::read_to_string(path) {
                            Ok(content) => IpcResponse::ok(serde_json::json!({
                                "content": content,
                            })),
                            Err(e) => IpcResponse::err(
                                "read_error",
                                &format!("failed to read {}: {}", path, e),
                                None,
                            ),
                        }
                    }
                    Err(reason) => {
                        let _ = self.audit.log(crate::audit::AuditPayload::FileIo {
                            action: canonical,
                            result: format!("deny: {}", reason),
                            decided_by: "tree".into(),
                            bytes: None,
                        });
                        IpcResponse::err("not_permitted", &reason, None)
                    }
                }
            }
            IpcRequest::Write {
                ref path,
                ref content,
            } => {
                let canonical = format!("file:write:{}", path);
                match self.check_file_permission(&canonical) {
                    Ok(()) => {
                        let _ = self.audit.log(crate::audit::AuditPayload::FileIo {
                            action: canonical,
                            result: "allow".into(),
                            decided_by: "tree".into(),
                            bytes: Some(content.len() as u64),
                        });
                        match std::fs::write(path, content) {
                            Ok(()) => IpcResponse::ok(serde_json::json!({
                                "bytes_written": content.len(),
                            })),
                            Err(e) => IpcResponse::err(
                                "write_error",
                                &format!("failed to write {}: {}", path, e),
                                None,
                            ),
                        }
                    }
                    Err(reason) => {
                        let _ = self.audit.log(crate::audit::AuditPayload::FileIo {
                            action: canonical,
                            result: format!("deny: {}", reason),
                            decided_by: "tree".into(),
                            bytes: None,
                        });
                        IpcResponse::err("not_permitted", &reason, None)
                    }
                }
            }

            // Approval queue commands
            IpcRequest::PendingApprovals => {
                if let Some(ref queue) = self.approval_queue {
                    let pending: Vec<serde_json::Value> = queue
                        .list_pending()
                        .iter()
                        .map(|p| {
                            serde_json::json!({
                                "id": p.id,
                                "action": p.action,
                                "risk_tier": p.risk_tier,
                                "plan_id": p.plan_id,
                                "age_s": p.created_at.elapsed().as_secs(),
                                "created_at": p.created_at_rfc3339,
                            })
                        })
                        .collect();
                    IpcResponse::ok(serde_json::json!({ "pending": pending }))
                } else {
                    IpcResponse::ok(serde_json::json!({ "pending": [] }))
                }
            }
            IpcRequest::Approve { ref id } => {
                if let Some(ref queue) = self.approval_queue {
                    match queue.resolve(id, ApprovalVerdict::Approved) {
                        Ok(info) => {
                            // Add permit rule for the approved action
                            self.tree.add_rule(crate::permission::Rule {
                                id: format!("human-{}", chrono::Utc::now().timestamp_millis()),
                                effect: crate::permission::Effect::Permit,
                                action: info.action.clone(),
                                rule_type: Some(crate::permission::RuleType::Idempotent),
                                approved_by: Some("human".into()),
                                source: Some("human-approval".into()),
                                plan_id: info.plan_id.clone(),
                                reason: None,
                                expires: None,
                            });
                            IpcResponse::ok(serde_json::json!({
                                "approved": true,
                                "action": info.action,
                            }))
                        }
                        Err(e) => IpcResponse::err("not_found", &e.to_string(), None),
                    }
                } else {
                    IpcResponse::err("no_queue", "approval queue not configured", None)
                }
            }
            IpcRequest::Deny { ref id, ref reason } => {
                if let Some(ref queue) = self.approval_queue {
                    let reason_str = reason.as_deref().unwrap_or("denied by human").to_string();
                    match queue.resolve(id, ApprovalVerdict::Denied { reason: reason_str }) {
                        Ok(info) => IpcResponse::ok(serde_json::json!({
                            "denied": true,
                            "action": info.action,
                        })),
                        Err(e) => IpcResponse::err("not_found", &e.to_string(), None),
                    }
                } else {
                    IpcResponse::err("no_queue", "approval queue not configured", None)
                }
            }
            IpcRequest::DeleteRule { ref rule_id } => {
                if self.tree.remove_rule(rule_id) {
                    IpcResponse::ok(serde_json::json!({ "deleted": true, "rule_id": rule_id }))
                } else {
                    IpcResponse::err("not_found", &format!("rule {} not found", rule_id), None)
                }
            }
        }
    }
}

impl ProductionIpcHandler {
    /// Check file action against the permission tree.
    /// Returns Ok(()) if permitted, Err(reason) if denied.
    fn check_file_permission(&self, canonical: &str) -> Result<(), String> {
        match self.tree.evaluate(canonical) {
            crate::permission::TreeVerdict::Allow => {
                self.state.record_decision(canonical, "allow", "tree");
                Ok(())
            }
            crate::permission::TreeVerdict::Deny { reason } => {
                // If there's an explicit forbid, hard deny
                if self.tree.has_forbid(canonical) {
                    self.state.record_denial(DenialInfo {
                        action: canonical.to_string(),
                        reason: reason.clone(),
                        risk_tier: "safe".into(),
                        hint: "this file action is explicitly forbidden".into(),
                    });
                    self.state.record_decision(canonical, "deny", "forbid");
                    return Err(reason);
                }

                // No explicit forbid, no permit — consult judge
                let result = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        let risk_tier = crate::judge::classify_risk(canonical);
                        let req = crate::judge::JudgeRequest {
                            requested_action: canonical.to_string(),
                            current_tree: self
                                .tree
                                .rules()
                                .iter()
                                .map(|r| {
                                    let effect = match r.effect {
                                        crate::permission::Effect::Permit => "permit",
                                        crate::permission::Effect::Forbid => "forbid",
                                    };
                                    format!("{} {}", effect, r.action)
                                })
                                .collect(),
                            session_context: crate::judge::SessionContext {
                                task: self.state.snapshot_task(),
                            },
                            history: self.state.snapshot_history(),
                            risk_tier: risk_tier.to_string(),
                            implicit: true,
                        };

                        self.judge.evaluate_action(req).await
                    })
                });

                match result {
                    crate::judge::JudgeDecision::Approve => {
                        self.tree.add_rule(crate::permission::Rule {
                            id: format!("judge-file-{}", chrono::Utc::now().timestamp_millis()),
                            effect: crate::permission::Effect::Permit,
                            action: canonical.to_string(),
                            rule_type: Some(crate::permission::RuleType::Idempotent),
                            approved_by: Some("judge".into()),
                            source: Some("implicit-ask".into()),
                            plan_id: None,
                            reason: None,
                            expires: None,
                        });
                        self.state.record_decision(canonical, "allow", "judge");
                        Ok(())
                    }
                    crate::judge::JudgeDecision::Deny { reason } => {
                        self.state.record_denial(DenialInfo {
                            action: canonical.to_string(),
                            reason: reason.clone(),
                            risk_tier: "safe".into(),
                            hint: format!("ask allow \"{}\"", canonical),
                        });
                        self.state.record_decision(canonical, "deny", "judge");
                        Err(reason)
                    }
                    crate::judge::JudgeDecision::EscalateHuman => {
                        let reason = "escalated to human approval".to_string();
                        self.state.record_denial(DenialInfo {
                            action: canonical.to_string(),
                            reason: reason.clone(),
                            risk_tier: "moderate".into(),
                            hint: "ask plan \"describe your goal\"".into(),
                        });
                        Err(reason)
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    #[test]
    fn deserialize_status() {
        let json = r#"{"type": "status"}"#;
        let req: IpcRequest = serde_json::from_str(json).unwrap();
        assert!(matches!(req, IpcRequest::Status));
    }

    #[test]
    fn deserialize_what_can_i() {
        let json = r#"{"type": "what_can_i", "pattern": "aws:s3:*"}"#;
        let req: IpcRequest = serde_json::from_str(json).unwrap();
        assert!(matches!(req, IpcRequest::WhatCanI { pattern } if pattern == "aws:s3:*"));
    }

    #[test]
    fn deserialize_write() {
        let json = r#"{"type": "write", "path": "/tmp/test.txt", "content": "hello"}"#;
        let req: IpcRequest = serde_json::from_str(json).unwrap();
        assert!(
            matches!(req, IpcRequest::Write { ref path, ref content } if path == "/tmp/test.txt" && content == "hello")
        );
    }

    #[test]
    fn serialize_ok_response() {
        let resp = IpcResponse::ok(serde_json::json!({"status": "running"}));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"ok\":true"));
        assert!(json.contains("\"status\":\"running\""));
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn serialize_err_response() {
        let resp = IpcResponse::err("not_found", "file not found", Some("check the path"));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"ok\":false"));
        assert!(json.contains("\"not_found\""));
        assert!(json.contains("\"check the path\""));
    }

    async fn roundtrip(socket_path: &str, request_json: &str) -> IpcResponse {
        let mut stream = UnixStream::connect(socket_path).await.unwrap();
        stream
            .write_all(format!("{}\n", request_json).as_bytes())
            .await
            .unwrap();
        stream.shutdown().await.unwrap();

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        serde_json::from_str(line.trim()).unwrap()
    }

    #[tokio::test]
    async fn unix_socket_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("test.sock");
        let sock_str = sock.to_str().unwrap().to_string();

        let handler: Arc<dyn IpcHandler> = Arc::new(YoloIpcHandler);
        let server = IpcServer::new(&sock_str, handler);
        let handle = server.start().unwrap();

        // Give the listener a moment to bind
        tokio::task::yield_now().await;

        let resp = roundtrip(&sock_str, r#"{"type": "status"}"#).await;
        assert!(resp.ok);
        assert_eq!(resp.data.unwrap()["mode"], "yolo");

        handle.abort();
    }

    #[tokio::test]
    async fn invalid_json_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("test.sock");
        let sock_str = sock.to_str().unwrap().to_string();

        let handler: Arc<dyn IpcHandler> = Arc::new(YoloIpcHandler);
        let server = IpcServer::new(&sock_str, handler);
        let handle = server.start().unwrap();

        tokio::task::yield_now().await;

        let resp = roundtrip(&sock_str, "not json at all").await;
        assert!(!resp.ok);
        assert_eq!(resp.error.unwrap(), "parse_error");

        handle.abort();
    }

    #[tokio::test]
    async fn file_read_write_via_ipc() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("test.sock");
        let sock_str = sock.to_str().unwrap().to_string();
        let test_file = dir.path().join("hello.txt");
        let test_file_str = test_file.to_str().unwrap();

        let handler: Arc<dyn IpcHandler> = Arc::new(YoloIpcHandler);
        let server = IpcServer::new(&sock_str, handler);
        let handle = server.start().unwrap();

        tokio::task::yield_now().await;

        // Write
        let req =
            serde_json::json!({"type": "write", "path": test_file_str, "content": "hello world"});
        let resp = roundtrip(&sock_str, &req.to_string()).await;
        assert!(resp.ok);
        assert_eq!(resp.data.as_ref().unwrap()["bytes_written"], 11);

        // Read
        let req = serde_json::json!({"type": "read", "path": test_file_str});
        let resp = roundtrip(&sock_str, &req.to_string()).await;
        assert!(resp.ok);
        assert_eq!(resp.data.unwrap()["content"], "hello world");

        handle.abort();
    }
}
