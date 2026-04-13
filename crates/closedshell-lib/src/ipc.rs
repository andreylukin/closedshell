use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::task::JoinHandle;

use crate::approval::{ApprovalQueue, ApprovalVerdict};
use crate::risk::HistoryEntry;

// -- Session state: shared between proxy decider and IPC handler --

const MAX_HISTORY: usize = 20;

/// Last denial info, returned by the decider and used to build 403 responses.
#[derive(Debug, Clone)]
pub struct DenialInfo {
    pub action: String,
    pub reason: String,
    pub risk_tier: String,
    pub hint: String,
    /// What denied this: "tree", "forbid", "human", "default", "timeout"
    pub denied_by: String,
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

/// Request types from the TUI
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum IpcRequest {
    Status,
    PendingApprovals,
    Approve { id: String },
    Deny { id: String, reason: Option<String> },
    DeleteRule { rule_id: String },
}

/// Response back to TUI
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

/// Enforcing mode handler — backed by permission tree and approval queue.
pub struct EnforcingIpcHandler {
    pub tree: Arc<crate::permission::PermissionTree>,
    pub state: Arc<SessionState>,
    pub audit: Arc<crate::audit::AuditLog>,
    pub approval_queue: Arc<ApprovalQueue>,
}

impl IpcHandler for EnforcingIpcHandler {
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

            IpcRequest::PendingApprovals => {
                let pending: Vec<serde_json::Value> = self
                    .approval_queue
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
            }

            IpcRequest::Approve { ref id } => {
                match self.approval_queue.resolve(id, ApprovalVerdict::Approved) {
                    Ok(info) => {
                        let _ = self.audit.log(crate::audit::AuditPayload::HumanApproval {
                            action: info.action.clone(),
                            verdict: "approved".to_string(),
                            risk_tier: info.risk_tier.clone(),
                            wait_ms: info.created_at.elapsed().as_millis() as u64,
                        });
                        IpcResponse::ok(serde_json::json!({
                            "approved": true,
                            "action": info.action,
                        }))
                    }
                    Err(e) => IpcResponse::err("not_found", &e.to_string(), None),
                }
            }

            IpcRequest::Deny { ref id, ref reason } => {
                let reason_str = reason.as_deref().unwrap_or("denied by human").to_string();
                match self
                    .approval_queue
                    .resolve(id, ApprovalVerdict::Denied { reason: reason_str })
                {
                    Ok(info) => {
                        let _ = self.audit.log(crate::audit::AuditPayload::HumanApproval {
                            action: info.action.clone(),
                            verdict: "denied".to_string(),
                            risk_tier: info.risk_tier.clone(),
                            wait_ms: info.created_at.elapsed().as_millis() as u64,
                        });
                        IpcResponse::ok(serde_json::json!({
                            "denied": true,
                            "action": info.action,
                        }))
                    }
                    Err(e) => IpcResponse::err("not_found", &e.to_string(), None),
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

        let tree = Arc::new(crate::permission::PermissionTree::new());
        let state = Arc::new(SessionState::new());
        let audit_dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(crate::audit::AuditLog::open(audit_dir.path(), "test-ipc").unwrap());
        let approval_queue = Arc::new(ApprovalQueue::new());

        let handler: Arc<dyn IpcHandler> = Arc::new(EnforcingIpcHandler {
            tree,
            state,
            audit,
            approval_queue,
        });
        let server = IpcServer::new(&sock_str, handler);
        let handle = server.start().unwrap();

        // Give the listener a moment to bind
        tokio::task::yield_now().await;

        let resp = roundtrip(&sock_str, r#"{"type": "status"}"#).await;
        assert!(resp.ok);

        handle.abort();
    }

    #[tokio::test]
    async fn invalid_json_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("test.sock");
        let sock_str = sock.to_str().unwrap().to_string();

        let tree = Arc::new(crate::permission::PermissionTree::new());
        let state = Arc::new(SessionState::new());
        let audit_dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(crate::audit::AuditLog::open(audit_dir.path(), "test-ipc").unwrap());
        let approval_queue = Arc::new(ApprovalQueue::new());

        let handler: Arc<dyn IpcHandler> = Arc::new(EnforcingIpcHandler {
            tree,
            state,
            audit,
            approval_queue,
        });
        let server = IpcServer::new(&sock_str, handler);
        let handle = server.start().unwrap();

        tokio::task::yield_now().await;

        let resp = roundtrip(&sock_str, "not json at all").await;
        assert!(!resp.ok);
        assert_eq!(resp.error.unwrap(), "parse_error");

        handle.abort();
    }
}
