use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::task::JoinHandle;

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
