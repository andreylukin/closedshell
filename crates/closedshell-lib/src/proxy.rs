//! MITM proxy: intercepts HTTPS, parses actions, logs decisions.
//!
//! The proxy uses a [`DecisionMaker`] to decide whether each intercepted
//! request should be forwarded or blocked. In YOLO mode, [`YoloDecider`]
//! allows everything.

use crate::audit::{AuditLog, AuditPayload, RequestMeta};
use crate::ipc::{DenialInfo, SessionState};
use crate::judge::{self, JudgeClient, JudgeDecision, JudgeRequest, SessionContext};
use crate::parser::{self, Action, RequestInfo};
use crate::permission::PermissionTree;
use crate::tls::SessionCA;

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

/// The result of evaluating an action against a policy.
pub enum Verdict {
    Allow,
    Deny { reason: String },
}

/// Decides whether an intercepted action should be forwarded or blocked.
pub trait DecisionMaker: Send + Sync + 'static {
    fn evaluate(&self, action: &Action) -> Verdict;
}

/// YOLO mode: always allow.
pub struct YoloDecider;

impl DecisionMaker for YoloDecider {
    fn evaluate(&self, _action: &Action) -> Verdict {
        Verdict::Allow
    }
}

/// Allow actions matching any of the given glob patterns. Default deny.
pub struct PatternDecider {
    pub allow_patterns: Vec<String>,
}

impl DecisionMaker for PatternDecider {
    fn evaluate(&self, action: &Action) -> Verdict {
        let canonical = action.canonical();
        for pattern in &self.allow_patterns {
            if glob_match::glob_match(pattern, &canonical) {
                return Verdict::Allow;
            }
        }
        Verdict::Deny {
            reason: format!("no allow rule matched: {}", canonical),
        }
    }
}

/// Judge-backed decider: checks permission tree first, consults judge on miss.
///
/// Decision flow:
/// 1. Tree permit hit → Allow (fast path)
/// 2. Tree forbid hit → Deny (judge NOT consulted)
/// 3. No match + implicit_ask → judge call via block_in_place
/// 4. No match + !implicit_ask → Deny
pub struct JudgeDecider {
    pub tree: Arc<PermissionTree>,
    pub judge: Arc<JudgeClient>,
    pub state: Arc<SessionState>,
    pub audit: Arc<AuditLog>,
    pub implicit_ask: bool,
}

impl JudgeDecider {
    /// Consult the judge for an action with no matching permit or forbid.
    async fn consult_judge(&self, canonical: &str) -> Verdict {
        let start = std::time::Instant::now();
        let risk_tier = judge::classify_risk(canonical);

        let req = JudgeRequest {
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
            session_context: SessionContext {
                task: self.state.snapshot_task(),
            },
            history: self.state.snapshot_history(),
            risk_tier: risk_tier.to_string(),
            implicit: true,
        };

        let decision = self.judge.evaluate_action(req).await;
        let latency_ms = start.elapsed().as_millis() as u64;

        let decision_str = match &decision {
            JudgeDecision::Approve => "approve",
            JudgeDecision::Deny { .. } => "deny",
            JudgeDecision::EscalateHuman => "escalate_human",
        };

        let _ = self.audit.log(AuditPayload::Judge {
            action: canonical.to_string(),
            decision: decision_str.to_string(),
            risk_tier: risk_tier.to_string(),
            latency_ms,
            implicit: true,
        });

        match decision {
            JudgeDecision::Approve => {
                // Add rule to tree so next time is fast path
                self.tree.add_rule(crate::permission::Rule {
                    id: format!("judge-{}", chrono::Utc::now().timestamp_millis()),
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
                Verdict::Allow
            }
            JudgeDecision::Deny { reason } => {
                self.state.record_denial(DenialInfo {
                    action: canonical.to_string(),
                    reason: reason.clone(),
                    risk_tier: risk_tier.to_string(),
                    hint: format!("ask allow \"{}\"", canonical),
                });
                self.state.record_decision(canonical, "deny", "judge");
                Verdict::Deny { reason }
            }
            JudgeDecision::EscalateHuman => {
                let reason =
                    "judge escalated to human — use `ask plan` to request approval".to_string();
                self.state.record_denial(DenialInfo {
                    action: canonical.to_string(),
                    reason: reason.clone(),
                    risk_tier: risk_tier.to_string(),
                    hint: "ask plan \"describe your goal\"".to_string(),
                });
                self.state
                    .record_decision(canonical, "deny", "judge-escalate");
                Verdict::Deny { reason }
            }
        }
    }
}

impl DecisionMaker for JudgeDecider {
    fn evaluate(&self, action: &Action) -> Verdict {
        let canonical = action.canonical();

        // Check permission tree first
        let tree_verdict = self.tree.evaluate(&canonical);

        match tree_verdict {
            crate::permission::TreeVerdict::Allow => {
                self.state.record_decision(&canonical, "allow", "tree");
                Verdict::Allow
            }
            crate::permission::TreeVerdict::Deny { reason } => {
                // Explicit forbid → hard deny, judge NOT consulted
                if self.tree.has_forbid(&canonical) {
                    self.state.record_denial(DenialInfo {
                        action: canonical.clone(),
                        reason: reason.clone(),
                        risk_tier: judge::classify_risk(&canonical).to_string(),
                        hint: "this action is explicitly forbidden".to_string(),
                    });
                    self.state.record_decision(&canonical, "deny", "forbid");
                    return Verdict::Deny { reason };
                }

                // No explicit forbid, just no matching permit
                if !self.implicit_ask {
                    self.state.record_denial(DenialInfo {
                        action: canonical.clone(),
                        reason: reason.clone(),
                        risk_tier: judge::classify_risk(&canonical).to_string(),
                        hint: format!("ask allow \"{}\"", canonical),
                    });
                    self.state.record_decision(&canonical, "deny", "default");
                    return Verdict::Deny { reason };
                }

                // Consult the judge — block_in_place bridges sync trait to async judge
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(self.consult_judge(&canonical))
                })
            }
        }
    }
}

/// MITM proxy configuration.
pub struct MitmProxy {
    pub ca: Arc<SessionCA>,
    pub audit: Arc<AuditLog>,
    pub port: u16,
    pub decider: Arc<dyn DecisionMaker>,
}

/// Shared counter for proxy decisions.
#[derive(Clone, Default)]
pub struct ProxyStats {
    pub total_decisions: Arc<AtomicU64>,
}

impl ProxyStats {
    pub fn total(&self) -> u64 {
        self.total_decisions.load(Ordering::Relaxed)
    }
}

impl MitmProxy {
    /// Start the proxy, listening on the configured port.
    /// Returns the actual port, a join handle, and shared stats for decision counts.
    pub async fn start(self) -> anyhow::Result<(u16, tokio::task::JoinHandle<()>, ProxyStats)> {
        let listener = TcpListener::bind(("127.0.0.1", self.port)).await?;
        let actual_port = listener.local_addr()?.port();
        let ca = self.ca;
        let audit = self.audit;
        let decider = self.decider;
        let stats = ProxyStats::default();

        let handle = {
            let stats = stats.clone();
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, _addr)) => {
                            let ca = ca.clone();
                            let audit = audit.clone();
                            let decider = decider.clone();
                            let stats = stats.clone();
                            tokio::spawn(async move {
                                if let Err(e) =
                                    handle_client(stream, ca, audit, decider, &stats).await
                                {
                                    tracing::debug!("client connection error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!("accept error: {}", e);
                        }
                    }
                }
            })
        };

        Ok((actual_port, handle, stats))
    }
}

/// Handle a single client connection. Expects an HTTP CONNECT request.
async fn handle_client(
    mut stream: TcpStream,
    ca: Arc<SessionCA>,
    audit: Arc<AuditLog>,
    decider: Arc<dyn DecisionMaker>,
    stats: &ProxyStats,
) -> anyhow::Result<()> {
    let mut buf_reader = BufReader::new(&mut stream);

    // Read the CONNECT request line
    let mut request_line = String::new();
    buf_reader.read_line(&mut request_line).await?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 || parts[0] != "CONNECT" {
        // Not a CONNECT request — send 400 and close
        let response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        buf_reader.get_mut().write_all(response.as_bytes()).await?;
        return Ok(());
    }

    let target = parts[1]; // host:port
    let hostname = target.split(':').next().unwrap_or(target).to_string();

    // Read and discard remaining headers until empty line
    loop {
        let mut line = String::new();
        buf_reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
    }

    // Send 200 Connection Established
    let response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    buf_reader.get_mut().write_all(response.as_bytes()).await?;

    // Drop the BufReader to get the stream back (no buffered data at this point)
    drop(buf_reader);

    // Now do TLS handshake with the client using our session CA leaf cert.
    // We generate the cert for the CONNECT hostname and configure rustls to
    // verify that the client's SNI matches. If a malicious client sends
    // CONNECT good.com but SNI evil.com, the handshake will fail because
    // the cert CN/SAN won't match the SNI.
    let leaf = ca.generate_leaf_cert(&hostname)?;

    let leaf_cert = rustls_pemfile::certs(&mut Cursor::new(leaf.cert_pem.as_bytes()))
        .next()
        .ok_or_else(|| anyhow::anyhow!("no cert in PEM"))??;
    let ca_cert = rustls_pemfile::certs(&mut Cursor::new(ca.ca_pem().as_bytes()))
        .next()
        .ok_or_else(|| anyhow::anyhow!("no CA cert in PEM"))??;
    let cert_chain = vec![leaf_cert, ca_cert];
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.key_der.clone()));

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)?;

    // Only advertise HTTP/1.1 — we don't support HTTP/2 MITM
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let client_tls = acceptor.accept(stream).await?;

    // Validate that TLS SNI matches the CONNECT target hostname.
    // Prevents a malicious client from CONNECTing to allowed-host.com
    // but sending SNI for a different domain.
    if let Some(sni) = client_tls.get_ref().1.server_name()
        && sni != hostname
    {
        tracing::warn!(
            connect_host = %hostname,
            sni = %sni,
            "SNI mismatch — rejecting connection"
        );
        anyhow::bail!("SNI '{}' does not match CONNECT target '{}'", sni, hostname);
    }

    let mut client_tls = client_tls;

    // Loop to handle HTTP/1.1 keepalive — multiple requests per connection
    loop {
        // Read the HTTP request from the decrypted stream
        let mut header_buf = BufReader::new(&mut client_tls);
        let mut request_line = String::new();
        match header_buf.read_line(&mut request_line).await {
            Ok(0) => break, // Connection closed
            Ok(_) => {}
            Err(_) => break,
        }

        let req_parts: Vec<&str> = request_line.split_whitespace().collect();
        if req_parts.len() < 2 {
            break;
        }
        let method = req_parts[0].to_string();
        let path = req_parts[1].to_string();

        // Read headers
        let mut headers = HashMap::new();
        let mut content_length: usize = 0;
        loop {
            let mut line = String::new();
            header_buf.read_line(&mut line).await?;
            if line.trim().is_empty() {
                break;
            }
            if let Some((key, value)) = line.trim().split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim().to_string();
                if key == "content-length" {
                    content_length = value.parse().unwrap_or(0);
                }
                headers.insert(key, value);
            }
        }

        // Read body if present
        let body = if content_length > 0 {
            let mut buf = vec![0u8; content_length];
            header_buf.read_exact(&mut buf).await?;
            Some(buf)
        } else {
            None
        };

        // Parse query params from path
        let (clean_path, query_params) = parse_query_string(&path);

        // Parse the action
        let req_info = RequestInfo {
            method: method.clone(),
            host: hostname.clone(),
            path: clean_path.clone(),
            headers: headers.clone(),
            query_params,
        };
        let action = parser::parse_action(&req_info);

        // Evaluate decision
        let verdict = decider.evaluate(&action);
        stats.total_decisions.fetch_add(1, Ordering::Relaxed);

        let (result_str, reason) = match &verdict {
            Verdict::Allow => ("allow".to_string(), None),
            Verdict::Deny { reason } => (format!("deny: {}", reason), Some(reason.clone())),
        };

        let _ = audit.log(AuditPayload::Decision {
            action: action.canonical(),
            result: result_str,
            decided_by: "decider".into(),
            reason,
            latency_ms: 0,
            request: RequestMeta {
                method: method.clone(),
                host: hostname.clone(),
                path: clean_path,
            },
        });

        // On deny: return 403 JSON with X-ClosedShell-Denied header
        if let Verdict::Deny { reason } = &verdict {
            let risk_tier = judge::classify_risk(&action.canonical());
            let deny_body = serde_json::json!({
                "error": "denied",
                "action": action.canonical(),
                "reason": reason,
                "risk_tier": risk_tier,
                "hint": "ask plan \"describe your goal\""
            });
            let body = serde_json::to_string(&deny_body).unwrap_or_default();
            let response = format!(
                "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nX-ClosedShell-Denied: true\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
                body.len(),
                body
            );
            drop(header_buf);
            client_tls.write_all(response.as_bytes()).await?;
            client_tls.flush().await?;
            continue;
        }

        // Connect to upstream
        let upstream_addr = format!("{}:443", hostname);
        let upstream_tcp = TcpStream::connect(&upstream_addr).await?;

        // TLS to upstream using system trust store
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let upstream_tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(upstream_tls_config));
        let server_name = rustls::pki_types::ServerName::try_from(hostname.clone())?;
        let mut upstream_tls = connector.connect(server_name, upstream_tcp).await?;

        // Reconstruct and send the request upstream
        let mut raw_request = format!("{}\r\n", request_line.trim());
        for (k, v) in &headers {
            raw_request.push_str(&format!("{}: {}\r\n", k, v));
        }
        raw_request.push_str("\r\n");
        upstream_tls.write_all(raw_request.as_bytes()).await?;
        if let Some(ref b) = body {
            upstream_tls.write_all(b).await?;
        }
        upstream_tls.flush().await?;

        // Read the full response from upstream and relay to client
        // We need to parse the response to know when it ends (for keepalive)
        let mut resp_reader = BufReader::new(&mut upstream_tls);
        let mut status_line = String::new();
        resp_reader.read_line(&mut status_line).await?;

        let mut resp_headers_raw = String::new();
        let mut resp_content_length: Option<usize> = None;
        let mut chunked = false;
        loop {
            let mut line = String::new();
            resp_reader.read_line(&mut line).await?;
            if line.trim().is_empty() {
                break;
            }
            if let Some((k, v)) = line.trim().split_once(':') {
                let k = k.trim().to_lowercase();
                let v = v.trim();
                if k == "content-length" {
                    resp_content_length = v.parse().ok();
                }
                if k == "transfer-encoding" && v.to_lowercase().contains("chunked") {
                    chunked = true;
                }
            }
            resp_headers_raw.push_str(&line);
        }

        // Send status line + headers to client
        // Drop the inner BufReader to get client_tls back
        drop(header_buf);
        client_tls.write_all(status_line.as_bytes()).await?;
        client_tls.write_all(resp_headers_raw.as_bytes()).await?;
        client_tls.write_all(b"\r\n").await?;

        // Relay body
        if let Some(len) = resp_content_length {
            let mut remaining = len;
            let mut buf = vec![0u8; 8192];
            while remaining > 0 {
                let to_read = remaining.min(buf.len());
                let n = resp_reader.read(&mut buf[..to_read]).await?;
                if n == 0 {
                    break;
                }
                client_tls.write_all(&buf[..n]).await?;
                remaining -= n;
            }
        } else if chunked {
            // Relay chunked encoding as-is
            loop {
                let mut chunk_header = String::new();
                resp_reader.read_line(&mut chunk_header).await?;
                client_tls.write_all(chunk_header.as_bytes()).await?;
                let size = usize::from_str_radix(chunk_header.trim(), 16).unwrap_or(0);
                if size == 0 {
                    // Read and relay trailing \r\n
                    let mut trailer = String::new();
                    resp_reader.read_line(&mut trailer).await?;
                    client_tls.write_all(trailer.as_bytes()).await?;
                    break;
                }
                let mut remaining = size;
                let mut buf = vec![0u8; 8192];
                while remaining > 0 {
                    let to_read = remaining.min(buf.len());
                    let n = resp_reader.read(&mut buf[..to_read]).await?;
                    if n == 0 {
                        break;
                    }
                    client_tls.write_all(&buf[..n]).await?;
                    remaining -= n;
                }
                // Read trailing \r\n after chunk data
                let mut crlf = [0u8; 2];
                resp_reader.read_exact(&mut crlf).await?;
                client_tls.write_all(&crlf).await?;
            }
        } else {
            // No content-length, not chunked — read until EOF (connection close)
            let mut buf = vec![0u8; 8192];
            loop {
                let n = resp_reader.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                client_tls.write_all(&buf[..n]).await?;
            }
            // Connection-close semantics — can't keepalive
            break;
        }

        client_tls.flush().await?;
        drop(resp_reader);
        // Loop continues for next request on same connection (keepalive)
    }

    Ok(())
}

/// Parse query string from a path. Returns (path, params).
fn parse_query_string(path: &str) -> (String, HashMap<String, String>) {
    let mut params = HashMap::new();
    if let Some((p, q)) = path.split_once('?') {
        for pair in q.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                params.insert(k.to_string(), v.to_string());
            }
        }
        (p.to_string(), params)
    } else {
        (path.to_string(), params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditLog;
    use crate::tls::SessionCA;

    #[test]
    fn test_parse_query_string_empty() {
        let (path, params) = parse_query_string("/foo/bar");
        assert_eq!(path, "/foo/bar");
        assert!(params.is_empty());
    }

    #[test]
    fn test_parse_query_string_with_params() {
        let (path, params) = parse_query_string("/foo?Action=List&Key=value");
        assert_eq!(path, "/foo");
        assert_eq!(params.get("Action").unwrap(), "List");
        assert_eq!(params.get("Key").unwrap(), "value");
    }

    #[tokio::test]
    async fn test_proxy_binds_and_accepts() {
        let ca = Arc::new(SessionCA::new().unwrap());
        let dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(dir.path(), "test-proxy").unwrap());

        let proxy = MitmProxy {
            ca,
            audit,
            port: 0, // OS-assigned port
            decider: Arc::new(YoloDecider),
        };

        let (port, handle, _stats) = proxy.start().await.unwrap();
        assert!(port > 0);

        // Verify we can connect
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        drop(stream);

        handle.abort();
    }

    #[tokio::test]
    async fn test_proxy_rejects_non_connect() {
        let ca = Arc::new(SessionCA::new().unwrap());
        let dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(dir.path(), "test-proxy").unwrap());

        let proxy = MitmProxy {
            ca,
            audit,
            port: 0,
            decider: Arc::new(YoloDecider),
        };

        let (port, handle, _stats) = proxy.start().await.unwrap();

        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();

        let mut response = vec![0u8; 1024];
        let n = stream.read(&mut response).await.unwrap();
        let response_str = String::from_utf8_lossy(&response[..n]);
        assert!(response_str.contains("400 Bad Request"));

        handle.abort();
    }

    #[tokio::test]
    async fn test_proxy_connect_handshake() {
        let ca = Arc::new(SessionCA::new().unwrap());
        let dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(dir.path(), "test-proxy").unwrap());

        let proxy = MitmProxy {
            ca,
            audit,
            port: 0,
            decider: Arc::new(YoloDecider),
        };

        let (port, handle, _stats) = proxy.start().await.unwrap();

        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();

        let mut response = vec![0u8; 1024];
        let n = stream.read(&mut response).await.unwrap();
        let response_str = String::from_utf8_lossy(&response[..n]);
        assert!(response_str.contains("200 Connection Established"));

        handle.abort();
    }
}
