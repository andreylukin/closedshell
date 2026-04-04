//! MITM proxy: intercepts HTTPS, parses actions, logs decisions.
//!
//! In YOLO mode: parse action, log as "allow (yolo)", forward to upstream.
//! No permission tree consulted, no judge.

use crate::audit::{AuditLog, AuditPayload, RequestMeta};
use crate::parser::{self, RequestInfo};
use crate::tls::SessionCA;

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

/// MITM proxy configuration.
pub struct MitmProxy {
    pub ca: Arc<SessionCA>,
    pub audit: Arc<AuditLog>,
    pub port: u16,
}

impl MitmProxy {
    /// Start the proxy, listening on the configured port.
    /// Returns the actual port bound to (useful if port was 0 for OS-assigned).
    pub async fn start(self) -> anyhow::Result<(u16, tokio::task::JoinHandle<()>)> {
        let listener = TcpListener::bind(("127.0.0.1", self.port)).await?;
        let actual_port = listener.local_addr()?.port();
        let ca = self.ca;
        let audit = self.audit;

        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        let ca = ca.clone();
                        let audit = audit.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, ca, audit).await {
                                tracing::debug!("client connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("accept error: {}", e);
                    }
                }
            }
        });

        Ok((actual_port, handle))
    }
}

/// Handle a single client connection. Expects an HTTP CONNECT request.
async fn handle_client(
    mut stream: TcpStream,
    ca: Arc<SessionCA>,
    audit: Arc<AuditLog>,
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
    let hostname = target
        .split(':')
        .next()
        .unwrap_or(target)
        .to_string();

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

    // Drop the BufReader to get the stream back
    drop(buf_reader);

    // Now do TLS handshake with the client using our session CA leaf cert
    let leaf = ca.generate_leaf_cert(&hostname)?;

    let cert_chain = vec![rustls_pemfile::certs(&mut Cursor::new(leaf.cert_pem.as_bytes()))
        .next()
        .ok_or_else(|| anyhow::anyhow!("no cert in PEM"))??];
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.key_der.clone()));

    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)?;

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let mut client_tls = acceptor.accept(stream).await?;

    // Read the actual HTTP request from the decrypted stream
    let mut header_buf = BufReader::new(&mut client_tls);
    let mut request_line = String::new();
    header_buf.read_line(&mut request_line).await?;

    let req_parts: Vec<&str> = request_line.split_whitespace().collect();
    if req_parts.len() < 2 {
        return Ok(());
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

    // Build the raw request to forward upstream
    // Reconstruct the request
    let mut raw_request = format!("{}\r\n", request_line.trim());
    for (k, v) in &headers {
        raw_request.push_str(&format!("{}: {}\r\n", k, v));
    }
    raw_request.push_str("\r\n");
    let mut raw_request_bytes = raw_request.into_bytes();

    // Read body if present
    if content_length > 0 {
        let mut body = vec![0u8; content_length];
        header_buf.read_exact(&mut body).await?;
        raw_request_bytes.extend_from_slice(&body);
    }

    // Parse query params from path
    let (clean_path, query_params) = parse_query_string(&path);

    // Parse the action
    let req_info = RequestInfo {
        method: method.clone(),
        host: hostname.clone(),
        path: clean_path.clone(),
        headers: headers.clone(),
        query_params,
        body_peek: None,
    };
    let action = parser::parse_action(&req_info);

    // Log decision (YOLO mode: always allow)
    let _ = audit.log(AuditPayload::Decision {
        action: action.canonical(),
        result: "allow (yolo)".into(),
        decided_by: "yolo".into(),
        reason: None,
        latency_ms: 0,
        request: RequestMeta {
            method: method.clone(),
            host: hostname.clone(),
            path: clean_path,
        },
    });

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

    // Send the request upstream
    upstream_tls.write_all(&raw_request_bytes).await?;
    upstream_tls.flush().await?;

    // Drop the BufReader wrapper before bidirectional copy
    drop(header_buf);

    // Relay the response back: bidirectional copy for keepalive/streaming
    let _ = tokio::io::copy_bidirectional(&mut client_tls, &mut upstream_tls).await;

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
        };

        let (port, handle) = proxy.start().await.unwrap();
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
        };

        let (port, handle) = proxy.start().await.unwrap();

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
        };

        let (port, handle) = proxy.start().await.unwrap();

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
