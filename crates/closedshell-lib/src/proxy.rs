//! MITM proxy: intercepts HTTPS, parses actions, logs decisions.
//!
//! In YOLO mode: parse action, log as "allow (yolo)", forward to upstream.
//! No permission tree consulted, no judge.

use crate::audit::{AuditLog, AuditPayload, RequestMeta};
use crate::parser::{self, RequestInfo};
use crate::tls::SessionCA;

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering};
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
        let stats = ProxyStats::default();

        let handle = {
            let stats = stats.clone();
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, _addr)) => {
                            let ca = ca.clone();
                            let audit = audit.clone();
                            let stats = stats.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_client(stream, ca, audit, &stats).await {
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

    // Drop the BufReader to get the stream back (no buffered data at this point)
    drop(buf_reader);

    // Now do TLS handshake with the client using our session CA leaf cert
    let leaf = ca.generate_leaf_cert(&hostname)?;

    let cert_chain = vec![rustls_pemfile::certs(&mut Cursor::new(leaf.cert_pem.as_bytes()))
        .next()
        .ok_or_else(|| anyhow::anyhow!("no cert in PEM"))??];
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.key_der.clone()));

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)?;

    // Only advertise HTTP/1.1 — we don't support HTTP/2 MITM
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let mut client_tls = acceptor.accept(stream).await?;

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
            body_peek: None,
        };
        let action = parser::parse_action(&req_info);

        // Log decision (YOLO mode: always allow)
        stats.total_decisions.fetch_add(1, Ordering::Relaxed);
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
