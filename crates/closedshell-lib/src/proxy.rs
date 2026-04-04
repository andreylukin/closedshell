//! MITM proxy: intercepts HTTPS, parses actions, logs decisions.
//!
//! In YOLO mode: parse action, log as "allow (yolo)", forward to upstream.
//! No permission tree consulted, no judge.

// TODO: implement the MITM proxy
// - Accept CONNECT requests on localhost:<port>
// - TLS terminate using session CA + dynamic per-SNI certs (tls module)
// - Parse HTTP request into RequestInfo
// - Call parser::parse_action to get canonical action
// - Log decision via audit::AuditLog
// - Forward request to upstream (new TLS connection with system trust store)
// - Relay response back to client
// - Support streaming (chunked, SSE) and WebSocket upgrade
