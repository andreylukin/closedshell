use closedshell_lib::audit::AuditLog;
use closedshell_lib::parser::Action;
use closedshell_lib::proxy::{DecisionMaker, MitmProxy, ProxyStats, Verdict};
use closedshell_lib::tls::SessionCA;

use std::path::PathBuf;
use std::sync::Arc;
use tokio::task::JoinHandle;

/// A test proxy instance with helpers for making requests and reading audit logs.
pub struct TestProxy {
    pub port: u16,
    pub ca: Arc<SessionCA>,
    #[allow(dead_code)]
    pub audit: Arc<AuditLog>,
    pub stats: ProxyStats,
    pub log_path: PathBuf,
    handle: JoinHandle<()>,
    _tmpdir: tempfile::TempDir,
}

impl TestProxy {
    /// Start a proxy with the given decider on an OS-assigned port.
    pub async fn start(decider: Arc<dyn DecisionMaker>) -> Self {
        // Install rustls crypto provider (no-op if already installed)
        let _ = rustls::crypto::ring::default_provider().install_default();

        let ca = Arc::new(SessionCA::new().unwrap());
        let tmpdir = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::open(tmpdir.path(), "test-e2e").unwrap());
        let log_path = tmpdir.path().join("closedshell-test-e2e.log");

        let proxy = MitmProxy {
            ca: ca.clone(),
            audit: audit.clone(),
            port: 0,
            decider,
        };

        let (port, handle, stats) = proxy.start().await.unwrap();

        Self {
            port,
            ca,
            audit,
            stats,
            log_path,
            handle,
            _tmpdir: tmpdir,
        }
    }

    /// Build a reqwest client that trusts this proxy's session CA and routes
    /// all HTTPS traffic through the proxy.
    pub fn client(&self) -> reqwest::Client {
        let ca_cert = reqwest::Certificate::from_pem(self.ca.ca_pem().as_bytes()).unwrap();

        reqwest::Client::builder()
            .proxy(reqwest::Proxy::https(format!("http://127.0.0.1:{}", self.port)).unwrap())
            .add_root_certificate(ca_cert)
            .http1_only()
            .build()
            .unwrap()
    }

    /// Read all Decision events from the audit log as JSON values.
    pub fn read_decisions(&self) -> Vec<serde_json::Value> {
        let contents = std::fs::read_to_string(&self.log_path).unwrap_or_default();
        contents
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|v| v["event"] == "decision")
            .collect()
    }
}

impl Drop for TestProxy {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Mock decider: denies any action whose canonical string contains the substring.
pub struct DenyContaining(pub String);

impl DecisionMaker for DenyContaining {
    fn evaluate(&self, action: &Action) -> Verdict {
        if action.canonical().contains(&self.0) {
            Verdict::Deny {
                reason: format!("blocked: {}", self.0),
            }
        } else {
            Verdict::Allow
        }
    }
}
