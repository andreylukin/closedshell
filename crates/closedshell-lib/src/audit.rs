//! Audit logger: NDJSON file writer.
//!
//! One line per event. File: `~/.closedshell/logs/<encoded-cwd>/closedshell-<session-id>.log`

use chrono::Utc;
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub struct AuditLog {
    file: Mutex<File>,
    pub path: PathBuf,
    session_id: String,
}

#[derive(Debug, Serialize)]
pub struct AuditEvent {
    pub ts: String,
    pub session: String,
    #[serde(flatten)]
    pub payload: AuditPayload,
}

#[derive(Debug, Serialize)]
#[serde(tag = "event")]
#[serde(rename_all = "snake_case")]
pub enum AuditPayload {
    Decision {
        action: String,
        result: String,
        decided_by: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        latency_ms: u64,
        request: RequestMeta,
    },
    SessionStart {
        command: String,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        templates: Vec<String>,
        yolo: bool,
    },
    SessionEnd {
        duration_s: u64,
        total_decisions: u64,
        denied: u64,
    },
    HumanApproval {
        action: String,
        verdict: String,
        risk_tier: String,
        wait_ms: u64,
    },
}

#[derive(Debug, Serialize)]
pub struct RequestMeta {
    pub method: String,
    pub host: String,
    pub path: String,
}

impl AuditLog {
    pub fn open(dir: &Path, session_id: &str) -> anyhow::Result<Self> {
        let filename = format!("closedshell-{}.log", session_id);
        let path = dir.join(&filename);
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            file: Mutex::new(file),
            path,
            session_id: session_id.to_string(),
        })
    }

    pub fn log(&self, payload: AuditPayload) -> anyhow::Result<()> {
        let event = AuditEvent {
            ts: Utc::now().to_rfc3339(),
            session: self.session_id.clone(),
            payload,
        };
        let mut line = serde_json::to_string(&event)?;
        line.push('\n');

        let mut file = self.file.lock().unwrap();
        file.write_all(line.as_bytes())?;
        file.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_log_write_and_read() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::open(dir.path(), "test-001").unwrap();

        log.log(AuditPayload::SessionStart {
            command: "pi".into(),
            templates: vec!["aws-debug".into()],
            yolo: true,
        })
        .unwrap();

        log.log(AuditPayload::Decision {
            action: "net:GET:example.com/api".into(),
            result: "allow (yolo)".into(),
            decided_by: "yolo".into(),
            reason: None,
            latency_ms: 0,
            request: RequestMeta {
                method: "GET".into(),
                host: "example.com".into(),
                path: "/api".into(),
            },
        })
        .unwrap();

        // Read back and verify
        let contents = std::fs::read_to_string(&log.path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(
            lines.len(),
            2,
            "ERROR: expected 2 log lines, got {}",
            lines.len()
        );

        // Verify each line is valid JSON
        for (i, line) in lines.iter().enumerate() {
            let parsed: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("ERROR: line {} is not valid JSON: {}", i, e));
            assert_eq!(parsed["session"], "test-001");
        }

        // Verify first event is session_start
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["event"], "session_start");
        assert_eq!(first["command"], "pi");
        assert_eq!(first["yolo"], true);

        // Verify second event is decision
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["event"], "decision");
        assert_eq!(second["action"], "net:GET:example.com/api");
        assert_eq!(second["result"], "allow (yolo)");
    }

    #[test]
    fn test_audit_log_filename() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::open(dir.path(), "8f3a-29c1").unwrap();
        assert!(log.path.ends_with("closedshell-8f3a-29c1.log"));
    }
}
