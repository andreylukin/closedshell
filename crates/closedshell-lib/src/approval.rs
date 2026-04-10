//! Human approval queue.
//!
//! When the judge returns `escalate_human`, the proxy parks the request here
//! and waits on a oneshot channel. The TUI (or webhook) resolves pending
//! approvals, unblocking the proxy.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::oneshot;

/// A pending approval visible to the TUI.
#[derive(Debug, Clone)]
pub struct PendingApproval {
    pub id: String,
    pub action: String,
    pub risk_tier: String,
    pub plan_id: Option<String>,
    pub created_at: Instant,
    pub created_at_rfc3339: String,
}

/// The human's verdict.
#[derive(Debug, Clone, PartialEq)]
pub enum ApprovalVerdict {
    Approved,
    Denied { reason: String },
}

struct PendingEntry {
    info: PendingApproval,
    tx: oneshot::Sender<ApprovalVerdict>,
}

/// Thread-safe queue of actions awaiting human approval.
pub struct ApprovalQueue {
    pending: Mutex<HashMap<String, PendingEntry>>,
    counter: AtomicU64,
}

impl Default for ApprovalQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl ApprovalQueue {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            counter: AtomicU64::new(0),
        }
    }

    /// Enqueue an action for human review. Returns the approval ID and a
    /// receiver the caller `.await`s until the human responds.
    pub fn enqueue(
        &self,
        action: String,
        risk_tier: String,
        plan_id: Option<String>,
    ) -> (String, oneshot::Receiver<ApprovalVerdict>) {
        let seq = self.counter.fetch_add(1, Ordering::Relaxed);
        let id = format!("approval-{}", seq);
        let (tx, rx) = oneshot::channel();
        let entry = PendingEntry {
            info: PendingApproval {
                id: id.clone(),
                action,
                risk_tier,
                plan_id,
                created_at: Instant::now(),
                created_at_rfc3339: chrono::Utc::now().to_rfc3339(),
            },
            tx,
        };
        self.pending.lock().unwrap().insert(id.clone(), entry);
        (id, rx)
    }

    /// Snapshot of all pending approvals (for TUI display).
    pub fn list_pending(&self) -> Vec<PendingApproval> {
        let pending = self.pending.lock().unwrap();
        let mut items: Vec<PendingApproval> = pending.values().map(|e| e.info.clone()).collect();
        items.sort_by_key(|p| p.created_at);
        items
    }

    /// Resolve a pending approval. Sends the verdict on the oneshot channel,
    /// unblocking the parked proxy request. Returns the approval info.
    pub fn resolve(&self, id: &str, verdict: ApprovalVerdict) -> anyhow::Result<PendingApproval> {
        let entry = self
            .pending
            .lock()
            .unwrap()
            .remove(id)
            .ok_or_else(|| anyhow::anyhow!("no pending approval: {}", id))?;
        let info = entry.info;
        // Receiver may have been dropped (proxy timed out). That's fine.
        let _ = entry.tx.send(verdict);
        Ok(info)
    }

    /// Auto-deny approvals older than `timeout`. Returns expired IDs.
    pub fn expire(&self, timeout: Duration) -> Vec<String> {
        let mut pending = self.pending.lock().unwrap();
        let now = Instant::now();
        let expired: Vec<String> = pending
            .iter()
            .filter(|(_, e)| now.duration_since(e.info.created_at) > timeout)
            .map(|(id, _)| id.clone())
            .collect();
        for id in &expired {
            if let Some(entry) = pending.remove(id) {
                let _ = entry.tx.send(ApprovalVerdict::Denied {
                    reason: "approval timed out".into(),
                });
            }
        }
        expired
    }

    pub fn count(&self) -> usize {
        self.pending.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn enqueue_and_resolve() {
        let queue = ApprovalQueue::new();
        let (id, rx) = queue.enqueue("aws:s3:DeleteBucket".into(), "dangerous".into(), None);

        assert_eq!(queue.count(), 1);
        assert_eq!(queue.list_pending().len(), 1);
        assert_eq!(queue.list_pending()[0].action, "aws:s3:DeleteBucket");

        queue.resolve(&id, ApprovalVerdict::Approved).unwrap();
        assert_eq!(queue.count(), 0);

        let verdict = rx.await.unwrap();
        assert_eq!(verdict, ApprovalVerdict::Approved);
    }

    #[tokio::test]
    async fn resolve_nonexistent_fails() {
        let queue = ApprovalQueue::new();
        assert!(queue.resolve("bogus", ApprovalVerdict::Approved).is_err());
    }

    #[tokio::test]
    async fn expire_removes_old() {
        let queue = ApprovalQueue::new();
        let (_id, _rx) = queue.enqueue("action".into(), "safe".into(), None);
        assert_eq!(queue.count(), 1);

        // With zero timeout, everything expires immediately
        let expired = queue.expire(Duration::from_secs(0));
        assert_eq!(expired.len(), 1);
        assert_eq!(queue.count(), 0);
    }

    #[tokio::test]
    async fn deny_verdict_delivered() {
        let queue = ApprovalQueue::new();
        let (id, rx) = queue.enqueue("action".into(), "moderate".into(), Some("plan-1".into()));

        queue
            .resolve(
                &id,
                ApprovalVerdict::Denied {
                    reason: "nope".into(),
                },
            )
            .unwrap();

        let verdict = rx.await.unwrap();
        assert_eq!(
            verdict,
            ApprovalVerdict::Denied {
                reason: "nope".into()
            }
        );
    }
}
