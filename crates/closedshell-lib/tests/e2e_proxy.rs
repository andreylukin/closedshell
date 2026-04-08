mod helpers;

use closedshell_lib::proxy::YoloDecider;
use helpers::{DenyContaining, TestProxy};
use std::sync::Arc;

/// Denied request returns HTTP 403 with reason in body and audit logs "deny".
#[tokio::test]
async fn test_deny_returns_403() {
    let tp = TestProxy::start(Arc::new(DenyContaining("example.com".into()))).await;
    let client = tp.client();

    let resp = client
        .get("https://example.com/test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let body = resp.text().await.unwrap();
    assert!(body.contains("denied"));

    let decisions = tp.read_decisions();
    assert_eq!(decisions.len(), 1);
    assert!(decisions[0]["result"]
        .as_str()
        .unwrap()
        .contains("deny"));
    assert_eq!(decisions[0]["action"], "net:GET:example.com/test");
}

/// AWS S3 action is parsed correctly through the full proxy pipeline.
#[tokio::test]
async fn test_aws_action_parsing_e2e() {
    let tp = TestProxy::start(Arc::new(DenyContaining("aws".into()))).await;
    let client = tp.client();

    let resp = client
        .get("https://s3.amazonaws.com/")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let decisions = tp.read_decisions();
    assert_eq!(decisions.len(), 1);
    assert_eq!(
        decisions[0]["action"],
        "aws[profile=default]:s3:ListBuckets"
    );
}

/// GCP compute action is parsed correctly.
#[tokio::test]
async fn test_gcp_action_parsing_e2e() {
    let tp = TestProxy::start(Arc::new(DenyContaining("gcp".into()))).await;
    let client = tp.client();

    let resp = client
        .get("https://compute.googleapis.com/compute/v1/projects/my-proj/zones/us-central1-a/instances/i-123")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let decisions = tp.read_decisions();
    assert_eq!(decisions.len(), 1);
    let action = decisions[0]["action"].as_str().unwrap();
    assert!(action.starts_with("gcp[project=my-proj]:compute:"));
}

/// GitHub API action is parsed correctly.
#[tokio::test]
async fn test_github_action_parsing_e2e() {
    let tp = TestProxy::start(Arc::new(DenyContaining("gh".into()))).await;
    let client = tp.client();

    let resp = client
        .get("https://api.github.com/repos/anthropics/claude-code")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let decisions = tp.read_decisions();
    assert_eq!(decisions.len(), 1);
    let action = decisions[0]["action"].as_str().unwrap();
    assert!(action.starts_with("gh:"));
}

/// Generic net action for unknown hosts.
#[tokio::test]
async fn test_generic_action_parsing_e2e() {
    let tp = TestProxy::start(Arc::new(DenyContaining("net".into()))).await;
    let client = tp.client();

    let resp = client
        .get("https://httpbin.org/get")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let decisions = tp.read_decisions();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0]["action"], "net:GET:httpbin.org/get");
}

/// Multiple requests on one connection produce separate audit entries.
#[tokio::test]
async fn test_keepalive_multiple_decisions() {
    let tp = TestProxy::start(Arc::new(DenyContaining("net".into()))).await;
    let client = tp.client();

    for path in &["/a", "/b", "/c"] {
        let _ = client
            .get(format!("https://example.com{}", path))
            .send()
            .await;
    }

    let decisions = tp.read_decisions();
    assert_eq!(decisions.len(), 3);
    assert_eq!(decisions[0]["request"]["path"], "/a");
    assert_eq!(decisions[1]["request"]["path"], "/b");
    assert_eq!(decisions[2]["request"]["path"], "/c");
}

/// Mix of allowed and denied requests: only matching actions are denied.
#[tokio::test]
async fn test_selective_deny() {
    // Deny only requests to amazonaws.com
    let tp = TestProxy::start(Arc::new(DenyContaining("aws".into()))).await;
    let client = tp.client();

    // This should be allowed (not aws) — will fail at upstream connect, but audit logs "allow"
    let _ = client.get("https://example.com/ok").send().await;

    // This should be denied (matches "aws")
    let resp = client
        .get("https://s3.amazonaws.com/")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let decisions = tp.read_decisions();
    assert_eq!(decisions.len(), 2);
    assert!(decisions[0]["result"]
        .as_str()
        .unwrap()
        .contains("allow"));
    assert!(decisions[1]["result"]
        .as_str()
        .unwrap()
        .contains("deny"));
}

/// Stats counter tracks total decisions.
#[tokio::test]
async fn test_stats_counter() {
    let tp = TestProxy::start(Arc::new(DenyContaining("net".into()))).await;
    let client = tp.client();

    let _ = client.get("https://example.com/1").send().await;
    let _ = client.get("https://example.com/2").send().await;

    // Small yield to let async tasks complete
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(tp.stats.total(), 2);
}

/// YoloDecider allows all requests (audit logs "allow").
#[tokio::test]
async fn test_yolo_allows_all() {
    let tp = TestProxy::start(Arc::new(YoloDecider)).await;
    let client = tp.client();

    // Will try upstream (may fail), but audit should log "allow"
    let _ = client.get("https://example.com/yolo").send().await;

    let decisions = tp.read_decisions();
    assert_eq!(decisions.len(), 1);
    assert!(decisions[0]["result"]
        .as_str()
        .unwrap()
        .contains("allow"));
    assert_eq!(decisions[0]["action"], "net:GET:example.com/yolo");
}
