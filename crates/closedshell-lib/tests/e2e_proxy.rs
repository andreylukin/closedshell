mod helpers;

use closedshell_lib::proxy::{PatternDecider, YoloDecider};
use helpers::{DenyContaining, LargeDenyDecider, TestProxy};
use std::sync::Arc;

/// Denied request returns HTTP 403 with reason in body and audit logs "deny".
#[tokio::test]
async fn test_deny_returns_403() {
    let tp = TestProxy::start(Arc::new(DenyContaining("example.com".into()))).await;
    let client = tp.client();

    let resp = client.get("https://example.com/test").send().await.unwrap();
    assert_eq!(resp.status(), 403);

    let body = resp.text().await.unwrap();
    assert!(body.contains("denied"));

    let decisions = tp.read_decisions();
    assert_eq!(decisions.len(), 1);
    assert!(decisions[0]["result"].as_str().unwrap().contains("deny"));
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

    let resp = client.get("https://httpbin.org/get").send().await.unwrap();
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
    assert!(decisions[0]["result"].as_str().unwrap().contains("allow"));
    assert!(decisions[1]["result"].as_str().unwrap().contains("deny"));
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
    assert!(decisions[0]["result"].as_str().unwrap().contains("allow"));
    assert_eq!(decisions[0]["action"], "net:GET:example.com/yolo");
}

/// Requests to different hosts get correct provider-specific action parsing.
#[tokio::test]
async fn test_multiple_hosts_same_connection_strategy() {
    // Deny everything so we don't need upstream connectivity (every canonical action contains ":")
    let tp = TestProxy::start(Arc::new(DenyContaining(":".into()))).await;
    let client = tp.client();

    // AWS host
    let resp = client
        .get("https://s3.amazonaws.com/")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // GitHub host
    let resp = client
        .get("https://api.github.com/repos/owner/repo")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Generic unknown host
    let resp = client.get("https://httpbin.org/get").send().await.unwrap();
    assert_eq!(resp.status(), 403);

    let decisions = tp.read_decisions();
    assert_eq!(decisions.len(), 3);
    assert_eq!(
        decisions[0]["action"],
        "aws[profile=default]:s3:ListBuckets"
    );
    assert!(decisions[1]["action"].as_str().unwrap().starts_with("gh:"));
    assert_eq!(decisions[2]["action"], "net:GET:httpbin.org/get");
}

/// Proxy relays a large response body (>64KB) without truncation.
/// Uses a custom decider that generates a deny reason >64KB, resulting in a large 403 body.
#[tokio::test]
async fn test_large_response_body() {
    let reason_size = 100_000; // >64KB
    let tp = TestProxy::start(Arc::new(LargeDenyDecider { reason_size })).await;
    let client = tp.client();

    let resp = client
        .get("https://example.com/large")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let body = resp.text().await.unwrap();
    // Body format: "closedshell: denied — {reason}\n"
    assert!(
        body.len() > 64 * 1024,
        "expected body > 64KB, got {} bytes",
        body.len()
    );
    // Verify the reason wasn't truncated
    assert!(body.contains(&"x".repeat(1000)));
}

/// Multiple concurrent requests through the same proxy all get correct responses.
#[tokio::test]
async fn test_concurrent_requests() {
    let tp = TestProxy::start(Arc::new(DenyContaining("net".into()))).await;
    let client = tp.client();

    let mut handles = Vec::new();
    for i in 0..10 {
        let c = client.clone();
        handles.push(tokio::spawn(async move {
            let resp = c
                .get(format!("https://example.com/{}", i))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 403);
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let decisions = tp.read_decisions();
    assert_eq!(decisions.len(), 10);
    assert_eq!(tp.stats.total(), 10);
}

/// POST request with JSON body is correctly parsed as a net:POST action.
#[tokio::test]
async fn test_post_with_body() {
    let tp = TestProxy::start(Arc::new(DenyContaining("net".into()))).await;
    let client = tp.client();

    let json_body = serde_json::json!({"key": "value", "numbers": [1, 2, 3]});
    let resp = client
        .post("https://httpbin.org/post")
        .json(&json_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let decisions = tp.read_decisions();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0]["action"], "net:POST:httpbin.org/post");
    assert_eq!(decisions[0]["request"]["method"], "POST");
    assert_eq!(decisions[0]["request"]["host"], "httpbin.org");
    assert_eq!(decisions[0]["request"]["path"], "/post");
}

/// PatternDecider allows some patterns and denies others.
#[tokio::test]
async fn test_custom_decider_with_mixed_rules() {
    let decider = PatternDecider {
        allow_patterns: vec!["net:GET:example.com*".into()],
    };
    let tp = TestProxy::start(Arc::new(decider)).await;
    let client = tp.client();

    // Should be allowed (matches pattern) — will fail at upstream, but audit logs "allow"
    let _ = client.get("https://example.com/ok").send().await;

    // Should be denied (AWS action doesn't match the net:GET pattern)
    let resp = client
        .get("https://s3.amazonaws.com/")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Should be denied (different host)
    let resp = client.get("https://httpbin.org/get").send().await.unwrap();
    assert_eq!(resp.status(), 403);

    let decisions = tp.read_decisions();
    assert_eq!(decisions.len(), 3);
    assert!(decisions[0]["result"].as_str().unwrap().contains("allow"));
    assert!(decisions[1]["result"].as_str().unwrap().contains("deny"));
    assert!(decisions[2]["result"].as_str().unwrap().contains("deny"));
}

/// After several requests, audit log NDJSON entries have correct fields.
#[tokio::test]
async fn test_audit_log_entries() {
    let tp = TestProxy::start(Arc::new(DenyContaining("net".into()))).await;
    let client = tp.client();

    let _ = client.get("https://example.com/a").send().await;
    let _ = client.post("https://example.com/b").send().await;
    let _ = client.get("https://example.com/c").send().await;

    // Read raw NDJSON log file
    let contents = std::fs::read_to_string(&tp.log_path).unwrap();
    let entries: Vec<serde_json::Value> = contents
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();

    assert_eq!(entries.len(), 3);

    for entry in &entries {
        // Every entry must have these top-level fields
        assert!(entry["ts"].is_string(), "missing ts");
        assert!(entry["session"].is_string(), "missing session");
        assert_eq!(entry["event"], "decision");
        assert!(entry["action"].is_string(), "missing action");
        assert!(entry["result"].is_string(), "missing result");
        assert!(entry["decided_by"].is_string(), "missing decided_by");
        assert!(entry["latency_ms"].is_number(), "missing latency_ms");

        // Request sub-object
        assert!(entry["request"]["method"].is_string(), "missing method");
        assert!(entry["request"]["host"].is_string(), "missing host");
        assert!(entry["request"]["path"].is_string(), "missing path");
    }

    // Verify specific entries
    assert_eq!(entries[0]["request"]["path"], "/a");
    assert_eq!(entries[0]["request"]["method"], "GET");
    assert_eq!(entries[1]["request"]["path"], "/b");
    assert_eq!(entries[1]["request"]["method"], "POST");
    assert_eq!(entries[2]["request"]["path"], "/c");
    assert_eq!(entries[2]["request"]["method"], "GET");
}

/// Client connects, sends one request, then drops the connection. Proxy should not panic
/// and should continue serving other clients.
#[tokio::test]
async fn test_proxy_handles_connection_close_gracefully() {
    let tp = TestProxy::start(Arc::new(DenyContaining("net".into()))).await;

    // First client: make one request then drop
    {
        let client = tp.client();
        let resp = client
            .get("https://example.com/first")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
        // client is dropped here, closing the connection
    }

    // Small pause to let proxy handle the disconnection
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Second client: verify proxy still works
    {
        let client = tp.client();
        let resp = client
            .get("https://example.com/second")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
    }

    let decisions = tp.read_decisions();
    assert_eq!(decisions.len(), 2);
    assert_eq!(decisions[0]["request"]["path"], "/first");
    assert_eq!(decisions[1]["request"]["path"], "/second");
}

/// Request to a completely unknown host parses as net:METHOD:host/path.
#[tokio::test]
async fn test_unknown_host_action_parsing() {
    let tp = TestProxy::start(Arc::new(DenyContaining("net".into()))).await;
    let client = tp.client();

    let resp = client
        .get("https://my-custom-service.internal.corp/api/v2/widgets?limit=10")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let decisions = tp.read_decisions();
    assert_eq!(decisions.len(), 1);
    let action = decisions[0]["action"].as_str().unwrap();
    // Query params are stripped from path before action formatting
    assert_eq!(
        action,
        "net:GET:my-custom-service.internal.corp/api/v2/widgets"
    );
    assert_eq!(
        decisions[0]["request"]["host"],
        "my-custom-service.internal.corp"
    );
}

/// AWS request with Authorization header containing Credential= extracts profile qualifier.
#[tokio::test]
async fn test_aws_with_auth_header() {
    let tp = TestProxy::start(Arc::new(DenyContaining("aws".into()))).await;
    let client = tp.client();

    let resp = client
        .get("https://s3.amazonaws.com/my-bucket/key.txt")
        .header(
            "Authorization",
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc123",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let decisions = tp.read_decisions();
    assert_eq!(decisions.len(), 1);
    let action = decisions[0]["action"].as_str().unwrap();
    assert!(action.starts_with("aws[profile="));
    assert_eq!(action, "aws[profile=AKIAIOSFODNN7EXAMPLE]:s3:GetObject");
}

/// GET then POST on the same keepalive connection are independently parsed.
#[tokio::test]
async fn test_keepalive_with_different_methods() {
    let tp = TestProxy::start(Arc::new(DenyContaining("net".into()))).await;
    let client = tp.client();

    // GET request
    let resp = client
        .get("https://example.com/resource")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // POST request on same client (same keepalive connection)
    let resp = client
        .post("https://example.com/resource")
        .body("data=test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let decisions = tp.read_decisions();
    assert_eq!(decisions.len(), 2);
    assert_eq!(decisions[0]["action"], "net:GET:example.com/resource");
    assert_eq!(decisions[0]["request"]["method"], "GET");
    assert_eq!(decisions[1]["action"], "net:POST:example.com/resource");
    assert_eq!(decisions[1]["request"]["method"], "POST");
}
