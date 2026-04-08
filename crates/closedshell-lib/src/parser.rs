//! Provider parsers: HTTP request → canonical action string.
//!
//! Format: provider[qualifier]:service:operation
//! Generic fallback: net:METHOD:host/path

use std::collections::HashMap;

/// A parsed canonical action.
#[derive(Debug, Clone, PartialEq)]
pub struct Action {
    pub provider: String,
    pub qualifier: HashMap<String, String>,
    pub service: String,
    pub operation: String,
    pub raw: String,
}

impl Action {
    /// Format as canonical action string: provider[key=val]:service:operation
    pub fn canonical(&self) -> String {
        self.raw.clone()
    }
}

/// Minimal HTTP request info needed for parsing.
#[derive(Debug, Clone)]
pub struct RequestInfo {
    pub method: String,
    pub host: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
    pub body_peek: Option<String>,
}

/// Parse an HTTP request into a canonical action.
pub fn parse_action(req: &RequestInfo) -> Action {
    if let Some(action) = try_parse_aws(req) {
        return action;
    }
    if let Some(action) = try_parse_gcp(req) {
        return action;
    }
    if let Some(action) = try_parse_github(req) {
        return action;
    }
    if let Some(action) = try_parse_k8s(req) {
        return action;
    }

    parse_generic(req)
}

fn parse_generic(req: &RequestInfo) -> Action {
    let raw = format!("net:{}:{}{}", req.method, req.host, req.path);
    Action {
        provider: "net".into(),
        qualifier: HashMap::new(),
        service: req.host.clone(),
        operation: req.method.clone(),
        raw,
    }
}

fn try_parse_aws(req: &RequestInfo) -> Option<Action> {
    if !req.host.ends_with(".amazonaws.com") {
        return None;
    }

    // Extract service from host. Examples:
    //   s3.amazonaws.com → s3
    //   s3.us-east-1.amazonaws.com → s3
    //   ec2.us-west-2.amazonaws.com → ec2
    //   ecs.amazonaws.com → ecs
    let service = req.host.split('.').next()?;

    let operation = if let Some(action) = req.query_params.get("Action") {
        action.clone()
    } else if let Some(target) = req.headers.get("x-amz-target") {
        // Format: ServiceName.OperationName
        target.split('.').next_back().unwrap_or(target).to_string()
    } else if service == "s3" {
        // S3 REST-style: map method + path to operation
        parse_s3_rest_operation(&req.method, &req.path)
    } else {
        format!("{}:{}", req.method, req.path)
    };

    let profile = extract_aws_profile(req);

    let raw = format!("aws[profile={}]:{}:{}", profile, service, operation);
    let mut qualifier = HashMap::new();
    qualifier.insert("profile".into(), profile);

    Some(Action {
        provider: "aws".into(),
        qualifier,
        service: service.into(),
        operation,
        raw,
    })
}

/// Map S3 REST method+path to a human-readable operation name.
/// Path format: / (list buckets), /bucket (bucket ops), /bucket/key (object ops)
fn parse_s3_rest_operation(method: &str, path: &str) -> String {
    let parts: Vec<&str> = path
        .trim_start_matches('/')
        .splitn(2, '/')
        .filter(|s| !s.is_empty())
        .collect();

    match (method, parts.len()) {
        ("GET", 0) => "ListBuckets".into(),
        ("GET", 1) => "ListObjects".into(),
        ("GET", 2) => "GetObject".into(),
        ("PUT", 1) => "CreateBucket".into(),
        ("PUT", _) => "PutObject".into(),
        ("DELETE", 1) => "DeleteBucket".into(),
        ("DELETE", _) => "DeleteObject".into(),
        ("HEAD", 1) => "HeadBucket".into(),
        ("HEAD", _) => "HeadObject".into(),
        ("POST", 1) => "PostObject".into(),
        _ => format!("{}:{}", method, path),
    }
}

fn extract_aws_profile(req: &RequestInfo) -> String {
    if let Some(auth) = req.headers.get("authorization")
        && auth.contains("Credential=")
    {
        return "default".into();
    }
    "default".into()
}

fn try_parse_gcp(req: &RequestInfo) -> Option<Action> {
    if !req.host.ends_with(".googleapis.com") {
        return None;
    }

    // Extract service from host: compute.googleapis.com → compute
    let service = req.host.strip_suffix(".googleapis.com")?;

    // GCP REST paths look like:
    // /compute/v1/projects/{project}/zones/{zone}/instances/{id}
    // /storage/v1/b/{bucket}/o/{object}
    let path_segments: Vec<&str> = req.path.trim_start_matches('/').split('/').collect();

    // Extract project from path if present
    let project = path_segments
        .iter()
        .zip(path_segments.iter().skip(1))
        .find(|(key, _)| **key == "projects")
        .map(|(_, val)| val.to_string())
        .unwrap_or_else(|| "unknown".into());

    // Build a dotted resource path from the path segments, skipping version and project info.
    // e.g., compute.instances.get from GET .../instances/{id}
    let operation = parse_gcp_operation(service, &req.method, &path_segments);

    let raw = format!("gcp[project={}]:{}:{}", project, service, operation);
    let mut qualifier = HashMap::new();
    qualifier.insert("project".into(), project);

    Some(Action {
        provider: "gcp".into(),
        qualifier,
        service: service.into(),
        operation,
        raw,
    })
}

/// Parse GCP REST path into a dotted operation string.
/// Strategy: take the last resource type from the path and combine with HTTP method.
fn parse_gcp_operation(service: &str, method: &str, segments: &[&str]) -> String {
    // Skip version prefix (e.g., "compute", "v1") and project/zone qualifiers
    // Look for known resource segments
    let skip_keys = ["projects", "zones", "regions", "locations", "global"];

    // Collect resource types (segments that aren't IDs or qualifier values)
    let mut resources = Vec::new();
    let mut i = 0;
    // Skip service name and version at the start
    while i < segments.len() {
        let seg = segments[i];
        if seg.starts_with('v') && seg[1..].chars().all(|c| c.is_ascii_digit()) {
            i += 1;
            continue; // skip version
        }
        if seg == service {
            i += 1;
            continue; // skip service name repeat
        }
        if skip_keys.contains(&seg) {
            i += 2; // skip key + value
            continue;
        }
        // This is either a resource type or an ID
        // Heuristic: resource types are alphabetic, IDs contain digits/hyphens
        if seg
            .chars()
            .all(|c| c.is_ascii_alphabetic() || c == '-' || c == '_')
            && !seg.is_empty()
        {
            resources.push(seg);
            i += 1;
        } else {
            // Skip IDs
            i += 1;
        }
    }

    let method_verb = match method {
        "GET" => "get",
        "POST" => "insert",
        "PUT" => "update",
        "PATCH" => "patch",
        "DELETE" => "delete",
        other => other,
    };

    if resources.is_empty() {
        return method_verb.to_string();
    }

    // Join resource types with dots and append method
    let resource_path = resources.join(".");
    format!("{}.{}", resource_path, method_verb)
}

/// Known Kubernetes resource types for detection heuristic.
const K8S_RESOURCES: &[&str] = &[
    "pods",
    "services",
    "deployments",
    "replicasets",
    "statefulsets",
    "daemonsets",
    "jobs",
    "cronjobs",
    "configmaps",
    "secrets",
    "nodes",
    "namespaces",
    "ingresses",
    "networkpolicies",
    "persistentvolumeclaims",
    "serviceaccounts",
    "roles",
    "rolebindings",
    "clusterroles",
    "clusterrolebindings",
];

fn try_parse_k8s(req: &RequestInfo) -> Option<Action> {
    // Detect K8s API paths
    if !req.path.starts_with("/api/") && !req.path.starts_with("/apis/") {
        return None;
    }

    // Split path, strip query string from last segment
    let path_no_query = req.path.split('?').next().unwrap_or(&req.path);
    let segments: Vec<&str> = path_no_query
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();

    // Find the resource type and optional name.
    // Patterns:
    //   /api/v1/namespaces/{ns}/{resource}[/{name}]
    //   /api/v1/{resource}[/{name}]
    //   /apis/{group}/{version}/namespaces/{ns}/{resource}[/{name}]
    //   /apis/{group}/{version}/{resource}[/{name}]
    let mut namespace: Option<String> = None;
    let mut resource: Option<&str> = None;
    let mut resource_name: Option<&str> = None;

    // Find "namespaces" segment to extract ns, then resource follows
    if let Some(ns_idx) = segments.iter().position(|&s| s == "namespaces") {
        if ns_idx + 1 < segments.len() {
            namespace = Some(segments[ns_idx + 1].to_string());
        }
        if ns_idx + 2 < segments.len() {
            resource = Some(segments[ns_idx + 2]);
        }
        if ns_idx + 3 < segments.len() {
            resource_name = Some(segments[ns_idx + 3]);
        }
    } else {
        // No namespace — cluster-scoped resource
        // /api/v1/{resource}[/{name}] or /apis/{group}/{version}/{resource}[/{name}]
        let start = if segments.first() == Some(&"apis") {
            3
        } else {
            2
        };
        if start < segments.len() {
            resource = Some(segments[start]);
        }
        if start + 1 < segments.len() {
            resource_name = Some(segments[start + 1]);
        }
    }

    let resource = resource?;

    // Require known K8s resource type to avoid false positives
    if !K8S_RESOURCES.contains(&resource) {
        return None;
    }

    // Map HTTP method to K8s verb
    let verb = if req.method == "GET" {
        if req.query_params.get("watch").map(|v| v.as_str()) == Some("true") {
            "watch"
        } else if resource_name.is_some() {
            "get"
        } else {
            "list"
        }
    } else {
        match req.method.as_str() {
            "POST" => "create",
            "PUT" => "update",
            "PATCH" => "patch",
            "DELETE" => "delete",
            other => other,
        }
    };

    let mut qualifier = HashMap::new();
    let raw = if let Some(ns) = &namespace {
        qualifier.insert("ns".into(), ns.clone());
        format!("k8s[ns={}]:{}:{}", ns, resource, verb)
    } else {
        format!("k8s:{}:{}", resource, verb)
    };

    Some(Action {
        provider: "k8s".into(),
        qualifier,
        service: resource.into(),
        operation: verb.into(),
        raw,
    })
}

fn try_parse_github(req: &RequestInfo) -> Option<Action> {
    if req.host != "api.github.com" {
        return None;
    }

    let path = req.path.trim_start_matches('/');
    let raw = format!("gh:{}:{}", path, req.method);

    Some(Action {
        provider: "gh".into(),
        qualifier: HashMap::new(),
        service: path.to_string(),
        operation: req.method.clone(),
        raw,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(method: &str, host: &str, path: &str) -> RequestInfo {
        RequestInfo {
            method: method.into(),
            host: host.into(),
            path: path.into(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
            body_peek: None,
        }
    }

    // -- Generic tests --

    #[test]
    fn test_generic_get() {
        let req = make_request("GET", "api.example.com", "/v1/data");
        let action = parse_action(&req);
        assert_eq!(action.canonical(), "net:GET:api.example.com/v1/data");
        assert_eq!(action.provider, "net");
    }

    #[test]
    fn test_generic_post() {
        let req = make_request("POST", "hooks.slack.com", "/services/T00/B00/xxx");
        let action = parse_action(&req);
        assert_eq!(
            action.canonical(),
            "net:POST:hooks.slack.com/services/T00/B00/xxx"
        );
    }

    // -- AWS tests --

    #[test]
    fn test_aws_query_action() {
        let mut req = make_request("POST", "ec2.amazonaws.com", "/");
        req.query_params
            .insert("Action".into(), "DescribeInstances".into());
        let action = parse_action(&req);
        assert_eq!(
            action.canonical(),
            "aws[profile=default]:ec2:DescribeInstances"
        );
        assert_eq!(action.provider, "aws");
        assert_eq!(action.service, "ec2");
        assert_eq!(action.operation, "DescribeInstances");
    }

    #[test]
    fn test_aws_regional_endpoint() {
        let mut req = make_request("POST", "ec2.us-west-2.amazonaws.com", "/");
        req.query_params
            .insert("Action".into(), "DescribeInstances".into());
        let action = parse_action(&req);
        assert_eq!(action.provider, "aws");
        assert_eq!(action.service, "ec2");
        assert_eq!(action.operation, "DescribeInstances");
    }

    #[test]
    fn test_aws_s3_host() {
        let mut req = make_request("GET", "s3.us-east-1.amazonaws.com", "/my-bucket");
        req.query_params
            .insert("Action".into(), "ListBuckets".into());
        let action = parse_action(&req);
        assert_eq!(action.provider, "aws");
        assert_eq!(action.service, "s3");
    }

    #[test]
    fn test_aws_target_header() {
        let mut req = make_request("POST", "ecs.amazonaws.com", "/");
        req.headers.insert(
            "x-amz-target".into(),
            "AmazonEC2ContainerServiceV20141113.UpdateService".into(),
        );
        let action = parse_action(&req);
        assert_eq!(action.provider, "aws");
        assert_eq!(action.operation, "UpdateService");
    }

    #[test]
    fn test_aws_s3_list_buckets() {
        let req = make_request("GET", "s3.amazonaws.com", "/");
        let action = parse_action(&req);
        assert_eq!(action.provider, "aws");
        assert_eq!(action.service, "s3");
        assert_eq!(action.operation, "ListBuckets");
    }

    #[test]
    fn test_aws_s3_list_objects() {
        let req = make_request("GET", "s3.amazonaws.com", "/my-bucket");
        let action = parse_action(&req);
        assert_eq!(action.operation, "ListObjects");
    }

    #[test]
    fn test_aws_s3_get_object() {
        let req = make_request("GET", "s3.amazonaws.com", "/my-bucket/some/key.txt");
        let action = parse_action(&req);
        assert_eq!(action.operation, "GetObject");
    }

    #[test]
    fn test_aws_s3_put_object() {
        let req = make_request("PUT", "s3.amazonaws.com", "/my-bucket/key.txt");
        let action = parse_action(&req);
        assert_eq!(action.operation, "PutObject");
    }

    #[test]
    fn test_aws_s3_delete_object() {
        let req = make_request("DELETE", "s3.amazonaws.com", "/my-bucket/key.txt");
        let action = parse_action(&req);
        assert_eq!(action.operation, "DeleteObject");
    }

    #[test]
    fn test_aws_s3_create_bucket() {
        let req = make_request("PUT", "s3.amazonaws.com", "/new-bucket");
        let action = parse_action(&req);
        assert_eq!(action.operation, "CreateBucket");
    }

    #[test]
    fn test_aws_s3_delete_bucket() {
        let req = make_request("DELETE", "s3.amazonaws.com", "/my-bucket");
        let action = parse_action(&req);
        assert_eq!(action.operation, "DeleteBucket");
    }

    #[test]
    fn test_non_aws_not_matched() {
        let req = make_request("GET", "example.com", "/api/v1");
        let action = parse_action(&req);
        assert_eq!(action.provider, "net");
    }

    // -- GCP tests --

    #[test]
    fn test_gcp_compute_instances_get() {
        let req = make_request(
            "GET",
            "compute.googleapis.com",
            "/compute/v1/projects/my-project/zones/us-central1-a/instances/my-instance",
        );
        let action = parse_action(&req);
        assert_eq!(action.provider, "gcp");
        assert_eq!(action.service, "compute");
        assert_eq!(action.qualifier.get("project").unwrap(), "my-project");
        assert!(action.operation.contains("instances"));
        assert!(action.operation.ends_with("get"));
    }

    #[test]
    fn test_gcp_compute_instances_delete() {
        let req = make_request(
            "DELETE",
            "compute.googleapis.com",
            "/compute/v1/projects/my-project/zones/us-central1-a/instances/i-123",
        );
        let action = parse_action(&req);
        assert_eq!(action.provider, "gcp");
        assert!(action.operation.ends_with("delete"));
    }

    #[test]
    fn test_gcp_storage() {
        let req = make_request(
            "GET",
            "storage.googleapis.com",
            "/storage/v1/b/my-bucket/o/my-object",
        );
        let action = parse_action(&req);
        assert_eq!(action.provider, "gcp");
        assert_eq!(action.service, "storage");
    }

    #[test]
    fn test_gcp_project_extraction() {
        let req = make_request(
            "POST",
            "compute.googleapis.com",
            "/compute/v1/projects/prod-project-123/zones/us-east1-b/instances",
        );
        let action = parse_action(&req);
        assert_eq!(action.qualifier.get("project").unwrap(), "prod-project-123");
    }

    #[test]
    fn test_non_gcp_not_matched() {
        let req = make_request("GET", "api.google.com", "/something");
        let action = parse_action(&req);
        assert_eq!(action.provider, "net");
    }

    // -- GitHub tests --

    #[test]
    fn test_github_repos_get() {
        let req = make_request("GET", "api.github.com", "/repos/owner/repo");
        let action = parse_action(&req);
        assert_eq!(action.provider, "gh");
        assert_eq!(action.canonical(), "gh:repos/owner/repo:GET");
    }

    #[test]
    fn test_github_pulls_post() {
        let req = make_request("POST", "api.github.com", "/repos/owner/repo/pulls");
        let action = parse_action(&req);
        assert_eq!(action.provider, "gh");
        assert_eq!(action.canonical(), "gh:repos/owner/repo/pulls:POST");
        assert_eq!(action.operation, "POST");
    }

    #[test]
    fn test_github_issues_get() {
        let req = make_request("GET", "api.github.com", "/repos/owner/repo/issues");
        let action = parse_action(&req);
        assert_eq!(action.canonical(), "gh:repos/owner/repo/issues:GET");
    }

    #[test]
    fn test_github_user() {
        let req = make_request("GET", "api.github.com", "/user");
        let action = parse_action(&req);
        assert_eq!(action.canonical(), "gh:user:GET");
    }

    #[test]
    fn test_non_github_not_matched() {
        let req = make_request("GET", "github.com", "/owner/repo");
        let action = parse_action(&req);
        assert_eq!(action.provider, "net");
    }

    // -- Kubernetes tests --

    #[test]
    fn test_k8s_list_pods() {
        let req = make_request("GET", "k8s.local", "/api/v1/namespaces/default/pods");
        let action = parse_action(&req);
        assert_eq!(action.canonical(), "k8s[ns=default]:pods:list");
        assert_eq!(action.provider, "k8s");
        assert_eq!(action.service, "pods");
        assert_eq!(action.operation, "list");
        assert_eq!(action.qualifier.get("ns").unwrap(), "default");
    }

    #[test]
    fn test_k8s_get_pod() {
        let req = make_request("GET", "k8s.local", "/api/v1/namespaces/default/pods/my-pod");
        let action = parse_action(&req);
        assert_eq!(action.canonical(), "k8s[ns=default]:pods:get");
    }

    #[test]
    fn test_k8s_delete_deployment() {
        let req = make_request(
            "DELETE",
            "k8s.local",
            "/apis/apps/v1/namespaces/prod/deployments/web",
        );
        let action = parse_action(&req);
        assert_eq!(action.canonical(), "k8s[ns=prod]:deployments:delete");
    }

    #[test]
    fn test_k8s_create_service() {
        let req = make_request("POST", "k8s.local", "/api/v1/namespaces/default/services");
        let action = parse_action(&req);
        assert_eq!(action.canonical(), "k8s[ns=default]:services:create");
    }

    #[test]
    fn test_k8s_list_nodes() {
        let req = make_request("GET", "k8s.local", "/api/v1/nodes");
        let action = parse_action(&req);
        assert_eq!(action.canonical(), "k8s:nodes:list");
        assert!(action.qualifier.is_empty());
    }

    #[test]
    fn test_k8s_watch_pods() {
        let mut req = make_request("GET", "k8s.local", "/api/v1/namespaces/default/pods");
        req.query_params.insert("watch".into(), "true".into());
        let action = parse_action(&req);
        assert_eq!(action.canonical(), "k8s[ns=default]:pods:watch");
    }

    #[test]
    fn test_non_k8s_not_matched() {
        // A random host with /api/v1/ but unknown resource type should NOT match K8s
        let req = make_request(
            "GET",
            "api.example.com",
            "/api/v1/namespaces/default/widgets",
        );
        let action = parse_action(&req);
        assert_eq!(action.provider, "net");
    }
}
