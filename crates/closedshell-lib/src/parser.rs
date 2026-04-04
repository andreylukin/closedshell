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
    // Try provider-specific parsers in order
    if let Some(action) = try_parse_aws(req) {
        return action;
    }

    // Fallback: generic net:METHOD:host/path
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
    // AWS endpoints: *.amazonaws.com
    if !req.host.ends_with(".amazonaws.com") {
        return None;
    }

    // Extract service from host: ec2.amazonaws.com → ec2
    // or: s3.us-east-1.amazonaws.com → s3
    let service = req.host.split('.').next()?;

    // AWS actions come from either:
    // 1. Query param: ?Action=DescribeInstances
    // 2. X-Amz-Target header: AmazonEC2.DescribeInstances
    // 3. REST-style from method + path (S3, API Gateway)
    let operation = if let Some(action) = req.query_params.get("Action") {
        action.clone()
    } else if let Some(target) = req.headers.get("x-amz-target") {
        // Format: ServiceName.OperationName
        target.split('.').next_back().unwrap_or(target).to_string()
    } else {
        // REST-style: use method as operation hint
        format!("{}:{}", req.method, req.path)
    };

    // Extract profile from authorization header or default
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

fn extract_aws_profile(req: &RequestInfo) -> String {
    // In practice, the proxy knows which credential mount was used.
    // For now, extract from the access key or default to "default".
    if let Some(auth) = req.headers.get("authorization")
        && auth.contains("Credential=")
    {
        // AWS Signature V4: Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request
        // We can't map access key → profile without the credentials file.
        // For YOLO mode, "default" is fine. Judge integration will resolve this later.
        return "default".into();
    }
    "default".into()
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

    #[test]
    fn test_generic_get() {
        let req = make_request("GET", "api.github.com", "/repos/foo/bar");
        let action = parse_action(&req);
        assert_eq!(action.canonical(), "net:GET:api.github.com/repos/foo/bar");
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
    fn test_non_aws_not_matched() {
        let req = make_request("GET", "example.com", "/api/v1");
        let action = parse_action(&req);
        assert_eq!(action.provider, "net");
    }
}
