//! Risk classification and shared types for permission decisions.

use serde::Serialize;

/// A decision history entry, used by session state to track recent actions.
#[derive(Debug, Clone, Serialize)]
pub struct HistoryEntry {
    pub action: String,
    pub decision: String,
    pub by: String,
    pub t: i64,
}

/// Classify risk tier based on the canonical action string.
pub fn classify_risk(action_canonical: &str) -> &'static str {
    // Extract the operation name — last segment after ':'
    let op = action_canonical
        .rsplit(':')
        .next()
        .unwrap_or(action_canonical);

    // Check prefixes for known patterns
    let safe_prefixes = ["Describe", "List", "Get", "Head"];
    let dangerous_prefixes = ["Delete", "Terminate", "Remove", "Revoke", "Detach"];
    let moderate_prefixes = ["Create", "Put", "Start", "Stop", "Update", "Tag"];

    // Also check lowercase keywords (for non-AWS styles like net:POST:...)
    let safe_keywords = ["read"];
    let dangerous_keywords: [&str; 0] = [];
    let moderate_keywords = ["insert", "patch", "write", "POST"];

    for prefix in &safe_prefixes {
        if op.starts_with(prefix) {
            return "safe";
        }
    }
    for kw in &safe_keywords {
        if op.eq_ignore_ascii_case(kw) {
            return "safe";
        }
    }

    for prefix in &dangerous_prefixes {
        if op.starts_with(prefix) {
            return "dangerous";
        }
    }
    for kw in &dangerous_keywords {
        if op.eq_ignore_ascii_case(kw) {
            return "dangerous";
        }
    }

    for prefix in &moderate_prefixes {
        if op.starts_with(prefix) {
            return "moderate";
        }
    }
    for kw in &moderate_keywords {
        if op.eq_ignore_ascii_case(kw) {
            return "moderate";
        }
    }

    "moderate"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_risk_safe() {
        assert_eq!(classify_risk("aws:s3:ListBuckets"), "safe");
        assert_eq!(classify_risk("aws:ec2:DescribeInstances"), "safe");
        assert_eq!(classify_risk("aws:s3:GetObject"), "safe");
        assert_eq!(classify_risk("aws:s3:HeadObject"), "safe");
        assert_eq!(classify_risk("fs:read"), "safe");
    }

    #[test]
    fn test_classify_risk_moderate() {
        assert_eq!(classify_risk("aws:s3:PutObject"), "moderate");
        assert_eq!(classify_risk("aws:ec2:CreateInstance"), "moderate");
        assert_eq!(classify_risk("aws:ec2:StartInstances"), "moderate");
        assert_eq!(classify_risk("aws:ec2:StopInstances"), "moderate");
        assert_eq!(classify_risk("aws:ec2:UpdateStack"), "moderate");
        assert_eq!(classify_risk("aws:ec2:TagResource"), "moderate");
        assert_eq!(classify_risk("net:POST:example.com/api"), "moderate");
    }

    #[test]
    fn test_classify_risk_dangerous() {
        assert_eq!(classify_risk("aws:s3:DeleteBucket"), "dangerous");
        assert_eq!(classify_risk("aws:ec2:TerminateInstances"), "dangerous");
        assert_eq!(
            classify_risk("aws:iam:RemoveRoleFromInstanceProfile"),
            "dangerous"
        );
        assert_eq!(
            classify_risk("aws:iam:RevokeSecurityGroupIngress"),
            "dangerous"
        );
        assert_eq!(classify_risk("aws:ec2:DetachVolume"), "dangerous");
    }

    #[test]
    fn test_classify_risk_default() {
        assert_eq!(classify_risk("aws:s3:SomeUnknownAction"), "moderate");
        assert_eq!(classify_risk("net:PATCH:example.com/api"), "moderate");
    }
}
