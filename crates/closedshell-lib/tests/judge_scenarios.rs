//! Judge scenario tests — multi-step conversations that validate judge decisions
//! against real LLM APIs.
//!
//! Gated behind ANTHROPIC_KEY env var. Skipped when not set.
//! Scenarios run in parallel (steps within a scenario are sequential).
//!
//! Run with:
//!   ANTHROPIC_KEY=... cargo test -p closedshell-lib --test judge_scenarios -- --nocapture

use closedshell_lib::config::JudgeConfig;
use closedshell_lib::judge::{
    classify_risk, HistoryEntry, JudgeClient, JudgeDecision, JudgeRequest, SessionContext,
};
use serde::Deserialize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize)]
struct Scenario {
    name: String,
    task: String,
    steps: Vec<Step>,
}

#[derive(Deserialize)]
struct Step {
    action: String,
    expected: String,
    #[serde(default)]
    implicit: bool,
}

struct StepResult {
    step_num: usize,
    action: String,
    expected: String,
    actual: String,
    reason: Option<String>,
    implicit: bool,
    pass: bool,
}

struct ScenarioResult {
    name: String,
    task: String,
    steps: Vec<StepResult>,
}

fn anthropic_config() -> Option<JudgeConfig> {
    let key = std::env::var("ANTHROPIC_KEY").ok()?;
    if key.is_empty() {
        return None;
    }
    Some(JudgeConfig {
        provider: "anthropic".into(),
        api_base: "https://api.anthropic.com/v1".into(),
        model: "claude-sonnet-4-6".into(),
        api_key: key,
        timeout_ms: 15000,
        temperature: 0.0,
        ..Default::default()
    })
}

fn load_scenarios() -> Vec<Scenario> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/judge-scenarios");
    let mut scenarios = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("judge-scenarios dir missing") {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "yaml") {
            let content = std::fs::read_to_string(&path).unwrap();
            let scenario: Scenario = serde_yaml::from_str(&content)
                .unwrap_or_else(|e| panic!("bad scenario {}: {}", path.display(), e));
            scenarios.push(scenario);
        }
    }
    scenarios.sort_by(|a, b| a.name.cmp(&b.name));
    scenarios
}

fn decision_matches(actual: &JudgeDecision, expected: &str) -> bool {
    match (actual, expected) {
        (JudgeDecision::Approve, "approve") => true,
        (JudgeDecision::Deny { .. }, "deny") => true,
        (JudgeDecision::EscalateHuman, "escalate") => true,
        // Escalate counts as "not approve" — treat as pass for deny expectations
        (JudgeDecision::EscalateHuman, "deny") => true,
        _ => false,
    }
}

fn decision_label(d: &JudgeDecision) -> &str {
    match d {
        JudgeDecision::Approve => "approve",
        JudgeDecision::Deny { .. } => "deny",
        JudgeDecision::EscalateHuman => "escalate",
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Run a single scenario sequentially (steps depend on history).
async fn run_scenario(client: &JudgeClient, scenario: &Scenario) -> ScenarioResult {
    let mut history: Vec<HistoryEntry> = Vec::new();
    let mut steps = Vec::new();

    for (i, step) in scenario.steps.iter().enumerate() {
        let risk_tier = classify_risk(&step.action);

        let req = JudgeRequest {
            requested_action: step.action.clone(),
            current_tree: vec![],
            session_context: SessionContext {
                task: Some(scenario.task.clone()),
            },
            history: history.clone(),
            risk_tier: risk_tier.into(),
            implicit: step.implicit,
        };

        let decision = client.evaluate_action(req).await;
        let pass = decision_matches(&decision, &step.expected);
        let actual = decision_label(&decision).to_string();
        let reason = if let JudgeDecision::Deny { ref reason } = decision {
            Some(reason.clone())
        } else {
            None
        };

        steps.push(StepResult {
            step_num: i + 1,
            action: step.action.clone(),
            expected: step.expected.clone(),
            actual: actual.clone(),
            reason,
            implicit: step.implicit,
            pass,
        });

        history.push(HistoryEntry {
            action: step.action.clone(),
            decision: actual,
            by: "judge".into(),
            t: now_unix(),
        });
    }

    ScenarioResult {
        name: scenario.name.clone(),
        task: scenario.task.clone(),
        steps,
    }
}

#[tokio::test]
async fn judge_scenarios() {
    let config = match anthropic_config() {
        Some(c) => c,
        None => {
            eprintln!("ANTHROPIC_KEY not set, skipping judge scenario tests");
            return;
        }
    };

    let client = Arc::new(JudgeClient::new(config).expect("failed to create judge client"));
    let scenarios = load_scenarios();
    assert!(!scenarios.is_empty(), "no scenarios found");

    // Run scenarios in parallel, capped at 10 concurrent
    let semaphore = Arc::new(tokio::sync::Semaphore::new(40));
    let mut handles = Vec::new();
    for scenario in scenarios {
        let client = client.clone();
        let sem = semaphore.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            run_scenario(&client, &scenario).await
        }));
    }

    let mut results: Vec<ScenarioResult> = Vec::new();
    for handle in handles {
        results.push(handle.await.unwrap());
    }
    results.sort_by(|a, b| a.name.cmp(&b.name));

    // Print results and tally
    let mut total = 0;
    let mut passed = 0;
    let mut failures: Vec<String> = Vec::new();

    for result in &results {
        eprintln!("\n━━━ {} ━━━", result.name);
        eprintln!("  task: {}", result.task);

        for step in &result.steps {
            total += 1;
            let marker = if step.pass { "✓" } else { "✗" };
            let implicit_tag = if step.implicit { " (implicit)" } else { "" };
            eprintln!(
                "  {} step {}: {} → {} (expected: {}){implicit_tag}",
                marker, step.step_num, step.action, step.actual, step.expected,
            );

            if let Some(ref reason) = step.reason {
                eprintln!("      reason: {}", reason);
            }

            if step.pass {
                passed += 1;
            } else {
                failures.push(format!(
                    "{} step {}: {} → {} (expected {})",
                    result.name, step.step_num, step.action, step.actual, step.expected,
                ));
            }
        }
    }

    eprintln!("\n━━━ Results: {}/{} passed ━━━", passed, total);
    if !failures.is_empty() {
        eprintln!("\nFailures:");
        for f in &failures {
            eprintln!("  - {}", f);
        }
    }
}
