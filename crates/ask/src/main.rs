mod ipc;

use clap::{Parser, Subcommand};
use serde_json::json;
use std::process;

#[derive(Parser)]
#[command(name = "ask", about = "ClosedShell in-sandbox CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show current permission tree
    Status,
    /// Query matching rules for a pattern
    WhatCanI {
        /// Action pattern to query
        pattern: String,
    },
    /// Explain last denial
    WhyDenied,
    /// Request permission for an action
    Allow {
        /// Action to request permission for
        action: String,
    },
    /// Submit a plan for approval
    Plan {
        /// Plan description
        description: String,
    },
    /// Update session context
    Context {
        /// Current task description
        task: String,
    },
    /// Read a file through the permission system
    Read {
        /// File path to read
        path: String,
    },
    /// Write a file through the permission system
    Write {
        /// File path to write
        path: String,
        /// Content to write
        content: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let client = match ipc::IpcClient::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ask: {e}");
            process::exit(1);
        }
    };

    let request = match &cli.command {
        Commands::Status => json!({"type": "status"}),
        Commands::WhatCanI { pattern } => json!({"type": "what_can_i", "pattern": pattern}),
        Commands::WhyDenied => json!({"type": "why_denied"}),
        Commands::Allow { action } => json!({"type": "allow", "action": action}),
        Commands::Plan { description } => json!({"type": "plan", "description": description}),
        Commands::Context { task } => json!({"type": "context", "task": task}),
        Commands::Read { path } => json!({"type": "read", "path": path}),
        Commands::Write { path, content } => {
            json!({"type": "write", "path": path, "content": content})
        }
    };

    let response = match client.send(&request) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ask: {e}");
            process::exit(1);
        }
    };

    let ok = response.get("ok").and_then(|v| v.as_bool());

    match ok {
        Some(true) => {
            if let Some(data) = response.get("data") {
                print_data(&cli.command, data);
            }
        }
        Some(false) => {
            let message = response
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            let hint = response.get("hint").and_then(|v| v.as_str());
            eprintln!("ask: {message}");
            if let Some(hint) = hint {
                eprintln!("hint: {hint}");
            }
            process::exit(1);
        }
        None => {
            eprintln!("ask: malformed response: {response}");
            process::exit(1);
        }
    }
}

fn print_data(command: &Commands, data: &serde_json::Value) {
    match command {
        Commands::Status => print_status(data),
        Commands::WhatCanI { .. } => print_rules(data),
        Commands::WhyDenied => print_why_denied(data),
        Commands::Allow { .. } => print_allow(data),
        Commands::Plan { .. } => print_plan(data),
        Commands::Context { .. } => print_context(data),
        Commands::Read { .. } => print_read(data),
        Commands::Write { .. } => print_write(data),
    }
}

fn print_status(data: &serde_json::Value) {
    if let Some(rules) = data.get("rules").and_then(|v| v.as_array()) {
        // Print forbids first, then permits
        let forbids: Vec<_> = rules
            .iter()
            .filter(|r| r.get("effect").and_then(|e| e.as_str()) == Some("forbid"))
            .collect();
        let permits: Vec<_> = rules
            .iter()
            .filter(|r| r.get("effect").and_then(|e| e.as_str()) != Some("forbid"))
            .collect();

        for rule in forbids.iter().chain(permits.iter()) {
            let effect = rule.get("effect").and_then(|v| v.as_str()).unwrap_or("?");
            let pattern = rule.get("pattern").and_then(|v| v.as_str()).unwrap_or("?");
            println!("{effect:>8}  {pattern}");
        }
    } else {
        println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
    }
}

fn print_rules(data: &serde_json::Value) {
    if let Some(rules) = data.as_array() {
        for rule in rules {
            let effect = rule.get("effect").and_then(|v| v.as_str()).unwrap_or("?");
            let pattern = rule.get("pattern").and_then(|v| v.as_str()).unwrap_or("?");
            println!("{effect:>8}  {pattern}");
        }
    } else {
        println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
    }
}

fn print_why_denied(data: &serde_json::Value) {
    if let Some(action) = data.get("action").and_then(|v| v.as_str()) {
        println!("action: {action}");
    }
    if let Some(reason) = data.get("reason").and_then(|v| v.as_str()) {
        println!("reason: {reason}");
    }
    if let Some(tier) = data.get("risk_tier").and_then(|v| v.as_str()) {
        println!("  tier: {tier}");
    }
    if let Some(hint) = data.get("hint").and_then(|v| v.as_str()) {
        println!("  hint: {hint}");
    }
}

fn print_allow(data: &serde_json::Value) {
    if let Some(granted) = data.get("granted").and_then(|v| v.as_bool()) {
        if granted {
            let pattern = data
                .get("pattern")
                .and_then(|v| v.as_str())
                .unwrap_or("(unknown)");
            println!("granted: {pattern}");
        } else {
            let reason = data
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("denied");
            println!("denied: {reason}");
        }
    } else {
        println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
    }
}

fn print_plan(data: &serde_json::Value) {
    if let Some(plan_id) = data.get("plan_id").and_then(|v| v.as_str()) {
        println!("plan_id: {plan_id}");
    }
    if let Some(status) = data.get("status").and_then(|v| v.as_str()) {
        println!(" status: {status}");
    }
}

fn print_context(data: &serde_json::Value) {
    if let Some(task) = data.get("task").and_then(|v| v.as_str()) {
        println!("context updated: {task}");
    } else {
        println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
    }
}

fn print_read(data: &serde_json::Value) {
    if let Some(content) = data.get("content").and_then(|v| v.as_str()) {
        print!("{content}");
    } else {
        println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
    }
}

fn print_write(data: &serde_json::Value) {
    if let Some(bytes) = data.get("bytes_written").and_then(|v| v.as_u64()) {
        println!("{bytes} bytes written");
    } else {
        println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
    }
}
