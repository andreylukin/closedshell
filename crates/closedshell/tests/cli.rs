//! macOS-only integration tests that run the closedshell binary end-to-end.
//!
//! These build and invoke the actual binary with --yolo mode, running simple
//! commands inside the sandbox and asserting on output and audit logs.

#![cfg(target_os = "macos")]

use std::path::PathBuf;
use std::process::Command;

/// Path to the built binary. `cargo test` builds it automatically via the
/// [[bin]] target in this crate.
fn closedshell_bin() -> PathBuf {
    // cargo sets this env var during `cargo test` for integration tests
    let mut path = PathBuf::from(env!("CARGO_BIN_EXE_closedshell"));
    // Fallback: if the env var gives us the right path, use it directly
    if !path.exists() {
        path = PathBuf::from("target/debug/closedshell");
    }
    path
}

fn run_closedshell(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(closedshell_bin())
        .args(args)
        .current_dir(std::env::temp_dir())
        .output()
        .expect("failed to run closedshell binary");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[test]
fn yolo_echo_exits_zero() {
    let (code, stdout, _) = run_closedshell(&["--yolo", "echo", "hello"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("hello"));
}

#[test]
fn motd_shows_session_and_mode() {
    let (code, _, stderr) = run_closedshell(&["--yolo", "echo", "hi"]);
    assert_eq!(code, 0);
    assert!(
        stderr.contains("[closedshell] session"),
        "MOTD should show session ID, got: {}",
        stderr
    );
    assert!(
        stderr.contains("[closedshell] mode: yolo"),
        "MOTD should show yolo mode, got: {}",
        stderr
    );
}

#[test]
fn no_motd_flag_suppresses_banner() {
    let (code, _, stderr) = run_closedshell(&["--yolo", "--no-motd", "echo", "hi"]);
    assert_eq!(code, 0);
    assert!(
        !stderr.contains("[closedshell] session"),
        "MOTD should be suppressed, got: {}",
        stderr
    );
}

#[test]
fn task_flag_shows_in_motd() {
    let (code, _, stderr) = run_closedshell(&["--yolo", "--task", "fix the bug", "echo", "ok"]);
    assert_eq!(code, 0);
    assert!(
        stderr.contains("[closedshell] task: fix the bug"),
        "task should appear in MOTD, got: {}",
        stderr
    );
}

#[test]
fn audit_log_is_created() {
    let tmpdir = tempfile::tempdir().unwrap();
    let output = Command::new(closedshell_bin())
        .args(["--yolo", "echo", "audit-test"])
        .current_dir(tmpdir.path())
        .output()
        .expect("failed to run closedshell");
    assert_eq!(output.status.code().unwrap_or(-1), 0);

    // Find the audit log file
    let logs: Vec<_> = std::fs::read_dir(tmpdir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name().to_string_lossy().starts_with("closedshell-")
                && e.file_name().to_string_lossy().ends_with(".log")
        })
        .collect();

    assert_eq!(logs.len(), 1, "expected one audit log file");

    let log_content = std::fs::read_to_string(logs[0].path()).unwrap();
    let events: Vec<serde_json::Value> = log_content
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();

    let has_start = events.iter().any(|e| e["event"] == "session_start");
    let has_end = events.iter().any(|e| e["event"] == "session_end");
    assert!(has_start, "audit log should have session_start");
    assert!(has_end, "audit log should have session_end");
}

#[test]
fn nonexistent_command_exits_nonzero() {
    let (code, _, _) = run_closedshell(&["--yolo", "this-command-does-not-exist-xyz"]);
    assert_ne!(code, 0);
}

#[test]
fn sandbox_env_vars_are_set() {
    let (code, stdout, _) = run_closedshell(&["--yolo", "env"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("HTTPS_PROXY="),
        "HTTPS_PROXY should be set in sandbox"
    );
    assert!(
        stdout.contains("CLOSEDSHELL_SESSION="),
        "CLOSEDSHELL_SESSION should be set in sandbox"
    );
}
