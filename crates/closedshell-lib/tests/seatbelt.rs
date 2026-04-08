//! macOS-only tests that verify seatbelt actually enforces network rules.
//!
//! These spawn real `sandbox-exec` processes and assert on OS-level behavior.
//! Skipped on non-macOS platforms.

#![cfg(target_os = "macos")]

use closedshell_lib::sandbox::generate_seatbelt_profile;
use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;

fn write_profile(content: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

/// Run a command inside sandbox-exec with the given profile, return (exit_code, stdout, stderr).
fn sandbox_run(profile: &str, cmd: &[&str]) -> (i32, String, String) {
    let f = write_profile(profile);
    let output = Command::new("sandbox-exec")
        .arg("-f")
        .arg(f.path())
        .args(cmd)
        .output()
        .expect("sandbox-exec not found — are you on macOS?");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[test]
fn seatbelt_allows_local_commands() {
    let profile = generate_seatbelt_profile(8443);
    let (code, stdout, _) = sandbox_run(&profile, &["echo", "hello from sandbox"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("hello from sandbox"));
}

#[test]
fn seatbelt_blocks_outbound_network() {
    let profile = generate_seatbelt_profile(8443);
    // curl to an external host should fail — seatbelt denies network-outbound
    // except localhost:8443. Use --connect-timeout to avoid hanging.
    let (code, _, _) = sandbox_run(
        &profile,
        &["curl", "-s", "--connect-timeout", "2", "https://example.com"],
    );
    assert_ne!(code, 0, "outbound network should be blocked by seatbelt");
}

#[test]
fn seatbelt_allows_localhost_proxy_port() {
    // Start a TCP listener on an OS-assigned port, generate a profile allowing that port,
    // then verify a sandboxed process can connect to it.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    // Accept one connection in a background thread
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        use std::io::Write;
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap();
    });

    let profile = generate_seatbelt_profile(port);
    let (code, stdout, _) = sandbox_run(
        &profile,
        &[
            "curl",
            "-s",
            "--connect-timeout",
            "2",
            &format!("http://localhost:{}", port),
        ],
    );

    handle.join().unwrap();
    assert_eq!(code, 0);
    assert_eq!(stdout.trim(), "ok");
}

#[test]
fn seatbelt_blocks_non_proxy_localhost_port() {
    // Bind a listener on one port, but generate a profile for a different port.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let real_port = listener.local_addr().unwrap().port();
    let wrong_port = real_port.wrapping_add(1); // profile allows a different port

    let profile = generate_seatbelt_profile(wrong_port);
    let (code, _, _) = sandbox_run(
        &profile,
        &[
            "curl",
            "-s",
            "--connect-timeout",
            "2",
            &format!("http://localhost:{}", real_port),
        ],
    );

    assert_ne!(code, 0, "connection to non-proxy port should be blocked");
}

#[test]
fn seatbelt_allows_file_operations() {
    let profile = generate_seatbelt_profile(8443);
    let (code, stdout, _) = sandbox_run(&profile, &["ls", "/"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("usr"), "should be able to list filesystem");
}
