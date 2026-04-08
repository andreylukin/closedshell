use clap::Parser;
use closedshell_lib::audit::{AuditLog, AuditPayload};
use closedshell_lib::config::{self, CliFlags};
use closedshell_lib::proxy::{MitmProxy, YoloDecider};
use closedshell_lib::sandbox;
use closedshell_lib::tls::SessionCA;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal::unix::{SignalKind, signal};

#[derive(Parser)]
#[command(name = "closedshell", about = "Sandbox for AI agents")]
struct Cli {
    /// Session task description (used by judge for scope detection)
    #[arg(long)]
    task: Option<String>,

    /// Permission template to load (repeatable)
    #[arg(long)]
    template: Vec<String>,

    /// Log-only mode — no blocking
    #[arg(long)]
    yolo: bool,

    /// Suppress MOTD on start
    #[arg(long)]
    no_motd: bool,

    /// Ignore existing session, start clean
    #[arg(long)]
    fresh: bool,

    /// Allow actions matching this glob pattern (repeatable, default deny when set)
    #[arg(long)]
    allow: Vec<String>,

    /// Command to run in sandbox (e.g., "pi", "claude-code")
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

fn generate_session_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:08x}", (t & 0xFFFF_FFFF) as u32)
}

/// Add a CA certificate to the macOS user trust store without a password prompt.
///
/// The `security add-trusted-cert` CLI always prompts for a password on modern
/// macOS. Instead, we compile a tiny Swift program that calls
/// `SecTrustSettingsSetTrustSettings` with the `.user` domain, which doesn't
/// require authentication. The compiled binary is cached next to the CA.
fn trust_ca_macos(ca_pem_path: &std::path::Path) -> anyhow::Result<()> {
    let cs_dir = ca_pem_path.parent().unwrap();
    let helper_bin = cs_dir.join("trust-cert");

    // Compile the Swift helper once, reuse on subsequent calls
    if !helper_bin.exists() {
        let swift_src = cs_dir.join("trust-cert.swift");
        std::fs::write(
            &swift_src,
            r#"import Foundation
import Security
guard CommandLine.arguments.count == 2 else { exit(1) }
let url = URL(fileURLWithPath: CommandLine.arguments[1])
let pem = try! String(contentsOf: url, encoding: .utf8)
    .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
    .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
    .replacingOccurrences(of: "\n", with: "")
guard let der = Data(base64Encoded: pem),
      let cert = SecCertificateCreateWithData(nil, der as CFData) else { exit(1) }
guard SecTrustSettingsSetTrustSettings(cert, .user, nil) == errSecSuccess else { exit(1) }
"#,
        )?;

        let status = std::process::Command::new("swiftc")
            .args(["-O", "-o"])
            .arg(&helper_bin)
            .arg(&swift_src)
            .status()?;

        // Clean up source regardless
        let _ = std::fs::remove_file(&swift_src);

        if !status.success() {
            let _ = std::fs::remove_file(&helper_bin);
            anyhow::bail!("swiftc failed");
        }
    }

    let status = std::process::Command::new(&helper_bin)
        .arg(ca_pem_path)
        .status()?;

    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("trust-cert helper failed")
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    // 1. Load config and merge CLI flags
    let mut config = config::load_config()?;
    let flags = CliFlags {
        yolo: cli.yolo,
        no_motd: cli.no_motd,
        task: cli.task.clone(),
        templates: cli.template.clone(),
    };
    config.merge_cli_flags(&flags);

    // 2. Generate session ID
    let session_id = generate_session_id();

    // 3. Create tmpdir
    let tmpdir = PathBuf::from(format!("/tmp/closedshell-{}", session_id));
    std::fs::create_dir_all(&tmpdir)?;

    // 4. Load persistent CA from ~/.closedshell/ (or create on first run)
    let home = PathBuf::from(std::env::var("HOME").unwrap());
    let cs_dir = home.join(".closedshell");
    let ca_cert_path = cs_dir.join("ca.pem");
    let ca_key_path = cs_dir.join("ca-key.pem");
    let is_new_ca = !ca_cert_path.exists();

    let ca = Arc::new(SessionCA::load_or_create(&ca_cert_path, &ca_key_path)?);

    // On first run, add CA to macOS user trust store.
    // Uses Security.framework's user domain via a small Swift helper —
    // unlike `security add-trusted-cert`, this doesn't prompt for a password.
    if is_new_ca {
        if let Err(e) = trust_ca_macos(&ca_cert_path) {
            tracing::warn!("could not auto-trust CA: {e}");
            eprintln!("[closedshell] CA created at {}", ca_cert_path.display());
            eprintln!("[closedshell] Auto-trust failed. To trust manually (one-time), run:");
            eprintln!(
                "[closedshell]   security add-trusted-cert -r trustRoot {}",
                ca_cert_path.display()
            );
        } else {
            eprintln!("[closedshell] CA created and trusted (one-time setup)");
        }
    }

    // Write combined trust store (our CA + system roots) to tmpdir for SSL_CERT_FILE
    let ca_pem_path = tmpdir.join("ca.pem");
    let mut trust_store = String::from(ca.ca_pem());
    if let Ok(system_pem) = std::fs::read_to_string("/etc/ssl/cert.pem") {
        trust_store.push('\n');
        trust_store.push_str(&system_pem);
    }
    std::fs::write(&ca_pem_path, &trust_store)?;

    // 5. Start MITM proxy
    let audit = Arc::new(AuditLog::open(&std::env::current_dir()?, &session_id)?);
    let decider: Arc<dyn closedshell_lib::proxy::DecisionMaker> = Arc::new(YoloDecider);

    let proxy = MitmProxy {
        ca: ca.clone(),
        audit: audit.clone(),
        port: 8443,
        decider: decider.clone(),
    };

    let (actual_port, proxy_handle, proxy_stats) = match proxy.start().await {
        Ok(r) => r,
        Err(_) => {
            // Port 8443 taken, try OS-assigned
            let proxy = MitmProxy {
                ca: ca.clone(),
                audit: audit.clone(),
                port: 0,
                decider: decider.clone(),
            };
            proxy.start().await?
        }
    };

    // 6. Generate seatbelt profile, write to tmpdir
    let profile = sandbox::generate_seatbelt_profile(actual_port);
    let profile_path = tmpdir.join("profile.sb");
    std::fs::write(&profile_path, &profile)?;

    // 7. Print MOTD
    if config.sandbox.motd {
        let mode = if config.sandbox.yolo {
            "yolo"
        } else {
            "enforcing"
        };
        eprintln!("[closedshell] session {} (new)", session_id);
        if let Some(ref task) = cli.task {
            eprintln!("[closedshell] task: {}", task);
        }
        if !cli.template.is_empty() {
            eprintln!("[closedshell] templates: {}", cli.template.join(", "));
        }
        eprintln!("[closedshell] mode: {}", mode);
        eprintln!("[closedshell] log: ./closedshell-{}.log", session_id);
    }

    // 8. Log session_start event
    audit.log(AuditPayload::SessionStart {
        command: cli.command.join(" "),
        templates: cli.template.clone(),
        yolo: config.sandbox.yolo,
    })?;

    let start_time = std::time::Instant::now();

    // 9. Build and exec sandbox-exec with environment
    let proxy_url = format!("http://localhost:{}", actual_port);

    let mut cmd = tokio::process::Command::new("sandbox-exec");
    cmd.arg("-f")
        .arg(&profile_path)
        .arg("env")
        .arg(format!("HTTPS_PROXY={}", proxy_url))
        .arg(format!("HTTP_PROXY={}", proxy_url))
        .arg(format!("SSL_CERT_FILE={}", ca_pem_path.display()))
        .arg(format!("SSL_CERT_DIR={}", tmpdir.display()))
        .arg("GODEBUG=x509usefallbackroots=1")
        .arg(format!("CLOSEDSHELL_SOCKET={}/ask.sock", tmpdir.display()))
        .arg(format!("CLOSEDSHELL_SESSION={}", session_id));

    // Pass through configured env vars
    for var in &config.sandbox.passthrough_env {
        if let Ok(val) = std::env::var(var) {
            cmd.arg(format!("{}={}", var, val));
        }
    }

    cmd.args(&cli.command);

    tracing::info!(
        session = %session_id,
        port = actual_port,
        command = ?cli.command,
        "sandbox starting"
    );

    // 10. Wait for child process, handling signals for clean shutdown
    let mut child = cmd.spawn()?;

    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    let exit_code = tokio::select! {
        status = child.wait() => {
            status?.code().unwrap_or(1)
        }
        _ = sigint.recv() => {
            tracing::info!("received SIGINT, cleaning up");
            let _ = child.kill().await;
            1
        }
        _ = sigterm.recv() => {
            tracing::info!("received SIGTERM, cleaning up");
            let _ = child.kill().await;
            1
        }
    };

    // 11. Cleanup (always runs, even on signal)
    let duration = start_time.elapsed();
    audit.log(AuditPayload::SessionEnd {
        duration_s: duration.as_secs(),
        total_decisions: proxy_stats.total(),
        denied: 0, // YOLO mode never denies
    })?;

    proxy_handle.abort();

    // Remove tmpdir (CA persists in ~/.closedshell/)
    let _ = std::fs::remove_dir_all(&tmpdir);

    tracing::info!(
        session = %session_id,
        duration_s = duration.as_secs(),
        "session ended"
    );

    // Exit with child's exit code
    std::process::exit(exit_code);
}
