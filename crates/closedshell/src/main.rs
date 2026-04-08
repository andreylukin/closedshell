use clap::Parser;
use closedshell_lib::audit::{AuditLog, AuditPayload};
use closedshell_lib::config::{self, CliFlags};
use closedshell_lib::proxy::{MitmProxy, YoloDecider};
use closedshell_lib::sandbox;
use closedshell_lib::tls::SessionCA;
use std::path::PathBuf;
use std::sync::Arc;

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

    // 4. Generate session CA, write combined trust store (session CA + system roots) to tmpdir
    let ca = Arc::new(SessionCA::new()?);
    let ca_pem_path = tmpdir.join("ca.pem");
    let mut trust_store = String::from(ca.ca_pem());
    // Append system roots so clients that replace their root store with SSL_CERT_FILE
    // (e.g., Go on macOS) can still verify upstream certs if needed.
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

    // 6b. Add session CA to macOS login keychain (removed on cleanup)
    let security_status = std::process::Command::new("security")
        .args(["add-trusted-cert", "-r", "trustRoot", "-k"])
        .arg(PathBuf::from(std::env::var("HOME").unwrap()).join("Library/Keychains/login.keychain-db"))
        .arg(&ca_pem_path)
        .status();
    let ca_in_keychain = matches!(security_status, Ok(s) if s.success());
    if !ca_in_keychain {
        tracing::warn!("could not add session CA to login keychain — Go/macOS TLS may fail");
    }

    // 7. Print MOTD
    if config.sandbox.motd {
        let mode = if config.sandbox.yolo { "yolo" } else { "enforcing" };
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

    let mut cmd = std::process::Command::new("sandbox-exec");
    cmd.arg("-f")
        .arg(&profile_path)
        .arg("env")
        .arg(format!("HTTPS_PROXY={}", proxy_url))
        .arg(format!("HTTP_PROXY={}", proxy_url))
        .arg(format!("SSL_CERT_FILE={}", ca_pem_path.display()))
        .arg(format!("SSL_CERT_DIR={}", tmpdir.display()))
        .arg("GODEBUG=x509usefallbackroots=1")
        .arg(format!(
            "CLOSEDSHELL_SOCKET={}/ask.sock",
            tmpdir.display()
        ))
        .arg(format!("CLOSEDSHELL_SESSION={}", session_id));

    // Pass through credential env vars
    for cred in &config.sandbox.credentials {
        if matches!(cred.mount_type, closedshell_lib::config::CredentialType::Env) {
            for var in &cred.vars {
                if let Ok(val) = std::env::var(var) {
                    cmd.arg(format!("{}={}", var, val));
                }
            }
        }
    }

    cmd.args(&cli.command);

    tracing::info!(
        session = %session_id,
        port = actual_port,
        command = ?cli.command,
        "sandbox starting"
    );

    // 10. Wait for child process
    let status = cmd.status()?;

    // 11. Cleanup
    let duration = start_time.elapsed();
    audit.log(AuditPayload::SessionEnd {
        duration_s: duration.as_secs(),
        total_decisions: proxy_stats.total(),
        denied: 0, // YOLO mode never denies
    })?;

    proxy_handle.abort();

    // Remove session CA from login keychain
    if ca_in_keychain {
        let _ = std::process::Command::new("security")
            .args(["remove-trusted-cert"])
            .arg(&ca_pem_path)
            .status();
    }

    // Remove tmpdir
    let _ = std::fs::remove_dir_all(&tmpdir);

    tracing::info!(
        session = %session_id,
        duration_s = duration.as_secs(),
        "session ended"
    );

    // Exit with child's exit code
    std::process::exit(status.code().unwrap_or(1));
}
