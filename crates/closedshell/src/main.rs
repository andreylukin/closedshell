mod tui;

use clap::Parser;
use closedshell_lib::approval::ApprovalQueue;
use closedshell_lib::audit::{AuditLog, AuditPayload};
use closedshell_lib::config::{self, CliFlags};
use closedshell_lib::db::{RuleRow, SessionDb, SessionRow};
use closedshell_lib::ipc::{EnforcingIpcHandler, IpcHandler, IpcServer, SessionState};
use closedshell_lib::permission::PermissionTree;
use closedshell_lib::pf;
use closedshell_lib::proxy::{
    DecisionMaker, EnforcingDecider, MitmProxy, PatternDecider, YoloDecider,
};
use closedshell_lib::sandbox;
use closedshell_lib::template;
use closedshell_lib::tls::SessionCA;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::signal::unix::{SignalKind, signal};

#[derive(Parser)]
#[command(name = "closedshell", about = "Sandbox for AI agents")]
struct Cli {
    /// Permission template to load (repeatable)
    #[arg(long)]
    template: Vec<String>,

    /// Session task (skips interactive prompt, enables instruction injection)
    #[arg(long)]
    task: Option<String>,

    /// Log-only mode — no blocking
    #[arg(long)]
    yolo: bool,

    /// Suppress MOTD on start
    #[arg(long)]
    no_motd: bool,

    /// Resume rules from previous session in this directory
    #[arg(long)]
    resume: bool,

    /// Allow actions matching this glob pattern (repeatable, default deny when set)
    #[arg(long)]
    allow: Vec<String>,

    /// Enable pf (packet filter) as secondary network enforcement layer (requires root)
    #[arg(long)]
    pf: bool,

    /// One-time system setup for pf enforcement (creates sandbox user + pf anchor)
    #[arg(long)]
    pf_setup: bool,

    /// Open the TUI monitor for an existing session
    #[arg(long, value_name = "SESSION_ID")]
    tui: Option<String>,

    /// Command to run in sandbox (e.g., "pi", "claude-code")
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

/// Shell-escape a string for use in `su -c "..."`.
fn shell_escape(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    // If the string contains no special chars, return as-is
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':' | '=' | ','))
    {
        return s.to_string();
    }
    // Wrap in single quotes, escaping existing single quotes
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn generate_session_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:08x}", (t & 0xFFFF_FFFF) as u32)
}

fn handle_template_command(args: &[String], templates_dir: &Path) -> anyhow::Result<()> {
    match args.first().map(|s| s.as_str()) {
        Some("init") => {
            let provider = args.get(1).ok_or_else(|| {
                anyhow::anyhow!("usage: cs template init <provider>\n\nScaffold a new template for the given provider.")
            })?;
            let path = template::init(templates_dir, provider)?;
            eprintln!("[closedshell] created template: {}", path.display());
            Ok(())
        }
        Some("list") => {
            let templates = template::list(templates_dir)?;
            if templates.is_empty() {
                eprintln!(
                    "[closedshell] no templates found in {}",
                    templates_dir.display()
                );
                eprintln!("[closedshell] use 'cs template init <provider>' to create one");
                return Ok(());
            }
            // Print header
            println!("{:<25} {:<45} {:>5}  PATH", "NAME", "DESCRIPTION", "RULES");
            println!("{}", "-".repeat(100));
            for t in &templates {
                let desc = if t.description.len() > 43 {
                    format!("{}...", &t.description[..40])
                } else {
                    t.description.clone()
                };
                println!(
                    "{:<25} {:<45} {:>5}  {}",
                    t.name,
                    desc,
                    t.rule_count,
                    t.path.display()
                );
            }
            Ok(())
        }
        Some("generate") => {
            let session_id = args.get(1).ok_or_else(|| {
                anyhow::anyhow!("usage: cs template generate <session-id> [--name <name>]\n\nGenerate a template from a YOLO session's audit log.")
            })?;

            // Parse optional --name flag
            let name = args
                .iter()
                .position(|a| a == "--name")
                .and_then(|i| args.get(i + 1).map(|s| s.as_str()));

            // Find session log path via DB
            let db_path = if let Ok(p) = std::env::var("CLOSEDSHELL_DB") {
                PathBuf::from(p)
            } else {
                let home = PathBuf::from(std::env::var("HOME").unwrap());
                home.join(".closedshell").join("sessions.db")
            };

            let log_path = if db_path.exists() {
                let db = SessionDb::open(&db_path)?;
                match db.find_session_by_id(session_id)? {
                    Some(session) => PathBuf::from(session.log_path),
                    None => {
                        // Fallback: look for log in current directory
                        let fallback = PathBuf::from(format!("closedshell-{}.log", session_id));
                        if fallback.exists() {
                            fallback
                        } else {
                            anyhow::bail!(
                                "session '{}' not found in database and no log file at {}",
                                session_id,
                                fallback.display()
                            );
                        }
                    }
                }
            } else {
                let fallback = PathBuf::from(format!("closedshell-{}.log", session_id));
                if fallback.exists() {
                    fallback
                } else {
                    anyhow::bail!(
                        "no session database found and no log file at {}",
                        fallback.display()
                    );
                }
            };

            let yaml = template::generate(&log_path, name)?;
            print!("{}", yaml);
            Ok(())
        }
        Some(other) => {
            anyhow::bail!(
                "unknown template command: '{}'\n\nusage: cs template <init|list|generate>",
                other
            );
        }
        None => {
            anyhow::bail!(
                "usage: cs template <init|list|generate>\n\n  init <provider>              Scaffold a new template\n  list                         Show available templates\n  generate <session-id>        Generate template from YOLO session log"
            );
        }
    }
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

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cli = Cli::parse();

    // pf setup mode: one-time system configuration (requires root)
    if cli.pf_setup {
        let pf_user = config::load_config()
            .map(|c| c.sandbox.pf_user)
            .unwrap_or_else(|_| pf::DEFAULT_PF_USER.to_string());
        return pf::setup_system(&pf_user);
    }

    // Template subcommand: dispatch before proxy startup
    if cli.command.first().map(|s| s.as_str()) == Some("template") {
        let config = config::load_config()?;
        let templates_dir = PathBuf::from(config::resolve_tilde(&config.sandbox.templates_dir));
        return handle_template_command(&cli.command[1..], &templates_dir);
    }

    // TUI mode: attach to an existing session
    if let Some(ref session_id) = cli.tui {
        return tui::run(session_id);
    }

    // No-args mode: show session list
    if cli.command.is_empty() {
        let db_path = if let Ok(p) = std::env::var("CLOSEDSHELL_DB") {
            PathBuf::from(p)
        } else {
            let home = PathBuf::from(std::env::var("HOME").unwrap());
            let cs_dir = home.join(".closedshell");
            std::fs::create_dir_all(&cs_dir)?;
            cs_dir.join("sessions.db")
        };
        let db = SessionDb::open(&db_path)?;
        return tui::run_session_list(&db);
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    // 1. Load config and merge CLI flags
    let mut config = config::load_config()?;
    let flags = CliFlags {
        yolo: cli.yolo,
        no_motd: cli.no_motd,
        templates: cli.template.clone(),
    };
    config.merge_cli_flags(&flags);

    // 2. Open SQLite database
    let home = PathBuf::from(std::env::var("HOME").unwrap());
    let cs_dir = home.join(".closedshell");
    std::fs::create_dir_all(&cs_dir)?;
    let db_path = if let Ok(p) = std::env::var("CLOSEDSHELL_DB") {
        PathBuf::from(p)
    } else {
        cs_dir.join("sessions.db")
    };
    let db = Arc::new(SessionDb::open(&db_path)?);

    // Crash recovery: mark sessions whose PIDs are dead
    for row in db.find_running()? {
        let pid_alive = unsafe { libc::kill(row.pid as i32, 0) } == 0;
        if !pid_alive {
            db.mark_crashed(&row.id)?;
            tracing::info!(session = %row.id, pid = row.pid, "marked crashed session");
        }
    }

    // 2b. Build permission tree early (may be populated by session restore)
    let tree = Arc::new(PermissionTree::new());

    // 2c. Session resume or new session
    // Always generate a fresh session ID (avoids tmpdir/audit-log conflicts).
    // Resume only restores the permission tree rules from the previous session.
    let cwd = std::env::current_dir()?.to_string_lossy().to_string();
    let session_id = generate_session_id();
    let is_resumed = if cli.resume {
        if let Some(existing) = db.find_by_workdir(&cwd)? {
            let rule_rows = db.load_rules(&existing.id)?;
            let rules: Vec<closedshell_lib::permission::Rule> = rule_rows
                .iter()
                .filter_map(|r| serde_json::from_str(&r.rule_json).ok())
                .collect();
            let rule_count = rules.len();
            tree.replace_rules(rules);
            tracing::info!(
                session = %session_id,
                previous = %existing.id,
                rules = rule_count,
                "restored rules from previous session"
            );
            true
        } else {
            false
        }
    } else {
        false
    };

    let task = cli.task.clone();

    // 3. Create tmpdir
    let tmpdir = PathBuf::from(format!("/private/tmp/closedshell-{}", session_id));
    std::fs::create_dir_all(&tmpdir)?;
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

    // Load templates into tree (on top of any restored rules)
    if !cli.template.is_empty() {
        let templates_dir = config::resolve_tilde(&config.sandbox.templates_dir);
        for name in &cli.template {
            let raw = std::path::Path::new(name);
            let path = if raw.exists() {
                PathBuf::from(name)
            } else if raw.with_extension("yaml").exists() {
                raw.with_extension("yaml")
            } else {
                let mut p = PathBuf::from(&templates_dir);
                p.push(format!("{}.yaml", name));
                p
            };
            let yaml = std::fs::read_to_string(&path).map_err(|e| {
                anyhow::anyhow!("failed to load template {}: {}", path.display(), e)
            })?;
            tree.load_template(&yaml)?;
            tracing::info!(template = %path.display(), "loaded permission template");
        }
    }

    // Build session state
    let state = Arc::new(SessionState::new());
    if let Some(ref t) = task {
        state.set_task(t.clone());
    }

    // Build approval queue (used in enforcing mode)
    let approval_queue = Arc::new(ApprovalQueue::new());

    // Build decider + optional IPC handler: yolo vs enforcing
    let (decider, ipc_handler): (Arc<dyn DecisionMaker>, Option<Arc<dyn IpcHandler>>) =
        if config.sandbox.yolo {
            if !cli.allow.is_empty() {
                (
                    Arc::new(PatternDecider {
                        allow_patterns: cli.allow.clone(),
                    }) as Arc<dyn DecisionMaker>,
                    None,
                )
            } else {
                (Arc::new(YoloDecider) as Arc<dyn DecisionMaker>, None)
            }
        } else {
            (
                Arc::new(EnforcingDecider {
                    tree: tree.clone(),
                    state: state.clone(),
                    audit: audit.clone(),
                    approval_queue: approval_queue.clone(),
                }) as Arc<dyn DecisionMaker>,
                Some(Arc::new(EnforcingIpcHandler {
                    tree: tree.clone(),
                    state: state.clone(),
                    audit: audit.clone(),
                    approval_queue: approval_queue.clone(),
                }) as Arc<dyn IpcHandler>),
            )
        };

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
    let ipc_socket_path = format!("{}/ask.sock", tmpdir.display());
    let profile = sandbox::generate_seatbelt_profile(
        actual_port,
        &home.to_string_lossy(),
        &ipc_socket_path,
        &ca_key_path.to_string_lossy(),
    );
    let profile_path = tmpdir.join("profile.sb");
    std::fs::write(&profile_path, &profile)?;

    // 6b. pf enforcement (optional, requires --pf and root)
    let pf_enabled = cli.pf || config.sandbox.pf;
    let _pf_enforcer = if pf_enabled {
        let pf_user = &config.sandbox.pf_user;
        let sandbox_uid = pf::resolve_uid(pf_user)?;

        if !pf::check_anchor_configured()? {
            anyhow::bail!("pf anchor not configured — run `sudo closedshell --pf-setup` first");
        }

        let enforcer = pf::PfEnforcer::new(&session_id, actual_port, sandbox_uid, &tmpdir)?;
        enforcer.load()?;

        // Make tmpdir and its contents accessible to the sandbox user
        let uid_str = sandbox_uid.to_string();
        let status = std::process::Command::new("chown")
            .args(["-R", &format!("{}:staff", pf_user)])
            .arg(&tmpdir)
            .status()?;
        if !status.success() {
            anyhow::bail!("failed to chown tmpdir for sandbox user");
        }

        // Also grant read access to the IPC socket path (will be created by IPC server)
        // The socket directory must be accessible
        let _ = std::process::Command::new("chmod")
            .args(["755", &tmpdir.to_string_lossy()])
            .status();

        eprintln!(
            "[closedshell] pf enforcement active (user: {}, uid: {})",
            pf_user, uid_str
        );
        Some((enforcer, sandbox_uid))
    } else {
        None
    };

    // 6c. Start IPC server (enforcing mode only — TUI uses it for approvals)
    let ipc_handle = if let Some(handler) = ipc_handler {
        let server = IpcServer::new(&ipc_socket_path, handler);
        Some(server.start()?)
    } else {
        None
    };

    // 7. Print MOTD
    if config.sandbox.motd {
        let mode = if config.sandbox.yolo {
            "yolo"
        } else {
            "enforcing"
        };
        let session_tag = if is_resumed { "resumed" } else { "new" };
        eprintln!("[closedshell] session {} ({})", session_id, session_tag);
        if let Some(ref t) = task {
            eprintln!("[closedshell] task: {}", t);
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

    // Register new session in DB (always a new row since we always generate a fresh ID)
    let now = chrono::Utc::now().to_rfc3339();
    {
        db.create_session(&SessionRow {
            id: session_id.clone(),
            workdir: cwd.clone(),
            command: cli.command.join(" "),
            task: task.clone(),
            status: "running".into(),
            templates: serde_json::to_string(&cli.template).unwrap_or_default(),
            pid: std::process::id() as i64,
            port: actual_port,
            log_path: audit.path.to_string_lossy().to_string(),
            created_at: now.clone(),
            last_used: now,
            total_decisions: 0,
            total_denied: 0,
        })?;
    }

    let start_time = std::time::Instant::now();

    // 9. Build and exec sandbox-exec with environment
    let proxy_url = format!("http://localhost:{}", actual_port);

    // Build the env + command args that go inside sandbox-exec
    let mut env_args: Vec<String> = vec![
        format!("HTTPS_PROXY={}", proxy_url),
        format!("HTTP_PROXY={}", proxy_url),
        format!("SSL_CERT_FILE={}", ca_pem_path.display()),
        format!("SSL_CERT_DIR={}", tmpdir.display()),
        "GODEBUG=x509usefallbackroots=1".to_string(),
        format!("CLOSEDSHELL_SOCKET={}/ask.sock", tmpdir.display()),
        format!("CLOSEDSHELL_SESSION={}", session_id),
    ];
    for var in &config.sandbox.passthrough_env {
        if let Ok(val) = std::env::var(var) {
            env_args.push(format!("{}={}", var, val));
        }
    }

    let mut cmd = if let Some((_, _sandbox_uid)) = &_pf_enforcer {
        // pf mode: run sandbox-exec as the dedicated sandbox user via `su`
        // Build the full command string for su -c
        let mut inner_parts: Vec<String> = vec![
            "sandbox-exec".into(),
            "-f".into(),
            profile_path.to_string_lossy().to_string(),
            "env".into(),
        ];
        inner_parts.extend(env_args);
        inner_parts.extend(cli.command.iter().cloned());

        // Shell-escape each part for su -c
        let inner_cmd = inner_parts
            .iter()
            .map(|s| shell_escape(s))
            .collect::<Vec<_>>()
            .join(" ");

        let mut c = tokio::process::Command::new("su");
        c.arg("-m") // preserve environment
            .arg(&config.sandbox.pf_user)
            .arg("-c")
            .arg(&inner_cmd);
        c
    } else {
        // Standard mode: direct sandbox-exec
        let mut c = tokio::process::Command::new("sandbox-exec");
        c.arg("-f").arg(&profile_path).arg("env");
        for arg in &env_args {
            c.arg(arg);
        }
        c.args(&cli.command);
        c
    };

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
    let total_decisions = proxy_stats.total();
    audit.log(AuditPayload::SessionEnd {
        duration_s: duration.as_secs(),
        total_decisions,
        denied: 0,
    })?;

    // Persist permission tree to SQLite
    let current_rules = tree.rules();
    let rule_rows: Vec<RuleRow> = current_rules
        .iter()
        .filter(|r| {
            // Skip consumed one-shot rules
            !matches!(
                r.rule_type,
                Some(closedshell_lib::permission::RuleType::OneShot { consumed: true })
            )
        })
        .map(|r| {
            let effect_str = match r.effect {
                closedshell_lib::permission::Effect::Permit => "permit",
                closedshell_lib::permission::Effect::Forbid => "forbid",
            };
            let type_str = r.rule_type.as_ref().map(|rt| match rt {
                closedshell_lib::permission::RuleType::Idempotent => "idempotent".to_string(),
                closedshell_lib::permission::RuleType::OneShot { .. } => "one-shot".to_string(),
            });
            RuleRow {
                id: r.id.clone(),
                session_id: session_id.clone(),
                effect: effect_str.into(),
                action: r.action.clone(),
                rule_type: type_str,
                rule_json: serde_json::to_string(r).unwrap_or_default(),
                created_at: chrono::Utc::now().to_rfc3339(),
            }
        })
        .collect();

    if let Err(e) = db.persist_rules(&session_id, &rule_rows) {
        tracing::warn!("failed to persist rules: {}", e);
    }
    if let Err(e) = db.update_session(&session_id, "ended", total_decisions, 0) {
        tracing::warn!("failed to update session: {}", e);
    }

    proxy_handle.abort();
    if let Some(h) = ipc_handle {
        h.abort();
    }

    // Remove tmpdir (CA persists in ~/.closedshell/)
    let _ = std::fs::remove_dir_all(&tmpdir);

    tracing::info!(
        session = %session_id,
        duration_s = duration.as_secs(),
        rules_persisted = rule_rows.len(),
        "session ended"
    );

    // Exit with child's exit code
    std::process::exit(exit_code);
}
