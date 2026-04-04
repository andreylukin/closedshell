use clap::Parser;

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

    /// Command to run in sandbox (e.g., "pi", "claude-code")
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    // TODO: implement session lifecycle
    // 1. Load config
    // 2. Generate session ID
    // 3. Start MITM proxy
    // 4. Generate seatbelt profile
    // 5. Print MOTD
    // 6. Open audit log
    // 7. Exec sandbox-exec with command
    // 8. On exit: teardown

    tracing::info!(
        command = ?cli.command,
        yolo = cli.yolo,
        "closedshell starting"
    );

    eprintln!("closedshell: not yet implemented");
    std::process::exit(1);
}
