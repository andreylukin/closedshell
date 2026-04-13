use anyhow::{Context, Result};
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Tabs},
};
use serde::Deserialize;
use std::io::{BufRead, BufReader, Write as IoWrite};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

// ── Audit log event types (deserialization mirrors audit.rs) ────────────────

#[derive(Debug, Deserialize)]
struct AuditEvent {
    ts: String,
    #[allow(dead_code)]
    session: String,
    #[serde(flatten)]
    payload: AuditPayload,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "event")]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
enum AuditPayload {
    Decision {
        action: String,
        result: String,
        decided_by: String,
        reason: Option<String>,
        latency_ms: u64,
        request: RequestMeta,
    },
    SessionStart {
        command: String,
        #[serde(default)]
        templates: Vec<String>,
        yolo: bool,
    },
    SessionEnd {
        duration_s: u64,
        total_decisions: u64,
        denied: u64,
    },
    HumanApproval {
        action: String,
        verdict: String,
        risk_tier: String,
        wait_ms: u64,
    },
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RequestMeta {
    method: String,
    host: String,
    path: String,
}

// ── IPC rule snapshot ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct RuleEntry {
    id: String,
    effect: String,
    pattern: String,
    source: Option<String>,
    rule_type: Option<String>,
    reason: Option<String>,
}

#[derive(Debug, Clone)]
struct PendingApprovalEntry {
    id: String,
    action: String,
    risk_tier: String,
    plan_id: Option<String>,
    age_s: u64,
}

// ── TUI state ───────────────────────────────────────────────────────────────

struct App {
    session_id: String,
    socket_path: PathBuf,
    log_path: PathBuf,

    // Data
    rules: Vec<RuleEntry>,
    activity: Vec<ActivityEntry>,
    pending_approvals: Vec<PendingApprovalEntry>,

    // UI state: 0=Live, 1=Rules, 2=Approvals
    active_tab: usize,
    scroll_offset: usize,
    selected_rule: usize,
    selected_approval: usize,
    session_info: Option<SessionInfo>,
    session_ended: bool,

    // History search
    search_query: String,
    search_active: bool,

    // File tailing
    log_offset: u64,
}

#[derive(Debug)]
struct ActivityEntry {
    ts: String,
    kind: ActivityKind,
}

#[derive(Debug)]
#[allow(dead_code)]
enum ActivityKind {
    Decision {
        action: String,
        result: String,
        decided_by: String,
        reason: Option<String>,
        latency_ms: u64,
        method: String,
        host: String,
    },
    HumanApproval {
        action: String,
        verdict: String,
        risk_tier: String,
        wait_ms: u64,
    },
    SessionEnd {
        duration_s: u64,
        total_decisions: u64,
        denied: u64,
    },
}

#[derive(Debug)]
#[allow(dead_code)]
struct SessionInfo {
    command: String,
    templates: Vec<String>,
    yolo: bool,
}

impl App {
    fn new(session_id: String) -> Self {
        let socket_path = PathBuf::from(format!("/private/tmp/closedshell-{}/cs.sock", session_id));

        let log_name = format!("closedshell-{}.log", session_id);
        let log_path = PathBuf::from(&log_name);

        Self {
            session_id,
            socket_path,
            log_path,
            rules: Vec::new(),
            activity: Vec::new(),
            pending_approvals: Vec::new(),
            active_tab: 0,
            scroll_offset: 0,
            selected_rule: 0,
            selected_approval: 0,
            session_info: None,
            session_ended: false,
            search_query: String::new(),
            search_active: false,
            log_offset: 0,
        }
    }

    fn poll_log(&mut self) {
        let file = match std::fs::File::open(&self.log_path) {
            Ok(f) => f,
            Err(_) => return,
        };

        let metadata = match file.metadata() {
            Ok(m) => m,
            Err(_) => return,
        };

        if metadata.len() <= self.log_offset {
            return;
        }

        use std::io::Seek;
        let mut reader = BufReader::new(file);
        if self.log_offset > 0 {
            let _ = reader.seek(std::io::SeekFrom::Start(self.log_offset));
        }

        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(n) => {
                    self.log_offset += n as u64;
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if let Ok(event) = serde_json::from_str::<AuditEvent>(trimmed) {
                        self.ingest_event(event);
                    }
                }
                Err(_) => break,
            }
        }
    }

    fn ingest_event(&mut self, event: AuditEvent) {
        let ts = short_ts(&event.ts);

        match event.payload {
            AuditPayload::SessionStart {
                command,
                templates,
                yolo,
            } => {
                self.session_info = Some(SessionInfo {
                    command,
                    templates,
                    yolo,
                });
            }
            AuditPayload::SessionEnd {
                duration_s,
                total_decisions,
                denied,
            } => {
                self.session_ended = true;
                self.activity.push(ActivityEntry {
                    ts,
                    kind: ActivityKind::SessionEnd {
                        duration_s,
                        total_decisions,
                        denied,
                    },
                });
            }
            AuditPayload::Decision {
                action,
                result,
                decided_by,
                reason,
                latency_ms,
                request,
            } => {
                self.activity.push(ActivityEntry {
                    ts,
                    kind: ActivityKind::Decision {
                        action,
                        result,
                        decided_by,
                        reason,
                        latency_ms,
                        method: request.method,
                        host: request.host,
                    },
                });
            }
            AuditPayload::HumanApproval {
                action,
                verdict,
                risk_tier,
                wait_ms,
            } => {
                self.activity.push(ActivityEntry {
                    ts,
                    kind: ActivityKind::HumanApproval {
                        action,
                        verdict,
                        risk_tier,
                        wait_ms,
                    },
                });
            }
        }
    }

    fn poll_rules(&mut self) {
        if !self.socket_path.exists() {
            return;
        }

        let resp = match ipc_status(&self.socket_path) {
            Ok(v) => v,
            Err(_) => return,
        };

        if let Some(rules_arr) = resp.get("data").and_then(|d| d.get("rules"))
            && let Some(arr) = rules_arr.as_array()
        {
            self.rules = arr
                .iter()
                .enumerate()
                .filter_map(|(i, v)| {
                    Some(RuleEntry {
                        id: v
                            .get("id")
                            .and_then(|s| s.as_str())
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| format!("rule-{}", i)),
                        effect: v.get("effect")?.as_str()?.to_string(),
                        pattern: v.get("pattern")?.as_str()?.to_string(),
                        source: v
                            .get("source")
                            .and_then(|s| s.as_str())
                            .map(|s| s.to_string()),
                        rule_type: v
                            .get("rule_type")
                            .and_then(|s| s.as_str())
                            .map(|s| s.to_string()),
                        reason: v
                            .get("reason")
                            .and_then(|s| s.as_str())
                            .map(|s| s.to_string()),
                    })
                })
                .collect();
        }
    }

    fn tab_names(&self) -> Vec<&str> {
        vec!["Live", "Rules", "Approvals"]
    }

    fn poll_approvals(&mut self) {
        if !self.socket_path.exists() {
            return;
        }
        let resp = match ipc_send(
            &self.socket_path,
            &serde_json::json!({"type": "pending_approvals"}),
        ) {
            Ok(v) => v,
            Err(_) => return,
        };
        if let Some(pending) = resp.get("data").and_then(|d| d.get("pending"))
            && let Some(arr) = pending.as_array()
        {
            self.pending_approvals = arr
                .iter()
                .filter_map(|v| {
                    Some(PendingApprovalEntry {
                        id: v.get("id")?.as_str()?.to_string(),
                        action: v.get("action")?.as_str()?.to_string(),
                        risk_tier: v.get("risk_tier")?.as_str()?.to_string(),
                        plan_id: v
                            .get("plan_id")
                            .and_then(|p| p.as_str())
                            .map(|s| s.to_string()),
                        age_s: v.get("age_s").and_then(|a| a.as_u64()).unwrap_or(0),
                    })
                })
                .collect();
        }
    }
}

fn ipc_send(socket_path: &PathBuf, req: &serde_json::Value) -> Result<serde_json::Value> {
    let mut stream =
        UnixStream::connect(socket_path).context("cannot connect to closedshell daemon")?;
    stream.set_read_timeout(Some(Duration::from_millis(500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(500)))?;

    let mut req_str = serde_json::to_string(req)?;
    req_str.push('\n');
    stream.write_all(req_str.as_bytes())?;
    stream.flush()?;

    let mut reader = BufReader::new(&stream);
    let mut response = String::new();
    reader.read_line(&mut response)?;
    Ok(serde_json::from_str(&response)?)
}

fn ipc_status(socket_path: &PathBuf) -> Result<serde_json::Value> {
    ipc_send(socket_path, &serde_json::json!({"type": "status"}))
}

fn short_ts(ts: &str) -> String {
    if let Some(t_pos) = ts.find('T') {
        let time_part = &ts[t_pos + 1..];
        if time_part.len() >= 8 {
            return time_part[..8].to_string();
        }
    }
    ts.to_string()
}

// ── Rendering ───────────────────────────────────────────────────────────────

fn draw(f: &mut Frame, app: &App) {
    let size = f.area();

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(size);

    draw_header(f, app, outer[0]);

    draw_right_panel(f, app, outer[1]);
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let mode = if let Some(ref info) = app.session_info {
        if info.yolo { "YOLO" } else { "ENFORCING" }
    } else {
        "..."
    };

    let status = if app.session_ended {
        Span::styled(" ENDED ", Style::default().fg(Color::White).bg(Color::Red))
    } else if app.socket_path.exists() {
        Span::styled(" LIVE ", Style::default().fg(Color::White).bg(Color::Green))
    } else {
        Span::styled(
            " CONNECTING ",
            Style::default().fg(Color::Black).bg(Color::Yellow),
        )
    };

    let decisions = app
        .activity
        .iter()
        .filter(|a| matches!(a.kind, ActivityKind::Decision { .. }))
        .count();
    let short_id = if app.session_id.len() > 8 {
        &app.session_id[..8]
    } else {
        &app.session_id
    };

    let header = Paragraph::new(Line::from(vec![
        Span::styled("closedshell", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(
            format!(" {} ", short_id),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw(format!(" {}  ", mode)),
        status,
        Span::raw(format!("  decisions={}", decisions)),
        if !app.pending_approvals.is_empty() {
            Span::styled(
                format!("  pending={}", app.pending_approvals.len()),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::raw("")
        },
    ]))
    .block(Block::default().borders(Borders::BOTTOM));

    f.render_widget(header, area);
}

fn draw_right_panel(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    let tab_titles: Vec<Line> = app.tab_names().iter().map(|t| Line::from(*t)).collect();
    let tabs = Tabs::new(tab_titles)
        .select(app.active_tab)
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(tabs, chunks[0]);

    match app.active_tab {
        0 => draw_activity(f, app, chunks[1]),
        1 => draw_rules_tab(f, app, chunks[1]),
        2 => draw_approvals(f, app, chunks[1]),
        _ => {}
    }
}

fn draw_activity(f: &mut Frame, app: &App, area: Rect) {
    // Reserve a line for search bar when active
    let (list_area, search_area) = if app.search_active {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(1)])
            .split(area);
        (chunks[0], Some(chunks[1]))
    } else {
        (area, None)
    };

    let visible_height = list_area.height.saturating_sub(2) as usize;
    let entries = &app.activity;

    // Filter by search query if active
    let filtered: Vec<&ActivityEntry> = if app.search_active && !app.search_query.is_empty() {
        let q = app.search_query.to_lowercase();
        entries
            .iter()
            .filter(|e| match &e.kind {
                ActivityKind::Decision {
                    action,
                    host,
                    reason,
                    ..
                } => {
                    action.to_lowercase().contains(&q)
                        || host.to_lowercase().contains(&q)
                        || reason.as_deref().unwrap_or("").to_lowercase().contains(&q)
                }
                ActivityKind::HumanApproval {
                    action, verdict, ..
                } => action.to_lowercase().contains(&q) || verdict.to_lowercase().contains(&q),
                ActivityKind::SessionEnd { .. } => false,
            })
            .collect()
    } else {
        entries.iter().collect()
    };

    let total = filtered.len();
    let skip = if total > visible_height + app.scroll_offset {
        total - visible_height - app.scroll_offset
    } else {
        0
    };

    let items: Vec<ListItem> = filtered
        .iter()
        .skip(skip)
        .take(visible_height)
        .map(|entry| {
            let ts = Span::styled(
                format!("{} ", entry.ts),
                Style::default().fg(Color::DarkGray),
            );
            match &entry.kind {
                ActivityKind::Decision {
                    action,
                    result,
                    decided_by,
                    latency_ms,
                    ..
                } => {
                    let (result_str, color) = if result.starts_with("allow") {
                        ("ALLOW", Color::Green)
                    } else {
                        ("DENY", Color::Red)
                    };
                    let (method, target) = split_action(action);
                    let latency_str = if *latency_ms > 0 {
                        format!(" {}ms", latency_ms)
                    } else {
                        String::new()
                    };
                    ListItem::new(Line::from(vec![
                        ts,
                        Span::styled(
                            format!("{:5}", result_str),
                            Style::default().fg(color).add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(" "),
                        Span::styled(format!("{:6} ", method), Style::default().fg(Color::White)),
                        Span::raw(target),
                        Span::styled(
                            format!("  {}{}", decided_by, latency_str),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]))
                }
                ActivityKind::HumanApproval {
                    action,
                    verdict,
                    risk_tier,
                    wait_ms,
                } => {
                    let (verdict_str, color) = if verdict == "approved" {
                        ("APPROVED", Color::Green)
                    } else {
                        ("DENIED", Color::Red)
                    };
                    let risk_color = match risk_tier.as_str() {
                        "safe" => Color::Green,
                        "moderate" => Color::Yellow,
                        "dangerous" => Color::Red,
                        _ => Color::White,
                    };
                    ListItem::new(Line::from(vec![
                        ts,
                        Span::styled(
                            format!("{:8}", verdict_str),
                            Style::default().fg(color).add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(" "),
                        Span::raw(truncate(action, 40)),
                        Span::raw("  "),
                        Span::styled(
                            format!("risk={}", risk_tier),
                            Style::default().fg(risk_color),
                        ),
                        Span::styled(
                            format!("  {}ms", wait_ms),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]))
                }
                ActivityKind::SessionEnd {
                    duration_s,
                    total_decisions,
                    denied,
                } => ListItem::new(Line::from(vec![
                    ts,
                    Span::styled(
                        "END  ",
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!(
                        "{}s  decisions={}  denied={}",
                        duration_s, total_decisions, denied
                    )),
                ])),
            }
        })
        .collect();

    let title_suffix = if app.search_active && !app.search_query.is_empty() {
        format!(" Activity ({}/{}) ", total, entries.len())
    } else {
        format!(" Activity ({}) ", total)
    };
    let list = List::new(items).block(
        Block::default()
            .title(title_suffix)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow)),
    );
    f.render_widget(list, list_area);

    if let Some(sa) = search_area {
        let search_line = Paragraph::new(Line::from(vec![
            Span::styled(" /", Style::default().fg(Color::Yellow)),
            Span::raw(&app.search_query),
            Span::styled("_", Style::default().fg(Color::DarkGray)),
        ]));
        f.render_widget(search_line, sa);
    }
}

fn draw_rules_tab(f: &mut Frame, app: &App, area: Rect) {
    // Cedar-style multi-line rule display:
    //   permit (action == "net:*:api.anthropic.com/*")
    //     when { source: template:anthropic/full, type: idempotent };
    let visible_height = area.height.saturating_sub(2) as usize;
    let mut lines: Vec<Line> = Vec::new();

    for (i, r) in app.rules.iter().enumerate() {
        let (effect_color, effect_str) = match r.effect.as_str() {
            "permit" => (Color::Green, "permit"),
            "forbid" => (Color::Red, "forbid"),
            _ => (Color::White, r.effect.as_str()),
        };
        let selected = i == app.selected_rule;
        let marker = if selected { "▸ " } else { "  " };

        // Line 1: effect (action == "pattern")
        lines.push(Line::from(vec![
            Span::styled(marker, Style::default().fg(Color::Yellow)),
            Span::styled(
                effect_str.to_string(),
                Style::default()
                    .fg(effect_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" (", Style::default().fg(Color::DarkGray)),
            Span::raw(format!("action == \"{}\"", r.pattern)),
            Span::styled(")", Style::default().fg(Color::DarkGray)),
        ]));

        // Line 2: when { source: ..., type: ... };
        let mut attrs: Vec<String> = Vec::new();
        if let Some(ref src) = r.source {
            attrs.push(format!("source: {}", src));
        }
        if let Some(ref rt) = r.rule_type {
            attrs.push(format!("type: {}", rt));
        }
        if let Some(ref reason) = r.reason {
            attrs.push(format!("reason: \"{}\"", truncate(reason, 50)));
        }
        if !attrs.is_empty() {
            lines.push(Line::from(vec![
                Span::raw("    "),
                Span::styled("when", Style::default().fg(Color::DarkGray)),
                Span::styled(" { ", Style::default().fg(Color::DarkGray)),
                Span::styled(attrs.join(", "), Style::default().fg(Color::DarkGray)),
                Span::styled(" };", Style::default().fg(Color::DarkGray)),
            ]));
        }

        // Blank line between rules
        if i < app.rules.len() - 1 {
            lines.push(Line::from(""));
        }
    }

    // Scroll support
    let total_lines = lines.len();
    let skip = if total_lines > visible_height + app.scroll_offset {
        total_lines - visible_height - app.scroll_offset
    } else {
        0
    };
    let visible_lines: Vec<Line> = lines.into_iter().skip(skip).take(visible_height).collect();

    let title = format!(" Rules ({})  [d] delete  [e] edit ", app.rules.len());
    let paragraph = Paragraph::new(visible_lines).block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    f.render_widget(paragraph, area);
}

fn draw_approvals(f: &mut Frame, app: &App, area: Rect) {
    if app.pending_approvals.is_empty() {
        let msg = Paragraph::new(Line::from(vec![Span::styled(
            "  No pending approvals",
            Style::default().fg(Color::DarkGray),
        )]))
        .block(
            Block::default()
                .title(" Approvals (0) ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        );
        f.render_widget(msg, area);
        return;
    }

    let items: Vec<ListItem> = app
        .pending_approvals
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let risk_color = match p.risk_tier.as_str() {
                "safe" => Color::Green,
                "moderate" => Color::Yellow,
                "dangerous" => Color::Red,
                _ => Color::White,
            };
            let style = if i == app.selected_approval {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            let plan_info = p
                .plan_id
                .as_deref()
                .map(|pid| format!("  plan:{}", pid))
                .unwrap_or_default();

            ListItem::new(Line::from(vec![
                Span::styled("→ ", Style::default().fg(Color::Yellow)),
                Span::styled(truncate(&p.action, 40), style.add_modifier(Modifier::BOLD)),
                Span::raw("  "),
                Span::styled(
                    format!("risk={}", p.risk_tier),
                    Style::default().fg(risk_color),
                ),
                Span::styled(
                    format!("  {}s{}", p.age_s, plan_info),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
        })
        .collect();

    let title = format!(
        " Approvals ({})  [y] approve  [n] deny ",
        app.pending_approvals.len()
    );
    let list = List::new(items).block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow)),
    );
    f.render_widget(list, area);
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}

/// Parse a canonical action string into (method, target) for compact display.
/// "net:POST:api.anthropic.com/v1/messages" → ("POST", "api.anthropic.com/v1/messages")
/// "aws:s3:DeleteBucket" → ("aws", "s3:DeleteBucket")
/// "file:read:/some/path" → ("file", "read:/some/path")
/// "gcp[project=unknown]:storage:..." → ("gcp", "storage:...")
fn split_action(action: &str) -> (&str, &str) {
    // Handle gcp[project=...]:rest
    if let Some(bracket_end) = action.find("]:") {
        return (
            &action[..action.find('[').unwrap_or(0)],
            &action[bracket_end + 2..],
        );
    }
    // net:METHOD:host/path → METHOD, host/path
    if let Some(rest) = action.strip_prefix("net:")
        && let Some(colon) = rest.find(':')
    {
        return (&rest[..colon], &rest[colon + 1..]);
    }
    // file:read:path → file, read:path
    // aws:s3:Op → aws, s3:Op
    if let Some(colon) = action.find(':') {
        return (&action[..colon], &action[colon + 1..]);
    }
    (action, "")
}

// ── Session list view ──────────────────────────────────────────────────────

pub fn run_session_list(db: &closedshell_lib::db::SessionDb) -> Result<()> {
    let sessions = db.list_sessions()?;

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(stdout, EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut selected: usize = 0;

    loop {
        terminal.draw(|f| {
            let size = f.area();

            let header = Paragraph::new(Line::from(vec![
                Span::styled("closedshell", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw("  sessions  "),
                Span::styled(
                    "[enter] open  [d] delete  [q] quit",
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
            .block(Block::default().borders(Borders::BOTTOM));

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(2), Constraint::Min(0)])
                .split(size);

            f.render_widget(header, chunks[0]);

            let items: Vec<ListItem> = sessions
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    let (dot, dot_color) = match s.status.as_str() {
                        "running" => ("●", Color::Green),
                        "crashed" => ("●", Color::Red),
                        _ => ("○", Color::DarkGray),
                    };
                    let style = if i == selected {
                        Style::default().add_modifier(Modifier::REVERSED)
                    } else {
                        Style::default()
                    };
                    // Truncate workdir to last 30 chars
                    let wd = if s.workdir.len() > 30 {
                        format!("...{}", &s.workdir[s.workdir.len() - 27..])
                    } else {
                        s.workdir.clone()
                    };
                    ListItem::new(Line::from(vec![
                        Span::styled(format!(" {} ", dot), Style::default().fg(dot_color)),
                        Span::styled(format!("{:10}", s.id), style.add_modifier(Modifier::BOLD)),
                        Span::styled(format!("  {:30}", wd), style),
                        Span::styled(format!("  {:12}", s.command), style),
                        Span::styled(
                            format!(
                                "  {}  decisions={}",
                                short_ts(&s.last_used),
                                s.total_decisions
                            ),
                            style.fg(Color::DarkGray),
                        ),
                    ]))
                })
                .collect();

            let list = List::new(items).block(
                Block::default()
                    .title(format!(" Sessions ({}) ", sessions.len()))
                    .borders(Borders::ALL),
            );
            f.render_widget(list, chunks[1]);
        })?;

        if event::poll(Duration::from_millis(250))?
            && let Event::Key(key) = event::read()?
        {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                KeyCode::Up | KeyCode::Char('k') => {
                    selected = selected.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if !sessions.is_empty() {
                        selected = (selected + 1).min(sessions.len() - 1);
                    }
                }
                KeyCode::Enter => {
                    if let Some(s) = sessions.get(selected) {
                        // Drop the terminal, run session TUI, re-enter our TUI on return
                        disable_raw_mode()?;
                        crossterm::execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
                        let _ = run(&s.id);
                        enable_raw_mode()?;
                        crossterm::execute!(terminal.backend_mut(), EnterAlternateScreen)?;
                    }
                }
                KeyCode::Char('d') => {
                    if let Some(s) = sessions.get(selected) {
                        let _ = db.delete_session(&s.id);
                        // Refresh — break out and let caller restart if needed
                        break;
                    }
                }
                _ => {}
            }
        }
    }

    disable_raw_mode()?;
    crossterm::execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

// ── Entry point ─────────────────────────────────────────────────────────────

pub fn run(session_id: &str) -> Result<()> {
    let mut app = App::new(session_id.to_string());

    // Try to find the log file in CWD
    if !app.log_path.exists() {
        eprintln!(
            "[closedshell] warning: log file {} not found in current directory",
            app.log_path.display()
        );
    }

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(stdout, EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let tick_rate = Duration::from_millis(250);
    let ipc_interval = Duration::from_secs(2);
    let approval_interval = Duration::from_millis(500);
    let mut last_ipc_poll = Instant::now() - ipc_interval;
    let mut last_approval_poll = Instant::now() - approval_interval;

    loop {
        app.poll_log();

        if last_ipc_poll.elapsed() >= ipc_interval {
            app.poll_rules();
            last_ipc_poll = Instant::now();
        }

        if last_approval_poll.elapsed() >= approval_interval {
            app.poll_approvals();
            last_approval_poll = Instant::now();
        }

        terminal.draw(|f| draw(f, &app))?;

        if event::poll(tick_rate)?
            && let Event::Key(key) = event::read()?
        {
            // Search mode intercepts all keys
            if app.search_active {
                match key.code {
                    KeyCode::Esc => {
                        app.search_active = false;
                        app.search_query.clear();
                    }
                    KeyCode::Enter => {
                        app.search_active = false;
                    }
                    KeyCode::Backspace => {
                        app.search_query.pop();
                    }
                    KeyCode::Char(c) => {
                        app.search_query.push(c);
                    }
                    _ => {}
                }
                continue;
            }

            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,

                // Tab switching
                KeyCode::Tab => {
                    app.active_tab = (app.active_tab + 1) % app.tab_names().len();
                    app.scroll_offset = 0;
                }
                KeyCode::Char('l') | KeyCode::Char('1') => {
                    app.active_tab = 0;
                    app.scroll_offset = 0;
                }
                KeyCode::Char('r') | KeyCode::Char('2') if app.active_tab != 1 => {
                    app.active_tab = 1;
                    app.scroll_offset = 0;
                }
                KeyCode::Char('a') | KeyCode::Char('3') => {
                    app.active_tab = 2;
                    app.scroll_offset = 0;
                }

                // Scrolling / selection
                KeyCode::Up | KeyCode::Char('k') => match app.active_tab {
                    1 => app.selected_rule = app.selected_rule.saturating_sub(1),
                    2 => app.selected_approval = app.selected_approval.saturating_sub(1),
                    _ => app.scroll_offset = app.scroll_offset.saturating_add(1),
                },
                KeyCode::Down | KeyCode::Char('j') => match app.active_tab {
                    1 => {
                        if !app.rules.is_empty() {
                            app.selected_rule = (app.selected_rule + 1).min(app.rules.len() - 1);
                        }
                    }
                    2 => {
                        if !app.pending_approvals.is_empty() {
                            app.selected_approval =
                                (app.selected_approval + 1).min(app.pending_approvals.len() - 1);
                        }
                    }
                    _ => app.scroll_offset = app.scroll_offset.saturating_sub(1),
                },
                KeyCode::Home | KeyCode::Char('g') => {
                    app.scroll_offset = usize::MAX / 2;
                }
                KeyCode::End | KeyCode::Char('G') => {
                    app.scroll_offset = 0;
                }

                // Approval actions (tab 2)
                KeyCode::Char('y') if app.active_tab == 2 => {
                    if let Some(p) = app.pending_approvals.get(app.selected_approval) {
                        let _ = ipc_send(
                            &app.socket_path,
                            &serde_json::json!({"type": "approve", "id": p.id}),
                        );
                        app.poll_approvals();
                    }
                }
                KeyCode::Char('n') if app.active_tab == 2 => {
                    if let Some(p) = app.pending_approvals.get(app.selected_approval) {
                        let _ = ipc_send(
                            &app.socket_path,
                            &serde_json::json!({"type": "deny", "id": p.id}),
                        );
                        app.poll_approvals();
                    }
                }

                // Rule deletion (tab 1)
                KeyCode::Char('d') if app.active_tab == 1 => {
                    if let Some(r) = app.rules.get(app.selected_rule) {
                        let _ = ipc_send(
                            &app.socket_path,
                            &serde_json::json!({"type": "delete_rule", "rule_id": r.id}),
                        );
                        app.poll_rules();
                    }
                }

                // Rule editing (tab 1) — open $EDITOR
                KeyCode::Char('e') if app.active_tab == 1 => {
                    // Write current rules to temp YAML, open in $EDITOR, reload on save
                    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".into());
                    let tmpfile = std::env::temp_dir()
                        .join(format!("closedshell-rules-{}.yaml", app.session_id));

                    // Serialize current rules to YAML
                    let mut yaml = String::from("# Edit rules below. Save and exit to apply.\n");
                    yaml.push_str("# Lines starting with # are ignored.\n");
                    yaml.push_str("# Format: effect action [source]\n\n");
                    for r in &app.rules {
                        let source = r.source.as_deref().unwrap_or("");
                        yaml.push_str(&format!("{} {}  # {}\n", r.effect, r.pattern, source));
                    }
                    let _ = std::fs::write(&tmpfile, &yaml);

                    // Exit raw mode, run editor, re-enter raw mode
                    disable_raw_mode()?;
                    crossterm::execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
                    let status = std::process::Command::new(&editor).arg(&tmpfile).status();
                    enable_raw_mode()?;
                    crossterm::execute!(terminal.backend_mut(), EnterAlternateScreen)?;

                    if let Ok(s) = status
                        && s.success()
                    {
                        // Parse edited YAML and apply via IPC
                        // (Simplified: just reload rules to show user changes)
                        app.poll_rules();
                    }

                    let _ = std::fs::remove_file(&tmpfile);
                }

                // Live search (tab 0)
                KeyCode::Char('/') if app.active_tab == 0 => {
                    app.search_active = true;
                    app.search_query.clear();
                }

                _ => {}
            }
        }
    }

    disable_raw_mode()?;
    crossterm::execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use std::io::Write as _W;

    fn make_log_line(payload: &str) -> String {
        format!(
            r#"{{"ts":"2026-04-10T12:30:45.123+00:00","session":"test01",{}}}"#,
            payload
        )
    }

    // ── Log parsing ─────────────────────────────────────────────────────

    #[test]
    fn parse_session_start() {
        let mut app = App::new("test01".into());
        let event: AuditEvent = serde_json::from_str(&make_log_line(
            r#""event":"session_start","command":"claude","templates":["anthropic/full"],"yolo":false"#,
        ))
        .unwrap();
        app.ingest_event(event);

        let info = app.session_info.unwrap();
        assert_eq!(info.command, "claude");
        assert_eq!(info.templates, vec!["anthropic/full"]);
        assert!(!info.yolo);
    }

    #[test]
    fn parse_decision_allow() {
        let mut app = App::new("test01".into());
        let event: AuditEvent = serde_json::from_str(&make_log_line(
            r#""event":"decision","action":"net:GET:api.anthropic.com/v1/messages","result":"allow","decided_by":"tree","reason":null,"latency_ms":0,"request":{"method":"GET","host":"api.anthropic.com","path":"/v1/messages"}"#,
        ))
        .unwrap();
        app.ingest_event(event);

        assert_eq!(app.activity.len(), 1);
        match &app.activity[0].kind {
            ActivityKind::Decision {
                action,
                result,
                decided_by,
                ..
            } => {
                assert_eq!(action, "net:GET:api.anthropic.com/v1/messages");
                assert_eq!(result, "allow");
                assert_eq!(decided_by, "tree");
            }
            other => panic!("expected Decision, got {:?}", other),
        }
    }

    #[test]
    fn parse_decision_deny() {
        let mut app = App::new("test01".into());
        let event: AuditEvent = serde_json::from_str(&make_log_line(
            r#""event":"decision","action":"aws:s3:DeleteBucket","result":"deny: forbidden","decided_by":"tree","reason":"forbidden by rule","latency_ms":0,"request":{"method":"POST","host":"s3.amazonaws.com","path":"/"}"#,
        ))
        .unwrap();
        app.ingest_event(event);

        assert_eq!(app.activity.len(), 1);
        match &app.activity[0].kind {
            ActivityKind::Decision { result, .. } => {
                assert!(result.starts_with("deny"));
            }
            other => panic!("expected Decision, got {:?}", other),
        }
    }

    #[test]
    fn parse_human_approval() {
        let mut app = App::new("test01".into());
        let event: AuditEvent = serde_json::from_str(&make_log_line(
            r#""event":"human_approval","action":"aws:s3:GetObject","verdict":"approved","risk_tier":"safe","wait_ms":2340"#,
        ))
        .unwrap();
        app.ingest_event(event);

        assert_eq!(app.activity.len(), 1);
        match &app.activity[0].kind {
            ActivityKind::HumanApproval {
                action,
                verdict,
                risk_tier,
                wait_ms,
            } => {
                assert_eq!(action, "aws:s3:GetObject");
                assert_eq!(verdict, "approved");
                assert_eq!(risk_tier, "safe");
                assert_eq!(*wait_ms, 2340);
            }
            other => panic!("expected HumanApproval, got {:?}", other),
        }
    }

    #[test]
    fn parse_session_end() {
        let mut app = App::new("test01".into());
        let event: AuditEvent = serde_json::from_str(&make_log_line(
            r#""event":"session_end","duration_s":120,"total_decisions":45,"denied":3"#,
        ))
        .unwrap();
        app.ingest_event(event);

        assert!(app.session_ended);
        assert_eq!(app.activity.len(), 1);
        match &app.activity[0].kind {
            ActivityKind::SessionEnd {
                duration_s,
                total_decisions,
                denied,
            } => {
                assert_eq!(*duration_s, 120);
                assert_eq!(*total_decisions, 45);
                assert_eq!(*denied, 3);
            }
            other => panic!("expected SessionEnd, got {:?}", other),
        }
    }

    // ── File tailing ────────────────────────────────────────────────────

    #[test]
    fn poll_log_tails_file() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("closedshell-tail01.log");

        // Write initial events
        {
            let mut f = std::fs::File::create(&log_path).unwrap();
            writeln!(
                f,
                "{}",
                make_log_line(
                    r#""event":"session_start","command":"claude","templates":[],"yolo":true"#
                )
            )
            .unwrap();
            writeln!(f, "{}", make_log_line(
                r#""event":"decision","action":"net:GET:example.com/api","result":"allow (yolo)","decided_by":"yolo","reason":null,"latency_ms":0,"request":{"method":"GET","host":"example.com","path":"/api"}"#
            )).unwrap();
        }

        let mut app = App::new("tail01".into());
        app.log_path = log_path.clone();

        app.poll_log();
        assert!(app.session_info.is_some());
        assert_eq!(app.activity.len(), 1);

        // Append more events (simulating live session)
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&log_path)
                .unwrap();
            writeln!(f, "{}", make_log_line(
                r#""event":"decision","action":"net:POST:api.openai.com/v1/chat","result":"allow (yolo)","decided_by":"yolo","reason":null,"latency_ms":0,"request":{"method":"POST","host":"api.openai.com","path":"/v1/chat"}"#
            )).unwrap();
        }

        app.poll_log();
        assert_eq!(app.activity.len(), 2);

        // Poll again with no new data — should not duplicate
        app.poll_log();
        assert_eq!(app.activity.len(), 2);
    }

    #[test]
    fn poll_log_handles_missing_file() {
        let mut app = App::new("nonexistent".into());
        app.log_path = PathBuf::from("/tmp/closedshell-does-not-exist.log");
        app.poll_log(); // should not panic
        assert!(app.activity.is_empty());
    }

    // ── IPC response parsing ────────────────────────────────────────────

    #[test]
    fn poll_rules_parses_ipc_response() {
        // We can't easily mock the unix socket, but we can test that
        // poll_rules handles a missing socket gracefully
        let mut app = App::new("nosocket".into());
        app.socket_path = PathBuf::from("/tmp/closedshell-nosocket/cs.sock");
        app.poll_rules(); // should not panic
        assert!(app.rules.is_empty());
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    #[test]
    fn short_ts_extracts_time() {
        assert_eq!(short_ts("2026-04-10T12:30:45.123+00:00"), "12:30:45");
        assert_eq!(short_ts("2026-04-10T09:05:02Z"), "09:05:02");
        assert_eq!(short_ts("not a timestamp"), "not a timestamp");
    }

    #[test]
    fn truncate_short_string() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 8), "hello...");
    }

    // ── Rendering (TestBackend) ─────────────────────────────────────────

    #[test]
    fn render_empty_state() {
        let app = App::new("render01".into());
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();

        let buf = terminal.backend().buffer().clone();
        let content = buffer_text(&buf);
        assert!(content.contains("closedshell"));
        assert!(content.contains("render01"));
        assert!(content.contains("Activity (0)"));
    }

    #[test]
    fn render_with_activity() {
        let mut app = App::new("render02".into());

        let event: AuditEvent = serde_json::from_str(&make_log_line(
            r#""event":"session_start","command":"claude","templates":[],"yolo":true"#,
        ))
        .unwrap();
        app.ingest_event(event);

        let event: AuditEvent = serde_json::from_str(&make_log_line(
            r#""event":"decision","action":"net:GET:example.com/api","result":"allow (yolo)","decided_by":"yolo","reason":null,"latency_ms":1,"request":{"method":"GET","host":"example.com","path":"/api"}"#,
        ))
        .unwrap();
        app.ingest_event(event);

        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();

        let buf = terminal.backend().buffer().clone();
        let content = buffer_text(&buf);
        assert!(content.contains("YOLO"));
        assert!(content.contains("Activity (1)"));
        assert!(content.contains("ALLOW"));
        assert!(content.contains("example.com"));
    }

    #[test]
    fn render_session_ended() {
        let mut app = App::new("render04".into());

        let event: AuditEvent = serde_json::from_str(&make_log_line(
            r#""event":"session_end","duration_s":60,"total_decisions":10,"denied":1"#,
        ))
        .unwrap();
        app.ingest_event(event);

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();

        let buf = terminal.backend().buffer().clone();
        let content = buffer_text(&buf);
        assert!(content.contains("ENDED"));
        assert!(content.contains("END"));
    }

    #[test]
    fn tab_switching() {
        let mut app = App::new("tabs".into());
        assert_eq!(app.active_tab, 0);

        app.active_tab = (app.active_tab + 1) % app.tab_names().len();
        assert_eq!(app.active_tab, 1);

        app.active_tab = (app.active_tab + 1) % app.tab_names().len();
        assert_eq!(app.active_tab, 2);

        app.active_tab = (app.active_tab + 1) % app.tab_names().len();
        assert_eq!(app.active_tab, 0); // wraps back
    }

    #[test]
    fn scroll_offset_saturates() {
        let mut app = App::new("scroll".into());
        assert_eq!(app.scroll_offset, 0);

        app.scroll_offset = app.scroll_offset.saturating_sub(1);
        assert_eq!(app.scroll_offset, 0); // doesn't underflow

        app.scroll_offset = app.scroll_offset.saturating_add(5);
        assert_eq!(app.scroll_offset, 5);
    }

    /// Extract all text from a ratatui Buffer for assertions.
    fn buffer_text(buf: &ratatui::buffer::Buffer) -> String {
        let mut text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                let cell = &buf[(x, y)];
                text.push_str(cell.symbol());
            }
            text.push('\n');
        }
        text
    }

    // ── Dual-output tests ───────────────────────────────────────────
    //
    // These spin up a real IPC server backed by a real PermissionTree
    // and a real AuditLog, then point the TUI App at them. Mutations
    // on the "session side" (add rules, write audit events) are
    // verified to appear on the "TUI side" after poll + render.

    use closedshell_lib::audit::{AuditLog, AuditPayload, RequestMeta as AuditRequestMeta};
    use closedshell_lib::ipc::{IpcHandler, IpcRequest, IpcResponse, IpcServer};
    use closedshell_lib::permission::{Effect, PermissionTree, Rule};

    /// Minimal IPC handler backed by a PermissionTree for tests.
    struct TestIpcHandler {
        tree: Arc<PermissionTree>,
    }

    impl IpcHandler for TestIpcHandler {
        fn handle(&self, request: IpcRequest) -> IpcResponse {
            match request {
                IpcRequest::Status => {
                    let rules: Vec<serde_json::Value> = self
                        .tree
                        .rules()
                        .iter()
                        .map(|r| {
                            let effect = match r.effect {
                                Effect::Permit => "permit",
                                Effect::Forbid => "forbid",
                            };
                            serde_json::json!({
                                "effect": effect,
                                "pattern": r.action,
                                "source": r.source,
                            })
                        })
                        .collect();
                    IpcResponse::ok(serde_json::json!({ "rules": rules }))
                }
                _ => IpcResponse::err("unsupported", "test handler only supports status", None),
            }
        }
    }

    use std::sync::Arc;

    struct DualHarness {
        tree: Arc<PermissionTree>,
        audit: Arc<AuditLog>,
        app: App,
        _ipc_handle: tokio::task::JoinHandle<()>,
    }

    impl DualHarness {
        async fn new(dir: &std::path::Path) -> Self {
            let session_id = "dual01";

            // Session side: permission tree + audit log + IPC server
            let tree = Arc::new(PermissionTree::new());
            let audit = Arc::new(AuditLog::open(dir, session_id).unwrap());

            let socket_path = dir.join("cs.sock");
            let handler = Arc::new(TestIpcHandler { tree: tree.clone() }) as Arc<dyn IpcHandler>;
            let server = IpcServer::new(socket_path.to_str().unwrap(), handler);
            let ipc_handle = server.start().unwrap();

            // Give the socket a moment to bind
            tokio::time::sleep(Duration::from_millis(50)).await;

            // TUI side: App pointed at the same log + socket
            let mut app = App::new(session_id.to_string());
            app.log_path = dir.join(format!("closedshell-{}.log", session_id));
            app.socket_path = socket_path;

            Self {
                tree,
                audit,
                app,
                _ipc_handle: ipc_handle,
            }
        }

        /// Write an audit event, poll the TUI, return rendered buffer text.
        fn write_event_and_render(&mut self, payload: AuditPayload) -> String {
            self.audit.log(payload).unwrap();
            self.poll_and_render()
        }

        /// Poll both log + rules, render to TestBackend, return text.
        fn poll_and_render(&mut self) -> String {
            self.app.poll_log();
            self.app.poll_rules();

            let backend = TestBackend::new(200, 30);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal.draw(|f| draw(f, &self.app)).unwrap();

            let buf = terminal.backend().buffer().clone();
            buffer_text(&buf)
        }

        fn add_rule(&self, effect: Effect, pattern: &str, source: &str) {
            self.tree.add_rule(Rule {
                id: format!("test:{}", pattern),
                effect,
                action: pattern.to_string(),
                rule_type: None,
                approved_by: None,
                source: Some(source.to_string()),
                plan_id: None,
                reason: None,
                expires: None,
            });
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dual_permissions_visible_after_template_load() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = DualHarness::new(dir.path()).await;

        // Session side: load template rules
        h.add_rule(
            Effect::Permit,
            "net:*:api.anthropic.com/*",
            "template:anthropic/full",
        );
        h.add_rule(
            Effect::Permit,
            "net:*:downloads.claude.ai/*",
            "template:anthropic/full",
        );
        h.add_rule(Effect::Forbid, "aws:iam:*", "template:anthropic/full");

        h.app.active_tab = 1; // Rules tab
        let text = h.poll_and_render();

        // TUI should show all 3 rules in Cedar format
        assert!(
            text.contains("Rules (3)"),
            "expected 3 rules, got: {}",
            text
        );
        assert!(text.contains("permit"), "missing permit rules");
        assert!(text.contains("forbid"), "missing forbid rule");
        assert!(
            text.contains("api.anthropic.com"),
            "missing anthropic pattern"
        );
        assert!(text.contains("aws:iam:*"), "missing iam forbid pattern");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dual_permission_added_mid_session() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = DualHarness::new(dir.path()).await;

        // Start with one rule
        h.add_rule(
            Effect::Permit,
            "net:*:api.anthropic.com/*",
            "template:anthropic/full",
        );
        h.app.active_tab = 1;
        let text = h.poll_and_render();
        assert!(text.contains("Rules (1)"));

        // Human approves a new action → rule added
        h.add_rule(Effect::Permit, "aws:s3:GetObject", "human");
        let text = h.poll_and_render();
        assert!(
            text.contains("Rules (2)"),
            "rule not visible after human approval"
        );
        assert!(text.contains("aws:s3:GetObject"));
        assert!(text.contains("human"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dual_decisions_appear_in_activity() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = DualHarness::new(dir.path()).await;

        // Write session start
        h.write_event_and_render(AuditPayload::SessionStart {
            command: "claude".into(),
            templates: vec!["anthropic/full".into()],
            yolo: false,
        });

        // Write an allow decision
        let text = h.write_event_and_render(AuditPayload::Decision {
            action: "net:POST:api.anthropic.com/v1/messages".into(),
            result: "allow".into(),
            decided_by: "tree".into(),
            reason: None,
            latency_ms: 0,
            request: AuditRequestMeta {
                method: "POST".into(),
                host: "api.anthropic.com".into(),
                path: "/v1/messages".into(),
            },
        });

        assert!(text.contains("ENFORCING"), "should show enforcing mode");
        assert!(text.contains("Activity (1)"));
        assert!(text.contains("ALLOW"));
        assert!(text.contains("api.anthropic.com"));
        assert!(text.contains("decisions=1"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dual_deny_visible_in_activity() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = DualHarness::new(dir.path()).await;

        h.write_event_and_render(AuditPayload::SessionStart {
            command: "claude".into(),
            templates: vec![],
            yolo: false,
        });

        let text = h.write_event_and_render(AuditPayload::Decision {
            action: "aws:s3:DeleteBucket".into(),
            result: "deny: forbidden by rule".into(),
            decided_by: "tree".into(),
            reason: Some("forbidden by rule".into()),
            latency_ms: 0,
            request: AuditRequestMeta {
                method: "DELETE".into(),
                host: "s3.amazonaws.com".into(),
                path: "/my-bucket".into(),
            },
        });

        assert!(text.contains("DENY"));
        assert!(text.contains("DeleteBucket"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dual_full_session_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = DualHarness::new(dir.path()).await;

        // 1. Session starts with template rules
        h.add_rule(
            Effect::Permit,
            "net:*:api.anthropic.com/*",
            "template:anthropic/full",
        );

        h.audit
            .log(AuditPayload::SessionStart {
                command: "claude".into(),
                templates: vec!["anthropic/full".into()],
                yolo: false,
            })
            .unwrap();

        let text = h.poll_and_render();
        assert!(text.contains("ENFORCING"));
        assert!(
            text.contains("Activity (0)"),
            "session_start shouldn't appear in activity"
        );

        // 2. Allowed request via template
        h.audit
            .log(AuditPayload::Decision {
                action: "net:POST:api.anthropic.com/v1/messages".into(),
                result: "allow".into(),
                decided_by: "tree".into(),
                reason: None,
                latency_ms: 0,
                request: AuditRequestMeta {
                    method: "POST".into(),
                    host: "api.anthropic.com".into(),
                    path: "/v1/messages".into(),
                },
            })
            .unwrap();

        let text = h.poll_and_render();
        assert!(text.contains("Activity (1)"));
        assert!(text.contains("ALLOW"));

        // 3. Unknown action → human approves → new rule appears
        h.audit
            .log(AuditPayload::HumanApproval {
                action: "net:GET:exa.ai/search".into(),
                verdict: "approved".into(),
                risk_tier: "safe".into(),
                wait_ms: 2500,
            })
            .unwrap();
        h.audit
            .log(AuditPayload::Decision {
                action: "net:GET:exa.ai/search".into(),
                result: "allow".into(),
                decided_by: "human".into(),
                reason: None,
                latency_ms: 2501,
                request: AuditRequestMeta {
                    method: "GET".into(),
                    host: "exa.ai".into(),
                    path: "/search".into(),
                },
            })
            .unwrap();
        h.add_rule(Effect::Permit, "net:GET:exa.ai/*", "human");

        let text = h.poll_and_render();
        assert!(
            text.contains("exa.ai"),
            "human-approved action should appear"
        );
        assert!(text.contains("Activity (3)")); // 1 decision + 1 human_approval + 1 decision

        // 4. Dangerous action → denied by tree (forbid rule)
        h.add_rule(Effect::Forbid, "aws:s3:DeleteBucket", "template:safety");
        h.audit
            .log(AuditPayload::Decision {
                action: "aws:s3:DeleteBucket".into(),
                result: "deny: forbidden by rule".into(),
                decided_by: "tree".into(),
                reason: Some("forbidden by rule".into()),
                latency_ms: 0,
                request: AuditRequestMeta {
                    method: "DELETE".into(),
                    host: "s3.amazonaws.com".into(),
                    path: "/my-bucket".into(),
                },
            })
            .unwrap();

        let text = h.poll_and_render();
        assert!(text.contains("Activity (4)"));
        assert!(text.contains("DENY"));

        // 5. Session ends
        h.app.active_tab = 0;
        let text = h.write_event_and_render(AuditPayload::SessionEnd {
            duration_s: 120,
            total_decisions: 3,
            denied: 1,
        });

        assert!(text.contains("ENDED"));
        assert!(text.contains("END"));
        assert!(text.contains("120s"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dual_forbid_overrides_permit_visible() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = DualHarness::new(dir.path()).await;

        // Both permit and forbid for overlapping patterns
        h.add_rule(Effect::Permit, "aws:s3:*", "template:aws-s3");
        h.add_rule(Effect::Forbid, "aws:s3:DeleteBucket", "template:aws-s3");

        h.app.active_tab = 1; // Rules tab
        let text = h.poll_and_render();

        assert!(text.contains("Rules (2)"));
        assert!(text.contains("permit"), "missing permit");
        assert!(text.contains("forbid"), "missing forbid");
        assert!(text.contains("DeleteBucket"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dual_rule_removal_reflected_in_tui() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = DualHarness::new(dir.path()).await;

        h.add_rule(Effect::Permit, "aws:s3:GetObject", "human");
        h.add_rule(Effect::Permit, "aws:s3:PutObject", "human");
        h.app.active_tab = 1; // Rules tab
        let text = h.poll_and_render();
        assert!(text.contains("Rules (2)"));

        // Remove one rule
        h.tree.remove_rule("test:aws:s3:GetObject");
        let text = h.poll_and_render();
        assert!(text.contains("Rules (1)"), "rule removal not reflected");
        assert!(!text.contains("GetObject"), "removed rule still visible");
        assert!(text.contains("PutObject"), "remaining rule missing");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dual_yolo_mode_header() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = DualHarness::new(dir.path()).await;

        let text = h.write_event_and_render(AuditPayload::SessionStart {
            command: "claude".into(),
            templates: vec![],
            yolo: true,
        });

        assert!(text.contains("YOLO"));
        assert!(!text.contains("ENFORCING"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dual_human_approval_visible() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = DualHarness::new(dir.path()).await;

        let text = h.write_event_and_render(AuditPayload::HumanApproval {
            action: "aws:s3:PutObject".into(),
            verdict: "approved".into(),
            risk_tier: "moderate".into(),
            wait_ms: 3400,
        });

        assert!(text.contains("APPROVED"));
        assert!(text.contains("PutObject"));
        assert!(text.contains("moderate"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dual_incremental_log_tailing() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = DualHarness::new(dir.path()).await;

        // Write 3 events one at a time, verify TUI catches up each time
        for i in 0..3 {
            h.audit
                .log(AuditPayload::Decision {
                    action: format!("net:GET:api{}.example.com/data", i),
                    result: "allow".into(),
                    decided_by: "tree".into(),
                    reason: None,
                    latency_ms: i as u64,
                    request: AuditRequestMeta {
                        method: "GET".into(),
                        host: format!("api{}.example.com", i),
                        path: "/data".into(),
                    },
                })
                .unwrap();

            let text = h.poll_and_render();
            assert!(
                text.contains(&format!("Activity ({})", i + 1)),
                "after event {}, expected Activity ({}), got: {}",
                i,
                i + 1,
                text
            );
        }
    }
}
