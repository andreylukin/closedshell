//! SQLite session and rule persistence.
//!
//! Database: `~/.closedshell/sessions.db`

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use std::path::Path;
use std::sync::Mutex;

/// A row from the `sessions` table.
#[derive(Debug, Clone)]
pub struct SessionRow {
    pub id: String,
    pub workdir: String,
    pub command: String,
    pub task: Option<String>,
    pub status: String,
    pub templates: String,
    pub pid: i64,
    pub port: u16,
    pub log_path: String,
    pub created_at: String,
    pub last_used: String,
    pub total_decisions: u64,
    pub total_denied: u64,
}

/// A row from the `rules` table.
#[derive(Debug, Clone)]
pub struct RuleRow {
    pub id: String,
    pub session_id: String,
    pub effect: String,
    pub action: String,
    pub rule_type: Option<String>,
    pub rule_json: String,
    pub created_at: String,
}

/// SQLite-backed session database.
pub struct SessionDb {
    conn: Mutex<Connection>,
}

impl SessionDb {
    /// Open (or create) the database at the given path.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).context("failed to open sessions.db")?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;",
        )?;
        Self::migrate(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn migrate(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                workdir TEXT NOT NULL,
                command TEXT NOT NULL,
                task TEXT,
                status TEXT NOT NULL DEFAULT 'running',
                templates TEXT NOT NULL DEFAULT '[]',
                pid INTEGER NOT NULL,
                port INTEGER NOT NULL,
                log_path TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_used TEXT NOT NULL,
                total_decisions INTEGER NOT NULL DEFAULT 0,
                total_denied INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS rules (
                id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                effect TEXT NOT NULL,
                action TEXT NOT NULL,
                rule_type TEXT,
                rule_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (id, session_id),
                FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_workdir ON sessions(workdir);
            CREATE INDEX IF NOT EXISTS idx_rules_session ON rules(session_id);",
        )?;
        Ok(())
    }

    /// Atomically find and claim the most recent resumable session for a workdir.
    /// Sets the session to "running" so other processes won't also resume it.
    /// Returns None if no resumable session exists.
    pub fn find_by_workdir(&self, workdir: &str) -> Result<Option<SessionRow>> {
        let conn = self.conn.lock().unwrap();

        // Atomically find and claim: only the first caller gets it
        let now = chrono::Utc::now().to_rfc3339();
        let affected = conn.execute(
            "UPDATE sessions SET status = 'running', last_used = ?1
             WHERE id = (
                SELECT id FROM sessions
                WHERE workdir = ?2 AND status != 'running'
                ORDER BY last_used DESC LIMIT 1
             )",
            params![now, workdir],
        )?;
        if affected == 0 {
            return Ok(None);
        }

        // Now read the row we just claimed
        let mut stmt = conn.prepare(
            "SELECT id, workdir, command, task, status, templates, pid, port, log_path,
                    created_at, last_used, total_decisions, total_denied
             FROM sessions WHERE workdir = ?1 AND status = 'running'
             ORDER BY last_used DESC LIMIT 1",
        )?;
        let row = stmt
            .query_row(params![workdir], |row| {
                Ok(SessionRow {
                    id: row.get(0)?,
                    workdir: row.get(1)?,
                    command: row.get(2)?,
                    task: row.get(3)?,
                    status: row.get(4)?,
                    templates: row.get(5)?,
                    pid: row.get(6)?,
                    port: row.get(7)?,
                    log_path: row.get(8)?,
                    created_at: row.get(9)?,
                    last_used: row.get(10)?,
                    total_decisions: row.get::<_, i64>(11)? as u64,
                    total_denied: row.get::<_, i64>(12)? as u64,
                })
            })
            .optional()?;
        Ok(row)
    }

    /// Insert or replace a session.
    pub fn create_session(&self, row: &SessionRow) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO sessions (id, workdir, command, task, status, templates, pid, port,
                                   log_path, created_at, last_used, total_decisions, total_denied)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                row.id,
                row.workdir,
                row.command,
                row.task,
                row.status,
                row.templates,
                row.pid,
                row.port as i64,
                row.log_path,
                row.created_at,
                row.last_used,
                row.total_decisions as i64,
                row.total_denied as i64,
            ],
        )?;
        Ok(())
    }

    /// Update session status and stats on shutdown.
    pub fn update_session(
        &self,
        id: &str,
        status: &str,
        total_decisions: u64,
        total_denied: u64,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE sessions SET status = ?1, total_decisions = ?2, total_denied = ?3, last_used = ?4
             WHERE id = ?5",
            params![status, total_decisions as i64, total_denied as i64, now, id],
        )?;
        Ok(())
    }

    /// Replace all rules for a session (DELETE + INSERT in a transaction).
    pub fn persist_rules(&self, session_id: &str, rules: &[RuleRow]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM rules WHERE session_id = ?1",
            params![session_id],
        )?;
        let mut stmt = tx.prepare(
            "INSERT INTO rules (id, session_id, effect, action, rule_type, rule_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        for r in rules {
            stmt.execute(params![
                r.id,
                r.session_id,
                r.effect,
                r.action,
                r.rule_type,
                r.rule_json,
                r.created_at,
            ])?;
        }
        drop(stmt);
        tx.commit()?;
        Ok(())
    }

    /// Load all rules for a session.
    pub fn load_rules(&self, session_id: &str) -> Result<Vec<RuleRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, session_id, effect, action, rule_type, rule_json, created_at
             FROM rules WHERE session_id = ?1",
        )?;
        let rows = stmt
            .query_map(params![session_id], |row| {
                Ok(RuleRow {
                    id: row.get(0)?,
                    session_id: row.get(1)?,
                    effect: row.get(2)?,
                    action: row.get(3)?,
                    rule_type: row.get(4)?,
                    rule_json: row.get(5)?,
                    created_at: row.get(6)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// List all sessions, most recently used first.
    pub fn list_sessions(&self) -> Result<Vec<SessionRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, workdir, command, task, status, templates, pid, port, log_path,
                    created_at, last_used, total_decisions, total_denied
             FROM sessions ORDER BY last_used DESC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(SessionRow {
                    id: row.get(0)?,
                    workdir: row.get(1)?,
                    command: row.get(2)?,
                    task: row.get(3)?,
                    status: row.get(4)?,
                    templates: row.get(5)?,
                    pid: row.get(6)?,
                    port: row.get(7)?,
                    log_path: row.get(8)?,
                    created_at: row.get(9)?,
                    last_used: row.get(10)?,
                    total_decisions: row.get::<_, i64>(11)? as u64,
                    total_denied: row.get::<_, i64>(12)? as u64,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Delete a session and its rules (CASCADE).
    pub fn delete_session(&self, id: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let affected = conn.execute("DELETE FROM sessions WHERE id = ?1", params![id])?;
        Ok(affected > 0)
    }

    /// Find sessions marked "running" whose PID is dead. Caller should verify PID liveness.
    pub fn find_running(&self) -> Result<Vec<SessionRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, workdir, command, task, status, templates, pid, port, log_path,
                    created_at, last_used, total_decisions, total_denied
             FROM sessions WHERE status = 'running'",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(SessionRow {
                    id: row.get(0)?,
                    workdir: row.get(1)?,
                    command: row.get(2)?,
                    task: row.get(3)?,
                    status: row.get(4)?,
                    templates: row.get(5)?,
                    pid: row.get(6)?,
                    port: row.get(7)?,
                    log_path: row.get(8)?,
                    created_at: row.get(9)?,
                    last_used: row.get(10)?,
                    total_decisions: row.get::<_, i64>(11)? as u64,
                    total_denied: row.get::<_, i64>(12)? as u64,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Mark a session as crashed.
    pub fn mark_crashed(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE sessions SET status = 'crashed', last_used = ?1 WHERE id = ?2",
            params![now, id],
        )?;
        Ok(())
    }
}

// rusqlite's optional() helper
use rusqlite::OptionalExtension;

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> (tempfile::TempDir, SessionDb) {
        let dir = tempfile::tempdir().unwrap();
        let db = SessionDb::open(&dir.path().join("test.db")).unwrap();
        (dir, db)
    }

    fn sample_session(id: &str, workdir: &str) -> SessionRow {
        SessionRow {
            id: id.into(),
            workdir: workdir.into(),
            command: "claude".into(),
            task: Some("test task".into()),
            status: "running".into(),
            templates: "[]".into(),
            pid: std::process::id() as i64,
            port: 8443,
            log_path: format!("closedshell-{}.log", id),
            created_at: chrono::Utc::now().to_rfc3339(),
            last_used: chrono::Utc::now().to_rfc3339(),
            total_decisions: 0,
            total_denied: 0,
        }
    }

    #[test]
    fn create_and_find_session() {
        let (_dir, db) = temp_db();
        let mut row = sample_session("abc123", "/tmp/myproject");
        row.status = "ended".into(); // find_by_workdir only returns non-running sessions
        db.create_session(&row).unwrap();

        let found = db.find_by_workdir("/tmp/myproject").unwrap().unwrap();
        assert_eq!(found.id, "abc123");
        assert_eq!(found.command, "claude");
        // find_by_workdir atomically marks it running
        assert_eq!(found.status, "running");
    }

    #[test]
    fn find_missing_returns_none() {
        let (_dir, db) = temp_db();
        assert!(db.find_by_workdir("/nonexistent").unwrap().is_none());
    }

    #[test]
    fn persist_and_load_rules() {
        let (_dir, db) = temp_db();
        let session = sample_session("sess01", "/tmp/proj");
        db.create_session(&session).unwrap();

        let rules = vec![
            RuleRow {
                id: "p-001".into(),
                session_id: "sess01".into(),
                effect: "permit".into(),
                action: "aws:s3:List*".into(),
                rule_type: Some("idempotent".into()),
                rule_json: r#"{"id":"p-001","effect":"Permit","action":"aws:s3:List*"}"#.into(),
                created_at: chrono::Utc::now().to_rfc3339(),
            },
            RuleRow {
                id: "f-001".into(),
                session_id: "sess01".into(),
                effect: "forbid".into(),
                action: "aws:s3:Delete*".into(),
                rule_type: None,
                rule_json: r#"{"id":"f-001","effect":"Forbid","action":"aws:s3:Delete*"}"#.into(),
                created_at: chrono::Utc::now().to_rfc3339(),
            },
        ];
        db.persist_rules("sess01", &rules).unwrap();

        let loaded = db.load_rules("sess01").unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].id, "p-001");
        assert_eq!(loaded[1].effect, "forbid");
    }

    #[test]
    fn persist_rules_replaces_old() {
        let (_dir, db) = temp_db();
        let session = sample_session("sess02", "/tmp/proj2");
        db.create_session(&session).unwrap();

        let rules1 = vec![RuleRow {
            id: "old".into(),
            session_id: "sess02".into(),
            effect: "permit".into(),
            action: "aws:s3:*".into(),
            rule_type: Some("idempotent".into()),
            rule_json: "{}".into(),
            created_at: chrono::Utc::now().to_rfc3339(),
        }];
        db.persist_rules("sess02", &rules1).unwrap();

        let rules2 = vec![RuleRow {
            id: "new".into(),
            session_id: "sess02".into(),
            effect: "forbid".into(),
            action: "aws:iam:*".into(),
            rule_type: None,
            rule_json: "{}".into(),
            created_at: chrono::Utc::now().to_rfc3339(),
        }];
        db.persist_rules("sess02", &rules2).unwrap();

        let loaded = db.load_rules("sess02").unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "new");
    }

    #[test]
    fn update_session_status() {
        let (_dir, db) = temp_db();
        let session = sample_session("sess03", "/tmp/proj3");
        db.create_session(&session).unwrap();

        db.update_session("sess03", "ended", 42, 3).unwrap();
        // find_by_workdir only returns non-running, so it should find the ended session
        let found = db.find_by_workdir("/tmp/proj3").unwrap().unwrap();
        // find_by_workdir atomically marks it running, but we can verify stats
        assert_eq!(found.total_decisions, 42);
        assert_eq!(found.total_denied, 3);
    }

    #[test]
    fn list_sessions_ordered() {
        let (_dir, db) = temp_db();
        db.create_session(&sample_session("a", "/tmp/a")).unwrap();
        db.create_session(&sample_session("b", "/tmp/b")).unwrap();

        let list = db.list_sessions().unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn delete_session_cascades() {
        let (_dir, db) = temp_db();
        db.create_session(&sample_session("del01", "/tmp/del"))
            .unwrap();
        db.persist_rules(
            "del01",
            &[RuleRow {
                id: "r1".into(),
                session_id: "del01".into(),
                effect: "permit".into(),
                action: "*".into(),
                rule_type: None,
                rule_json: "{}".into(),
                created_at: chrono::Utc::now().to_rfc3339(),
            }],
        )
        .unwrap();

        assert!(db.delete_session("del01").unwrap());
        assert!(db.find_by_workdir("/tmp/del").unwrap().is_none());
        assert!(db.load_rules("del01").unwrap().is_empty());
    }

    #[test]
    fn find_running_and_mark_crashed() {
        let (_dir, db) = temp_db();
        db.create_session(&sample_session("run01", "/tmp/run"))
            .unwrap();

        let running = db.find_running().unwrap();
        assert_eq!(running.len(), 1);

        db.mark_crashed("run01").unwrap();
        let running = db.find_running().unwrap();
        assert!(running.is_empty());

        // find_by_workdir finds the crashed session and marks it running
        let found = db.find_by_workdir("/tmp/run").unwrap().unwrap();
        assert_eq!(found.id, "run01");
    }
}
