use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection};

pub struct Stats {
    pub total_labels: i64,
    pub tp_count: i64,
    pub fp_count: i64,
    pub model_stage: String,
    pub labels_until_next_stage: i64,
}

pub struct QueueItem {
    pub case_no: i64,
    pub cve_id: Option<String>,
    pub code: String,
    pub language: String,
    pub findings_json: String,
    pub submitted_at: String,
}

pub struct KnowledgeItem {
    pub case_no: i64,
    pub cve_id: Option<String>,
    pub code: String,
    pub language: String,
    pub findings_json: String,
    pub labels_json: String,
    pub submitted_at: String,
    pub verified_at: String,
}

fn makina_dir() -> std::path::PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".makina")
}

fn open_feedback() -> Result<Connection> {
    let path = makina_dir().join("feedback.db");
    std::fs::create_dir_all(path.parent().unwrap())?;
    Ok(Connection::open(path)?)
}

fn open_verify() -> Result<Connection> {
    let path = makina_dir().join("verify.db");
    std::fs::create_dir_all(path.parent().unwrap())?;
    Ok(Connection::open(path)?)
}

fn open_knowledge() -> Result<Connection> {
    let path = makina_dir().join("knowledge.db");
    std::fs::create_dir_all(path.parent().unwrap())?;
    Ok(Connection::open(path)?)
}

pub fn init_db() -> Result<()> {
    // ── feedback.db ─────────────────────────────────────────────────────────────
    let feedback_conn = open_feedback()?;
    feedback_conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            code_hash TEXT NOT NULL,
            feature_vector BLOB,
            rule_id TEXT NOT NULL,
            language TEXT NOT NULL,
            line_number INTEGER NOT NULL,
            model_version TEXT NOT NULL DEFAULT 'rules-only',
            confidence REAL NOT NULL,
            label TEXT CHECK(label IN ('tp','fp')),
            labeled_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            group_key TEXT
        );",
    )?;
    // Idempotent ALTER for upgrades from earlier schemas without group_key.
    let _ = feedback_conn.execute("ALTER TABLE findings ADD COLUMN group_key TEXT", []);

    // ── verify.db ───────────────────────────────────────────────────────────────
    let verify_conn = open_verify()?;
    verify_conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS verify_queue (
            case_no INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            code TEXT NOT NULL,
            language TEXT NOT NULL,
            findings_json TEXT NOT NULL DEFAULT '[]',
            submitted_at TEXT NOT NULL
        );",
    )?;

    // ── knowledge.db ────────────────────────────────────────────────────────────
    let knowledge_conn = open_knowledge()?;
    knowledge_conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS knowledge (
            case_no INTEGER PRIMARY KEY,
            cve_id TEXT,
            code TEXT NOT NULL,
            language TEXT NOT NULL,
            findings_json TEXT NOT NULL DEFAULT '[]',
            labels_json TEXT NOT NULL DEFAULT '{}',
            submitted_at TEXT NOT NULL,
            verified_at TEXT NOT NULL
        );",
    )?;

    // Migrate data from legacy feedback.db verify_queue table
    migrate_legacy(&feedback_conn, &verify_conn, &knowledge_conn)?;

    Ok(())
}

fn migrate_legacy(
    feedback_conn: &Connection,
    verify_conn: &Connection,
    knowledge_conn: &Connection,
) -> Result<()> {
    let has_old: i64 = feedback_conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='verify_queue'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);

    if has_old == 0 {
        return Ok(());
    }

    // Pending rows → verify.db (skip if verify.db already has data)
    let verify_count: i64 = verify_conn
        .query_row("SELECT COUNT(*) FROM verify_queue", [], |r| r.get(0))
        .unwrap_or(0);

    if verify_count == 0 {
        let mut stmt = feedback_conn.prepare(
            "SELECT case_no, cve_id, code, language, findings_json, submitted_at
             FROM verify_queue WHERE status = 'pending' ORDER BY case_no",
        )?;
        let rows: Vec<(i64, Option<String>, String, String, String, String)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })?
            .filter_map(|r| r.ok())
            .collect();

        for (case_no, cve_id, code, language, findings_json, submitted_at) in rows {
            let _ = verify_conn.execute(
                "INSERT OR IGNORE INTO verify_queue
                 (case_no, cve_id, code, language, findings_json, submitted_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![case_no, cve_id, code, language, findings_json, submitted_at],
            );
        }
    }

    // Done rows → knowledge.db (skip if knowledge.db already has data)
    let knowledge_count: i64 = knowledge_conn
        .query_row("SELECT COUNT(*) FROM knowledge", [], |r| r.get(0))
        .unwrap_or(0);

    if knowledge_count == 0 {
        let mut stmt = feedback_conn.prepare(
            "SELECT case_no, cve_id, code, language, findings_json,
                    submitted_at, COALESCE(verified_at, submitted_at)
             FROM verify_queue WHERE status = 'done' ORDER BY case_no",
        )?;
        let rows: Vec<_> = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            })?
            .filter_map(|r| r.ok())
            .collect();

        for (case_no, cve_id, code, language, findings_json, submitted_at, verified_at) in rows {
            let _ = knowledge_conn.execute(
                "INSERT OR IGNORE INTO knowledge
                 (case_no, cve_id, code, language, findings_json, labels_json, submitted_at, verified_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, '{}', ?6, ?7)",
                params![case_no, cve_id, code, language, findings_json, submitted_at, verified_at],
            );
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn save_finding(
    id: &str,
    code_hash: &str,
    rule_id: &str,
    language: &str,
    line_number: u32,
    confidence: f32,
    embedding: Option<&[u8]>,
    group_key: Option<&str>,
) -> Result<()> {
    let conn = open_feedback()?;
    conn.execute(
        "INSERT OR IGNORE INTO findings
         (id, code_hash, rule_id, language, line_number, confidence, feature_vector, group_key)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            id,
            code_hash,
            rule_id,
            language,
            line_number,
            confidence,
            embedding,
            group_key
        ],
    )?;
    Ok(())
}

pub fn update_label(finding_id: &str, label: &str) -> Result<()> {
    let conn = open_feedback()?;
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE findings SET label = ?1, labeled_at = ?2 WHERE id = ?3",
        params![label, now, finding_id],
    )?;
    Ok(())
}

pub fn get_stats() -> Result<Stats> {
    let conn = open_feedback()?;

    let total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM findings WHERE label IS NOT NULL",
        [],
        |r| r.get(0),
    )?;
    let tp: i64 = conn.query_row(
        "SELECT COUNT(*) FROM findings WHERE label = 'tp'",
        [],
        |r| r.get(0),
    )?;
    let fp: i64 = conn.query_row(
        "SELECT COUNT(*) FROM findings WHERE label = 'fp'",
        [],
        |r| r.get(0),
    )?;

    // Maturity indicator — not a capability gate.
    // The model trains from the first label onward; stage reflects confidence level.
    let stage = if total == 0 { "bootstrapping" }
                else if total < 50  { "learning" }
                else if total < 500 { "refining" }
                else                { "mature" };

    Ok(Stats {
        total_labels: total,
        tp_count: tp,
        fp_count: fp,
        model_stage: stage.to_string(),
        labels_until_next_stage: 0,
    })
}

// ── Verify queue ──────────────────────────────────────────────────────────────

pub fn add_queue_item(
    cve_id: Option<&str>,
    code: &str,
    language: &str,
    findings_json: &str,
) -> Result<(i64, String)> {
    let conn = open_verify()?;
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO verify_queue (cve_id, code, language, findings_json, submitted_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![cve_id, code, language, findings_json, now],
    )?;
    Ok((conn.last_insert_rowid(), now))
}

pub fn get_queue_items() -> Result<Vec<QueueItem>> {
    let conn = open_verify()?;
    let mut stmt = conn.prepare(
        "SELECT case_no, cve_id, code, language, findings_json, submitted_at
         FROM verify_queue ORDER BY case_no",
    )?;
    let items = stmt
        .query_map([], |row| {
            Ok(QueueItem {
                case_no: row.get(0)?,
                cve_id: row.get(1)?,
                code: row.get(2)?,
                language: row.get(3)?,
                findings_json: row.get(4)?,
                submitted_at: row.get(5)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(items)
}

pub fn submit_to_knowledge(case_no: i64, labels_json: &str) -> Result<()> {
    let verify_conn = open_verify()?;
    let knowledge_conn = open_knowledge()?;

    let item = verify_conn.query_row(
        "SELECT case_no, cve_id, code, language, findings_json, submitted_at
         FROM verify_queue WHERE case_no = ?1",
        params![case_no],
        |row| {
            Ok(QueueItem {
                case_no: row.get(0)?,
                cve_id: row.get(1)?,
                code: row.get(2)?,
                language: row.get(3)?,
                findings_json: row.get(4)?,
                submitted_at: row.get(5)?,
            })
        },
    )?;

    let verified_at = Utc::now().to_rfc3339();
    knowledge_conn.execute(
        "INSERT OR REPLACE INTO knowledge
         (case_no, cve_id, code, language, findings_json, labels_json, submitted_at, verified_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            item.case_no,
            item.cve_id,
            item.code,
            item.language,
            item.findings_json,
            labels_json,
            item.submitted_at,
            verified_at
        ],
    )?;

    verify_conn.execute(
        "DELETE FROM verify_queue WHERE case_no = ?1",
        params![case_no],
    )?;

    Ok(())
}

pub fn get_knowledge_items() -> Result<Vec<KnowledgeItem>> {
    let conn = open_knowledge()?;
    let mut stmt = conn.prepare(
        "SELECT case_no, cve_id, code, language, findings_json, labels_json,
                submitted_at, verified_at
         FROM knowledge ORDER BY verified_at DESC",
    )?;
    let items = stmt
        .query_map([], |row| {
            Ok(KnowledgeItem {
                case_no: row.get(0)?,
                cve_id: row.get(1)?,
                code: row.get(2)?,
                language: row.get(3)?,
                findings_json: row.get(4)?,
                labels_json: row.get(5)?,
                submitted_at: row.get(6)?,
                verified_at: row.get(7)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(items)
}
