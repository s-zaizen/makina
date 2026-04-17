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

fn db_path() -> std::path::PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".deus")
        .join("feedback.db")
}

fn open() -> Result<Connection> {
    let path = db_path();
    std::fs::create_dir_all(path.parent().unwrap())?;
    Ok(Connection::open(path)?)
}

pub fn init_db() -> Result<()> {
    let conn = open()?;
    conn.execute_batch(
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
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS verify_queue (
            case_no INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            code TEXT NOT NULL,
            language TEXT NOT NULL,
            findings_json TEXT NOT NULL DEFAULT '[]',
            submitted_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending'
        );",
    )?;
    Ok(())
}

pub fn save_finding(
    id: &str,
    code_hash: &str,
    rule_id: &str,
    language: &str,
    line_number: u32,
    confidence: f32,
    embedding: Option<&[u8]>,
) -> Result<()> {
    let conn = open()?;
    conn.execute(
        "INSERT OR IGNORE INTO findings (id, code_hash, rule_id, language, line_number, confidence, feature_vector)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![id, code_hash, rule_id, language, line_number, confidence, embedding],
    )?;
    Ok(())
}

pub fn update_label(finding_id: &str, label: &str) -> Result<()> {
    let conn = open()?;
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE findings SET label = ?1, labeled_at = ?2 WHERE id = ?3",
        params![label, now, finding_id],
    )?;
    Ok(())
}

pub fn get_stats() -> Result<Stats> {
    let conn = open()?;

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
                else if total < 50  { "learning"      }
                else if total < 500 { "refining"      }
                else                { "mature"         };

    Ok(Stats {
        total_labels: total,
        tp_count: tp,
        fp_count: fp,
        model_stage: stage.to_string(),
        labels_until_next_stage: 0,
    })
}

// ── Verify queue ─────────────────────────────────────────────────────────────

pub fn add_queue_item(
    cve_id: Option<&str>,
    code: &str,
    language: &str,
    findings_json: &str,
) -> Result<(i64, String)> {
    let conn = open()?;
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO verify_queue (cve_id, code, language, findings_json, submitted_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![cve_id, code, language, findings_json, now],
    )?;
    Ok((conn.last_insert_rowid(), now))
}

pub fn get_queue_items() -> Result<Vec<QueueItem>> {
    let conn = open()?;
    let mut stmt = conn.prepare(
        "SELECT case_no, cve_id, code, language, findings_json, submitted_at
         FROM verify_queue WHERE status = 'pending' ORDER BY case_no",
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

pub fn mark_queue_done(case_no: i64) -> Result<()> {
    let conn = open()?;
    conn.execute(
        "UPDATE verify_queue SET status = 'done' WHERE case_no = ?1",
        params![case_no],
    )?;
    Ok(())
}
