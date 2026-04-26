use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct ScanRequest {
    pub code: String,
    pub language: Language,
    #[allow(dead_code)]
    pub filename: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    Auto,
    Python,
    Rust,
    JavaScript,
    TypeScript,
    Go,
    Java,
    Ruby,
    C,
    #[serde(rename = "cpp")]
    Cpp,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Finding {
    pub id: String,
    pub rule_id: String,
    pub message: String,
    pub severity: Severity,
    pub line_start: u32,
    pub line_end: u32,
    pub code_snippet: String,
    pub confidence: f32,
    pub is_uncertain: bool,
    pub cwe: Option<String>,
    pub source: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Serialize)]
pub struct ScanResponse {
    pub scan_id: String,
    pub findings: Vec<Finding>,
    pub language: Language,
    pub lines_scanned: usize,
}

#[derive(Debug, Deserialize)]
pub struct FeedbackRequest {
    pub finding_id: String,
    pub label: Label,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Label {
    Tp,
    Fp,
}

impl std::fmt::Display for Label {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Label::Tp => write!(f, "tp"),
            Label::Fp => write!(f, "fp"),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct FeedbackResponse {
    pub success: bool,
    pub total_labels: i64,
}

#[derive(Debug, Deserialize)]
pub struct ManualFindingRequest {
    pub code: String,
    pub language: Language,
    pub line_start: u32,
    pub line_end: u32,
    pub severity: String,
    pub cwe: Option<String>,
    pub message: String,
    /// Opaque grouping key (e.g. CVE id) used by the GBDT trainer to keep
    /// related samples together when splitting train/val. Optional so the
    /// regular Verify-Submit flow keeps working without it.
    #[serde(default)]
    pub group_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub total_labels: i64,
    pub tp_count: i64,
    pub fp_count: i64,
    pub model_stage: String,
    pub labels_until_next_stage: i64,
}

// ── Verify queue ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct VerifyQueueCase {
    pub case_no: i64,
    pub cve_id: Option<String>,
    pub code: String,
    pub language: String,
    pub findings: Vec<Finding>,
    pub submitted_at: String,
}

#[derive(Debug, Deserialize)]
pub struct AddToQueueRequest {
    pub cve_id: Option<String>,
    pub code: String,
    pub language: String,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
pub struct KnowledgeCase {
    pub case_no: i64,
    pub cve_id: Option<String>,
    pub code: String,
    pub language: String,
    pub findings: Vec<Finding>,
    pub labels: HashMap<String, String>,
    pub submitted_at: String,
    pub verified_at: String,
}

#[derive(Debug, Deserialize)]
pub struct SubmitKnowledgeRequest {
    pub case_no: i64,
    pub labels: HashMap<String, Label>,
}
