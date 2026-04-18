use axum::{extract::{Json, Path}, http::StatusCode, response::IntoResponse};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

use crate::feedback::store;

use super::models::{
    AddToQueueRequest, FeedbackRequest, FeedbackResponse, Finding, KnowledgeCase, Language,
    ManualFindingRequest, Severity, ScanRequest, ScanResponse, StatsResponse,
    SubmitKnowledgeRequest, VerifyQueueCase,
};

#[derive(serde::Deserialize, Default)]
struct MlResponse {
    #[serde(default)]
    status: String,
    #[serde(default)]
    findings: Vec<MlFinding>,
}

#[derive(serde::Deserialize)]
struct MlFinding {
    rule_id: String,
    message: String,
    severity: String,
    line_start: u32,
    line_end: u32,
    code_snippet: String,
    confidence: f32,
    cwe: Option<String>,
}

#[derive(serde::Deserialize, Default)]
struct EmbedBatchResponse {
    #[serde(default)]
    embeddings: Vec<Vec<f32>>,
}

struct RawFinding {
    finding: Finding,
}

fn ml_url() -> String {
    std::env::var("DEUS_ML_URL").unwrap_or_else(|_| "http://localhost:8080".to_string())
}

fn language_hint(lang: &Language) -> &'static str {
    match lang {
        Language::Auto => "auto",
        Language::Python => "python",
        Language::Rust => "rust",
        Language::JavaScript => "javascript",
        Language::TypeScript => "typescript",
        Language::Go => "go",
        Language::Java => "java",
        Language::Ruby => "ruby",
        Language::C => "c",
        Language::Cpp => "cpp",
    }
}

fn severity_from_str(s: &str) -> Severity {
    match s {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        _ => Severity::Low,
    }
}

fn build_client() -> Option<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .ok()
}

fn ml_finding_to_raw(mf: MlFinding, source: &str) -> RawFinding {
    let is_uncertain = mf.confidence >= 0.45 && mf.confidence <= 0.65;
    RawFinding {
        finding: Finding {
            id: Uuid::new_v4().to_string(),
            rule_id: mf.rule_id,
            message: mf.message,
            severity: severity_from_str(&mf.severity),
            line_start: mf.line_start,
            line_end: mf.line_end,
            code_snippet: mf.code_snippet,
            confidence: mf.confidence,
            is_uncertain,
            cwe: mf.cwe,
            source: source.to_string(),
        },
    }
}

async fn call_semgrep(client: &reqwest::Client, code: &str, language: &Language) -> Vec<RawFinding> {
    let url = format!("{}/semgrep", ml_url());
    let body = serde_json::json!({
        "code": code,
        "language": language_hint(language),
    });

    let resp = match client.post(&url).json(&body).send().await {
        Ok(r) => r,
        Err(_) => return vec![],
    };
    if !resp.status().is_success() {
        return vec![];
    }
    let ml: MlResponse = match resp.json().await {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    ml.findings.into_iter().map(|mf| ml_finding_to_raw(mf, "semgrep")).collect()
}

async fn call_analyze(client: &reqwest::Client, code: &str, language: &Language) -> Vec<RawFinding> {
    let url = format!("{}/analyze", ml_url());
    let body = serde_json::json!({
        "code": code,
        "language": language_hint(language),
    });

    let resp = match client.post(&url).json(&body).send().await {
        Ok(r) => r,
        Err(_) => return vec![],
    };
    if !resp.status().is_success() {
        return vec![];
    }
    let ml: MlResponse = match resp.json().await {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    if ml.status != "ready" {
        return vec![];
    }

    ml.findings.into_iter().map(|mf| ml_finding_to_raw(mf, "ml")).collect()
}

async fn call_taint(client: &reqwest::Client, code: &str, language: &Language) -> Vec<RawFinding> {
    let url = format!("{}/taint", ml_url());
    let body = serde_json::json!({
        "code": code,
        "language": language_hint(language),
    });

    let resp = match client.post(&url).json(&body).send().await {
        Ok(r) => r,
        Err(_) => return vec![],
    };
    if !resp.status().is_success() {
        return vec![];
    }
    let ml: MlResponse = match resp.json().await {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    ml.findings.into_iter().map(|mf| ml_finding_to_raw(mf, "taint")).collect()
}

async fn call_embed_with_graph(
    client: &reqwest::Client,
    code: &str,
    language: &Language,
    line_starts: &[u32],
) -> Vec<Vec<u8>> {
    if line_starts.is_empty() {
        return vec![];
    }
    let url = format!("{}/embed_with_graph", ml_url());
    let body = serde_json::json!({
        "code": code,
        "language": language_hint(language),
        "line_starts": line_starts,
    });

    let resp = match client.post(&url).json(&body).send().await {
        Ok(r) => r,
        Err(_) => return vec![vec![]; line_starts.len()],
    };
    if !resp.status().is_success() {
        return vec![vec![]; line_starts.len()];
    }
    let data: EmbedBatchResponse = match resp.json().await {
        Ok(v) => v,
        Err(_) => return vec![vec![]; line_starts.len()],
    };

    data.embeddings
        .into_iter()
        .map(|floats| floats.iter().flat_map(|f| f.to_le_bytes()).collect())
        .collect()
}

pub async fn scan(
    Json(req): Json<ScanRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let scan_id = Uuid::new_v4().to_string();
    let code_hash = format!("{:x}", Sha256::digest(req.code.as_bytes()));
    let lang_str = language_hint(&req.language);

    let client = build_client().unwrap_or_default();

    let (semgrep_raw, ml_raw, taint_raw) = tokio::join!(
        call_semgrep(&client, &req.code, &req.language),
        call_analyze(&client, &req.code, &req.language),
        call_taint(&client, &req.code, &req.language),
    );

    let mut raw_findings: Vec<RawFinding> = semgrep_raw;
    raw_findings.extend(ml_raw);
    raw_findings.extend(taint_raw);

    // Embed all findings with call-graph-augmented context
    let line_starts: Vec<u32> = raw_findings.iter().map(|r| r.finding.line_start).collect();
    let embeddings = call_embed_with_graph(&client, &req.code, &req.language, &line_starts).await;

    let mut findings: Vec<Finding> = Vec::new();
    for (i, r) in raw_findings.into_iter().enumerate() {
        let emb = embeddings.get(i).filter(|v| !v.is_empty()).map(|v| v.as_slice());
        let _ = store::save_finding(&r.finding.id, &code_hash, &r.finding.rule_id, lang_str, r.finding.line_start, r.finding.confidence, emb);
        findings.push(r.finding);
    }

    Ok(Json(ScanResponse {
        scan_id,
        findings,
        language: req.language,
        lines_scanned: req.code.lines().count(),
    }))
}

pub async fn feedback(
    Json(req): Json<FeedbackRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    store::update_label(&req.finding_id, &req.label.to_string())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let stats = store::get_stats()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Retrain every 10 individual labels as a background signal.
    // The primary retrain trigger is remove_from_queue (Verify Submit).
    let total = stats.total_labels;
    if total % 10 == 0 {
        let client = build_client().unwrap_or_default();
        let url = format!("{}/train", ml_url());
        let _ = client.post(&url).json(&serde_json::json!({})).send().await;
    }

    Ok(Json(FeedbackResponse {
        success: true,
        total_labels: stats.total_labels,
    }))
}

pub async fn manual_finding(
    Json(req): Json<ManualFindingRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let id = Uuid::new_v4().to_string();
    let code_hash = format!("{:x}", Sha256::digest(req.code.as_bytes()));
    let lang_str = language_hint(&req.language);

    let source_lines: Vec<&str> = req.code.lines().collect();
    let total = source_lines.len();
    let ls = (req.line_start as usize).saturating_sub(1);
    let le = (req.line_end as usize).min(total);

    let code_snippet = source_lines.get(ls..le).map(|l| l.join("\n")).unwrap_or_default();

    let client = build_client().unwrap_or_default();
    let embeddings = call_embed_with_graph(&client, &req.code, &req.language, &[req.line_start]).await;
    let emb = embeddings.first().filter(|v| !v.is_empty()).map(|v| v.as_slice());

    let rule_id = req.cwe.as_deref().unwrap_or("manual").to_string();
    let finding = Finding {
        id: id.clone(),
        rule_id,
        message: req.message,
        severity: severity_from_str(&req.severity),
        line_start: req.line_start,
        line_end: req.line_end,
        code_snippet,
        confidence: 1.0,
        is_uncertain: false,
        cwe: req.cwe,
        source: "manual".to_string(),
    };

    let _ = store::save_finding(
        &finding.id, &code_hash, &finding.rule_id, lang_str,
        finding.line_start, finding.confidence, emb,
    );

    Ok(Json(finding))
}

pub async fn stats() -> Result<impl IntoResponse, (StatusCode, String)> {
    let s = store::get_stats()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(StatsResponse {
        total_labels: s.total_labels,
        tp_count: s.tp_count,
        fp_count: s.fp_count,
        model_stage: s.model_stage,
        labels_until_next_stage: s.labels_until_next_stage,
    }))
}

// ── Verify queue ──────────────────────────────────────────────────────────────

pub async fn get_knowledge() -> Result<impl IntoResponse, (StatusCode, String)> {
    let items = store::get_knowledge_items()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let cases: Vec<KnowledgeCase> = items
        .into_iter()
        .map(|item| {
            let findings: Vec<Finding> =
                serde_json::from_str(&item.findings_json).unwrap_or_default();
            let labels: HashMap<String, String> =
                serde_json::from_str(&item.labels_json).unwrap_or_default();
            KnowledgeCase {
                case_no: item.case_no,
                cve_id: item.cve_id,
                code: item.code,
                language: item.language,
                findings,
                labels,
                submitted_at: item.submitted_at,
                verified_at: item.verified_at,
            }
        })
        .collect();

    Ok(Json(cases))
}

pub async fn submit_knowledge(
    Json(req): Json<SubmitKnowledgeRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    for (id, label) in &req.labels {
        store::update_label(id, &label.to_string())
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    let labels_map: HashMap<String, String> = req
        .labels
        .iter()
        .map(|(k, v)| (k.clone(), v.to_string()))
        .collect();
    let labels_json = serde_json::to_string(&labels_map)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    store::submit_to_knowledge(req.case_no, &labels_json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Retrain on every Verify Submit — this is the primary learning trigger.
    let client = build_client().unwrap_or_default();
    let url = format!("{}/train", ml_url());
    let _ = client.post(&url).json(&serde_json::json!({})).send().await;

    Ok(Json(serde_json::json!({ "success": true })))
}

pub async fn get_queue() -> Result<impl IntoResponse, (StatusCode, String)> {
    let items = store::get_queue_items()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let cases: Vec<VerifyQueueCase> = items
        .into_iter()
        .map(|item| {
            let findings: Vec<Finding> =
                serde_json::from_str(&item.findings_json).unwrap_or_default();
            VerifyQueueCase {
                case_no: item.case_no,
                cve_id: item.cve_id,
                code: item.code,
                language: item.language,
                findings,
                submitted_at: item.submitted_at,
            }
        })
        .collect();

    Ok(Json(cases))
}

pub async fn add_to_queue(
    Json(req): Json<AddToQueueRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let findings_json = serde_json::to_string(&req.findings)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let (case_no, submitted_at) =
        store::add_queue_item(req.cve_id.as_deref(), &req.code, &req.language, &findings_json)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(VerifyQueueCase {
        case_no,
        cve_id: req.cve_id,
        code: req.code,
        language: req.language,
        findings: req.findings,
        submitted_at,
    }))
}

pub async fn remove_from_queue(
    Path(case_no): Path<i64>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    store::submit_to_knowledge(case_no, "{}")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Retrain on every Verify Submit — this is the primary learning trigger.
    let client = build_client().unwrap_or_default();
    let url = format!("{}/train", ml_url());
    let _ = client.post(&url).json(&serde_json::json!({})).send().await;

    Ok(Json(serde_json::json!({ "success": true })))
}
