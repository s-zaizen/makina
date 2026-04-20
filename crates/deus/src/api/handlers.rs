use axum::{extract::{Extension, Json, Path, Query}, http::StatusCode, response::IntoResponse};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tracing::{info, warn};
use uuid::Uuid;

use crate::feedback::store;
use crate::logging::RequestId;

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

#[derive(serde::Deserialize, Default)]
struct PredictBatchResponse {
    #[serde(default)]
    confidences: Option<Vec<f32>>,
    #[serde(default)]
    model_ready: bool,
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

fn with_request_id(rb: reqwest::RequestBuilder, req_id: &str) -> reqwest::RequestBuilder {
    rb.header("x-request-id", req_id)
}

async fn call_semgrep(client: &reqwest::Client, req_id: &str, code: &str, language: &Language) -> Vec<RawFinding> {
    let url = format!("{}/semgrep", ml_url());
    let body = serde_json::json!({
        "code": code,
        "language": language_hint(language),
    });
    let start = std::time::Instant::now();

    let resp = match with_request_id(client.post(&url).json(&body), req_id).send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "semgrep call failed");
            return vec![];
        }
    };
    if !resp.status().is_success() {
        warn!(status = resp.status().as_u16(), "semgrep non-success");
        return vec![];
    }
    let ml: MlResponse = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "semgrep decode failed");
            return vec![];
        }
    };

    let findings: Vec<RawFinding> = ml.findings.into_iter().map(|mf| ml_finding_to_raw(mf, "semgrep")).collect();
    info!(count = findings.len(), elapsed_ms = start.elapsed().as_millis() as u64, "semgrep done");
    findings
}

async fn call_analyze(client: &reqwest::Client, req_id: &str, code: &str, language: &Language) -> Vec<RawFinding> {
    let url = format!("{}/analyze", ml_url());
    let body = serde_json::json!({
        "code": code,
        "language": language_hint(language),
    });
    let start = std::time::Instant::now();

    let resp = match with_request_id(client.post(&url).json(&body), req_id).send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "analyze call failed");
            return vec![];
        }
    };
    if !resp.status().is_success() {
        warn!(status = resp.status().as_u16(), "analyze non-success");
        return vec![];
    }
    let ml: MlResponse = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "analyze decode failed");
            return vec![];
        }
    };
    if ml.status != "ready" {
        info!(status = %ml.status, "analyze skipped (not ready)");
        return vec![];
    }

    let findings: Vec<RawFinding> = ml.findings.into_iter().map(|mf| ml_finding_to_raw(mf, "ml")).collect();
    info!(count = findings.len(), elapsed_ms = start.elapsed().as_millis() as u64, "analyze done");
    findings
}

async fn call_taint(client: &reqwest::Client, req_id: &str, code: &str, language: &Language) -> Vec<RawFinding> {
    let url = format!("{}/taint", ml_url());
    let body = serde_json::json!({
        "code": code,
        "language": language_hint(language),
    });
    let start = std::time::Instant::now();

    let resp = match with_request_id(client.post(&url).json(&body), req_id).send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "taint call failed");
            return vec![];
        }
    };
    if !resp.status().is_success() {
        warn!(status = resp.status().as_u16(), "taint non-success");
        return vec![];
    }
    let ml: MlResponse = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "taint decode failed");
            return vec![];
        }
    };

    let findings: Vec<RawFinding> = ml.findings.into_iter().map(|mf| ml_finding_to_raw(mf, "taint")).collect();
    info!(count = findings.len(), elapsed_ms = start.elapsed().as_millis() as u64, "taint done");
    findings
}

async fn call_predict_batch(
    client: &reqwest::Client,
    req_id: &str,
    feature_vectors: Vec<Vec<f32>>,
) -> Option<Vec<Option<f32>>> {
    // Build a compact list of non-empty vectors and remember their original
    // indices so we can stitch GBDT scores back to the right findings.
    let mut compact: Vec<Vec<f32>> = Vec::with_capacity(feature_vectors.len());
    let mut idx_map: Vec<usize> = Vec::with_capacity(feature_vectors.len());
    for (i, v) in feature_vectors.iter().enumerate() {
        if !v.is_empty() {
            idx_map.push(i);
            compact.push(v.clone());
        }
    }
    if compact.is_empty() {
        return None;
    }

    let url = format!("{}/predict_batch", ml_url());
    let body = serde_json::json!({ "feature_vectors": compact });
    let start = std::time::Instant::now();

    let resp = match with_request_id(client.post(&url).json(&body), req_id).send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "predict_batch call failed");
            return None;
        }
    };
    if !resp.status().is_success() {
        warn!(status = resp.status().as_u16(), "predict_batch non-success");
        return None;
    }
    let data: PredictBatchResponse = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "predict_batch decode failed");
            return None;
        }
    };
    info!(
        elapsed_ms = start.elapsed().as_millis() as u64,
        model_ready = data.model_ready,
        returned = data.confidences.as_ref().map(|v| v.len()).unwrap_or(0),
        "predict_batch done"
    );

    let confs = data.confidences?;
    if confs.len() != compact.len() {
        warn!(got = confs.len(), expected = compact.len(), "predict_batch length mismatch");
        return None;
    }
    let mut out = vec![None; feature_vectors.len()];
    for (j, &i) in idx_map.iter().enumerate() {
        out[i] = Some(confs[j]);
    }
    Some(out)
}

fn bytes_to_f32_vec(bytes: &[u8]) -> Vec<f32> {
    // Embeddings are stored as raw LE float32 bytes (3072 = 768 × 4).
    // Reject sizes that aren't a multiple of 4.
    #[allow(clippy::manual_is_multiple_of)]
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return vec![];
    }
    bytes
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

async fn call_embed_with_graph(
    client: &reqwest::Client,
    req_id: &str,
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

    let resp = match with_request_id(client.post(&url).json(&body), req_id).send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "embed call failed");
            return vec![vec![]; line_starts.len()];
        }
    };
    if !resp.status().is_success() {
        warn!(status = resp.status().as_u16(), "embed non-success");
        return vec![vec![]; line_starts.len()];
    }
    let data: EmbedBatchResponse = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "embed decode failed");
            return vec![vec![]; line_starts.len()];
        }
    };

    data.embeddings
        .into_iter()
        .map(|floats| floats.iter().flat_map(|f| f.to_le_bytes()).collect())
        .collect()
}

pub async fn scan(
    Extension(req_id): Extension<RequestId>,
    Json(req): Json<ScanRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let scan_id = Uuid::new_v4().to_string();
    let code_hash = format!("{:x}", Sha256::digest(req.code.as_bytes()));
    let lang_str = language_hint(&req.language);
    let lines = req.code.lines().count();

    info!(scan_id = %scan_id, language = lang_str, lines, "scan start");

    let client = build_client().unwrap_or_default();

    let (semgrep_raw, ml_raw, taint_raw) = tokio::join!(
        call_semgrep(&client, &req_id.0, &req.code, &req.language),
        call_analyze(&client, &req_id.0, &req.code, &req.language),
        call_taint(&client, &req_id.0, &req.code, &req.language),
    );

    let mut raw_findings: Vec<RawFinding> = semgrep_raw;
    raw_findings.extend(ml_raw);
    raw_findings.extend(taint_raw);

    let line_starts: Vec<u32> = raw_findings.iter().map(|r| r.finding.line_start).collect();
    let embeddings = call_embed_with_graph(&client, &req_id.0, &req.code, &req.language, &line_starts).await;

    // GBDT scoring: convert per-finding embedding bytes → f32 vectors, batch
    // score via the ML service. `gbdt_scores[i]` is None when the embedding
    // was missing or the model is not trained yet.
    let float_vecs: Vec<Vec<f32>> = embeddings
        .iter()
        .map(|v| bytes_to_f32_vec(v))
        .collect();
    let gbdt_scores = call_predict_batch(&client, &req_id.0, float_vecs).await;

    let mut findings: Vec<Finding> = Vec::new();
    for (i, mut r) in raw_findings.into_iter().enumerate() {
        let emb = embeddings.get(i).filter(|v| !v.is_empty()).map(|v| v.as_slice());

        // When GBDT is trained, blend its score into the finding's confidence:
        //   final = 0.5 * heuristic + 0.5 * gbdt
        // When GBDT is absent, keep the heuristic as-is.
        if let Some(ref scores) = gbdt_scores {
            if let Some(Some(gbdt)) = scores.get(i) {
                let original = r.finding.confidence;
                let blended = 0.5 * original + 0.5 * *gbdt;
                r.finding.confidence = blended;
                r.finding.is_uncertain = (0.40..=0.60).contains(&blended);
            }
        }

        let _ = store::save_finding(&r.finding.id, &code_hash, &r.finding.rule_id, lang_str, r.finding.line_start, r.finding.confidence, emb);
        findings.push(r.finding);
    }

    info!(
        scan_id = %scan_id,
        findings = findings.len(),
        gbdt_applied = gbdt_scores.is_some(),
        "scan done"
    );

    Ok(Json(ScanResponse {
        scan_id,
        findings,
        language: req.language,
        lines_scanned: lines,
    }))
}

pub async fn feedback(
    Json(req): Json<FeedbackRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    store::update_label(&req.finding_id, &req.label.to_string())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let stats = store::get_stats()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    info!(
        finding_id = %req.finding_id,
        label = %req.label.to_string(),
        total_labels = stats.total_labels,
        "label recorded"
    );

    let total = stats.total_labels;
    if total % 10 == 0 {
        let client = build_client().unwrap_or_default();
        let url = format!("{}/train", ml_url());
        info!(total_labels = total, "secondary train trigger (every 10 labels)");
        let _ = client.post(&url).json(&serde_json::json!({})).send().await;
    }

    Ok(Json(FeedbackResponse {
        success: true,
        total_labels: stats.total_labels,
    }))
}

pub async fn manual_finding(
    Extension(req_id): Extension<RequestId>,
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
    let embeddings = call_embed_with_graph(&client, &req_id.0, &req.code, &req.language, &[req.line_start]).await;
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

    info!(finding_id = %finding.id, rule = %finding.rule_id, "manual finding added");

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

#[derive(serde::Deserialize, Default)]
pub struct SkipTrainQuery {
    #[serde(default)]
    pub skip_train: bool,
}

pub async fn submit_knowledge(
    Extension(req_id): Extension<RequestId>,
    Query(q): Query<SkipTrainQuery>,
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

    if q.skip_train {
        info!(case_no = req.case_no, labels = req.labels.len(), "knowledge submitted (train skipped)");
    } else {
        info!(case_no = req.case_no, labels = req.labels.len(), "knowledge submitted, scheduling train");
        spawn_train(&req_id.0);
    }

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
    Extension(req_id): Extension<RequestId>,
    Query(q): Query<SkipTrainQuery>,
    Path(case_no): Path<i64>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    store::submit_to_knowledge(case_no, "{}")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if q.skip_train {
        info!(case_no, "queue item submitted (train skipped)");
    } else {
        info!(case_no, "queue item submitted, scheduling train");
        spawn_train(&req_id.0);
    }

    Ok(Json(serde_json::json!({ "success": true })))
}

pub async fn retrain(
    Extension(req_id): Extension<RequestId>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let client = build_client()
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "http client".to_string()))?;
    let url = format!("{}/train", ml_url());
    info!("retrain requested");
    let start = std::time::Instant::now();
    let resp = with_request_id(client.post(&url).json(&serde_json::json!({})), &req_id.0)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::json!({}));
    let elapsed_ms = start.elapsed().as_millis() as u64;
    info!(status = status.as_u16(), elapsed_ms, "retrain completed");
    Ok(Json(body))
}

fn spawn_train(req_id: &str) {
    let Some(client) = build_client() else { return };
    let url = format!("{}/train", ml_url());
    let req_id = req_id.to_string();
    tokio::spawn(async move {
        let start = std::time::Instant::now();
        let result = with_request_id(client.post(&url).json(&serde_json::json!({})), &req_id)
            .send()
            .await;
        let elapsed_ms = start.elapsed().as_millis() as u64;
        match result {
            Ok(r) => info!(status = r.status().as_u16(), elapsed_ms, "train completed"),
            Err(e) => warn!(error = %e, elapsed_ms, "train failed"),
        }
    });
}
