use axum::{
    extract::{Extension, Json, Path, Query},
    http::StatusCode,
    response::IntoResponse,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tracing::info;
use uuid::Uuid;

use crate::store;
use crate::infra::ml::{bytes_to_f32_vec, language_hint, severity_from_str, MlClient};
use crate::logging::RequestId;

use super::models::{
    AddToQueueRequest, FeedbackRequest, FeedbackResponse, Finding, KnowledgeCase,
    ManualFindingRequest, ScanRequest, ScanResponse, StatsResponse, SubmitKnowledgeRequest,
    VerifyQueueCase,
};

#[derive(serde::Deserialize, Default)]
pub struct SkipTrainQuery {
    #[serde(default)]
    pub skip_train: bool,
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

    let ml = MlClient::new();

    let (semgrep, analyze, taint) = tokio::join!(
        ml.semgrep(&req_id.0, &req.code, &req.language),
        ml.analyze(&req_id.0, &req.code, &req.language),
        ml.taint(&req_id.0, &req.code, &req.language),
    );

    let mut findings: Vec<Finding> = semgrep;
    findings.extend(analyze);
    findings.extend(taint);

    let line_starts: Vec<u32> = findings.iter().map(|f| f.line_start).collect();
    let embeddings = ml
        .embed_with_graph(&req_id.0, &req.code, &req.language, &line_starts)
        .await;

    // GBDT scoring: convert per-finding embedding bytes → f32 vectors,
    // batch score via the ML service. `gbdt_scores[i]` is None when the
    // embedding was missing or the model is not trained yet.
    let float_vecs: Vec<Vec<f32>> = embeddings.iter().map(|v| bytes_to_f32_vec(v)).collect();
    let gbdt_scores = ml.predict_batch(&req_id.0, float_vecs).await;

    for (i, finding) in findings.iter_mut().enumerate() {
        let emb = embeddings
            .get(i)
            .filter(|v| !v.is_empty())
            .map(|v| v.as_slice());

        // When GBDT is trained, blend its score into the finding's confidence:
        //   final = 0.5 * heuristic + 0.5 * gbdt
        // When GBDT is absent, keep the heuristic as-is.
        if let Some(ref scores) = gbdt_scores {
            if let Some(Some(gbdt)) = scores.get(i) {
                let blended = 0.5 * finding.confidence + 0.5 * *gbdt;
                finding.confidence = blended;
                finding.is_uncertain = (0.40..=0.60).contains(&blended);
            }
        }

        // Live scans don't carry an explicit group_key; the GBDT trainer
        // falls back to a stratified random split for these rows.
        let _ = store::save_finding(
            &finding.id,
            &code_hash,
            &finding.rule_id,
            lang_str,
            finding.line_start,
            finding.confidence,
            emb,
            None,
        );
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
    Extension(req_id): Extension<RequestId>,
    Json(req): Json<FeedbackRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    store::update_label(&req.finding_id, &req.label.to_string())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let stats =
        store::get_stats().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    info!(
        finding_id = %req.finding_id,
        label = %req.label.to_string(),
        total_labels = stats.total_labels,
        "label recorded"
    );

    if stats.total_labels % 10 == 0 {
        info!(
            total_labels = stats.total_labels,
            "secondary train trigger (every 10 labels)"
        );
        MlClient::new().spawn_train(&req_id.0);
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

    let code_snippet = source_lines
        .get(ls..le)
        .map(|l| l.join("\n"))
        .unwrap_or_default();

    let ml = MlClient::new();
    let embeddings = ml
        .embed_with_graph(&req_id.0, &req.code, &req.language, &[req.line_start])
        .await;
    let emb = embeddings
        .first()
        .filter(|v| !v.is_empty())
        .map(|v| v.as_slice());

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
        &finding.id,
        &code_hash,
        &finding.rule_id,
        lang_str,
        finding.line_start,
        finding.confidence,
        emb,
        req.group_key.as_deref(),
    );

    info!(finding_id = %finding.id, rule = %finding.rule_id, "manual finding added");

    Ok(Json(finding))
}

pub async fn stats() -> Result<impl IntoResponse, (StatusCode, String)> {
    let s = store::get_stats().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(StatsResponse {
        total_labels: s.total_labels,
        tp_count: s.tp_count,
        fp_count: s.fp_count,
        model_stage: s.model_stage,
        labels_until_next_stage: s.labels_until_next_stage,
    }))
}

// ── Verify queue / Knowledge ──────────────────────────────────────────────

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
        info!(
            case_no = req.case_no,
            labels = req.labels.len(),
            "knowledge submitted (train skipped)"
        );
    } else {
        info!(
            case_no = req.case_no,
            labels = req.labels.len(),
            "knowledge submitted, scheduling train"
        );
        MlClient::new().spawn_train(&req_id.0);
    }

    Ok(Json(serde_json::json!({ "success": true })))
}

pub async fn get_queue() -> Result<impl IntoResponse, (StatusCode, String)> {
    let items =
        store::get_queue_items().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

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

    let (case_no, submitted_at) = store::add_queue_item(
        req.cve_id.as_deref(),
        &req.code,
        &req.language,
        &findings_json,
    )
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
        MlClient::new().spawn_train(&req_id.0);
    }

    Ok(Json(serde_json::json!({ "success": true })))
}

pub async fn model_metrics(
    Extension(req_id): Extension<RequestId>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let body = MlClient::new()
        .metrics(&req_id.0)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok(Json(body))
}

pub async fn retrain(
    Extension(req_id): Extension<RequestId>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    info!("retrain requested");
    let body = MlClient::new()
        .train(&req_id.0)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok(Json(body))
}
