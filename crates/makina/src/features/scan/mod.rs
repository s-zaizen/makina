//! `POST /api/scan` — run all three detectors in parallel, blend GBDT
//! confidence into each finding, persist embeddings for future training.

use axum::{
    extract::{Extension, Json},
    http::StatusCode,
    response::IntoResponse,
};
use sha2::{Digest, Sha256};
use tracing::info;
use uuid::Uuid;

use crate::api::models::{Finding, ScanRequest, ScanResponse};
use crate::infra::ml::{bytes_to_f32_vec, language_hint, MlClient};
use crate::logging::RequestId;
use crate::store;

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
