//! `POST /api/findings/manual` — pin a finding to a specific
//! line range without going through the scan pipeline. Used by
//! `bulk_import.py` to seed the corpus from CVEfixes-derived ranges.

use axum::{
    extract::{Extension, Json},
    http::StatusCode,
    response::IntoResponse,
};
use sha2::{Digest, Sha256};
use tracing::info;
use uuid::Uuid;

use crate::api::models::{Finding, ManualFindingRequest};
use crate::infra::ml::{language_hint, severity_from_str, MlClient};
use crate::logging::RequestId;
use crate::store;

pub async fn manual(
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
