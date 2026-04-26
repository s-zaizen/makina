//! `/api/knowledge` — verified cases archive.
//!
//! `list` returns all cases that have been labelled and submitted.
//! `submit` records per-finding labels for an existing queue case,
//! moves it to the knowledge archive, and triggers retrain (unless
//! `?skip_train=true` for bulk import).

use axum::{
    extract::{Extension, Json, Query},
    http::StatusCode,
    response::IntoResponse,
};
use std::collections::HashMap;
use tracing::info;

use crate::api::models::{Finding, KnowledgeCase, SkipTrainQuery, SubmitKnowledgeRequest};
use crate::infra::ml::MlClient;
use crate::logging::RequestId;
use crate::store;

pub async fn list() -> Result<impl IntoResponse, (StatusCode, String)> {
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

pub async fn submit(
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
