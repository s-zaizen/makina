//! `/api/verify/queue` — pending Verify-tab cases.
//!
//! `list` returns everything currently awaiting human review,
//! `add` enqueues a new case, `remove` archives a case to the
//! Knowledge tab (without per-finding labels — used by Verify's
//! "submit empty" path) and triggers retrain unless `?skip_train=true`.

use axum::{
    extract::{Extension, Json, Path, Query},
    http::StatusCode,
    response::IntoResponse,
};
use tracing::info;

use crate::api::models::{AddToQueueRequest, Finding, SkipTrainQuery, VerifyQueueCase};
use crate::infra::ml::MlClient;
use crate::logging::RequestId;
use crate::store;

pub async fn list() -> Result<impl IntoResponse, (StatusCode, String)> {
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

pub async fn add(
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

pub async fn remove(
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
