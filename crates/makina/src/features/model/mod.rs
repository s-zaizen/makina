//! Model-tab views: maturity stats, full retrain trigger, and the
//! GBDT metrics blob proxied from the ML service.

use axum::{
    extract::{Extension, Json},
    http::StatusCode,
    response::IntoResponse,
};
use tracing::info;

use crate::api::models::StatsResponse;
use crate::infra::ml::MlClient;
use crate::logging::RequestId;
use crate::store;

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

pub async fn metrics(
    Extension(req_id): Extension<RequestId>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let body = MlClient::new()
        .metrics(&req_id.0)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok(Json(body))
}
