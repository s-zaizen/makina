//! Model-tab views: maturity stats, full retrain trigger, and the
//! GBDT metrics blob proxied from the ML service.

use axum::{
    extract::{Extension, Json},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use std::path::PathBuf;
use tracing::info;

use crate::api::models::StatsResponse;
use crate::infra::ml::MlClient;
use crate::logging::RequestId;
use crate::store;

/// Subset of `metrics.json` we surface through `/api/stats` when the
/// live `feedback.db` is empty (= public deployment baked from a
/// frozen offline-trained model). Mirrors the writer in
/// `ml/makina_ml/services/training.py`.
#[derive(Debug, Deserialize)]
struct FrozenMetrics {
    samples: Option<i64>,
    tp: Option<i64>,
    fp: Option<i64>,
    stage: Option<String>,
}

fn read_frozen_metrics() -> Option<FrozenMetrics> {
    let path: PathBuf = std::env::var("MAKINA_METRICS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".makina/metrics.json")
        });
    let bytes = std::fs::read(&path).ok()?;
    serde_json::from_slice::<FrozenMetrics>(&bytes).ok()
}

pub async fn stats() -> Result<impl IntoResponse, (StatusCode, String)> {
    let s = store::get_stats().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // When `feedback.db` carries no live labels (public deployment
    // shipping a frozen model), surface the trained-model counts so
    // the Stats / Model tabs reflect reality instead of a misleading
    // 0/0/0 "bootstrapping" state.
    if s.total_labels == 0 {
        if let Some(m) = read_frozen_metrics() {
            let total = m.samples.unwrap_or(0);
            if total > 0 {
                return Ok(Json(StatsResponse {
                    total_labels: total,
                    tp_count: m.tp.unwrap_or(0),
                    fp_count: m.fp.unwrap_or(0),
                    model_stage: m.stage.unwrap_or_else(|| "mature".into()),
                    labels_until_next_stage: 0,
                }));
            }
        }
    }

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
