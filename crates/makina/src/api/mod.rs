pub mod models;

use axum::{
    middleware,
    routing::{delete, get, post},
    Router,
};
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};

use crate::features::{findings, knowledge, labels, model, scan, verify};
use crate::logging::request_id_mw;

pub async fn serve(host: &str, port: u16) -> anyhow::Result<()> {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/api/scan", post(scan::scan))
        .route("/api/feedback", post(labels::record))
        .route("/api/findings/manual", post(findings::manual))
        .route("/api/stats", get(model::stats))
        .route("/api/verify/queue", get(verify::list).post(verify::add))
        .route("/api/verify/queue/:case_no", delete(verify::remove))
        .route(
            "/api/knowledge",
            get(knowledge::list).post(knowledge::submit),
        )
        .route("/api/retrain", post(model::retrain))
        .route("/api/model_metrics", get(model::metrics))
        .layer(middleware::from_fn(request_id_mw))
        .layer(cors);

    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;
    tracing::info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
