mod handlers;
pub mod models;

use axum::{
    middleware,
    routing::{delete, get, post},
    Router,
};
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};

use crate::logging::request_id_mw;

pub async fn serve(host: &str, port: u16) -> anyhow::Result<()> {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/api/scan", post(handlers::scan))
        .route("/api/feedback", post(handlers::feedback))
        .route("/api/findings/manual", post(handlers::manual_finding))
        .route("/api/stats", get(handlers::stats))
        .route(
            "/api/verify/queue",
            get(handlers::get_queue).post(handlers::add_to_queue),
        )
        .route(
            "/api/verify/queue/:case_no",
            delete(handlers::remove_from_queue),
        )
        .route(
            "/api/knowledge",
            get(handlers::get_knowledge).post(handlers::submit_knowledge),
        )
        .route("/api/retrain", post(handlers::retrain))
        .route("/api/model_metrics", get(handlers::model_metrics))
        .layer(middleware::from_fn(request_id_mw))
        .layer(cors);

    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;
    tracing::info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
