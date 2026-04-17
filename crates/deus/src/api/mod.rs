mod handlers;
pub mod models;

use axum::{routing::{delete, get, post}, Router};
use tower_http::cors::{Any, CorsLayer};
use std::net::SocketAddr;

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
        .route("/api/verify/queue", get(handlers::get_queue).post(handlers::add_to_queue))
        .route("/api/verify/queue/:case_no", delete(handlers::remove_from_queue))
        .layer(cors);

    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;
    tracing::info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
