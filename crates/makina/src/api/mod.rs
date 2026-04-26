pub mod models;

use axum::{
    middleware,
    routing::{delete, get, post},
    Router,
};
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};

use crate::features::{findings, knowledge, labels, model, scan, verify};
use crate::flags::Flags;
use crate::logging::request_id_mw;

/// Build the application router with the supplied feature flags. Public
/// mode strips every route that mutates the learning corpus — the model
/// is fixed in that deployment, so writes have nothing to update.
pub fn build_router(flags: Flags) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Read-only routes — always exposed.
    let mut app = Router::new()
        .route("/api/scan", post(scan::scan))
        .route("/api/stats", get(model::stats))
        .route("/api/verify/queue", get(verify::list))
        .route("/api/knowledge", get(knowledge::list))
        .route("/api/model_metrics", get(model::metrics));

    if !flags.public_mode {
        // Learning-loop write routes — only in dev / private deployments.
        app = app
            .route("/api/feedback", post(labels::record))
            .route("/api/findings/manual", post(findings::manual))
            .route("/api/verify/queue", post(verify::add))
            .route("/api/verify/queue/:case_no", delete(verify::remove))
            .route("/api/knowledge", post(knowledge::submit))
            .route("/api/retrain", post(model::retrain));
    }

    app.layer(middleware::from_fn(request_id_mw)).layer(cors)
}

pub async fn serve(host: &str, port: u16) -> anyhow::Result<()> {
    let flags = Flags::from_env();
    if flags.public_mode {
        tracing::info!("public mode: learning-loop write routes are disabled");
    }
    let app = build_router(flags);

    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;
    tracing::info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use serial_test::serial;
    use tower::ServiceExt;

    /// Helper — issue a request against the router and return the status.
    async fn status_for(flags: Flags, method: &str, uri: &str) -> StatusCode {
        let app = build_router(flags);
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        app.oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    #[serial]
    async fn public_mode_strips_write_routes() {
        // MAKINA_HOME isn't set so store calls would 500 — but we want
        // the router itself to refuse before that. axum returns 405 when
        // the route exists for other methods (GET) but not the one used,
        // and 404 when the route is absent entirely.
        let flags = Flags { public_mode: true };

        // POST /api/feedback — wholly absent in public mode.
        assert_eq!(
            status_for(flags, "POST", "/api/feedback").await,
            StatusCode::NOT_FOUND,
        );
        // POST /api/findings/manual — absent.
        assert_eq!(
            status_for(flags, "POST", "/api/findings/manual").await,
            StatusCode::NOT_FOUND,
        );
        // POST /api/verify/queue — GET is wired, POST must be absent
        // (axum returns 405 because the path matches a different method).
        assert_eq!(
            status_for(flags, "POST", "/api/verify/queue").await,
            StatusCode::METHOD_NOT_ALLOWED,
        );
        // DELETE /api/verify/queue/:case_no — absent.
        assert_eq!(
            status_for(flags, "DELETE", "/api/verify/queue/42").await,
            StatusCode::NOT_FOUND,
        );
        // POST /api/knowledge — GET wired, POST must be absent.
        assert_eq!(
            status_for(flags, "POST", "/api/knowledge").await,
            StatusCode::METHOD_NOT_ALLOWED,
        );
        // POST /api/retrain — absent.
        assert_eq!(
            status_for(flags, "POST", "/api/retrain").await,
            StatusCode::NOT_FOUND,
        );
    }

    #[tokio::test]
    #[serial]
    async fn dev_mode_keeps_write_routes_registered() {
        // We don't set MAKINA_HOME, so the handler will 500 from store
        // failures — but that proves the route IS reachable, which is
        // exactly what we want to test here.
        let flags = Flags {
            public_mode: false,
        };
        let status = status_for(flags, "POST", "/api/feedback").await;
        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "feedback route must be registered in dev mode (got {status})"
        );
    }
}
