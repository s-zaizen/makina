use axum::{extract::Request, http::HeaderValue, middleware::Next, response::Response};
use tracing::Instrument;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct RequestId(pub String);

pub fn init() -> anyhow::Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,makina=info"));

    tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_current_span(true)
        .with_span_list(false)
        .with_target(true)
        .with_env_filter(filter)
        .init();

    Ok(())
}

pub async fn request_id_mw(mut req: Request, next: Next) -> Response {
    let id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let method = req.method().clone();
    let path = req.uri().path().to_string();

    req.extensions_mut().insert(RequestId(id.clone()));

    let span = tracing::info_span!(
        "http",
        request_id = %id,
        method = %method,
        path = %path,
    );

    let id_for_header = id.clone();
    async move {
        let start = std::time::Instant::now();
        let mut resp = next.run(req).await;
        let status = resp.status().as_u16();
        let elapsed_ms = start.elapsed().as_millis() as u64;

        if let Ok(hv) = HeaderValue::from_str(&id_for_header) {
            resp.headers_mut().insert("x-request-id", hv);
        }

        tracing::info!(status, elapsed_ms, "request");
        resp
    }
    .instrument(span)
    .await
}
