//! HTTP adapter for the Python ML service.
//!
//! All `reqwest` traffic from the Rust core to the ML side goes through
//! `MlClient`. Keeping the wire format (semgrep / analyze / taint /
//! embed_with_graph / predict_batch / train / metrics) behind one type
//! lets feature handlers stay free of `serde_json`/`reqwest` boilerplate
//! and gives us a single seam to swap or mock for tests.

use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use reqwest::{Client, RequestBuilder};
use serde::Deserialize;
use tracing::{info, warn};
use uuid::Uuid;

use crate::api::models::{Finding, Language, Severity};

// ── Wire DTOs (kept private — callers see domain types) ────────────────────

#[derive(Deserialize, Default)]
struct MlResponse {
    #[serde(default)]
    status: String,
    #[serde(default)]
    findings: Vec<MlFinding>,
}

#[derive(Deserialize)]
struct MlFinding {
    rule_id: String,
    message: String,
    severity: String,
    line_start: u32,
    line_end: u32,
    code_snippet: String,
    confidence: f32,
    cwe: Option<String>,
}

#[derive(Deserialize, Default)]
struct EmbedBatchResponse {
    #[serde(default)]
    embeddings: Vec<Vec<f32>>,
}

#[derive(Deserialize, Default)]
struct PredictBatchResponse {
    #[serde(default)]
    confidences: Option<Vec<f32>>,
    #[serde(default)]
    model_ready: bool,
}

// ── Public adapter ────────────────────────────────────────────────────────

/// HTTP gateway to the Python ML service. Cheap to clone — wraps a
/// reusable `reqwest::Client` with connection pooling.
#[derive(Clone)]
pub struct MlClient {
    http: Client,
    base_url: String,
}

impl Default for MlClient {
    fn default() -> Self {
        Self::new()
    }
}

impl MlClient {
    pub fn new() -> Self {
        Self::with_base_url(default_base_url())
    }

    pub fn with_base_url(base_url: String) -> Self {
        // 120 s — generous enough to swallow CodeBERT + semgrep cold-
        // start work on a fresh Cloud Run revision. The previous 30 s
        // budget repeatedly tripped on `/semgrep` because the CLI's
        // first-call rule parse alone takes 60 s+.
        let http = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .unwrap_or_default();
        Self { http, base_url }
    }

    /// Run the rule-based semgrep detector. Errors are logged and
    /// surfaced as an empty result so a single failing detector cannot
    /// take down the whole scan.
    pub async fn semgrep(&self, req_id: &str, code: &str, language: &Language) -> Vec<Finding> {
        self.detect("semgrep", "semgrep", req_id, code, language, false)
            .await
    }

    /// Run the CodeBERT semantic analyzer. The analyzer reports
    /// `status` and we treat anything other than `"ready"` as
    /// "no findings" — the model is still loading.
    pub async fn analyze(&self, req_id: &str, code: &str, language: &Language) -> Vec<Finding> {
        self.detect("analyze", "ml", req_id, code, language, true)
            .await
    }

    /// Run the interprocedural taint engine.
    pub async fn taint(&self, req_id: &str, code: &str, language: &Language) -> Vec<Finding> {
        self.detect("taint", "taint", req_id, code, language, false)
            .await
    }

    /// Embed each `(code, line_start)` window through the call-graph
    /// augmented embedder. Returns one byte vector per input line; an
    /// empty inner vec means "no embedding produced for this line".
    pub async fn embed_with_graph(
        &self,
        req_id: &str,
        code: &str,
        language: &Language,
        line_starts: &[u32],
    ) -> Vec<Vec<u8>> {
        if line_starts.is_empty() {
            return vec![];
        }
        let url = format!("{}/embed_with_graph", self.base_url);
        let body = serde_json::json!({
            "code": code,
            "language": language_hint(language),
            "line_starts": line_starts,
        });

        let resp = match self
            .with_req_id(self.http.post(&url).json(&body), req_id)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "embed call failed");
                return vec![vec![]; line_starts.len()];
            }
        };
        if !resp.status().is_success() {
            warn!(status = resp.status().as_u16(), "embed non-success");
            return vec![vec![]; line_starts.len()];
        }
        let data: EmbedBatchResponse = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "embed decode failed");
                return vec![vec![]; line_starts.len()];
            }
        };

        data.embeddings
            .into_iter()
            .map(|floats| floats.iter().flat_map(|f| f.to_le_bytes()).collect())
            .collect()
    }

    /// Score `feature_vectors` through the GBDT in batch. Empty inner
    /// vecs are skipped; the returned slot is `None` for those indices
    /// and for any index when the GBDT is not yet trained.
    pub async fn predict_batch(
        &self,
        req_id: &str,
        feature_vectors: Vec<Vec<f32>>,
    ) -> Option<Vec<Option<f32>>> {
        let mut compact: Vec<Vec<f32>> = Vec::with_capacity(feature_vectors.len());
        let mut idx_map: Vec<usize> = Vec::with_capacity(feature_vectors.len());
        for (i, v) in feature_vectors.iter().enumerate() {
            if !v.is_empty() {
                idx_map.push(i);
                compact.push(v.clone());
            }
        }
        if compact.is_empty() {
            return None;
        }

        let url = format!("{}/predict_batch", self.base_url);
        let body = serde_json::json!({ "feature_vectors": compact });
        let start = Instant::now();

        let resp = match self
            .with_req_id(self.http.post(&url).json(&body), req_id)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "predict_batch call failed");
                return None;
            }
        };
        if !resp.status().is_success() {
            warn!(status = resp.status().as_u16(), "predict_batch non-success");
            return None;
        }
        let data: PredictBatchResponse = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "predict_batch decode failed");
                return None;
            }
        };
        info!(
            elapsed_ms = start.elapsed().as_millis() as u64,
            model_ready = data.model_ready,
            returned = data.confidences.as_ref().map(|v| v.len()).unwrap_or(0),
            "predict_batch done"
        );

        let confs = data.confidences?;
        if confs.len() != compact.len() {
            warn!(
                got = confs.len(),
                expected = compact.len(),
                "predict_batch length mismatch"
            );
            return None;
        }
        let mut out = vec![None; feature_vectors.len()];
        for (j, &i) in idx_map.iter().enumerate() {
            out[i] = Some(confs[j]);
        }
        Some(out)
    }

    /// Synchronous training trigger — used by `/api/retrain`.
    pub async fn train(&self, req_id: &str) -> Result<serde_json::Value> {
        let url = format!("{}/train", self.base_url);
        let start = Instant::now();
        let resp = self
            .with_req_id(self.http.post(&url).json(&serde_json::json!({})), req_id)
            .send()
            .await?;
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::json!({}));
        info!(
            status = status.as_u16(),
            elapsed_ms = start.elapsed().as_millis() as u64,
            "retrain completed"
        );
        if !status.is_success() {
            return Err(anyhow!("ml /train returned {}", status));
        }
        Ok(body)
    }

    /// Fire-and-forget train — used after every Verify Submit and
    /// every 10 individual feedback labels.
    pub fn spawn_train(&self, req_id: &str) {
        let http = self.http.clone();
        let url = format!("{}/train", self.base_url);
        let req_id = req_id.to_string();
        tokio::spawn(async move {
            let start = Instant::now();
            let result = http
                .post(&url)
                .header("x-request-id", &req_id)
                .json(&serde_json::json!({}))
                .send()
                .await;
            let elapsed_ms = start.elapsed().as_millis() as u64;
            match result {
                Ok(r) => info!(status = r.status().as_u16(), elapsed_ms, "train completed"),
                Err(e) => warn!(error = %e, elapsed_ms, "train failed"),
            }
        });
    }

    /// Fetch model metrics blob — proxied to the Model tab.
    pub async fn metrics(&self, req_id: &str) -> Result<serde_json::Value> {
        let url = format!("{}/metrics", self.base_url);
        let resp = self.with_req_id(self.http.get(&url), req_id).send().await?;
        if !resp.status().is_success() {
            return Err(anyhow!("ml /metrics returned {}", resp.status()));
        }
        let body: serde_json::Value = resp.json().await?;
        Ok(body)
    }

    // ── Internals ──────────────────────────────────────────────────

    fn with_req_id(&self, rb: RequestBuilder, req_id: &str) -> RequestBuilder {
        rb.header("x-request-id", req_id)
    }

    /// Common wire layer for the three detectors. `endpoint` is the
    /// last path segment ("semgrep" / "analyze" / "taint"), `source`
    /// is the value stamped onto each finding's `source` field.
    /// `require_ready` matches the analyzer's `status` gate.
    async fn detect(
        &self,
        endpoint: &str,
        source: &str,
        req_id: &str,
        code: &str,
        language: &Language,
        require_ready: bool,
    ) -> Vec<Finding> {
        let url = format!("{}/{}", self.base_url, endpoint);
        let body = serde_json::json!({
            "code": code,
            "language": language_hint(language),
        });
        let start = Instant::now();

        let resp = match self
            .with_req_id(self.http.post(&url).json(&body), req_id)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, endpoint, "ml call failed");
                return vec![];
            }
        };
        if !resp.status().is_success() {
            warn!(status = resp.status().as_u16(), endpoint, "ml non-success");
            return vec![];
        }
        let ml: MlResponse = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, endpoint, "ml decode failed");
                return vec![];
            }
        };
        if require_ready && ml.status != "ready" {
            info!(status = %ml.status, endpoint, "ml skipped (not ready)");
            return vec![];
        }

        let findings: Vec<Finding> = ml
            .findings
            .into_iter()
            .map(|mf| ml_finding_to_domain(mf, source))
            .collect();
        info!(
            count = findings.len(),
            elapsed_ms = start.elapsed().as_millis() as u64,
            endpoint,
            "ml done"
        );
        findings
    }
}

// ── Free helpers ──────────────────────────────────────────────────────────

pub fn default_base_url() -> String {
    std::env::var("MAKINA_ML_URL").unwrap_or_else(|_| "http://localhost:8080".to_string())
}

/// Embeddings are stored as raw LE float32 bytes (3072 = 768 × 4).
/// Reject sizes that aren't a multiple of 4.
pub fn bytes_to_f32_vec(bytes: &[u8]) -> Vec<f32> {
    #[allow(clippy::manual_is_multiple_of)]
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return vec![];
    }
    bytes
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

fn ml_finding_to_domain(mf: MlFinding, source: &str) -> Finding {
    let is_uncertain = mf.confidence >= 0.45 && mf.confidence <= 0.65;
    Finding {
        id: Uuid::new_v4().to_string(),
        rule_id: mf.rule_id,
        message: mf.message,
        severity: severity_from_str(&mf.severity),
        line_start: mf.line_start,
        line_end: mf.line_end,
        code_snippet: mf.code_snippet,
        confidence: mf.confidence,
        is_uncertain,
        cwe: mf.cwe,
        source: source.to_string(),
    }
}

pub fn severity_from_str(s: &str) -> Severity {
    match s {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        _ => Severity::Low,
    }
}

/// Lowercase tag used by the ML wire format. Stable across the
/// API ↔ ML boundary; also used as the `language` column value
/// when persisting findings.
pub fn language_hint(lang: &Language) -> &'static str {
    match lang {
        Language::Auto => "auto",
        Language::Python => "python",
        Language::Rust => "rust",
        Language::JavaScript => "javascript",
        Language::TypeScript => "typescript",
        Language::Go => "go",
        Language::Java => "java",
        Language::Ruby => "ruby",
        Language::C => "c",
        Language::Cpp => "cpp",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_to_f32_vec_round_trips_three_values() {
        let floats = [1.5_f32, -2.25, 0.125];
        let bytes: Vec<u8> = floats.iter().flat_map(|f| f.to_le_bytes()).collect();
        let out = bytes_to_f32_vec(&bytes);
        assert_eq!(out, floats);
    }

    #[test]
    fn bytes_to_f32_vec_rejects_empty_input() {
        assert_eq!(bytes_to_f32_vec(&[]), Vec::<f32>::new());
    }

    #[test]
    fn bytes_to_f32_vec_rejects_non_multiple_of_four() {
        // 5 bytes is not a valid float buffer — must yield empty.
        assert_eq!(bytes_to_f32_vec(&[0u8; 5]), Vec::<f32>::new());
    }

    #[test]
    fn language_hint_is_stable_for_every_variant() {
        assert_eq!(language_hint(&Language::Auto), "auto");
        assert_eq!(language_hint(&Language::Python), "python");
        assert_eq!(language_hint(&Language::Rust), "rust");
        assert_eq!(language_hint(&Language::JavaScript), "javascript");
        assert_eq!(language_hint(&Language::TypeScript), "typescript");
        assert_eq!(language_hint(&Language::Go), "go");
        assert_eq!(language_hint(&Language::Java), "java");
        assert_eq!(language_hint(&Language::Ruby), "ruby");
        assert_eq!(language_hint(&Language::C), "c");
        assert_eq!(language_hint(&Language::Cpp), "cpp");
    }

    #[test]
    fn severity_from_str_handles_known_buckets() {
        assert!(matches!(severity_from_str("critical"), Severity::Critical));
        assert!(matches!(severity_from_str("high"), Severity::High));
        assert!(matches!(severity_from_str("medium"), Severity::Medium));
        assert!(matches!(severity_from_str("low"), Severity::Low));
    }

    #[test]
    fn severity_from_str_falls_back_to_low_for_unknown() {
        assert!(matches!(severity_from_str(""), Severity::Low));
        assert!(matches!(severity_from_str("bogus"), Severity::Low));
    }

    #[test]
    fn ml_finding_to_domain_marks_uncertain_band() {
        let mk = |conf: f32| MlFinding {
            rule_id: "r".into(),
            message: "m".into(),
            severity: "low".into(),
            line_start: 1,
            line_end: 1,
            code_snippet: "".into(),
            confidence: conf,
            cwe: None,
        };
        // Uncertain band is [0.45, 0.65] inclusive.
        assert!(ml_finding_to_domain(mk(0.50), "ml").is_uncertain);
        assert!(ml_finding_to_domain(mk(0.45), "ml").is_uncertain);
        assert!(ml_finding_to_domain(mk(0.65), "ml").is_uncertain);
        assert!(!ml_finding_to_domain(mk(0.44), "ml").is_uncertain);
        assert!(!ml_finding_to_domain(mk(0.66), "ml").is_uncertain);
        assert!(!ml_finding_to_domain(mk(0.95), "ml").is_uncertain);
    }

    #[test]
    fn ml_finding_to_domain_propagates_source_tag() {
        let mf = MlFinding {
            rule_id: "r".into(),
            message: "m".into(),
            severity: "high".into(),
            line_start: 7,
            line_end: 9,
            code_snippet: "snip".into(),
            confidence: 0.9,
            cwe: Some("CWE-78".into()),
        };
        let f = ml_finding_to_domain(mf, "taint");
        assert_eq!(f.source, "taint");
        assert_eq!(f.line_start, 7);
        assert_eq!(f.cwe.as_deref(), Some("CWE-78"));
    }

    #[test]
    fn default_base_url_falls_back_when_env_missing() {
        // Save+clear the env var so we exercise the fallback branch.
        let prev = std::env::var("MAKINA_ML_URL").ok();
        std::env::remove_var("MAKINA_ML_URL");
        assert_eq!(default_base_url(), "http://localhost:8080");
        if let Some(v) = prev {
            std::env::set_var("MAKINA_ML_URL", v);
        }
    }
}
