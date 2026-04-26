//! Outbound adapters — concrete clients for things that live outside
//! the Rust core (Python ML service, future RunPod jobs, …).
//!
//! Feature handlers should depend on this layer rather than calling
//! `reqwest`/`serde_json` directly, so the wire format stays pinned in
//! one place and tests can substitute a fake.

pub mod ml;
