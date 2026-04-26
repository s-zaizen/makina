//! Vertical slices — one module per user-visible feature (Scan,
//! Verify, Knowledge, Model, plus the supporting `labels` and
//! `findings` endpoints). Each slice owns its handler(s) and pulls
//! in `infra::ml`, `store`, and `api::models` as needed.

pub mod findings;
pub mod knowledge;
pub mod labels;
pub mod model;
pub mod scan;
pub mod verify;
