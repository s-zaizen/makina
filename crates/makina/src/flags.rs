//! Runtime feature flags.
//!
//! Read from environment once at startup and passed through the router
//! by value (cheap copy). Kept deliberately small — for makina the only
//! axis that matters is "public deployment vs developer dogfood":
//!
//! * **public mode** (`MAKINA_PUBLIC_MODE=true`) — read-only demo. The
//!   model is fixed, so every endpoint that mutates labels or triggers
//!   retraining is removed from the router and returns 404.
//! * **dev mode** (default) — full Verify → train loop is wired up.
//!
//! We picked a hand-rolled struct over the OpenFeature Rust SDK because
//! the latter is still alpha as of the time of writing; once it
//! stabilises (or once we host Flipt / Unleash) this module is the only
//! seam to swap.

#[derive(Debug, Clone, Copy)]
pub struct Flags {
    /// True when the deployment is publicly visible and must not accept
    /// learning-loop writes (feedback, manual findings, verify queue
    /// submit, knowledge submit, retrain).
    pub public_mode: bool,
}

impl Flags {
    pub fn from_env() -> Self {
        Self {
            public_mode: bool_env("MAKINA_PUBLIC_MODE"),
        }
    }
}

fn bool_env(key: &str) -> bool {
    matches!(
        std::env::var(key).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("True") | Some("yes")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn with_env<F: FnOnce()>(key: &str, value: Option<&str>, body: F) {
        let prev = std::env::var(key).ok();
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        body();
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    #[serial]
    fn defaults_to_dev_mode_when_env_absent() {
        with_env("MAKINA_PUBLIC_MODE", None, || {
            assert!(!Flags::from_env().public_mode);
        });
    }

    #[test]
    #[serial]
    fn parses_truthy_values() {
        for v in ["1", "true", "TRUE", "True", "yes"] {
            with_env("MAKINA_PUBLIC_MODE", Some(v), || {
                assert!(Flags::from_env().public_mode, "expected true for {v:?}");
            });
        }
    }

    #[test]
    #[serial]
    fn rejects_falsy_and_garbage() {
        for v in ["0", "false", "no", "off", "", "garbage"] {
            with_env("MAKINA_PUBLIC_MODE", Some(v), || {
                assert!(!Flags::from_env().public_mode, "expected false for {v:?}");
            });
        }
    }
}
