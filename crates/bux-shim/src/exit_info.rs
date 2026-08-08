//! Structured crash diagnostics written by the shim process.
//!
//! The host Runtime reads these JSON files when a shim dies before the
//! guest agent becomes ready.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Structured exit information written by the shim on crash.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
#[non_exhaustive]
pub enum ExitInfo {
    /// Process killed by a signal.
    Signal {
        /// Unix convention: 128 + signal number.
        exit_code: i32,
        /// Signal name (e.g. `"SIGABRT"`).
        signal: String,
    },
    /// Rust panic occurred.
    Panic {
        /// Always 101 (Rust default panic exit code).
        exit_code: i32,
        /// Panic message payload.
        message: String,
        /// Source location (`file:line:col`).
        location: String,
    },
    /// Normal error from boot or config parsing.
    Error {
        /// Process exit code.
        exit_code: i32,
        /// Error description.
        message: String,
    },
}

impl ExitInfo {
    /// Reads exit info from a JSON file. Returns `None` if missing or invalid.
    #[must_use]
    pub fn from_file(path: &Path) -> Option<Self> {
        let content = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&content).ok()
    }

    /// Exit code regardless of variant.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Signal { exit_code, .. }
            | Self::Panic { exit_code, .. }
            | Self::Error { exit_code, .. } => *exit_code,
        }
    }

    /// Human-readable summary for error messages.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::Signal { signal, .. } => format!("killed by {signal}"),
            Self::Panic {
                message, location, ..
            } => format!("panic at {location}: {message}"),
            Self::Error { message, .. } => message.clone(),
        }
    }
}

/// Unix convention: exit code = 128 + signal number.
pub const SIGNAL_EXIT_BASE: i32 = 128;

/// Rust default panic exit code.
pub const PANIC_EXIT_CODE: i32 = 101;

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn serde_signal() {
        let info = ExitInfo::Signal {
            exit_code: 134,
            signal: "SIGABRT".into(),
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: ExitInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.exit_code(), 134);
        assert!(parsed.summary().contains("SIGABRT"));
    }
}
