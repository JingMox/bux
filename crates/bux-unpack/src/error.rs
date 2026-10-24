//! Error types for bux-unpack.

/// Result type for layer extraction.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors from layer extraction.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
#[allow(
    clippy::error_impl_error,
    reason = "idiomatic per-crate Error; disambiguated via bux_unpack::Error"
)]
pub enum Error {
    /// Filesystem I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// A layer member was refused (escape, hop limit, or invalid whiteout).
    #[error("extract: {0}")]
    Extract(String),
}
