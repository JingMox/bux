//! Safe OCI layer extraction for bux.
//!
//! [`extract_layer_files`] applies image layer tarballs to a directory in
//! order, with OCI whiteout semantics. Every member path is resolved inside
//! the destination root: symlinks are followed there and absolute targets are
//! re-anchored at the root, so a crafted layer cannot write or delete outside
//! it. On Linux the resolver uses `pathrs`.

#![allow(
    clippy::missing_docs_in_private_items,
    reason = "internal modules have self-explanatory fields"
)]

mod error;
mod extract;
mod safe_root;

pub use error::{Error, Result};
pub use extract::extract_layer_files;
