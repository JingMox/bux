//! Host side of the guest agent channel.
//!
//! libkrun maps the agent's vsock port to a Unix socket on the host
//! (`{id}.sock`). Everything that talks to the agent connects through
//! [`connect`], so the socket type lives in one place.

use std::io;
use std::path::Path;

/// Connected stream to the guest agent.
pub(crate) type Stream = tokio::net::UnixStream;

/// Connect to the guest agent socket at `path`.
pub(crate) async fn connect(path: &Path) -> io::Result<Stream> {
    tokio::net::UnixStream::connect(path).await
}

/// Listener that stands in for the guest agent in tests.
#[cfg(test)]
pub(crate) type Listener = tokio::net::UnixListener;

/// Bind a [`Listener`] at `path`.
#[cfg(test)]
pub(crate) fn listen(path: &Path) -> io::Result<Listener> {
    tokio::net::UnixListener::bind(path)
}
