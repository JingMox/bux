# bux-net

Network backend abstraction for bux micro-VMs.

## Overview

This crate exposes a small, backend-neutral API:

- **`NetworkBackend` trait** — test/mock surface; product path is gvproxy only.
- **`NetworkConfig`** — concrete port mappings, `allow_net`, secrets + CA PEMs,
  optional stats logging (off by default).
- **`GvproxyBackend`** — concrete backend over [`bux-gvproxy`](../bux-gvproxy/).
- **`SocketShortener`** — Unix domain socket `sun_path` length workaround.

Network-topology defaults (subnet, gateway/guest IP & MAC, MTU, DNS
search domains) live in `bux_gvproxy::constants` — the single source of
truth for both the Go and Rust sides.

## Layering

```text
bux-net        (this crate — pure Rust, no native deps)
    │
    ▼
bux-gvproxy    (L1 platform primitive — Go CGO bridge + FFI)
    │
    ▼
libgvproxy.a   (Go c-archive)
```

Because the Go toolchain dependency now lives entirely in
`bux-gvproxy`, `bux-net` itself is a pure-Rust crate with no
`build.rs`.

## License

MIT OR Apache-2.0
