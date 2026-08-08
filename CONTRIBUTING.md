# Contributing to bux

## Build

```bash
cargo build -p bux -p bux-cli -p bux-shim
# Linux guest agent (static musl recommended for rootfs injection):
cargo build -p bux-guest --target aarch64-unknown-linux-musl   # or x86_64-...
```

Requires a working C toolchain for libkrun / e2fs / qcow2 native deps, and Go for `bux-gvproxy` (build.rs compiles the bridge).

## Capture environment

| Variable | Purpose |
|----------|---------|
| `BUX_HOME` | Runtime data directory (lock, SQLite, disks, volumes, socks) |
| `BUX_SHIM_PATH` | Absolute path to `bux-shim` (else next to CLI or `$PATH`) |
| `BUX_GUEST_DIR` | Directory with prebuilt `bux-guest` Linux ELF for host arch |
| `BUX_GUEST_DOWNLOAD` | Set `1` to fetch a release guest binary when none is local |
| `PATH` | Locates `bux-shim`, `bwrap` (Linux), `sandbox-exec` (macOS), `go` |

Inspect the live host with:

```bash
bux system info
bux system info --format json
```

## Architecture notes

- Product entry: `Runtime` + `VmOptions` / `ImageRef` (`crates/bux`).
- Engine boundary: product `VmConfig` → `ShimConfig` → `bux-shim` → libkrun.
- Managed network: gvproxy virtio-net (default); secrets are memory-only MITM placeholders.
- Guest agent: postcard protocol (`PROTOCOL_VERSION`); Phase A process identity only.
- Schema: product SQLite `user_version` — **no migrations**; wipe `BUX_HOME` on version mismatch.

Design RFC: `docs/bux-redesign.md`.

## Tests

```bash
cargo test -p bux --lib
cargo test -p bux-proto --lib
# Full e2e (needs KVM/HVF + Linux guest binary + rootfs):
./scripts/e2e/smoke.sh
```

## Lints

Workspace clippy is strict (`unsafe_code = deny` with crate exceptions). Prefer small, modular PRs along the redesign plan spine.
