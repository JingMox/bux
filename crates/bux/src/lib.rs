//! Embedded micro-VM sandbox for running AI agents.
//!
//! `bux` wraps [`libkrun`] into a safe Rust API for creating, running,
//! and managing lightweight virtual machines powered by KVM (Linux) or
//! Hypervisor.framework (macOS).
//!
//! # Quick start — managed VM via Runtime
//!
//! ```no_run
//! # #[cfg(unix)]
//! # async fn example() -> bux::Result<()> {
//! use bux::{ExecStart, Runtime, VmOptions};
//!
//! let rt = Runtime::open(bux::default_data_dir())?;
//! let mut vm = rt
//!     .create(VmOptions::from_image("python:slim").vcpus(2).ram_mib(1024))
//!     .await?;
//!
//! vm.exec_output(ExecStart::new("python").args(vec!["-c".into(), "print(1)".into()]))
//!     .await?;
//! vm.stop().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Quick start — low-level VM (takes over the process)
//!
//! ```no_run
//! # #[cfg(unix)]
//! # fn demo() {
//! use bux::Vm;
//!
//! let vm = Vm::builder()
//!     .vcpus(2)
//!     .ram_mib(512)
//!     .root("/path/to/rootfs")
//!     .exec("/bin/bash", &["--login"])
//!     .build()
//!     .expect("invalid VM config");
//!
//! vm.start().expect("failed to start VM");
//! # }
//! ```
//!
//! [`libkrun`]: https://github.com/containers/libkrun

#[cfg(unix)]
mod client;
mod disk;
mod error;
pub mod events;
#[cfg(unix)]
mod guest;
#[cfg(unix)]
pub mod health;
#[cfg(unix)]
pub mod lifecycle;
mod log_level;
pub mod metrics;
#[cfg(unix)]
mod net_manager;
#[cfg(unix)]
pub mod options;
#[cfg(unix)]
mod pipeline;
#[cfg(unix)]
pub mod process;
pub mod ports;
pub mod security;
#[cfg(unix)]
pub mod volumes;
#[cfg(unix)]
mod runtime;
#[cfg(unix)]
pub mod secrets;
#[cfg(unix)]
mod shim_convert;
#[cfg(unix)]
pub mod snapshot;
mod state;
mod util;
#[cfg(unix)]
mod vm;
#[cfg(unix)]
pub mod watchdog;

#[cfg(unix)]
pub use bux_krun::{Feature, KernelFormat, LogStyle, SyncMode};
pub use bux_proto::{ExecStart, GuestBootConfig, GuestNetworkMode, GUEST_BOOT_CONFIG_ENV};
#[cfg(target_os = "linux")]
pub use bux_seccomp::Error as SeccompError;
#[cfg(unix)]
pub use bux_shim::{ExitInfo, PANIC_EXIT_CODE, SIGNAL_EXIT_BASE};
#[cfg(unix)]
pub use bux_shim::{ShimConfig, ShimDiskFormat, ShimNetConn, ShimNetwork};
#[cfg(unix)]
pub use client::{Client, ExecHandle, ExecOutput, PongInfo};
pub use disk::DiskFormat;
#[cfg(unix)]
pub use disk::{Disk, DiskManager, QcowHeader};
pub use error::{Error, Result};
pub use events::{
    AuditEvent, AuditEventKind, CopyDirection, EventDispatcher, EventListener, RingBufferListener,
};
#[cfg(unix)]
pub use health::{HealthCheckConfig, HealthCheckHandle};
#[cfg(unix)]
pub use bux_jail::checks::{HostCapabilities, audit_isolation, check_guest_binary, check_host};
#[cfg(target_os = "linux")]
pub use bux_jail::credentials::CredentialConfig;
#[cfg(unix)]
pub use bux_jail::{
    JailConfig, NoopSandbox, ResourceLimits, Sandbox, SandboxCapabilities, SandboxKind,
};
#[cfg(unix)]
pub use lifecycle::{RecoverAction, SECRETS_RESUPPLY_ERROR, SweepReport, recover_action};
pub use log_level::{LogLevel, ParseLogLevelError};
pub use metrics::{BoxMetrics, RuntimeMetrics};
#[cfg(unix)]
pub use options::{ImageRef, VmOptions};
#[cfg(unix)]
pub use process::{
    PHASE_A_LIMITS, PHASE_B_LIMITS, apply_workload_defaults, merge_env, parse_numeric_user,
};
pub use ports::{PortSpec, PublishedPort, BIND_ADDR, parse_publish_spec, resolve_ports};
pub use security::{HostInfo, LayerStatus, SecurityOptions, SecurityStatus};
#[cfg(unix)]
pub use volumes::{
    VolumeInfo, VolumeManager, VolumeMount, VolumeSource, parse_bind_spec, validate_volume_name,
};
#[cfg(unix)]
pub use secrets::{SECRET_PLACEHOLDER_PREFIX, Secret, StartOptions, default_placeholder};
#[cfg(unix)]
pub use runtime::{HealthStatus, RunOptions, Runtime, VmHandle, default_data_dir};
#[cfg(unix)]
pub use snapshot::{SnapshotInfo, SnapshotManager};
#[cfg(unix)]
pub use state::{BaseDiskRow, PRODUCT_SCHEMA_VERSION, SnapshotRow, StateDb};
pub use state::{HealthState, Status, VirtioFs, VmConfig, VmState, VsockPort};
#[cfg(unix)]
pub use vm::{Vm, VmBuilder};

/// Crash-diagnostics helpers shared with the shim (exit codes).
#[cfg(unix)]
pub mod exit_info {
    pub use bux_shim::{ExitInfo, PANIC_EXIT_CODE, SIGNAL_EXIT_BASE};
}
