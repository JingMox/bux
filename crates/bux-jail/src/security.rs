//! Security layer outcomes reported after a jail spawn.

/// Status of one isolation layer after spawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LayerStatus {
    /// Layer was requested and is active on the child process.
    Enforced,
    /// Layer was requested, unavailable, and [`crate::JailConfig::allow_degraded_security`]
    /// allowed continue.
    Degraded,
    /// Layer was not requested.
    Disabled,
    /// Layer does not apply on this platform (e.g. Landlock off Linux).
    NotApplicable,
}

/// Isolation stack used for the shim process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SandboxKind {
    /// Linux bubblewrap namespaces.
    Bwrap,
    /// macOS `sandbox-exec` seatbelt.
    Seatbelt,
    /// No platform sandbox (`pre_exec` hardening only).
    Noop,
}

impl SandboxKind {
    /// Stable string for logs / inspect.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bwrap => "bwrap",
            Self::Seatbelt => "seatbelt",
            Self::Noop => "noop",
        }
    }
}

/// Actual security posture for a spawned shim (for `VmInfo` / inspect).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SecurityReport {
    /// Platform sandbox in use.
    pub sandbox: SandboxKind,
    /// Landlock LSM (Linux).
    pub landlock: LayerStatus,
    /// Seatbelt / MAC layer status (macOS seatbelt is covered by [`Self::sandbox`]).
    pub mac: LayerStatus,
}
