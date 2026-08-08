//! Shim process spawning and lifecycle utilities.
//!
//! Free functions shared by [`super::Runtime`] spawn paths and
//! [`super::VmHandle`] restart logic.

use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{fs, io};

use nix::sys::signal;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::Pid;

use bux_jail::JailConfig;
use bux_proto::{GUEST_BOOT_CONFIG_ENV, GuestBootConfig, GuestNetworkMode};
use bux_shim::ShimNetwork;

use crate::Result;
use crate::guest::ManagedGuestBinary;
use crate::state;
use crate::watchdog::{self, Keepalive};

/// Result of spawning a shim subprocess.
pub(super) struct ShimSpawnResult {
    /// Child PID (as i32 for nix compatibility).
    pub pid: i32,
    /// Parent-side watchdog keepalive.
    pub keepalive: Option<Keepalive>,
    /// Actual security posture from the jail spawn.
    pub security: crate::security::SecurityStatus,
}

/// Builds a diagnostic message when the shim process dies before the guest agent is ready.
///
/// Combines structured [`ExitInfo`] JSON and the last few lines of the shim's
/// stderr file into a single actionable error message.
pub(super) fn shim_death_message(pid: i32, exit_file: &Path) -> String {
    let detail = crate::ExitInfo::from_file(exit_file)
        .map_or_else(|| "unknown reason".into(), |info| info.summary());

    let stderr_path = exit_file.with_extension("stderr");
    let stderr_hint = fs::read_to_string(&stderr_path)
        .ok()
        .filter(|s| !s.is_empty())
        .map(|s| {
            let total = s.lines().count();
            let skip = total.saturating_sub(5);
            let tail: String = s.lines().skip(skip).collect::<Vec<_>>().join("\n");
            format!("\n  stderr:\n    {}", tail.replace('\n', "\n    "))
        })
        .unwrap_or_default();

    format!("VM process (pid {pid}) died before ready: {detail}{stderr_hint}")
}

/// Removes all transient files associated with a VM socket path.
///
/// Cleans `.sock`, `.exit`, `.json`, and `.stderr` files that share the
/// same stem as the socket.
pub(super) fn clean_vm_files(socket: &Path) {
    drop(fs::remove_file(socket));
    for ext in ["exit", "json", "stderr"] {
        drop(fs::remove_file(socket.with_extension(ext)));
    }
}

/// Checks if a process is alive via `kill(pid, 0)`.
pub(super) fn is_pid_alive(pid: i32) -> bool {
    signal::kill(Pid::from_raw(pid), None).is_ok()
}

/// Blocks until a process exits.
///
/// Tries `waitpid` first (works for child processes — zero CPU, zero delay).
/// Falls back to `kill(pid, 0)` polling if the process is not a direct child.
#[allow(
    clippy::disallowed_methods,
    reason = "sync fallback poll cannot use tokio::time::sleep"
)]
pub(super) fn wait_for_exit(pid: i32) {
    let nix_pid = Pid::from_raw(pid);
    if let Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..)) = waitpid(nix_pid, None) {
        return;
    }
    while is_pid_alive(pid) {
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Resolves the managed guest binary and validates the VM configuration for managed mode.
///
/// Boot-time `env` / `workdir` / `uid` / `gid` on the product config are **routed**
/// into [`state::VmConfig::workload_*`] fields for Phase A exec defaults — they are
/// not applied as libkrun boot identity. Guest boot env is re-injected later via
/// [`inject_guest_boot_env`].
pub(super) fn prepare_managed_config(config: &mut state::VmConfig) -> Result<()> {
    let guest = ManagedGuestBinary::resolve()?;

    if let Some(exec_path) = config.exec_path.as_deref()
        && exec_path != ManagedGuestBinary::exec_path()
    {
        return Err(crate::Error::InvalidConfig(
            "managed runtime no longer supports boot-time exec; start the VM, then run commands through bux exec".to_owned(),
        ));
    }
    if config.root_disk.is_some() && config.rootfs.is_none() && config.base_disk.is_none() {
        return Err(crate::Error::InvalidConfig(
            "managed runtime does not yet support direct root_disk boot without a managed guest-rootfs preparation step".to_owned(),
        ));
    }
    if let Some(rootfs) = config.rootfs.as_deref() {
        guest.inject_into_rootfs(Path::new(rootfs))?;
    }

    route_workload_identity(config);

    config.exec_path = Some(ManagedGuestBinary::exec_path().to_owned());
    config.exec_args.clear();
    // Boot env is set only by inject_guest_boot_env (BUX_GUEST_CONFIG).
    config.env = None;
    config.workdir = None;
    config.uid = None;
    config.gid = None;
    Ok(())
}

/// Move product identity fields into `workload_*` (Phase A exec defaults).
///
/// Existing `workload_*` values win over migrated boot-style fields.
/// Entries for [`GUEST_BOOT_CONFIG_ENV`] are never treated as workload env
/// (restart re-runs this after a previous `inject_guest_boot_env`).
fn route_workload_identity(config: &mut state::VmConfig) {
    if let Some(env) = config.env.take()
        && config.workload_env.is_empty()
    {
        let prefix = format!("{GUEST_BOOT_CONFIG_ENV}=");
        let workload: Vec<String> = env
            .into_iter()
            .filter(|e| !e.starts_with(&prefix))
            .collect();
        if !workload.is_empty() {
            config.workload_env = workload;
        }
    }
    if config.workload_workdir.is_none() {
        config.workload_workdir = config.workdir.take();
    }
    if config.workload_user.is_none() {
        match (config.uid, config.gid) {
            (Some(u), Some(g)) => config.workload_user = Some(format!("{u}:{g}")),
            (Some(u), None) => config.workload_user = Some(u.to_string()),
            (None, Some(g)) => config.workload_user = Some(format!("0:{g}")),
            (None, None) => {}
        }
    }
}

/// Inject `BUX_GUEST_CONFIG` for the guest agent (network mode + optional MITM CA).
///
/// Called after [`prepare_managed_config`] once the VM id is known.
pub(super) fn inject_guest_boot_env(
    config: &mut state::VmConfig,
    vm_id: &str,
    mitm_ca_pem: Option<String>,
) -> Result<()> {
    let mode = if config.virtio_net {
        GuestNetworkMode::Enabled
    } else {
        GuestNetworkMode::Disabled
    };
    let mut boot = GuestBootConfig::new(vm_id, mode);
    boot.mitm_ca_pem = mitm_ca_pem;
    let entry = boot
        .to_env_assignment()
        .map_err(crate::Error::InvalidConfig)?;
    config.env = Some(vec![entry]);
    Ok(())
}

/// Writes config JSON, creates watchdog pipe, and spawns `bux-shim` inside a sandbox.
///
/// Shared by [`super::Runtime::spawn()`] and [`super::VmHandle::start()`].
///
/// `network`: when `Some`, shim attaches virtio-net (gvproxy); when `None`, TSI ports.
///
/// # Errors
///
/// Returns [`crate::Error::SecurityUnavailable`] when Landlock is required but missing (K22),
/// or I/O / jail errors on spawn failure.
pub(super) fn spawn_shim(
    config: &state::VmConfig,
    config_path: &Path,
    socks_dir: &Path,
    vm_id: &str,
    watch_parent: bool,
    network: Option<ShimNetwork>,
) -> Result<ShimSpawnResult> {
    // Engine wire format is ShimConfig (not product VmConfig).
    let shim_cfg = crate::shim_convert::to_shim_config(vm_id, config, network);
    let json = shim_cfg
        .to_json()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    fs::write(config_path, &json)?;

    // Capture shim stderr to a file for post-mortem diagnostics.
    let stderr_path = config_path.with_extension("stderr");
    let stderr_file = fs::File::create(&stderr_path)?;

    let (shim_wd_fd, keepalive) = if watch_parent {
        let (fd, keepalive) = watchdog::create()?;
        (Some(fd), Some(keepalive))
    } else {
        (None, None)
    };
    let shim = find_shim()?;
    #[cfg(target_os = "macos")]
    ensure_shim_dylib_aliases(&shim)?;

    let readonly_paths = config
        .root_disk
        .as_deref()
        .map(|d| crate::disk::readonly_disk_paths(Path::new(d)))
        .unwrap_or_default();

    let sec = &config.security;
    let sandbox: Option<Box<dyn bux_jail::Sandbox>> = if sec.jailer {
        None // auto-detect bwrap/seatbelt
    } else {
        Some(Box::new(bux_jail::NoopSandbox::default()))
    };

    // Include net socket dir (same socks_dir) so bwrap/seatbelt can reach gvproxy.
    let jail_config = JailConfig {
        rootfs: config.rootfs.as_deref().map(PathBuf::from),
        root_disk: config.root_disk.as_deref().map(PathBuf::from),
        readonly_paths,
        socks_dir: socks_dir.to_path_buf(),
        virtiofs_paths: config
            .virtiofs
            .iter()
            .map(|v| PathBuf::from(&v.path))
            .collect(),
        watchdog_fd: shim_wd_fd
            .as_ref()
            .map(std::os::unix::io::AsRawFd::as_raw_fd),
        sandbox,
        resource_limits: None,
        stderr_file: Some(stderr_file),
        landlock: sec.landlock,
        allow_degraded_security: sec.allow_degraded,
    };

    let result = bux_jail::spawn(&shim, config_path, jail_config, vm_id).map_err(|e| {
        drop(fs::remove_file(config_path));
        map_jail_error(e, &shim)
    })?;

    #[allow(
        clippy::cast_possible_wrap,
        reason = "PID fits in i32 on all supported platforms"
    )]
    let pid = result.child.id() as i32;
    drop(shim_wd_fd);

    Ok(ShimSpawnResult {
        pid,
        keepalive,
        security: crate::security::SecurityStatus::from_report(&result.security),
    })
}

/// Map jail errors to product errors (preserve K22 fail-closed).
fn map_jail_error(e: bux_jail::Error, shim: &Path) -> crate::Error {
    match e {
        bux_jail::Error::LandlockUnavailable => {
            crate::Error::SecurityUnavailable(
                "landlock required but unavailable on this kernel (set SecurityOptions.allow_degraded to proceed)"
                    .into(),
            )
        }
        bux_jail::Error::Landlock(msg) => {
            crate::Error::SecurityUnavailable(format!("landlock ruleset failed: {msg}"))
        }
        bux_jail::Error::Io(io_err) => crate::Error::Io(io::Error::new(
            io_err.kind(),
            format!("failed to spawn {}: {io_err}", shim.display()),
        )),
        other => crate::Error::Jail(other),
    }
}

/// Locates the `bux-shim` binary.
///
/// Search order:
/// 1. `$BUX_SHIM_PATH` environment variable (development override).
/// 2. Next to the current executable.
/// 3. In `$PATH`.
fn find_shim() -> io::Result<PathBuf> {
    const NAME: &str = "bux-shim";

    if let Ok(p) = std::env::var("BUX_SHIM_PATH") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Ok(path);
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name(NAME);
        if sibling.is_file() {
            return Ok(sibling);
        }
    }

    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(NAME);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("'{NAME}' not found; install it next to the bux binary or in $PATH"),
    ))
}

#[cfg(target_os = "macos")]
#[allow(
    clippy::missing_docs_in_private_items,
    reason = "macOS-only helper with self-explanatory name"
)]
fn ensure_shim_dylib_aliases(shim: &Path) -> io::Result<()> {
    let Some(shim_dir) = shim.parent() else {
        return Ok(());
    };

    for (src, alias) in [
        ("libkrun.dylib", "libkrun.1.dylib"),
        ("libkrunfw.dylib", "libkrunfw.5.dylib"),
    ] {
        let src_path = shim_dir.join(src);
        let alias_path = shim_dir.join(alias);
        if alias_path.exists() {
            continue;
        }
        if !src_path.exists() {
            continue;
        }
        match std::os::unix::fs::symlink(src, &alias_path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            Err(_) => {
                fs::copy(&src_path, &alias_path)?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use crate::state::VmConfig;

    fn empty_config() -> VmConfig {
        VmConfig {
            vcpus: 1,
            ram_mib: 512,
            rootfs: None,
            root_disk: None,
            disk_format: crate::disk::DiskFormat::default(),
            base_disk: None,
            exec_path: None,
            exec_args: vec![],
            env: None,
            workdir: None,
            ports: vec![],
            allow_net: vec![],
            published_ports: vec![],
            virtiofs: vec![],
            vsock_ports: vec![],
            log_level: None,
            uid: None,
            gid: None,
            rlimits: vec![],
            nested_virt: None,
            snd_device: None,
            console_output: None,
            virtio_net: true,
            secrets_required: false,
            workload_env: vec![],
            workload_workdir: None,
            workload_user: None,
            security: crate::security::SecurityOptions::default(),
            security_status: crate::security::SecurityStatus::default(),
            auto_remove: false,
            auto_stop_secs: None,
            auto_delete_secs: None,
            last_activity_at: None,
            last_error: None,
        }
    }

    #[test]
    fn route_migrates_env_workdir_user() {
        let mut c = empty_config();
        c.env = Some(vec!["FOO=bar".into(), "BAZ=1".into()]);
        c.workdir = Some("/app".into());
        c.uid = Some(1000);
        c.gid = Some(1000);

        route_workload_identity(&mut c);

        assert_eq!(c.workload_env, vec!["FOO=bar", "BAZ=1"]);
        assert_eq!(c.workload_workdir.as_deref(), Some("/app"));
        assert_eq!(c.workload_user.as_deref(), Some("1000:1000"));
        assert!(c.env.is_none());
        assert!(c.workdir.is_none());
    }

    #[test]
    fn route_skips_guest_boot_config_env() {
        let mut c = empty_config();
        c.env = Some(vec![format!("{GUEST_BOOT_CONFIG_ENV}={{\"vm_id\":\"x\"}}")]);
        c.workload_env = vec!["KEEP=1".into()];

        route_workload_identity(&mut c);

        assert_eq!(c.workload_env, vec!["KEEP=1"]);
        assert!(c.env.is_none());
    }

    #[test]
    fn route_preserves_existing_workload() {
        let mut c = empty_config();
        c.env = Some(vec!["NEW=1".into()]);
        c.workdir = Some("/new".into());
        c.uid = Some(1);
        c.workload_env = vec!["OLD=1".into()];
        c.workload_workdir = Some("/old".into());
        c.workload_user = Some("root".into());

        route_workload_identity(&mut c);

        assert_eq!(c.workload_env, vec!["OLD=1"]);
        assert_eq!(c.workload_workdir.as_deref(), Some("/old"));
        assert_eq!(c.workload_user.as_deref(), Some("root"));
    }
}
