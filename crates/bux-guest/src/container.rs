//! Primary OCI workload container (Phase B).
//!
//! Starts a long-lived primary container with libcontainer so exec can enter
//! its namespaces (`nsenter`). Agent remains outside as supervisor (K24).
//!
//! If container startup fails, the agent continues in Phase A (shared NS).

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use libcontainer::container::builder::ContainerBuilder;
use libcontainer::syscall::syscall::SyscallType;
use oci_spec::runtime::{
    LinuxBuilder, LinuxNamespaceBuilder, LinuxNamespaceType, ProcessBuilder, RootBuilder,
    SpecBuilder, UserBuilder,
};

/// Guest layout root for container state/bundles.
const RUN_BUX: &str = "/run/bux";
/// Stable primary container id.
const PRIMARY_ID: &str = "primary";

/// Global primary container (init PID) after successful Phase B start.
static PRIMARY: OnceLock<PrimaryContainer> = OnceLock::new();

/// Handle to the primary workload container.
#[derive(Debug)]
pub struct PrimaryContainer {
    /// Init process PID inside the guest (container init).
    pub init_pid: i32,
    /// libcontainer state root (retained for future exec/kill APIs).
    #[allow(
        dead_code,
        reason = "state root reserved for full libcontainer exec path"
    )]
    pub state_root: PathBuf,
    /// OCI bundle path (retained for lifecycle management).
    #[allow(dead_code, reason = "bundle path reserved for container delete/status")]
    pub bundle_path: PathBuf,
}

/// Current workload isolation label for ping.
#[must_use]
pub fn workload_isolation() -> &'static str {
    if PRIMARY.get().is_some() {
        "phase_b"
    } else {
        "phase_a"
    }
}

/// Whether Phase B primary container is ready.
#[must_use]
pub fn phase_b_ready() -> bool {
    PRIMARY.get().is_some()
}

/// Start the primary container if requested. Failures are non-fatal (Phase A fallback).
pub fn try_start_primary(enabled: bool) {
    if !enabled {
        eprintln!("[bux-guest] primary container disabled by boot config");
        return;
    }
    match start_primary() {
        Ok(pc) => {
            let pid = pc.init_pid;
            if PRIMARY.set(pc).is_err() {
                eprintln!("[bux-guest] primary container already set");
            } else {
                eprintln!("[bux-guest] Phase B primary container ready (init_pid={pid})");
            }
        }
        Err(e) => {
            eprintln!("[bux-guest] Phase B primary container failed: {e}; continuing Phase A");
        }
    }
}

/// Whether this exec should run inside the primary container.
///
/// # Errors
///
/// Returns an error if `in_container=true` but Phase B is not ready.
pub fn should_use_container(in_container: Option<bool>) -> Result<bool, io::Error> {
    match in_container {
        Some(true) if !phase_b_ready() => Err(io::Error::other(
            "in_container=true requested but Phase B primary container is not available",
        )),
        Some(true) => Ok(true),
        Some(false) => Ok(false),
        None => Ok(phase_b_ready()),
    }
}

/// Resolve program + argv for an exec, optionally wrapping with `nsenter`.
///
/// Returns `(program, args)` ready for `Command::new(program).args(args)`.
pub fn resolve_exec_argv(
    cmd: &str,
    args: &[String],
    in_container: Option<bool>,
) -> io::Result<(String, Vec<String>)> {
    if !should_use_container(in_container)? {
        return Ok((cmd.to_owned(), args.to_vec()));
    }
    let Some(pc) = PRIMARY.get() else {
        return Err(io::Error::other("primary container not ready"));
    };
    // nsenter -t <init> -m -u -i -p -- <cmd> <args...>
    let mut ns_args = vec![
        "-t".into(),
        pc.init_pid.to_string(),
        "-m".into(),
        "-u".into(),
        "-i".into(),
        "-p".into(),
        "--".into(),
        cmd.to_owned(),
    ];
    ns_args.extend(args.iter().cloned());
    Ok(("nsenter".into(), ns_args))
}

/// Create the OCI bundle, start the primary container, and return its handle.
fn start_primary() -> io::Result<PrimaryContainer> {
    let run = Path::new(RUN_BUX);
    let state_root = run.join("state");
    let bundle_path = run.join("containers").join(PRIMARY_ID);
    fs::create_dir_all(&state_root)?;
    fs::create_dir_all(&bundle_path)?;

    write_oci_config(&bundle_path)?;

    let mut container = ContainerBuilder::new(PRIMARY_ID.to_owned(), SyscallType::default())
        .with_root_path(state_root.clone())
        .map_err(io_map)?
        .as_init(&bundle_path)
        .with_systemd(false)
        .build()
        .map_err(io_map)?;

    container.start().map_err(io_map)?;

    let pid = container
        .pid()
        .ok_or_else(|| io::Error::other("primary container has no init pid after start"))?
        .as_raw();

    Ok(PrimaryContainer {
        init_pid: pid,
        state_root,
        bundle_path,
    })
}

/// Write `config.json` for a minimal long-lived primary container at `bundle`.
fn write_oci_config(bundle: &Path) -> io::Result<()> {
    let pause = find_pause_binary()?;
    let args = pause_args(&pause);
    // Root is the VM rootfs (`/`); namespaces isolate processes/mounts.
    let root = RootBuilder::default()
        .path("/")
        .readonly(false)
        .build()
        .map_err(io_map)?;

    let user = UserBuilder::default()
        .uid(0u32)
        .gid(0u32)
        .build()
        .map_err(io_map)?;

    let process = ProcessBuilder::default()
        .user(user)
        .args(args)
        .env([
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
            "TERM=xterm".into(),
        ])
        .cwd("/")
        .build()
        .map_err(io_map)?;

    let ns = |t: LinuxNamespaceType| {
        LinuxNamespaceBuilder::default()
            .typ(t)
            .build()
            .map_err(io_map)
    };

    let linux = LinuxBuilder::default()
        .namespaces(vec![
            ns(LinuxNamespaceType::Pid)?,
            ns(LinuxNamespaceType::Ipc)?,
            ns(LinuxNamespaceType::Uts)?,
            ns(LinuxNamespaceType::Mount)?,
        ])
        .build()
        .map_err(io_map)?;

    let spec = SpecBuilder::default()
        .version("1.0.2")
        .root(root)
        .process(process)
        .linux(linux)
        .hostname("bux")
        .build()
        .map_err(io_map)?;

    let path = bundle.join("config.json");
    let json = serde_json::to_string_pretty(&spec)
        .map_err(|e| io::Error::other(format!("serialize oci config: {e}")))?;
    let mut f = fs::File::create(&path)?;
    f.write_all(json.as_bytes())?;
    Ok(())
}

/// Locate a sleep/pause binary suitable as container init.
fn find_pause_binary() -> io::Result<String> {
    for candidate in [
        "/usr/bin/sleep",
        "/bin/sleep",
        "/usr/bin/pause",
        "/bin/pause",
    ] {
        if Path::new(candidate).is_file() {
            // sleep infinity / large duration keeps container alive.
            if candidate.ends_with("sleep") {
                return Ok(candidate.to_owned());
            }
            return Ok(candidate.to_owned());
        }
    }
    // Last resort: busybox sleep if present.
    if Path::new("/bin/busybox").is_file() {
        return Ok("/bin/busybox".into());
    }
    Err(io::Error::other(
        "no pause/sleep binary found for primary container init",
    ))
}

/// Map a displayable error into `io::Error::other`.
fn io_map(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

/// Adjust OCI process args for sleep-based pause (needs argument).
pub fn pause_args(program: &str) -> Vec<String> {
    if program.ends_with("sleep") {
        vec![program.to_owned(), "infinity".into()]
    } else if program.ends_with("busybox") {
        vec![program.to_owned(), "sleep".into(), "infinity".into()]
    } else {
        vec![program.to_owned()]
    }
}
