//! Linux sandbox using bubblewrap (bwrap).
//!
//! Wraps the shim binary with namespace isolation: new PID/IPC/UTS/mount
//! namespaces, read-only `/` bind, and selective writable mounts for
//! rootfs, sockets, and virtiofs paths.

use std::path::Path;
use std::process::{Command, Stdio};

use bux_bwrap::{BwrapCommand, Namespace};

use super::{JailConfig, Sandbox, SandboxCapabilities, SandboxKind};

/// The namespaces and base mounts of every jail.
fn base_command(bwrap: &Path) -> Option<BwrapCommand> {
    // `ro_bind("/", "/")` already covers resolver files (`/etc/resolv.conf`, `/etc/hosts`).
    let mut builder = BwrapCommand::from_path(bwrap)
        .ok()?
        .unshare([Namespace::Pid, Namespace::Ipc, Namespace::Uts])
        .ro_bind("/", "/")
        .tmpfs("/tmp")
        .tmpfs("/dev/shm");

    if Path::new("/dev/kvm").exists() {
        builder = builder.dev_bind("/dev/kvm", "/dev/kvm");
    }
    Some(builder)
}

/// Check that `bwrap` can start a jail on this host, by running it with the
/// jail's namespaces and mounts around a command that does nothing.
///
/// # Errors
///
/// Returns what `bwrap` printed, or why it could not run.
pub fn probe_bwrap(bwrap: &Path) -> Result<(), String> {
    let builder =
        base_command(bwrap).ok_or_else(|| format!("{} is not a file", bwrap.display()))?;
    let output = builder
        .program(bwrap)
        .arg("--version")
        .into_command()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .output()
        .map_err(|e| e.to_string())?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = stderr.trim();
    Err(if stderr.is_empty() {
        output.status.to_string()
    } else {
        stderr.to_owned()
    })
}

/// Bubblewrap (bwrap) sandbox for Linux.
///
/// Provides namespace isolation (PID/IPC/UTS/mount), a read-only root
/// bind, and selective writable mounts for VM resources.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct BwrapSandbox;

impl Sandbox for BwrapSandbox {
    fn wrap(&self, shim: &Path, config_path: &Path, jail: &JailConfig) -> Option<Command> {
        let mut builder = base_command(jail.bwrap_path.as_ref()?)?;
        if jail.die_with_parent {
            builder = builder.die_with_parent();
        }

        if let Some(rootfs) = &jail.rootfs {
            builder = builder.bind(rootfs, rootfs);
        }
        if let Some(disk) = &jail.root_disk {
            builder = builder.bind(disk, disk);
        }

        builder = builder.bind(&jail.socks_dir, &jail.socks_dir);
        for path in &jail.virtiofs_paths {
            builder = builder.bind(path, path);
        }
        builder = builder.ro_bind(config_path, config_path);

        Some(builder.program(shim).arg(config_path).into_command())
    }

    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities {
            namespaces: true,
            seccomp: false,
            mandatory_access_control: false,
        }
    }

    fn kind(&self) -> SandboxKind {
        SandboxKind::Bwrap
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "unit tests")]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn jail(die_with_parent: bool) -> JailConfig {
        JailConfig {
            rootfs: None,
            root_disk: None,
            readonly_paths: vec![],
            socks_dir: PathBuf::from("/tmp/bux-socks"),
            virtiofs_paths: vec![],
            sandbox: None,
            log_file: None,
            landlock: false,
            allow_degraded_security: false,
            die_with_parent,
            network_host: false,
            bwrap_path: Some(PathBuf::from("/bin/true")),
        }
    }

    fn args_contain_die_with_parent(cmd: &Command) -> bool {
        cmd.get_args()
            .any(|a| a == std::ffi::OsStr::new("--die-with-parent"))
    }

    /// A fake `bwrap` in `dir`: appends its arguments to `args`, then runs `body`.
    fn fake_bwrap(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let bwrap = dir.join("bwrap");
        let args = dir.join("args");
        std::fs::write(
            &bwrap,
            format!("#!/bin/sh\necho \"$@\" >> {}\n{body}\n", args.display()),
        )
        .unwrap();
        std::fs::set_permissions(&bwrap, std::fs::Permissions::from_mode(0o755)).unwrap();
        bwrap
    }

    #[test]
    fn probe_runs_the_jail_namespaces_and_mounts() {
        let dir = tempfile::tempdir().unwrap();
        let bwrap = fake_bwrap(dir.path(), "exit 0");

        probe_bwrap(&bwrap).unwrap();

        let args = std::fs::read_to_string(dir.path().join("args")).unwrap();
        for flag in [
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--ro-bind / /",
            "--tmpfs /tmp",
            "--tmpfs /dev/shm",
        ] {
            assert!(args.contains(flag), "{flag} missing: {args}");
        }
        assert!(
            args.trim_end()
                .ends_with(&format!("-- {} --version", bwrap.display())),
            "{args}"
        );
    }

    #[test]
    fn probe_returns_what_bwrap_printed() {
        let dir = tempfile::tempdir().unwrap();
        let bwrap = fake_bwrap(
            dir.path(),
            "echo 'bwrap: setting up uid map: Permission denied' >&2; exit 1",
        );
        assert_eq!(
            probe_bwrap(&bwrap).unwrap_err(),
            "bwrap: setting up uid map: Permission denied"
        );

        let silent = fake_bwrap(dir.path(), "exit 3");
        assert!(
            probe_bwrap(&silent).unwrap_err().contains('3'),
            "a silent failure reports its exit status"
        );
        assert!(
            probe_bwrap(Path::new("/nonexistent/bwrap"))
                .unwrap_err()
                .contains("not a file")
        );
    }

    #[test]
    fn foreground_includes_die_with_parent() {
        let Some(cmd) = BwrapSandbox.wrap(
            Path::new("/usr/bin/true"),
            Path::new("/tmp/cfg.json"),
            &jail(true),
        ) else {
            return;
        };
        assert!(
            args_contain_die_with_parent(&cmd),
            "foreground jail must pass --die-with-parent"
        );
    }

    #[test]
    fn detached_omits_die_with_parent() {
        let Some(cmd) = BwrapSandbox.wrap(
            Path::new("/usr/bin/true"),
            Path::new("/tmp/cfg.json"),
            &jail(false),
        ) else {
            return;
        };
        assert!(
            !args_contain_die_with_parent(&cmd),
            "detached jail must not pass --die-with-parent"
        );
    }
}
