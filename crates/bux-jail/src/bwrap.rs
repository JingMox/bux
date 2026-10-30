//! Linux sandbox using bubblewrap (bwrap).
//!
//! Wraps the shim binary with namespace isolation: new PID/IPC/UTS/mount
//! namespaces, read-only `/` bind, and selective writable mounts for
//! rootfs, sockets, and virtiofs paths.

use std::path::Path;
use std::process::Command;

use bux_bwrap::{BwrapCommand, Namespace};

use super::{JailConfig, Sandbox, SandboxCapabilities, SandboxKind};

/// Bubblewrap (bwrap) sandbox for Linux.
///
/// Provides namespace isolation (PID/IPC/UTS/mount), a read-only root
/// bind, and selective writable mounts for VM resources.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct BwrapSandbox;

impl Sandbox for BwrapSandbox {
    fn wrap(&self, shim: &Path, config_path: &Path, jail: &JailConfig) -> Option<Command> {
        let mut builder = BwrapCommand::from_path(jail.bwrap_path.as_ref()?)
            .ok()?
            .unshare([Namespace::Pid, Namespace::Ipc, Namespace::Uts]);
        if jail.die_with_parent {
            builder = builder.die_with_parent();
        }
        // `ro_bind("/", "/")` already covers resolver files (`/etc/resolv.conf`, `/etc/hosts`).
        builder = builder.ro_bind("/", "/").tmpfs("/tmp").tmpfs("/dev/shm");

        if Path::new("/dev/kvm").exists() {
            builder = builder.dev_bind("/dev/kvm", "/dev/kvm");
        }

        // The tmpfs above may hide them. Before the writable binds: a read-only
        // directory here must not cover a writable path beneath it.
        for path in &jail.readonly_paths {
            builder = builder.ro_bind(path, path);
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
#[allow(clippy::unwrap_used, clippy::panic, reason = "unit tests")]
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
    fn readonly_paths_are_bound_before_writable_ones() {
        let mut cfg = jail(false);
        cfg.readonly_paths = vec![
            PathBuf::from("/tmp/home/disks"),
            PathBuf::from("/tmp/home/disks/base.raw"),
        ];
        cfg.root_disk = Some(PathBuf::from("/tmp/home/disks/vm.qcow2"));
        let Some(cmd) =
            BwrapSandbox.wrap(Path::new("/usr/bin/true"), Path::new("/tmp/cfg.json"), &cfg)
        else {
            return;
        };
        let args: Vec<_> = cmd.get_args().collect();
        let position = |seq: &[&str]| {
            args.windows(seq.len())
                .position(|w| w.iter().zip(seq).all(|(arg, want)| *arg == *want))
                .unwrap_or_else(|| panic!("no {seq:?} in {args:?}"))
        };

        let tmpfs = position(&["--tmpfs", "/tmp"]);
        let dir = position(&["--ro-bind", "/tmp/home/disks", "/tmp/home/disks"]);
        let base = position(&[
            "--ro-bind",
            "/tmp/home/disks/base.raw",
            "/tmp/home/disks/base.raw",
        ]);
        let disk = position(&[
            "--bind",
            "/tmp/home/disks/vm.qcow2",
            "/tmp/home/disks/vm.qcow2",
        ]);
        assert!(tmpfs < dir && dir < disk && base < disk, "{args:?}");
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
