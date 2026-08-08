//! [`VmBuilder`] — fluent builder for configuring a micro-VM.

use crate::disk::DiskFormat;
use crate::error::Result;
#[cfg(unix)]
use crate::state::VmConfig;

use crate::log_level::LogLevel;

use super::Vm;

/// Builder for configuring a micro-VM.
///
/// Defaults: 1 vCPU, 512 MiB RAM, host environment inherited.
///
/// # Example
///
/// ```no_run
/// use bux::Vm;
///
/// let vm = Vm::builder()
///     .vcpus(2)
///     .ram_mib(1024)
///     .root("/path/to/rootfs")
///     .exec("/bin/bash", &["--login"])
///     .build()
///     .expect("invalid VM config");
/// ```
#[derive(Debug)]
#[must_use = "a VmBuilder does nothing until .build() is called"]
pub struct VmBuilder {
    /// Number of virtual CPUs.
    pub(super) vcpus: u8,
    /// RAM size in MiB.
    pub(super) ram_mib: u32,
    /// Root filesystem directory path.
    pub(super) root: Option<String>,
    /// Root filesystem disk image path (mutually exclusive with `root`).
    pub(super) root_disk: Option<String>,
    /// Disk image format.
    pub(super) disk_format: DiskFormat,
    /// Shared base image for QCOW2 overlay creation (consumed by Runtime).
    pub(super) base_disk: Option<String>,
    /// Executable path inside the VM.
    pub(super) exec_path: Option<String>,
    /// Arguments passed to the executable (does not include argv[0]).
    pub(super) exec_args: Vec<String>,
    /// Environment variables (`KEY=VALUE`). `None` = inherit from host.
    pub(super) env: Option<Vec<String>>,
    /// Working directory inside the VM.
    pub(super) workdir: Option<String>,
    /// TCP port mappings (`"host_port:guest_port"` or ephemeral forms).
    pub(super) ports: Vec<String>,
    /// Egress allow-list (empty = unrestricted).
    pub(super) allow_net: Vec<String>,
    /// virtio-fs shared directories.
    pub(super) virtiofs: Vec<crate::state::VirtioFs>,
    /// Global log level for libkrun.
    pub(super) log_level: Option<LogLevel>,
    /// UID to set before starting the VM.
    pub(super) uid: Option<u32>,
    /// GID to set before starting the VM.
    pub(super) gid: Option<u32>,
    /// Resource limits (`RESOURCE=RLIM_CUR:RLIM_MAX`).
    pub(super) rlimits: Vec<String>,
    /// Enable nested virtualization (macOS only).
    pub(super) nested_virt: Option<bool>,
    /// Enable/disable virtio-snd.
    pub(super) snd_device: Option<bool>,
    /// Redirect console output to a file.
    pub(super) console_output: Option<String>,
    /// vsock port mappings `(guest_port, host_socket_path, listen)`.
    pub(super) vsock_ports: Vec<(u32, String, bool)>,
    /// Use gvproxy virtio-net (default `true` after network redesign).
    pub(super) virtio_net: bool,
    /// Host-only secrets for MITM (not serialised into `SQLite` values).
    pub(crate) secrets: Vec<crate::secrets::Secret>,
    /// Workload user string for Phase A (`uid[:gid]` or `name[:group]`).
    pub(crate) workload_user: Option<String>,
    /// Workload env already staged as product fields (merged into `workload_env`).
    ///
    /// When set, takes precedence over boot-style [`Self::env`] migration.
    pub(crate) workload_env: Vec<String>,
    /// Workload workdir for Phase A (takes precedence over [`Self::workdir`]).
    pub(crate) workload_workdir: Option<String>,
    /// Isolation policy (Landlock / jailer).
    pub(crate) security: crate::security::SecurityOptions,
    /// Auto-stop idle seconds (`None` = off).
    pub(crate) auto_stop_secs: Option<u64>,
    /// Auto-delete stopped idle seconds (`None` = off).
    pub(crate) auto_delete_secs: Option<u64>,
}

impl VmBuilder {
    /// Creates a new builder with sensible defaults.
    pub(super) fn new() -> Self {
        Self {
            vcpus: 1,
            ram_mib: 512,
            root: None,
            root_disk: None,
            disk_format: DiskFormat::default(),
            base_disk: None,
            exec_path: None,
            exec_args: Vec::new(),
            env: None,
            workdir: None,
            ports: Vec::new(),
            allow_net: Vec::new(),
            virtiofs: Vec::new(),
            log_level: None,
            uid: None,
            gid: None,
            rlimits: Vec::new(),
            nested_virt: None,
            snd_device: None,
            console_output: None,
            vsock_ports: Vec::new(),
            virtio_net: true,
            secrets: Vec::new(),
            workload_user: None,
            workload_env: Vec::new(),
            workload_workdir: None,
            security: crate::security::SecurityOptions::default(),
            auto_stop_secs: None,
            auto_delete_secs: None,
        }
    }

    /// Sets the number of virtual CPUs (default: 1).
    pub const fn vcpus(mut self, n: u8) -> Self {
        self.vcpus = n;
        self
    }

    /// Sets the RAM size in MiB (default: 512).
    pub const fn ram_mib(mut self, mib: u32) -> Self {
        self.ram_mib = mib;
        self
    }

    /// Sets the root filesystem directory path (virtiofs-based).
    pub fn root(mut self, path: impl Into<String>) -> Self {
        self.root = Some(path.into());
        self.root_disk = None;
        self
    }

    /// Sets the root filesystem disk image path (raw format).
    ///
    /// The image is attached as `/dev/vda` and remounted as the root
    /// filesystem during boot. Mutually exclusive with [`root()`](Self::root).
    pub fn root_disk(mut self, path: impl Into<String>) -> Self {
        self.root_disk = Some(path.into());
        self.disk_format = DiskFormat::Raw;
        self.root = None;
        self
    }

    /// Sets a shared base image for automatic QCOW2 overlay creation.
    ///
    /// [`crate::Runtime::spawn()`] will create a per-VM QCOW2 overlay backed by
    /// this image, set `root_disk` to the overlay path, and configure
    /// `disk_format` to [`DiskFormat::Qcow2`]. The base image is never modified.
    pub fn base_disk(mut self, path: impl Into<String>) -> Self {
        self.base_disk = Some(path.into());
        self.root = None;
        self.root_disk = None;
        self
    }

    /// Sets the executable and its arguments to run inside the VM.
    ///
    /// `args` should **not** include the program name (argv\[0\]).
    pub fn exec(mut self, path: impl Into<String>, args: &[&str]) -> Self {
        self.exec_path = Some(path.into());
        self.exec_args = args.iter().map(|s| (*s).to_owned()).collect();
        self
    }

    /// Sets explicit environment variables (`KEY=VALUE` format).
    ///
    /// If never called, the host environment is inherited automatically.
    pub fn env(mut self, vars: &[&str]) -> Self {
        self.env = Some(vars.iter().map(|s| (*s).to_owned()).collect());
        self
    }

    /// Sets the working directory inside the VM.
    pub fn workdir(mut self, path: impl Into<String>) -> Self {
        self.workdir = Some(path.into());
        self
    }

    /// Adds a TCP port mapping in `"host_port:guest_port"` format.
    /// Publish a TCP port.
    ///
    /// Formats: `host:guest`, `guest` / `0:guest` / `:guest` (ephemeral host),
    /// optional `/tcp`. UDP is rejected at Runtime start.
    pub fn port(mut self, mapping: impl Into<String>) -> Self {
        self.ports.push(mapping.into());
        self
    }

    /// Restrict egress to the given hosts/CIDRs (repeatable via multiple calls).
    ///
    /// Empty list (default) = **unrestricted** egress. Non-empty = allow-list
    /// enforced by gvproxy DNS/TCP filters.
    pub fn allow_net(mut self, hosts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.allow_net
            .extend(hosts.into_iter().map(Into::into));
        self
    }

    /// Adds a virtio-fs shared directory.
    ///
    /// - `tag` — identifier used to mount the filesystem in the guest.
    /// - `host_path` — absolute path to the directory on the host.
    pub fn virtiofs(mut self, tag: impl Into<String>, host_path: impl Into<String>) -> Self {
        self.virtiofs.push(crate::state::VirtioFs {
            tag: tag.into(),
            path: host_path.into(),
            guest_path: String::new(),
            read_only: false,
        });
        self
    }

    /// Adds a fully specified virtio-fs share (from volume resolution).
    pub fn virtiofs_share(mut self, share: crate::state::VirtioFs) -> Self {
        self.virtiofs.push(share);
        self
    }

    /// Sets the global libkrun log level (applies to all VMs in the process).
    pub const fn log_level(mut self, level: LogLevel) -> Self {
        self.log_level = Some(level);
        self
    }

    /// Sets the UID before starting the VM.
    pub const fn uid(mut self, uid: u32) -> Self {
        self.uid = Some(uid);
        self
    }

    /// Sets the GID before starting the VM.
    pub const fn gid(mut self, gid: u32) -> Self {
        self.gid = Some(gid);
        self
    }

    /// Adds a resource limit (`"RESOURCE=RLIM_CUR:RLIM_MAX"` format).
    pub fn rlimit(mut self, rlimit: impl Into<String>) -> Self {
        self.rlimits.push(rlimit.into());
        self
    }

    /// Enables or disables nested virtualization (macOS only).
    pub const fn nested_virt(mut self, enable: bool) -> Self {
        self.nested_virt = Some(enable);
        self
    }

    /// Enables or disables the virtio-snd audio device.
    pub const fn snd_device(mut self, enable: bool) -> Self {
        self.snd_device = Some(enable);
        self
    }

    /// Redirects console output to a file (ignores stdin).
    pub fn console_output(mut self, path: impl Into<String>) -> Self {
        self.console_output = Some(path.into());
        self
    }

    /// Maps a guest vsock port to a host Unix socket path.
    ///
    /// When `listen` is `true`, the guest listens on the vsock port and the
    /// host connects to the Unix socket (typical for guest agent pattern).
    pub fn vsock_port(mut self, port: u32, host_path: impl Into<String>, listen: bool) -> Self {
        self.vsock_ports.push((port, host_path.into(), listen));
        self
    }

    /// Enable/disable gvproxy virtio-net (default **enabled**).
    ///
    /// When `true` (default): Runtime starts gvproxy, shim attaches virtio-net,
    /// guest configures static eth0. When `false`: legacy TSI + no eth0 setup.
    pub const fn virtio_net(mut self, enable: bool) -> Self {
        self.virtio_net = enable;
        self
    }

    /// Attach secrets for gvproxy MITM substitution (host-only values).
    ///
    /// Requires `virtio_net`. Guest traffic uses placeholders like
    /// `<BUX_SECRET:name>`; real values never enter the guest.
    pub fn secrets(mut self, secrets: impl IntoIterator<Item = crate::secrets::Secret>) -> Self {
        self.secrets.extend(secrets);
        self
    }

    /// Add one secret.
    pub fn secret(mut self, secret: crate::secrets::Secret) -> Self {
        self.secrets.push(secret);
        self
    }

    /// Workload user for Phase A exec (`uid[:gid]` or `name[:group]`).
    ///
    /// Not applied as libkrun boot credentials on the managed path.
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.workload_user = Some(user.into());
        self
    }

    /// Workload env for Phase A exec (`KEY=VALUE`).
    pub fn workload_env(mut self, vars: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.workload_env = vars.into_iter().map(Into::into).collect();
        self
    }

    /// Workload working directory for Phase A exec.
    pub fn workload_workdir(mut self, path: impl Into<String>) -> Self {
        self.workload_workdir = Some(path.into());
        self
    }

    /// Isolation policy (Landlock fail-closed by default on Linux — K22).
    pub const fn security(mut self, opts: crate::security::SecurityOptions) -> Self {
        self.security = opts;
        self
    }

    /// Idle auto-stop policy in seconds (`None` = off).
    pub const fn auto_stop_secs(mut self, secs: Option<u64>) -> Self {
        self.auto_stop_secs = secs;
        self
    }

    /// Idle auto-delete policy for stopped VMs (`None` = off).
    pub const fn auto_delete_secs(mut self, secs: Option<u64>) -> Self {
        self.auto_delete_secs = secs;
        self
    }

    /// Extracts a serializable configuration snapshot.
    #[cfg(unix)]
    pub(crate) fn to_config(&self) -> VmConfig {
        use crate::state::VsockPort;
        VmConfig {
            vcpus: self.vcpus,
            ram_mib: self.ram_mib,
            rootfs: self.root.clone(),
            root_disk: self.root_disk.clone(),
            disk_format: self.disk_format,
            base_disk: self.base_disk.clone(),
            exec_path: self.exec_path.clone(),
            exec_args: self.exec_args.clone(),
            env: self.env.clone(),
            workdir: self.workdir.clone(),
            ports: self.ports.clone(),
            allow_net: self.allow_net.clone(),
            published_ports: vec![],
            virtiofs: self.virtiofs.clone(),
            vsock_ports: self
                .vsock_ports
                .iter()
                .map(|(port, path, listen)| VsockPort {
                    port: *port,
                    path: path.clone(),
                    listen: *listen,
                })
                .collect(),
            log_level: self.log_level,
            uid: self.uid,
            gid: self.gid,
            rlimits: self.rlimits.clone(),
            nested_virt: self.nested_virt,
            snd_device: self.snd_device,
            console_output: self.console_output.clone(),
            virtio_net: self.virtio_net,
            secrets_required: !self.secrets.is_empty(),
            workload_env: self.workload_env.clone(),
            workload_workdir: self.workload_workdir.clone(),
            workload_user: self.workload_user.clone(),
            security: self.security,
            security_status: crate::security::SecurityStatus::default(),
            auto_remove: false,
            auto_stop_secs: self.auto_stop_secs,
            auto_delete_secs: self.auto_delete_secs,
            last_activity_at: Some(std::time::SystemTime::now()),
            last_error: None,
        }
    }

    /// Reconstructs a [`VmBuilder`] from a serialized [`VmConfig`].
    ///
    /// Secrets are **not** restored (memory-only).
    #[cfg(unix)]
    pub fn from_config(c: &VmConfig) -> Self {
        Self {
            vcpus: c.vcpus,
            ram_mib: c.ram_mib,
            root: c.rootfs.clone(),
            root_disk: c.root_disk.clone(),
            disk_format: c.disk_format,
            base_disk: c.base_disk.clone(),
            exec_path: c.exec_path.clone(),
            exec_args: c.exec_args.clone(),
            env: c.env.clone(),
            workdir: c.workdir.clone(),
            ports: c.ports.clone(),
            allow_net: c.allow_net.clone(),
            virtiofs: c.virtiofs.clone(),
            vsock_ports: c
                .vsock_ports
                .iter()
                .map(|v| (v.port, v.path.clone(), v.listen))
                .collect(),
            log_level: c.log_level,
            uid: c.uid,
            gid: c.gid,
            rlimits: c.rlimits.clone(),
            nested_virt: c.nested_virt,
            snd_device: c.snd_device,
            console_output: c.console_output.clone(),
            virtio_net: c.virtio_net,
            secrets: Vec::new(),
            workload_user: c.workload_user.clone(),
            workload_env: c.workload_env.clone(),
            workload_workdir: c.workload_workdir.clone(),
            security: c.security,
            auto_stop_secs: c.auto_stop_secs,
            auto_delete_secs: c.auto_delete_secs,
        }
    }

    /// Builds and returns the configured [`Vm`].
    ///
    /// Creates a libkrun context via the shared [`bux_shim::prepare`] path
    /// (same engine boundary as the `bux-shim` binary).
    ///
    /// # Errors
    ///
    /// Returns an error if context creation or any configuration step fails.
    #[cfg(unix)]
    pub fn build(self) -> Result<Vm> {
        let product = self.to_config();
        // Low-level build has no Runtime NetworkManager; virtio_net requires
        // an external ShimNetwork (managed path only for now).
        let shim = crate::shim_convert::to_shim_config("", &product, None);
        let prepared = bux_shim::prepare(&shim)?;
        Ok(Vm::from_raw_ctx(prepared.into_ctx()?))
    }

    /// Non-Unix stub — libkrun is Unix-only.
    #[cfg(not(unix))]
    pub fn build(self) -> Result<Vm> {
        let _ = self;
        Err(crate::Error::InvalidConfig(
            "VmBuilder::build requires Unix".into(),
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn vm_config_roundtrip() {
        let builder = Vm::builder()
            .vcpus(4)
            .ram_mib(2048)
            .root("/rootfs")
            .exec("/bin/sh", &["-c", "echo hello"])
            .env(&["FOO=bar", "BAZ=1"])
            .workdir("/app")
            .port("8080:80")
            .virtiofs("share", "/host/share")
            .log_level(LogLevel::Debug)
            .uid(1000)
            .gid(1000)
            .rlimit("NOFILE=1024:4096")
            .nested_virt(true)
            .snd_device(false)
            .console_output("/tmp/console.log")
            .vsock_port(1024, "/tmp/agent.sock", true);

        let config = builder.to_config();
        let rebuilt = VmBuilder::from_config(&config);
        let config2 = rebuilt.to_config();

        assert_eq!(config.vcpus, config2.vcpus);
        assert_eq!(config.ram_mib, config2.ram_mib);
        assert_eq!(config.rootfs, config2.rootfs);
        assert_eq!(config.exec_path, config2.exec_path);
        assert_eq!(config.exec_args, config2.exec_args);
        assert_eq!(config.env, config2.env);
        assert_eq!(config.workdir, config2.workdir);
        assert_eq!(config.ports, config2.ports);
        assert_eq!(config.log_level, config2.log_level);
        assert_eq!(config.uid, config2.uid);
        assert_eq!(config.gid, config2.gid);
        assert_eq!(config.rlimits, config2.rlimits);
        assert_eq!(config.nested_virt, config2.nested_virt);
        assert_eq!(config.snd_device, config2.snd_device);
        assert_eq!(config.console_output, config2.console_output);
        assert_eq!(config.virtiofs.len(), config2.virtiofs.len());
        assert_eq!(config.vsock_ports.len(), config2.vsock_ports.len());
    }

    #[test]
    fn builder_root_and_root_disk_mutually_exclusive() {
        let disk_wins = Vm::builder().root("/rootfs").root_disk("/disk.img");
        assert!(disk_wins.root.is_none());
        assert!(disk_wins.root_disk.is_some());

        let root_wins = Vm::builder().root_disk("/disk.img").root("/rootfs");
        assert!(root_wins.root.is_some());
        assert!(root_wins.root_disk.is_none());
    }

    #[test]
    fn builder_base_disk_clears_root_and_root_disk() {
        let b = Vm::builder().root("/rootfs").base_disk("/base.img");
        assert!(b.root.is_none());
        assert!(b.root_disk.is_none());
        assert_eq!(b.base_disk.as_deref(), Some("/base.img"));
    }
}
