//! `bux run` — create and run a command in a new micro-VM.
//!
//! Follows the Docker CLI convention: `bux run [OPTIONS] IMAGE [COMMAND] [ARG...]`

use std::path::Path;

use anyhow::{Context, Result};
use bux::{LogLevel, Vm};
#[cfg(unix)]
use sha2::{Digest, Sha256};

struct ResolvedRootfs {
    path: String,
    oci_cfg: Option<bux_oci::ImageConfig>,
    disk_cache_key: Option<String>,
}

/// Arguments for `bux run`.
///
/// Usage: `bux run [OPTIONS] IMAGE [COMMAND] [ARG...]`
#[derive(clap::Args)]
#[command(trailing_var_arg = true)]
pub struct RunArgs {
    /// OCI image reference (e.g., ubuntu:latest). Conflicts with --root/--root-disk.
    #[arg(conflicts_with_all = ["root", "root_disk"], required_unless_present_any = ["root", "root_disk"])]
    image: Option<String>,

    /// Explicit root filesystem directory path.
    #[arg(long, conflicts_with = "root_disk")]
    root: Option<String>,

    /// Root filesystem disk image path (ext4 raw).
    #[arg(long, conflicts_with = "root")]
    root_disk: Option<String>,

    /// Auto-create ext4 disk image from OCI rootfs.
    #[arg(long)]
    disk: bool,

    /// Assign a name to the VM.
    #[arg(long)]
    name: Option<String>,

    /// Run in background and print VM ID.
    #[arg(short = 'd', long)]
    detach: bool,

    /// Automatically remove the VM when it stops.
    #[arg(long)]
    rm: bool,

    /// Number of virtual CPUs.
    #[arg(long, default_value_t = 1)]
    cpus: u8,

    /// Memory in MiB.
    #[arg(long, short = 'm', default_value_t = 512)]
    memory: u32,

    /// Working directory inside the VM.
    #[arg(short = 'w', long)]
    workdir: Option<String>,

    /// Publish a TCP port (host:guest, guest, 0:guest, :guest; optional /tcp).
    ///
    /// Host bind is always 0.0.0.0. UDP is not supported in v1.
    #[arg(short = 'p', long = "publish")]
    publish: Vec<String>,

    /// Restrict egress to hostnames/CIDRs (repeatable). Empty = unrestricted.
    #[arg(long = "allow-net")]
    allow_net: Vec<String>,

    /// Network mode: `enabled` (gvproxy virtio-net, default) or `none` (TSI / offline).
    #[arg(long, default_value = "enabled", value_parser = ["enabled", "none"])]
    network: String,

    /// Host MITM secret (`name=value@host1,host2` or `name=value` using --allow-net hosts).
    ///
    /// Real values never enter the guest; use placeholders like `<BUX_SECRET:name>` in traffic.
    #[arg(long = "secret")]
    secrets: Vec<String>,

    /// Bind mount a volume (format: `hostPath:guestPath[:ro]`).
    #[arg(short = 'v', long = "volume")]
    volume: Vec<String>,

    /// Set environment variables.
    #[arg(short = 'e', long = "env")]
    env: Vec<String>,

    /// Read environment variables from a file.
    #[arg(long)]
    env_file: Vec<String>,

    /// User inside the VM (format: `uid[:gid]`).
    #[arg(short = 'u', long = "user")]
    user: Option<String>,

    /// Keep STDIN open even if not attached.
    #[arg(short = 'i', long)]
    interactive: bool,

    /// Allocate a pseudo-TTY.
    #[arg(short = 't', long)]
    tty: bool,

    /// Override the default ENTRYPOINT of the image.
    #[arg(long)]
    entrypoint: Option<String>,

    /// Set ulimits (format: type=soft:hard).
    #[arg(long)]
    ulimit: Vec<String>,

    /// Enable nested virtualization (macOS only).
    #[arg(long)]
    nested_virt: bool,

    /// Enable virtio-snd audio device.
    #[arg(long)]
    snd: bool,

    /// Redirect console output to a file.
    #[arg(long)]
    console_output: Option<String>,

    /// libkrun log level.
    #[arg(long, default_value = "info")]
    log_level: LogLevel,

    /// Command and arguments to run inside the VM.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

/// Arguments for `bux create` — start a VM without an initial command.
#[derive(clap::Args)]
pub struct CreateArgs {
    /// OCI image reference.
    #[arg(required = true)]
    image: String,

    /// Assign a name to the VM.
    #[arg(long)]
    name: Option<String>,

    /// Automatically remove the VM when it stops.
    #[arg(long)]
    rm: bool,

    /// Number of virtual CPUs.
    #[arg(long, default_value_t = 1)]
    cpus: u8,

    /// Memory in MiB.
    #[arg(long, short = 'm', default_value_t = 512)]
    memory: u32,

    /// Publish a TCP port.
    #[arg(short = 'p', long = "publish")]
    publish: Vec<String>,

    /// Restrict egress (repeatable). Empty = unrestricted.
    #[arg(long = "allow-net")]
    allow_net: Vec<String>,

    /// Network mode: `enabled` or `none`.
    #[arg(long, default_value = "enabled", value_parser = ["enabled", "none"])]
    network: String,

    /// Host MITM secret (`name=value@host` or `name=value`).
    #[arg(long = "secret")]
    secrets: Vec<String>,

    /// Bind mount (`hostPath:guestPath[:ro]`).
    #[arg(short = 'v', long = "volume")]
    volume: Vec<String>,

    /// libkrun log level.
    #[arg(long, default_value = "info")]
    log_level: LogLevel,
}

impl CreateArgs {
    /// Create + start VM, print ID (no initial command).
    pub async fn run(self) -> Result<()> {
        // Reuse run path as detached empty-command run.
        let args = RunArgs {
            image: Some(self.image),
            root: None,
            root_disk: None,
            disk: true,
            name: self.name,
            detach: true,
            rm: self.rm,
            cpus: self.cpus,
            memory: self.memory,
            workdir: None,
            publish: self.publish,
            allow_net: self.allow_net,
            network: self.network,
            secrets: self.secrets,
            volume: self.volume,
            env: vec![],
            env_file: vec![],
            user: None,
            interactive: false,
            tty: false,
            entrypoint: None,
            ulimit: vec![],
            nested_virt: false,
            snd: false,
            console_output: None,
            log_level: self.log_level,
            command: vec![],
        };
        args.run().await
    }
}

impl RunArgs {
    /// Create/start VM according to CLI flags.
    #[allow(
        clippy::cognitive_complexity,
        clippy::too_many_lines,
        reason = "CLI orchestration; splitting obscures flag wiring"
    )]
    pub async fn run(self) -> Result<()> {
        if self.root_disk.is_some() {
            anyhow::bail!(
                "managed bux run no longer supports direct --root-disk boot; use --root/--disk or an OCI image so the runtime can prepare a managed guest rootfs"
            )
        }

        let resolved_root = self.resolve_rootfs().await?;
        let rootfs = resolved_root.path;
        let oci_cfg = resolved_root.oci_cfg;
        let disk_cache_key = resolved_root.disk_cache_key;

        let image = self.image.clone();
        let name = self.name;
        let detach = self.detach;
        let interactive = self.interactive;
        let tty = self.tty;
        let auto_remove = self.rm;
        let root_disk = self.root_disk.clone();
        let use_disk = self.disk;
        let user = self.user;

        let mut b = Vm::builder()
            .vcpus(self.cpus)
            .ram_mib(self.memory)
            .log_level(self.log_level);

        // Root filesystem: explicit disk > OCI image (auto QCOW2 overlay) > --root directory.
        if let Some(ref disk) = root_disk {
            b = b.root_disk(disk);
        } else if image.is_some() || use_disk {
            // OCI images always get a writable QCOW2 overlay so pip/apt work.
            let base_path = create_disk_from_rootfs(&rootfs, disk_cache_key.as_deref())?;
            b = b.base_disk(base_path);
        } else {
            b = b.root(&rootfs);
        }

        // Working directory: CLI flag > OCI config > none.
        let workdir = self
            .workdir
            .or_else(|| oci_cfg.as_ref()?.working_dir.clone())
            .filter(|w| !w.is_empty());

        // Command: --entrypoint override > CLI args > OCI ENTRYPOINT+CMD.
        let cmd = if let Some(ep) = self.entrypoint {
            let mut parts = vec![ep];
            parts.extend(self.command);
            parts
        } else if self.command.is_empty() {
            oci_cfg
                .as_ref()
                .map(bux_oci::ImageConfig::command)
                .unwrap_or_default()
        } else {
            self.command
        };

        // Environment: OCI defaults + --env-file + CLI -e overrides.
        let mut env_file_vars = Vec::new();
        for path in &self.env_file {
            env_file_vars.extend(crate::vm::read_env_file(path)?);
        }
        let merged_env: Vec<String> = oci_cfg
            .as_ref()
            .and_then(|c| c.env.clone())
            .unwrap_or_default()
            .into_iter()
            .chain(env_file_vars)
            .chain(self.env)
            .collect();

        // Ports: -p host:guest | guest | 0:guest | :guest [/tcp]
        for spec in &self.publish {
            // Validate early with the same parser Runtime uses.
            bux::parse_publish_spec(spec).with_context(|| format!("invalid -p {spec:?}"))?;
            b = b.port(spec.clone());
        }

        if !self.allow_net.is_empty() {
            b = b.allow_net(self.allow_net.clone());
        }

        let virtio_net = self.network != "none";
        b = b.virtio_net(virtio_net);

        if !self.secrets.is_empty() {
            if !virtio_net {
                anyhow::bail!("--secret requires --network=enabled (gvproxy MITM)");
            }
            let secrets = parse_secrets(&self.secrets, &self.allow_net)?;
            b = b.secrets(secrets);
        }

        // Volumes: -v hostPath:guestPath[:ro] — policy checked via VolumeManager.
        if !self.volume.is_empty() {
            let data = bux::default_data_dir();
            let db = std::sync::Arc::new(
                bux::StateDb::open(data.join("bux.db"))
                    .context("open state db for volume validation")?,
            );
            let vol_mgr = bux::VolumeManager::open(&data, db).context("open volume manager")?;
            let mut mounts = Vec::with_capacity(self.volume.len());
            for spec in &self.volume {
                mounts.push(
                    bux::parse_bind_spec(spec).with_context(|| format!("invalid -v {spec:?}"))?,
                );
            }
            let resolved_vols = vol_mgr
                .resolve_mounts(&mounts)
                .context("volume path validation failed")?;
            for r in resolved_vols {
                b = b.virtiofs_share(r.to_virtiofs());
            }
        }

        // Ulimits.
        for ul in self.ulimit {
            b = b.rlimit(ul);
        }

        if self.nested_virt {
            b = b.nested_virt(true);
        }
        if self.snd {
            b = b.snd_device(true);
        }
        if let Some(path) = self.console_output {
            b = b.console_output(path);
        }

        let has_exec_options =
            workdir.is_some() || user.is_some() || !merged_env.is_empty() || interactive || tty;
        let exec_req = if cmd.is_empty() {
            None
        } else {
            let args = cmd[1..].to_vec();
            let req = bux::ExecStart::new(&cmd[0]).args(args);
            Some(crate::vm::apply_exec_options(
                req,
                merged_env,
                workdir.as_deref(),
                user.as_deref(),
                interactive,
                tty,
            ))
        };

        if exec_req.is_none() && has_exec_options {
            anyhow::bail!(
                "env/workdir/user/interactive options require an initial command or image entrypoint under the managed runtime"
            )
        }

        if detach {
            if interactive || tty {
                anyhow::bail!("detached run does not support -i/-t")
            }
            if exec_req.is_some() {
                anyhow::bail!(
                    "detached run with an initial command is not supported by the managed runtime; start the VM detached, then run the command with bux exec"
                )
            }
            spawn_vm(b, image, name, true, auto_remove).await
        } else {
            run_foreground_vm(b, image, name, auto_remove, exec_req, interactive).await
        }
    }

    /// Resolves rootfs path and optional OCI config.
    async fn resolve_rootfs(&self) -> Result<ResolvedRootfs> {
        match (&self.image, &self.root, &self.root_disk) {
            (Some(img), None, None) => {
                let oci = bux_oci::Oci::open()?;
                let r = oci.ensure(img, |msg| eprintln!("{msg}")).await?;
                Ok(ResolvedRootfs {
                    path: r.rootfs.to_string_lossy().into_owned(),
                    oci_cfg: r.config,
                    disk_cache_key: Some(r.digest.replace(':', "-")),
                })
            }
            (None, Some(root), None) => Ok(ResolvedRootfs {
                path: root.clone(),
                oci_cfg: None,
                disk_cache_key: self
                    .disk
                    .then(|| rootfs_cache_key(Path::new(root)))
                    .transpose()?,
            }),
            (None, None, Some(_)) => Ok(ResolvedRootfs {
                path: String::new(),
                oci_cfg: None,
                disk_cache_key: None,
            }),
            _ => unreachable!("clap validation"),
        }
    }
}

#[cfg(unix)]
async fn run_foreground_vm(
    builder: bux::VmBuilder,
    image: Option<String>,
    name: Option<String>,
    auto_remove: bool,
    exec_req: Option<bux::ExecStart>,
    interactive: bool,
) -> Result<()> {
    let rt = crate::vm::open_runtime()?;
    let mut handle = rt.spawn(&builder, image, name, auto_remove)?;
    handle
        .wait_ready(std::time::Duration::from_secs(30))
        .await?;
    let id = handle.state().id.clone();

    let run = async move {
        if let Some(req) = exec_req {
            let exec_handle = handle.exec(req).await?;
            let output = crate::vm::stream_exec_output(exec_handle, interactive).await?;
            let code = output.code;
            handle.stop().await?;
            Ok::<i32, anyhow::Error>(code)
        } else {
            handle.wait().await?;
            Ok::<i32, anyhow::Error>(0)
        }
    };

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;

    let exit_code = tokio::select! {
        result = run => result?,
        _ = sigterm.recv() => {
            stop_vm(&id).await?;
            128 + libc::SIGTERM
        }
        _ = sigint.recv() => {
            stop_vm(&id).await?;
            128 + libc::SIGINT
        }
    };

    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

#[cfg(unix)]
async fn stop_vm(id: &str) -> Result<()> {
    let rt = crate::vm::open_runtime()?;
    let mut handle = rt.get(id)?;
    match handle.stop().await {
        Err(_) if handle.is_alive() => {
            let _ = handle.kill();
            Ok(())
        }
        Ok(()) | Err(_) => Ok(()),
    }
}

/// Parse `--secret` specs into [`bux::Secret`] values.
///
/// Formats:
/// - `name=value@host1,host2`
/// - `name=value` (hosts from `--allow-net`, or `*` if empty)
pub fn parse_secrets(specs: &[String], allow_net: &[String]) -> Result<Vec<bux::Secret>> {
    let mut out = Vec::with_capacity(specs.len());
    for spec in specs {
        out.push(parse_one_secret(spec, allow_net)?);
    }
    Ok(out)
}

fn parse_one_secret(spec: &str, allow_net: &[String]) -> Result<bux::Secret> {
    let (left, hosts_part) = match spec.rsplit_once('@') {
        Some((l, h)) if l.contains('=') => (l, Some(h)),
        _ => (spec, None),
    };
    let (name, value) = left.split_once('=').with_context(|| {
        format!("invalid --secret {spec:?}; expected name=value or name=value@host1,host2")
    })?;
    if name.is_empty() || value.is_empty() {
        anyhow::bail!("invalid --secret {spec:?}: name and value must be non-empty");
    }
    let hosts: Vec<String> = hosts_part.map_or_else(
        || {
            if allow_net.is_empty() {
                vec!["*".into()]
            } else {
                allow_net.to_vec()
            }
        },
        |h| {
            h.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        },
    );
    if hosts.is_empty() {
        anyhow::bail!("--secret {name}: no hosts (use @host or --allow-net)");
    }
    Ok(bux::Secret::new(name, hosts, value))
}

/// Creates an ext4 disk image from an OCI rootfs directory.
#[cfg(unix)]
fn create_disk_from_rootfs(rootfs: &str, cache_key: Option<&str>) -> Result<String> {
    let dm = bux::DiskManager::open(bux::default_data_dir())?;
    let digest = match cache_key {
        Some(digest) => digest.to_owned(),
        None => rootfs_cache_key(Path::new(rootfs))?,
    };
    let base = dm.create_managed_base(Path::new(rootfs), &digest)?;
    Ok(base.to_string_lossy().into_owned())
}

#[cfg(not(unix))]
fn create_disk_from_rootfs(_rootfs: &str, _cache_key: Option<&str>) -> Result<String> {
    anyhow::bail!("Disk image creation requires Linux or macOS")
}

#[cfg(unix)]
fn rootfs_cache_key(rootfs: &Path) -> Result<String> {
    use std::fmt::Write;

    let root = std::fs::canonicalize(rootfs).unwrap_or_else(|_| rootfs.to_path_buf());
    let mut hasher = Sha256::new();
    hash_rootfs_entry(&root, &root, &mut hasher)?;
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(hex)
}

#[cfg(not(unix))]
fn rootfs_cache_key(_rootfs: &Path) -> Result<String> {
    anyhow::bail!("Disk image creation requires Linux or macOS")
}

#[cfg(unix)]
fn hash_rootfs_entry(root: &Path, path: &Path, hasher: &mut Sha256) -> Result<()> {
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    let meta = std::fs::symlink_metadata(path)?;
    let rel = path.strip_prefix(root).unwrap_or(path);
    hasher.update(rel.as_os_str().as_bytes());
    hasher.update(meta.mode().to_le_bytes());

    if meta.is_file() {
        hasher.update(b"f");
        let mut file = std::fs::File::open(path)?;
        let mut buf = [0_u8; 8192];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
    } else if meta.is_dir() {
        hasher.update(b"d");
        let mut entries = std::fs::read_dir(path)?.collect::<std::result::Result<Vec<_>, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            hash_rootfs_entry(root, &entry.path(), hasher)?;
        }
    } else if meta.is_symlink() {
        hasher.update(b"l");
        let target = std::fs::read_link(path)?;
        hasher.update(target.as_os_str().as_bytes());
    } else {
        hasher.update(b"o");
    }

    Ok(())
}

#[cfg(unix)]
async fn spawn_vm(
    builder: bux::VmBuilder,
    image: Option<String>,
    name: Option<String>,
    detach: bool,
    auto_remove: bool,
) -> Result<()> {
    let rt = crate::vm::open_runtime()?;
    let mut handle = if detach {
        rt.spawn_detached(&builder, image, name, auto_remove)?
    } else {
        rt.spawn(&builder, image, name, auto_remove)?
    };

    let id = handle.state().id.clone();
    if detach {
        println!("{}", handle.state().name.as_deref().unwrap_or(&id));
        return Ok(());
    }

    eprintln!("{id}");

    // Race: wait for VM exit vs. SIGTERM/SIGINT for graceful shutdown.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;

    tokio::select! {
        result = handle.wait() => result?,
        _ = sigterm.recv() => {
            eprintln!("\n[bux] received SIGTERM, stopping VM {id}...");
            handle.stop().await?;
        }
        _ = sigint.recv() => {
            eprintln!("\n[bux] received SIGINT, stopping VM {id}...");
            handle.stop().await?;
        }
    }

    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unused_async)]
async fn spawn_vm(
    _builder: bux::VmBuilder,
    _image: Option<String>,
    _name: Option<String>,
    _detach: bool,
    _auto_remove: bool,
) -> Result<()> {
    anyhow::bail!("VM execution requires Linux or macOS")
}

#[cfg(test)]
mod secret_tests {
    use super::*;

    #[test]
    fn parse_with_hosts() {
        let s = parse_one_secret("openai=sk-x@api.openai.com,api.example.com", &[]).unwrap();
        assert_eq!(s.name, "openai");
        assert_eq!(s.value, "sk-x");
        assert_eq!(s.hosts, vec!["api.openai.com", "api.example.com"]);
    }

    #[test]
    fn parse_uses_allow_net() {
        let s = parse_one_secret("t=val", &["h1".into()]).unwrap();
        assert_eq!(s.hosts, vec!["h1"]);
    }

    #[test]
    fn parse_star_default() {
        let s = parse_one_secret("t=val", &[]).unwrap();
        assert_eq!(s.hosts, vec!["*"]);
    }
}
