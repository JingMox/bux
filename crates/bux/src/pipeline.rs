//! Managed boot pipeline: [`VmOptions`] → running [`VmHandle`].
//!
//! Stages (product path):
//! ```text
//! Validate → ResolveImage → EnsureBaseDisk → (overlay in spawn)
//!   → Network → ShimConfig → JailSpawn → WaitReady
//! ```
//!
//! Workload identity (`env` / `workdir` / `user`) is stored on the VM config
//! for Phase A exec defaults — not applied as libkrun boot env.

use std::path::PathBuf;

use tracing::info;

use crate::Result;
use crate::options::{ImageRef, VmOptions};
use crate::process::merge_image_config;
use crate::runtime::{Runtime, VmHandle};
use crate::vm::Vm;

/// Create and start a managed VM from product options.
///
/// # Errors
///
/// Propagates image pull, disk, network, or spawn failures.
pub(crate) async fn create(
    rt: &Runtime,
    mut opts: VmOptions,
    on_progress: impl Fn(&str) + Send + Sync,
) -> Result<VmHandle> {
    on_progress("validating options");
    validate(&opts)?;

    on_progress("resolving image");
    let (builder_base, image_label, oci_cfg) =
        resolve_image(rt, &opts.image, &on_progress).await?;

    // OCI ImageConfig fills gaps / bases env; product opts already on `opts` win.
    if let Some(ref img) = oci_cfg {
        merge_image_config(&mut opts.env, &mut opts.workdir, &mut opts.user, img);
    }

    let mut builder = builder_base
        .vcpus(opts.vcpus)
        .ram_mib(opts.ram_mib)
        .virtio_net(opts.virtio_net)
        .allow_net(opts.allow_net.clone())
        .secrets(opts.secrets.clone())
        .workload_env(opts.env.clone())
        .security(opts.security)
        .auto_stop_secs(opts.auto_stop_secs)
        .auto_delete_secs(opts.auto_delete_secs);

    if let Some(ref wd) = opts.workdir {
        builder = builder.workload_workdir(wd.clone());
    }
    if let Some(ref user) = opts.user {
        builder = builder.user(user.clone());
    }

    for p in &opts.ports {
        builder = builder.port(p.clone());
    }

    on_progress("resolving volumes");
    let resolved_vols = rt.volumes().resolve_mounts(&opts.volumes)?;
    for r in &resolved_vols {
        builder = builder.virtiofs_share(r.to_virtiofs());
    }

    on_progress("spawning shim");
    let handle = if opts.detach {
        rt.spawn_detached(
            &builder,
            image_label,
            opts.name.clone(),
            opts.auto_remove,
        )?
    } else {
        rt.spawn(
            &builder,
            image_label,
            opts.name.clone(),
            opts.auto_remove,
        )?
    };

    if !resolved_vols.is_empty() {
        rt.volumes()
            .link_vm(handle.state().id.as_str(), &resolved_vols)?;
    }

    if !opts.ready_timeout.is_zero() {
        on_progress("waiting for guest agent");
        drop(handle.wait_ready(opts.ready_timeout).await);
    }

    on_progress("running");
    Ok(handle)
}

/// Validate product options before expensive work.
fn validate(opts: &VmOptions) -> Result<()> {
    if opts.vcpus == 0 {
        return Err(crate::Error::InvalidConfig("vcpus must be >= 1".into()));
    }
    if opts.ram_mib == 0 {
        return Err(crate::Error::InvalidConfig("ram_mib must be >= 1".into()));
    }
    if !opts.secrets.is_empty() && !opts.virtio_net {
        return Err(crate::Error::SecretsNeedVirtioNet);
    }
    for p in &opts.ports {
        crate::ports::parse_publish_spec(p)?;
    }
    Ok(())
}

/// Resolve [`ImageRef`] into builder + label + optional OCI process config.
async fn resolve_image(
    rt: &Runtime,
    image: &ImageRef,
    on_progress: &(impl Fn(&str) + Send + Sync),
) -> Result<(
    crate::vm::VmBuilder,
    Option<String>,
    Option<bux_oci::ImageConfig>,
)> {
    match image {
        ImageRef::Oci(reference) => {
            on_progress("pulling/ensuring OCI image");
            let pull = rt.oci().ensure(reference, on_progress).await?;
            let oci_cfg = pull.config.clone();

            on_progress("building ext4 base disk");
            let image_label = reference.clone();
            let base_path = {
                let disk = rt.disk().clone();
                let rootfs = pull.rootfs.clone();
                let digest = pull.digest.replace(':', "-");
                let pull_ref = pull.reference.clone();
                tokio::task::spawn_blocking(move || -> Result<PathBuf> {
                    info!(image = %pull_ref, "creating ext4 base image from rootfs");
                    disk.create_managed_base(&rootfs, &digest)
                })
                .await
                .map_err(std::io::Error::other)??
            };

            Ok((
                Vm::builder().base_disk(base_path.to_string_lossy()),
                Some(image_label),
                oci_cfg,
            ))
        }
        ImageRef::Rootfs(path) => {
            if !path.is_dir() {
                return Err(crate::Error::InvalidConfig(format!(
                    "rootfs is not a directory: {}",
                    path.display()
                )));
            }
            Ok((
                Vm::builder().root(path.to_string_lossy()),
                Some(path.display().to_string()),
                None,
            ))
        }
        ImageRef::BaseDisk(path) => {
            if !path.is_file() {
                return Err(crate::Error::InvalidConfig(format!(
                    "base disk not found: {}",
                    path.display()
                )));
            }
            Ok((
                Vm::builder().base_disk(path.to_string_lossy()),
                Some(path.display().to_string()),
                None,
            ))
        }
    }
}

/// OCI image + builder configure (prefer [`create`]).
pub(crate) async fn create_from_oci(
    rt: &Runtime,
    image: &str,
    configure: impl FnOnce(crate::vm::VmBuilder) -> crate::vm::VmBuilder + Send,
    name: Option<String>,
    auto_remove: bool,
    ready_timeout: std::time::Duration,
    on_progress: impl Fn(&str) + Send + Sync,
) -> Result<VmHandle> {
    let mut opts = VmOptions::from_image(image)
        .auto_remove(auto_remove)
        .ready_timeout(ready_timeout);
    if let Some(n) = name {
        opts = opts.name(n);
    }

    on_progress("validating options");
    validate(&opts)?;

    on_progress("resolving image");
    let (builder, image_label, _oci_cfg) =
        resolve_image(rt, &opts.image, &on_progress).await?;
    let builder = configure(
        builder
            .vcpus(opts.vcpus)
            .ram_mib(opts.ram_mib)
            .virtio_net(opts.virtio_net),
    );

    on_progress("spawning shim");
    let handle = rt.spawn(&builder, image_label, opts.name, opts.auto_remove)?;
    if !opts.ready_timeout.is_zero() {
        on_progress("waiting for guest agent");
        drop(handle.wait_ready(opts.ready_timeout).await);
    }
    Ok(handle)
}
