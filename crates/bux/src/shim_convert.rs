//! Convert product [`VmConfig`] → engine [`ShimConfig`].
//!
//! Single mapping so Runtime spawn and low-level builders share wire shape.

use bux_shim::{ShimConfig, ShimDiskFormat, ShimNetwork, ShimVirtioFs, ShimVsockPort};

use crate::disk::DiskFormat;
use crate::state::VmConfig;

/// Map a persisted / product [`VmConfig`] into engine [`ShimConfig`].
///
/// When `network` is `Some`, TSI `ports` are cleared (port publish is
/// handled by gvproxy). When `None`, `config.ports` are TSI maps.
#[must_use]
pub(crate) fn to_shim_config(
    vm_id: &str,
    config: &VmConfig,
    network: Option<ShimNetwork>,
) -> ShimConfig {
    let use_virtio = network.is_some();
    ShimConfig {
        vm_id: vm_id.to_owned(),
        vcpus: config.vcpus,
        ram_mib: config.ram_mib,
        rootfs: config.rootfs.clone(),
        root_disk: config.root_disk.clone(),
        disk_format: match config.disk_format {
            DiskFormat::Qcow2 => ShimDiskFormat::Qcow2,
            DiskFormat::Raw => ShimDiskFormat::Raw,
        },
        virtiofs: config
            .virtiofs
            .iter()
            .map(|v| ShimVirtioFs {
                tag: v.tag.clone(),
                path: v.path.clone(),
            })
            .collect(),
        // TSI maps only when not using virtio-net.
        ports: if use_virtio {
            Vec::new()
        } else {
            config.ports.clone()
        },
        vsock_ports: config
            .vsock_ports
            .iter()
            .map(|v| ShimVsockPort {
                port: v.port,
                path: v.path.clone(),
                listen: v.listen,
            })
            .collect(),
        network,
        log_level: config.log_level.map(|l| l as u32),
        exec_path: config.exec_path.clone(),
        exec_args: config.exec_args.clone(),
        env: config.env.clone(),
        workdir: config.workdir.clone(),
        uid: config.uid,
        gid: config.gid,
        rlimits: config.rlimits.clone(),
        nested_virt: config.nested_virt,
        snd_device: config.snd_device,
        console_output: config.console_output.clone(),
    }
}
