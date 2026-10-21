//! Safe wrappers around the raw `krun_*` FFI calls.
//!
//! Public functions in this module correspond 1:1 to the `krun_*` C entry
//! points that bux calls, declared by [`libkrun.h`]. Only calls with the
//! same signature in upstream libkrun 1.19 and the smolvm fork belong here.
//! All `unsafe` inside `bux-krun` is confined here and in [`crate::sys`].
//!
//! Callers manage libkrun context IDs directly: start with
//! [`create_ctx`] (returns `u32`), pass the ID to the various
//! configuration helpers (`set_vm_config`, `add_disk2`, …), and either
//! [`start_enter`] (takes over the process) or [`free_ctx`] to release
//! it. Higher layers (`bux`) wrap the raw context ID in RAII types.
//!
//! [`libkrun`]: https://github.com/libkrun/libkrun
//! [`libkrun.h`]: https://github.com/libkrun/libkrun/blob/main/include/libkrun.h

#![allow(
    unsafe_code,
    clippy::undocumented_unsafe_blocks,
    clippy::multiple_unsafe_ops_per_block,
    clippy::missing_safety_doc,
    reason = "FFI wrapper module — every unsafe block is a direct 1:1 krun_* call; safety invariants are documented on the wrapping function"
)]

use std::ffi::{CString, c_char};

use crate::error::{Error, Result};
use crate::sys;

/// Disk image format for [`add_disk2`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u32)]
pub enum DiskFormat {
    /// Raw disk image.
    Raw = sys::KRUN_DISK_FORMAT_RAW,
    /// QCOW2 copy-on-write image.
    Qcow2 = sys::KRUN_DISK_FORMAT_QCOW2,
}

/// Translate a signed libkrun status code into a [`Result`].
const fn check(op: &'static str, ret: i32) -> Result<()> {
    if ret < 0 {
        Err(Error::Krun { op, code: ret })
    } else {
        Ok(())
    }
}

/// Owned NULL-terminated C string array for FFI calls expecting
/// `*const *const c_char`.
struct CStringArray {
    /// Retained to keep the `CString` buffers alive while `ptrs` holds
    /// raw pointers into them.
    _owned: Vec<CString>,
    /// `NULL`-terminated array of pointers handed to libkrun.
    ptrs: Vec<*const c_char>,
}

impl CStringArray {
    /// Build from a slice of owned Rust strings.
    fn new(strings: &[String]) -> Result<Self> {
        let owned: Vec<CString> = strings
            .iter()
            .map(|s| CString::new(s.as_str()))
            .collect::<std::result::Result<_, _>>()?;
        let mut ptrs: Vec<*const c_char> = owned.iter().map(|c| c.as_ptr()).collect();
        ptrs.push(std::ptr::null());
        Ok(Self {
            _owned: owned,
            ptrs,
        })
    }

    /// Pointer to the first element; the array is NULL-terminated.
    fn as_ptr(&self) -> *const *const c_char {
        self.ptrs.as_ptr()
    }
}

// ----------------------------------------------------------------------
// Context lifecycle
// ----------------------------------------------------------------------

/// Create a new VM configuration context.
///
/// Returns the context ID on success.
///
/// # Errors
///
/// Returns [`Error::Krun`] if libkrun fails to allocate a new context.
pub fn create_ctx() -> Result<u32> {
    let ret = unsafe { sys::krun_create_ctx() };
    if ret < 0 {
        return Err(Error::Krun {
            op: "create_ctx",
            code: ret,
        });
    }
    #[allow(
        clippy::cast_sign_loss,
        reason = "krun returns non-negative i32 on success"
    )]
    Ok(ret as u32)
}

/// Free an existing configuration context.
///
/// # Errors
///
/// Returns [`Error::Krun`] if libkrun reports a failure freeing the
/// context.
pub fn free_ctx(ctx: u32) -> Result<()> {
    check("free_ctx", unsafe { sys::krun_free_ctx(ctx) })
}

/// Start the microVM and take over the current process.
///
/// On success this function **never returns** — libkrun calls `exit()`
/// when the VM shuts down. Only returns on pre-start configuration
/// errors.
///
/// # Errors
///
/// Returns [`Error::Krun`] with the start-up diagnostic code if the VM
/// cannot enter.
pub fn start_enter(ctx: u32) -> Result<()> {
    check("start_enter", unsafe { sys::krun_start_enter(ctx) })
}

// ----------------------------------------------------------------------
// VM configuration
// ----------------------------------------------------------------------

/// Set basic VM parameters: vCPU count and RAM size.
///
/// # Errors
///
/// Returns [`Error::Krun`] if libkrun rejects the configuration.
pub fn set_vm_config(ctx: u32, vcpus: u8, ram_mib: u32) -> Result<()> {
    check("set_vm_config", unsafe {
        sys::krun_set_vm_config(ctx, vcpus, ram_mib)
    })
}

/// Set the executable, arguments, and optionally environment variables.
///
/// If `env` is `None`, libkrun auto-inherits the host environment.
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] if any string has embedded NULs, or
/// [`Error::Krun`] if libkrun rejects the configuration.
pub fn set_exec(ctx: u32, path: &str, args: &[String], env: Option<&[String]>) -> Result<()> {
    let c_path = CString::new(path)?;
    let argv = CStringArray::new(args)?;
    let c_envp = env.map(CStringArray::new).transpose()?;
    let envp_ptr = c_envp
        .as_ref()
        .map_or(std::ptr::null(), CStringArray::as_ptr);
    check("set_exec", unsafe {
        sys::krun_set_exec(ctx, c_path.as_ptr(), argv.as_ptr(), envp_ptr)
    })
}

/// Set environment variables without specifying an executable.
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn set_env(ctx: u32, env: &[String]) -> Result<()> {
    let array = CStringArray::new(env)?;
    check("set_env", unsafe { sys::krun_set_env(ctx, array.as_ptr()) })
}

// ----------------------------------------------------------------------
// virtio-fs
// ----------------------------------------------------------------------

/// Add a virtio-fs shared directory with DAX SHM size and a read-only flag.
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn add_virtiofs3(
    ctx: u32,
    tag: &str,
    host_path: &str,
    shm_size: u64,
    read_only: bool,
) -> Result<()> {
    let c_tag = CString::new(tag)?;
    let c_path = CString::new(host_path)?;
    check("add_virtiofs3", unsafe {
        sys::krun_add_virtiofs3(ctx, c_tag.as_ptr(), c_path.as_ptr(), shm_size, read_only)
    })
}

// ----------------------------------------------------------------------
// Disks
// ----------------------------------------------------------------------

/// Add a disk image with an explicit format (Raw, QCOW2, or VMDK).
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn add_disk2(
    ctx: u32,
    block_id: &str,
    disk_path: &str,
    format: DiskFormat,
    read_only: bool,
) -> Result<()> {
    let c_id = CString::new(block_id)?;
    let c_path = CString::new(disk_path)?;
    check("add_disk2", unsafe {
        sys::krun_add_disk2(
            ctx,
            c_id.as_ptr(),
            c_path.as_ptr(),
            format as u32,
            read_only,
        )
    })
}

/// Configure a block device as the root filesystem (remount after boot).
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn set_root_disk_remount(
    ctx: u32,
    device: &str,
    fstype: Option<&str>,
    options: Option<&str>,
) -> Result<()> {
    let c_dev = CString::new(device)?;
    let c_fs = fstype.map(CString::new).transpose()?;
    let c_opts = options.map(CString::new).transpose()?;
    check("set_root_disk_remount", unsafe {
        sys::krun_set_root_disk_remount(
            ctx,
            c_dev.as_ptr(),
            c_fs.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            c_opts.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
        )
    })
}

// ----------------------------------------------------------------------
// Networking
// ----------------------------------------------------------------------

/// Add a virtio-net device with a Unix stream backend (passt / socket\_vmnet).
///
/// `path` and `fd` are mutually exclusive. If no network device is added,
/// libkrun uses the built-in TSI backend.
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn add_net_unixstream(
    ctx: u32,
    path: Option<&str>,
    fd: i32,
    mac: &[u8; 6],
    features: u32,
    flags: u32,
) -> Result<()> {
    let c_path = path.map(CString::new).transpose()?;
    check("add_net_unixstream", unsafe {
        sys::krun_add_net_unixstream(
            ctx,
            c_path.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            fd,
            mac.as_ptr().cast_mut(),
            features,
            flags,
        )
    })
}

/// Add a virtio-net device with a Unix datagram backend (gvproxy / vmnet-helper).
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn add_net_unixgram(
    ctx: u32,
    path: Option<&str>,
    fd: i32,
    mac: &[u8; 6],
    features: u32,
    flags: u32,
) -> Result<()> {
    let c_path = path.map(CString::new).transpose()?;
    check("add_net_unixgram", unsafe {
        sys::krun_add_net_unixgram(
            ctx,
            c_path.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            fd,
            mac.as_ptr().cast_mut(),
            features,
            flags,
        )
    })
}

// ----------------------------------------------------------------------
// vsock
// ----------------------------------------------------------------------

/// Map a vsock port to a host Unix socket with direction control.
///
/// # Errors
///
/// Returns [`Error::InteriorNul`] / [`Error::Krun`] as above.
pub fn add_vsock_port2(ctx: u32, port: u32, path: &str, listen: bool) -> Result<()> {
    let c = CString::new(path)?;
    check("add_vsock_port2", unsafe {
        sys::krun_add_vsock_port2(ctx, port, c.as_ptr(), listen)
    })
}

/// Add a vsock device with specified TSI features.
///
/// Requires [`disable_implicit_vsock`] first. Use `KRUN_TSI_HIJACK_INET`
/// (1) and/or `KRUN_TSI_HIJACK_UNIX` (2) as bitmask values, or 0 for
/// none.
///
/// # Errors
///
/// Returns [`Error::Krun`] as above.
pub fn add_vsock(ctx: u32, tsi_features: u32) -> Result<()> {
    check("add_vsock", unsafe {
        sys::krun_add_vsock(ctx, tsi_features)
    })
}

/// Disable the implicit vsock device created by default.
///
/// # Errors
///
/// Returns [`Error::Krun`] as above.
pub fn disable_implicit_vsock(ctx: u32) -> Result<()> {
    check("disable_implicit_vsock", unsafe {
        sys::krun_disable_implicit_vsock(ctx)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_virtiofs3_invokes_krun_add_virtiofs3() {
        let _: unsafe extern "C" fn(u32, *const c_char, *const c_char, u64, bool) -> i32 =
            sys::krun_add_virtiofs3;
        let err = add_virtiofs3(u32::MAX, "vol0", "/tmp", 0, true);
        assert!(
            matches!(&err, Err(Error::Krun { op, code }) if *op == "add_virtiofs3" && *code < 0),
            "{err:?}"
        );
    }
}
