//! Shim-side Landlock: enter the domain whose ruleset the parent built.
//!
//! Env: `BUX_LANDLOCK_FD` = decimal ruleset FD (`bux_jail::ENV_LANDLOCK_FD`
//! contract), open across `exec`.

use std::os::unix::process::CommandExt;
use std::process::Command;

use crate::error::{Error, Result};

/// Environment variable name (must match `bux_jail::ENV_LANDLOCK_FD`).
pub const ENV_LANDLOCK_FD: &str = "BUX_LANDLOCK_FD";

/// Enter the Landlock domain the parent prepared, then re-execute this binary
/// inside it. Call first thing in `main`.
///
/// `landlock_restrict_self` covers only the calling thread and the threads it
/// starts later, and the Go runtime linked in for gvproxy starts a thread from
/// an ELF constructor, before `main`. `exec` ends that thread and keeps the
/// domain, so the new image runs entirely inside it.
///
/// Returns `Ok` only when the parent passed no ruleset: Landlock is off, or
/// this is the re-executed image.
///
/// # Errors
///
/// Returns [`Error::Landlock`] if the ruleset cannot be applied or the
/// re-execution fails. The shim must not continue: it would run unconfined.
pub fn enter_landlock_domain() -> Result<()> {
    let Some(value) = std::env::var_os(ENV_LANDLOCK_FD) else {
        return Ok(());
    };
    let fd = value.to_str().and_then(|s| s.parse().ok()).ok_or_else(|| {
        Error::Landlock(format!("invalid {ENV_LANDLOCK_FD}: {}", value.display()))
    })?;

    // SAFETY: the parent passed `fd` as a ruleset for this process to apply,
    // and nothing else in this process uses it.
    #[allow(unsafe_code, reason = "applies the ruleset; closes the fd")]
    let errno = unsafe { bux_landlock::restrict_self(fd) };
    if errno != 0 {
        let cause = std::io::Error::from_raw_os_error(errno);
        return Err(Error::Landlock(format!("cannot apply ruleset: {cause}")));
    }

    let mut args = std::env::args_os();
    let cause = Command::new("/proc/self/exe")
        .arg0(args.next().unwrap_or_default())
        .args(args)
        .env_remove(ENV_LANDLOCK_FD)
        .exec();
    Err(Error::Landlock(format!(
        "cannot re-execute inside the domain: {cause}"
    )))
}
