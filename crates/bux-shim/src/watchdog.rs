//! Shim-side watchdog: exit when the parent Runtime dies.
//!
//! Env: `BUX_WATCHDOG_FD` = decimal read-end FD of a pipe whose write end
//! is held by the parent (`bux_jail::ENV_WATCHDOG_FD` contract).

#![allow(
    clippy::print_stderr,
    clippy::exit,
    clippy::disallowed_methods,
    reason = "shim process: stderr + process::exit on parent death"
)]

use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd};

/// Environment variable name (must match `bux_jail::ENV_WATCHDOG_FD`).
pub const ENV_WATCHDOG_FD: &str = "BUX_WATCHDOG_FD";

/// Block until parent death (`POLLHUP` on the watchdog pipe).
#[cfg(unix)]
pub fn wait_for_parent_death(fd: BorrowedFd<'_>) {
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

    let mut pfd = [PollFd::new(fd, PollFlags::empty())];
    loop {
        match poll(&mut pfd, PollTimeout::NONE) {
            Ok(n) if n > 0 => {
                if let Some(revents) = pfd[0].revents()
                    && revents.contains(PollFlags::POLLHUP)
                {
                    return;
                }
            }
            Err(nix::errno::Errno::EINTR) => {}
            Err(_) => return,
            _ => {}
        }
    }
}

/// Spawn a background thread that exits the process when the parent dies.
///
/// No-op when `BUX_WATCHDOG_FD` is unset (detach mode).
#[cfg(unix)]
pub fn start_watchdog_thread() {
    let Ok(fd_str) = std::env::var(ENV_WATCHDOG_FD) else {
        return;
    };
    let Ok(fd_num) = fd_str.parse::<i32>() else {
        eprintln!("[bux-shim] invalid {ENV_WATCHDOG_FD}: {fd_str}");
        return;
    };

    #[allow(
        unsafe_code,
        reason = "fd created by parent via pipe and preserved across exec"
    )]
    // SAFETY: fd_num is the read end created by the parent without CLOEXEC.
    let owned_fd = unsafe { OwnedFd::from_raw_fd(fd_num) };

    if let Err(e) = std::thread::Builder::new()
        .name("watchdog".into())
        .spawn(move || {
            #[allow(unsafe_code, reason = "borrow raw fd for poll lifetime")]
            // SAFETY: owned_fd keeps the fd open for this thread.
            let borrowed = unsafe { BorrowedFd::borrow_raw(fd_num) };
            wait_for_parent_death(borrowed);
            drop(owned_fd);
            eprintln!("[bux-shim] parent process died, shutting down");
            std::process::exit(0);
        })
    {
        eprintln!("[bux-shim] failed to spawn watchdog thread: {e}");
    }
}
