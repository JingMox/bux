//! Shim process identity, liveness, and the parent keepalive.
//!
//! A pid alone cannot name a process across a host restart: once the shim
//! exits, the OS may hand its pid to an unrelated process. [`ShimProcess`]
//! pairs the pid with the process start time and treats a pid whose start
//! time differs as a process that is gone.

use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::time::Duration;

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{Pid, pipe};

/// A `bux-shim` process, identified by pid and start time.
///
/// Plain identity: safe to persist and to rebuild with [`Self::open`]
/// after a host restart. Every operation first checks that the pid still
/// belongs to the same process, so a reused pid is never signalled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShimProcess {
    /// OS process id.
    pid: u32,
    /// Opaque start time read when the process was identified.
    start_time: u64,
}

impl ShimProcess {
    /// Rebuild a handle from a stored pid and start time.
    #[must_use]
    pub const fn open(pid: u32, start_time: u64) -> Self {
        Self { pid, start_time }
    }

    /// Identify the process that currently holds `pid`.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::NotFound`] if no process has this pid.
    pub fn from_pid(pid: u32) -> io::Result<Self> {
        let start_time = start_time(pid).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no process with pid {pid}"),
            )
        })?;
        Ok(Self { pid, start_time })
    }

    /// OS process id.
    #[must_use]
    pub const fn pid(self) -> u32 {
        self.pid
    }

    /// Start time as an opaque token: clock ticks since boot on Linux,
    /// microseconds since the Unix epoch on macOS. Only compare it.
    #[must_use]
    pub const fn start_time(self) -> u64 {
        self.start_time
    }

    /// `true` while the pid still belongs to this process.
    #[must_use]
    pub fn is_alive(self) -> bool {
        start_time(self.pid) == Some(self.start_time)
    }

    /// Ask the process to exit (`SIGTERM`). A process that is gone is not an error.
    ///
    /// # Errors
    ///
    /// Returns the OS error if the signal cannot be delivered.
    pub fn terminate(self) -> io::Result<()> {
        self.send_if_alive(Signal::SIGTERM)
    }

    /// Kill the process (`SIGKILL`). A process that is gone is not an error.
    ///
    /// # Errors
    ///
    /// Returns the OS error if the signal cannot be delivered.
    pub fn kill(self) -> io::Result<()> {
        self.send_if_alive(Signal::SIGKILL)
    }

    /// Send the POSIX signal number `sig`.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] for an unknown signal, and
    /// `ESRCH` if the process is gone.
    pub fn signal(self, sig: i32) -> io::Result<()> {
        let sig = Signal::try_from(sig).map_err(io::Error::from)?;
        if !self.is_alive() {
            return Err(Errno::ESRCH.into());
        }
        signal::kill(self.nix_pid(), sig).map_err(io::Error::from)
    }

    /// Block until the process exits.
    ///
    /// Reaps the process when it is a child of this process; otherwise polls.
    #[allow(
        clippy::disallowed_methods,
        reason = "blocking wait runs on a blocking thread, not in async code"
    )]
    pub fn wait(self) {
        if !self.is_alive() {
            return;
        }
        if let Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..)) = waitpid(self.nix_pid(), None)
        {
            return;
        }
        while self.is_alive() {
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Deliver `sig` unless the pid no longer belongs to this process.
    fn send_if_alive(self, sig: Signal) -> io::Result<()> {
        if !self.is_alive() {
            return Ok(());
        }
        match signal::kill(self.nix_pid(), sig) {
            Ok(()) | Err(Errno::ESRCH) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// pid as a `nix` [`Pid`].
    #[allow(
        clippy::cast_possible_wrap,
        reason = "pids are positive and below i32::MAX on Unix"
    )]
    const fn nix_pid(self) -> Pid {
        Pid::from_raw(self.pid as i32)
    }
}

/// Parent end of the watchdog pipe.
///
/// While it is held, the shim's read end stays open. Dropping it (or the
/// parent exiting) closes the pipe; the shim sees `POLLHUP` and shuts down.
/// This works on every Unix platform, unlike `PR_SET_PDEATHSIG`.
#[derive(Debug)]
pub struct Keepalive(#[allow(dead_code, reason = "dropped to close the pipe")] OwnedFd);

/// Create the watchdog pipe: `(shim read end, parent keepalive)`.
///
/// The read end has no `O_CLOEXEC` so it survives `exec` into the shim.
/// The write end has `O_CLOEXEC` so it does not leak into the child.
pub(crate) fn watchdog_pipe() -> io::Result<(OwnedFd, Keepalive)> {
    let (read_fd, write_fd) = pipe()?;
    fcntl(write_fd.as_fd(), FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
    Ok((read_fd, Keepalive(write_fd)))
}

/// Start time of `pid`, or `None` if no such process exists.
#[cfg(target_os = "linux")]
fn start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_stat_start_time(&stat)
}

/// Field 22 (`starttime`) of `/proc/<pid>/stat`.
///
/// `comm` (field 2) may contain spaces and parentheses, so fields are
/// counted from the last `)`, which closes it.
#[cfg(any(target_os = "linux", test))]
fn parse_stat_start_time(stat: &str) -> Option<u64> {
    let (_, rest) = stat.rsplit_once(')')?;
    // `rest` starts at field 3 (state); field 22 is 19 fields later.
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// Start time of `pid`, or `None` if no such process exists.
#[cfg(target_os = "macos")]
#[allow(unsafe_code, reason = "proc_pidinfo fills a caller-owned proc_bsdinfo")]
fn start_time(pid: u32) -> Option<u64> {
    let pid = libc::c_int::try_from(pid).ok()?;
    let size = libc::c_int::try_from(size_of::<libc::proc_bsdinfo>()).ok()?;
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    // SAFETY: `info` is a writable buffer of exactly `size` bytes.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if written != size {
        return None;
    }
    // SAFETY: proc_pidinfo filled the whole struct (written == size).
    let info = unsafe { info.assume_init() };
    Some(
        info.pbi_start_tvsec
            .saturating_mul(1_000_000)
            .saturating_add(info.pbi_start_tvusec),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "unit tests")]
mod tests {
    use std::process::{Child, Command};

    use super::*;

    fn sleep_child() -> (Child, ShimProcess) {
        let child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let process = ShimProcess::from_pid(child.id()).unwrap();
        (child, process)
    }

    #[test]
    fn parses_start_time_after_last_paren() {
        let stat = "42 (a) b (c)) S 1 42 42 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 98765 1 2";
        assert_eq!(parse_stat_start_time(stat), Some(98_765));
        assert_eq!(parse_stat_start_time("42 (x) S 1"), None);
        assert_eq!(parse_stat_start_time("no paren"), None);
    }

    #[test]
    fn own_process_is_alive() {
        let me = ShimProcess::from_pid(std::process::id()).unwrap();
        assert!(me.is_alive());
        assert_eq!(me, ShimProcess::open(me.pid(), me.start_time()));
    }

    #[test]
    fn different_start_time_is_gone() {
        let (mut child, process) = sleep_child();
        let reused = ShimProcess::open(process.pid(), process.start_time() + 1);
        assert!(!reused.is_alive());
        reused.kill().unwrap();
        assert!(
            process.is_alive(),
            "kill on a mismatched start time must not signal the live process"
        );
        assert_eq!(
            reused.signal(libc::SIGTERM).unwrap_err().raw_os_error(),
            Some(libc::ESRCH)
        );
        drop(child.kill());
        drop(child.wait());
    }

    #[test]
    fn kill_then_wait_reaps_child() {
        let (_child, process) = sleep_child();
        assert!(process.is_alive());
        process.kill().unwrap();
        process.wait();
        assert!(!process.is_alive());
        process.kill().unwrap();
    }

    #[test]
    fn terminate_stops_child() {
        let (_child, process) = sleep_child();
        process.terminate().unwrap();
        process.wait();
        assert!(!process.is_alive());
    }

    #[test]
    fn unknown_signal_is_invalid_input() {
        let me = ShimProcess::from_pid(std::process::id()).unwrap();
        assert_eq!(
            me.signal(9999).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn dropping_keepalive_hangs_up_reader() {
        let (read_end, keepalive) = watchdog_pipe().unwrap();
        drop(keepalive);
        let mut buf = [0_u8; 1];
        let n = nix::unistd::read(&read_end, &mut buf).unwrap();
        assert_eq!(n, 0, "reader must see EOF once the keepalive is dropped");
    }
}
