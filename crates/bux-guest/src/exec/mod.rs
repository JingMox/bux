//! Command execution with PTY support and timeout management.

mod pty;

use std::io;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use bux_proto::{ErrorCode, ErrorInfo, ExecIn, ExecOut, ExecStart, HelloAck};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::reaper::{Exit, Reaper};

/// Monotonic counter for generating unique execution IDs.
static EXEC_SEQ: AtomicU64 = AtomicU64::new(1);

/// Wrap a stdio fd as `tokio::fs::File` (blocking pool).
fn file_from_stdio(fd: impl Into<OwnedFd>) -> tokio::fs::File {
    tokio::fs::File::from_std(std::fs::File::from(fd.into()))
}

/// Handles an exec connection: spawns a child, multiplexes I/O until exit.
///
/// # Errors
///
/// Returns an error if spawn, session I/O, or exit reporting fails.
pub async fn handle(
    r: &mut (impl AsyncRead + Unpin + Send),
    w: &mut (impl AsyncWrite + Unpin + Send),
    req: ExecStart,
    reaper: Reaper,
) -> io::Result<()> {
    let exec_id = format!("exec-{}", EXEC_SEQ.fetch_add(1, Ordering::Relaxed));
    let spawn_t0 = Instant::now();

    if req.tty.is_some() {
        handle_pty(r, w, req, &exec_id, spawn_t0, &reaper).await
    } else {
        handle_pipe(r, w, req, &exec_id, spawn_t0, &reaper).await
    }
}

/// Pipe-mode execution: stdout and stderr are separate streams.
async fn handle_pipe(
    r: &mut (impl AsyncRead + Unpin + Send),
    w: &mut (impl AsyncWrite + Unpin + Send),
    req: ExecStart,
    exec_id: &str,
    spawn_t0: Instant,
    reaper: &Reaper,
) -> io::Result<()> {
    use std::os::unix::process::CommandExt as _;
    use std::process::{Command, Stdio};

    let credentials = match resolve_credentials(&req) {
        Ok(c) => c,
        Err(e) => {
            let err = ErrorInfo::new(ErrorCode::Internal, e.to_string());
            bux_proto::send(w, &HelloAck::Error(err)).await?;
            return w.flush().await;
        }
    };

    let mut cmd = Command::new(&req.cmd);
    cmd.args(&req.args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if req.stdin {
        cmd.stdin(Stdio::piped());
    }

    // Child setpgid(0, 0) in do_exec, before the credentials pre_exec.
    cmd.process_group(0);
    apply_exec_options!(&mut cmd, &req, credentials);

    let mut spawned = match reaper.spawn(&mut cmd) {
        Ok(s) => s,
        Err(e) => {
            let err = ErrorInfo::new(ErrorCode::Internal, e.to_string());
            bux_proto::send(w, &HelloAck::Error(err)).await?;
            return w.flush().await;
        }
    };

    #[allow(clippy::cast_possible_wrap)]
    let pid = spawned.child.id() as i32;
    // Parent race closer if the child has not yet run do_exec.
    unsafe {
        let _ = libc::setpgid(pid, pid);
    }
    bux_proto::send(
        w,
        &HelloAck::ExecStarted {
            exec_id: exec_id.to_owned(),
            pid,
        },
    )
    .await?;
    w.flush().await?;

    let timed_out = Arc::new(AtomicBool::new(false));
    let killer = spawn_timeout_killer(pid, req.timeout_ms, &timed_out);

    let mut child_stdin = spawned.child.stdin.take().map(file_from_stdio);
    // SAFETY: stdout/stderr were set to Stdio::piped() above.
    let Some(mut stdout) = spawned.child.stdout.take().map(file_from_stdio) else {
        unreachable!()
    };
    let Some(mut stderr) = spawned.child.stderr.take().map(file_from_stdio) else {
        unreachable!()
    };
    drop(spawned.child);
    let mut stdout_done = false;
    let mut stderr_done = false;
    let mut stdout_buf = [0u8; 4096];
    let mut stderr_buf = [0u8; 4096];

    loop {
        // Exit the I/O loop once both output streams are done.
        if stdout_done && stderr_done {
            break;
        }

        tokio::select! {
            host_msg = bux_proto::recv::<ExecIn>(r) => {
                match host_msg {
                    Ok(ExecIn::Stdin(data)) => {
                        if let Some(ref mut stdin) = child_stdin {
                            let _ = stdin.write_all(&data).await;
                        }
                    }
                    Ok(ExecIn::StdinClose) => {
                        child_stdin = None;
                    }
                    Ok(ExecIn::Signal(sig)) => {
                        kill_job(pid, sig);
                    }
                    Ok(_) => {}
                    Err(_) => {
                        // Host disconnected — kill the job and collect exit status.
                        kill_job(pid, libc::SIGKILL);
                        break;
                    }
                }
            }
            n = stdout.read(&mut stdout_buf), if !stdout_done => {
                match n {
                    Ok(0) | Err(_) => stdout_done = true,
                    Ok(len) => {
                        bux_proto::send(w, &ExecOut::Stdout(stdout_buf[..len].to_vec())).await?;
                    }
                }
            }
            n = stderr.read(&mut stderr_buf), if !stderr_done => {
                match n {
                    Ok(0) | Err(_) => stderr_done = true,
                    Ok(len) => {
                        bux_proto::send(w, &ExecOut::Stderr(stderr_buf[..len].to_vec())).await?;
                    }
                }
            }
        }
    }

    if let Some(h) = killer {
        h.abort();
    }
    drop(child_stdin);
    send_exit(w, spawned.exit.await, spawn_t0, &timed_out).await
}

/// PTY-mode execution: stdout and stderr are merged into a single PTY stream.
async fn handle_pty(
    r: &mut (impl AsyncRead + Unpin + Send),
    w: &mut (impl AsyncWrite + Unpin + Send),
    req: ExecStart,
    exec_id: &str,
    spawn_t0: Instant,
    reaper: &Reaper,
) -> io::Result<()> {
    let spawn_result = pty::spawn(&req, reaper);
    let mut pty_handle = match spawn_result {
        Ok(h) => h,
        Err(e) => {
            let err = ErrorInfo::new(ErrorCode::Internal, e.to_string());
            bux_proto::send(w, &HelloAck::Error(err)).await?;
            return w.flush().await;
        }
    };

    let pid = pty_handle.pid;
    bux_proto::send(
        w,
        &HelloAck::ExecStarted {
            exec_id: exec_id.to_owned(),
            pid,
        },
    )
    .await?;
    w.flush().await?;

    let timed_out = Arc::new(AtomicBool::new(false));
    let killer = spawn_timeout_killer(pid, req.timeout_ms, &timed_out);

    let mut pty_buf = [0u8; 4096];

    loop {
        tokio::select! {
            host_msg = bux_proto::recv::<ExecIn>(r) => {
                match host_msg {
                    Ok(ExecIn::Stdin(data)) => {
                        let _ = pty_handle.master_write.write_all(&data).await;
                    }
                    Ok(ExecIn::Signal(sig)) => {
                        kill_job(pid, sig);
                    }
                    Ok(ExecIn::ResizeTty(config)) => {
                        pty_handle.resize(&config);
                    }
                    Ok(_) => {}
                    Err(_) => {
                        kill_job(pid, libc::SIGKILL);
                        break;
                    }
                }
            }
            n = pty_handle.master_read.read(&mut pty_buf) => {
                match n {
                    Ok(0) | Err(_) => break,
                    Ok(len) => {
                        bux_proto::send(w, &ExecOut::Stdout(pty_buf[..len].to_vec())).await?;
                    }
                }
            }
        }
    }

    if let Some(h) = killer {
        h.abort();
    }
    send_exit(w, pty_handle.exit.await, spawn_t0, &timed_out).await
}

/// Negative pid is the group. Second kill covers the window before the child is a leader.
fn kill_job(pgid: i32, sig: i32) {
    if pgid <= 1 {
        return;
    }
    unsafe {
        let _ = libc::kill(-pgid, sig);
        let _ = libc::kill(pgid, sig);
    }
}

/// After `timeout_ms`, `kill_job` the process group. Abort the handle when the I/O loop ends.
fn spawn_timeout_killer(
    pid: i32,
    timeout_ms: u64,
    timed_out: &Arc<AtomicBool>,
) -> Option<tokio::task::JoinHandle<()>> {
    if timeout_ms == 0 {
        return None;
    }
    let flag = Arc::clone(timed_out);
    Some(tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(timeout_ms)).await;
        flag.store(true, Ordering::SeqCst);
        eprintln!("[bux-guest] exec timeout killpg pid={pid}");
        kill_job(pid, libc::SIGKILL);
    }))
}

/// Awaits the reaper waiter and sends `ExecOut::Exit`.
///
/// A cancelled oneshot (reaper task died) is an I/O error, not `code: 0`.
///
/// # Errors
///
/// Returns an error if the waiter was dropped or sending `ExecOut::Exit` fails.
async fn send_exit(
    w: &mut (impl AsyncWrite + Unpin + Send),
    wait: Result<Exit, tokio::sync::oneshot::error::RecvError>,
    spawn_t0: Instant,
    timed_out: &AtomicBool,
) -> io::Result<()> {
    let exit = wait.map_err(|_| io::Error::other("reaper waiter dropped"))?;

    #[allow(clippy::cast_possible_truncation)]
    let duration_ms = spawn_t0.elapsed().as_millis() as u64;

    bux_proto::send(
        w,
        &ExecOut::Exit {
            code: exit.code,
            signal: exit.signal,
            timed_out: timed_out.load(Ordering::SeqCst),
            duration_ms,
            error_message: None,
        },
    )
    .await
}

/// Resolved `(uid, gid)` for an exec, if any credential change is requested.
pub(crate) type Credentials = Option<(u32, u32)>;

/// Resolve numeric or name-based user for this exec.
///
/// Priority: explicit `uid`/`gid` on the request → `user` string (passwd) → none.
pub(crate) fn resolve_credentials(req: &ExecStart) -> io::Result<Credentials> {
    if req.uid.is_some() || req.gid.is_some() {
        let uid = req.uid.or(req.gid).unwrap_or(0);
        let gid = req.gid.or(req.uid).unwrap_or(uid);
        return Ok(Some((uid, gid)));
    }
    if let Some(ref user) = req.user {
        let (uid, gid) = crate::user::resolve_user(user)?;
        return Ok(Some((uid, gid)));
    }
    Ok(None)
}

/// Applies common exec options (cwd, env, credentials) to a command.
///
/// `$credentials` is [`Credentials`] from [`resolve_credentials`].
macro_rules! apply_exec_options {
    ($cmd:expr, $req:expr, $credentials:expr) => {{
        if let Some(ref cwd) = $req.cwd {
            $cmd.current_dir(cwd);
        }
        for pair in &$req.env {
            if let Some((k, v)) = pair.split_once('=') {
                $cmd.env(k, v);
            }
        }
        // Apply gid before uid — setuid would drop privilege to change gid.
        if let Some((uid, gid)) = $credentials {
            unsafe {
                $cmd.pre_exec(move || {
                    if libc::setgid(gid) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::setuid(uid) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
    }};
}
pub(crate) use apply_exec_options;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_wrap,
    reason = "tests"
)]
mod tests {
    use std::os::unix::process::CommandExt as _;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use tokio::io::AsyncReadExt;

    fn prod_src() -> &'static str {
        include_str!("mod.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("prod")
    }

    fn fn_body<'a>(src: &'a str, start: &str, end: &str) -> &'a str {
        src.split(start)
            .nth(1)
            .and_then(|rest| rest.split(end).next())
            .expect("fn body")
    }

    async fn read_to_eof(file: &mut tokio::fs::File) {
        let mut buf = [0u8; 64];
        loop {
            match file.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    }

    #[tokio::test]
    async fn kill_job_reaps_grandchild_holding_pipes() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "sleep 8 &"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = cmd.spawn().unwrap();
        let pid = child.id() as i32;
        unsafe {
            let _ = libc::setpgid(pid, pid);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        super::kill_job(pid, libc::SIGKILL);

        let mut stdout = super::file_from_stdio(child.stdout.take().unwrap());
        let mut stderr = super::file_from_stdio(child.stderr.take().unwrap());
        let t0 = Instant::now();
        tokio::time::timeout(Duration::from_secs(1), async {
            read_to_eof(&mut stdout).await;
            read_to_eof(&mut stderr).await;
        })
        .await
        .expect("kill_job must close grandchild pipe writers");
        assert!(
            t0.elapsed() < Duration::from_secs(1),
            "kill(pid) leaves sleep holding pipes for ~8s"
        );
        drop(child.wait());
    }

    #[test]
    fn production_pipe_uses_process_group_and_kill_job() {
        let prod = prod_src();
        assert!(prod.contains("process_group(0)"), "pipe process group");
        assert!(prod.contains("setpgid"), "parent setpgid");
        assert!(prod.contains("fn kill_job"), "kill_job exists");
        assert!(prod.contains("apply_exec_options"), "macro kept");
        assert!(prod.contains(".abort()"), "abort killer");

        let pipe = fn_body(prod, "async fn handle_pipe(", "\nasync fn handle_pty(");
        assert!(
            pipe.contains("process_group(0)"),
            "handle_pipe process_group"
        );
        assert!(pipe.contains("setpgid"), "handle_pipe parent setpgid");
        assert!(
            pipe.contains("apply_exec_options"),
            "handle_pipe keeps credentials macro"
        );
        assert_eq!(
            pipe.matches("kill_job(pid").count(),
            2,
            "pipe signal + disconnect use kill_job"
        );
        assert!(pipe.contains(".abort()"), "pipe aborts killer");
        assert!(
            !pipe.contains("libc::kill("),
            "pipe must not kill pid directly"
        );

        let pty = fn_body(prod, "async fn handle_pty(", "\nfn kill_job(");
        assert_eq!(
            pty.matches("kill_job(pid").count(),
            2,
            "pty signal + disconnect use kill_job"
        );
        assert!(pty.contains(".abort()"), "pty aborts killer");
        assert!(
            !pty.contains("libc::kill("),
            "pty must not kill pid directly"
        );
        assert!(
            !pty.contains("process_group"),
            "pty handler must not process_group"
        );

        let killer = fn_body(prod, "fn spawn_timeout_killer(", "\nasync fn send_exit(");
        assert!(
            killer.contains("kill_job(pid"),
            "timeout killer uses kill_job"
        );
        assert!(
            !killer.contains("libc::kill("),
            "timeout killer must not kill pid directly"
        );
    }

    #[test]
    fn production_pty_does_not_process_group() {
        let pty = include_str!("pty.rs");
        assert!(
            !pty.contains("process_group"),
            "PTY must not process_group (setsid would EPERM)"
        );
        assert!(
            !pty.contains("only the last pre_exec"),
            "pre_exec appends; not a single slot"
        );
        assert!(
            pty.contains("pre_exec appends"),
            "comment must record that pre_exec appends"
        );
    }
}
