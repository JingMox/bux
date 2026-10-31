//! A jailed shim dies with bwrap's outer process.

#![allow(
    unused_crate_dependencies,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::panic,
    clippy::disallowed_methods,
    reason = "linux-only integration test binary"
)]
#![cfg(target_os = "linux")]

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const SHIM: &str = env!("CARGO_BIN_EXE_bux-shim");
/// `O_NONBLOCK`: opening a FIFO to write then fails until it has a reader.
const O_NONBLOCK: i32 = 0o4000;
/// `ENXIO`: what that open fails with.
const ENXIO: i32 = 6;

/// bwrap with the arguments that matter here, around `program`.
fn bwrap(program: &str) -> Command {
    let mut cmd = Command::new("bwrap");
    cmd.args(["--unshare-pid", "--as-pid-1", "--ro-bind", "/", "/", "--"])
        .arg(program)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd
}

#[test]
fn a_jailed_shim_dies_with_the_outer_process() {
    if !bwrap("/bin/true").status().is_ok_and(|s| s.success()) {
        return;
    }
    // Reading a FIFO without a writer's data keeps the shim up.
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("jail-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let config = dir.join("cfg.json");
    drop(fs::remove_file(&config));
    assert!(
        Command::new("mkfifo")
            .arg(&config)
            .status()
            .unwrap()
            .success()
    );

    let mut outer = bwrap(SHIM).arg(&config).spawn().unwrap();
    let opened_by = Instant::now() + Duration::from_secs(10);
    let mut fifo = loop {
        match OpenOptions::new()
            .write(true)
            .custom_flags(O_NONBLOCK)
            .open(&config)
        {
            Ok(fifo) => break fifo,
            Err(e) if e.raw_os_error() == Some(ENXIO) && Instant::now() < opened_by => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("the shim did not open its config: {e}"),
        }
    };

    outer.kill().unwrap();
    outer.wait().unwrap();

    // The shim was the FIFO's only reader.
    let gone_by = Instant::now() + Duration::from_secs(10);
    loop {
        match fifo.write(b" ") {
            Err(e) if e.kind() == ErrorKind::BrokenPipe => break,
            _ => {
                assert!(
                    Instant::now() < gone_by,
                    "the shim outlived bwrap's outer process"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    drop(fs::remove_dir_all(&dir));
}
