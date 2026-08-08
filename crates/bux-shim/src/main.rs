//! bux-shim — child process that boots a micro-VM via libkrun process takeover.
//!
//! Parent writes [`bux_shim::ShimConfig`] JSON and execs:
//! `bux-shim <config.json>`.

#![allow(clippy::print_stderr, reason = "shim reports errors via stderr")]
#![allow(
    clippy::disallowed_methods,
    clippy::exit,
    reason = "shim binary uses process::exit"
)]
#![allow(
    unused_crate_dependencies,
    reason = "binary target shares package deps with the library"
)]

#[cfg(not(unix))]
fn main() {
    eprintln!("[bux-shim] only supported on Unix");
    std::process::exit(1);
}

#[cfg(unix)]
fn main() {
    let Some(config_path) = std::env::args().nth(1) else {
        eprintln!("[bux-shim] usage: bux-shim <config.json>");
        std::process::exit(1);
    };

    let exit_path = std::path::Path::new(&config_path).with_extension("exit");
    bux_shim::install_crash_capture(&exit_path);
    bux_shim::start_watchdog_thread();

    let json = match std::fs::read(&config_path) {
        Ok(j) => {
            drop(std::fs::remove_file(&config_path));
            j
        }
        Err(e) => {
            bux_shim::write_exit_error(&exit_path, &format!("failed to read config: {e}"));
            std::process::exit(1);
        }
    };

    let config = match bux_shim::ShimConfig::from_json(&json) {
        Ok(c) => c,
        Err(e) => {
            bux_shim::write_exit_error(&exit_path, &format!("invalid config JSON: {e}"));
            std::process::exit(1);
        }
    };

    match bux_shim::boot(&config) {
        Ok(()) => unreachable!("krun_start_enter returned"),
        Err(e) => {
            bux_shim::write_exit_error(&exit_path, &format!("VM start failed: {e}"));
            std::process::exit(1);
        }
    }
}
