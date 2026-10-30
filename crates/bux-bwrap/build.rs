//! Build script for bux-bwrap.
//!
//! 1. Locates or downloads the pre-built `bwrap` binary.
//! 2. Exposes the binary path to dependent crates and the runtime.
//!
//! # Environment variables
//!
//! - `BUX_BWRAP_DIR` — Path to a directory containing a pre-built `bwrap`
//!   binary. When set, skips downloading. Primary flow for local development.
//!
//! - `BUX_BWRAP_VERSION` — Override the bubblewrap release version to download.
//!   Defaults to `BUBBLEWRAP_VERSION`, whose archives are checked against
//!   `BWRAP_SHA256`. Other releases are not checked.

// Build scripts legitimately use stderr for diagnostics, expect/panic for
// unrecoverable failures, and have internal-only helpers.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::unwrap_used,
    missing_docs,
    reason = "build script uses expect/panic for unrecoverable failures"
)]

use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// GitHub repository for downloading pre-built bwrap releases.
const GITHUB_REPO: &str = "qntx/bux";

/// Pinned bubblewrap version — keep in sync with `.github/workflows/bwrap-build.yml`.
const BUBBLEWRAP_VERSION: &str = "0.12.0";

/// Download attempts before the build gives up. The delay between attempts
/// doubles from one second.
const DOWNLOAD_ATTEMPTS: u32 = 3;

/// SHA-256 of each `bwrap-v{BUBBLEWRAP_VERSION}` asset, by target. Update it with the
/// release: `gh release download <tag> --repo qntx/bux` and `shasum -a 256`.
const BWRAP_SHA256: &[(&str, &str)] = &[
    (
        "aarch64-unknown-linux-gnu",
        "81a8e6cbabe0485ce9dc22c17640b2fcef18f0656185e58d6327d6a478c64bd1",
    ),
    (
        "x86_64-unknown-linux-gnu",
        "bbb38b9bddb37149b904b3b1159634cb104408a92f4fda66e21dbff672b60f1c",
    ),
];

fn main() {
    println!("cargo:rerun-if-env-changed=BUX_BWRAP_DIR");
    println!("cargo:rerun-if-env-changed=BUX_BWRAP_VERSION");
    println!("cargo:rerun-if-env-changed=DOCS_RS");

    // docs.rs: no network, no native binaries needed.
    if env::var("DOCS_RS").is_ok() {
        println!("cargo:BWRAP_PATH=/nonexistent");
        return;
    }

    let target = env::var("TARGET").expect("TARGET not set");

    // bubblewrap is Linux-only.
    if !target.contains("linux") {
        println!("cargo:BWRAP_PATH=/nonexistent");
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let bwrap_path = obtain_binary(&target, &out_dir);
    stage_bwrap_beside_binaries(&bwrap_path, &out_dir);

    // Expose the bwrap path to dependent crates' build scripts
    // (available as DEP_BUBBLEWRAP_BWRAP_PATH) and to lib.rs at compile time.
    println!("cargo:BWRAP_PATH={}", bwrap_path.display());
    println!(
        "cargo:rustc-env=BUX_BWRAP_BUILD_PATH={}",
        bwrap_path.display()
    );
}

/// `OUT_DIR` ancestor named `$PROFILE` is the cargo bin dir (native or `--target`).
fn profile_bin_dir(out_dir: &Path, profile: &str) -> PathBuf {
    out_dir
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == profile))
        .map_or_else(
            || {
                panic!(
                    "bux-bwrap: cannot resolve profile bin dir from OUT_DIR={} PROFILE={profile}",
                    out_dir.display()
                )
            },
            Path::to_path_buf,
        )
}

/// Copy `bwrap` into the cargo profile dir so sibling lookup finds it for `cargo run`.
fn stage_bwrap_beside_binaries(bwrap: &Path, out_dir: &Path) {
    let profile = env::var("PROFILE").expect("PROFILE not set");
    let dest_dir = profile_bin_dir(out_dir, &profile);
    fs::create_dir_all(&dest_dir).unwrap_or_else(|e| {
        panic!(
            "bux-bwrap: failed to create profile dir {}: {e}",
            dest_dir.display()
        )
    });
    let dest = dest_dir.join("bwrap");
    if dest.symlink_metadata().is_ok() {
        fs::remove_file(&dest).unwrap_or_else(|e| {
            panic!("bux-bwrap: failed to replace {}: {e}", dest.display());
        });
    }
    fs::copy(bwrap, &dest).unwrap_or_else(|e| {
        panic!(
            "bux-bwrap: failed to copy {} -> {}: {e}",
            bwrap.display(),
            dest.display()
        );
    });
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o755)).unwrap_or_else(|e| {
            panic!("bux-bwrap: failed to chmod 0755 {}: {e}", dest.display());
        });
    }
    assert!(
        dest.is_file(),
        "bux-bwrap: bwrap missing next to binaries at {}",
        dest.display()
    );
}

/// Obtain the pre-built bwrap binary — local directory or GitHub Releases.
fn obtain_binary(target: &str, out_dir: &Path) -> PathBuf {
    if let Ok(dir) = env::var("BUX_BWRAP_DIR") {
        let path = PathBuf::from(&dir).join("bwrap");
        if path.is_file() {
            eprintln!("bux-bwrap: using local binary: {}", path.display());
            return path;
        }
        eprintln!("bux-bwrap: BUX_BWRAP_DIR set but bwrap not found, downloading");
    }

    let version = env::var("BUX_BWRAP_VERSION");
    let version = version.as_deref().unwrap_or(BUBBLEWRAP_VERSION);
    let bin_dir = out_dir.join("bwrap");
    let bwrap_path = bin_dir.join("bwrap");

    if !bwrap_path.is_file() {
        download_binary(version, target, &bin_dir);
    }
    bwrap_path
}

/// Downloads the pre-built bwrap binary from GitHub Releases.
fn download_binary(version: &str, target: &str, dest: &Path) {
    let url = format!(
        "https://github.com/{GITHUB_REPO}/releases/download/bwrap-v{version}/bux-bwrap-{target}.tar.gz"
    );
    // Only the pinned release has known hashes.
    let sha256 = (version == BUBBLEWRAP_VERSION).then(|| pinned_sha256(BWRAP_SHA256, target));
    let archive = download(&url, sha256);

    fs::create_dir_all(dest).expect("Failed to create bwrap dir");
    tar::Archive::new(flate2::read::GzDecoder::new(archive.as_slice()))
        .unpack(dest)
        .expect("Failed to extract bwrap archive");

    let bwrap = dest.join("bwrap");
    assert!(
        bwrap.is_file(),
        "bwrap not found after extraction. Check GitHub Release bwrap-v{version}."
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&bwrap, fs::Permissions::from_mode(0o755))
            .expect("Failed to set bwrap permissions");
    }
}

/// The pinned SHA-256 for `target`. A target without one has no release.
fn pinned_sha256(table: &'static [(&str, &str)], target: &str) -> &'static str {
    table.iter().find(|(t, _)| *t == target).map_or_else(
        || panic!("bux-bwrap: no pinned SHA-256 for {target}"),
        |(_, sha256)| *sha256,
    )
}

/// Download `url`, retrying on errors, and check its SHA-256 when one is
/// pinned for it.
#[allow(
    clippy::disallowed_methods,
    reason = "a build script has no async runtime; retries wait in place"
)]
fn download(url: &str, sha256: Option<&str>) -> Vec<u8> {
    eprintln!("bux-bwrap: downloading {url}");
    let mut delay = std::time::Duration::from_secs(1);
    let mut attempt = 1;
    let body = loop {
        match fetch(url) {
            Ok(body) => break body,
            Err(e) if attempt < DOWNLOAD_ATTEMPTS => {
                eprintln!(
                    "bux-bwrap: attempt {attempt} of {DOWNLOAD_ATTEMPTS} failed: {e}; retrying"
                );
                std::thread::sleep(delay);
                delay *= 2;
                attempt += 1;
            }
            Err(e) => panic!(
                "bux-bwrap: failed to download {url} after {DOWNLOAD_ATTEMPTS} attempts: {e}. \
                 Without access to it, unpack that archive elsewhere and set BUX_BWRAP_DIR \
                 to the directory that holds the `bwrap` binary."
            ),
        }
    };
    match sha256 {
        Some(expected) => {
            let actual = sha256_hex(&body);
            assert!(
                actual == expected,
                "bux-bwrap: SHA-256 mismatch for {url}: expected {expected}, got {actual}"
            );
        }
        None => println!(
            "cargo:warning=bux-bwrap: {url} is not the pinned release, so its SHA-256 is not checked"
        ),
    }
    body
}

/// The body of `url`, without the size limit of `read_to_vec`.
fn fetch(url: &str) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    ureq::get(url)
        .call()
        .map_err(|e| e.to_string())?
        .into_body()
        .into_reader()
        .read_to_end(&mut body)
        .map_err(|e| e.to_string())?;
    Ok(body)
}

/// Lowercase hex SHA-256 of `data`.
fn sha256_hex(data: &[u8]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(data) {
        std::fmt::Write::write_fmt(&mut hex, format_args!("{byte:02x}")).ok();
    }
    hex
}
