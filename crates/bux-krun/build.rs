//! Build script for bux-krun.
//!
//! 1. Locates or downloads the pre-built `libkrun` dynamic library.
//! 2. Optionally runs `bindgen` to regenerate Rust bindings (feature `regenerate`).
//! 3. Configures the linker for dynamic linking.
//!
//! # Environment variables
//!
//! - `BUX_DEPS_DIR` — Path to a local directory containing pre-built libraries.
//!   When set, skips downloading. Primary flow for local development.
//!
//! - `BUX_DEPS_VERSION` — Override the deps release version to download.
//!   Defaults to the pinned `LIBKRUN_VERSION`, whose archives are checked
//!   against `DEPS_SHA256`. Other releases are not checked.
//!
//! - `BUX_UPDATE_BINDINGS` — When set alongside the `regenerate` feature, the
//!   freshly generated `bindings.rs` is copied back to `src/bindings.rs` so it
//!   can be committed to the repository.

// Build scripts legitimately use stderr for diagnostics and
// expect/panic for unrecoverable failures (missing network / archive).
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::unwrap_in_result,
    clippy::panic,
    clippy::print_stderr,
    clippy::let_underscore_must_use,
    clippy::missing_docs_in_private_items,
    missing_docs,
    reason = "build scripts may panic/expect on unrecoverable setup failures"
)]

use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::Command;

use sha2::{Digest, Sha256};

/// Pinned native library versions — keep in sync with `.github/workflows/krun-build.yml`.
const LIBKRUN_VERSION: &str = "1.19.6";
const LIBKRUNFW_VERSION: &str = "5.5.0";

/// Download attempts before the build gives up. The delay between attempts
/// doubles from one second.
const DOWNLOAD_ATTEMPTS: u32 = 3;

/// SHA-256 of each `krun-v{LIBKRUN_VERSION}` asset, by target. Update it with the
/// release: `gh release download <tag> --repo qntx/bux` and `shasum -a 256`.
const DEPS_SHA256: &[(&str, &str)] = &[
    (
        "aarch64-apple-darwin",
        "104ec1d11ae563a488d89ab70db879ac87e9a013e4bdca2f018c5c89ba664188",
    ),
    (
        "aarch64-unknown-linux-gnu",
        "601c2f1c8fdbcfd55aa1d79cce2ca98c8fb1e12788e772795ffe6254c5c9e3e7",
    ),
    (
        "x86_64-unknown-linux-gnu",
        "1cfc5c699c3b7a63ccfcc0d9d00aa0185d623dc3bb5164dd237cba012eaa7851",
    ),
];

/// Base URL template for downloading the libkrun header.
#[cfg(feature = "regenerate")]
const HEADER_URL_BASE: &str = "https://raw.githubusercontent.com/libkrun/libkrun";

/// `krun_*` functions wrapped by `ctx`: the calls bux makes that have the
/// same signature in upstream libkrun 1.19 and the smolvm fork.
#[cfg(feature = "regenerate")]
const FUNCTIONS: &[&str] = &[
    "krun_create_ctx",
    "krun_free_ctx",
    "krun_start_enter",
    "krun_set_vm_config",
    "krun_set_exec",
    "krun_set_env",
    "krun_add_virtiofs3",
    "krun_add_disk2",
    "krun_set_root_disk_remount",
    "krun_add_net_unixstream",
    "krun_add_net_unixgram",
    "krun_add_vsock_port2",
    "krun_add_vsock",
    "krun_disable_implicit_vsock",
];

/// Constants used by `ctx` and its callers.
#[cfg(feature = "regenerate")]
const VARS: &[&str] = &[
    "KRUN_FS_ROOT_TAG",
    "KRUN_DISK_FORMAT_RAW",
    "KRUN_DISK_FORMAT_QCOW2",
    "NET_FLAG_VFKIT",
    "COMPAT_NET_FEATURES",
];

/// GitHub repository for downloading pre-built library releases.
const GITHUB_REPO: &str = "qntx/bux";

fn main() {
    println!("cargo:rerun-if-env-changed=BUX_DEPS_DIR");
    println!("cargo:rerun-if-env-changed=BUX_DEPS_VERSION");
    println!("cargo:rerun-if-env-changed=BUX_UPDATE_BINDINGS");
    println!("cargo:rerun-if-env-changed=DOCS_RS");

    // docs.rs: no network, no native libs — pre-generated bindings suffice.
    if env::var("DOCS_RS").is_ok() {
        return;
    }

    let target = env::var("TARGET").expect("TARGET not set");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));

    // Optionally regenerate bindings from the remote header.
    #[cfg(feature = "regenerate")]
    {
        let header = download_header(&out_dir);
        generate_bindings(&header, &out_dir);
    }

    // Only link on supported platforms.
    if !is_supported_target(&target) {
        return;
    }

    let lib_dir = obtain_libraries(&target, &out_dir);
    let link_lib = prepare_link_lib(&lib_dir, &target, &out_dir);
    stage_libraries_beside_binaries(&link_lib, &target, &out_dir);
    println!("cargo:rustc-link-search=native={}", link_lib.display());
    println!("cargo:rustc-link-lib=dylib=krun");
    println!("cargo:LIB_DIR={}", link_lib.display());
}

/// Download `libkrun.h` from the pinned libkrun tag into `$OUT_DIR`.
#[cfg(feature = "regenerate")]
fn download_header(out_dir: &Path) -> PathBuf {
    let path = out_dir.join("libkrun.h");
    if path.exists() {
        return path;
    }

    let url = format!("{HEADER_URL_BASE}/v{LIBKRUN_VERSION}/include/libkrun.h");
    eprintln!("bux-krun: downloading header from {url}");
    let resp = ureq::get(&url)
        .call()
        .unwrap_or_else(|e| panic!("Failed to download libkrun.h: {e}"));

    let mut buf = Vec::new();
    resp.into_body()
        .into_reader()
        .read_to_end(&mut buf)
        .expect("Failed to read header");
    fs::write(&path, &buf).expect("Failed to write libkrun.h");
    path
}

/// Run `bindgen` on the header to produce `$OUT_DIR/bindings.rs`.
#[cfg(feature = "regenerate")]
fn generate_bindings(header: &Path, out_dir: &Path) {
    let out_file = out_dir.join("bindings.rs");

    let mut builder = bindgen::Builder::default()
        .header(header.to_str().expect("path is not valid UTF-8"))
        .use_core();
    for name in FUNCTIONS {
        builder = builder.allowlist_function(name);
    }
    for name in VARS {
        builder = builder.allowlist_var(name);
    }
    let bindings = builder
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("bindgen failed to generate bindings from libkrun.h");

    bindings
        .write_to_file(&out_file)
        .expect("Failed to write bindings.rs");

    // Copy back to src/ when requested, so it can be committed.
    if env::var("BUX_UPDATE_BINDINGS").is_ok() {
        let manifest =
            PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
        let committed = manifest.join("src").join("bindings.rs");
        fs::copy(&out_file, &committed).expect("Failed to copy bindings.rs to src/");
        println!(
            "cargo:warning=Updated committed bindings: {}",
            committed.display()
        );
    }
}

/// Obtain the pre-built dynamic library — local directory or GitHub Releases.
fn obtain_libraries(target: &str, out_dir: &Path) -> PathBuf {
    if let Ok(dir) = env::var("BUX_DEPS_DIR") {
        eprintln!("bux-krun: using local deps: {dir}");
        let lib_dir = PathBuf::from(dir);
        create_versioned_symlinks(&lib_dir, target);
        return lib_dir;
    }

    let version = env::var("BUX_DEPS_VERSION").unwrap_or_else(|_| LIBKRUN_VERSION.to_owned());
    let lib_dir = out_dir.join("lib");

    if !lib_dir.join(lib_filename(target)).exists() {
        download_libs(&version, target, &lib_dir);
    }
    create_versioned_symlinks(&lib_dir, target);
    lib_dir
}

fn is_supported_target(target: &str) -> bool {
    let linux =
        target.contains("linux") && (target.contains("x86_64") || target.contains("aarch64"));
    let macos = target.contains("apple") && target.contains("aarch64");
    linux || macos
}

fn lib_filename(target: &str) -> &'static str {
    if target.contains("apple") {
        "libkrun.dylib"
    } else {
        "libkrun.so"
    }
}

/// `OUT_DIR` ancestor named `$PROFILE` is the cargo bin dir (native or `--target`).
fn profile_bin_dir(out_dir: &Path, profile: &str) -> PathBuf {
    out_dir
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == profile))
        .map_or_else(
            || {
                panic!(
                    "bux-krun: cannot resolve profile bin dir from OUT_DIR={} PROFILE={profile}",
                    out_dir.display()
                )
            },
            Path::to_path_buf,
        )
}

fn remove_existing(path: &Path) {
    if path.symlink_metadata().is_ok() {
        fs::remove_file(path).unwrap_or_else(|e| {
            panic!("bux-krun: failed to replace {}: {e}", path.display());
        });
    }
}

fn copy_over(src: &Path, dest: &Path) {
    remove_existing(dest);
    fs::copy(src, dest).unwrap_or_else(|e| {
        panic!(
            "bux-krun: failed to copy {} -> {}: {e}",
            src.display(),
            dest.display()
        );
    });
}

fn prepare_link_lib(lib_dir: &Path, target: &str, out_dir: &Path) -> PathBuf {
    if target.contains("apple") {
        rewrite_darwin_dylibs(lib_dir, out_dir)
    } else {
        lib_dir.to_path_buf()
    }
}

/// Copies into `$OUT_DIR/link-lib` and sets `LC_ID_DYLIB` to `@loader_path/…`
/// so dependents record that load path. `LC_RPATH @loader_path` on libkrun is
/// required for `dlopen("libkrunfw.5.dylib")`.
#[cfg(target_os = "macos")]
fn rewrite_darwin_dylibs(lib_dir: &Path, out_dir: &Path) -> PathBuf {
    let link_lib = out_dir.join("link-lib");
    fs::create_dir_all(&link_lib)
        .unwrap_or_else(|e| panic!("bux-krun: failed to create {}: {e}", link_lib.display()));

    for name in ["libkrun.dylib", "libkrunfw.dylib"] {
        let src = lib_dir.join(name);
        assert!(
            src.exists(),
            "bux-krun: {name} not found in {}",
            lib_dir.display()
        );
        let dest = link_lib.join(name);
        copy_over(&src, &dest);
        make_writable(&dest);
        let id = format!("@loader_path/{name}");
        run_macos_tool("install_name_tool", &["-id", &id, utf8_path(&dest)]);
    }

    let krun = link_lib.join("libkrun.dylib");
    run_macos_tool(
        "install_name_tool",
        &["-add_rpath", "@loader_path", utf8_path(&krun)],
    );
    for name in ["libkrun.dylib", "libkrunfw.dylib"] {
        let dest = link_lib.join(name);
        run_macos_tool("codesign", &["--force", "-s", "-", utf8_path(&dest)]);
    }
    link_lib
}

#[cfg(not(target_os = "macos"))]
fn rewrite_darwin_dylibs(_lib_dir: &Path, _out_dir: &Path) -> PathBuf {
    panic!("bux-krun: Darwin libkrun rewrite requires macOS");
}

#[cfg(target_os = "macos")]
fn utf8_path(path: &Path) -> &str {
    path.to_str()
        .unwrap_or_else(|| panic!("bux-krun: non-UTF-8 path {}", path.display()))
}

#[cfg(target_os = "macos")]
fn make_writable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)
        .unwrap_or_else(|e| panic!("bux-krun: stat {}: {e}", path.display()))
        .permissions();
    perms.set_mode(perms.mode() | 0o200);
    fs::set_permissions(path, perms).unwrap_or_else(|e| {
        panic!("bux-krun: chmod {}: {e}", path.display());
    });
}

#[cfg(target_os = "macos")]
fn run_macos_tool(tool: &str, args: &[&str]) {
    let status = Command::new(tool).args(args).status().unwrap_or_else(|e| {
        panic!("bux-krun: failed to run {tool}: {e}");
    });
    assert!(
        status.success(),
        "bux-krun: {tool} {} failed with {status}",
        args.join(" ")
    );
}

/// Stage libs next to cargo bins and recreate soname aliases for firmware `dlopen`.
fn stage_libraries_beside_binaries(lib_dir: &Path, target: &str, out_dir: &Path) {
    let profile = env::var("PROFILE").expect("PROFILE not set");
    let dest = profile_bin_dir(out_dir, &profile);
    fs::create_dir_all(&dest).unwrap_or_else(|e| {
        panic!(
            "bux-krun: failed to create profile dir {}: {e}",
            dest.display()
        )
    });

    let aliases = soname_aliases(target);
    for (unversioned, _) in &aliases {
        let src = lib_dir.join(unversioned);
        assert!(
            src.exists(),
            "bux-krun: {unversioned} not found in {}",
            lib_dir.display()
        );
        copy_over(&src, &dest.join(unversioned));
    }

    for (_, alias) in &aliases {
        remove_existing(&dest.join(alias));
    }
    create_versioned_symlinks(&dest, target);

    let required = lib_filename(target);
    assert!(
        dest.join(required).exists(),
        "bux-krun: {required} missing next to binaries at {}",
        dest.display()
    );
    for (_, alias) in &aliases {
        assert!(
            dest.join(alias).exists(),
            "bux-krun: {alias} missing next to binaries at {}",
            dest.display()
        );
    }
}

fn download_libs(version: &str, target: &str, dest: &Path) {
    let url = format!(
        "https://github.com/{GITHUB_REPO}/releases/download/krun-v{version}/bux-deps-{target}.tar.gz"
    );
    // Only the pinned release has known hashes.
    let sha256 = (version == LIBKRUN_VERSION).then(|| pinned_sha256(DEPS_SHA256, target));
    let archive = download(&url, sha256);

    fs::create_dir_all(dest).expect("Failed to create lib dir");
    tar::Archive::new(flate2::read::GzDecoder::new(archive.as_slice()))
        .unpack(dest)
        .expect("Failed to extract archive");

    assert!(
        dest.join(lib_filename(target)).exists(),
        "Library not found after extraction. Check GitHub Release krun-v{version}."
    );

    // libkrun loads libkrunfw via dlopen with a versioned soname.
    // Create versioned symlinks so the runtime linker can find them.
    create_versioned_symlinks(dest, target);
}

/// Extract the major version component from a semver string (e.g. `"5.2.1"` → `"5"`).
fn major_version(version: &str) -> &str {
    version.split('.').next().expect("empty version string")
}

fn soname_aliases(target: &str) -> [(&'static str, String); 2] {
    let krun_major = major_version(LIBKRUN_VERSION);
    let krunfw_major = major_version(LIBKRUNFW_VERSION);
    if target.contains("apple") {
        [
            ("libkrun.dylib", format!("libkrun.{krun_major}.dylib")),
            ("libkrunfw.dylib", format!("libkrunfw.{krunfw_major}.dylib")),
        ]
    } else {
        [
            ("libkrun.so", format!("libkrun.so.{krun_major}")),
            ("libkrunfw.so", format!("libkrunfw.so.{krunfw_major}")),
        ]
    }
}

/// Create versioned symlinks (e.g. `libkrunfw.so.5 -> libkrunfw.so`) so that
/// `dlopen("libkrunfw.so.5")` succeeds at runtime.
fn create_versioned_symlinks(dir: &Path, target: &str) {
    for (src, link) in &soname_aliases(target) {
        let src_path = dir.join(src);
        let link_path = dir.join(link);
        if !src_path.exists() || link_path.exists() {
            continue;
        }
        #[cfg(unix)]
        if let Err(e) = std::os::unix::fs::symlink(src, &link_path) {
            eprintln!("bux-krun: warning: failed to create symlink {link}: {e}");
        }
        #[cfg(not(unix))]
        let _ = fs::copy(&src_path, &link_path);
    }
}

/// The pinned SHA-256 for `target`. A target without one has no release.
fn pinned_sha256(table: &'static [(&str, &str)], target: &str) -> &'static str {
    table.iter().find(|(t, _)| *t == target).map_or_else(
        || panic!("bux-krun: no pinned SHA-256 for {target}"),
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
    eprintln!("bux-krun: downloading {url}");
    let mut delay = std::time::Duration::from_secs(1);
    let mut attempt = 1;
    let body = loop {
        match fetch(url) {
            Ok(body) => break body,
            Err(e) if attempt < DOWNLOAD_ATTEMPTS => {
                eprintln!(
                    "bux-krun: attempt {attempt} of {DOWNLOAD_ATTEMPTS} failed: {e}; retrying"
                );
                std::thread::sleep(delay);
                delay *= 2;
                attempt += 1;
            }
            Err(e) => panic!(
                "bux-krun: failed to download {url} after {DOWNLOAD_ATTEMPTS} attempts: {e}. \
                 Without access to it, unpack that archive elsewhere and set BUX_DEPS_DIR \
                 to the directory that holds its libraries."
            ),
        }
    };
    match sha256 {
        Some(expected) => {
            let actual = sha256_hex(&body);
            assert!(
                actual == expected,
                "bux-krun: SHA-256 mismatch for {url}: expected {expected}, got {actual}"
            );
        }
        None => println!(
            "cargo:warning=bux-krun: {url} is not the pinned release, so its SHA-256 is not checked"
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
