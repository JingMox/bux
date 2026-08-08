//! Install MITM CA certificate into guest trust stores (overlay-writable paths).

use std::fs;
use std::io;
use std::process::Command;

/// Write the CA PEM to common trust locations and refresh if tools exist.
///
/// Best-effort: missing `update-ca-certificates` is not fatal (many slim images).
pub fn install_mitm_ca(pem: &str) -> io::Result<()> {
    // Debian/Ubuntu style
    fs::create_dir_all("/usr/local/share/ca-certificates")?;
    fs::write(
        "/usr/local/share/ca-certificates/bux-mitm-ca.crt",
        pem.as_bytes(),
    )?;

    // Generic OpenSSL path used by many tools
    fs::create_dir_all("/etc/ssl/certs")?;
    fs::write("/etc/ssl/certs/bux-mitm-ca.pem", pem.as_bytes())?;

    // Alpine / some distros also read anchors
    let _ = fs::create_dir_all("/etc/pki/ca-trust/source/anchors");
    let _ = fs::write(
        "/etc/pki/ca-trust/source/anchors/bux-mitm-ca.pem",
        pem.as_bytes(),
    );

    // Refresh system bundles when helpers exist (ignore failures).
    let _ = Command::new("update-ca-certificates").status();
    let _ = Command::new("update-ca-trust").arg("extract").status();

    eprintln!("[bux-guest] installed MITM CA into guest trust paths");
    Ok(())
}
