//! Guest-side user resolution for Phase A exec (`/etc/passwd`, `/etc/group`).

use std::fs;
use std::io;
use std::path::Path;

/// Resolve `uid`, `uid:gid`, `name`, or `name:group` to numeric credentials.
///
/// # Errors
///
/// Returns an error if the user or group is unknown, or passwd/group cannot be read.
pub fn resolve_user(spec: &str) -> io::Result<(u32, u32)> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty user specification",
        ));
    }

    if let Some((user_part, group_part)) = spec.split_once(':') {
        let uid = resolve_uid(user_part)?;
        let gid = resolve_gid(group_part)?;
        return Ok((uid, gid));
    }

    if let Ok(uid) = spec.parse::<u32>() {
        // Numeric uid alone: primary gid from passwd if present, else same as uid.
        let gid = lookup_passwd_gid(uid).unwrap_or(uid);
        return Ok((uid, gid));
    }

    let (uid, gid) = lookup_passwd_name(spec)?;
    Ok((uid, gid))
}

/// Resolve a user part (numeric or name) to a uid.
fn resolve_uid(part: &str) -> io::Result<u32> {
    let part = part.trim();
    if part.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty user in user:group",
        ));
    }
    if let Ok(uid) = part.parse::<u32>() {
        return Ok(uid);
    }
    lookup_passwd_name(part).map(|(uid, _)| uid)
}

/// Resolve a group part (numeric or name) to a gid.
fn resolve_gid(part: &str) -> io::Result<u32> {
    let part = part.trim();
    if part.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty group in user:group",
        ));
    }
    if let Ok(gid) = part.parse::<u32>() {
        return Ok(gid);
    }
    lookup_group_name(part)
}

/// Look up uid and primary gid for a username in `/etc/passwd`.
fn lookup_passwd_name(name: &str) -> io::Result<(u32, u32)> {
    for line in read_lines(Path::new("/etc/passwd"))? {
        // name:passwd:uid:gid:...
        let mut parts = line.split(':');
        let n = parts.next().unwrap_or("");
        if n != name {
            continue;
        }
        let _passwd = parts.next();
        let uid: u32 = parts
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad passwd uid"))?;
        let gid: u32 = parts
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad passwd gid"))?;
        return Ok((uid, gid));
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("unknown user {name:?}"),
    ))
}

/// Look up the primary gid for a numeric uid in `/etc/passwd`.
fn lookup_passwd_gid(uid: u32) -> Option<u32> {
    for line in read_lines(Path::new("/etc/passwd")).ok()? {
        let mut parts = line.split(':');
        let _name = parts.next()?;
        let _passwd = parts.next()?;
        let entry_uid: u32 = parts.next()?.parse().ok()?;
        if entry_uid != uid {
            continue;
        }
        return parts.next()?.parse().ok();
    }
    None
}

/// Look up a group name in `/etc/group` and return its gid.
fn lookup_group_name(name: &str) -> io::Result<u32> {
    for line in read_lines(Path::new("/etc/group"))? {
        // name:passwd:gid:...
        let mut parts = line.split(':');
        let n = parts.next().unwrap_or("");
        if n != name {
            continue;
        }
        let _passwd = parts.next();
        let gid: u32 = parts
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad group gid"))?;
        return Ok(gid);
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("unknown group {name:?}"),
    ))
}

/// Read non-empty, non-comment lines from a file.
fn read_lines(path: &Path) -> io::Result<Vec<String>> {
    let data = fs::read_to_string(path)?;
    Ok(data
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn numeric_uid_gid() {
        let (u, g) = resolve_user("1000:100").unwrap();
        assert_eq!((u, g), (1000, 100));
    }

    #[test]
    fn numeric_uid_only() {
        // May or may not exist in passwd; still returns a gid.
        let (u, g) = resolve_user("0").unwrap();
        assert_eq!(u, 0);
        // root's primary gid is typically 0
        assert_eq!(g, 0);
    }

    #[test]
    fn empty_rejected() {
        assert!(resolve_user("").is_err());
        assert!(resolve_user("  ").is_err());
    }
}
