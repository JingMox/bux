//! Error types for ext4 filesystem operations.

use std::fmt;

/// Errors returned by ext4 operations.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
#[allow(
    clippy::error_impl_error,
    reason = "Error is the crate's public error type"
)]
pub enum Error {
    /// A libext2fs function returned a non-zero error code.
    #[error("{op}: {code}")]
    Ext2fs {
        /// Name of the libext2fs operation that failed.
        op: &'static str,
        /// The decoded libext2fs error code.
        code: Ext2Code,
    },

    /// A path could not be converted to a C string.
    #[error("invalid path: {0}")]
    InvalidPath(String),

    /// An I/O error occurred outside of libext2fs.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Convenience alias for `std::result::Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// A libext2fs error code.
///
/// Codes live in the `ext2_err.h` error table as `EXT2_ET_BASE + offset`,
/// where `EXT2_ET_BASE` is 2133571328 (`0x7F2BB700`). Functions in
/// `misc/create_inode.c` may instead propagate a bare host `errno`; those are
/// represented by [`Ext2Code::Errno`].
///
/// Only codes this crate matches on in control flow get their own variant.
/// Everything else keeps its raw value in [`Ext2Code::Other`] and is described
/// by the [`fmt::Display`] impl. The enum is `#[non_exhaustive]` so a code can
/// be promoted out of `Other` without a breaking change.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ext2Code {
    /// `EXT2_ET_NO_INODE_BITMAP` (offset 39) — the inode bitmap is not loaded.
    NoInodeBitmap,
    /// `EXT2_ET_NO_BLOCK_BITMAP` (offset 40) — the block bitmap is not loaded.
    NoBlockBitmap,
    /// `EXT2_ET_TOOSMALL` (offset 44) — the filesystem is too small.
    TooSmall,
    /// `EXT2_ET_DIR_EXISTS` (offset 79) — the directory entry already exists.
    DirExists,
    /// `EXT2_ET_FILE_EXISTS` (offset 155) — the file already exists.
    FileExists,
    /// A bare host `errno` propagated by `misc/create_inode.c`.
    Errno(i32),
    /// Any other libext2fs code, kept verbatim.
    Other(i64),
}

impl Ext2Code {
    /// `EXT2_ET_BASE` — first entry of the libext2fs error table.
    pub const BASE: i64 = 2_133_571_328;

    /// Classifies a raw `errcode_t` returned by libext2fs.
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        reason = "guarded by 0 < code < BASE, and BASE < i32::MAX"
    )]
    pub const fn from_raw(code: i64) -> Self {
        // create_inode.c returns bare errno values for host-side I/O failures.
        if code > 0 && code < Self::BASE {
            return Self::Errno(code as i32);
        }
        match code - Self::BASE {
            39 => Self::NoInodeBitmap,
            40 => Self::NoBlockBitmap,
            44 => Self::TooSmall,
            79 => Self::DirExists,
            155 => Self::FileExists,
            _ => Self::Other(code),
        }
    }

    /// The raw `errcode_t` this code was decoded from.
    #[must_use]
    pub const fn raw(self) -> i64 {
        match self {
            Self::NoInodeBitmap => Self::BASE + 39,
            Self::NoBlockBitmap => Self::BASE + 40,
            Self::TooSmall => Self::BASE + 44,
            Self::DirExists => Self::BASE + 79,
            Self::FileExists => Self::BASE + 155,
            Self::Errno(errno) => errno as i64,
            Self::Other(code) => code,
        }
    }
}

impl fmt::Display for Ext2Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NoInodeBitmap => f.write_str("inode bitmap not loaded"),
            Self::NoBlockBitmap => f.write_str("block bitmap not loaded"),
            Self::TooSmall => f.write_str("filesystem too small for the requested operation"),
            Self::DirExists => f.write_str("directory entry already exists"),
            Self::FileExists => f.write_str("file already exists"),
            Self::Errno(errno) => write!(
                f,
                "{} (errno {errno})",
                std::io::Error::from_raw_os_error(errno)
            ),
            // Offsets verified against ext2_err.h (e2fsprogs 1.47.1).
            Self::Other(code) => match code - Self::BASE {
                19 => f.write_str("bad magic number in superblock"),
                20 => f.write_str("filesystem revision too high"),
                21 => f.write_str("cannot write to a read-only filesystem"),
                22 => f.write_str("group descriptors read failure"),
                23 => f.write_str("group descriptors write failure"),
                35 => f.write_str("directory corrupted"),
                36 => f.write_str("short read"),
                37 => f.write_str("short write"),
                38 => f.write_str("no space left in directory"),
                41 => f.write_str("illegal inode number"),
                42 => f.write_str("illegal block number"),
                60 => f.write_str("corrupt superblock"),
                67 => f.write_str("unsupported feature"),
                68 => f.write_str("unsupported read-only feature"),
                70 => f.write_str("out of memory"),
                71 => f.write_str("invalid argument"),
                72 => f.write_str("block allocation failed"),
                73 => f.write_str("inode allocation failed"),
                74 => f.write_str("not a directory"),
                76 => f.write_str("file not found"),
                78 => f.write_str("directory block not found"),
                80 => f.write_str("operation not implemented"),
                82 => f.write_str("file too big"),
                85 => f.write_str("journal too small"),
                _ => write!(f, "libext2fs error {code:#x}"),
            },
        }
    }
}
