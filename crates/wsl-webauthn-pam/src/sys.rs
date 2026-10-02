//! Minimal, audited `libc` helpers for the PAM module.
//!
//! This is the **only** module in the crate (besides the PAM ABI bindings) permitted
//! to contain `unsafe` (see the crate-root `deny(unsafe_code)`). It exposes safe
//! wrappers so the authentication logic itself stays entirely safe:
//!
//! * `statfs(2)` — detect a WSL DrvFs/9p mount, where POSIX ownership/mode are not
//!   authoritative.
//!
//! `statfs` is not exposed by the `libc` crate, so its struct is declared locally;
//! `f_type` is the first field and the remaining layout is only used as an opaque
//! out-buffer.

#![allow(unsafe_code)]

use std::ffi::{CString, c_char, c_int};
use std::io;
use std::path::Path;

/// Convert a path to a NUL-terminated C string.
fn cpath(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL byte"))
}

/// `statfs(2)` superblock magic for `path`, if it can be statted.
///
/// Returns `None` on any failure (a missing/inaccessible path simply is not DrvFs).
pub(crate) fn superblock_magic(path: &Path) -> Option<i64> {
    /// Linux `statfs` (struct layout is stable; only `f_type` is consumed).
    #[repr(C)]
    struct Statfs {
        f_type: i64,
        f_bsize: i64,
        f_blocks: u64,
        f_bfree: u64,
        f_bavail: u64,
        f_files: u64,
        f_ffree: u64,
        f_fsid: [i32; 2],
        f_namelen: i64,
        f_frsize: i64,
        f_flags: i64,
        f_spare: [i64; 4],
    }
    // SAFETY: `statfs` is an extern symbol on every Linux target.
    unsafe extern "C" {
        fn statfs(path: *const c_char, buf: *mut Statfs) -> c_int;
    }

    let c = cpath(path).ok()?;
    // SAFETY: `c` is a valid NUL-terminated path; `st` is a plain zeroed buffer that
    // only `statfs` writes and this function then reads.
    let mut st: Statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` outlives the call and `st` is a valid writable pointer.
    let rc = unsafe { statfs(c.as_ptr(), &mut st) };
    (rc == 0).then_some(st.f_type)
}

/// Whether `path` is on a WSL DrvFs/9p mount (`V9FS_MAGIC`).
pub(crate) fn is_drvfs(path: &Path) -> bool {
    /// `V9FS_MAGIC` (include/uapi/linux/magic.h), the superblock magic of DrvFs/9p.
    const V9FS_MAGIC: i64 = 0x0102_1997;
    superblock_magic(path) == Some(V9FS_MAGIC)
}
