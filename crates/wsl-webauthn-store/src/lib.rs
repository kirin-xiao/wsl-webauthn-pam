//! Linux credential store and config parsing.
//!
//! This crate owns the root-owned, symlink-hardened on-disk layout used by the PAM
//! module (hot path) and the CLI (enrollment):
//!
//! ```text
//! <base>/credentials/          # mode 0700, root:root
//! <base>/credentials/<user>.json   # mode 0600, root:root
//! <base>/config                # mode 0600, root:root (TOML)
//! ```
//!
//! The production base dir is `/etc/wsl_webauthn` ([`Store::system`]); an arbitrary base
//! directory is passed via [`Store::with_owner`].
//!
//! # Hardening model
//!
//! * The username is validated by hand before it is ever joined to a path; anything
//!   outside `^[A-Za-z_][A-Za-z0-9._-]{0,31}$` is rejected with
//!   [`StoreError::InvalidUsername`]. This never reaches the filesystem.
//! * Every path component from the base down (base dir, `credentials` dir, record file)
//!   is `lstat`ed; a symlink anywhere is [`StoreError::SymlinkedPath`].
//! * The base directory must be owned by the store's expected owner and must not be
//!   group/other-writable (it has no exact-mode requirement); otherwise
//!   [`StoreError::InsecureBase`].
//! * The `credentials` dir must be **exactly** `0700`, the record/config files **exactly**
//!   `0600`, all owned by the store's expected owner (root in production). The check is an
//!   equality test, so any group/other bit (or setuid/setgid/sticky bit) is rejected as
//!   [`StoreError::BadOwnership`]; stricter than a "no wider than" test, and fail-closed.
//! * Reads use `open(2)` with `O_RDONLY|O_NOFOLLOW|O_NOCTTY|O_CLOEXEC`, then `fstat` the
//!   opened descriptor and compare `(dev, ino)` with the earlier `lstat` — a file swapped
//!   between the two calls is rejected as [`StoreError::PathChanged`]. The post-open
//!   ownership/mode check is performed on the **opened descriptor's** `fstat`, so a file
//!   swapped in after the pre-open `lstat` cannot pass with attacker-chosen metadata.
//! * Reads are capped at 256 KiB (`64 KiB` for the config); the cap is enforced while
//!   reading (the cap-exceeding byte is observed and never accumulated), so an oversized
//!   or growing file cannot blow up memory. A larger file is [`StoreError::TooLarge`].
//!   The content must parse as JSON/TOML or it is [`StoreError::Corrupt`]/[`StoreError::Config`].
//! * The record's `schema_version` must be exactly 1 and its `linux_user` must equal the
//!   lookup name; otherwise [`StoreError::Corrupt`]/[`StoreError::RecordUserMismatch`].
//!   Parsing uses `deny_unknown_fields`, so a record carrying unexpected keys is
//!   [`StoreError::Corrupt`] (strict, fail-closed). [`CredentialRecord::validate`] also
//!   enforces the cross-field invariants serde cannot express: `attestation.mode` must be
//!   `"strict"` or `"unattested-opt-in"`, a `"strict"` record must be `verified`, and the
//!   `attestation.leaf_sha256` / `bridge_sha256` digests, when present, must be exactly 64
//!   lowercase hex characters (an uppercase or truncated digest is
//!   [`StoreError::Corrupt`] on load and [`StoreError::Encode`] on save).
//!   `enrolled_at` is stored but not re-validated here (the verifier/PAM trust only the
//!   cryptographic fields).
//! * Writes are atomic: `mkstemp` in the target directory (`.tmp-XXXXXX`), `fchmod 0600`,
//!   `fsync` the file, then `renameat` over the target (or `linkat` when `replace ==
//!   false`) **relative to the held, identity-checked directory descriptor**, then
//!   `fsync` the directory **on every success path** (durability of the rename). Going
//!   through the descriptor, not the absolute paths, means a directory swapped in at the
//!   same path cannot receive the record: the temp name does not exist in the held
//!   directory, so the install fails `ENOENT` (the temp create is still path-based, for
//!   want of an `*at` `mkstemp`). A temp file is removed on every error path; after a
//!   successful `linkat` a failed temp cleanup is ignored, because the record is already
//!   installed and a leftover `.tmp-*` (root-only `0700` directory) is harmless.
//!
//! # JSON schema (`schema_version: 1`)
//!
//! ```json
//! {
//!   "schema_version": 1,
//!   "rp_id": "wsl-webauthn-pam",
//!   "origin": "wsl-webauthn-pam",
//!   "linux_user": "alice",
//!   "linux_uid": 1000,
//!   "credential_id": "<base64url>",
//!   "cose_public_key": "<base64url>",
//!   "alg": -7,
//!   "aaguid": "08987058-cadc-4b81-b6e1-30de50dcbe96",
//!   "attestation": {
//!     "format": "packed",
//!     "mode": "strict",
//!     "verified": true,
//!     "leaf_sha256": "<lowercase hex>"
//!   },
//!   "windows_identity": { "account": "HOST\\alice", "sid": "S-1-5-21-..." },
//!   "enrolled_at": "2026-10-01T12:34:56Z",
//!   "sign_count": 0,
//!   "bridge_path": "/mnt/c/Users/alice/AppData/Local/Programs/wsl-webauthn-pam/WSLWebAuthnBridge.exe",
//!   "bridge_sha256": "<lowercase hex>"
//! }
//! ```
//!
//! `windows_identity` may be `null`. `attestation.mode` is `"strict"` or
//! `"unattested-opt-in"`; [`Store::load`] rejects any other value as
//! [`StoreError::Corrupt`].
//!
//! The config TOML is written by the store: [`Config::to_toml`] is the serializer,
//! [`Store::save_config`] the atomic, `0600`, owner-checked writer, and
//! [`Store::load_config`] the matching parser.

// `forbid` would prevent the audited `sys` module from using `unsafe`; use crate-wide
// `deny` plus one documented `#[allow(unsafe_code)]` on `sys`.
#![deny(unsafe_code)]
#![warn(missing_docs)]

mod record;
mod sys;

use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;
use wsl_webauthn_protocol::b64u_decode;

pub use record::{
    AttestationRecord, Config, CredentialRecord, InvalidRecord, MODE_STRICT,
    MODE_UNATTESTED_OPT_IN, SCHEMA_VERSION, WindowsIdentity,
};

/// Mode required on the `credentials` directory.
pub const DIR_MODE: u32 = 0o700;
/// Mode required on credential record files.
pub const FILE_MODE: u32 = 0o600;
/// Mode required on the config file.
pub const CONFIG_MODE: u32 = 0o600;
/// Mode used when [`Store::save_config`] creates the base directory itself (`0755`).
///
/// The base directory has no *exact*-mode requirement, only "owner-controlled and not
/// group/other-writable".
pub const BASE_MODE: u32 = 0o755;

/// Maximum size of a credential record file (256 KiB).
pub const MAX_RECORD_BYTES: usize = 256 * 1024;
/// Maximum size of the config file (64 KiB).
pub const MAX_CONFIG_BYTES: usize = 64 * 1024;

/// The production base directory (`/etc/wsl_webauthn`).
pub const SYSTEM_BASE: &str = "/etc/wsl_webauthn";

/// Exhaustive error type for every store operation.
///
/// The PAM module maps store failures to `PAM_AUTHINFO_UNAVAIL` (fail-closed); a missing
/// record ([`StoreError::NotFound`]) maps to `PAM_USER_UNKNOWN`. Ceremony vs. transport
/// distinctions are handled by other crates.
#[derive(Debug, Error)]
pub enum StoreError {
    /// The username did not match `^[A-Za-z_][A-Za-z0-9._-]{0,31}$`.
    #[error("invalid username")]
    InvalidUsername,
    /// A path component (base dir, credentials dir, or record file) is a symbolic link.
    #[error("refusing to follow symlink at {path}")]
    SymlinkedPath {
        /// The offending path.
        path: PathBuf,
    },
    /// A path expected to be a regular file or directory had the wrong type.
    #[error("unexpected file type at {path}")]
    NotRegularFile {
        /// The offending path.
        path: PathBuf,
    },
    /// Ownership or permission bits did not match the required root-owned modes.
    #[error(
        "bad ownership/mode at {path}: expected uid {expected_uid} mode {expected_mode:o}, \
         found uid {actual_uid} mode {actual_mode:o}"
    )]
    BadOwnership {
        /// The offending path.
        path: PathBuf,
        /// Expected owner uid.
        expected_uid: u32,
        /// Actual owner uid.
        actual_uid: u32,
        /// Expected permission bits.
        expected_mode: u32,
        /// Actual permission bits.
        actual_mode: u32,
    },
    /// The base directory is owned by the wrong user or is group/other-writable.
    ///
    /// Group/other write access would let an attacker replace the `credentials`
    /// directory or the `config` file underneath it.
    #[error(
        "insecure base directory {path}: expected uid {expected_uid}, \
         found uid {actual_uid} mode {actual_mode:o}"
    )]
    InsecureBase {
        /// The offending base directory.
        path: PathBuf,
        /// Expected owner uid.
        expected_uid: u32,
        /// Actual owner uid.
        actual_uid: u32,
        /// Actual permission bits.
        actual_mode: u32,
    },
    /// The requested record/config does not exist.
    #[error("not found: {path}")]
    NotFound {
        /// The missing path.
        path: PathBuf,
    },
    /// An existing record was found although `replace == false`.
    #[error("record already exists: {path}")]
    AlreadyExists {
        /// The existing record path.
        path: PathBuf,
    },
    /// A record file existed but was not valid JSON / a supported schema.
    #[error("corrupt credential record at {path}: {message}")]
    Corrupt {
        /// The record path.
        path: PathBuf,
        /// Human-readable parse/validation failure.
        message: String,
    },
    /// Content exceeded the configured read cap.
    #[error("file at {path} exceeds the {cap}-byte cap")]
    TooLarge {
        /// The offending path.
        path: PathBuf,
        /// The enforced cap in bytes.
        cap: usize,
    },
    /// The file identity changed between `lstat` and `open` (TOCTOU).
    #[error("path changed during open (possible race): {path}")]
    PathChanged {
        /// The offending path.
        path: PathBuf,
    },
    /// A record's `linux_user` did not match the username it was stored/looked up under.
    #[error("record linux_user {record_user:?} does not match {argument_user:?}")]
    RecordUserMismatch {
        /// The value stored in the record.
        record_user: String,
        /// The username argument.
        argument_user: String,
    },
    /// A conditional update found the record was replaced or removed since it was read.
    ///
    /// Distinct from [`StoreError::PathChanged`], which flags a suspicious mid-read swap:
    /// this is the benign outcome of two logins racing an enrollment/re-enrollment, or of
    /// an `unregister` completing during an in-flight authentication. The update is
    /// refused rather than clobbering the newer (or removed) credential.
    #[error("record changed since it was read: {path}")]
    RecordChanged {
        /// The record path.
        path: PathBuf,
    },
    /// The config file is absent (`/etc/wsl_webauthn/config`).
    #[error("config file missing: {path}")]
    ConfigMissing {
        /// The missing config path.
        path: PathBuf,
    },
    /// The config file existed but could not be parsed.
    #[error("invalid config at {path}: {message}")]
    Config {
        /// The config path.
        path: PathBuf,
        /// The parse failure.
        message: String,
    },
    /// A record could not be serialized (should not happen for the fixed schema).
    #[error("failed to encode credential record: {message}")]
    Encode {
        /// The serialization failure.
        message: String,
    },
    /// An underlying OS error occurred.
    #[error("i/o error at {path}: {source}")]
    Io {
        /// The path being operated on.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
}

impl StoreError {
    /// A stable, non-identifying token for the error's *kind*.
    ///
    /// Unlike [`Display`](std::fmt::Display), this never embeds an absolute path or a
    /// username: the PAM module logs it to `authpriv` syslog, where the full `Display`
    /// would disclose the record path — and therefore the username — on every failure.
    /// The CLI keeps using `Display` for operator diagnostics. The spelling of each token
    /// is part of this API and must not change.
    #[must_use]
    pub fn kind_str(&self) -> &'static str {
        match self {
            StoreError::InvalidUsername => "invalid_username",
            StoreError::SymlinkedPath { .. } => "symlink",
            StoreError::NotRegularFile { .. } => "not_regular_file",
            StoreError::BadOwnership { .. } => "bad_ownership",
            StoreError::InsecureBase { .. } => "insecure_base",
            StoreError::NotFound { .. } => "not_found",
            StoreError::AlreadyExists { .. } => "already_exists",
            StoreError::Corrupt { .. } => "record_corrupt",
            StoreError::TooLarge { .. } => "too_large",
            StoreError::PathChanged { .. } => "path_changed",
            StoreError::RecordUserMismatch { .. } => "record_user_mismatch",
            StoreError::RecordChanged { .. } => "record_changed",
            StoreError::ConfigMissing { .. } => "config_missing",
            StoreError::Config { .. } => "config_invalid",
            StoreError::Encode { .. } => "encode",
            StoreError::Io { .. } => "io",
        }
    }
}

/// A credential store rooted at an arbitrary base directory.
///
/// [`Store::system`] is rooted at [`SYSTEM_BASE`] and expects root (`uid 0`) ownership.
#[derive(Debug, Clone)]
pub struct Store {
    base: PathBuf,
    owner_uid: u32,
}

/// The filesystem identity (`st_dev`, `st_ino`) of a credential record file.
///
/// Captured from the `fstat` of the descriptor the record bytes were actually read from
/// (see [`Store::load_with_identity`]), so a conditional update can refuse to clobber a
/// record that was replaced or removed since. This is an opaque comparison token, not a
/// path.
///
/// The `Default` (zero) identity is never produced by a real load; it exists so test
/// doubles that synthesize a record without a backing file can still name a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileIdentity {
    dev: u64,
    ino: u64,
}

/// Borrowed arguments to the shared atomic temp-file install path.
struct Install<'a> {
    fd: sys::Fd,
    temp: &'a Path,
    target: &'a Path,
    contents: &'a [u8],
    replace: bool,
    dir_fd: &'a sys::Fd,
    mode: u32,
    /// Directory being fsynced (for the error message only).
    dir_path: &'a Path,
    /// When set, the install proceeds only if the target still resolves to this identity
    /// (a conditional update); a mismatch or a vanished target is
    /// [`StoreError::RecordChanged`].
    expected_identity: Option<FileIdentity>,
}

impl Store {
    /// Open the production store at [`SYSTEM_BASE`] with root ownership expectations.
    pub fn system() -> Store {
        Store::with_owner(SYSTEM_BASE, 0)
    }

    /// Open a store at `base`, expecting files to be owned by `owner_uid`.
    pub fn with_owner(base: impl AsRef<Path>, owner_uid: u32) -> Store {
        Store {
            base: base.as_ref().to_path_buf(),
            owner_uid,
        }
    }

    /// The base directory this store is rooted at.
    #[must_use]
    pub fn base(&self) -> &Path {
        &self.base
    }

    /// The expected owner uid.
    #[must_use]
    pub fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    /// `<base>/credentials`.
    #[must_use]
    pub fn credentials_dir(&self) -> PathBuf {
        self.base.join("credentials")
    }

    /// `<base>/config`.
    #[must_use]
    pub fn config_path(&self) -> PathBuf {
        self.base.join("config")
    }

    /// `<base>/credentials/<username>.json`.
    ///
    /// `username` must already satisfy [`validate_username`]: every caller validates
    /// first, so this is a defensive assertion (debug builds panic on a violation) rather
    /// than an input check that returns an error.
    #[must_use]
    pub fn record_path(&self, username: &str) -> PathBuf {
        debug_assert!(
            validate_username(username).is_ok(),
            "record_path requires a username that passed validate_username"
        );
        self.credentials_dir().join(format!("{username}.json"))
    }

    fn io(&self, path: impl Into<PathBuf>, source: io::Error) -> StoreError {
        StoreError::Io {
            path: path.into(),
            source,
        }
    }

    fn check_owner_mode(&self, path: &Path, st: sys::Stat, mode: u32) -> Result<(), StoreError> {
        if st.uid != self.owner_uid || st.perm_bits() != mode {
            return Err(StoreError::BadOwnership {
                path: path.to_path_buf(),
                expected_uid: self.owner_uid,
                actual_uid: st.uid,
                expected_mode: mode,
                actual_mode: st.perm_bits(),
            });
        }
        Ok(())
    }

    /// Validate a directory and return an `O_NOFOLLOW|O_DIRECTORY` handle to it.
    ///
    /// Closes the window between the `lstat` checks and subsequent operations: metadata
    /// is re-read from the **opened descriptor** (`fstat`) and its `(dev, ino)` compared
    /// with the earlier `lstat`, so a directory swapped in mid-operation is
    /// [`StoreError::PathChanged`] rather than silently trusted.
    fn open_checked_dir(&self, path: &Path, mode: u32) -> Result<sys::Fd, StoreError> {
        let before = match sys::lstat(path) {
            Ok(st) => st,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::NotFound {
                    path: path.to_path_buf(),
                });
            }
            Err(e) => return Err(self.io(path, e)),
        };
        if before.is_symlink() {
            return Err(StoreError::SymlinkedPath {
                path: path.to_path_buf(),
            });
        }
        if !before.is_dir() {
            return Err(StoreError::NotRegularFile {
                path: path.to_path_buf(),
            });
        }
        self.check_owner_mode(path, before, mode)?;

        let fd = sys::open_dir(path).map_err(|e| self.io(path, e))?;
        let after = sys::fstat(fd.raw()).map_err(|e| self.io(path, e))?;
        if after.uid != self.owner_uid || after.perm_bits() != mode {
            return Err(StoreError::BadOwnership {
                path: path.to_path_buf(),
                expected_uid: self.owner_uid,
                actual_uid: after.uid,
                expected_mode: mode,
                actual_mode: after.perm_bits(),
            });
        }
        if after.dev != before.dev || after.ino != before.ino {
            return Err(StoreError::PathChanged {
                path: path.to_path_buf(),
            });
        }
        Ok(fd)
    }

    /// Verify the base directory exists, is a directory, is not a symlink, is owned by
    /// the expected user, and is not group/other-writable.
    ///
    /// The base directory has **no** exact-mode requirement (an admin may use `0755`),
    /// but group/other-writable is refused as [`StoreError::InsecureBase`], since an
    /// attacker could otherwise swap in their own `credentials/` directory or `config`
    /// file. Runs first on every operation that resolves a path under the base.
    fn check_base(&self) -> Result<sys::Stat, StoreError> {
        let st = match sys::lstat(&self.base) {
            Ok(st) => st,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::NotFound {
                    path: self.base.clone(),
                });
            }
            Err(e) => return Err(self.io(&self.base, e)),
        };
        if st.is_symlink() {
            return Err(StoreError::SymlinkedPath {
                path: self.base.clone(),
            });
        }
        if !st.is_dir() {
            return Err(StoreError::NotRegularFile {
                path: self.base.clone(),
            });
        }
        if st.uid != self.owner_uid || st.perm_bits() & 0o022 != 0 {
            return Err(StoreError::InsecureBase {
                path: self.base.clone(),
                expected_uid: self.owner_uid,
                actual_uid: st.uid,
                actual_mode: st.perm_bits(),
            });
        }
        Ok(st)
    }

    /// Ensure `<base>/credentials` exists with mode `0700` and the expected owner,
    /// creating it (and `fchmod`ing to defeat umask) if missing.
    ///
    /// Returns an ownership/mode-validated `O_DIRECTORY|O_NOFOLLOW` handle. It is held for
    /// the whole install: the temp file is installed (`renameat`/`linkat`) and the
    /// directory entry is `fsynced` **relative to this descriptor**, so the install cannot
    /// be redirected into a directory swapped in at the same path. The path is still used
    /// to *create* the temp file (see [`Store::save_atomic`]); a swap before that create
    /// makes the descriptor-relative install fail `ENOENT`, which is fail-closed.
    fn ensure_credentials_dir(&self) -> Result<sys::Fd, StoreError> {
        let dir = self.credentials_dir();
        match sys::lstat(&dir) {
            Ok(_) => {
                // Reuse the TOCTOU-safe descriptor checks for an existing directory.
                self.open_checked_dir(&dir, DIR_MODE)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                self.check_base()?;
                sys::mkdir(&dir, DIR_MODE).map_err(|e| self.io(&dir, e))?;
                // mkdir is subject to umask; pin the mode exactly.
                let fd = sys::open_dir(&dir).map_err(|e| self.io(&dir, e))?;
                sys::fchmod(fd.raw(), DIR_MODE).map_err(|e| self.io(&dir, e))?;
                drop(fd);
                self.open_checked_dir(&dir, DIR_MODE)
            }
            Err(e) => Err(self.io(&dir, e)),
        }
    }

    /// Open, `fstat`-validate, and read a hardened file with a size cap.
    ///
    /// Returns the bytes together with the `fstat` identity of the descriptor they were
    /// read from, so a caller that will later conditionally update the file can detect a
    /// replacement/removal (see [`Store::load_with_identity`]).
    fn read_secure_file(
        &self,
        path: &Path,
        mode: u32,
        cap: usize,
        missing: impl FnOnce(PathBuf) -> StoreError,
    ) -> Result<(Vec<u8>, sys::Stat), StoreError> {
        let before = match sys::lstat(path) {
            Ok(st) => st,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(missing(path.to_path_buf()));
            }
            Err(e) => return Err(self.io(path, e)),
        };
        if before.is_symlink() {
            return Err(StoreError::SymlinkedPath {
                path: path.to_path_buf(),
            });
        }
        if !before.is_file() {
            return Err(StoreError::NotRegularFile {
                path: path.to_path_buf(),
            });
        }
        self.check_owner_mode(path, before, mode)?;

        let fd = sys::open_readonly(path).map_err(|e| self.io(path, e))?;
        let after = sys::fstat(fd.raw()).map_err(|e| self.io(path, e))?;
        if after.uid != self.owner_uid || after.perm_bits() != mode {
            return Err(StoreError::BadOwnership {
                path: path.to_path_buf(),
                expected_uid: self.owner_uid,
                actual_uid: after.uid,
                expected_mode: mode,
                actual_mode: after.perm_bits(),
            });
        }
        if after.dev != before.dev || after.ino != before.ino {
            return Err(StoreError::PathChanged {
                path: path.to_path_buf(),
            });
        }

        match sys::read_capped(fd.raw(), cap).map_err(|e| self.io(path, e))? {
            None => Err(StoreError::TooLarge {
                path: path.to_path_buf(),
                cap,
            }),
            Some(bytes) => Ok((bytes, after)),
        }
    }

    /// Load the credential record for `username` (PAM hot path).
    ///
    /// A missing record is [`StoreError::NotFound`] (PAM maps it to
    /// `PAM_USER_UNKNOWN`).
    pub fn load(&self, username: &str) -> Result<CredentialRecord, StoreError> {
        self.load_with_identity(username).map(|(record, _)| record)
    }

    /// Load the credential record together with the filesystem identity of the file it was
    /// read from.
    ///
    /// The identity is captured from the `fstat` of the very descriptor the bytes came
    /// from, so it can be handed to [`Store::update_if_unchanged`] to refuse a conditional
    /// write if the record was replaced or removed in the meantime.
    pub fn load_with_identity(
        &self,
        username: &str,
    ) -> Result<(CredentialRecord, FileIdentity), StoreError> {
        validate_username(username)?;
        self.check_base()?;
        let _dir_fd = self.open_checked_dir(&self.credentials_dir(), DIR_MODE)?;

        let path = self.record_path(username);
        let (bytes, stat) = self.read_secure_file(&path, FILE_MODE, MAX_RECORD_BYTES, |p| {
            StoreError::NotFound { path: p }
        })?;
        let record: CredentialRecord =
            serde_json::from_slice(&bytes).map_err(|e| StoreError::Corrupt {
                path: path.clone(),
                message: e.to_string(),
            })?;
        if !record.schema_supported() {
            return Err(StoreError::Corrupt {
                path,
                message: format!(
                    "unsupported schema_version {} (expected {SCHEMA_VERSION})",
                    record.schema_version
                ),
            });
        }
        if record.linux_user != username {
            return Err(StoreError::RecordUserMismatch {
                record_user: record.linux_user,
                argument_user: username.to_string(),
            });
        }
        // Validate self-consistency invariants (e.g. `attestation.mode` is one of the
        // known values) here too, not only on write, so a hand-edited record cannot
        // load clean.
        if let Err(e) = record.validate() {
            return Err(StoreError::Corrupt {
                path,
                message: e.to_string(),
            });
        }
        // Defense in depth: the two binary fields PAM/verifier will decode must be valid
        // unpadded base64url, so a corrupt record fails closed at load rather than deep
        // inside the ceremony. Values are not otherwise constrained here.
        b64u_decode(&record.credential_id).map_err(|e| StoreError::Corrupt {
            path: path.clone(),
            message: format!("credential_id is not valid base64url: {e}"),
        })?;
        b64u_decode(&record.cose_public_key).map_err(|e| StoreError::Corrupt {
            path: path.clone(),
            message: format!("cose_public_key is not valid base64url: {e}"),
        })?;
        Ok((
            record,
            FileIdentity {
                dev: stat.dev,
                ino: stat.ino,
            },
        ))
    }

    /// Conditionally overwrite an existing credential record.
    ///
    /// Installs `record` only if the target still resolves (via `fstatat` relative to the
    /// held, identity-checked `credentials` directory, without following a final symlink)
    /// to `expected` — the identity [`Store::load_with_identity`] returned for that record.
    /// If the record was replaced (e.g. `enroll --replace` during an in-flight
    /// authentication) or removed (`unregister`), the write is refused as
    /// [`StoreError::RecordChanged`] instead of resurrecting a deleted credential or
    /// undoing a newer enrollment.
    ///
    /// The write itself follows [`Store::save_atomic`]'s atomic discipline
    /// (`mkstemp`→`0600`→`fsync`→`renameat`→`fsync(dir)`, temp removed on error), with
    /// both install names resolved relative to the held, identity-checked `credentials`
    /// descriptor, so a swapped directory cannot receive the record. The `(dev, ino)`
    /// compared immediately before the `renameat` is the identity captured at load time,
    /// so the guarded interval is the whole load→check span. The residual is the few
    /// instructions between the `fstatat` and the `renameat` within the *same* held
    /// directory, plus the theoretical reuse of `expected`'s inode number by an enrollment
    /// that completes inside the load→check window; closing that fully would need an
    /// inode-generation field or a held lock, and it is accepted because the store is
    /// root-owned `0700` and the only actors are root.
    pub fn update_if_unchanged(
        &self,
        record: &CredentialRecord,
        expected: FileIdentity,
    ) -> Result<(), StoreError> {
        validate_username(&record.linux_user)?;
        record.validate().map_err(|e| StoreError::Encode {
            message: e.to_string(),
        })?;
        self.check_base()?;
        // A conditional update to a store whose `credentials` directory has gone is a
        // changed/removed record, not a reason to recreate directories as a side effect
        // of an advisory write. (A missing *base* is reported as-is by `check_base` above.)
        let dir_fd = match self.open_checked_dir(&self.credentials_dir(), DIR_MODE) {
            Ok(fd) => fd,
            Err(StoreError::NotFound { .. }) => {
                return Err(StoreError::RecordChanged {
                    path: self.record_path(&record.linux_user),
                });
            }
            Err(e) => return Err(e),
        };

        let dir = self.credentials_dir();
        let target = self.record_path(&record.linux_user);
        let json = serde_json::to_vec(record).map_err(|e| StoreError::Encode {
            message: e.to_string(),
        })?;

        // Path-based temp create; see `save_atomic`: if the directory was swapped since the
        // descriptor check, the descriptor-relative install below fails `ENOENT`.
        let (fd, temp_path) = sys::mkstemp_in(&dir).map_err(|e| self.io(&dir, e))?;
        let temp = PathBuf::from(temp_path);
        let result = self.write_and_install(&Install {
            fd,
            temp: &temp,
            target: &target,
            contents: &json,
            replace: true,
            dir_fd: &dir_fd,
            mode: FILE_MODE,
            dir_path: &dir,
            expected_identity: Some(expected),
        });
        if result.is_err() {
            // Best-effort cleanup of the temp file on every failure path.
            let _ = sys::remove_file(&temp);
        }
        result
    }

    /// Validate that this store can accept a [`Store::save_atomic`] write, without
    /// writing a record.
    ///
    /// Runs the same write preconditions as `save_atomic`: `check_base` rejects a
    /// missing, symlinked, or insecure base, and `ensure_credentials_dir` creates
    /// `<base>/credentials` (`0700`) if absent or validates it otherwise. Surfacing them
    /// separately lets a caller fail *before* side effects that cannot be undone.
    ///
    /// A missing base stays [`StoreError::NotFound`]; it is deliberately not created here,
    /// because provisioning the base (including `config`) belongs to `install`, and a base
    /// created without a `config` would let `enroll` persist a record that PAM cannot use.
    pub fn preflight_write(&self) -> Result<(), StoreError> {
        self.check_base()?;
        let _dir_fd = self.ensure_credentials_dir()?;
        Ok(())
    }

    /// Atomically write a credential record (enrollment path).
    ///
    /// Fails with [`StoreError::AlreadyExists`] if a record exists and `replace` is
    /// `false`.
    pub fn save_atomic(&self, record: &CredentialRecord, replace: bool) -> Result<(), StoreError> {
        validate_username(&record.linux_user)?;
        // Refuse to persist a record that would not survive `load` (e.g. an unknown
        // `attestation.mode`), so the writer cannot create a record the reader rejects.
        record.validate().map_err(|e| StoreError::Encode {
            message: e.to_string(),
        })?;
        self.check_base()?;
        // Re-validate ownership/mode of the destination directory *before* creating a
        // temp file in it. The returned identity-checked handle then binds the install and
        // the final directory `fsync` to *that* directory; a directory swapped in at the
        // same path afterwards cannot receive the record (see `write_and_install`).
        let dir_fd = self.ensure_credentials_dir()?;

        let dir = self.credentials_dir();
        let target = self.record_path(&record.linux_user);

        if !replace {
            match sys::lstat(&target) {
                Ok(st) if st.is_symlink() => {
                    return Err(StoreError::SymlinkedPath { path: target });
                }
                Ok(_) => {
                    return Err(StoreError::AlreadyExists { path: target });
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(self.io(&target, e)),
            }
        }

        let json = serde_json::to_vec(record).map_err(|e| StoreError::Encode {
            message: e.to_string(),
        })?;

        // Deliberately path-based: there is no `*at` form of `mkstemp`. If the directory is
        // swapped between the descriptor check above and this create, the temp file lands
        // in the *replacement* directory while the held descriptor still names the original
        // one, so the descriptor-relative `renameat`/`linkat` below fails `ENOENT` and
        // nothing is installed — fail-closed rather than a write into a swapped directory.
        let (fd, temp_path) = sys::mkstemp_in(&dir).map_err(|e| self.io(&dir, e))?;
        let temp = PathBuf::from(temp_path);
        let result = self.write_and_install(&Install {
            fd,
            temp: &temp,
            target: &target,
            contents: &json,
            replace,
            dir_fd: &dir_fd,
            mode: FILE_MODE,
            dir_path: &dir,
            expected_identity: None,
        });
        if result.is_err() {
            // Best-effort cleanup of the temp file on every failure path.
            let _ = sys::remove_file(&temp);
        }
        result
    }

    fn write_and_install(&self, install: &Install<'_>) -> Result<(), StoreError> {
        sys::fchmod(install.fd.raw(), install.mode).map_err(|e| self.io(install.temp, e))?;
        sys::write_all(install.fd.raw(), install.contents).map_err(|e| self.io(install.temp, e))?;
        sys::fsync(install.fd.raw()).map_err(|e| self.io(install.temp, e))?;
        // Install both names relative to the held, identity-checked directory descriptor.
        // Resolving them against the descriptor (rather than re-walking the absolute paths)
        // means a directory swapped in at the same path cannot receive the install: the
        // temp name does not exist in the *held* directory, so the call fails `ENOENT`.
        let (Some(temp_name), Some(target_name)) =
            (install.temp.file_name(), install.target.file_name())
        else {
            return Err(self.io(
                install.target,
                io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"),
            ));
        };
        // `Install` holds the only owned `Fd`; dropping it closes the descriptor exactly
        // once.
        if install.replace {
            if let Some(expected) = install.expected_identity {
                self.ensure_record_unchanged(install, expected)?;
            }
            sys::renameat(install.dir_fd.raw(), temp_name, target_name)
                .map_err(|e| self.io(install.target, e))?;
        } else {
            match sys::linkat(install.dir_fd.raw(), temp_name, target_name) {
                Ok(()) => {
                    // Contract: once the link succeeds the install has succeeded. The temp
                    // name is only a second link to the same inode, so a failed unlink
                    // (`EACCES`/`EROFS`/`EIO`) must not turn a successful install into an
                    // error — otherwise callers would assume nothing was written. A
                    // leftover `.tmp-*` is harmless in the root-owned `0700` directory and
                    // is best-effort cleanup here, exactly like the failure paths in
                    // `save_atomic`/`update_if_unchanged`. Never unlink the target here.
                    let _ = sys::unlinkat(install.dir_fd.raw(), temp_name);
                }
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                    return Err(StoreError::AlreadyExists {
                        path: install.target.to_path_buf(),
                    });
                }
                Err(e) => return Err(self.io(install.temp, e)),
            }
        }

        // Persist the directory entry on every success path; the handle was
        // identity-checked before the temp file existed.
        sys::fsync(install.dir_fd.raw()).map_err(|e| self.io(install.dir_path, e))?;
        Ok(())
    }

    /// Refuse a conditional install when the target no longer resolves to `expected`.
    ///
    /// Runs immediately before the replacing `renameat`, `fstatat`ing the single-component
    /// name relative to the held, identity-checked `credentials` directory. A missing
    /// target or a different `(dev, ino)` is [`StoreError::RecordChanged`]; a symlink or
    /// non-regular file is refused as [`StoreError::SymlinkedPath`] /
    /// [`StoreError::NotRegularFile`] respectively. All three refuse the install, so the
    /// caller cannot resurrect a removed record or undo a newer enrollment.
    fn ensure_record_unchanged(
        &self,
        install: &Install<'_>,
        expected: FileIdentity,
    ) -> Result<(), StoreError> {
        let Some(file_name) = install.target.file_name() else {
            return Err(StoreError::RecordChanged {
                path: install.target.to_path_buf(),
            });
        };
        let st = match sys::fstatat_nofollow(install.dir_fd.raw(), file_name) {
            Ok(st) => st,
            // The record vanished (e.g. `unregister` won the race): never recreate it.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::RecordChanged {
                    path: install.target.to_path_buf(),
                });
            }
            Err(e) => return Err(self.io(install.target, e)),
        };
        if st.is_symlink() {
            return Err(StoreError::SymlinkedPath {
                path: install.target.to_path_buf(),
            });
        }
        if !st.is_file() {
            return Err(StoreError::NotRegularFile {
                path: install.target.to_path_buf(),
            });
        }
        if st.dev != expected.dev || st.ino != expected.ino {
            return Err(StoreError::RecordChanged {
                path: install.target.to_path_buf(),
            });
        }
        Ok(())
    }

    /// Remove the record for `username`, returning `false` if there was none.
    ///
    /// Refuses a symlinked `credentials` directory, a symlinked record, and an insecure
    /// base directory. The directory is opened `O_NOFOLLOW` and its `(dev, ino)` compared
    /// with the earlier `lstat`, so a directory swapped in mid-operation is
    /// [`StoreError::PathChanged`] instead of having the unlink redirected into it.
    /// Unlike [`Store::load`], the record's own ownership/mode are not re-checked, so an
    /// administrator can clean up a mis-owned record.
    pub fn remove(&self, username: &str) -> Result<bool, StoreError> {
        validate_username(username)?;
        match self.check_base() {
            Ok(_) => {}
            // A missing base means no `credentials` dir either: nothing to remove.
            Err(StoreError::NotFound { .. }) => return Ok(false),
            Err(e) => return Err(e),
        }
        let dir = self.credentials_dir();
        let before = match sys::lstat(&dir) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(self.io(&dir, e)),
            Ok(st) => st,
        };
        if before.is_symlink() {
            return Err(StoreError::SymlinkedPath { path: dir });
        }
        if !before.is_dir() {
            return Err(StoreError::NotRegularFile { path: dir });
        }

        // Hold the directory open and unlink relative to it, so the symlink check and the
        // unlink refer to the same directory even under a concurrent swap. Re-check the
        // opened descriptor's identity against the `lstat` above (mirroring
        // `open_checked_dir`), so a directory swapped between the two is refused instead
        // of having the unlink redirected into it.
        let dfd = sys::open_dir(&dir).map_err(|e| self.io(&dir, e))?;
        let after = sys::fstat(dfd.raw()).map_err(|e| self.io(&dir, e))?;
        if after.dev != before.dev || after.ino != before.ino {
            return Err(StoreError::PathChanged { path: dir });
        }
        let target = self.record_path(username);
        // `record_path` always ends in `<username>.json`; refuse rather than panic if that
        // ever stops holding (this is a library, so an invariant violation must not abort
        // the caller's process).
        let Some(name) = target.file_name() else {
            return Err(StoreError::InvalidUsername);
        };
        match sys::fstatat_nofollow(dfd.raw(), name) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(self.io(&target, e)),
            Ok(st) => {
                if st.is_symlink() {
                    return Err(StoreError::SymlinkedPath { path: target });
                }
                if !st.is_file() {
                    return Err(StoreError::NotRegularFile { path: target });
                }
                sys::unlinkat(dfd.raw(), name).map_err(|e| self.io(&target, e))?;
                Ok(true)
            }
        }
    }

    /// List enrolled usernames (sorted, deduplicated) from `<base>/credentials/*.json`.
    ///
    /// A missing base or `credentials` directory yields an empty list. An insecure base
    /// is refused as [`StoreError::InsecureBase`]. Non-regular files, symlinks, and
    /// names that fail [`validate_username`] are skipped.
    ///
    /// # Residual: the directory is re-resolved by path
    ///
    /// Unlike [`Store::load`] and the write path, this is the one operation that is not
    /// descriptor-bound: `lstat` checks the `credentials` directory, but the subsequent
    /// listing goes through `std::fs::read_dir(&dir)`, which re-resolves the path (the
    /// standard library exposes no `fdopendir`/`readdir` over a held descriptor). A
    /// directory swapped between the check and the listing is therefore not detected by a
    /// `(dev, ino)` recheck, and [`Store::check_base`] is the only guard. That is accepted
    /// because `list` is read-only and advisory (an operator-facing inventory, never an
    /// authentication decision), it returns only filtered names, and a hostile swap
    /// requires write access to the root-owned base directory — the very condition
    /// `check_base` refuses. Closing it properly needs a `readdir` wrapper in the audited
    /// syscall module.
    pub fn list(&self) -> Result<Vec<String>, StoreError> {
        match self.check_base() {
            Ok(_) => {}
            // A missing base means no `credentials` dir either: an empty list.
            Err(StoreError::NotFound { .. }) => return Ok(Vec::new()),
            Err(e) => return Err(e),
        }
        let dir = self.credentials_dir();
        match sys::lstat(&dir) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(self.io(&dir, e)),
            Ok(st) => {
                if st.is_symlink() {
                    return Err(StoreError::SymlinkedPath { path: dir });
                }
                if !st.is_dir() {
                    return Err(StoreError::NotRegularFile { path: dir });
                }
            }
        }

        let mut names = Vec::new();
        let entries = std::fs::read_dir(&dir).map_err(|e| self.io(&dir, e))?;
        for entry in entries {
            let entry = entry.map_err(|e| self.io(&dir, e))?;
            let file_type = entry.file_type().map_err(|e| self.io(&dir, e))?;
            if !file_type.is_file() {
                continue;
            }
            let file_name = entry.file_name();
            let Some(file_name) = file_name.to_str() else {
                continue;
            };
            let Some(stem) = file_name.strip_suffix(".json") else {
                continue;
            };
            if validate_username(stem).is_ok() {
                names.push(stem.to_string());
            }
        }
        names.sort();
        names.dedup();
        Ok(names)
    }

    /// Load and parse `<base>/config` (TOML, mode `0600`, root-owned).
    ///
    /// A missing file is [`StoreError::ConfigMissing`].
    pub fn load_config(&self) -> Result<Config, StoreError> {
        let path = self.config_path();
        let (bytes, _identity) =
            self.read_secure_file(&path, CONFIG_MODE, MAX_CONFIG_BYTES, |p| {
                StoreError::ConfigMissing { path: p }
            })?;
        let raw: record::RawConfig =
            toml::from_str(std::str::from_utf8(&bytes).map_err(|e| StoreError::Config {
                path: path.clone(),
                message: format!("config is not valid UTF-8: {e}"),
            })?)
            .map_err(|e| StoreError::Config {
                path: path.clone(),
                message: e.to_string(),
            })?;
        Ok(raw.into())
    }

    /// Atomically write `<base>/config` (TOML, mode `0600`, owned by the store's
    /// expected owner).
    ///
    /// The store owns both sides of the on-disk format: serialization goes through
    /// [`Config::to_toml`] and parsing through the same `deny_unknown_fields` schema, so
    /// the write and read schemas cannot drift. The base directory is created (`0755`)
    /// if missing.
    pub fn save_config(&self, config: &Config) -> Result<(), StoreError> {
        let path = self.config_path();
        // Ensure the base exists, then validate it. A fresh base is created `0755`
        // (umask-corrected) and re-validated.
        let before = match self.check_base() {
            Ok(st) => st,
            Err(StoreError::NotFound { .. }) => {
                sys::mkdir(&self.base, BASE_MODE).map_err(|e| self.io(&self.base, e))?;
                let fd = sys::open_dir(&self.base).map_err(|e| self.io(&self.base, e))?;
                sys::fchmod(fd.raw(), BASE_MODE).map_err(|e| self.io(&self.base, e))?;
                drop(fd);
                self.check_base()?
            }
            Err(e) => return Err(e),
        };
        // Hold an identity-checked base descriptor for the descriptor-relative install and
        // the final fsync. The base has no exact-mode requirement, so this mirrors
        // `open_checked_dir` without imposing one.
        let base_fd = sys::open_dir(&self.base).map_err(|e| self.io(&self.base, e))?;
        let after = sys::fstat(base_fd.raw()).map_err(|e| self.io(&self.base, e))?;
        if after.uid != self.owner_uid || after.perm_bits() & 0o022 != 0 {
            return Err(StoreError::InsecureBase {
                path: self.base.clone(),
                expected_uid: self.owner_uid,
                actual_uid: after.uid,
                actual_mode: after.perm_bits(),
            });
        }
        if after.dev != before.dev || after.ino != before.ino {
            return Err(StoreError::PathChanged {
                path: self.base.clone(),
            });
        }

        let toml_bytes = config.to_toml().into_bytes();
        // Path-based temp create; see `save_atomic`: a directory swapped since the
        // descriptor check makes the descriptor-relative install fail `ENOENT`.
        let (fd, temp_path) = sys::mkstemp_in(&self.base).map_err(|e| self.io(&self.base, e))?;
        let temp = PathBuf::from(temp_path);
        let result = self.write_and_install(&Install {
            fd,
            temp: &temp,
            target: &path,
            contents: &toml_bytes,
            replace: true,
            dir_fd: &base_fd,
            mode: CONFIG_MODE,
            dir_path: &self.base,
            expected_identity: None,
        });
        if result.is_err() {
            let _ = sys::remove_file(&temp);
        }
        result
    }
}

/// Validate a Linux username against `^[A-Za-z_][A-Za-z0-9._-]{0,31}$`.
///
/// Implemented by hand (no `regex` dependency); rejects the empty string, names longer
/// than 32 bytes, path separators, leading digits/dots/dashes, and NUL bytes.
pub fn validate_username(username: &str) -> Result<(), StoreError> {
    let bytes = username.as_bytes();
    if bytes.is_empty() || bytes.len() > 32 {
        return Err(StoreError::InvalidUsername);
    }
    let first = bytes[0];
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return Err(StoreError::InvalidUsername);
    }
    for &b in &bytes[1..] {
        if !(b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-') {
            return Err(StoreError::InvalidUsername);
        }
    }
    Ok(())
}

/// The effective uid of the calling process, for callers that need to build a non-root
/// [`Store`].
pub fn current_euid() -> u32 {
    sys::geteuid()
}

/// The real uid of the calling process.
pub fn current_uid() -> u32 {
    sys::getuid()
}

#[cfg(test)]
mod tests {
    //! Unit tests that need a private seam.
    //!
    //! The bulk of the store's tests are integration tests in `tests/store.rs`; these few
    //! exist only because they must drive an internal step that the public API cannot reach
    //! deterministically (a stale directory descriptor).

    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A `credentials` directory swapped after its descriptor was identity-checked must
    /// make the descriptor-relative install fail closed, and must never place a record in
    /// the replacement directory (nor in the directory that was swapped away).
    ///
    /// This exercises the install step directly: `save_atomic` cannot be used, because a
    /// single-threaded test cannot reliably time a swap between its `lstat` and its
    /// `open`, and a whole-base swap is not the window being tested. Holding a genuine
    /// descriptor for the *old* directory and installing relative to it is the
    /// deterministic equivalent, modelled on the CLI's
    /// `atomic_write_rejects_swapped_parent_dir`.
    #[test]
    fn install_rejects_swapped_credentials_dir() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = Store::with_owner(tmp.path(), sys::geteuid());

        // Create and identity-check the real `credentials` directory, as `save_atomic` does.
        let dir_fd = store.ensure_credentials_dir().expect("checked dir");
        let dir = store.credentials_dir();

        // Swap it: rename the checked directory away (renaming rather than removing keeps
        // its inode alive, so the replacement cannot be handed the same `(dev, ino)`), then
        // recreate the same path as a fresh directory. This is the attacker's move between
        // the directory check and the install.
        let original = tmp.path().join("original-credentials");
        std::fs::rename(&dir, &original).expect("swap away");
        std::fs::create_dir(&dir).expect("replacement");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        let target = store.record_path("alice");

        // `replace == false` (the `linkat` branch): the temp name does not exist in the held
        // directory, so the install must fail and install nothing anywhere.
        let (fd, temp_path) = sys::mkstemp_in(&dir).expect("temp in replacement dir");
        let temp = PathBuf::from(temp_path);
        let err = store
            .write_and_install(&Install {
                fd,
                temp: &temp,
                target: &target,
                contents: b"{}",
                replace: false,
                dir_fd: &dir_fd,
                mode: FILE_MODE,
                dir_path: &dir,
                expected_identity: None,
            })
            .expect_err("install through a stale descriptor must fail");
        match &err {
            StoreError::Io { source, .. } => {
                assert_eq!(
                    source.raw_os_error(),
                    Some(libc::ENOENT),
                    "the temp name does not exist in the held directory: {source}"
                );
            }
            other => panic!("expected an i/o error from the stale install, got {other:?}"),
        }
        assert!(
            !target.exists(),
            "no record may appear in the replacement directory"
        );
        assert!(
            !original.join("alice.json").exists(),
            "no record may appear in the swapped-away directory"
        );
        let _ = sys::remove_file(&temp);

        // `replace == true` (the `renameat` branch) must fail the same way.
        let (fd, temp_path) = sys::mkstemp_in(&dir).expect("temp in replacement dir");
        let temp = PathBuf::from(temp_path);
        let err = store
            .write_and_install(&Install {
                fd,
                temp: &temp,
                target: &target,
                contents: b"{}",
                replace: true,
                dir_fd: &dir_fd,
                mode: FILE_MODE,
                dir_path: &dir,
                expected_identity: None,
            })
            .expect_err("replacing install through a stale descriptor must fail");
        match &err {
            StoreError::Io { source, .. } => assert_eq!(
                source.raw_os_error(),
                Some(libc::ENOENT),
                "the temp name does not exist in the held directory: {source}"
            ),
            other => panic!("expected an i/o error from the stale install, got {other:?}"),
        }
        assert!(!target.exists());
        let _ = sys::remove_file(&temp);

        // Control: a descriptor opened on the *replacement* directory accepts the same
        // install, pinning the failure above on the stale identity rather than on anything
        // else (the temp create is path-based and would otherwise mask the real check).
        let fresh_fd = store
            .ensure_credentials_dir()
            .expect("replacement is valid");
        let (fd, temp_path) = sys::mkstemp_in(&dir).expect("temp");
        let temp = PathBuf::from(temp_path);
        store
            .write_and_install(&Install {
                fd,
                temp: &temp,
                target: &target,
                contents: b"{}",
                replace: false,
                dir_fd: &fresh_fd,
                mode: FILE_MODE,
                dir_path: &dir,
                expected_identity: None,
            })
            .expect("install through a current descriptor succeeds");
        assert!(target.exists(), "the control install must write the record");
    }
}
