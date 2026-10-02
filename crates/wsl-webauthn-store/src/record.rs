//! On-disk credential/config data types (plan §6).
//!
//! These are plain serde types with no filesystem logic; [`crate::Store`] owns the
//! hardening. The JSON schema is documented on the crate root.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current on-disk record schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// `attestation.mode` value: attestation was verified under the strict policy (D3).
pub const MODE_STRICT: &str = "strict";

/// `attestation.mode` value: a self/`none`-attested key admitted by explicit opt-in.
pub const MODE_UNATTESTED_OPT_IN: &str = "unattested-opt-in";

/// Returns `true` if `mode` is one of the known [`MODE_STRICT`]/[`MODE_UNATTESTED_OPT_IN`]
/// `attestation.mode` values.
///
/// This is the single allow-list used both while serializing a record and while loading
/// one, so a hand-edited `"mode"` value cannot be persisted or read back as valid.
pub(crate) fn valid_attestation_mode(mode: &str) -> bool {
    mode == MODE_STRICT || mode == MODE_UNATTESTED_OPT_IN
}

/// A `CredentialRecord` that violates the on-disk invariant documented at
/// [`crate::CredentialRecord::validate`].
#[derive(Debug, Error)]
pub enum InvalidRecord {
    /// `attestation.mode` was not [`MODE_STRICT`] or [`MODE_UNATTESTED_OPT_IN`].
    #[error(
        "unknown attestation mode {0:?} (expected {MODE_STRICT:?} or {MODE_UNATTESTED_OPT_IN:?})"
    )]
    AttestationMode(String),
    /// `attestation.verified` was `false` while `attestation.mode` claimed [`MODE_STRICT`].
    #[error("attestation.mode {MODE_STRICT:?} requires verified = true")]
    StrictNotVerified,
}

/// A single Linux user's enrolled credential (one record per user, plan D8).
///
/// Serialized to `<base>/credentials/<linux_user>.json` (mode `0600`, root-owned).
/// See the crate docs for the exact JSON schema and an example.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRecord {
    /// On-disk schema version; currently [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Pinned Relying Party ID (compile-time constant, plan D2).
    pub rp_id: String,
    /// Pinned WebAuthn origin (equal to `rp_id`, plan D2).
    pub origin: String,
    /// The Linux login name this credential authenticates.
    pub linux_user: String,
    /// The Linux uid captured at enrollment (informational; not used for authorization).
    pub linux_uid: u32,
    /// Credential ID, unpadded `base64url`.
    pub credential_id: String,
    /// COSE public key bytes, unpadded `base64url`.
    pub cose_public_key: String,
    /// COSE algorithm identifier (`-7` ES256, `-257` RS256, `-8` EdDSA).
    pub alg: i32,
    /// Authenticator AAGUID as the canonical lowercase hyphenated UUID string.
    pub aaguid: String,
    /// Attestation details captured at enrollment.
    pub attestation: AttestationRecord,
    /// The enrolling Windows account, when it could be determined (plan D8).
    pub windows_identity: Option<WindowsIdentity>,
    /// Enrollment time, RFC 3339 in UTC.
    pub enrolled_at: String,
    /// Signature counter captured at enrollment (assertions update the caller's view).
    pub sign_count: u32,
    /// Absolute path of the pinned bridge executable at enrollment (plan D11).
    pub bridge_path: String,
    /// Lowercase hex SHA-256 of the bridge executable at enrollment (plan D11).
    pub bridge_sha256: String,
}

impl CredentialRecord {
    /// Returns `true` if the record's claimed schema version is supported.
    pub fn schema_supported(&self) -> bool {
        self.schema_version == SCHEMA_VERSION
    }

    /// Validate the invariants the store documents for a record but that serde alone
    /// cannot express.
    ///
    /// This is called from [`crate::Store::load`] and [`crate::Store::save_atomic`], so
    /// an invalid record is rejected both when read from disk and before it is written.
    /// Today that means `attestation.mode` must be [`MODE_STRICT`] or
    /// [`MODE_UNATTESTED_OPT_IN`], and a strict record must be `verified`.
    pub fn validate(&self) -> Result<(), InvalidRecord> {
        if !valid_attestation_mode(&self.attestation.mode) {
            return Err(InvalidRecord::AttestationMode(
                self.attestation.mode.clone(),
            ));
        }
        if self.attestation.mode == MODE_STRICT && !self.attestation.verified {
            return Err(InvalidRecord::StrictNotVerified);
        }
        Ok(())
    }
}

/// Attestation facts recorded for a credential (plan §6, D3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationRecord {
    /// Attestation statement format, e.g. `packed` or `none`.
    pub format: String,
    /// Either [`MODE_STRICT`] or [`MODE_UNATTESTED_OPT_IN`].
    pub mode: String,
    /// Whether the attestation chain was cryptographically verified to the pinned root.
    pub verified: bool,
    /// Lowercase hex SHA-256 of the leaf certificate, when one was present.
    pub leaf_sha256: Option<String>,
}

/// The Windows account bound to a credential for audit purposes (plan D8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsIdentity {
    /// Account name in `HOST\user` form.
    pub account: String,
    /// Windows security identifier, e.g. `S-1-5-21-…`.
    pub sid: String,
}

/// Parsed `<base>/config` (plan §6, §10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Path to the pinned bridge executable.
    pub bridge_path: PathBuf,
    /// Windows mount root used as the bridge's working directory (e.g. `/mnt/c`).
    pub win_mnt: PathBuf,
    /// Optional auth deadline override in seconds; `None` means use the protocol default.
    pub timeout_secs: Option<u64>,
}

impl Config {
    /// Default Windows mount root when the config file omits `win_mnt`.
    pub const DEFAULT_WIN_MNT: &'static str = "/mnt/c";
}

/// Default serialization of [`Config`]'s TOML shape.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawConfig {
    pub bridge_path: PathBuf,
    #[serde(default = "default_win_mnt")]
    pub win_mnt: PathBuf,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

fn default_win_mnt() -> PathBuf {
    PathBuf::from(Config::DEFAULT_WIN_MNT)
}

impl From<RawConfig> for Config {
    fn from(raw: RawConfig) -> Self {
        Self {
            bridge_path: raw.bridge_path,
            win_mnt: raw.win_mnt,
            timeout_secs: raw.timeout_secs,
        }
    }
}
