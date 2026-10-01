//! Assertion verification (WebAuthn §7.2).
//!
//! Steps:
//!
//! 1. `clientDataJSON` must be a `webauthn.get` for our challenge and origin.
//! 2. `authenticatorData`: `rpIdHash == SHA-256(RP_ID)`, `UP=1`, `UV=1`.
//! 3. The enrolled credential id must be present in the authenticator data. (Windows
//!    Hello platform assertions may omit the attested-credential-data block, so a
//!    plain `authData` without the AT flag is accepted provided the caller-supplied
//!    credential id is what was enrolled; see the module note below.)
//! 4. The signature over `authenticatorData || SHA-256(clientDataJSON)` must verify
//!    under the enrolled COSE key.
//! 5. The observed `signCount` is returned for persistence. Per the spec's counter
//!    policy a `0` counter is *accepted* (Windows Hello is a zero-counter
//!    authenticator); we never reject on the counter value.
//!
//! ## Note on credential id and Windows Hello
//!
//! Plan §4 lists "credentialId match" as an assertion invariant. The bridge always
//! echoes the credential id it used, and the PAM path passes the *enrolled* id here;
//! the id is therefore already pinned by the store lookup. This function additionally
//! accepts an assertion whose `authData` carries attested credential data only when
//! the embedded id equals `credential_id`.

use sha2::{Digest as _, Sha256};

use crate::AssertionOutcome;
use crate::authdata::{self, parse_and_validate_prefix};
use crate::clientdata;
use crate::cose;
use crate::error::VerifyError;
use wsl_webauthn_protocol::ClientDataKind;

/// Verify an assertion. See the module documentation for the exact checks.
pub(crate) fn verify(
    expected_challenge: &[u8],
    credential_id: &[u8],
    cose_public_key: &[u8],
    client_data_json: &[u8],
    authenticator_data: &[u8],
    signature: &[u8],
) -> Result<AssertionOutcome, VerifyError> {
    if credential_id.is_empty() {
        return Err(VerifyError::EmptyCredentialId);
    }

    // 1. clientDataJSON for `webauthn.get`.
    clientdata::validate(client_data_json, ClientDataKind::Get, expected_challenge)?;

    // 2. authData prefix + rpIdHash + UP + UV.
    let prefix = parse_and_validate_prefix(authenticator_data)?;

    // 3. If attested credential data is present, its credential id must be the
    //    enrolled one. Assertions from platform authenticators omit AT, in which
    //    case the enrolled id (already checked by the caller) is authoritative.
    if prefix.has_attested_credential_data() {
        let attested = authdata::parse_attested_credential_data(authenticator_data)?;
        if attested.credential_id != credential_id {
            return Err(VerifyError::CredentialIdMismatch);
        }
    }

    // 4. Parse the enrolled key and verify the signature.
    let key = cose::parse(cose_public_key)?;
    let mut signed = Vec::with_capacity(authenticator_data.len() + 32);
    signed.extend_from_slice(authenticator_data);
    signed.extend_from_slice(&Sha256::digest(client_data_json));
    key.verify(&signed, signature)?;

    // 5. Return the observed counter for the store to persist.
    Ok(AssertionOutcome {
        sign_count: prefix.sign_count,
    })
}
