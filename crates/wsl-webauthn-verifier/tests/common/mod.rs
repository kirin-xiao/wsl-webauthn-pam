//! Shared synthetic-vector machinery for the verifier test suite.
//!
//! Everything here is generated in-process: no real-machine material and no
//! vendor binaries.

#![allow(dead_code)]
#![allow(unused_imports)]

use std::str::FromStr;
use std::time::{Duration, SystemTime};

use ciborium::value::Value;
use der::Encode;
use der::asn1::BitString;
use der::asn1::OctetString;
use p256::ecdsa::SigningKey as P256SigningKey;
use p256::elliptic_curve::sec1::ToSec1Point as _;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use sha2::{Digest as _, Sha256};
use x509_cert::Certificate;
use x509_cert::certificate::Version;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::Validity;

use wsl_webauthn_protocol::{ClientDataKind, RP_ID, b64u_encode, build_client_data};

/// The first strict allow-listed AAGUID (Windows Hello software TPM).
pub const AAGUID_ALLOWED: [u8; 16] = [
    0x08, 0x98, 0x70, 0x58, 0xCA, 0xDC, 0x4B, 0x81, 0xB6, 0xE1, 0x30, 0xDE, 0x50, 0xDC, 0xBE, 0x96,
];

/// A well-formed AAGUID that is deliberately *not* on the strict allow-list.
pub const AAGUID_DISALLOWED: [u8; 16] = [0xAA; 16];

/// OID `id-fido-gen-ce-aaguid`.
pub const ID_FIDO_GEN_CE_AAGUID: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.45724.1.1.4");

/// OID `tcg-kp-AIKCertificate` (2.23.133.8.3).
pub const OID_TCG_KP_AIK_CERTIFICATE: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.23.133.8.3");

/// The single wall-clock instant every synthesized fixture is pinned to
/// (2020-09-13T12:26:40Z). Fixture validity windows and `EnrollCheck::now` are
/// both derived from it, so no test depends on the verifier re-reading the real
/// clock independently of the fixture. It sits well inside the default ±1 h
/// validity windows and inside the committed independent vector's 2020..2049
/// certificate window.
pub const FIXTURE_NOW_SECS: u64 = 1_600_000_000;

/// [`FIXTURE_NOW_SECS`] as a [`SystemTime`].
pub fn fixture_now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(FIXTURE_NOW_SECS)
}

/// A default certificate validity window around [`fixture_now`].
pub fn fixture_validity() -> Validity {
    validity_from(
        fixture_now() - Duration::from_secs(3600),
        fixture_now() + Duration::from_secs(3600),
    )
}

// ---------------------------------------------------------------------------
// Authenticator-data / client-data / attestation-object builders
// ---------------------------------------------------------------------------

/// Extra attested-credential-data to embed in an `authData`.
pub struct AttestedData {
    pub aaguid: [u8; 16],
    pub credential_id: Vec<u8>,
    pub cose_public_key: Vec<u8>,
}

/// Build authenticator data.
///
/// When `attested` is `Some`, the AT flag is OR-ed in and the attested credential
/// data is appended.
pub fn build_auth_data(
    rp_id: &str,
    mut flags: u8,
    sign_count: u32,
    attested: Option<&AttestedData>,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    if attested.is_some() {
        flags |= 0x40; // AT
    }
    out.push(flags);
    out.extend_from_slice(&sign_count.to_be_bytes());
    if let Some(a) = attested {
        out.extend_from_slice(&a.aaguid);
        out.extend_from_slice(&(a.credential_id.len() as u16).to_be_bytes());
        out.extend_from_slice(&a.credential_id);
        out.extend_from_slice(&a.cose_public_key);
    }
    out
}

/// Build `clientDataJSON` via the protocol crate.
pub fn client_data(kind: ClientDataKind, challenge: &[u8]) -> Vec<u8> {
    build_client_data(kind, challenge).expect("challenge is long enough")
}

/// Build a CBOR attestation object from a raw `attStmt` map.
pub fn attestation_object(fmt: &str, auth_data: &[u8], att_stmt: Vec<(Value, Value)>) -> Vec<u8> {
    let map = vec![
        (Value::from("fmt"), Value::from(fmt)),
        (Value::from("attStmt"), Value::Map(att_stmt)),
        (Value::from("authData"), Value::Bytes(auth_data.to_vec())),
    ];
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(map), &mut out).expect("CBOR encode");
    out
}

/// The signed message for an assertion or attestation:
/// `authenticatorData || SHA-256(clientDataJSON)`.
pub fn signed_message(auth_data: &[u8], client_data_json: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(auth_data.len() + 32);
    out.extend_from_slice(auth_data);
    out.extend_from_slice(&Sha256::digest(client_data_json));
    out
}

// ---------------------------------------------------------------------------
// COSE keys and signing keys
// ---------------------------------------------------------------------------

/// A generated key pair plus its COSE_Key encoding.
pub struct TestKey {
    /// COSE_Key CBOR bytes for the public key.
    pub cose: Vec<u8>,
    /// COSE algorithm identifier.
    pub alg: i64,
    /// Signing backend.
    pub signer: Signer,
}

/// A concrete signer.
pub enum Signer {
    Es256(P256SigningKey),
    Rs256(Box<rsa::pkcs1v15::SigningKey<Sha256>>),
    Ed25519(Box<ed25519_dalek::SigningKey>),
}

impl Signer {
    /// Produce a signature over `message` in the algorithm's wire encoding
    /// (ES256 → DER, RS256 → raw PKCS#1 v1.5, EdDSA → raw 64 bytes).
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        use rsa::signature::{SignatureEncoding as _, Signer as _};
        match self {
            Signer::Es256(sk) => {
                use p256::ecdsa::signature::Signer as _;
                let sig: p256::ecdsa::DerSignature = sk.sign(message);
                sig.as_bytes().to_vec()
            }
            Signer::Rs256(sk) => sk.sign(message).to_vec(),
            Signer::Ed25519(sk) => {
                use ed25519_dalek::Signer as _;
                sk.sign(message).to_bytes().to_vec()
            }
        }
    }

    /// The corresponding certificate subject public key.
    pub fn spki(&self) -> SubjectPublicKeyInfoOwned {
        use rsa::signature::Keypair as _;
        match self {
            Signer::Es256(sk) => {
                SubjectPublicKeyInfoOwned::from_key(sk.verifying_key()).expect("spki")
            }
            Signer::Rs256(sk) => {
                SubjectPublicKeyInfoOwned::from_key(&sk.verifying_key()).expect("spki")
            }
            Signer::Ed25519(sk) => {
                // `ed25519-dalek` only implements `EncodePublicKey` with its `alloc`
                // feature enabled, which this dev-dependency does not turn on. The
                // Ed25519 SPKI is trivial: OID 1.3.101.112 with absent parameters and
                // the raw 32-byte key as the BIT STRING.
                SubjectPublicKeyInfoOwned {
                    algorithm: AlgorithmIdentifierOwned {
                        oid: ED25519,
                        parameters: None,
                    },
                    subject_public_key: BitString::from_bytes(sk.verifying_key().as_bytes())
                        .expect("ed25519 public key"),
                }
            }
        }
    }
}

fn cose_es256(sk: &P256SigningKey) -> Vec<u8> {
    let point = sk.verifying_key().to_sec1_point(false);
    let map = vec![
        (Value::from(1i64), Value::from(2i64)),
        (Value::from(3i64), Value::from(-7i64)),
        (Value::from(-1i64), Value::from(1i64)),
        (
            Value::from(-2i64),
            Value::Bytes(point.x().expect("x").to_vec()),
        ),
        (
            Value::from(-3i64),
            Value::Bytes(point.y().expect("y").to_vec()),
        ),
    ];
    cbor(map)
}

fn cose_rs256(key: &rsa::PublicKey) -> Vec<u8> {
    use p256::elliptic_curve::bigint::Encoding as _;
    use rsa::traits::PublicKeyParts as _;
    let n = key.n().to_be_bytes();
    let e = key.e().to_be_bytes();
    let map = vec![
        (Value::from(1i64), Value::from(3i64)),
        (Value::from(3i64), Value::from(-257i64)),
        (
            Value::from(-1i64),
            Value::Bytes(minimal_be_bytes(&n).to_vec()),
        ),
        (
            Value::from(-2i64),
            Value::Bytes(minimal_be_bytes(&e).to_vec()),
        ),
    ];
    cbor(map)
}

/// Strip the fixed-width leading zero bytes from a big-endian `BoxedUint` encoding.
///
/// `crypto-bigint`'s `Encoding::to_be_bytes` returns the integer at its declared
/// precision (for the RSA exponent that is four bytes, `00 01 00 01`), while both
/// COSE and the verifier require the minimal big-endian form (`01 00 01`).
fn minimal_be_bytes(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&b| b != 0) {
        Some(start) => &bytes[start..],
        None => &bytes[bytes.len().saturating_sub(1)..],
    }
}

fn cose_ed25519(key: &ed25519_dalek::VerifyingKey) -> Vec<u8> {
    let map = vec![
        (Value::from(1i64), Value::from(1i64)),
        (Value::from(3i64), Value::from(-8i64)),
        (Value::from(-1i64), Value::from(6i64)),
        (Value::from(-2i64), Value::Bytes(key.to_bytes().to_vec())),
    ];
    cbor(map)
}

fn cbor(map: Vec<(Value, Value)>) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(map), &mut out).expect("CBOR encode");
    out
}

/// Generate an ES256 (P-256) key.
pub fn es256() -> TestKey {
    use p256::elliptic_curve::Generate as _;
    let sk = P256SigningKey::generate_from_rng(&mut UnwrapErr(SysRng));
    let cose = cose_es256(&sk);
    TestKey {
        cose,
        alg: -7,
        signer: Signer::Es256(sk),
    }
}

/// Generate an RS256 (RSA-2048) key.
pub fn rs256() -> TestKey {
    let key = rsa::PrivateKey::new(&mut UnwrapErr(SysRng), 2048).expect("rsa keygen");
    let cose = cose_rs256(&key.to_public_key());
    TestKey {
        cose,
        alg: -257,
        signer: Signer::Rs256(Box::new(rsa::pkcs1v15::SigningKey::<Sha256>::new(key))),
    }
}

/// Generate an EdDSA (Ed25519) key.
pub fn ed25519() -> TestKey {
    let sk = ed25519_dalek::SigningKey::generate(&mut UnwrapErr(SysRng));
    let cose = cose_ed25519(&sk.verifying_key());
    TestKey {
        cose,
        alg: -8,
        signer: Signer::Ed25519(Box::new(sk)),
    }
}

// ---------------------------------------------------------------------------
// Packed attestation statements
// ---------------------------------------------------------------------------

/// Assemble a `packed` `attStmt` map.
pub fn packed_att_stmt(alg: i64, sig: &[u8], x5c: Option<&[Vec<u8>]>) -> Vec<(Value, Value)> {
    let mut map = vec![
        (Value::from("alg"), Value::from(alg)),
        (Value::from("sig"), Value::Bytes(sig.to_vec())),
    ];
    if let Some(chain) = x5c {
        map.push((
            Value::from("x5c"),
            Value::Array(chain.iter().map(|der| Value::Bytes(der.clone())).collect()),
        ));
    }
    map
}

// ---------------------------------------------------------------------------
// X.509 test chain
// ---------------------------------------------------------------------------

/// `ecdsa-with-SHA256` (1.2.840.10045.4.3.2), the signature algorithm every
/// synthesized chain link uses.
const ECDSA_WITH_SHA256: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// `Ed25519` (1.3.101.112).
const ED25519: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("1.3.101.112");

/// A locally mutable `TBSCertificate`.
///
/// `x509-cert 0.3` made `TbsCertificateInner`'s fields private (read-only accessors,
/// no `*_mut`) and replaced `builder::Profile` with the `BuilderProfile` trait, so the
/// old "build, then mutate and re-sign" harness cannot survive. Instead the harness
/// encodes the structure itself. The field types and `#[asn1(...)]` tag attributes are
/// copied verbatim from `x509-cert 0.3`'s `TbsCertificateInner`: the verifier parses
/// this output with the same crate, and [`assert_cert_roundtrip`] pins the two
/// encodings together.
#[derive(Clone, Debug, der::Sequence)]
struct TestTbs {
    #[asn1(context_specific = "0", default = "Default::default")]
    version: Version,
    serial_number: SerialNumber,
    signature: AlgorithmIdentifierOwned,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfoOwned,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    issuer_unique_id: Option<BitString>,

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    subject_unique_id: Option<BitString>,

    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    extensions: Option<Vec<Extension>>,
}

/// The outer `Certificate` over [`TestTbs`].
#[derive(Clone, Debug, der::Sequence)]
struct TestCert {
    tbs: TestTbs,
    signature_algorithm: AlgorithmIdentifierOwned,
    signature: BitString,
}

/// The certificate shape the synthesized chain needs.
///
/// This is the `x509-cert 0.2` `builder::Profile` enum, retained locally now that the
/// crate no longer ships it (0.3's `Profile` is a deprecated alias for the
/// `BuilderProfile` trait, and the CABF profile types do not fit synthetic FIDO
/// attestation certificates).
#[derive(Clone)]
pub enum Profile {
    /// A self-signed root CA.
    Root,
    /// An intermediate CA.
    SubCA {
        /// The issuer name.
        issuer: Name,
        /// `pathLenConstraint` to encode, if any.
        path_len_constraint: Option<u8>,
    },
    /// An end-entity certificate.
    Leaf {
        /// The issuer name.
        issuer: Name,
        /// Set the `keyAgreement` KeyUsage bit.
        enable_key_agreement: bool,
        /// Set the `keyEncipherment` KeyUsage bit.
        enable_key_encipherment: bool,
    },
}

/// Options controlling the synthesized chain shape.
#[derive(Clone)]
pub struct ChainOptions {
    /// The AAGUID placed in `authData`.
    pub aaguid: [u8; 16],
    /// The AAGUID placed in the leaf's extension; defaults to `aaguid`.
    pub cert_aaguid: Option<[u8; 16]>,
    pub leaf_ou: String,
    pub leaf_is_ca: bool,
    pub intermediate_is_ca: bool,
    /// Insert a fourth CA level between the root and the leaf-signing intermediate,
    /// so an `extra_intermediate_path_len` constraint can be genuinely exceeded.
    pub extra_intermediate: bool,
    /// The `pathLenConstraint` on the extra CA: `Some(0)` (default) is violated by
    /// the intermediate below it; `Some(1)` or `None` admits the chain.
    pub extra_intermediate_path_len: Option<u8>,
    pub include_aaguid_ext: bool,
    /// Sign the leaf with a key other than the intermediate's (breaks the link).
    pub break_leaf_signature: bool,
    /// Omit the root from `x5c` (so the pinned anchor cannot be found).
    pub omit_root: bool,
    /// Emit the TCG AIK Extended Key Usage on the `tpm` leaf (required by §8.3.1).
    pub include_aik_eku: bool,
    /// Replace the `tpm` leaf's KeyUsage with one that omits `digitalSignature`, so
    /// the "KeyUsage forbids signatures" rejection can be exercised.
    pub aik_key_usage_forbids_signature: bool,
    /// Remove the `tpm` leaf's KeyUsage extension entirely (absent is allowed).
    pub omit_aik_key_usage: bool,
    /// Sign the leaf with a certificate name that does not match the issuer's
    /// subject, so the issuer/subject link is rejected even though the signature
    /// checks out.
    pub issuer_name_override: Option<Name>,
    /// Emit the leaf certificate as X.509 **version 1** (default V3).
    pub leaf_version_v1: bool,
    /// Omit the leaf's BasicConstraints extension (the verifier requires it).
    pub omit_leaf_basic_constraints: bool,
    /// Omit the intermediate's BasicConstraints extension.
    pub omit_intermediate_basic_constraints: bool,
    /// Override the leaf's OID and its `TBSCertificate.signature` OID with an
    /// unsupported value (e.g. `1.2.840.113549.1.1.4` = md5WithRSA).
    pub leaf_sig_oid: Option<der::asn1::ObjectIdentifier>,
    /// Replace the leaf's `id-fido-gen-ce-aaguid` extension value with arbitrary
    /// (malformed) bytes.
    pub malformed_aaguid_ext: bool,
    /// Replace the leaf's BasicConstraints extension with the empty SEQUENCE
    /// encoding; RFC 5280 defines `cA BOOLEAN DEFAULT FALSE`, so this is a valid
    /// *non-CA* constraints extension and must be accepted.
    pub leaf_basic_constraints_empty: bool,
    pub leaf_validity: Validity,
    pub intermediate_validity: Validity,
    pub root_validity: Validity,
}

impl Default for ChainOptions {
    fn default() -> Self {
        Self {
            aaguid: AAGUID_ALLOWED,
            cert_aaguid: None,
            leaf_ou: "Authenticator Attestation".to_string(),
            leaf_is_ca: false,
            intermediate_is_ca: true,
            extra_intermediate: false,
            extra_intermediate_path_len: Some(0),
            include_aaguid_ext: true,
            break_leaf_signature: false,
            omit_root: false,
            include_aik_eku: true,
            aik_key_usage_forbids_signature: false,
            omit_aik_key_usage: false,
            issuer_name_override: None,
            leaf_version_v1: false,
            omit_leaf_basic_constraints: false,
            omit_intermediate_basic_constraints: false,
            leaf_sig_oid: None,
            malformed_aaguid_ext: false,
            leaf_basic_constraints_empty: false,
            leaf_validity: fixture_validity(),
            intermediate_validity: fixture_validity(),
            root_validity: fixture_validity(),
        }
    }
}

/// A generated chain: DER bytes leaf-first, the root fingerprint, the leaf signer,
/// and the leaf subject public key.
pub struct TestChain {
    pub x5c: Vec<Vec<u8>>,
    pub root_fingerprint: [u8; 32],
    pub leaf_signer: Signer,
}

/// Build a three-certificate chain (root CA → intermediate CA → leaf).
///
/// The root is included last in `x5c` unless [`ChainOptions::omit_root`] is set.
pub fn build_chain(opts: &ChainOptions) -> TestChain {
    let root_key = es256();
    let extra_key = es256();
    let intermediate_key = es256();
    let leaf_key = es256();
    // A throwaway key used only to produce a bad leaf signature.
    let wrong_key = es256();

    let root_subject =
        Name::from_str("CN=Test Root CA,O=wsl-webauthn-pam tests,C=US").expect("root name");
    let extra_subject =
        Name::from_str("CN=Test Extra CA,O=wsl-webauthn-pam tests,C=US").expect("extra name");
    let intermediate_subject =
        Name::from_str("CN=Test Intermediate CA,O=wsl-webauthn-pam tests,C=US").expect("int name");
    let leaf_subject = Name::from_str(&format!(
        "CN=Test Authenticator,OU={},O=wsl-webauthn-pam tests,C=US",
        opts.leaf_ou
    ))
    .expect("leaf name");

    let root = build_cert(
        &root_key, // issuer==subject==root
        &root_key,
        Profile::Root,
        1,
        opts.root_validity,
        root_subject.clone(),
        None,
    );

    // Optionally insert an extra CA level below the root. The intermediate (and thus
    // the leaf's issuer) is then signed by this extra CA instead of directly by the
    // root, so a `pathLenConstraint` declared here bounds the intermediate below it.
    let (extra, intermediate_issuer) = if opts.extra_intermediate {
        let extra = build_cert_full(
            &root_key, // signed by the root
            &extra_key,
            Profile::SubCA {
                issuer: root_subject.clone(),
                path_len_constraint: opts.extra_intermediate_path_len,
            },
            4,
            opts.intermediate_validity,
            extra_subject.clone(),
            None,
            &[],
            &ChainOptions::default(),
        );
        (Some(extra), extra_subject)
    } else {
        (None, root_subject.clone())
    };

    let intermediate = build_cert_full(
        if opts.extra_intermediate {
            &extra_key
        } else {
            &root_key
        }, // signed by the extra CA (or the root)
        &intermediate_key, // subject key
        if opts.intermediate_is_ca {
            Profile::SubCA {
                issuer: intermediate_issuer.clone(),
                path_len_constraint: Some(0),
            }
        } else {
            Profile::Leaf {
                issuer: intermediate_issuer.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            }
        },
        2,
        opts.intermediate_validity,
        intermediate_subject.clone(),
        None,
        &[],
        &ChainOptions {
            omit_leaf_basic_constraints: opts.omit_intermediate_basic_constraints,
            ..Default::default()
        },
    );

    let leaf_profile = if opts.leaf_is_ca {
        Profile::SubCA {
            issuer: intermediate_subject.clone(),
            path_len_constraint: Some(0),
        }
    } else {
        Profile::Leaf {
            issuer: intermediate_subject.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        }
    };

    // For the broken-signature case, sign the leaf's TBS with a key that is *not*
    // the intermediate's, while still naming the real intermediate as issuer.
    let leaf_issuer_key = if opts.break_leaf_signature {
        &wrong_key
    } else {
        &intermediate_key
    };
    let leaf = build_cert_full(
        leaf_issuer_key, // signed by the intermediate (or the wrong key)
        &leaf_key,       // subject key: what the attestation verifies against
        leaf_profile,
        3,
        opts.leaf_validity,
        leaf_subject,
        if opts.include_aaguid_ext {
            Some(opts.cert_aaguid.unwrap_or(opts.aaguid))
        } else {
            None
        },
        &[],
        opts,
    );

    let mut x5c = vec![leaf, intermediate];
    if let Some(extra) = extra {
        x5c.push(extra);
    }
    if !opts.omit_root {
        x5c.push(root.clone());
    }

    TestChain {
        x5c,
        root_fingerprint: sha256(&root),
        leaf_signer: leaf_key.signer,
    }
}

/// Build a certificate, applying the [`ChainOptions`] leaf-shape knobs (issuer
/// mismatch, version, BasicConstraints, KeyUsage, signature OID, malformed AAGUID
/// extension). Used by both the packed and tpm chain builders, and by [`chain_leaf`]
/// for standalone leaf construction.
///
/// Returns the certificate DER. Every knob is applied while the TBS is being built, so
/// the signature always covers the final bytes; the old "mutate, then re-sign" step is
/// gone with the `x509-cert 0.2` builder.
#[allow(clippy::too_many_arguments)]
fn build_cert_full(
    signing_key: &TestKey,
    subject_key: &TestKey,
    profile: Profile,
    serial: u32,
    validity: Validity,
    subject: Name,
    aaguid: Option<[u8; 16]>,
    eku: &[der::asn1::ObjectIdentifier],
    opts: &ChainOptions,
) -> Vec<u8> {
    if !matches!(signing_key.signer, Signer::Es256(_)) {
        unimplemented!("test chains use P-256 signers");
    }

    let (issuer, basic_constraints, key_usage) = match profile {
        Profile::Root => (
            subject.clone(),
            BasicConstraints {
                ca: true,
                path_len_constraint: None,
            },
            Some(KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)),
        ),
        Profile::SubCA {
            issuer,
            path_len_constraint,
        } => (
            issuer,
            BasicConstraints {
                ca: true,
                path_len_constraint,
            },
            Some(KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)),
        ),
        Profile::Leaf {
            issuer,
            enable_key_agreement,
            enable_key_encipherment,
        } => {
            let mut usage = KeyUsages::DigitalSignature | KeyUsages::NonRepudiation;
            if enable_key_encipherment {
                usage |= KeyUsages::KeyEncipherment;
            }
            if enable_key_agreement {
                usage |= KeyUsages::KeyAgreement;
            }
            let key_usage = if opts.aik_key_usage_forbids_signature {
                // `digitalSignature` deliberately absent: the AIK must not be usable
                // to sign `certInfo`.
                Some(KeyUsage(KeyUsages::KeyAgreement.into()))
            } else if opts.omit_aik_key_usage {
                None
            } else {
                Some(KeyUsage(usage))
            };
            (
                // `issuer_name_override` targets the leaf's issuer/subject link only.
                opts.issuer_name_override.clone().unwrap_or(issuer),
                BasicConstraints {
                    ca: false,
                    path_len_constraint: None,
                },
                key_usage,
            )
        }
    };

    let mut extensions = Vec::new();
    if !opts.omit_leaf_basic_constraints {
        let value = if opts.leaf_basic_constraints_empty {
            // RFC 5280's `cA BOOLEAN DEFAULT FALSE`: the empty SEQUENCE is a valid
            // *non-CA* constraints extension.
            vec![0x30, 0x00]
        } else {
            basic_constraints.to_der().expect("basic constraints")
        };
        extensions.push(extension(
            <BasicConstraints as const_oid::AssociatedOid>::OID,
            true,
            value,
        ));
    }
    if let Some(usage) = key_usage {
        extensions.push(extension(
            <KeyUsage as const_oid::AssociatedOid>::OID,
            true,
            usage.to_der().expect("key usage"),
        ));
    }
    if let Some(aaguid) = aaguid {
        extensions.push(extension(
            ID_FIDO_GEN_CE_AAGUID,
            false,
            OctetString::new(aaguid.to_vec())
                .expect("aaguid octet string")
                .to_der()
                .expect("aaguid extension value"),
        ));
    }
    if opts.malformed_aaguid_ext {
        set_extension_raw(&mut extensions, ID_FIDO_GEN_CE_AAGUID, &[0x01, 0x02, 0x03]);
    }
    if !eku.is_empty() {
        extensions.push(extension(
            <ExtendedKeyUsage as const_oid::AssociatedOid>::OID,
            false,
            ExtendedKeyUsage(eku.to_vec())
                .to_der()
                .expect("extended key usage"),
        ));
    }

    let signature_algorithm = AlgorithmIdentifierOwned {
        oid: opts.leaf_sig_oid.unwrap_or(ECDSA_WITH_SHA256),
        parameters: None,
    };

    let tbs = TestTbs {
        version: if opts.leaf_version_v1 {
            Version::V1
        } else {
            Version::V3
        },
        serial_number: SerialNumber::from(serial),
        signature: signature_algorithm.clone(),
        issuer,
        validity,
        subject,
        subject_public_key_info: subject_key.signer.spki(),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: (!extensions.is_empty()).then_some(extensions),
    };

    let tbs_der = tbs.to_der().expect("tbs der");
    let signature = signing_key.signer.sign(&tbs_der);
    let cert = TestCert {
        tbs,
        signature_algorithm,
        signature: BitString::from_bytes(&signature).expect("signature bit string"),
    };
    let der = cert.to_der().expect("certificate der");
    assert_cert_roundtrip(&der);
    der
}

/// Build an [`Extension`] whose `extnValue` is the DER encoding of `value`.
fn extension(extn_id: der::asn1::ObjectIdentifier, critical: bool, value: Vec<u8>) -> Extension {
    Extension {
        extn_id,
        critical,
        extn_value: OctetString::new(value).expect("extension value is a valid octet string"),
    }
}

/// Replace (or insert) an extension's `extnValue` with raw bytes.
fn set_extension_raw(
    extensions: &mut Vec<Extension>,
    oid: der::asn1::ObjectIdentifier,
    value: &[u8],
) {
    let octets = OctetString::new(value.to_vec()).expect("octet string");
    if let Some(e) = extensions.iter_mut().find(|e| e.extn_id == oid) {
        e.extn_value = octets;
    } else {
        extensions.push(Extension {
            extn_id: oid,
            critical: false,
            extn_value: octets,
        });
    }
}

/// Assert that a hand-encoded certificate parses with `x509-cert 0.3` and re-encodes
/// to exactly the same bytes.
///
/// The verifier decodes the harness's output with the same crate, so a wrong
/// context-specific tag, tag mode, or `DEFAULT` omission shows up here immediately
/// instead of as a confusing verification verdict.
pub fn assert_cert_roundtrip(der: &[u8]) {
    use der::Decode as _;

    let parsed = Certificate::from_der(der).expect("synthesized certificate parses");
    let reencoded = parsed.to_der().expect("parsed certificate re-encodes");
    assert_eq!(
        reencoded, der,
        "synthesized certificate does not round-trip through x509-cert"
    );
}

/// Build a cert signed by `issuer_key` whose own subject key is `subject_key`.
fn build_cert(
    issuer_key: &TestKey,
    subject_key: &TestKey,
    profile: Profile,
    serial: u32,
    validity: Validity,
    subject: Name,
    aaguid: Option<[u8; 16]>,
) -> Vec<u8> {
    build_cert_full(
        issuer_key,
        subject_key,
        profile,
        serial,
        validity,
        subject,
        aaguid,
        &[],
        &ChainOptions::default(),
    )
}

/// A standalone leaf certificate, used for the BasicConstraints leaf-negative test.
pub struct ChainLeaf {
    /// The leaf DER.
    pub der: Vec<u8>,
    /// The leaf's public key, to sign the attestation statement.
    pub signer: Signer,
}

/// Build just a leaf certificate shaped by `opts` (issuer and subject key are
/// throwaway P-256 keys). Used where the desired rejection happens at the leaf
/// before any chain link is checked.
pub fn chain_leaf(opts: &ChainOptions) -> ChainLeaf {
    let issuer_key = es256();
    let leaf_key = es256();
    let issuer_subject =
        Name::from_str("CN=ChainLeaf Issuer,O=wsl-webauthn-pam tests,C=US").expect("issuer name");
    let leaf_subject = Name::from_str(&format!(
        "CN=ChainLeaf,OU={},O=wsl-webauthn-pam tests,C=US",
        opts.leaf_ou
    ))
    .expect("leaf name");
    let leaf = build_cert_full(
        &issuer_key,
        &leaf_key,
        Profile::Leaf {
            issuer: issuer_subject,
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        77,
        opts.leaf_validity,
        leaf_subject,
        if opts.include_aaguid_ext {
            Some(opts.cert_aaguid.unwrap_or(opts.aaguid))
        } else {
            None
        },
        &[],
        opts,
    );
    ChainLeaf {
        der: leaf,
        signer: leaf_key.signer,
    }
}

/// Build a TPM AIK certificate chain: P-256 root → P-256 intermediate → **RSA AIK**
/// leaf with an empty Subject (WebAuthn §8.3.1).
///
/// The returned `leaf_signer` is a throwaway signer; the AIK private key must be
/// supplied separately to sign `certInfo`.
pub fn build_tpm_chain(aik: &TestKey, opts: &ChainOptions) -> TestChain {
    let root_key = es256();
    let intermediate_key = es256();

    let root_subject =
        Name::from_str("CN=Test TPM Root CA,O=wsl-webauthn-pam tests,C=US").expect("root name");
    let intermediate_subject =
        Name::from_str("CN=Test TPM Intermediate CA,O=wsl-webauthn-pam tests,C=US")
            .expect("int name");

    let root = build_cert(
        &root_key,
        &root_key,
        Profile::Root,
        11,
        opts.root_validity,
        root_subject.clone(),
        None,
    );
    let intermediate = build_cert_full(
        &root_key,
        &intermediate_key,
        if opts.intermediate_is_ca {
            Profile::SubCA {
                issuer: root_subject.clone(),
                path_len_constraint: Some(0),
            }
        } else {
            Profile::Leaf {
                issuer: root_subject.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            }
        },
        12,
        opts.intermediate_validity,
        intermediate_subject.clone(),
        None,
        &[],
        &ChainOptions {
            omit_leaf_basic_constraints: opts.omit_intermediate_basic_constraints,
            ..Default::default()
        },
    );

    // The AIK leaf: signed by the intermediate, own subject key = RSA AIK, empty
    // Subject, and (unless disabled) the TCG AIK Extended Key Usage required by
    // WebAuthn §8.3.1.
    let aik_eku: &[der::asn1::ObjectIdentifier] = if opts.include_aik_eku {
        &[OID_TCG_KP_AIK_CERTIFICATE]
    } else {
        &[]
    };
    let leaf = build_cert_full(
        &intermediate_key,
        aik,
        Profile::Leaf {
            issuer: intermediate_subject,
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        13,
        opts.leaf_validity,
        Name::default(),
        None,
        aik_eku,
        opts,
    );

    let mut x5c = vec![leaf, intermediate];
    if !opts.omit_root {
        x5c.push(root.clone());
    }

    TestChain {
        x5c,
        root_fingerprint: sha256(&root),
        leaf_signer: intermediate_key.signer,
    }
}

/// SHA-256 helper.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

/// Build a `Validity` with explicit bounds relative to `now`.
pub fn validity_from(not_before: SystemTime, not_after: SystemTime) -> Validity {
    Validity::new(
        not_before.try_into().expect("not_before"),
        not_after.try_into().expect("not_after"),
    )
}

// ---------------------------------------------------------------------------
// Convenience: full positive enrollment + assertion
// ---------------------------------------------------------------------------

/// A successful `packed`/x5c enrollment bundle.
pub struct EnrolledPacked {
    pub challenge: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub aaguid: [u8; 16],
    pub cose: Vec<u8>,
    pub alg: i64,
    pub client_data_json: Vec<u8>,
    pub attestation_object: Vec<u8>,
    pub root_fingerprint: [u8; 32],
    pub x5c: Vec<Vec<u8>>,
}

/// Produce a positive `packed`-with-x5c enrollment for `key`.
///
/// The attestation is signed by the generated leaf certificate's key, so the
/// `attStmt.alg` is always ES256 regardless of the credential key's algorithm.
pub fn packed_enrollment(key: &TestKey) -> EnrolledPacked {
    let challenge = vec![0x42u8; 32];
    let credential_id = b"test-credential-id".to_vec();
    let client_data_json = client_data(ClientDataKind::Create, &challenge);
    let attested = AttestedData {
        aaguid: AAGUID_ALLOWED,
        credential_id: credential_id.clone(),
        cose_public_key: key.cose.clone(),
    };
    let auth_data = build_auth_data(RP_ID, 0x01 | 0x04, 0, Some(&attested));
    let chain = build_chain(&ChainOptions {
        aaguid: AAGUID_ALLOWED,
        ..Default::default()
    });
    let signed = signed_message(&auth_data, &client_data_json);
    let sig = chain.leaf_signer.sign(&signed);
    let att_stmt = packed_att_stmt(-7, &sig, Some(&chain.x5c));
    let attestation_object = attestation_object("packed", &auth_data, att_stmt);

    EnrolledPacked {
        challenge,
        credential_id,
        aaguid: AAGUID_ALLOWED,
        cose: key.cose.clone(),
        alg: key.alg,
        client_data_json,
        attestation_object,
        root_fingerprint: chain.root_fingerprint,
        x5c: chain.x5c,
    }
}

/// Encode a challenge to base64url (exposed for tests that hand-build clientData).
pub fn challenge_b64(challenge: &[u8]) -> String {
    b64u_encode(challenge)
}

/// Decode a DER certificate and re-encode it, as a sanity helper.
pub fn cert_roundtrip(der: &[u8]) -> Vec<u8> {
    use der::Decode as _;
    Certificate::from_der(der)
        .expect("valid cert")
        .to_der()
        .expect("der")
}

// ---------------------------------------------------------------------------
// TPM (`tpm`) attestation vectors
//
// Synthesized to match the WebAuthn §8.3 structure, signed by an RSA "AIK" key
// mirroring the Windows Hello RS1 layout.
// ---------------------------------------------------------------------------

/// TPM algorithm identifiers used by the vector builder.
pub mod tpm_alg {
    pub const RSA: u16 = 0x0001;
    pub const ECC: u16 = 0x0023;
    pub const SHA1: u16 = 0x0004;
    pub const SHA256: u16 = 0x000b;
    pub const ECC_NIST_P256: u16 = 0x0003;
    pub const ST_ATTEST_CERTIFY: u16 = 0x8017;
}

/// Which TPM signature/hash scheme a synthesized vector uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmSig {
    /// RSA PKCS#1 v1.5 with SHA-1 (COSE `RS1`, `alg: -65535`) — Windows Hello.
    Rs1,
    /// RSA PKCS#1 v1.5 with SHA-256 (COSE `RS256`, `alg: -257`).
    Rs256,
}

impl TpmSig {
    /// The COSE algorithm identifier these vectors carry in `attStmt.alg`.
    pub fn cose_alg(self) -> i64 {
        match self {
            TpmSig::Rs1 => -65535,
            TpmSig::Rs256 => -257,
        }
    }

    fn tpm_hash_id(self) -> u16 {
        match self {
            TpmSig::Rs1 => tpm_alg::SHA1,
            TpmSig::Rs256 => tpm_alg::SHA256,
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            TpmSig::Rs1 => sha1::Sha1::digest(data).to_vec(),
            TpmSig::Rs256 => Sha256::digest(data).to_vec(),
        }
    }

    pub fn sign(self, key: &rsa::PrivateKey, msg: &[u8]) -> Vec<u8> {
        use rsa::signature::SignatureEncoding as _;
        match self {
            TpmSig::Rs1 => {
                let sk = rsa::pkcs1v15::SigningKey::<sha1::Sha1>::new(key.clone());
                use rsa::signature::Signer as _;
                sk.sign(msg).to_vec()
            }
            TpmSig::Rs256 => {
                let sk = rsa::pkcs1v15::SigningKey::<Sha256>::new(key.clone());
                use rsa::signature::Signer as _;
                sk.sign(msg).to_vec()
            }
        }
    }
}
/// Encode a `TPM2B_*` value: u16 big-endian length then bytes.
fn tpm2b(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

/// Build a bare `TPMT_PUBLIC` for a P-256 credential key (no outer size prefix).
pub fn tpm_pub_area_ec(x: &[u8], y: &[u8], name_alg: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&tpm_alg::ECC.to_be_bytes());
    out.extend_from_slice(&name_alg.to_be_bytes());
    out.extend_from_slice(&0x0004_0432u32.to_be_bytes()); // objectAttributes
    out.extend_from_slice(&tpm2b(&[0u8; 32])); // authPolicy
    // TPMS_ECC_PARMS: symmetric, scheme, curveID, kdf.
    out.extend_from_slice(&0x0010u16.to_be_bytes()); // symmetric NULL
    out.extend_from_slice(&0x0010u16.to_be_bytes()); // scheme NULL
    out.extend_from_slice(&tpm_alg::ECC_NIST_P256.to_be_bytes());
    out.extend_from_slice(&0x0010u16.to_be_bytes()); // kdf NULL
    out.extend_from_slice(&tpm2b(x)); // unique.x
    out.extend_from_slice(&tpm2b(y)); // unique.y
    out
}

/// Build a bare `TPMT_PUBLIC` for an RSA credential key (no outer size prefix).
pub fn tpm_pub_area_rsa(n: &[u8], e: u32, name_alg: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&tpm_alg::RSA.to_be_bytes());
    out.extend_from_slice(&name_alg.to_be_bytes());
    out.extend_from_slice(&0x0004_0432u32.to_be_bytes()); // objectAttributes
    out.extend_from_slice(&tpm2b(&[0u8; 32])); // authPolicy
    // TPMS_RSA_PARMS: symmetric, scheme, keyBits, exponent (fixed-width u32).
    out.extend_from_slice(&0x0010u16.to_be_bytes()); // symmetric NULL
    out.extend_from_slice(&0x0010u16.to_be_bytes()); // scheme NULL
    out.extend_from_slice(&((n.len() * 8) as u16).to_be_bytes()); // keyBits
    out.extend_from_slice(&e.to_be_bytes()); // exponent
    out.extend_from_slice(&tpm2b(n)); // unique: modulus
    out
}

/// Extract `(n, e)` from an RS256 COSE key (modulus bytes, exponent as u32).
pub fn rsa_ne_from_cose(cose: &[u8]) -> (Vec<u8>, u32) {
    let value: Value = ciborium::from_reader(cose).expect("cose cbor");
    let map = value.as_map().expect("cose map");
    let get = |label: i64| -> Vec<u8> {
        map.iter()
            .find_map(|(k, v)| {
                (k.as_integer().and_then(|i| i64::try_from(i).ok()) == Some(label))
                    .then(|| v.as_bytes().cloned())
                    .flatten()
            })
            .expect("cose field")
    };
    let n = get(-1);
    let e_bytes = get(-2);
    let e = e_bytes
        .iter()
        .fold(0u32, |acc, b| (acc << 8) | u32::from(*b));
    (n, e)
}

/// Build a `TPMS_ATTEST` (certInfo) for a certify operation.
pub fn tpm_cert_info(extra_data: &[u8], attested_name: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xff54_4347u32.to_be_bytes()); // magic TPM_GENERATED
    out.extend_from_slice(&tpm_alg::ST_ATTEST_CERTIFY.to_be_bytes());
    out.extend_from_slice(&tpm2b(&[])); // qualifiedSigner
    out.extend_from_slice(&tpm2b(extra_data));
    out.extend_from_slice(&0u64.to_be_bytes()); // clock
    out.extend_from_slice(&0u32.to_be_bytes()); // resetCount
    out.extend_from_slice(&0u32.to_be_bytes()); // restartCount
    out.push(0); // safe
    out.extend_from_slice(&0u64.to_be_bytes()); // firmwareVersion
    out.extend_from_slice(&tpm2b(attested_name)); // TPMS_CERTIFY_INFO.name
    out.extend_from_slice(&tpm2b(attested_name)); // qualifiedName (ignored)
    out
}

/// The TPM Name of a `TPMT_PUBLIC`: `nameAlg || H(pubArea)` over the bare bytes.
pub fn tpm_name(pub_area: &[u8], name_alg: u16) -> Vec<u8> {
    let digest = match name_alg {
        tpm_alg::SHA1 => sha1::Sha1::digest(pub_area).to_vec(),
        tpm_alg::SHA256 => Sha256::digest(pub_area).to_vec(),
        _ => panic!("unsupported nameAlg in test builder"),
    };
    let mut out = Vec::new();
    out.extend_from_slice(&name_alg.to_be_bytes());
    out.extend_from_slice(&digest);
    out
}

/// A synthesized `tpm` enrollment bundle.
pub struct TpmEnrollment {
    pub challenge: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub attestation_object: Vec<u8>,
    pub auth_data: Vec<u8>,
    pub root_fingerprint: [u8; 32],
    pub aaguid: [u8; 16],
    pub credential_key: TestKey,
}

/// Assemble a `tpm` `attStmt` map.
pub fn tpm_att_stmt(
    ver: &str,
    alg: i64,
    sig: &[u8],
    cert_info: &[u8],
    pub_area: &[u8],
    x5c: &[Vec<u8>],
) -> Vec<(Value, Value)> {
    vec![
        (Value::from("ver"), Value::from(ver)),
        (Value::from("alg"), Value::from(alg)),
        (Value::from("sig"), Value::Bytes(sig.to_vec())),
        (Value::from("certInfo"), Value::Bytes(cert_info.to_vec())),
        (Value::from("pubArea"), Value::Bytes(pub_area.to_vec())),
        (
            Value::from("x5c"),
            Value::Array(x5c.iter().cloned().map(Value::Bytes).collect()),
        ),
    ]
}

/// Build a positive `tpm` enrollment for a P-256 credential key.
///
/// The AIK is an RSA key (`aik_key`), its certificate chain is `chain`, and the
/// signature uses `sig_scheme`.
pub fn tpm_enrollment(
    credential: &TestKey,
    aik_key: &rsa::PrivateKey,
    chain: &TestChain,
    sig_scheme: TpmSig,
    name_alg: u16,
) -> TpmEnrollment {
    assert_eq!(
        name_alg,
        sig_scheme.tpm_hash_id(),
        "nameAlg must match the signature hash for these vectors"
    );
    let challenge = vec![0x5au8; 32];
    let credential_id = b"tpm-cred-id".to_vec();
    let client_data_json = client_data(ClientDataKind::Create, &challenge);
    let attested = AttestedData {
        aaguid: AAGUID_ALLOWED,
        credential_id: credential_id.clone(),
        cose_public_key: credential.cose.clone(),
    };
    let auth_data = build_auth_data(RP_ID, 0x01 | 0x04, 0, Some(&attested));

    // Build the pubArea describing the credential public key (EC or RSA).
    let pub_area = match credential.alg {
        -7 => {
            let (x, y) = p256_xy_from_cose(&credential.cose);
            tpm_pub_area_ec(&x, &y, name_alg)
        }
        -257 => {
            let (n, e) = rsa_ne_from_cose(&credential.cose);
            tpm_pub_area_rsa(&n, e, name_alg)
        }
        other => panic!("tpm vectors support ES256/RS256 credential keys, got alg {other}"),
    };
    let name = tpm_name(&pub_area, name_alg);

    let att_to_be_signed = signed_message(&auth_data, &client_data_json);
    let extra = sig_scheme.digest(&att_to_be_signed);
    let cert_info = tpm_cert_info(&extra, &name);

    let sig = sig_scheme.sign(aik_key, &cert_info);
    let att_stmt = tpm_att_stmt(
        "2.0",
        sig_scheme.cose_alg(),
        &sig,
        &cert_info,
        &pub_area,
        &chain.x5c,
    );
    let attestation_object = attestation_object("tpm", &auth_data, att_stmt);

    TpmEnrollment {
        challenge,
        credential_id,
        client_data_json,
        attestation_object,
        auth_data,
        root_fingerprint: chain.root_fingerprint,
        aaguid: AAGUID_ALLOWED,
        credential_key: match credential.alg {
            -7 => es256(),
            -257 => rs256(),
            _ => ed25519(),
        },
    }
}

/// Extract the affine X/Y coordinates of a P-256 COSE key.
pub fn p256_xy_from_cose(cose: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let value: Value = ciborium::from_reader(cose).expect("cose cbor");
    let map = value.as_map().expect("cose map");
    let get = |label: i64| -> Vec<u8> {
        map.iter()
            .find_map(|(k, v)| {
                (k.as_integer().and_then(|i| i64::try_from(i).ok()) == Some(label))
                    .then(|| v.as_bytes().cloned())
                    .flatten()
            })
            .expect("cose coordinate")
    };
    (get(-2), get(-3))
}

/// Generate an RSA AIK key for TPM vectors.
pub fn rsa_aik() -> rsa::PrivateKey {
    rsa::PrivateKey::new(&mut UnwrapErr(SysRng), 2048).expect("rsa aik")
}
