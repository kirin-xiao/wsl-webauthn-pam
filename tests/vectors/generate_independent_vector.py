#!/usr/bin/env python3
"""Regenerate the committed, independent `packed`/x5c WebAuthn test vector.

This script is the *second implementation* backing
`crates/wsl-webauthn-verifier/tests/independent.rs` and
`fuzz/fuzz_targets/common.rs`: it uses `python3` + `cryptography` and a
hand-rolled minimal CBOR encoder, never the in-repo Rust builders. The vector is
deliberately generated off-line so it can catch a verifier and a builder that
agree with each other but not with the spec.

It regenerates, for the current compile-time RP ID / ORIGIN
(`wsl_webauthn_protocol::RP_ID`, which is pinned equal to `ORIGIN`):

* `clientDataJSON` for `webauthn.create` and `webauthn.get`,
* the attested `authenticatorData` (rpIdHash, UP|UV|AT, signCount, AAGUID,
  credential id, canonical COSE_Key),
* a three-certificate `packed`/AttCA chain (leaf, intermediate, self-signed
  root), all `ecdsa-with-SHA256`, the leaf carrying the
  `id-fido-gen-ce-aaguid` extension,
* the `attStmt` ECDSA signature over `authData || SHA-256(clientDataCreate)`,
* the assertion `authenticatorData`, signature, and golden digests.

The credential and CA private keys are generated fresh on every run; only the
resulting *public* vector is committed. Re-running produces a different but
equally valid vector, exactly like the original off-line generation.

Output is a Python/JSON dict of hex/byte literals printed to stdout so the
constants in the two Rust files can be updated verbatim.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import (
    BasicConstraints,
    CertificateBuilder,
    Name,
    NameAttribute,
    NameOID,
    UnrecognizedExtension,
)
from cryptography.x509.oid import ObjectIdentifier

# --- Pinned inputs -----------------------------------------------------------

RP_ID = "wsl-webauthn-pam"
ORIGIN = RP_ID  # `wsl_webauthn_protocol::ORIGIN` is pinned equal to `RP_ID`.
CHALLENGE = b"\x42" * 32
CREDENTIAL_ID = b"independent-vector-cred"
AAGUID = bytes.fromhex("08987058cadc4b81b6e130de50dcbe96")

ID_FIDO_GEN_CE_AAGUID = ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")

# The exact `clientDataJSON` bytes, field order type, challenge, origin and no
# whitespace. Built by hand so the committed Rust literals match byte-for-byte.
CHALLENGE_B64 = base64.urlsafe_b64encode(CHALLENGE).rstrip(b"=").decode("ascii")
CLIENT_DATA_CREATE = (
    '{"type":"webauthn.create","challenge":"%s","origin":"%s"}' % (CHALLENGE_B64, ORIGIN)
).encode("ascii")
CLIENT_DATA_GET = (
    '{"type":"webauthn.get","challenge":"%s","origin":"%s"}' % (CHALLENGE_B64, ORIGIN)
).encode("ascii")


# --- Minimal canonical CBOR encoder ------------------------------------------


def cbor_head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 0x100:
        return bytes([(major << 5) | 24, value])
    if value < 0x10000:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value < 0x100000000:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")


def cbor_int(value: int) -> bytes:
    if value >= 0:
        return cbor_head(0, value)
    return cbor_head(1, -1 - value)


def cbor_bytes(value: bytes) -> bytes:
    return cbor_head(2, len(value)) + value


def cbor_text(value: str) -> bytes:
    raw = value.encode("utf-8")
    return cbor_head(3, len(raw)) + raw


def cbor_array(items) -> bytes:
    return cbor_head(4, len(items)) + b"".join(items)


def cbor_map(pairs) -> bytes:
    """Encode a map from already-encoded `(key, value)` byte pairs.

    Canonical order: sort by the encoded key bytes (RFC 8949 §4.2.1).
    """
    encoded = sorted(pairs, key=lambda kv: kv[0])
    return cbor_head(5, len(encoded)) + b"".join(k + v for k, v in encoded)


# --- Key material ------------------------------------------------------------


def generate_ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def cose_es256(public_key) -> bytes:
    """Canonical COSE_Key map for an uncompressed P-256 key."""
    numbers = public_key.public_numbers()
    return cbor_map(
        [
            (cbor_int(1), cbor_int(2)),  # kty: EC2
            (cbor_int(3), cbor_int(-7)),  # alg: ES256
            (cbor_int(-1), cbor_int(1)),  # crv: P-256
            (cbor_int(-2), cbor_bytes(numbers.x.to_bytes(32, "big"))),
            (cbor_int(-3), cbor_bytes(numbers.y.to_bytes(32, "big"))),
        ]
    )


def sign_der(key, message: bytes) -> bytes:
    return key.sign(message, ec.ECDSA(hashes.SHA256()))


# --- X.509 chain -------------------------------------------------------------


def name(*common_then_rest) -> Name:
    return Name([NameAttribute(oid, value) for oid, value in common_then_rest])


def build_chain():
    root_key = generate_ec_key()
    intermediate_key = generate_ec_key()
    leaf_key = generate_ec_key()

    root_subject = name(
        (NameOID.COMMON_NAME, "Independent Test Root CA"),
        (NameOID.ORGANIZATION_NAME, "wsl-webauthn-pam tests"),
        (NameOID.COUNTRY_NAME, "US"),
    )
    intermediate_subject = name(
        (NameOID.COMMON_NAME, "Independent Test Intermediate CA"),
        (NameOID.ORGANIZATION_NAME, "wsl-webauthn-pam tests"),
        (NameOID.COUNTRY_NAME, "US"),
    )
    leaf_subject = name(
        (NameOID.COMMON_NAME, "Independent Test Authenticator"),
        (NameOID.ORGANIZATIONAL_UNIT_NAME, "Authenticator Attestation"),
        (NameOID.ORGANIZATION_NAME, "wsl-webauthn-pam tests"),
        (NameOID.COUNTRY_NAME, "US"),
    )

    not_before = datetime.datetime(2020, 1, 1)
    not_after = datetime.datetime(2049, 1, 1)

    def base(subject, issuer, key, serial, bc):
        return (
            CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(bc, critical=True)
        )

    root = base(
        root_subject,
        root_subject,
        root_key,
        0x1000,
        BasicConstraints(ca=True, path_length=None),
    ).sign(root_key, hashes.SHA256())

    intermediate = base(
        intermediate_subject,
        root_subject,
        intermediate_key,
        0x1001,
        BasicConstraints(ca=True, path_length=0),
    ).sign(root_key, hashes.SHA256())

    aaguid_ext = UnrecognizedExtension(
        ID_FIDO_GEN_CE_AAGUID,
        # DER OCTET STRING wrapping the raw 16-byte AAGUID; the verifier also
        # accepts the double-wrapped form.
        b"\x04\x10" + AAGUID,
    )
    leaf = (
        base(
            leaf_subject,
            intermediate_subject,
            leaf_key,
            0x1002,
            BasicConstraints(ca=False, path_length=None),
        )
        .add_extension(aaguid_ext, critical=False)
        .sign(intermediate_key, hashes.SHA256())
    )

    der = lambda cert: cert.public_bytes(serialization.Encoding.DER)

    return {
        "root_key": root_key,
        "intermediate_key": intermediate_key,
        "leaf_key": leaf_key,
        "root_der": der(root),
        "intermediate_der": der(intermediate),
        "leaf_der": der(leaf),
    }


# --- Vector assembly ---------------------------------------------------------


def main() -> None:
    chain = build_chain()
    credential_key = generate_ec_key()
    cose = cose_es256(credential_key.public_key())

    rp_id_hash = hashlib.sha256(RP_ID.encode()).digest()

    # Enrollment authenticatorData: UP|UV|AT = 0x45, signCount 0.
    cred_id_len = len(CREDENTIAL_ID).to_bytes(2, "big")
    auth_data_create = (
        rp_id_hash
        + bytes([0x45])
        + (0).to_bytes(4, "big")
        + AAGUID
        + cred_id_len
        + CREDENTIAL_ID
        + cose
    )

    # Assertion authenticatorData: UP|UV = 0x05, signCount 5.
    auth_data_get = rp_id_hash + bytes([0x05]) + (5).to_bytes(4, "big")

    # attStmt signature over authData || SHA-256(clientDataCreate).
    signed_create = auth_data_create + hashlib.sha256(CLIENT_DATA_CREATE).digest()
    att_sig = sign_der(chain["leaf_key"], signed_create)

    att_stmt = cbor_map(
        [
            (cbor_text("alg"), cbor_int(-7)),
            (cbor_text("sig"), cbor_bytes(att_sig)),
            (
                cbor_text("x5c"),
                cbor_array(
                    [
                        cbor_bytes(chain["leaf_der"]),
                        cbor_bytes(chain["intermediate_der"]),
                        cbor_bytes(chain["root_der"]),
                    ]
                ),
            ),
        ]
    )
    attestation_object = cbor_map(
        [
            (cbor_text("fmt"), cbor_text("packed")),
            (cbor_text("attStmt"), att_stmt),
            (cbor_text("authData"), cbor_bytes(auth_data_create)),
        ]
    )

    # Assertion signature over authData || SHA-256(clientDataGet).
    signed_get = auth_data_get + hashlib.sha256(CLIENT_DATA_GET).digest()
    assert_sig = sign_der(credential_key, signed_get)

    out = {
        "RP_ID": RP_ID,
        "CHALLENGE_HEX": CHALLENGE.hex(),
        "CREDENTIAL_ID": CREDENTIAL_ID.decode(),
        "CLIENT_DATA_CREATE": CLIENT_DATA_CREATE.decode(),
        "CLIENT_DATA_GET": CLIENT_DATA_GET.decode(),
        "AUTH_DATA_HEX": auth_data_create.hex(),
        "ATTESTATION_OBJECT_HEX": attestation_object.hex(),
        "ROOT_FINGERPRINT_HEX": hashlib.sha256(chain["root_der"]).hexdigest(),
        "ASSERT_AUTH_DATA_HEX": auth_data_get.hex(),
        "ASSERT_SIGNATURE_HEX": assert_sig.hex(),
        "CREDENTIAL_COSE_HEX": cose.hex(),
        "SHA256_CLIENT_DATA_CREATE_HEX": hashlib.sha256(CLIENT_DATA_CREATE).hexdigest(),
        "SHA256_SIGNED_MESSAGE_HEX": hashlib.sha256(signed_create).hexdigest(),
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
