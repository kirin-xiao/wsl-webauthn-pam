#!/usr/bin/env python3
"""Stage-1 Windows WebAuthn spike harness (plan §13 wave B3).

This is *spike-only* tooling. It is deliberately stand-alone (no Rust build
required beyond the bridge exe) and never becomes part of the product. It:

  * frames/parses the plan §3 wire protocol,
  * builds `clientDataJSON` byte-for-byte the way the Linux side will
    (see `wsl-webauthn-protocol::build_client_data`),
  * invokes the real `WSLWebAuthnBridge.exe` via WSL interop under a hard
    Linux-side deadline (so a hung Windows Hello prompt can never wedge us),
  * decodes the CBOR attestation object / authenticator data / COSE key,
  * verifies `rpIdHash == SHA-256(RP_ID)` (the D2 validation), the
    `client_data_json_echo` pass-through (D5/§3) and the assertion signature,
  * writes/reads local-only vectors under `tests/vectors/local/` (git-ignored).

All values are derived from the pinned `protocol` constants below; keep them in
sync with `crates/wsl-webauthn-protocol/src/lib.rs` (they are asserted in this
harness against the values seen on the wire where possible).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------
# Pinned constants (mirror crates/wsl-webauthn-protocol/src/lib.rs)
# --------------------------------------------------------------------------

RP_ID = "io.github.kirin-xiao.wsl-webauthn-pam"
RP_NAME = "sudo on WSL (wsl-webauthn-pam)"
ORIGIN = RP_ID  # D2: origin pinned equal to RP ID
MIN_CHALLENGE_BYTES = 16
MAX_REQUEST_BYTES = 8 * 1024
MAX_RESPONSE_BYTES = 64 * 1024

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_EXE = REPO_ROOT / "target/x86_64-pc-windows-gnu/release/WSLWebAuthnBridge.exe"
# D11: always spawn with current_dir = the Windows mount root.
DEFAULT_CWD = Path("/mnt/c")


def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def build_client_data(kind: str, challenge: bytes) -> bytes:
    """Byte-identical to protocol::build_client_data (fixed field order)."""
    assert kind in ("webauthn.get", "webauthn.create")
    assert len(challenge) >= MIN_CHALLENGE_BYTES
    return (
        '{"type":"%s","challenge":"%s","origin":"%s"}'
        % (kind, b64u_encode(challenge), ORIGIN)
    ).encode("utf-8")


def encode_frame(payload: bytes) -> bytes:
    return struct.pack("<I", len(payload)) + payload


# --------------------------------------------------------------------------
# Minimal CBOR decoder (only what WebAuthn needs; bounds-checked)
# --------------------------------------------------------------------------


class CborError(Exception):
    pass


def cbor_decode(data: bytes, offset: int = 0):
    """Return (value, next_offset). Decodes the CTAP2 subset."""
    v, off = _cbor_head(data, offset)
    return v, off


def _read(data: bytes, off: int, n: int) -> tuple[bytes, int]:
    if off + n > len(data):
        raise CborError(f"truncated: need {n} bytes at {off}, have {len(data) - off}")
    return data[off : off + n], off + n


def _head(data: bytes, off: int) -> tuple[int, int, int]:
    """Return (major, additional_info_value, new_offset)."""
    if off >= len(data):
        raise CborError("truncated head")
    ib = data[off]
    off += 1
    major = ib >> 5
    ai = ib & 0x1F
    if ai < 24:
        return major, ai, off
    if ai == 24:
        b, off = _read(data, off, 1)
        return major, b[0], off
    if ai == 25:
        b, off = _read(data, off, 2)
        return major, struct.unpack(">H", b)[0], off
    if ai == 26:
        b, off = _read(data, off, 4)
        return major, struct.unpack(">I", b)[0], off
    if ai == 27:
        b, off = _read(data, off, 8)
        return major, struct.unpack(">Q", b)[0], off
    if ai == 31:
        return major, -1, off  # indefinite length
    raise CborError(f"reserved additional info {ai}")


def _cbor_head(data: bytes, off: int):
    major, ai, off = _head(data, off)
    if major == 0:
        return ai, off
    if major == 1:
        return -1 - ai, off
    if major == 2:  # byte string
        b, off = _read(data, off, ai)
        return b, off
    if major == 3:  # text string
        b, off = _read(data, off, ai)
        return b.decode("utf-8", "replace"), off
    if major == 4:  # array
        if ai == -1:
            out = []
            while True:
                if data[off] == 0xFF:
                    return out, off + 1
                v, off = _cbor_head(data, off)
                out.append(v)
        out = []
        for _ in range(ai):
            v, off = _cbor_head(data, off)
            out.append(v)
        return out, off
    if major == 5:  # map
        out = {}
        if ai == -1:
            while True:
                if data[off] == 0xFF:
                    return out, off + 1
                k, off = _cbor_head(data, off)
                v, off = _cbor_head(data, off)
                out[k] = v
        for _ in range(ai):
            k, off = _cbor_head(data, off)
            v, off = _cbor_head(data, off)
            out[k] = v
        return out, off
    if major == 6:  # tag: decode the tagged value, ignore the tag number
        return _cbor_head(data, off)
    if major == 7:
        if ai == 20:
            return False, off
        if ai == 21:
            return True, off
        if ai == 22:
            return None, off
        if ai == 23:
            return None, off  # undefined
        if ai == 24:
            b, off = _read(data, off, 1)
            return b[0], off
        if ai == 25:  # half float
            b, off = _read(data, off, 2)
            import math

            return struct.unpack(">e", b)[0], off
        if ai == 26:
            b, off = _read(data, off, 4)
            return struct.unpack(">f", b)[0], off
        if ai == 27:
            b, off = _read(data, off, 8)
            return struct.unpack(">d", b)[0], off
        raise CborError(f"simple value {ai}")
    raise CborError(f"major {major}")


# --------------------------------------------------------------------------
# Authenticator data / attestation parsing
# --------------------------------------------------------------------------


@dataclass
class AuthData:
    rp_id_hash: bytes
    flags: int
    sign_count: int
    aaguid: bytes | None = None
    credential_id: bytes | None = None
    cose_key: bytes | None = None
    cose_key_parsed: object = None
    extensions: bytes | None = None

    @property
    def up(self) -> bool:
        return bool(self.flags & 0x01)

    @property
    def uv(self) -> bool:
        return bool(self.flags & 0x04)

    @property
    def be(self) -> bool:
        return bool(self.flags & 0x08)

    @property
    def bs(self) -> bool:
        return bool(self.flags & 0x10)

    @property
    def at(self) -> bool:
        return bool(self.flags & 0x40)

    @property
    def ed(self) -> bool:
        return bool(self.flags & 0x80)


def parse_auth_data(data: bytes) -> AuthData:
    if len(data) < 37:
        raise ValueError(f"authData too short: {len(data)}")
    rp_id_hash = data[0:32]
    flags = data[32]
    sign_count = struct.unpack(">I", data[33:37])[0]
    ad = AuthData(rp_id_hash, flags, sign_count)
    off = 37
    if ad.at:
        if len(data) < off + 18:
            raise ValueError("authData AT set but truncated")
        ad.aaguid = data[off : off + 16]
        cred_len = struct.unpack(">H", data[off + 16 : off + 18])[0]
        off += 18
        ad.credential_id = data[off : off + cred_len]
        off += cred_len
        ad.cose_key, off = cbor_decode(data, off)
        ad.cose_key_parsed = ad.cose_key
    if ad.ed:
        ad.extensions = data[off:]
    return ad


def parse_attestation_object(att: bytes) -> dict:
    obj, _ = cbor_decode(att, 0)
    if not isinstance(obj, dict):
        raise ValueError("attestation object is not a CBOR map")
    return obj


# --------------------------------------------------------------------------
# COSE -> cryptography public key
# --------------------------------------------------------------------------


def cose_to_public_key(cose):
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    kty = cose.get(1)
    alg = cose.get(3)
    if kty == 2:  # EC2
        crv = cose.get(-1)
        x = cose.get(-2)
        y = cose.get(-3)
        curves = {1: ec.SECP256R1(), 2: ec.SECP384R1(), 3: ec.SECP521R1()}
        if crv not in curves:
            raise ValueError(f"unsupported EC curve {crv}")
        from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers

        return EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"), curves[crv]
        ).public_key()
    if kty == 3:  # RSA
        n = cose.get(-1)
        e = cose.get(-2)
        return rsa.RSAPublicNumbers(int.from_bytes(e, "big"), int.from_bytes(n, "big")).public_key()
    raise ValueError(f"unsupported COSE kty {kty}")


def verify_assertion_signature(cose, message: bytes, signature: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, utils

    pk = cose_to_public_key(cose)
    alg = cose.get(3)
    try:
        if alg == -7:  # ES256, DER-encoded signature
            pk.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        elif alg == -257:  # RS256
            pk.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise ValueError(f"unsupported alg {alg}")
        return True
    except InvalidSignature:
        return False


# --------------------------------------------------------------------------
# Bridge invocation (hard Linux-side deadline)
# --------------------------------------------------------------------------


@dataclass
class Invocation:
    response: dict | None
    raw_stdout: bytes
    stderr: str
    exit_code: int | None
    linux_elapsed: float
    windows_pid: int | None = None
    linux_deadline_hit: bool = False
    transport_error: str | None = None
    extra: dict = field(default_factory=dict)


def _drain(pipe, sink: list, done: threading.Event) -> None:
    try:
        while True:
            chunk = pipe.read(4096)
            if not chunk:
                break
            sink.append(chunk)
    except Exception:
        pass
    finally:
        done.set()


def parse_pid(stderr_bytes: bytes) -> int | None:
    text = stderr_bytes.decode("utf-8", "replace")
    first = text.splitlines()[0] if text.splitlines() else ""
    if first.startswith("PID "):
        try:
            return int(first[4:].strip())
        except ValueError:
            return None
    return None


def invoke(
    request: dict,
    *,
    exe: Path = DEFAULT_EXE,
    cwd: Path = DEFAULT_CWD,
    deadline_s: float = 90.0,
    taskkill: bool = True,
) -> Invocation:
    """Send one framed request; enforce a hard Linux-side deadline.

    On deadline: SIGKILL the interop child and best-effort `taskkill.exe /F`
    the reported Windows PID (plan §7 backstop).
    """
    frame = encode_frame(json.dumps(request, separators=(",", ":")).encode())
    assert len(frame) - 4 <= MAX_REQUEST_BYTES

    # The Windows exe must be spawned via an absolute path: `cwd` is forced to
    # the Windows mount root (D11), so a relative exe path would not resolve.
    exe = Path(exe).resolve()

    proc = subprocess.Popen(
        [str(exe)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(cwd),
    )
    out_chunks: list[bytes] = []
    err_chunks: list[bytes] = []
    out_done, err_done = threading.Event(), threading.Event()
    t_out = threading.Thread(target=_drain, args=(proc.stdout, out_chunks, out_done), daemon=True)
    t_err = threading.Thread(target=_drain, args=(proc.stderr, err_chunks, err_done), daemon=True)
    t_out.start()
    t_err.start()

    start = time.monotonic()
    assert proc.stdin is not None
    try:
        proc.stdin.write(frame)
        proc.stdin.flush()
    except Exception as e:  # noqa: BLE001
        proc.stdin = None
        proc.kill()
        return Invocation(None, b"", "", proc.wait(), 0.0, transport_error=f"stdin write: {e}")
    proc.stdin.close()
    proc.stdin = None  # type: ignore[assignment]

    deadline_hit = False
    try:
        proc.wait(timeout=deadline_s)
    except subprocess.TimeoutExpired:
        deadline_hit = True
        proc.kill()
        proc.wait()

    elapsed = time.monotonic() - start
    out_done.wait(2.0)
    err_done.wait(2.0)
    raw_out = b"".join(out_chunks)
    raw_err = b"".join(err_chunks)
    pid = parse_pid(raw_err)

    if deadline_hit and taskkill and pid is not None:
        subprocess.run(
            ["taskkill.exe", "/F", "/PID", str(pid)],
            cwd=str(cwd),
            capture_output=True,
            timeout=5,
        )

    response = None
    transport_error = None
    if raw_out:
        if len(raw_out) < 4:
            transport_error = "response frame shorter than 4 bytes"
        else:
            declared = struct.unpack("<I", raw_out[:4])[0]
            if declared > MAX_RESPONSE_BYTES:
                transport_error = f"response too large: {declared}"
            elif len(raw_out) < 4 + declared:
                transport_error = f"truncated response: {len(raw_out) - 4} of {declared}"
            else:
                try:
                    response = json.loads(raw_out[4 : 4 + declared])
                except Exception as e:  # noqa: BLE001
                    transport_error = f"response JSON invalid: {e}"
    else:
        transport_error = "no framed response on stdout"

    return Invocation(
        response=response,
        raw_stdout=raw_out,
        stderr=raw_err.decode("utf-8", "replace"),
        exit_code=proc.returncode,
        linux_elapsed=elapsed,
        windows_pid=pid,
        linux_deadline_hit=deadline_hit,
        transport_error=transport_error,
    )


# --------------------------------------------------------------------------
# Requests
# --------------------------------------------------------------------------


def probe_request(timeout_ms: int = 3000) -> dict:
    return {"op": "probe", "timeout_ms": timeout_ms}


def enroll_request(challenge: bytes, user_name: str, user_display: str, timeout_ms: int) -> dict:
    user_id = hashlib.sha256(("wsl-webauthn-pam:" + user_name).encode()).digest()[:32]
    return {
        "op": "enroll",
        "client_data_json": b64u_encode(build_client_data("webauthn.create", challenge)),
        "user_id": b64u_encode(user_id),
        "user_name": user_name,
        "user_display_name": user_display,
        "algs": [-7, -257],
        "timeout_ms": timeout_ms,
    }


def assert_request(challenge: bytes, cred_id_b64: str, timeout_ms: int) -> dict:
    return {
        "op": "assert",
        "client_data_json": b64u_encode(build_client_data("webauthn.get", challenge)),
        "allow_credentials": [cred_id_b64],
        "timeout_ms": timeout_ms,
    }


# --------------------------------------------------------------------------
# Reporting helpers
# --------------------------------------------------------------------------


def hexs(b: bytes | None, n: int = 0) -> str:
    if b is None:
        return "None"
    s = b.hex()
    if n and len(s) > 2 * n + 3:
        return "0x" + s[: 2 * n] + "..."
    return "0x" + s


def guid_from_uuid_bytes(b: bytes) -> str:
    # AAGUID is a 16-byte big-endian UUID.
    h = b.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def print_invocation(title: str, inv: Invocation) -> None:
    print(f"=== {title} ===")
    print(f"exit_code           : {inv.exit_code}")
    print(f"windows_pid         : {inv.windows_pid}")
    print(f"linux_elapsed_s     : {inv.linux_elapsed:.3f}")
    print(f"linux_deadline_hit  : {inv.linux_deadline_hit}")
    if inv.transport_error:
        print(f"transport_error     : {inv.transport_error}")
    print(f"response            : {json.dumps(inv.response, indent=2) if inv.response else None}")
    if inv.stderr.strip():
        print("stderr:")
        print("  " + "\n  ".join(inv.stderr.strip().splitlines()))
    print()


def summarize_enroll(resp: dict) -> dict:
    att = b64u_decode(resp["attestation_object"])
    obj = parse_attestation_object(att)
    auth_data_bytes = obj["authData"]
    ad = parse_auth_data(auth_data_bytes)
    fmt = obj.get("fmt")
    att_stmt = obj.get("attStmt", {})
    rp_ok = ad.rp_id_hash == hashlib.sha256(RP_ID.encode()).digest()
    cred_id = b64u_decode(resp["credential_id"])
    summary = {
        "fmt": fmt,
        "attStmt_keys": sorted(map(str, att_stmt.keys())) if isinstance(att_stmt, dict) else None,
        "attStmt_alg": att_stmt.get("alg") if isinstance(att_stmt, dict) else None,
        "has_x5c": bool(att_stmt.get("x5c")) if isinstance(att_stmt, dict) else None,
        "attestation_object_len": len(att),
        "authData_len": len(auth_data_bytes),
        "rpIdHash": ad.rp_id_hash.hex(),
        "rpIdHash_matches_sha256_RP_ID": rp_ok,
        "flags": f"0x{ad.flags:02x}",
        "UP": ad.up,
        "UV": ad.uv,
        "BE": ad.be,
        "BS": ad.bs,
        "AT": ad.at,
        "ED": ad.ed,
        "signCount": ad.sign_count,
        "AAGUID": guid_from_uuid_bytes(ad.aaguid) if ad.aaguid else None,
        "credentialId_len": len(ad.credential_id) if ad.credential_id else None,
        "credentialId_reported_matches_authData": (
            ad.credential_id == cred_id if ad.credential_id else None
        ),
        "cose": ad.cose_key_parsed,
        "extensions_hex": ad.extensions.hex() if ad.extensions else None,
    }
    if isinstance(att_stmt, dict) and att_stmt.get("x5c"):
        certs = att_stmt["x5c"]
        summary["x5c_count"] = len(certs)
        summary["x5c_subject_fp_sha256"] = hashlib.sha256(certs[0]).hexdigest()
        summary["x5c_leaf_der_len"] = len(certs[0])
    return summary


def extract_enroll_cose(enroll_response: dict):
    """Return the parsed COSE key from an enrollment response's authData."""
    att = b64u_decode(enroll_response["attestation_object"])
    obj = parse_attestation_object(att)
    ad = parse_auth_data(obj["authData"])
    return ad.cose_key_parsed


def print_summary(s: dict) -> None:
    for k, v in s.items():
        print(f"{k:44}: {v}")


# --------------------------------------------------------------------------
# Subcommands
# --------------------------------------------------------------------------


def cmd_probe(args) -> int:
    inv = invoke(probe_request(args.timeout_ms), exe=args.exe, deadline_s=args.deadline)
    print_invocation("probe", inv)
    return 0 if inv.response and inv.response.get("ok") else 1


def cmd_raw(args) -> int:
    req = json.loads(Path(args.request).read_text())
    inv = invoke(req, exe=args.exe, deadline_s=args.deadline)
    print_invocation(f"raw {req.get('op')}", inv)
    if args.out:
        Path(args.out).write_text(json.dumps(inv.response, indent=2) + "\n")
    return 0


def cmd_enroll(args) -> int:
    challenge = args.challenge_hex and bytes.fromhex(args.challenge_hex) or os.urandom(32)
    req = enroll_request(challenge, args.user_name, args.user_display, args.timeout_ms)
    cd = b64u_decode(req["client_data_json"])
    print(f"rp_id       : {RP_ID}")
    print(f"origin      : {ORIGIN}")
    print(f"clientData  : {cd.decode()}")
    print(f"challenge   : {challenge.hex()}")
    print("Waiting for the Windows Hello prompt (complete it with your gesture)...")
    inv = invoke(req, exe=args.exe, deadline_s=args.deadline)
    print_invocation("enroll", inv)

    if not inv.response or not inv.response.get("ok"):
        return 1

    record = {
        "rp_id": RP_ID,
        "origin": ORIGIN,
        "client_data_json": req["client_data_json"],
        "enroll_request": req,
        "enroll_response": inv.response,
    }
    summary = summarize_enroll(inv.response)
    print("--- enroll summary ---")
    print_summary(summary)
    record["enroll_summary"] = {k: str(v) for k, v in summary.items()}
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(record, indent=2) + "\n")
        print(f"wrote enroll record to {args.out}")
    return 0 if summary.get("rpIdHash_matches_sha256_RP_ID") else 2


def cmd_assert(args) -> int:
    challenge = args.challenge_hex and bytes.fromhex(args.challenge_hex) or os.urandom(32)
    if args.merge:
        record = json.loads(Path(args.merge).read_text())
        cred_id = record["enroll_response"]["credential_id"]
        out = record
    else:
        cred_id = args.credential_id
        out = {"rp_id": RP_ID, "origin": ORIGIN}
    req = assert_request(challenge, cred_id, args.timeout_ms)
    cd = b64u_decode(req["client_data_json"])
    print(f"rp_id       : {RP_ID}")
    print(f"origin      : {ORIGIN}")
    print(f"clientData  : {cd.decode()}")
    print(f"challenge   : {challenge.hex()}")
    print("Waiting for the Windows Hello prompt (complete/cancel as instructed)...")
    inv = invoke(req, exe=args.exe, deadline_s=args.deadline)
    print_invocation("assert", inv)

    if not inv.response or not inv.response.get("ok"):
        if args.out:
            out["assert_request"] = req
            out["assert_response"] = inv.response
            out["assert_error_stderr"] = inv.stderr
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(json.dumps(out, indent=2) + "\n")
        return 1

    resp = inv.response
    # Persist the pair *before* any analysis so a harness bug cannot lose the
    # captured bytes; the summary is appended and rewritten below.
    out["assert_request"] = req
    out["assert_response"] = resp
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(out, indent=2) + "\n")
        print(f"wrote raw pair to {args.out}")
    ad = parse_auth_data(b64u_decode(resp["authenticator_data"]))
    # The assertion's authData has AT=0, so the credential public key is not
    # embedded: take the COSE key from the enrollment when we have it.
    cose = ad.cose_key_parsed
    if cose is None and "enroll_response" in out:
        cose = extract_enroll_cose(out["enroll_response"])
    echo = resp.get("client_data_json_echo")
    echo_match = None
    echo_kind = None
    if echo is not None:
        echo_bytes = b64u_decode(echo)
        echo_kind = "bytes" if echo_bytes == cd else "different"
        # Windows' pbClientDataJSON is itself base64url of the JSON bytes.
        try:
            echo_match = cd in echo_bytes
        except Exception:  # noqa: BLE001
            echo_match = False
    msg = b64u_decode(resp["authenticator_data"]) + hashlib.sha256(cd).digest()
    sig_ok = verify_assertion_signature(cose, msg, b64u_decode(resp["signature"]))
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    pk = cose_to_public_key(cose)
    if isinstance(pk, ec.EllipticCurvePublicKey):
        pub = pk.public_numbers()
        cose_key = {"kty": "EC2", "curve": "P-256", "x": hex(pub.x), "y": hex(pub.y), "alg": cose.get(3)}
    else:
        pub = pk.public_numbers()
        cose_key = {"kty": "RSA", "n": hex(pub.n), "e": hex(pub.e), "alg": cose.get(3)}

    summary = {
        "UP": ad.up,
        "UV": ad.uv,
        "flags": f"0x{ad.flags:02x}",
        "signCount": ad.sign_count,
        "rpIdHash": ad.rp_id_hash.hex(),
        "rpIdHash_matches_sha256_RP_ID": ad.rp_id_hash == hashlib.sha256(RP_ID.encode()).digest(),
        "credential_id_matches_request": b64u_decode(resp["credential_id"])
        == b64u_decode(cred_id),
        "client_data_json_echo_present": echo is not None,
        "client_data_json_echo_raw_prefix": (echo[:24] + "..." if echo else None),
        "echo_equals_sent_b64url": (echo == req["client_data_json"]) if echo else None,
        "sent_bytes_are_substring_of_echo_bytes": echo_match,
        "echo_decoded_utf8": (b64u_decode(echo).decode("utf-8", "replace") if echo else None),
        "signature_verifies_over_authData_sha256_clientData": sig_ok,
        "cose_public_key": cose_key,
    }
    print("--- assert summary ---")
    print_summary(summary)
    out["assert_summary"] = {k: str(v) for k, v in summary.items()}
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(out, indent=2) + "\n")
        print(f"wrote pair to {args.out}")
    return 0 if (ad.up and ad.uv and sig_ok) else 2


def cmd_check(args) -> int:
    record = json.loads(Path(args.file).read_text())
    resp = record.get("enroll_response") or record
    print_summary(summarize_enroll(resp))
    return 0


def cmd_verify(args) -> int:
    record = json.loads(Path(args.file).read_text())
    ok = True
    if "enroll_response" in record:
        es = summarize_enroll(record["enroll_response"])
        print("--- enroll ---")
        print_summary(es)
        ok &= bool(es["rpIdHash_matches_sha256_RP_ID"]) and es["UP"] and es["UV"]
    if "assert_response" in record and record["assert_response"]:
        ar = record["assert_response"]
        ad = parse_auth_data(b64u_decode(ar["authenticator_data"]))
        cd = b64u_decode(record["assert_request"]["client_data_json"])
        msg = b64u_decode(ar["authenticator_data"]) + hashlib.sha256(cd).digest()
        cose = extract_enroll_cose(record["enroll_response"])
        sig_ok = verify_assertion_signature(cose, msg, b64u_decode(ar["signature"]))
        echo = ar.get("client_data_json_echo")
        print("--- assert ---")
        print(f"UP                          : {ad.up}")
        print(f"UV                          : {ad.uv}")
        print(f"rpIdHash matches            : {ad.rp_id_hash == hashlib.sha256(RP_ID.encode()).digest()}")
        print(f"signature verifies          : {sig_ok}")
        print(f"echo present                : {echo is not None}")
        if echo:
            print(f"echo == sent clientData     : {echo == record['assert_request']['client_data_json']}")
        ok &= sig_ok and ad.up and ad.uv
    print("VERDICT:", "OK" if ok else "FAIL")
    return 0 if ok else 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--exe", type=Path, default=DEFAULT_EXE)
    p.add_argument("--deadline", type=float, default=90.0, help="Linux-side hard deadline (s)")
    p.add_argument(
        "--rp-id",
        default=None,
        help="override RP_ID/ORIGIN (D2 robustness experiment; the exe must be "
        "built with the same constant)",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("probe")
    sp.add_argument("--timeout-ms", type=int, default=3000)
    sp.set_defaults(func=cmd_probe)

    sp = sub.add_parser("raw")
    sp.add_argument("request", help="path to JSON request object")
    sp.add_argument("--out")
    sp.set_defaults(func=cmd_raw)

    sp = sub.add_parser("enroll")
    sp.add_argument("--user-name", default="spike")
    sp.add_argument("--user-display", default="spike (Linux sudo)")
    sp.add_argument("--timeout-ms", type=int, default=175_000)
    sp.add_argument("--out")
    sp.add_argument("--challenge-hex", default=None)
    sp.set_defaults(func=cmd_enroll)

    sp = sub.add_parser("assert")
    sp.add_argument("--credential-id", default=None)
    sp.add_argument("--merge", default=None, help="enroll record to extend into a pair")
    sp.add_argument("--timeout-ms", type=int, default=55_000)
    sp.add_argument("--out")
    sp.add_argument("--challenge-hex", default=None)
    sp.set_defaults(func=cmd_assert)

    sp = sub.add_parser("check")
    sp.add_argument("file")
    sp.set_defaults(func=cmd_check)

    sp = sub.add_parser("verify")
    sp.add_argument("file")
    sp.set_defaults(func=cmd_verify)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    global RP_ID, ORIGIN
    if getattr(args, "rp_id", None):
        RP_ID = args.rp_id
        ORIGIN = args.rp_id
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
