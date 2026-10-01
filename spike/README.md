# Windows WebAuthn spike harness (plan §13 wave B3)

Spike-only tooling used to empirically validate plan decisions D2/D3/D5 against a
real Windows host (WSL2 + TPM + Windows Hello). It is **not** product code and is
not part of the Cargo workspace.

The findings live in [`../SPIKE.md`](../SPIKE.md).

## What it does

`harness.py` drives the real `WSLWebAuthnBridge.exe` through WSL interop:

* builds `clientDataJSON` byte-for-byte the way the Linux side will
  (`build_client_data` mirrors `wsl-webauthn-protocol::build_client_data`);
* frames/parses the plan §3 wire protocol (4-byte LE length + JSON);
* enforces a **hard Linux-side deadline** on every invocation and, on expiry,
  SIGKILLs the interop child and best-effort `taskkill.exe /F` the reported
  Windows PID (plan §7 backstop);
* decodes the CBOR attestation object / authenticator data / COSE key (a small
  built-in CBOR decoder, so no extra Python deps beyond `cryptography`);
* verifies `rpIdHash == SHA-256(RP_ID)` (the D2 check), the
  `client_data_json_echo` pass-through (D5/§3) and the assertion signature.

## Requirements

* `cargo` + `x86_64-pc-windows-gnu` target, `x86_64-w64-mingw32-gcc`;
* Python 3 with `cryptography` (used for ECDSA/RSA verification only);
* WSL interop enabled; the bridge exe built at
  `target/x86_64-pc-windows-gnu/release/WSLWebAuthnBridge.exe`.

## Usage

```sh
# build the bridge first
cargo build --release -p wsl-webauthn-bridge --target x86_64-pc-windows-gnu --locked

python3 spike/harness.py --deadline 30 probe

# enrollment / assertion RAISE A WINDOWS HELLO PROMPT; run one at a time.
python3 spike/harness.py --deadline 190 enroll --user-name spike \
    --user-display "spike (Linux sudo)" --out tests/vectors/local/spike-enroll-assert.json
python3 spike/harness.py --deadline 90 assert \
    --merge tests/vectors/local/spike-enroll-assert.json \
    --out tests/vectors/local/spike-enroll-assert.json   # appends assert_* to the pair

python3 spike/harness.py verify tests/vectors/local/spike-enroll-assert.json
```

Useful knobs: `--exe`, `--deadline`, `--timeout-ms`, `--challenge-hex`. The
`assert` subcommand without `--merge` needs `--credential-id`.

> **Safety:** ceremonies raise UI on the user's screen. Run one at a time and
> tell the user which prompt is coming. Every invocation is deadline-bounded so
> a hung prompt can never wedge the run.

## Second-RP-ID experiment (D2 robustness)

`build_testrp.sh` patches the compile-time `RP_ID` constant, builds an exe that
pins a different RP ID, and restores the source (it never commits the patch):

```sh
spike/build_testrp.sh io.github.kirin-xiao.wsl-webauthn-pam-test
python3 spike/harness.py --exe spike/WSLWebAuthnBridge-testrp.exe \
    --rp-id io.github.kirin-xiao.wsl-webauthn-pam-test --deadline 90 \
    enroll --user-name spike-testrp --out /tmp/opencode/testrp.json
```

`--rp-id` only changes the `clientDataJSON` the harness builds; the exe must have
been built with the same constant.

## Local vectors

`tests/vectors/local/` is **git-ignored** (it contains machine identifiers:
attestation material, credential IDs, account-linked keys). Nothing captured
here is ever committed; only the `.gitignore` entry is.
