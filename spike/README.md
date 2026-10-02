# Windows WebAuthn spike harness

Spike-only tooling for running the real `WSLWebAuthnBridge.exe` on a Windows host
(WSL2 + TPM + Windows Hello). It is not product code and is not part of the Cargo
workspace. The findings are in [`../SPIKE.md`](../SPIKE.md).

## What it does

`harness.py` drives the bridge through WSL interop:

* builds `clientDataJSON` the way the Linux side does (`build_client_data` mirrors
  `wsl-webauthn-protocol::build_client_data`);
* frames/parses the wire protocol (4-byte LE length + JSON);
* enforces a Linux-side deadline on every invocation and, on expiry, SIGKILLs the
  interop child and best-effort `taskkill.exe /F` the reported Windows PID;
* decodes the CBOR attestation object / authenticator data / COSE key with a small
  built-in decoder, so no extra Python deps beyond `cryptography`;
* verifies `rpIdHash == SHA-256(RP_ID)`, the `client_data_json_echo` pass-through,
  and the assertion signature.

## Requirements

* `cargo` + `x86_64-pc-windows-gnu` target, `x86_64-w64-mingw32-gcc`;
* Python 3 with `cryptography` (ECDSA/RSA verification only);
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

Knobs: `--exe`, `--deadline`, `--timeout-ms`, `--challenge-hex`. The `assert`
subcommand without `--merge` needs `--credential-id`.

> **Safety:** ceremonies raise UI on the user's screen. Run one at a time and say
> which prompt is coming. Every invocation is deadline-bounded so a hung prompt
> cannot wedge the run.

## Second-RP-ID experiment

`build_testrp.sh` patches the compile-time `RP_ID` constant, builds an exe pinning a
different RP ID, and restores the source:

```sh
spike/build_testrp.sh io.github.kirin-xiao.wsl-webauthn-pam-test
python3 spike/harness.py --exe spike/WSLWebAuthnBridge-testrp.exe \
    --rp-id io.github.kirin-xiao.wsl-webauthn-pam-test --deadline 90 \
    enroll --user-name spike-testrp --out /tmp/opencode/testrp.json
```

`--rp-id` only changes the `clientDataJSON` the harness builds; the exe must have
been built with the same constant.

## Local vectors

`tests/vectors/local/` is git-ignored: it contains machine identifiers (attestation
material, credential IDs, account-linked keys). Nothing captured there is committed;
only the `.gitignore` entry is.
