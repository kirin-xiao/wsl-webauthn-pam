//! Guard: production code must not perform RSA private-key operations.
//!
//! Every shipped path is public-key verification only (WebAuthn assertion and
//! attestation checks); RSA private keys exist solely in this crate's local test
//! harness, which synthesizes vectors. This test scans every workspace crate's `src/`
//! for RSA private-key constructs so a private-key path cannot land in a shipped
//! binary unnoticed.
//!
//! It outlived the `RUSTSEC-2023-0071` ignore that originally motivated it: that
//! advisory is gone from the graph with `rsa 0.10` (which uses `crypto-bigint`, not
//! `num-bigint-dig`), but "no private-key operations in production" is a property
//! worth pinning independently of any advisory.

use std::path::{Path, PathBuf};

/// Substrings that would indicate an RSA private-key operation in production code.
///
/// `PrivateKey` is `rsa 0.10`'s name for the private-key type (it was `RsaPrivateKey`
/// in 0.9); the P-256 side calls its equivalent `SecretKey`, so this does not collide.
const FORBIDDEN: &[&str] = &[
    "PrivateKey",
    "rsa::pkcs1v15::SigningKey",
    "EncodePrivateKey",
    "Pkcs1v15Encrypt",
];

fn crates_dir() -> Option<PathBuf> {
    // CARGO_MANIFEST_DIR == <workspace>/crates/wsl-webauthn-verifier
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let crates = manifest.parent()?.to_path_buf();
    crates.is_dir().then_some(crates)
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn production_src_has_no_rsa_private_key_path() {
    let Some(crates) = crates_dir() else {
        // Running outside the workspace (e.g. a packaged crate); nothing to scan.
        return;
    };

    let mut files = Vec::new();
    for entry in std::fs::read_dir(&crates).into_iter().flatten().flatten() {
        let src = entry.path().join("src");
        if src.is_dir() {
            collect_rs_files(&src, &mut files);
        }
    }
    assert!(
        !files.is_empty(),
        "no workspace `src/` trees found under {crates:?}"
    );

    let mut hits = Vec::new();
    for file in files {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        for needle in FORBIDDEN {
            if text.contains(needle) {
                hits.push(format!("{}: contains `{needle}`", file.display()));
            }
        }
    }

    assert!(
        hits.is_empty(),
        "RSA private-key constructs found in production `src/`; the shipped \
         paths must stay public-key-verification only:\n{}",
        hits.join("\n")
    );
}
