//! Guard for the `RUSTSEC-2023-0071` ignore rationale in `deny.toml`.
//!
//! The advisory (non-constant-time RSA private-key operations) is ignored on the
//! grounds that the *production* code path is public-key verification only: RSA
//! private keys exist solely in this crate's local test harness for synthesized
//! vectors. This test keeps that rationale honest by scanning every workspace
//! crate's `src/` for RSA private-key constructs. If a real private-key path
//! ever lands in `src/`, this fails and the advisory must be re-evaluated.

use std::path::{Path, PathBuf};

/// Substrings that would indicate an RSA private-key operation in production code.
const FORBIDDEN: &[&str] = &[
    "RsaPrivateKey",
    "rsa::pkcs1v15::SigningKey",
    "rsa::pkcs8::EncodePrivateKey",
    "rsa::Pkcs1v15Encrypt",
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
        "RSA private-key constructs found in production `src/`; the \
         RUSTSEC-2023-0071 ignore in deny.toml is no longer justified:\n{}",
        hits.join("\n")
    );
}
