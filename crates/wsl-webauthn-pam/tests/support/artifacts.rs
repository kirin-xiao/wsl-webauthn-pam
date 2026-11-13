//! Locate build artifacts without depending on cargo's internal directory layout.
//!
//! `cargo test` used to leave the cdylib and the test executables in
//! `target/<profile>/deps/`. Since cargo 1.100's build-dir layout they can instead
//! appear in `target/<profile>/build/<package>/<hash>/out/`, and a plain `cargo build`
//! still copies the cdylib to `target/<profile>/`. Nothing here may assume one scheme:
//! a locator that does turns a cargo upgrade into a false "artifact missing" failure in
//! the `REQUIRE_LIBPAM` tier.
//!
//! Resolution order: the running test executable's ancestor chain, then the workspace
//! `target/<profile>` directories (including their `build/<package>/<hash>/out`
//! subtrees, for both the single- and two-level layouts).
//!
//! Standard library only, so the light ABI test can include it without pulling in the
//! test doubles.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// The cdylib this crate produces.
const LIBRARY: &str = "libpam_wsl_webauthn.so";

/// Locate the built `pam_wsl_webauthn.so`.
#[must_use]
pub fn locate_library() -> Option<PathBuf> {
    find(LIBRARY)
}

/// Locate a built example binary (`examples/<name>`).
#[must_use]
pub fn locate_example(name: &str) -> Option<PathBuf> {
    find(&format!("examples/{name}"))
}

/// Find `rel` (a path under a profile directory) in every plausible location.
fn find(rel: &str) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    let mut profiles: Vec<PathBuf> = Vec::new();

    if let Ok(exe) = std::env::current_exe() {
        for ancestor in exe.ancestors().skip(1) {
            candidates.push(ancestor.join(rel));
            // The first `debug`/`release` component above the test binary is the
            // profile directory; remember it for the build-dir scan below.
            if is_profile_dir(ancestor) && !profiles.iter().any(|p| p == ancestor) {
                profiles.push(ancestor.to_path_buf());
            }
        }
    }

    // Fallback for a test binary that lives outside the target tree: the workspace
    // `target` directory, resolved from `<workspace>/crates/<crate>`.
    if let Some(manifest) = std::env::var_os("CARGO_MANIFEST_DIR") {
        let crate_dir = PathBuf::from(manifest);
        if let Some(workspace) = crate_dir.parent().and_then(Path::parent) {
            for profile in ["debug", "release"] {
                profiles.push(workspace.join("target").join(profile));
            }
        }
    }

    for profile in profiles {
        candidates.push(profile.join(rel));
        candidates.push(profile.join("deps").join(rel));
        for package in package_build_dirs(&profile) {
            // `build/<package>-<hash>/out` (older cargo) …
            candidates.push(package.join("out").join(rel));
            // … and `build/<package>/<hash>/out` (cargo >= 1.100).
            for hash in subdirs(&package) {
                candidates.push(hash.join("out").join(rel));
            }
        }
    }

    candidates.into_iter().find(|path| path.is_file())
}

/// Whether `dir` is a cargo profile directory.
fn is_profile_dir(dir: &Path) -> bool {
    matches!(
        dir.file_name().and_then(|n| n.to_str()),
        Some("debug" | "release")
    )
}

/// Directories under `<profile>/build` that belong to this package.
fn package_build_dirs(profile: &Path) -> Vec<PathBuf> {
    subdirs(&profile.join("build"))
        .into_iter()
        .filter(|dir| {
            dir.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("wsl-webauthn-pam"))
        })
        .collect()
}

/// Immediate subdirectories of `dir`, ignoring a missing or unreadable directory.
fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect()
}
