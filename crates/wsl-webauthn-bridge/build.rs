//! Embed a Windows `VERSIONINFO` resource into `WSLWebAuthnBridge.exe`.
//!
//! The Windows WebAuthn prompt can surface a "Requested by <name> (<publisher>)"
//! line sourced from the calling executable's version resource; without one the
//! dialog shows only the credential identity. This is a UX-only concern: the
//! resource is never a trust input (the Linux side pins the whole `.exe` by
//! SHA-256), so resource compilation is deliberately **best-effort** and never
//! fails the build. If no resource compiler is found, the bridge is built without
//! one.
//!
//! Gated to Windows targets. A native MSVC build uses `rc.exe`; a GNU
//! (`*-pc-windows-gnu`) cross-build from Linux uses the matching
//! `mingw-w64` `windres`, whose COFF object is passed to the linker directly.
//! No build-dependency is added: both compilers are invoked as external tools.

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=bridge.rc");
    println!("cargo:rerun-if-changed=build.rs");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os != "windows" {
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    let version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_string());
    let (version_commas, version_dotted) = version_forms(&version);

    match target_env.as_str() {
        "msvc" => embed_msvc(&out_dir, &version_commas, &version_dotted),
        "gnu" | "gnullvm" => embed_gnu(&out_dir, &version_commas, &version_dotted),
        _ => {}
    }
}

/// Return `(a,b,c,d, e.f.g)` for a Cargo version string.
///
/// Pre-release/build suffixes are dropped (a Windows `FILEVERSION` has no room for
/// them), and missing components default to `0`.
fn version_forms(version: &str) -> (String, String) {
    let core = version.split(['-', '+']).next().unwrap_or("0.0.0");
    let mut parts: Vec<u64> = core
        .split('.')
        .map(|p| p.parse::<u64>().unwrap_or(0))
        .collect();
    while parts.len() < 4 {
        parts.push(0);
    }
    let dotted = format!("{}.{}.{}", parts[0], parts[1], parts[2]);
    let commas = format!("{},{},{},{}", parts[0], parts[1], parts[2], parts[3]);
    (commas, dotted)
}

/// Expand the `.rc` template into an `.rc` file in `OUT_DIR`.
///
/// Returns `None` if the template is missing, so the resource step stays best-effort
/// even for a downstream packager that drops non-source files.
fn render_rc(out_dir: &Path, commas: &str, dotted: &str) -> Option<PathBuf> {
    let template = Path::new("bridge.rc");
    println!("cargo:rerun-if-changed={}", template.display());
    let Ok(text) = std::fs::read_to_string(template) else {
        eprintln!("note: bridge.rc not found; building bridge without a version resource");
        return None;
    };
    let rendered = text
        .replace("__VERSION_COMMAS__", commas)
        .replace("__VERSION__", dotted);
    let path = out_dir.join("bridge.rc");
    std::fs::write(&path, rendered).expect("write rendered bridge.rc");
    Some(path)
}

/// MSVC: `rc.exe` → `.res`, linked directly by link.exe.
///
/// `rc.exe` has no `--version` flag, so the tool is probed by actually compiling:
/// the first candidate that produces the `.res` wins.
fn embed_msvc(out_dir: &Path, commas: &str, dotted: &str) {
    let Some(rc) = render_rc(out_dir, commas, dotted) else {
        return;
    };
    let res = out_dir.join("bridge.res");
    for rc_exe in ["rc", "rc.exe"] {
        let status = Command::new(rc_exe)
            .arg("/nologo")
            .arg("/fo")
            .arg(&res)
            .arg(&rc)
            .status();
        if matches!(status, Ok(s) if s.success()) {
            println!("cargo:rustc-link-arg-bins={}", res.display());
            return;
        }
    }
    eprintln!("note: rc.exe not found or failed; building bridge without a version resource");
}

/// GNU / gnullvm: `windres` → COFF resource object, linked directly.
///
/// The object is passed straight to the linker. Wrapping it in a `static=` archive
/// does **not** work: a resource-only object defines no symbols, so the linker never
/// pulls the archive member in and the resource silently disappears.
fn embed_gnu(out_dir: &Path, commas: &str, dotted: &str) {
    let Some(rc) = render_rc(out_dir, commas, dotted) else {
        return;
    };
    let obj = out_dir.join("bridge.res.o");

    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target = env::var("TARGET").unwrap_or_default();
    let windres_names: Vec<&str> = if arch == "x86_64" {
        vec!["x86_64-w64-mingw32-windres", "windres"]
    } else {
        vec!["aarch64-w64-mingw32-windres", "windres"]
    };
    let Some(windres) = find_tool(&windres_names) else {
        eprintln!("note: windres not found; building bridge without a version resource");
        return;
    };

    let status = Command::new(&windres)
        .arg("--target")
        .arg(pe_target(&target))
        .arg("-i")
        .arg(&rc)
        .arg("-o")
        .arg(&obj)
        .status();
    if !matches!(status, Ok(s) if s.success()) {
        eprintln!("note: windres failed; building bridge without a version resource");
        return;
    }

    println!("cargo:rustc-link-arg-bins={}", obj.display());
}

/// Map a Rust target triple to a `windres --target` value.
fn pe_target(target: &str) -> &'static str {
    if target.starts_with("x86_64") {
        "pe-x86-64"
    } else if target.starts_with("aarch64") {
        "pe-aarch64"
    } else if target.starts_with("i686") || target.starts_with("i586") {
        "pe-i386"
    } else {
        "pe-x86-64"
    }
}

/// Find the first tool on `PATH` from `names`.
fn find_tool(names: &[&str]) -> Option<OsString> {
    for name in names {
        if Command::new(name)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok()
        {
            return Some(OsString::from(name));
        }
    }
    None
}
