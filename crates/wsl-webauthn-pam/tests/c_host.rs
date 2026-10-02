//! A non-Rust host for the module and a real-libpam tier that **fails** rather than
//! skips when the FFI path cannot run.
//!
//! Rust test binaries set `SIGPIPE=SIG_IGN`; a C host under sudo/su/sshd leaves it at
//! `SIG_DFL`. This test closes that gap in two ways:
//!
//! * it compiles `tests/c_host/pam_host.c` with the system C compiler (never a
//!   checked-in binary) and calls the module through `dlopen`/`dlsym` as a C consumer
//!   would — including all five non-authentication `pam_sm_*` entry points, not merely
//!   checking for their presence;
//! * it drives the module through the **real libpam** (`pam_start_confdir` →
//!   `pam_authenticate`) from that C host with `SIGPIPE` reset to `SIG_DFL`.
//!
//! # The require-libpam gate
//!
//! Dev boxes may legitimately lack the built `.so` (filtered builds) or the
//! facilities to run the privileged tier, so by default a missing prerequisite
//! *skips* with a printed reason. CI sets `WSL_WEBAUTHN_REQUIRE_LIBPAM=1`, which
//! turns every skip in this file into a hard failure: green then proves libpam
//! loaded the module and ran the real `pam_sm_authenticate`.
//!
//! # The privileged tier
//!
//! `pam_start` reaches the module's store (`/etc/wsl_webauthn`) and bridge only
//! after a successful config+record load, which needs a root-owned store. Rather
//! than write the host `/etc`, `tests/c_host/provision_and_drive.sh` is always run
//! inside a **mount namespace** with a private tmpfs over `/etc`:
//!
//! * unprivileged (default here): `unshare -rm` maps the caller to uid 0, so the
//!   files it creates read back as uid 0 — exactly what `Store::system()` expects.
//! * root-gated fallback (real root, or passwordless `sudo -n`): the same script
//!   under `unshare -m`.
//!
//! Either way the host `/etc` is never touched and the store disappears with the
//! namespace. A private tmpfs over `/proc/sys/fs` supplies the `WSLInterop`
//! registration the runner's pre-flight reads.
//!
//! What this proves end to end: libpam `dlopen`s the built `.so`, calls
//! `pam_sm_authenticate`, the module runs the production `SystemDeps` against a
//! provisioned tempdir store, hashes and trusts the bridge, mints a random
//! challenge, spawns the dynamic fake bridge, verifies a genuine ES256 assertion it
//! signed, invokes the application conversation (`PAM_CONV`), and returns
//! `PAM_SUCCESS`.
//!
//! Requires `libpam0g-dev` (headers + `-lpam`), a C compiler, and one of:
//! unprivileged user namespaces (`unshare -rm`), root, or passwordless `sudo`.

#![cfg(target_os = "linux")]

mod gate;
mod support;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// The C host, compiled once per test process.
const PAM_HOST_OUT: &str = concat!(env!("CARGO_TARGET_TMPDIR"), "/pam_host");
const C_SOURCE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/c_host/pam_host.c");
const PROVISION_SH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/c_host/provision_and_drive.sh"
);

/// Return `None` after handling a would-be skip: fail loudly when the CI gate is
/// set, otherwise print the named missing prerequisite and let the caller pass.
fn skip_or_fail(what: &str) -> Option<()> {
    gate::enforce(what);
    None
}

/// Locate the built cdylib next to the running test binary or the workspace target.
fn locate_library() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe()
        && let Some(deps_dir) = exe.parent()
    {
        candidates.push(deps_dir.join("libpam_wsl_webauthn.so"));
        if let Some(profile_dir) = deps_dir.parent() {
            candidates.push(profile_dir.join("libpam_wsl_webauthn.so"));
            if let Some(target_dir) = profile_dir.parent() {
                for profile in ["debug", "release"] {
                    candidates.push(target_dir.join(profile).join("libpam_wsl_webauthn.so"));
                    candidates.push(
                        target_dir
                            .join(profile)
                            .join("deps")
                            .join("libpam_wsl_webauthn.so"),
                    );
                }
            }
        }
    }
    if let Some(manifest) = std::env::var_os("CARGO_MANIFEST_DIR") {
        let crate_dir = PathBuf::from(manifest);
        if let Some(workspace) = crate_dir.parent().and_then(|p| p.parent()) {
            for profile in ["debug", "release"] {
                candidates.push(
                    workspace
                        .join("target")
                        .join(profile)
                        .join("libpam_wsl_webauthn.so"),
                );
                candidates.push(
                    workspace
                        .join("target")
                        .join(profile)
                        .join("deps")
                        .join("libpam_wsl_webauthn.so"),
                );
            }
        }
    }
    candidates.into_iter().find(|p| p.exists())
}

/// Locate a built example binary (`target/<profile>/examples/<name>`).
fn locate_example(name: &str) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe()
        && let Some(deps_dir) = exe.parent()
        && let Some(profile_dir) = deps_dir.parent()
    {
        candidates.push(profile_dir.join("examples").join(name));
        if let Some(target_dir) = profile_dir.parent() {
            for profile in ["debug", "release"] {
                candidates.push(target_dir.join(profile).join("examples").join(name));
            }
        }
    }
    candidates.into_iter().find(|p| p.exists())
}

/// Compile `pam_host.c` once. Skips/fails on a missing compiler or link library.
fn compiled_c_host() -> Option<&'static Path> {
    static HOST: OnceLock<Option<PathBuf>> = OnceLock::new();
    HOST.get_or_init(|| {
        let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
        let out = PathBuf::from(PAM_HOST_OUT);
        if let Some(parent) = out.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let status = Command::new(&cc)
            .args(["-O2", "-Wall", "-Wextra", "-o"])
            .arg(&out)
            .arg(C_SOURCE)
            .args(["-ldl", "-lpam"])
            .status();
        match status {
            Ok(s) if s.success() => Some(out),
            Ok(s) => {
                eprintln!("C compiler exited {s:?} compiling pam_host.c");
                None
            }
            Err(e) => {
                eprintln!("could not run C compiler {cc:?}: {e}");
                None
            }
        }
    })
    .as_deref()
}

/// Whether `unshare -rm` (unprivileged user+mount namespace) works here.
fn user_namespace_available() -> bool {
    Command::new("unshare")
        .args(["-rm", "true"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Whether we are already root (so a plain `unshare -m` suffices).
fn is_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .is_some_and(|s| s.trim() == "0")
}

/// Whether passwordless `sudo` is available for the root-gated fallback.
fn sudo_available() -> bool {
    Command::new("sudo")
        .args(["-n", "true"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Whether the provisioned tier can run at all (unprivileged namespaces, real
/// root, or passwordless sudo).
fn can_provision() -> bool {
    user_namespace_available() || is_root() || sudo_available()
}

/// The located artifacts a run needs.
struct Artifacts {
    so: PathBuf,
    c_host: PathBuf,
    bridge: PathBuf,
}

impl Artifacts {
    fn discover() -> Option<Artifacts> {
        let c_host = match compiled_c_host() {
            Some(p) => p.to_path_buf(),
            None => {
                skip_or_fail("the C compiler/`-lpam` is unavailable")?;
                return None;
            }
        };
        let Some(so) = locate_library() else {
            skip_or_fail(
                "libpam_wsl_webauthn.so was not found; run `cargo build -p wsl-webauthn-pam`",
            )?;
            return None;
        };
        let Some(bridge) = locate_example("dyn_assert_bridge") else {
            skip_or_fail(
                "the dyn_assert_bridge example was not built; \
                 run `cargo build -p wsl-webauthn-pam --example dyn_assert_bridge`",
            )?;
            return None;
        };
        Some(Artifacts { so, c_host, bridge })
    }
}

/// `pam_host abi <so>` directly (no libpam stack, no privileges needed).
#[test]
fn c_host_dlopens_module_and_calls_entry_points() {
    let Some(arts) = Artifacts::discover() else {
        return;
    };
    let out = Command::new(&arts.c_host)
        .arg("abi")
        .arg(&arts.so)
        .output()
        .expect("spawn pam_host abi");
    assert!(
        out.status.success(),
        "pam_host abi failed: status={:?} stdout={} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The five non-auth entry points must return their contract codes through the
    // real dlopen'd FFI frame (setcred=0, the rest PAM_IGNORE=25).
    assert!(
        stdout.contains("setcred=0 acct=25 open=25 close=25 chauthtok=25"),
        "unexpected entry-point returns: {stdout}"
    );
}

/// `pam_start_confdir` + `pam_authenticate` from the C host with `SIGPIPE=SIG_DFL`,
/// against a module that must fail closed when no store is provisioned.
///
/// This needs no namespace: it proves the real libpam loaded `$SO`, resolved
/// `pam_sm_authenticate`, and returned a fail-closed code, all under a non-Rust
/// host. It always runs when the `.so` exists (so it is a good dev-box smoke too).
#[test]
fn c_host_libpam_loads_module_and_fails_closed() {
    let Some(arts) = Artifacts::discover() else {
        return;
    };
    let confdir = tempfile::TempDir::new().expect("tempdir");
    let service = confdir.path().join("wslwt-test");
    std::fs::write(&service, format!("auth required {}\n", arts.so.display()))
        .expect("write service file");

    let out = Command::new(&arts.c_host)
        .args(["libpam"])
        .arg(confdir.path())
        .args(["wslwt-test", "alice", "failclosed", "0"])
        .output()
        .expect("spawn pam_host libpam");
    assert!(
        out.status.success(),
        "libpam fail-closed run failed: status={:?} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("pam_authenticate="),
        "the C host did not report a pam_authenticate result"
    );
}

/// The success + conversation path through the real stack, in a mount namespace.
///
/// The store is provisioned, the bridge is the dynamic signer, and the module must
/// return `PAM_SUCCESS` *and* invoke the application conversation.
#[test]
fn c_host_libpam_success_path_with_provisioned_store() {
    let Some(arts) = Artifacts::discover() else {
        return;
    };
    if !can_provision() {
        let _ = skip_or_fail(
            "neither unprivileged namespaces, root, nor passwordless sudo is available",
        );
        return;
    }
    let fx = support::Fixture::new();
    let secret_hex = hex(&fx.key.signing.to_bytes());
    let cred_id_b64 = wsl_webauthn_protocol::b64u_encode(&fx.credential_id);

    // The bridge is installed at a fixed in-namespace path; hash its real bytes so
    // the record's pin matches.
    let bridge_digest = support::hash_file(&arts.bridge).expect("hash example bridge");
    let record = support::record_for(
        "alice",
        &fx.bundle,
        &fx.key.cose,
        Path::new("/tmp/wslwt-test/bridge"),
        &bridge_digest,
        0,
    );
    let config = support::config_for(
        Path::new("/tmp/wslwt-test/bridge"),
        Path::new("/tmp/wslwt-test"),
    );

    let files = tempfile::TempDir::new().expect("tempdir");
    let record_src = files.path().join("alice.json");
    let config_src = files.path().join("config");
    std::fs::write(
        &record_src,
        serde_json::to_vec_pretty(&record).expect("serialize record"),
    )
    .expect("write record");
    std::fs::write(&config_src, config.to_toml()).expect("write config");
    let confdir = files.path().join("pam.d");
    std::fs::create_dir(&confdir).expect("create confdir");
    std::fs::write(
        confdir.join("wslwt-test"),
        format!("auth required {}\n", arts.so.display()),
    )
    .expect("write service file");

    run_provisioned(
        &arts,
        &record_src,
        &config_src,
        &confdir,
        "success",
        true,
        &secret_hex,
        &cred_id_b64,
        "single",
        1,
    );
}

/// The success path driven by eight concurrent threads from the C host, each with
/// its own `pam_handle_t`, alternating a no-argument service with a `debug` one.
///
/// Proves the module is callable concurrently from a non-Rust host with distinct
/// per-handle module arguments (per-thread `debug` isolation) and that simultaneous
/// authentication neither crashes nor deadlocks.
#[test]
fn c_host_libpam_concurrent_distinct_debug_args() {
    let Some(arts) = Artifacts::discover() else {
        return;
    };
    if !can_provision() {
        let _ = skip_or_fail(
            "neither unprivileged namespaces, root, nor passwordless sudo is available",
        );
        return;
    }
    let fx = support::Fixture::new();
    let secret_hex = hex(&fx.key.signing.to_bytes());
    let cred_id_b64 = wsl_webauthn_protocol::b64u_encode(&fx.credential_id);
    let bridge_digest = support::hash_file(&arts.bridge).expect("hash example bridge");
    let record = support::record_for(
        "alice",
        &fx.bundle,
        &fx.key.cose,
        Path::new("/tmp/wslwt-test/bridge"),
        &bridge_digest,
        0,
    );
    let config = support::config_for(
        Path::new("/tmp/wslwt-test/bridge"),
        Path::new("/tmp/wslwt-test"),
    );

    let files = tempfile::TempDir::new().expect("tempdir");
    let record_src = files.path().join("alice.json");
    let config_src = files.path().join("config");
    std::fs::write(
        &record_src,
        serde_json::to_vec_pretty(&record).expect("serialize record"),
    )
    .expect("write record");
    std::fs::write(&config_src, config.to_toml()).expect("write config");
    let confdir = files.path().join("pam.d");
    std::fs::create_dir(&confdir).expect("create confdir");
    // One service with no module arguments, one with `debug`: distinct per-handle
    // verbosity, driven concurrently.
    std::fs::write(
        confdir.join("wslwt-test"),
        format!("auth required {}\n", arts.so.display()),
    )
    .expect("write plain service");
    std::fs::write(
        confdir.join("wslwt-test-debug"),
        format!("auth required {} debug\n", arts.so.display()),
    )
    .expect("write debug service");

    run_provisioned(
        &arts,
        &record_src,
        &config_src,
        &confdir,
        "success",
        false,
        &secret_hex,
        &cred_id_b64,
        "concurrent",
        8,
    );
}

/// The deny path (well-formed assertion with a tampered signature) through the
/// real stack: the module must return `PAM_AUTH_ERR`.
#[test]
fn c_host_libpam_deny_path_with_provisioned_store() {
    let Some(arts) = Artifacts::discover() else {
        return;
    };
    if !can_provision() {
        let _ = skip_or_fail(
            "neither unprivileged namespaces, root, nor passwordless sudo is available",
        );
        return;
    }
    // A different key signs the assertion than the one enrolled in the record.
    let enrolled = support::Fixture::new();
    let signer = support::Fixture::new();
    let secret_hex = hex(&signer.key.signing.to_bytes());
    let cred_id_b64 = wsl_webauthn_protocol::b64u_encode(&enrolled.credential_id);

    let bridge_digest = support::hash_file(&arts.bridge).expect("hash example bridge");
    let record = support::record_for(
        "alice",
        &enrolled.bundle,
        &enrolled.key.cose,
        Path::new("/tmp/wslwt-test/bridge"),
        &bridge_digest,
        0,
    );
    let config = support::config_for(
        Path::new("/tmp/wslwt-test/bridge"),
        Path::new("/tmp/wslwt-test"),
    );

    let files = tempfile::TempDir::new().expect("tempdir");
    let record_src = files.path().join("alice.json");
    let config_src = files.path().join("config");
    std::fs::write(
        &record_src,
        serde_json::to_vec_pretty(&record).expect("serialize record"),
    )
    .expect("write record");
    std::fs::write(&config_src, config.to_toml()).expect("write config");
    let confdir = files.path().join("pam.d");
    std::fs::create_dir(&confdir).expect("create confdir");
    std::fs::write(
        confdir.join("wslwt-test"),
        format!("auth required {}\n", arts.so.display()),
    )
    .expect("write service file");

    run_provisioned(
        &arts,
        &record_src,
        &config_src,
        &confdir,
        "deny",
        true,
        &secret_hex,
        &cred_id_b64,
        "single",
        1,
    );
}

/// Diagnostic: report whether the provisioned tier can run here (unprivileged
/// namespaces, root, or passwordless sudo). Kept so a CI failure names the missing
/// facility rather than looking like a product bug.
#[test]
fn provisioned_real_libpam_tier_is_available_or_gated() {
    if can_provision() {
        return;
    }
    let _ = skip_or_fail(
        "user namespaces, root, and passwordless sudo are all unavailable, \
         so the provisioned real-libpam tier was skipped",
    );
}

/// Run `provision_and_drive.sh` in a mount namespace with the provisioned store.
///
/// Prefers the unprivileged tier (`unshare -rm`, the caller mapped to uid 0). If
/// user namespaces are unavailable, falls back to a root-gated
/// `sudo -n unshare -m` so a host that permits passwordless sudo still gets the
/// tier; if neither works the caller has already skipped (or the gate has already
/// failed).
///
/// Everything the script needs is passed as **arguments**, never the environment:
/// `sudo` resets the environment, and the script exports the bridge secrets itself
/// before it execs the C host.
#[allow(clippy::too_many_arguments)]
fn run_provisioned(
    arts: &Artifacts,
    record_src: &Path,
    config_src: &Path,
    confdir: &Path,
    expect: &str,
    require_conv: bool,
    secret_hex: &str,
    cred_id_b64: &str,
    mode: &str,
    nthreads: usize,
) {
    let script_args: Vec<std::ffi::OsString> = [
        arts.so.as_os_str().to_os_string(),
        arts.c_host.as_os_str().to_os_string(),
        arts.bridge.as_os_str().to_os_string(),
        record_src.as_os_str().to_os_string(),
        config_src.as_os_str().to_os_string(),
        confdir.as_os_str().to_os_string(),
        expect.into(),
        if require_conv { "1" } else { "0" }.into(),
        mode.into(),
        nthreads.to_string().into(),
        secret_hex.into(),
        cred_id_b64.into(),
        "1".into(),
    ]
    .into_iter()
    .collect();

    let mut cmd = if user_namespace_available() {
        // Unprivileged tier: map this uid to 0 and mount a private /etc.
        let mut c = Command::new("unshare");
        c.args(["-rm", "/bin/sh", PROVISION_SH]);
        c
    } else if is_root() {
        // Already root: a plain mount namespace is enough.
        let mut c = Command::new("unshare");
        c.args(["-m", "/bin/sh", PROVISION_SH]);
        c
    } else {
        // Root-gated fallback: the same script in a root-owned mount namespace,
        // only if passwordless sudo is available (`can_provision` checked this).
        let mut c = Command::new("sudo");
        c.args(["-n", "unshare", "-m", "/bin/sh", PROVISION_SH]);
        c
    };
    cmd.args(&script_args);
    let status = cmd.status().expect("spawn provision_and_drive.sh");
    assert!(
        status.success(),
        "provisioned real-libpam {expect} ({mode}) run failed: {status:?}"
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
