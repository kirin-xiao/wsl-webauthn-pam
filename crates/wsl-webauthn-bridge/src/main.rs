//! Windows bridge — implemented in Wave A (plan §5).

#[cfg(not(windows))]
fn main() {
    eprintln!("WSLWebAuthnBridge is Windows-only");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    // Wave A implements the WebAuthn ceremony here.
}
