//! PAM module argument parsing (plan §8).
//!
//! Recognised arguments (all optional, order-independent):
//!
//! * `debug` — emit `LOG_DEBUG` detail (never secrets) to syslog.
//! * `timeout=<secs>` — whole-child authentication deadline; overrides the config
//!   value and the 60 s default. A non-numeric or zero value is ignored (debug-logged).
//! * `noverifypin` — skip the bridge-executable SHA-256 pin check (plan D11). This
//!   weakens a defence-in-depth control; it is logged loudly on every use.
//!
//! Unknown arguments are ignored and debug-logged; parsing never panics.

use wsl_webauthn_protocol::DEFAULT_AUTH_TIMEOUT_SECS;

/// Parsed module arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ModuleArgs {
    /// `debug`.
    pub debug: bool,
    /// `timeout=<secs>`, when supplied and valid.
    pub timeout_secs: Option<u64>,
    /// `noverifypin`.
    pub noverifypin: bool,
}

/// Parse module arguments.
///
/// `raw` are the strings as delivered to `pam_sm_authenticate`.
pub fn parse(raw: &[String]) -> ModuleArgs {
    let mut args = ModuleArgs::default();
    for arg in raw {
        match arg.as_str() {
            "debug" => args.debug = true,
            "noverifypin" => args.noverifypin = true,
            other => {
                if let Some((key, value)) = other.split_once('=') {
                    if key == "timeout" {
                        match value.parse::<u64>() {
                            Ok(secs) if secs > 0 => args.timeout_secs = Some(secs),
                            _ => crate::logger::debug(&format!(
                                "ignoring invalid timeout argument: {other:?}"
                            )),
                        }
                    } else {
                        crate::logger::debug(&format!(
                            "ignoring unknown module argument: {other:?}"
                        ));
                    }
                } else {
                    crate::logger::debug(&format!("ignoring unknown module argument: {other:?}"));
                }
            }
        }
    }
    args
}

impl ModuleArgs {
    /// Resolve the whole-child deadline (seconds).
    ///
    /// Precedence: explicit module argument → config `timeout_secs` → built-in default.
    /// A module argument in `pam.d` is the operator's most specific instruction, so it
    /// wins over the installer-written config.
    pub fn deadline_secs(&self, config_timeout: Option<u64>) -> u64 {
        self.timeout_secs
            .or(config_timeout)
            .unwrap_or(DEFAULT_AUTH_TIMEOUT_SECS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn empty_defaults() {
        assert_eq!(parse(&[]), ModuleArgs::default());
    }

    #[test]
    fn flags_parse() {
        let a = parse(&s(&["debug", "noverifypin"]));
        assert!(a.debug);
        assert!(a.noverifypin);
        assert_eq!(a.timeout_secs, None);
    }

    #[test]
    fn timeout_parses() {
        assert_eq!(parse(&s(&["timeout=30"])).timeout_secs, Some(30));
        assert_eq!(parse(&s(&["timeout=0"])).timeout_secs, None);
        assert_eq!(parse(&s(&["timeout=abc"])).timeout_secs, None);
        assert_eq!(parse(&s(&["timeout="])).timeout_secs, None);
    }

    #[test]
    fn unknown_args_ignored() {
        let a = parse(&s(&["bogus", "foo=bar", "=x", "timeout=5"]));
        assert!(!a.debug);
        assert!(!a.noverifypin);
        assert_eq!(a.timeout_secs, Some(5));
    }

    #[test]
    fn deadline_precedence() {
        let none = ModuleArgs::default();
        assert_eq!(none.deadline_secs(None), DEFAULT_AUTH_TIMEOUT_SECS);
        assert_eq!(none.deadline_secs(Some(42)), 42);
        let with_arg = ModuleArgs {
            timeout_secs: Some(7),
            ..ModuleArgs::default()
        };
        assert_eq!(with_arg.deadline_secs(Some(42)), 7);
        assert_eq!(with_arg.deadline_secs(None), 7);
    }
}
