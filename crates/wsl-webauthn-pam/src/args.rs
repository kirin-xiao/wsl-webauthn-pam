//! PAM module argument parsing (plan §8).
//!
//! Recognised arguments (all optional, order-independent):
//!
//! * `debug` — emit `LOG_DEBUG` detail (never secrets) to syslog.
//! * `timeout=<secs>` — whole-child authentication deadline, in
//!   `1..=`[`MAX_TIMEOUT_SECS`]; overrides the config value and the 60 s default.
//!
//! There is deliberately **no `noverifypin` argument**: disabling the
//! bridge-executable SHA-256 pin from `/etc/pam.d` let an operator (or a near-miss
//! typo they believed enabled it) silently turn root authentication into "run
//! whatever executable is at the configured path". The pin is now always verified.
//! A future build/install-time escape hatch, if ever needed, must live behind
//! `cfg(debug_assertions)` — never in the runtime argument surface (L2-4).
//!
//! Unknown arguments are **logged at `LOG_ERR`**, not silently debug-logged: a
//! near-miss `timeout=`, a misspelled flag, or a stale `noverifypin` must be visible
//! at the default log level. `timeout=` outside the accepted range is likewise
//! `LOG_ERR` and ignored (the config/default applies), never honoured as an
//! unbounded value. Parsing never panics.

use wsl_webauthn_protocol::DEFAULT_AUTH_TIMEOUT_SECS;

use crate::bindings::LOG_ERR;
use crate::logger;

/// Upper bound for an operator-supplied `timeout=<secs>`.
///
/// The whole authentication is a 1–3 s Windows Hello gesture; a value above this is
/// far more likely to be a typo (`timeout=6000`) or a denial-of-service knob than a
/// deliberate setting, so an out-of-range value is rejected rather than honoured
/// unboundedly (L2-7).
pub const MAX_TIMEOUT_SECS: u64 = 600;

/// Parsed module arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ModuleArgs {
    /// `debug`.
    pub debug: bool,
    /// `timeout=<secs>`, when supplied and valid.
    pub timeout_secs: Option<u64>,
}

/// Parse module arguments.
///
/// `raw` are the strings as delivered to `pam_sm_authenticate`. Invalid or unknown
/// tokens are reported at `LOG_ERR` and ignored; they never change the decision.
pub fn parse(raw: &[String]) -> ModuleArgs {
    let mut args = ModuleArgs::default();
    for arg in raw {
        match arg.as_str() {
            "debug" => args.debug = true,
            other => {
                if let Some((key, value)) = other.split_once('=') {
                    if key == "timeout" {
                        match value.parse::<u64>() {
                            Ok(secs) if (1..=MAX_TIMEOUT_SECS).contains(&secs) => {
                                args.timeout_secs = Some(secs);
                            }
                            Ok(secs) => logger::auth(
                                LOG_ERR,
                                &format!(
                                    "invalid timeout argument {other:?}: {secs} is outside \
                                     1..={MAX_TIMEOUT_SECS}; ignoring it"
                                ),
                            ),
                            Err(_) => logger::auth(
                                LOG_ERR,
                                &format!(
                                    "invalid timeout argument {other:?}: not a number; ignoring it"
                                ),
                            ),
                        }
                    } else {
                        logger::auth(
                            LOG_ERR,
                            &format!("ignoring unknown module argument: {other:?}"),
                        );
                    }
                } else {
                    logger::auth(
                        LOG_ERR,
                        &format!("ignoring unknown module argument: {other:?}"),
                    );
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
    fn debug_parses() {
        let a = parse(&s(&["debug"]));
        assert!(a.debug);
        assert_eq!(a.timeout_secs, None);
    }

    #[test]
    fn timeout_parses_within_range() {
        assert_eq!(parse(&s(&["timeout=30"])).timeout_secs, Some(30));
        assert_eq!(parse(&s(&["timeout=1"])).timeout_secs, Some(1));
        assert_eq!(
            parse(&s(&[&format!("timeout={MAX_TIMEOUT_SECS}")])).timeout_secs,
            Some(MAX_TIMEOUT_SECS)
        );
    }

    #[test]
    fn timeout_out_of_range_or_malformed_is_ignored() {
        // Zero, non-numeric, empty, and the previously-unbounded u64::MAX all fall
        // back to the config/default rather than being honoured.
        assert_eq!(parse(&s(&["timeout=0"])).timeout_secs, None);
        assert_eq!(parse(&s(&["timeout=abc"])).timeout_secs, None);
        assert_eq!(parse(&s(&["timeout="])).timeout_secs, None);
        assert_eq!(parse(&s(&["timeout=-1"])).timeout_secs, None);
        assert_eq!(
            parse(&s(&["timeout=99999999999999999999"])).timeout_secs,
            None
        );
        assert_eq!(
            parse(&s(&[&format!("timeout={}", MAX_TIMEOUT_SECS + 1)])).timeout_secs,
            None
        );
        assert_eq!(
            parse(&s(&[&format!("timeout={}", u64::MAX)])).timeout_secs,
            None
        );
    }

    #[test]
    fn unknown_and_removed_args_are_ignored() {
        let a = parse(&s(&["bogus", "foo=bar", "=x", "timeout=5"]));
        assert!(!a.debug);
        assert_eq!(a.timeout_secs, Some(5));
        // `noverifypin` is no longer an argument; it must not silently do anything.
        assert_eq!(parse(&s(&["noverifypin"])), ModuleArgs::default());
        assert_eq!(parse(&s(&["no_verify_pin"])), ModuleArgs::default());
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
