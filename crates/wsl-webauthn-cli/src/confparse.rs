//! Tiny parsers for the external text the installer consumes.
//!
//! Both parsers are pure functions over a byte/string input, and every consumer passes an
//! injectable path. Only the minimal grammar the installer needs is implemented; there is
//! no general INI parser and no shell interpolation anywhere.

use std::path::PathBuf;

/// Extract the Windows mount root from `/etc/wsl.conf`.
///
/// Only the `[automount]` section's `root=` key is honored: a `root=` appearing in
/// any other section is ignored, because otherwise an unrelated `[network]` section
/// could silently redirect the installer's DrvFs paths. Rules:
///
/// * CRLF- and BOM-tolerant; lines are trimmed.
/// * `#` and `;` start a comment.
/// * Values may be single- or double-quoted.
/// * A trailing `/` is stripped (except for a bare `/`).
/// * `root=/` is recognized as a real value (the root of the automounted drive),
///   not treated as "unset".
/// * An empty value, a missing `[automount]` section, or a missing key yields `None`
///   so the caller falls back to [`crate::DEFAULT_WIN_MNT`].
pub(crate) fn parse_win_mnt(text: &str) -> Option<PathBuf> {
    let mut in_automount = false;
    let mut value: Option<String> = None;

    for raw_line in text.lines() {
        let line = raw_line.trim_start_matches('\u{feff}').trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            in_automount = line
                .trim_start_matches('[')
                .split(']')
                .next()
                .map(|s| s.trim().eq_ignore_ascii_case("automount"))
                .unwrap_or(false);
            continue;
        }
        if !in_automount {
            continue;
        }
        let Some((key, val)) = line.split_once('=') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("root") {
            value = Some(unquote(val.trim()));
        }
    }

    let value = value?;
    if value.is_empty() {
        return None;
    }
    // Normalize a trailing slash (but keep a bare "/").
    let normalized = if value.len() > 1 {
        value.trim_end_matches('/')
    } else {
        value.as_str()
    };
    if normalized.is_empty() {
        return None;
    }
    Some(PathBuf::from(normalized))
}

/// Strip one layer of matching single/double quotes.
fn unquote(value: &str) -> String {
    let bytes = value.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
    {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

/// Normalize a `%LOCALAPPDATA%` command output into a Windows path string.
///
/// `cmd.exe /c echo %LOCALAPPDATA%` on Windows emits CRLF. Returns `None` for output that
/// is empty/whitespace only, or that clearly is an unconverted variable echo
/// (`%LOCALAPPDATA%` — cmd.exe prints it back when the variable is undefined).
pub(crate) fn parse_local_appdata(raw: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(raw);
    let trimmed = text.trim_matches(|c: char| c == '\r' || c == '\n' || c.is_whitespace());
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.contains('%') {
        // Undefined variable: `echo` prints the literal `%LOCALAPPDATA%`.
        return None;
    }
    Some(trimmed.to_string())
}

/// Join a Windows directory string with extra components, producing a Windows-style
/// path (`\`-separated) suitable for translation to `/mnt/<drive>/...` on WSL.
pub(crate) fn windows_join(base: &str, parts: &[&str]) -> String {
    let mut out = base.trim_end_matches(['\\', '/']).to_string();
    for part in parts {
        out.push('\\');
        out.push_str(part.trim_matches(['\\', '/']));
    }
    out
}

/// Translate a Windows path (`C:\Users\alice\...`) into its WSL DrvFs form
/// (`/mnt/c/Users/alice/...`), using `win_mnt` as the mount root for the drive letter.
///
/// Only drive-letter paths are translated; anything else (a UNC path, a relative
/// path) is returned unchanged so the caller can report it clearly.
pub(crate) fn windows_to_wsl(path: &str, win_mnt: &std::path::Path) -> PathBuf {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        let drive = (bytes[0] as char).to_ascii_lowercase();
        let rest = path[2..].replace('\\', "/");
        let rest = rest.trim_start_matches('/');
        // Map the drive letter to `win_mnt`: `/mnt/c` for `C:`, `/mnt/d` for `D:`.
        let root = match win_mnt.file_name().and_then(|n| n.to_str()) {
            Some(letter)
                if letter.len() == 1
                    && letter
                        .chars()
                        .next()
                        .is_some_and(|c| c.eq_ignore_ascii_case(&drive)) =>
            {
                win_mnt.to_path_buf()
            }
            _ => {
                // A non-standard mount (e.g. `/mnt/windows`): derive the drive root by
                // replacing the final component when it matches the drive letter,
                // otherwise fall back to `<win_mnt>/<drive>`.
                win_mnt.join(drive.to_string())
            }
        };
        root.join(rest)
    } else {
        PathBuf::from(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn win_mnt_basic() {
        let text = "[automount]\nenabled=true\nroot=/mnt/d\n";
        assert_eq!(parse_win_mnt(text), Some(PathBuf::from("/mnt/d")));
    }

    #[test]
    fn win_mnt_crlf_and_bom() {
        let text = "\u{feff}[automount]\r\nroot = /mnt/e\r\n";
        assert_eq!(parse_win_mnt(text), Some(PathBuf::from("/mnt/e")));
    }

    #[test]
    fn win_mnt_trailing_slash_stripped() {
        let text = "[automount]\nroot=/mnt/windows/\n";
        assert_eq!(parse_win_mnt(text), Some(PathBuf::from("/mnt/windows")));
    }

    #[test]
    fn win_mnt_root_slash_preserved() {
        let text = "[automount]\nroot=/\n";
        assert_eq!(parse_win_mnt(text), Some(PathBuf::from("/")));
    }

    #[test]
    fn win_mnt_missing_section_is_none() {
        assert_eq!(parse_win_mnt("[network]\nroot=/mnt/x\n"), None);
        assert_eq!(parse_win_mnt(""), None);
    }

    #[test]
    fn win_mnt_root_in_other_section_ignored() {
        let text = "[network]\nroot=/mnt/wrong\n[automount]\nroot=/mnt/right\n";
        assert_eq!(parse_win_mnt(text), Some(PathBuf::from("/mnt/right")));
        // And the reverse order: a later [network] must not override.
        let text = "[automount]\nroot=/mnt/right\n[network]\nroot=/mnt/wrong\n";
        assert_eq!(parse_win_mnt(text), Some(PathBuf::from("/mnt/right")));
    }

    #[test]
    fn win_mnt_comments_and_quotes() {
        let text = "[automount]\n# root=/mnt/nope\nroot = \"/mnt/q\"\n";
        assert_eq!(parse_win_mnt(text), Some(PathBuf::from("/mnt/q")));
    }

    #[test]
    fn win_mnt_empty_value_is_none() {
        assert_eq!(parse_win_mnt("[automount]\nroot=\n"), None);
    }

    #[test]
    fn local_appdata_strips_crlf() {
        assert_eq!(
            parse_local_appdata(b"C:\\Users\\alice\\AppData\\Local\r\n"),
            Some("C:\\Users\\alice\\AppData\\Local".to_string())
        );
    }

    #[test]
    fn local_appdata_empty_is_none() {
        assert_eq!(parse_local_appdata(b"\r\n"), None);
        assert_eq!(parse_local_appdata(b""), None);
    }

    #[test]
    fn local_appdata_unexpanded_is_none() {
        assert_eq!(parse_local_appdata(b"%LOCALAPPDATA%\r\n"), None);
    }

    #[test]
    fn windows_join_and_translate() {
        let joined = windows_join("C:\\Users\\alice\\AppData\\Local", &["Programs", "x"]);
        assert_eq!(joined, "C:\\Users\\alice\\AppData\\Local\\Programs\\x");
        let wsl = windows_to_wsl(&joined, Path::new("/mnt/c"));
        assert_eq!(
            wsl,
            PathBuf::from("/mnt/c/Users/alice/AppData/Local/Programs/x")
        );
    }

    #[test]
    fn windows_to_wsl_handles_other_mount_and_letters() {
        assert_eq!(
            windows_to_wsl("D:\\data\\x.exe", Path::new("/mnt/d")),
            PathBuf::from("/mnt/d/data/x.exe")
        );
        // Non-drive path is returned unchanged.
        assert_eq!(
            windows_to_wsl("\\\\server\\share", Path::new("/mnt/c")),
            PathBuf::from("\\\\server\\share")
        );
    }
}
