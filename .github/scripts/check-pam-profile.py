#!/usr/bin/env python3
"""Validate a pam-auth-update-expanded PAM configuration (plan §11 / SR-21).

The installer ships a pam-configs profile that uses the ``pam-auth-update``
"``end``" idiom:

    Auth:
            [success=end default=ignore]    pam_wsl_webauthn.so

``pam-auth-update`` rewrites ``end`` into an integer jump at package-install
time.  If that expansion is ever wrong the failure is silent and security
relevant — most famously, ``success=0`` is *not* "stay" but is parsed by
libpam as ``ignore`` (Linux-PAM parses control values with ``strtol`` and lets
``0`` through), which would make the module a no-op.  This script re-checks the
generated file on every CI run:

  (a) a real ``pam_wsl_webauthn.so`` line exists;
  (b) every bracket control token uses only valid libpam actions
      (``ignore``/``ok``/``done``/``bad``/``die``/``reset`` or a positive
      integer) — i.e. no literal ``end`` survived expansion;
  (c) the ``success=`` jump is >= 1 (guards the ``success=0 == ignore`` trap);
  (d) every ``value=action`` key is a real libpam return-value name.

Usage:
    check-pam-profile.py [FILE ...]     # default: /etc/pam.d/common-auth
    check-pam-profile.py --profile PATH # validate a pam-configs profile source
    check-pam-profile.py --self-test    # run the committed fixtures

Exit status is 0 only when every checked file passes.  No third-party deps.
"""

from __future__ import annotations

import argparse
import os
import re
import sys

# --- libpam facts (mirrored from _pam_types.h; do not invent) ---------------

# Linux-PAM return-value names accepted as keys in a bracket control token.
RETURN_VALUES = frozenset(
    {
        "success",
        "open_err",
        "symbol_err",
        "service_err",
        "system_err",
        "buf_err",
        "perm_denied",
        "auth_err",
        "cred_insufficient",
        "authinfo_unavail",
        "user_unknown",
        "maxtries",
        "new_authtok_reqd",
        "acct_expired",
        "session_err",
        "cred_unavail",
        "cred_expired",
        "cred_err",
        "no_module_data",
        "conv_err",
        "authtok_err",
        "authtok_recover_err",
        "authtok_lock_busy",
        "authtok_disable_aging",
        "try_again",
        "ignore",
        "abort",
        "authtok_expired",
        "module_unknown",
        "bad_item",
        "conv_again",
        "incomplete",
        "default",
    }
)

# Bracket control-token actions.  `ignore` is special-cased by libpam, the
# other five are the documented keyword actions.
KEYWORD_ACTIONS = frozenset({"ignore", "ok", "done", "bad", "die", "reset"})

# Control keywords valid *without* brackets on the module line.
CONTROL_KEYWORDS = frozenset({"required", "requisite", "sufficient", "optional", "include", "substack"})

MODULE = "pam_wsl_webauthn.so"

# pam-auth-update's own idiom, only valid in a *profile source* file.
PROFILE_END = "end"

TOKEN_RE = re.compile(r"^(?P<key>[A-Za-z_][A-Za-z0-9_]*)(?:=(?P<val>[^\s=\[\]]+))?$")
LINE_RE = re.compile(r"^(?P<type>[a-z-]+)\s+(?P<rest>.*\S)\s*$")


class Problem(Exception):
    pass


def parse_control(rest: str):
    """Split a pam.d line into (control, module_and_args)."""
    rest = rest.strip()
    if rest.startswith("["):
        end = rest.find("]")
        if end < 0:
            raise Problem("unterminated bracket control token")
        return rest[: end + 1], rest[end + 1 :].strip()
    parts = rest.split(None, 1)
    return parts[0], (parts[1].strip() if len(parts) > 1 else "")


def validate_bracket(control: str) -> list[str]:
    """Return a list of problems found in a bracket control token."""
    problems: list[str] = []
    inner = control.strip()[1:-1].strip()
    tokens = inner.split()
    if not tokens:
        return ["empty bracket control token"]
    for token in tokens:
        m = TOKEN_RE.match(token)
        if not m:
            problems.append(f"malformed control field {token!r}")
            continue
        key = m.group("key")
        val = m.group("val")
        if key not in RETURN_VALUES:
            problems.append(f"unknown libpam return-value key {key!r} in token {token!r}")
        if val is not None:
            if val == PROFILE_END:
                problems.append(
                    f"literal 'end' survived pam-auth-update expansion in {token!r} "
                    "(the jump was not rewritten to an integer)"
                )
            elif val in KEYWORD_ACTIONS:
                pass
            elif val.isdigit():
                if int(val) <= 0:
                    problems.append(
                        f"non-positive control action {val!r} in {token!r}: "
                        "success=0 is parsed by libpam as 'ignore' (no-op)"
                    )
            else:
                problems.append(f"invalid control action {val!r} in token {token!r}")
    return problems


def check_common_auth(path: str) -> tuple[bool, list[str]]:
    """Validate an expanded /etc/pam.d/common-* file."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError as exc:
        return False, [f"cannot read {path}: {exc}"]

    problems: list[str] = []
    module_lineno: int | None = None
    module_control: str | None = None

    for lineno, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = LINE_RE.match(stripped)
        if not m:
            # Not a normal module line; flag only if it mentions our module.
            if MODULE in stripped:
                problems.append(f"{path}:{lineno}: could not parse line containing {MODULE}")
            continue
        rest = m.group("rest")
        try:
            control, target = parse_control(rest)
        except Problem as exc:
            problems.append(f"{path}:{lineno}: {exc}")
            continue
        if not target.startswith(MODULE):
            continue

        if module_lineno is not None:
            problems.append(f"{path}:{lineno}: duplicate {MODULE} line")
        module_lineno = lineno
        module_control = control

        if control.startswith("["):
            for p in validate_bracket(control):
                problems.append(f"{path}:{lineno}: {p}")
        elif control in CONTROL_KEYWORDS:
            problems.append(
                f"{path}:{lineno}: {MODULE} uses bare control keyword {control!r}; the "
                "profile must use a bracket token so failures are handled explicitly"
            )
        else:
            problems.append(f"{path}:{lineno}: invalid control {control!r} for {MODULE}")

    if module_lineno is None:
        problems.append(f"{path}: no {MODULE} line found after pam-auth-update expansion")

    # (c) explicitly: success jump >= 1 on the module line.
    if module_control and module_control.startswith("["):
        for token in module_control.strip()[1:-1].split():
            m = TOKEN_RE.match(token)
            if m and m.group("key") == "success" and m.group("val") is not None:
                val = m.group("val")
                if val.isdigit() and int(val) < 1:
                    problems.append(
                        f"{path}:{module_lineno}: expanded success jump is {val}; must be >= 1"
                    )
                elif val == PROFILE_END:
                    problems.append(
                        f"{path}:{module_lineno}: success jump is still {PROFILE_END!r}"
                    )

    return (not problems), problems


def check_profile_source(path: str) -> tuple[bool, list[str]]:
    """Sanity-check a /usr/share/pam-configs source file.

    The source is *allowed* (indeed expected) to contain ``end``; this mode
    only verifies the file is well-formed and carries the mandatory keys and
    the exact module line the installer relies on.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        return False, [f"cannot read {path}: {exc}"]

    problems: list[str] = []
    required = ("Name:", "Default:", "Priority:", "Auth-Type:", "Auth:")
    for key in required:
        if not re.search(rf"^{re.escape(key)}", text, re.MULTILINE):
            problems.append(f"{path}: missing required profile key {key!r}")
    if MODULE not in text:
        problems.append(f"{path}: profile does not reference {MODULE}")
    if "[success=end" not in text:
        problems.append(f"{path}: expected the '[success=end default=ignore]' idiom")
    # Only keys valid in a *source* profile are checked loosely here.
    m = re.search(r"^Auth:\s*\n(?P<lines>(?:\s+.*\n?)+)", text, re.MULTILINE)
    if not m:
        problems.append(f"{path}: could not find the Auth: block")
    else:
        for line in m.group("lines").splitlines():
            if MODULE in line and not line.strip().startswith("[success=end"):
                problems.append(f"{path}: unexpected Auth: module line {line.strip()!r}")
    return (not problems), problems


FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "scripts", "fixtures")


def self_test() -> int:
    base = os.path.normpath(FIXTURES)
    cases = [
        ("common-auth.sample", True),
        ("negative-end-survives.sample", False),
        ("negative-success-zero.sample", False),
        ("negative-bad-action.sample", False),
        ("negative-unknown-return-value.sample", False),
    ]
    failed = 0
    for name, expect_ok in cases:
        path = os.path.join(base, name)
        ok, problems = check_common_auth(path)
        status = "PASS" if ok else "FAIL"
        verdict = "ok" if ok == expect_ok else "UNEXPECTED"
        if ok != expect_ok:
            failed += 1
        print(f"[{verdict}] {name}: checker={status} expected={'PASS' if expect_ok else 'FAIL'}")
        for p in problems:
            print(f"           - {p}")
    print()
    if failed:
        print(f"self-test FAILED ({failed} unexpected result(s))")
        return 1
    print(f"self-test passed ({len(cases)} fixtures)")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*", help="expanded common-auth file(s) to check")
    ap.add_argument("--profile", metavar="PATH", help="validate a pam-configs profile source instead")
    ap.add_argument("--self-test", action="store_true", help="run the committed fixtures and exit")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if args.profile:
        ok, problems = check_profile_source(args.profile)
        for p in problems:
            print(f"error: {p}", file=sys.stderr)
        if ok:
            print(f"OK: {args.profile} is a well-formed pam-configs profile")
        return 0 if ok else 1

    files = args.files or ["/etc/pam.d/common-auth"]
    all_ok = True
    for path in files:
        ok, problems = check_common_auth(path)
        for p in problems:
            print(f"error: {p}", file=sys.stderr)
        if ok:
            print(f"OK: {path} passes the PAM profile guard")
        else:
            all_ok = False
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
