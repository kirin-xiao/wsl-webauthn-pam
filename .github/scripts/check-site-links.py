#!/usr/bin/env python3
"""Guard the tree GitHub Pages serves: the docs site *and* the signed apt repo.

The published origin is one tree with two owners:

    /                               landing page (Zola, `web/public/index.html`)
    /docs/<slug>/                   the seven documentation pages
    /dists/, /pool/, /*.gpg         the signed apt repository
                                    (`.github/scripts/build-apt-repo.sh`)

Zola happily builds a site with a dead relative link, a `#fragment` that names
no `id`, a page that was renamed out of the docs set, or a `static/` file at
`pool/` that would land on top of the signed package index.  None of those fail
the build, and each one is only visible to a user *after* a deploy.  This
checker makes them fail in CI instead, against the built tree:

  (a) every internal `href`/`src` resolves to a file in the tree.  "Internal"
      covers relative references, site-absolute ones (`/docs/install/`) and
      absolute URLs on the site's own origin — which is what Zola's `get_url()`
      emits, so a real build is almost entirely absolute same-origin.  `mailto:`,
      other origins, protocol-relative `//host` and `#anchor` keep their old
      meaning (external, or in-page);
  (b) every in-page `#fragment` resolves to an `id`/`name` in the target
      document (`#` and `#top` are the browser's own no-op targets);
  (c) exactly the seven docs pages exist, each at `/docs/<slug>/`;
  (d) no generated path shadows an apt path (`dists/`, `pool/`, `*.gpg` at the
      root): the site must never be able to replace a signed index;
  (e) `web/content/docs/security.md` still carries `EXPECTED_INVARIANT_MARKERS`
      `<!-- INVARIANT: … -->` markers with unique ids, so a content/theme
      refactor cannot quietly drop a documented security invariant from the
      page that mirrors `SECURITY.md` (`check-doc-invariants.py` guards the
      invariant -> test mapping); and the **built** `docs/security/index.html`
      carries the same markers with the same ids, so an HTML minifier or a
      template cannot strip them from what users can actually read in
      "view source".

References into `/dists/`, `/pool/` and the archive keyring at the root are
"apt-provided": `build-apt-repo.sh` produces them when the tree is assembled
(`publish-pages.sh`), not Zola, so they are accepted by namespace instead of by
`stat` and counted separately in the summary.  Everything else must exist in the
built tree.

The origin the tree is served from is read, in this order, from `--base-url`,
from `base_url` in the `config.toml` next to the built tree (`web/config.toml`
for `web/public`), or from the `og:url`/`rel="canonical"` of the landing page.
Only scheme+host+port are compared, so an `http://` link to the right host is
still external.  The `base_url` path prefix (GitHub project pages serve a site
under `/<repo>/` rather than `/`) is stripped before the path is resolved
against the tree, so `https://<owner>.github.io/<repo>/docs/install/` maps to
`docs/install/index.html`.  A same-origin URL outside that prefix, or a path
whose `..` segments climb out of the root, is an error rather than a 404 nobody
notices until after a deploy.

Usage:
    check-site-links.py                    # check the built site (web/public)
    check-site-links.py DIR                # check another built site tree
    check-site-links.py --security-source PATH
    check-site-links.py --base-url URL     # override the site's published origin
    check-site-links.py --self-test        # exercise the checker on fixtures

Exit status is 0 only when every check passes.  No third-party deps.
"""

from __future__ import annotations

import argparse
import posixpath
import re
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import SplitResult, unquote, urlsplit

# The published docs set.  A page added to (or removed from) `web/content/docs/`
# must be a deliberate decision here too, because the site is linked from the
# install docs and from the README.
DOCS_PAGES = (
    "install",
    "how-it-works",
    "security",
    "usage",
    "troubleshooting",
    "faq",
    "prior-art",
)

# Paths the apt repository owns at the published root.  The site build must not
# produce them, and links to them are resolved by the assembly step, not Zola.
APT_ROOT_NAMES = ("dists", "pool")
ARCHIVE_KEYRING = "wsl-webauthn-pam-archive-keyring.gpg"

# The security page mirrors SECURITY.md, which carries 17 `<!-- INVARIANT: … -->`
# marker comments (holding 54 distinct ids).  The count is pinned so that a
# reworded/refactored page cannot silently lose a marker: dropping one is an
# explicit change to this constant, reviewed like any other doc invariant.
EXPECTED_INVARIANT_MARKERS = 17

# Same marker syntax `check-doc-invariants.py` uses, so the two agree on what
# counts as a marker.  Ids may be comma/space separated within one comment.
MARKER_RE = re.compile(r"<!--\s*INVARIANT:\s*(?P<ids>[A-Za-z0-9_,.\s\-]+?)\s*-->")
ID_SPLIT_RE = re.compile(r"[\s,]+")

DEFAULT_SITE = "web/public"
DEFAULT_SECURITY_SOURCE = "web/content/docs/security.md"
# Zola's config; `base_url` is the single place the published origin is declared.
DEFAULT_CONFIG = "web/config.toml"
BASE_URL_RE = re.compile(r"""^\s*base_url\s*=\s*["']([^"']*)["']""", re.MULTILINE)

# `#` (bare) and `#top` are handled by the browser itself; every other fragment
# must name a real target.
BROWSER_FRAGMENTS = frozenset({"", "top"})


# ---------------------------------------------------------------------------
# HTML scanning
# ---------------------------------------------------------------------------


class _DocumentParser(HTMLParser):
    """Collect `id`/`<a name>` targets, every `href`/`src`, and the page's URL."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: set[str] = set()
        self.refs: list[tuple[str, str, int]] = []
        # The page's own absolute URL (`og:url` / `rel="canonical"`), used only
        # as a fallback when no `config.toml` sits next to the built tree.
        self.page_url: str | None = None

    def handle_starttag(self, tag, attrs) -> None:
        seen: dict[str, str] = {}
        for name, value in attrs:
            if value is None:
                continue
            seen[name] = value
            if name == "id" or (tag == "a" and name == "name"):
                value = value.strip()
                if value:
                    self.ids.add(value)
            elif name in ("href", "src"):
                self.refs.append((name, value, self.getpos()[0]))

        if self.page_url is not None:
            return
        if tag == "meta" and "og:url" in (seen.get("property"), seen.get("name")):
            self.page_url = seen.get("content")
        elif tag == "link" and seen.get("rel") == "canonical":
            self.page_url = seen.get("href")

    def handle_startendtag(self, tag, attrs) -> None:
        # `<img src=... />` and friends: self-closing tags never reach
        # handle_starttag, so route them through the same collector.
        self.handle_starttag(tag, attrs)


def parse_document(path: Path) -> _DocumentParser:
    parser = _DocumentParser()
    parser.feed(path.read_text(encoding="utf-8", errors="replace"))
    parser.close()
    return parser


# ---------------------------------------------------------------------------
# The published origin
# ---------------------------------------------------------------------------


def _default_port(scheme: str) -> int | None:
    return {"http": 80, "https": 443}.get(scheme)


@dataclass(frozen=True)
class SiteBase:
    """Where the built tree is served: origin plus the path prefix it sits under.

    GitHub project pages serve the tree at `/<repo>/`, not `/`, and Zola bakes
    that prefix into every URL its `get_url()` produces.  `path` is the prefix
    with no trailing slash (`""` or `"/wsl-webauthn-pam"`), so the site root is
    `path + "/"`.
    """

    url: str
    scheme: str
    host: str
    port: int
    path: str

    def is_same_origin(self, parts: SplitResult) -> bool:
        try:
            port = parts.port
        except ValueError:
            return False
        if parts.scheme.lower() != self.scheme:
            return False
        if (parts.hostname or "").lower() != self.host:
            return False
        return (port or _default_port(self.scheme)) == self.port

    def strip_prefix(self, path: str) -> str | None:
        """Map a same-origin path onto a site-absolute one; None if outside."""
        if not self.path:
            return path
        if path == self.path:
            return "/"
        if path.startswith(self.path + "/"):
            return path[len(self.path):]
        return None


def parse_base_url(value: str | None) -> SiteBase | None:
    """Parse an http(s) base URL, keeping the path prefix separate from the origin."""
    if not value:
        return None
    try:
        parts = urlsplit(value.strip())
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if scheme not in ("http", "https") or not host:
        return None
    return SiteBase(
        url=value.strip(),
        scheme=scheme,
        host=host,
        port=port if port is not None else (_default_port(scheme) or 0),
        path=parts.path.rstrip("/"),
    )


def _config_base_url(path: Path) -> str | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    match = BASE_URL_RE.search(text)
    return match.group(1) if match else None


def detect_base_url(site: Path, explicit: str | None = None) -> tuple[SiteBase | None, str]:
    """Find the origin the tree is served from; returns ``(base, where it came from)``.

    The site's `base_url` is declared once, in `web/config.toml`; everything else
    here only recovers it, so a repository rename or a custom domain is a
    one-line change there.
    """
    if explicit:
        base = parse_base_url(explicit)
        origin = "--base-url" if base else f"--base-url {explicit!r} (not an http(s) URL)"
        return (base, origin)

    candidates = (
        site.parent / "config.toml",          # web/public -> web/config.toml
        site.parent.parent / "config.toml",
        Path(DEFAULT_CONFIG),                  # the repository's own site config
    )
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen or not candidate.is_file():
            continue
        seen.add(candidate)
        base = parse_base_url(_config_base_url(candidate))
        if base is not None:
            return (base, f"{candidate}: base_url")

    landing = site / "index.html"
    if landing.is_file():
        base = parse_base_url(parse_document(landing).page_url)
        if base is not None:
            return (base, "og:url/canonical on index.html")

    return (None, "not found")


# ---------------------------------------------------------------------------
# Reference classification
# ---------------------------------------------------------------------------


def _apt_provided(rel: str) -> bool:
    """True for a path the assembled apt root provides (not the site build)."""
    return rel.split("/", 1)[0] in APT_ROOT_NAMES or rel == ARCHIVE_KEYRING


def resolve_reference(
    site: Path, doc_rel: str, ref: str, base: SiteBase | None = None
) -> tuple[str, str | None, str | None]:
    """Classify one `href`/`src` against the built tree.

    Returns ``(kind, path, fragment)`` where kind is one of ``external``,
    ``apt``, ``file`` (path is the resolved file, site-relative), ``missing``
    (path is the first candidate tried), ``outside`` (a same-origin URL outside
    the site's base path) or ``escape`` (the path climbed out of the root).
    """
    raw = ref.strip()
    try:
        parts = urlsplit(raw)
    except ValueError:
        return ("missing", raw, None)

    if raw.startswith("//"):
        return ("external", None, None)

    if parts.scheme:
        # `mailto:`, `tel:`, or another origin: external, as before.  A URL on
        # our own origin is what Zola's `get_url()` emits, and it is internal.
        if base is None or not base.is_same_origin(parts):
            return ("external", None, None)
        path = unquote(parts.path) or "/"
        fragment = unquote(parts.fragment) or None
        inner = base.strip_prefix(path)
        if inner is None:
            return ("outside", path, fragment)
        path = inner
    else:
        path = unquote(parts.path)
        fragment = unquote(parts.fragment) or None

    doc_dir = posixpath.dirname(doc_rel)

    if path in ("", "."):
        rel = doc_rel
        want_dir = False
    else:
        joined = path.lstrip("/") if path.startswith("/") else posixpath.join(doc_dir, path)
        rel = posixpath.normpath(joined)
        want_dir = path.endswith("/")

    if rel == ".":
        rel = "index.html"
        want_dir = False

    # A `../` chain that climbs out of the site root can never be served, and
    # usually means a moved page whose relative links were not updated.
    if rel == ".." or rel.startswith("../"):
        return ("escape", rel, fragment)

    if _apt_provided(rel):
        return ("apt", rel, fragment)

    candidates = [f"{rel}/index.html"] if want_dir else [rel, f"{rel}/index.html"]
    for candidate in candidates:
        if (site / candidate).is_file():
            return ("file", candidate, fragment)
    return ("missing", candidates[0], fragment)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def check_links(
    site: Path, stats: dict[str, int], base: SiteBase | None = None
) -> list[str]:
    """Every internal href/src resolves and every #fragment names a target."""
    errors: list[str] = []
    pages = sorted(site.rglob("*.html"))
    stats["pages"] = len(pages)
    if not pages:
        return [f"no HTML page under {site}; build the site first (`make site`)"]

    ids: dict[Path, set[str]] = {}
    for page in pages:
        doc_rel = page.relative_to(site).as_posix()
        document = parse_document(page)
        ids[page] = document.ids

        for attr, value, line in document.refs:
            where = f"{doc_rel}:{line}"
            stats["refs"] += 1
            kind, target, fragment = resolve_reference(site, doc_rel, value, base)

            if kind == "external":
                stats["external"] += 1
                continue
            if kind == "apt":
                stats["apt"] += 1
                continue
            if kind == "escape":
                stats["broken"] += 1
                errors.append(f"{where}: {attr}={value!r} escapes the site root")
                continue
            if kind == "outside":
                stats["broken"] += 1
                prefix = (base.path if base else "") + "/"
                errors.append(
                    f"{where}: {attr}={value!r} is on the site's origin but outside "
                    f"{prefix} (base_url in {DEFAULT_CONFIG})"
                )
                continue
            if kind == "missing":
                stats["broken"] += 1
                errors.append(f"{where}: {attr}={value!r} does not resolve ({target} not found)")
                continue

            # kind == "file": an internal reference that names a real file.
            stats["internal"] += 1
            if not fragment or fragment in BROWSER_FRAGMENTS:
                continue
            if not target.endswith(".html"):
                # Fragments on non-HTML assets are the server's problem; the
                # checker only knows anchors in documents.
                continue
            target_page = site / target
            if target_page not in ids:
                ids[target_page] = parse_document(target_page).ids
            if fragment not in ids[target_page]:
                stats["broken"] += 1
                errors.append(
                    f"{where}: {attr}={value!r} names no id/name {fragment!r} in {target}"
                )
    return errors


def check_docs_pages(site: Path) -> list[str]:
    """Exactly the seven docs pages exist, each as /docs/<slug>/."""
    errors: list[str] = []
    docs = site / "docs"
    for slug in DOCS_PAGES:
        if not (docs / slug / "index.html").is_file():
            errors.append(f"docs page missing: /docs/{slug}/ (expected docs/{slug}/index.html)")
    if docs.is_dir():
        for child in sorted(docs.iterdir()):
            if child.is_dir() and (child / "index.html").is_file() and child.name not in DOCS_PAGES:
                errors.append(
                    f"unexpected docs page: /docs/{child.name}/ "
                    f"(the published set is exactly {', '.join(DOCS_PAGES)})"
                )
    return errors


def check_apt_collisions(site: Path) -> list[str]:
    """No generated path may shadow a path the apt repository owns."""
    errors: list[str] = []
    for name in APT_ROOT_NAMES:
        if (site / name).exists():
            errors.append(f"generated path /{name}/ collides with the apt repository root")
    for keyring in sorted(site.glob("*.gpg")):
        errors.append(f"generated path /{keyring.name} collides with the archive keyring path")
    return errors


def _marker_ids(text: str) -> tuple[list[str], int]:
    """Every `<!-- INVARIANT: … -->` marker id in `text`, in document order."""
    markers = list(MARKER_RE.finditer(text))
    ids: list[str] = []
    for marker in markers:
        for ident in ID_SPLIT_RE.split(marker.group("ids").strip()):
            if ident:
                ids.append(ident)
    return (ids, len(markers))


def check_invariants(security_source: Path) -> tuple[list[str], int, list[str]]:
    """The security page source keeps every invariant marker, each id once."""
    errors: list[str] = []
    if not security_source.is_file():
        return ([f"security page source not found: {security_source}"], 0, [])

    text = security_source.read_text(encoding="utf-8", errors="replace")
    ids, count = _marker_ids(text)

    if count != EXPECTED_INVARIANT_MARKERS:
        errors.append(
            f"{security_source}: {count} `<!-- INVARIANT: … -->` marker(s), "
            f"expected {EXPECTED_INVARIANT_MARKERS}; a content/theme refactor dropped "
            f"a documented security invariant"
        )
    duplicates = sorted({ident for ident in ids if ids.count(ident) > 1})
    if duplicates:
        errors.append(
            f"{security_source}: duplicate invariant id(s) {', '.join(duplicates)}; "
            f"each documented invariant may be marked only once"
        )
    return (errors, count, ids)


def check_published_invariants(
    site: Path, source_ids: list[str], source_count: int
) -> tuple[list[str], int]:
    """The *built* security page still carries the source's markers and ids.

    Zola minifies every generated page by default and `minify-html` drops HTML
    comments, so a source-only check would pass while the published page lost
    the markers.  This inspects the page a reader gets from "view source".
    """
    page = site / "docs" / "security" / "index.html"
    if not page.is_file():
        return ([f"built security page not found: {page}; build the site first"], 0)

    text = page.read_text(encoding="utf-8", errors="replace")
    ids, count = _marker_ids(text)
    errors: list[str] = []

    if count != source_count:
        errors.append(
            f"{page}: {count} `<!-- INVARIANT: … -->` marker(s) in the published page, "
            f"expected {source_count} (the source has that many); the HTML minifier or "
            f"a template dropped them"
        )

    duplicates = sorted({ident for ident in ids if ids.count(ident) > 1})
    if duplicates:
        errors.append(
            f"{page}: duplicate invariant id(s) {', '.join(duplicates)} in the "
            f"published page; each documented invariant may be published only once"
        )

    if ids != source_ids:
        missing = [ident for ident in source_ids if ident not in ids]
        extra = [ident for ident in ids if ident not in source_ids]
        detail = []
        if missing:
            detail.append(f"missing {', '.join(missing)}")
        if extra:
            detail.append(f"unexpected {', '.join(extra)}")
        if not detail:
            detail.append("same ids in a different order")
        errors.append(
            f"{page}: published invariant markers differ from "
            f"{DEFAULT_SECURITY_SOURCE}: {'; '.join(detail)}"
        )
    return (errors, count)


def check_site(
    site: Path, security_source: Path, base: SiteBase | None = None
) -> tuple[list[str], dict[str, int]]:
    """Run every check; returns (errors, stats)."""
    stats = {
        "pages": 0,
        "refs": 0,
        "internal": 0,
        "external": 0,
        "apt": 0,
        "broken": 0,
        "markers": 0,
        "published_markers": 0,
    }
    if not site.is_dir():
        return ([f"{site} is not a directory; build the site first (`make site`)"], stats)

    errors = check_links(site, stats, base)
    errors += check_docs_pages(site)
    errors += check_apt_collisions(site)
    marker_errors, stats["markers"], source_ids = check_invariants(security_source)
    errors += marker_errors
    if security_source.is_file():
        published_errors, stats["published_markers"] = check_published_invariants(
            site, source_ids, stats["markers"]
        )
        errors += published_errors
    return (errors, stats)


# ---------------------------------------------------------------------------
# --self-test: exercise the checker on synthetic trees.
# ---------------------------------------------------------------------------


# The origin the fixtures pretend to be served from.  It deliberately carries a
# path prefix, like a GitHub project page, so the prefix-stripping path is
# exercised by every fixture rather than only by the real build.
SELF_TEST_BASE = "https://example.test/project"


def _base_tree() -> dict[str, str]:
    """A minimal but realistic good tree: landing page + the seven docs pages.

    The landing page mixes relative, site-absolute and absolute same-origin
    references, because that is what a real Zola build emits.
    """
    files: dict[str, str] = {
        "index.html": (
            "<!doctype html><html><body>"
            '<a href="/docs/install/">install</a>'
            f'<a href="{SELF_TEST_BASE}/docs/usage/#title">usage</a>'
            f'<img src="{SELF_TEST_BASE}/img/logo%20wide.svg" alt="">'
            f'<link rel="canonical" href="{SELF_TEST_BASE}/">'
            '<a href="https://example.org/upstream">upstream</a>'
            '<a href="//cdn.example.org/also-not-here.js">proto-relative</a>'
            '<a href="mailto:security@example.org">mail</a>'
            '<a href="#top">top</a>'
            '<img src="/img/logo.svg" alt="">'
            "</body></html>"
        ),
        "img/logo.svg": "<svg/>",
        # Reached only through the percent-encoded URL above: without decoding
        # the path, `img/logo%20wide.svg` does not exist and the fixture fails.
        "img/logo wide.svg": "<svg/>",
    }
    for slug in DOCS_PAGES:
        cross = "" if slug == "faq" else '<a href="/docs/faq/#faq-id">faq</a>'
        anchor = '<h2 id="faq-id">q</h2>' if slug == "faq" else ""
        files[f"docs/{slug}/index.html"] = (
            '<!doctype html><html><body><h1 id="title">t</h1>'
            '<a href="/">home</a>'
            '<a href="#title">title</a>'
            '<a href="../install/">install</a>'
            '<a href="/wsl-webauthn-pam-archive-keyring.gpg">keyring</a>'
            '<a href="/dists/stable/InRelease">dists</a>'
            f"{anchor}{cross}"
            "</body></html>"
        )
    return files


def _markers(count: int) -> str:
    return "".join(f"<!-- INVARIANT: INV-{i:02d} -->\n" for i in range(count))


def self_test() -> int:
    tree = _base_tree()
    site_base = parse_base_url(SELF_TEST_BASE)
    assert site_base is not None
    good_markers = _markers(EXPECTED_INVARIANT_MARKERS)

    def broken_link(files: dict[str, str]) -> None:
        files["docs/install/index.html"] += '<a href="/docs/nope/">x</a>'

    def broken_anchor(files: dict[str, str]) -> None:
        files["docs/install/index.html"] += '<a href="#missing-anchor">x</a>'

    def broken_cross_page_anchor(files: dict[str, str]) -> None:
        files["index.html"] += '<a href="/docs/faq/#no-such-id">x</a>'

    def absolute_missing_page(files: dict[str, str]) -> None:
        # What Zola emits for a page that was renamed out of the docs set.
        files["index.html"] += f'<a href="{SELF_TEST_BASE}/docs/nope/">x</a>'

    def absolute_existing_page(files: dict[str, str]) -> None:
        files["index.html"] += f'<a href="{SELF_TEST_BASE}/docs/security/">security</a>'

    def absolute_bad_fragment(files: dict[str, str]) -> None:
        files["index.html"] += f'<a href="{SELF_TEST_BASE}/docs/faq/#no-such-id">x</a>'

    def absolute_other_origin(files: dict[str, str]) -> None:
        files["index.html"] += '<a href="https://cdn.example.org/nope/">x</a>'

    def absolute_outside_base_path(files: dict[str, str]) -> None:
        # Same origin as the site, but outside its `/project/` prefix: Pages
        # would serve that path from somebody else's site, so it cannot pass.
        files["index.html"] += '<a href="https://example.test/elsewhere/">x</a>'

    def dropped_published_marker(files: dict[str, str]) -> None:
        # The source is intact but the minifier/template dropped one marker from
        # the page a reader actually gets.
        page = files["docs/security/index.html"]
        files["docs/security/index.html"] = page.replace(
            "<!-- INVARIANT: INV-00 -->", "", 1
        )

    def reworded_published_marker(files: dict[str, str]) -> None:
        # Same number of markers, but one id changed: the count alone would pass.
        page = files["docs/security/index.html"]
        files["docs/security/index.html"] = page.replace(
            "<!-- INVARIANT: INV-01 -->", "<!-- INVARIANT: INV-99 -->", 1
        )

    def missing_docs_page(files: dict[str, str]) -> None:
        del files["docs/faq/index.html"]

    def extra_docs_page(files: dict[str, str]) -> None:
        files["docs/extra/index.html"] = "<html></html>"

    def escapes_root(files: dict[str, str]) -> None:
        files["index.html"] += '<a href="../../etc/passwd">x</a>'

    def shadows_pool(files: dict[str, str]) -> None:
        files["pool/main/w/wsl-webauthn-pam/example.deb"] = ""

    def shadows_dists(files: dict[str, str]) -> None:
        files["dists/stable/InRelease"] = ""

    def shadows_keyring(files: dict[str, str]) -> None:
        files[ARCHIVE_KEYRING] = ""

    def counts_add_up(stats: dict[str, int], _errors: list[str]) -> str | None:
        """The good tree classifies every reference exactly once."""
        if stats["broken"]:
            return f"the good tree reported {stats['broken']} broken reference(s)"
        accounted = stats["internal"] + stats["external"] + stats["apt"]
        if accounted != stats["refs"]:
            return f"{stats['refs']} reference(s), only {accounted} classified"
        if stats["internal"] == 0:
            return "no reference was resolved as internal; the check would be vacuous"
        return None

    def counts_delta(**delta: int) -> Callable[..., str | None]:
        """Assert a fixture moved the classification counts by exactly `delta`."""

        def verify(stats: dict[str, int], _errors: list[str]) -> str | None:
            good = seen_stats.get("good-tree")
            if good is None:
                return "the good-tree fixture must run before this one"
            for key, change in delta.items():
                want = good[key] + change
                if stats[key] != want:
                    return f"expected {key}={want} ({good[key]} {change:+d}), got {stats[key]}"
            return None

        return verify

    cases: list[
        tuple[str, dict[str, str], str | None, bool, Callable[..., str | None] | None]
    ] = [
        ("good-tree", tree, good_markers, True, counts_add_up),
        ("absolute-same-origin-existing-page", tree, good_markers, True, counts_delta(internal=1)),
        ("broken-internal-link", tree, good_markers, False, None),
        ("broken-self-anchor", tree, good_markers, False, None),
        ("broken-cross-page-anchor", tree, good_markers, False, None),
        ("absolute-same-origin-missing-page", tree, good_markers, False, None),
        ("absolute-same-origin-bad-fragment", tree, good_markers, False, None),
        ("absolute-other-origin-ignored", tree, good_markers, True, counts_delta(external=1)),
        ("absolute-outside-base-path", tree, good_markers, False, None),
        ("escape-site-root", tree, good_markers, False, None),
        ("missing-docs-page", tree, good_markers, False, None),
        ("extra-docs-page", tree, good_markers, False, None),
        ("shadow-pool", tree, good_markers, False, None),
        ("shadow-dists", tree, good_markers, False, None),
        ("shadow-root-keyring", tree, good_markers, False, None),
        (
            "too-few-markers",
            tree,
            _markers(EXPECTED_INVARIANT_MARKERS - 1),
            False,
            None,
        ),
        (
            "duplicate-marker-id",
            tree,
            _markers(EXPECTED_INVARIANT_MARKERS - 1) + "<!-- INVARIANT: INV-00 -->\n",
            False,
            None,
        ),
        ("dropped-published-marker", tree, good_markers, False, None),
        ("reworded-published-marker", tree, good_markers, False, None),
        ("missing-security-source", tree, None, False, None),
    ]
    edits = {
        "absolute-same-origin-existing-page": absolute_existing_page,
        "broken-internal-link": broken_link,
        "broken-self-anchor": broken_anchor,
        "broken-cross-page-anchor": broken_cross_page_anchor,
        "absolute-same-origin-missing-page": absolute_missing_page,
        "absolute-same-origin-bad-fragment": absolute_bad_fragment,
        "absolute-other-origin-ignored": absolute_other_origin,
        "absolute-outside-base-path": absolute_outside_base_path,
        "escape-site-root": escapes_root,
        "missing-docs-page": missing_docs_page,
        "extra-docs-page": extra_docs_page,
        "shadow-pool": shadows_pool,
        "shadow-dists": shadows_dists,
        "shadow-root-keyring": shadows_keyring,
        "dropped-published-marker": dropped_published_marker,
        "reworded-published-marker": reworded_published_marker,
    }

    failed = 0
    seen_stats: dict[str, dict[str, int]] = {}
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        for name, origin, markers, expect_ok, verify in cases:
            files = dict(origin)
            if markers is not None:
                # A real build copies the source markers into the published
                # page; the fixtures do the same, so the published-page check
                # is exercised by every case rather than only by the real tree.
                files["docs/security/index.html"] = files[
                    "docs/security/index.html"
                ].replace("</body>", markers + "</body>")
            edit = edits.get(name)
            if edit is not None:
                edit(files)

            site = tmp / name / "site"
            for relpath, body in files.items():
                target = site / relpath
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(body, encoding="utf-8")

            security = tmp / name / "security.md"
            if markers is not None:
                security.write_text(markers, encoding="utf-8")

            errors, stats = check_site(site, security, site_base)
            seen_stats[name] = stats
            problem = verify(stats, errors) if verify is not None else None
            ok = not errors and problem is None
            verdict = "ok" if ok == expect_ok else "UNEXPECTED"
            if ok != expect_ok:
                failed += 1
            print(f"[{verdict}] {name}: checker={'PASS' if ok else 'FAIL'} "
                  f"expected={'PASS' if expect_ok else 'FAIL'}")
            if ok != expect_ok:
                for report in errors:
                    print(f"           - {report}")
                if problem is not None:
                    print(f"           - {problem}")

    print()
    if failed:
        print(f"self-test FAILED ({failed} unexpected result(s))")
        return 1
    print(f"self-test passed ({len(cases)} fixtures)")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("site", nargs="?", default=DEFAULT_SITE,
                    help=f"built site tree to check (default: {DEFAULT_SITE})")
    ap.add_argument("--security-source", default=DEFAULT_SECURITY_SOURCE,
                    help=f"security page source with the invariant markers "
                         f"(default: {DEFAULT_SECURITY_SOURCE})")
    ap.add_argument("--base-url", default=None,
                    help="origin the tree is served from (default: base_url in the "
                         f"config.toml next to the tree, usually {DEFAULT_CONFIG}; "
                         "falls back to og:url/rel=canonical on index.html)")
    ap.add_argument("--self-test", action="store_true",
                    help="exercise the checker on synthetic trees and exit")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    site = Path(args.site)
    base, base_source = detect_base_url(site, args.base_url)
    errors, stats = check_site(site, Path(args.security_source), base)

    if base is None:
        origin = (
            f"base URL: unknown ({base_source}) — pass --base-url or restore base_url "
            f"in {DEFAULT_CONFIG}; absolute URLs were counted as external"
        )
    else:
        origin = f"base URL: {base.url} (from {base_source})"

    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        print(
            f"FAILED: {len(errors)} problem(s) in {site} "
            f"({stats['refs']} reference(s) across {stats['pages']} page(s), "
            f"{stats['broken']} broken internal reference(s))",
            file=sys.stderr,
        )
        print(f"  {origin}", file=sys.stderr)
        return 1

    print(
        f"OK: {stats['refs']} reference(s) across {stats['pages']} page(s) checked "
        f"({stats['internal']} resolved inside the tree, {stats['external']} external, "
        f"{stats['apt']} apt-provided), all {len(DOCS_PAGES)} docs pages present, "
        f"{stats['markers']} invariant markers intact in the source and "
        f"{stats['published_markers']} in the built security page, "
        f"no apt-path shadowing in {site}"
    )
    print(f"  {origin}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
