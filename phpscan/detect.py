"""PHP presence markers and version extraction from HTTP responses."""
from __future__ import annotations

import re

# "PHP/8.2.12", "PHP/7.4.33-1+deb11u5", "PHP/8.1.2-1ubuntu2.14" in X-Powered-By or Server headers.
HEADER_VERSION_RE = re.compile(r"\bPHP/(\d+\.\d+\.\d+[^\s,;()]*)", re.I)

# phpinfo() output: <h1 class="p">PHP Version 8.2.12</h1>, or the table row
# <td class="e">PHP Version </td><td class="v">8.2.12 </td>
PHPINFO_VERSION_RE = re.compile(
    r"PHP Version\s*(?:</[a-z0-9]+>\s*<[a-z0-9]+[^>]*>\s*)?(\d+\.\d+\.\d+[^\s<]*)", re.I
)
# Newer phpinfo() titles: <title>PHP 8.3.4 - phpinfo()</title>
PHPINFO_TITLE_RE = re.compile(r"<title>\s*PHP\s+(\d+\.\d+\.\d+[^\s<]*)\s*-\s*phpinfo\(\)", re.I)

UPSTREAM_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(.*)$")

# Cookies that only PHP applications set.
PHP_COOKIES = {
    "phpsessid": "cookie PHPSESSID",
    "laravel_session": "cookie laravel_session (Laravel)",
    "ci_session": "cookie ci_session (CodeIgniter)",
    "symfony": "cookie symfony",
}
PHP_COOKIE_PATTERNS = [
    (re.compile(r"^S?SESS[0-9a-f]{32}$", re.I), "Drupal session cookie"),
    (re.compile(r"^wordpress_|^wp-settings-", re.I), "WordPress cookie"),
]

# Body markers that point to PHP but carry no version.
PHP_BODY_MARKERS = [
    (re.compile(r"<b>(?:Fatal error|Warning|Notice|Deprecated|Parse error)</b>:.{0,400}? on line <b>\d+</b>", re.I | re.S),
     "PHP error message in body"),
    (re.compile(r"/wp-(?:content|includes)/", re.I), "WordPress paths in body"),
    (re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'](?:WordPress|Drupal|Joomla|TYPO3|MediaWiki|phpBB)', re.I),
     "CMS generator meta tag"),
    (re.compile(r'(?:href|src|action)=["\'][^"\'#?]*\.php(?:[?#"\'])', re.I), ".php links in body"),
]

# Headers that point to PHP software but carry no PHP version.
PHP_HEADER_MARKERS = {
    "x-pingback": "X-Pingback header (WordPress)",
    "x-drupal-cache": "X-Drupal-Cache header",
    "x-drupal-dynamic-cache": "X-Drupal-Dynamic-Cache header",
    "x-generator": None,  # only if value names a PHP CMS, see below
}
PHP_GENERATORS = re.compile(r"Drupal|WordPress|Joomla|TYPO3|Contao|Shopware|Magento", re.I)


def parse_version(version: str) -> tuple[tuple[int, int, int], str] | None:
    """Split "8.1.2-1ubuntu2.14" into ((8, 1, 2), "-1ubuntu2.14")."""
    m = UPSTREAM_RE.match(version.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))), m.group(4)


def load_patched(path: str) -> set[tuple[int, int, int]]:
    patched = set()
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parsed = parse_version(line)
            if not parsed:
                raise ValueError(f"{path}: cannot parse version {line!r}")
            patched.add(parsed[0])
    return patched


def is_patched(version: str, patched: set[tuple[int, int, int]]) -> bool:
    """Exact match on the upstream x.y.z part; "8.2.3" never matches "8.2.35"."""
    parsed = parse_version(version)
    return bool(parsed) and parsed[0] in patched


def analyze_response(headers: list[tuple[str, str]], body: str) -> list[tuple[str, str | None]]:
    """Return (source, version-or-None) findings for one HTTP response."""
    found: list[tuple[str, str | None]] = []

    for name, value in headers:
        lname = name.lower()
        if lname in ("x-powered-by", "server"):
            label = "X-Powered-By" if lname == "x-powered-by" else "Server"
            versions = HEADER_VERSION_RE.findall(value)
            for v in versions:
                found.append((f"{label} header", v))
            if not versions and re.search(r"\bPHP\b", value, re.I):
                found.append((f"{label} header (version hidden)", None))
        elif lname == "set-cookie":
            cookie = value.split("=", 1)[0].strip()
            label = PHP_COOKIES.get(cookie.lower())
            if not label:
                label = next((l for rx, l in PHP_COOKIE_PATTERNS if rx.search(cookie)), None)
            if label:
                found.append((label, None))
        elif lname == "x-generator":
            if PHP_GENERATORS.search(value):
                found.append((f"X-Generator header ({value.strip()[:40]})", None))
        elif lname in PHP_HEADER_MARKERS and PHP_HEADER_MARKERS[lname]:
            found.append((PHP_HEADER_MARKERS[lname], None))

    if "phpinfo()" in body:
        m = PHPINFO_TITLE_RE.search(body) or PHPINFO_VERSION_RE.search(body)
        if m:
            found.append(("phpinfo() page", m.group(1)))

    for rx, label in PHP_BODY_MARKERS:
        if rx.search(body):
            found.append((label, None))

    return found
