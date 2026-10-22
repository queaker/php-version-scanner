import pytest

from phpscan.detect import analyze_response, is_patched, load_patched, parse_version


@pytest.mark.parametrize("header, expected", [
    (("X-Powered-By", "PHP/8.2.35"), "8.2.35"),
    (("X-Powered-By", "PHP/7.4.33-1+deb11u5"), "7.4.33-1+deb11u5"),
    (("X-Powered-By", "PHP/8.1.2-1ubuntu2.14"), "8.1.2-1ubuntu2.14"),
    (("X-Powered-By", "PHP/8.3.36, PleskLin"), "8.3.36"),
    (("Server", "Apache/2.4.38 (Debian) PHP/7.3.31-1~deb10u5 OpenSSL/1.1.1n"), "7.3.31-1~deb10u5"),
    (("Server", "Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16"), "5.4.16"),
])
def test_header_versions(header, expected):
    assert (f"{header[0]} header", expected) in analyze_response([header], "")


def test_header_php_without_version():
    assert analyze_response([("X-Powered-By", "PHP")], "") == [("X-Powered-By header (version hidden)", None)]


def test_non_php_powered_by_ignored():
    assert analyze_response([("X-Powered-By", "ASP.NET"), ("Server", "nginx/1.24.0")], "") == []


def test_cookies():
    found = analyze_response([("Set-Cookie", "PHPSESSID=abc; path=/"),
                              ("Set-Cookie", "SESS0123456789abcdef0123456789abcdef=x"),
                              ("Set-Cookie", "JSESSIONID=1")], "")
    assert ("cookie PHPSESSID", None) in found
    assert ("Drupal session cookie", None) in found
    assert len(found) == 2


@pytest.mark.parametrize("body, expected", [
    ('<title>phpinfo()</title><h1 class="p">PHP Version 8.4.27</h1>', "8.4.27"),
    ('<title>phpinfo()</title><tr><td class="e">PHP Version </td><td class="v">7.4.33-1+deb11u5 </td></tr>',
     "7.4.33-1+deb11u5"),
    ("<title>PHP 8.5.12 - phpinfo()</title>", "8.5.12"),
])
def test_phpinfo(body, expected):
    assert ("phpinfo() page", expected) in analyze_response([], body)


def test_php_version_text_without_phpinfo_is_ignored():
    assert analyze_response([], "<p>We require PHP Version 8.1.0 or later</p>") == []


def test_body_markers():
    body = ('<b>Warning</b>:  Undefined variable $x in <b>/var/www/index.php</b> on line <b>3</b>'
            '<link href="/wp-content/themes/x.css"><a href="/login.php">')
    sources = {s for s, _ in analyze_response([], body)}
    assert sources == {"PHP error message in body", "WordPress paths in body", ".php links in body"}


def test_parse_version():
    assert parse_version("8.1.2-1ubuntu2.14") == ((8, 1, 2), "-1ubuntu2.14")
    assert parse_version("8.1") is None


def test_is_patched_exact(patched):
    assert is_patched("8.2.35", patched)
    assert is_patched("8.2.35-1+deb12u1", patched)
    assert not is_patched("8.2.3", patched)
    assert not is_patched("8.2.350", patched)
    assert not is_patched("8.2.34", patched)
    assert not is_patched("garbage", patched)


def test_load_patched(tmp_path):
    f = tmp_path / "v.txt"
    f.write_text("8.5.12\n# comment\n\n8.2.35  # trailing\n")
    assert load_patched(str(f)) == {(8, 5, 12), (8, 2, 35)}
    f.write_text("eight\n")
    with pytest.raises(ValueError):
        load_patched(str(f))
