import errno
import re
import socket
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor

import pytest

from phpscan import probe
from phpscan.models import PortResult
from phpscan.probe import Config, fetch, probe_php, scan_port, scan_vhost
from testserver import PHPTestServer, PHPWebsite


@pytest.mark.parametrize("version", ["8.2.35", "7.4.33-1+deb11u5", "5.4.16"])
def test_probe_php_detects_configured_header_version(
    php_server: Callable[..., PHPTestServer], version: str,
) -> None:
    server = php_server(PHPWebsite(version))

    evidence = probe_php("http", server.ip, server.port, Config(timeout=1))

    assert [(item.source, item.version) for item in evidence] == [
        ("X-Powered-By header", version),
    ]
    assert [request.path for request in server.requests] == ["/"]


def test_probe_php_falls_back_to_phpinfo(
    php_server: Callable[..., PHPTestServer],
) -> None:
    server = php_server(PHPWebsite("8.4.27", version_header=None))

    evidence = probe_php("http", server.ip, server.port, Config(timeout=1))

    assert [(item.source, item.version) for item in evidence] == [
        ("phpinfo() page", "8.4.27"),
    ]
    paths = [request.path for request in server.requests]
    assert paths[:2] == ["/", "/index.php"]
    assert re.fullmatch(r"/[^/]+\.php", paths[2])
    assert paths[2] not in probe.PHPINFO_PATHS
    assert paths[3:] == ["/phpinfo.php"]


def test_fetch_keeps_duplicate_headers_and_limits_body(
    php_server: Callable[..., PHPTestServer],
) -> None:
    website = PHPWebsite(
        "8.3.36",
        body="abcdefghij",
        extra_headers=(("X-Test", "one"), ("X-Test", "two")),
    )
    server = php_server(website)

    response = fetch("http", server.ip, server.port, "/", Config(timeout=1, max_body=4))

    assert response is not None
    assert response.body == "abcd"
    assert [value for name, value in response.headers if name.lower() == "x-test"] == ["one", "two"]


@pytest.mark.parametrize("tls_first", [False, True], ids=["plain-first", "tls-first"])
def test_scan_port_detects_https_and_default_certificate(
    php_server: Callable[..., PHPTestServer], monkeypatch: pytest.MonkeyPatch, tls_first: bool,
) -> None:
    # A vhost with its own certificate makes sure the default one is fetched without SNI.
    server = php_server(PHPWebsite("8.2.35"), vhosts={"new.example.test": PHPWebsite("8.4.27")}, tls=True)
    if tls_first:
        # The OS-assigned port is never 443/8443, so mark it as a TLS-first port.
        monkeypatch.setattr(probe, "TLS_FIRST_PORTS", frozenset({server.port}))

    result = scan_port(server.ip, server.port, Config(timeout=1))

    assert result.state == "open"
    assert result.scheme == "https"
    assert result.error is None
    assert result.cert is not None
    assert result.cert.subject_cn == "localhost"
    assert server.ip in result.cert.san_ips
    assert [(item.source, item.version) for item in result.evidence] == [
        ("X-Powered-By header", "8.2.35"),
    ]
    assert server.requests
    assert all(request.sni is None for request in server.requests)


def test_scan_vhost_uses_host_header_and_sni_without_mutating_port_result(
    php_server: Callable[..., PHPTestServer],
) -> None:
    server = php_server(
        PHPWebsite("8.1.31"),
        vhosts={"new.example.test": PHPWebsite("8.4.27")},
        tls=True,
    )
    port_result = PortResult(server.port, "open", scheme="https")

    evidence = scan_vhost(server.ip, port_result, "new.example.test", Config(timeout=1))

    assert [(item.source, item.version) for item in evidence] == [
        ("X-Powered-By header", "8.4.27"),
    ]
    assert evidence[0].location.endswith("(Host: new.example.test)")
    assert port_result.evidence == []
    assert port_result.vhosts_checked == []
    request = server.requests[-1]
    assert request.host == "new.example.test"
    assert request.sni == "new.example.test"


# --------------------------------------------------------------------------- port states

def _free_port() -> int:
    """A port that was just free on 127.0.0.1 (nothing listens on it afterwards)."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def silent_port() -> Iterator[int]:
    """A port that completes the TCP handshake (kernel backlog) but never answers."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(16)
        yield sock.getsockname()[1]


def _ipv6_loopback_available() -> bool:
    try:
        with socket.socket(socket.AF_INET6) as sock:
            sock.bind(("::1", 0))
        return True
    except OSError:
        return False


def test_scan_port_closed_port() -> None:
    result = scan_port("127.0.0.1", _free_port(), Config(timeout=1))

    assert result.state == "closed"
    assert result.scheme is None
    assert result.error == "connection refused"
    assert result.evidence == []


def test_scan_port_open_without_http_answer_is_bounded(silent_port: int) -> None:
    timeout = 0.5
    started = time.monotonic()

    result = scan_port("127.0.0.1", silent_port, Config(timeout=timeout))

    elapsed = time.monotonic() - started
    assert result.state == "open"
    assert result.scheme is None
    assert result.cert is None
    assert result.error
    assert result.evidence == []
    # HTTP attempt, TLS handshake and HTTPS attempt each wait at most `timeout`.
    assert elapsed < 6 * timeout


# --------------------------------------------------------------------------- IPv6

@pytest.mark.skipif(not _ipv6_loopback_available(), reason="no IPv6 loopback")
@pytest.mark.parametrize("tls", [False, True], ids=["http", "https"])
def test_scan_port_ipv6(php_server: Callable[..., PHPTestServer], tls: bool) -> None:
    server = php_server(PHPWebsite("8.3.36"), tls=tls, ip="::1")

    result = scan_port("::1", server.port, Config(timeout=1))

    assert result.state == "open"
    assert result.scheme == server.scheme
    assert [(item.source, item.version) for item in result.evidence] == [
        ("X-Powered-By header", "8.3.36"),
    ]
    assert result.evidence[0].location.startswith(f"{server.scheme}://[::1]:{server.port}/")
    if tls:
        assert result.cert is not None
        assert "::1" in result.cert.san_ips


# --------------------------------------------------------------------------- PHP markers without a version

def test_probe_php_hidden_header_then_phpinfo(php_server: Callable[..., PHPTestServer]) -> None:
    server = php_server(PHPWebsite("8.4.27", header_version=False))

    evidence = probe_php("http", server.ip, server.port, Config(timeout=1))

    assert [(item.source, item.version) for item in evidence] == [
        ("X-Powered-By header (version hidden)", None),
        ("phpinfo() page", "8.4.27"),
    ]
    assert server.requests[-1].path == "/phpinfo.php"


def test_probe_php_version_never_revealed_tries_all_phpinfo_paths(
    php_server: Callable[..., PHPTestServer],
) -> None:
    server = php_server(PHPWebsite(None, php_session=True))

    evidence = probe_php("http", server.ip, server.port, Config(timeout=1))

    assert sorted((item.source, item.version) for item in evidence) == [
        ("X-Powered-By header (version hidden)", None),
        ("cookie PHPSESSID", None),
    ]
    paths = [request.path for request in server.requests]
    assert paths[3:] == list(probe.PHPINFO_PATHS)


def test_scan_port_site_without_php(php_server: Callable[..., PHPTestServer]) -> None:
    server = php_server()  # default profile: no PHP header, no phpinfo

    result = scan_port(server.ip, server.port, Config(timeout=1))

    assert result.state == "open"
    assert result.scheme == "http"
    assert result.error is None
    assert result.evidence == []


# --------------------------------------------------------------------------- Config options

def test_probe_php_without_phpinfo_probe(php_server: Callable[..., PHPTestServer]) -> None:
    server = php_server(PHPWebsite("8.4.27", version_header=None))

    evidence = probe_php("http", server.ip, server.port, Config(timeout=1, phpinfo_probe=False))

    assert evidence == []
    paths = [request.path for request in server.requests]
    assert len(paths) == 3
    assert not set(paths) & set(probe.PHPINFO_PATHS)


@pytest.mark.parametrize("user_agent", [None, "custom-agent/2.0"])
def test_all_requests_send_configured_user_agent(
    php_server: Callable[..., PHPTestServer], user_agent: str | None,
) -> None:
    server = php_server(PHPWebsite("8.2.35"), tls=True)
    cfg = Config(timeout=1) if user_agent is None else Config(timeout=1, user_agent=user_agent)

    scan_port(server.ip, server.port, cfg)

    assert server.requests
    assert {request.user_agent for request in server.requests} == {cfg.user_agent}


def test_probe_php_requests_extra_paths_in_order(php_server: Callable[..., PHPTestServer]) -> None:
    server = php_server()
    cfg = Config(timeout=1, phpinfo_probe=False, extra_paths=("/app/status", "/admin/login.php"))

    probe_php("http", server.ip, server.port, cfg)

    paths = [request.path for request in server.requests]
    assert paths[:2] == ["/", "/index.php"]
    assert paths[3:] == ["/app/status", "/admin/login.php"]


# --------------------------------------------------------------------------- redirects

@pytest.mark.parametrize("target", ["/app/", "{origin}/app/"], ids=["relative", "absolute-same-origin"])
def test_fetch_follows_same_host_redirect(
    php_server: Callable[..., PHPTestServer], target: str,
) -> None:
    server = php_server(PHPWebsite("8.2.35", redirects=(("/", target),)))

    response = fetch("http", server.ip, server.port, "/", Config(timeout=1))

    assert response is not None
    assert response.status == 404  # /app/ is not a known page, but it was requested
    assert response.url == f"{server.origin}/app/"
    assert [request.path for request in server.requests] == ["/", "/app/"]


@pytest.mark.parametrize("target", ["http://elsewhere.example.test/", "http://127.0.0.1:1/"],
                         ids=["other-host", "same-ip-other-port"])
def test_redirect_to_other_origin_is_not_followed_but_analysed(
    php_server: Callable[..., PHPTestServer], target: str,
) -> None:
    server = php_server(PHPWebsite("8.0.30", redirects=(("/", target),)))

    evidence = probe_php("http", server.ip, server.port, Config(timeout=1))

    assert [(item.source, item.version) for item in evidence] == [("X-Powered-By header", "8.0.30")]
    assert evidence[0].location == f"{server.origin}/"
    assert [request.path for request in server.requests] == ["/"]


def test_fetch_stops_after_max_redirects(php_server: Callable[..., PHPTestServer]) -> None:
    server = php_server(PHPWebsite("8.2.35", redirects=(("/", "/"),)))

    response = fetch("http", server.ip, server.port, "/", Config(timeout=1, max_redirects=2))

    assert response is not None
    assert response.status == 302
    assert len(server.requests) == 3  # original request + 2 redirects


# --------------------------------------------------------------------------- tcp_state: timeout / error

class _UnmappedOSError(OSError):
    """OSError(errno, ...) is auto-mapped to subclasses such as ConnectionRefusedError.
    A subclass keeps a plain errno, like platforms that report errors that way."""


@pytest.mark.parametrize("exc, expected_state", [
    (ConnectionRefusedError(errno.ECONNREFUSED, "refused"), "closed"),
    (_UnmappedOSError(errno.ECONNREFUSED, "refused"), "closed"),
    (TimeoutError("timed out"), "timeout"),
    (TimeoutError(), "timeout"),
    (_UnmappedOSError(errno.ETIMEDOUT, "timed out"), "timeout"),
    (OSError(errno.EHOSTUNREACH, "No route to host"), "error"),
    (OSError(errno.ENETUNREACH, "Network is unreachable"), "error"),
], ids=["refused", "refused-errno", "timeout", "timeout-no-message", "timeout-errno",
        "host-unreachable", "net-unreachable"])
def test_tcp_state_maps_connection_errors(
    monkeypatch: pytest.MonkeyPatch, exc: OSError, expected_state: str,
) -> None:
    def fail(*_args, **_kwargs):
        raise exc

    monkeypatch.setattr(probe.socket, "create_connection", fail)

    state, error = probe.tcp_state("192.0.2.1", 80, 1)

    assert state == expected_state
    assert error  # always a non-empty detail for non-open states


@pytest.mark.parametrize("state_exc, state", [
    (TimeoutError("timed out"), "timeout"),
    (OSError(errno.EHOSTUNREACH, "No route to host"), "error"),
])
def test_scan_port_stops_after_failed_tcp_connect(
    monkeypatch: pytest.MonkeyPatch, state_exc: OSError, state: str,
) -> None:
    def fail(*_args, **_kwargs):
        raise state_exc

    def must_not_be_called(*_args, **_kwargs):
        raise AssertionError("no HTTP/TLS attempt expected after a failed TCP connect")

    monkeypatch.setattr(probe.socket, "create_connection", fail)
    monkeypatch.setattr(probe, "detect_scheme", must_not_be_called)

    result = scan_port("192.0.2.1", 443, Config(timeout=1))

    assert result.state == state
    assert result.scheme is None
    assert result.error
    assert result.evidence == []


# --------------------------------------------------------------------------- nginx "plain HTTP to HTTPS port"

def test_plain_http_answer_with_https_port_marker_is_not_treated_as_http(
    php_server: Callable[..., PHPTestServer],
) -> None:
    marker_page = (
        "<html><head><title>400 The plain HTTP request was sent to HTTPS port</title></head>"
        f"<body><center>{probe.HTTPS_PORT_MARKER}</center></body></html>"
    )
    server = php_server(PHPWebsite(None, version_header=None, expose_phpinfo=False, body=marker_page))

    result = scan_port(server.ip, server.port, Config(timeout=1))

    assert result.state == "open"
    assert result.scheme is None
    assert "TLS service" in (result.error or "")
    assert result.evidence == []


# --------------------------------------------------------------------------- fetch errors

def test_fetch_returns_none_on_network_error() -> None:
    assert fetch("http", "127.0.0.1", _free_port(), "/", Config(timeout=1)) is None


def test_fetch_https_against_plain_http_returns_none(php_server: Callable[..., PHPTestServer]) -> None:
    server = php_server(PHPWebsite("8.2.35"))  # plain HTTP

    assert fetch("https", server.ip, server.port, "/", Config(timeout=1)) is None


def test_fetch_rejects_unknown_scheme() -> None:
    with pytest.raises(ValueError):
        fetch("ftp", "127.0.0.1", 21, "/", Config(timeout=1))


# --------------------------------------------------------------------------- thread safety

def test_parallel_vhost_scans_keep_host_and_sni_apart(php_server: Callable[..., PHPTestServer]) -> None:
    vhosts = {f"v{i}.example.test": PHPWebsite(f"8.{i % 5}.{10 + i}") for i in range(6)}
    server = php_server(PHPWebsite("7.4.33"), vhosts=vhosts, tls=True)
    port_result = PortResult(server.port, "open", scheme="https")
    names = list(vhosts) * 3  # each name several times, all at once

    with ThreadPoolExecutor(max_workers=len(names)) as pool:
        results = list(pool.map(
            lambda name: scan_vhost(server.ip, port_result, name, Config(timeout=2)), names))

    for name, evidence in zip(names, results):
        assert [(item.source, item.version) for item in evidence] == [
            ("X-Powered-By header", vhosts[name].php_version),
        ]
        assert evidence[0].location.endswith(f"(Host: {name})")
    assert all(request.sni == request.host for request in server.requests)
    assert port_result.evidence == [] and port_result.vhosts_checked == []
