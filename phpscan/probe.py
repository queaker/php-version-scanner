"""Per-port probing: protocol detection, certificate capture and PHP checks.

INTERFACE ONLY. The functions marked ``TODO`` must be implemented. The rest of
the scanner relies only on the signatures and contracts documented here (see
``docs/probe-interface.md``).

General contract for every function in this module:

* **Never raise on network problems.** Timeouts, refused connections, TLS
  failures and HTTP protocol errors are reported through return values
  (``None``, ``PortResult.state``/``.error``). Programming errors (bad arguments)
  may raise.
* **Thread-safe.** The CLI calls these functions concurrently from a thread pool,
  one call per (IP, port) or (IP, port, vhost). Do not share mutable state
  without a lock.
* **Bounded.** Every network operation respects ``Config.timeout``. Response
  bodies are read up to ``Config.max_body`` bytes at most.
* IP addresses are passed as strings in any valid notation. IPv6 addresses
  are never bracketed. Use :func:`url_for` to build URLs.
"""
from __future__ import annotations

import errno
import ipaddress
import secrets
import socket
from contextlib import closing
from dataclasses import dataclass, field

import httpx

from .certs import fetch_cert, insecure_context
from .detect import analyze_response
from .models import CertInfo, Evidence, PortResult

DEFAULT_PORTS = (80, 443, 8080, 8443)
TLS_FIRST_PORTS = frozenset({443, 8443})
PHPINFO_PATHS = ("/phpinfo.php", "/info.php", "/test.php", "/i.php", "/php_info.php", "/php.php")
HTTPS_PORT_MARKER = "plain HTTP request was sent to HTTPS port"


@dataclass(frozen=True)
class Config:
    """Probe settings. One instance is shared by all threads (read-only)."""

    timeout: float = 5.0          # seconds, per connect / per read
    phpinfo_probe: bool = True    # request PHPINFO_PATHS when no version was found yet
    max_body: int = 512 * 1024    # bytes of each response body to read
    max_redirects: int = 3        # only same-host redirects are followed
    user_agent: str = "php-version-scanner/1.0 (internal patch audit)"
    extra_paths: tuple[str, ...] = field(default_factory=tuple)  # additional paths to request


@dataclass
class Fetched:
    """One HTTP response, reduced to what detection needs."""

    url: str                          # final URL that was requested (after redirects)
    status: int                       # HTTP status code
    headers: list[tuple[str, str]]    # all headers in order, duplicates kept (e.g. multiple Set-Cookie)
    body: str                         # decoded body, truncated to Config.max_body bytes; "" for HEAD/empty
    host: str | None = None           # Host header / SNI name used, None when the IP was used directly


# --------------------------------------------------------------------------- helpers (implemented)

def url_for(scheme: str, ip: str, port: int, path: str = "/") -> str:
    """Build a URL for an IP, bracketing IPv6: ``url_for("https", "2001:db8::1", 443, "/")``
    returns ``"https://[2001:db8::1]:443/"``."""
    addr = ipaddress.ip_address(ip)
    host = f"[{addr.compressed}]" if addr.version == 6 else addr.compressed
    if not path.startswith("/"):
        path = "/" + path
    return f"{scheme}://{host}:{port}{path}"


def evidence_from(fetched: Fetched) -> list[Evidence]:
    """Run PHP detection on one response and turn the findings into Evidence objects."""
    location = fetched.url + (f" (Host: {fetched.host})" if fetched.host else "")
    return [Evidence(source=src, location=location, version=ver)
            for src, ver in analyze_response(fetched.headers, fetched.body)]


# --------------------------------------------------------------------------- interface (TODO)

def tcp_state(ip: str, port: int, timeout: float) -> tuple[str, str | None]:
    """Check whether a TCP port accepts connections.

    Returns ``(state, error)``:

    * ``("open", None)``: the connection was established (and then closed again)
    * ``("closed", "connection refused")``: RST received, so the host is up but the port is closed
    * ``("timeout", "<detail>")``: no answer within ``timeout`` (filtered or host down)
    * ``("error", "<detail>")``: anything else (no route, network unreachable, ...)
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return "open", None
    except ConnectionRefusedError:
        return "closed", "connection refused"
    except TimeoutError as exc:
        return "timeout", str(exc) or "timed out"
    except OSError as exc:
        # Some platforms return a plain OSError instead of one of the more
        # specific subclasses above.
        if exc.errno == errno.ECONNREFUSED:
            return "closed", "connection refused"
        if exc.errno == errno.ETIMEDOUT:
            return "timeout", str(exc) or "timed out"
        return "error", str(exc) or exc.__class__.__name__


def detect_scheme(ip: str, port: int, cfg: Config) -> tuple[str | None, CertInfo | None, str | None]:
    """Find out which protocol an open port speaks, and capture its certificate.

    Order: try TLS first on ``TLS_FIRST_PORTS``, plain HTTP first on other ports.
    If the first protocol fails, try the other one. A plain-HTTP response
    containing ``HTTPS_PORT_MARKER`` (nginx) means the port speaks TLS.

    For TLS, connect **without SNI** and use :func:`phpscan.certs.fetch_cert`
    to get the server's default certificate.

    Returns ``(scheme, cert, error)``:

    * ``("https", CertInfo, None)``: TLS handshake succeeded and an HTTP request returned a response
    * ``("http", None, None)``: plain HTTP returned a response
    * ``(None, CertInfo | None, "<detail>")``: the port is open but no HTTP answer came back.
      Still return the cert if the TLS handshake succeeded.
    """
    cert: CertInfo | None = None
    errors: list[str] = []

    def try_https() -> bool:
        nonlocal cert
        try:
            # Deliberately omit SNI here so this is the service's default
            # certificate rather than a certificate for a virtual host.
            cert = fetch_cert(ip, port, cfg.timeout)
        except (OSError, ValueError) as exc:
            errors.append(f"TLS handshake failed: {str(exc) or exc.__class__.__name__}")

        if fetch("https", ip, port, "/", cfg) is not None:
            return True
        errors.append("HTTPS request failed")
        return False

    def try_http() -> tuple[bool, bool]:
        response = fetch("http", ip, port, "/", cfg)
        if response is None:
            errors.append("HTTP request failed")
            return False, False
        return True, HTTPS_PORT_MARKER in response.body

    if port in TLS_FIRST_PORTS:
        if try_https():
            return "https", cert, None

        answered, tls_marker = try_http()
        if answered and not tls_marker:
            return "http", None, None
        if tls_marker:
            errors.append("plain HTTP response indicates a TLS service")
    else:
        answered, tls_marker = try_http()
        if answered and not tls_marker:
            return "http", None, None

        if try_https():
            return "https", cert, None
        if tls_marker:
            errors.append("plain HTTP response indicates a TLS service")

    return None, cert, "; ".join(errors) or "no HTTP response"


def fetch(scheme: str, ip: str, port: int, path: str, cfg: Config,
          host: str | None = None) -> Fetched | None:
    """Send one GET request to ``ip:port`` and return the response.

    * Always connect to ``ip``, even when ``host`` is given (no DNS lookup).
    * If ``host`` is set, send it as the ``Host`` header and, for https, as the
      TLS SNI name. If it is ``None``, use the IP as Host and send no SNI.
    * Ignore certificate errors (use :func:`phpscan.certs.insecure_context`).
    * Send ``cfg.user_agent``.
    * Follow up to ``cfg.max_redirects`` redirects, but only when the target
      points to the **same IP/host and port**. Otherwise return the 3xx response
      itself, because its headers often carry ``X-Powered-By`` too.
    * Read at most ``cfg.max_body`` bytes of the body. Decode leniently
      (``errors="replace"``).
    * Keep header order and duplicates (``httpx``: ``response.headers.multi_items()``).
    * Don't reuse TLS connections across different ``host`` values, because a
      pooled connection would carry the wrong SNI.

    Returns ``None`` on any network or protocol error.
    """
    if scheme not in {"http", "https"}:
        raise ValueError(f"unsupported scheme: {scheme!r}")
    if cfg.max_body < 0 or cfg.max_redirects < 0:
        raise ValueError("max_body and max_redirects must not be negative")

    # A client local to this call avoids sharing an HTTPS connection (and its
    # already negotiated SNI name) with a fetch for another virtual host.
    transport = httpx.HTTPTransport(verify=insecure_context(), retries=0)
    timeout = httpx.Timeout(cfg.timeout)
    headers = {"User-Agent": cfg.user_agent}
    if host is not None:
        headers["Host"] = host

    allowed_hosts = {ipaddress.ip_address(ip).compressed.lower()}
    if host is not None:
        allowed_hosts.add(host.lower().rstrip("."))

    current_scheme = scheme
    current_path = path if path.startswith("/") else "/" + path

    try:
        with httpx.Client(transport=transport, timeout=timeout,
                          follow_redirects=False, trust_env=False) as client:
            for redirects in range(cfg.max_redirects + 1):
                current_url = url_for(current_scheme, ip, port, current_path)
                request = client.build_request("GET", current_url, headers=headers)
                if current_scheme == "https" and host is not None:
                    # httpcore honours this request extension while the URL's
                    # host remains the IP address used for the TCP connection.
                    request.extensions["sni_hostname"] = host

                with closing(client.send(request, stream=True)) as response:
                    location = response.headers.get("location")
                    if (redirects < cfg.max_redirects
                            and response.status_code in {301, 302, 303, 307, 308}
                            and location):
                        target = response.url.join(location)
                        target_port = target.port
                        if target_port is None:
                            target_port = 443 if target.scheme == "https" else 80
                        target_host = target.host.lower().rstrip(".")

                        if (target.scheme in {"http", "https"}
                                and target_host in allowed_hosts
                                and target_port == port):
                            current_scheme = target.scheme
                            current_path = target.raw_path.decode("ascii")
                            continue

                    chunks: list[bytes] = []
                    remaining = cfg.max_body
                    if remaining:
                        for chunk in response.iter_bytes():
                            chunks.append(chunk[:remaining])
                            remaining -= min(len(chunk), remaining)
                            if remaining == 0:
                                break

                    raw_body = b"".join(chunks)
                    encoding = response.encoding or "utf-8"
                    try:
                        body = raw_body.decode(encoding, errors="replace")
                    except LookupError:
                        body = raw_body.decode("utf-8", errors="replace")

                    return Fetched(
                        url=current_url,
                        status=response.status_code,
                        headers=list(response.headers.multi_items()),
                        body=body,
                        host=host,
                    )
    except (httpx.HTTPError, httpx.InvalidURL, OSError, UnicodeError):
        return None

    return None


def probe_php(scheme: str, ip: str, port: int, cfg: Config,
              host: str | None = None) -> list[Evidence]:
    """Collect PHP evidence from one HTTP service (one IP/port, optionally one vhost).

    Suggested sequence (stop early once an Evidence with a version exists):

    1. ``GET /``
    2. ``GET /index.php``
    3. ``GET /<random>.php``: a 404 handled by PHP-FPM often still sends ``X-Powered-By``
    4. each of ``cfg.extra_paths``
    5. if ``cfg.phpinfo_probe`` and no version yet: each of ``PHPINFO_PATHS``

    Use :func:`fetch` and :func:`evidence_from`. Remove duplicate evidence with
    the same ``(source, version)`` but keep one location for each.
    Returns an empty list when nothing points to PHP.
    """
    evidence: dict[tuple[str, str | None], Evidence] = {}

    def probe_path(path: str) -> bool:
        response = fetch(scheme, ip, port, path, cfg, host=host)
        if response is None:
            return False

        findings = evidence_from(response)
        for finding in findings:
            evidence.setdefault((finding.source, finding.version), finding)
        return any(finding.version is not None for finding in findings)

    initial_paths = (
        "/",
        "/index.php",
        f"/phpscan-{secrets.token_hex(8)}.php",
        *cfg.extra_paths,
    )
    for path in initial_paths:
        if probe_path(path):
            return list(evidence.values())

    if cfg.phpinfo_probe:
        for path in PHPINFO_PATHS:
            if probe_path(path):
                break

    return list(evidence.values())


def scan_port(ip: str, port: int, cfg: Config) -> PortResult:
    """Full check of one (IP, port) pair. This is the main entry point for phase 1.

    1. ``tcp_state``. If not ``"open"``, return
       ``PortResult(port, state, error=...)`` right away.
    2. ``detect_scheme``. Set ``scheme``, ``cert`` and ``error``.
    3. If a scheme was found: ``evidence = probe_php(scheme, ip, port, cfg)``.

    Must always return a ``PortResult`` (``state`` is one of
    ``"open" | "closed" | "timeout" | "error"``) and never raise on network errors.
    """
    state, error = tcp_state(ip, port, cfg.timeout)
    if state != "open":
        return PortResult(port=port, state=state, error=error)

    scheme, cert, error = detect_scheme(ip, port, cfg)
    evidence = probe_php(scheme, ip, port, cfg) if scheme is not None else []
    return PortResult(
        port=port,
        state="open",
        scheme=scheme,
        cert=cert,
        error=error,
        evidence=evidence,
    )


def scan_vhost(ip: str, port_result: PortResult, name: str, cfg: Config) -> list[Evidence]:
    """Vhost check (phase 3) for a name that is forward-confirmed for ``ip``.

    Only called when ``port_result.scheme`` is set. Runs
    ``probe_php(port_result.scheme, ip, port_result.port, cfg, host=name)``.
    The caller adds the result to ``port_result.evidence`` and adds ``name`` to
    ``port_result.vhosts_checked``. This function itself must **not** change
    ``port_result``, because several vhost calls for the same port may run in
    parallel.
    """
    if port_result.scheme is None:
        return []
    return probe_php(
        port_result.scheme,
        ip,
        port_result.port,
        cfg,
        host=name,
    )
