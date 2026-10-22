"""Configurable local web server that exposes simulated PHP installations."""
from __future__ import annotations

import ipaddress
import socket
import ssl
import sys
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import TracebackType
from urllib.parse import urlsplit

from .certs import CertStore

PHPINFO_PATHS = frozenset(
    {"/phpinfo.php", "/info.php", "/test.php", "/i.php", "/php_info.php", "/php.php"}
)
# Per-connection socket timeout, also bounds the TLS handshake of a silent client.
CONNECTION_TIMEOUT = 5.0
# How quickly serve_forever() notices shutdown(); the default 0.5 s slows down teardown.
POLL_INTERVAL = 0.05


@dataclass(frozen=True)
class PHPWebsite:
    """Response profile for one Host header.

    ``version_header=None`` hides the version in normal responses. Setting
    ``php_version=None`` together with a header emits just ``PHP``, which is
    useful for testing version-hidden evidence. Set both ``version_header``
    and ``expose_phpinfo`` to false values to simulate a non-PHP site.

    ``header_version=False`` sends just ``PHP`` in the version header while
    phpinfo pages still show ``php_version``.

    ``redirects`` maps a request path to a ``Location`` value, answered with
    ``302`` (the version header is still sent). ``{origin}`` in the target is
    replaced by this server's ``scheme://ip:port``.
    """

    php_version: str | None
    version_header: str | None = "X-Powered-By"
    header_version: bool = True
    expose_phpinfo: bool = True
    php_session: bool = False
    body: str = "<html><body>Test site</body></html>"
    extra_headers: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    redirects: tuple[tuple[str, str], ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class RequestRecord:
    """One request observed by the test server."""

    path: str
    host: str
    sni: str | None
    user_agent: str | None


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], owner: PHPTestServer):
        self.owner = owner
        super().__init__(address, _RequestHandler)

    def handle_error(self, request: object, client_address: object) -> None:
        # Failed handshakes, plain HTTP on a TLS port, timeouts and resets are
        # expected while probing; only report real handler bugs.
        if isinstance(sys.exc_info()[1], OSError):
            return
        super().handle_error(request, client_address)


class _IPv6Server(_Server):
    address_family = socket.AF_INET6


class _RequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = CONNECTION_TIMEOUT

    def setup(self) -> None:
        # The listening socket is wrapped with do_handshake_on_connect=False,
        # so the handshake runs here in the per-connection thread (with a
        # timeout) instead of blocking the accept loop.
        if isinstance(self.request, ssl.SSLSocket):
            self.request.settimeout(self.timeout)
            self.request.do_handshake()
        super().setup()

    def do_GET(self) -> None:
        self.server.owner._serve(self)  # type: ignore[attr-defined]

    def log_message(self, _format: str, *args: object) -> None:
        pass


class PHPTestServer:
    """A start/stop capable HTTP(S) server for probe tests.

    Use it as a context manager, or call :meth:`start` and :meth:`close`.
    Binding to port ``0`` lets the operating system choose an unused port.
    """

    def __init__(
        self,
        default: PHPWebsite | None = None,
        *,
        vhosts: dict[str, PHPWebsite] | None = None,
        tls: bool = False,
        ip: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        self.default = default or PHPWebsite(
            php_version=None,
            version_header=None,
            expose_phpinfo=False,
        )
        self.vhosts = {
            self._normalise_name(name): website
            for name, website in (vhosts or {}).items()
        }
        self.tls = tls
        self.ip = ipaddress.ip_address(ip).compressed
        self.requested_port = port
        self._server: _Server | None = None
        self._thread: threading.Thread | None = None
        self._certs: CertStore | None = None
        self._requests: list[RequestRecord] = []
        self._requests_lock = threading.Lock()

    @property
    def scheme(self) -> str:
        return "https" if self.tls else "http"

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("test server has not been started")
        return int(self._server.server_address[1])

    @property
    def origin(self) -> str:
        """``scheme://ip:port`` of this server, IPv6 in brackets."""
        host = f"[{self.ip}]" if ipaddress.ip_address(self.ip).version == 6 else self.ip
        return f"{self.scheme}://{host}:{self.port}"

    @property
    def requests(self) -> list[RequestRecord]:
        """Return a thread-safe snapshot of requests received so far."""
        with self._requests_lock:
            return list(self._requests)

    def start(self) -> PHPTestServer:
        if self._server is not None:
            return self

        server_type = _IPv6Server if ipaddress.ip_address(self.ip).version == 6 else _Server
        server = server_type((self.ip, self.requested_port), self)
        try:
            if self.tls:
                self._certs = CertStore(
                    default_cn="localhost",
                    default_dns=["localhost"],
                    default_ips=[self.ip],
                    sni_certs={name: [] for name in self.vhosts},
                )
                server.socket = self._certs.default_ctx.wrap_socket(
                    server.socket,
                    server_side=True,
                    do_handshake_on_connect=False,
                )
        except BaseException:
            server.server_close()
            if self._certs is not None:
                self._certs.close()
                self._certs = None
            raise

        self._server = server
        self._thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": POLL_INTERVAL},
            name=f"php-test-server-{self.scheme}-{self.port}",
            daemon=True,
        )
        self._thread.start()
        return self

    def close(self) -> None:
        server, thread = self._server, self._thread
        self._server = None
        self._thread = None
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=2)
        if self._certs is not None:
            self._certs.close()
            self._certs = None

    def __enter__(self) -> PHPTestServer:
        return self.start()

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.close()

    def _serve(self, handler: _RequestHandler) -> None:
        path = urlsplit(handler.path).path
        host = self._host_without_port(handler.headers.get("Host", ""))
        sni = getattr(handler.connection, "sni_name", None)
        with self._requests_lock:
            self._requests.append(RequestRecord(
                path=path,
                host=host,
                sni=sni,
                user_agent=handler.headers.get("User-Agent"),
            ))

        website = self.vhosts.get(host, self.default)
        location = dict(website.redirects).get(path)
        is_phpinfo = path in PHPINFO_PATHS and website.expose_phpinfo
        if location is not None:
            status = 302
            body = ""
        elif is_phpinfo and website.php_version is not None:
            status = 200
            body = (
                "<!doctype html><html><head>"
                f"<title>PHP {website.php_version} - phpinfo()</title>"
                "</head><body>phpinfo()</body></html>"
            )
        else:
            status = 200 if path in {"/", "/index.php"} else 404
            body = website.body

        encoded = body.encode("utf-8")
        handler.send_response(status)
        if location is not None:
            handler.send_header("Location", location.replace("{origin}", self.origin))
        if website.version_header is not None:
            hidden = website.php_version is None or not website.header_version
            value = "PHP" if hidden else f"PHP/{website.php_version}"
            handler.send_header(website.version_header, value)
        if website.php_session:
            handler.send_header("Set-Cookie", "PHPSESSID=test-session; Path=/; HttpOnly")
        for name, value in website.extra_headers:
            handler.send_header(name, value)
        handler.send_header("Content-Type", "text/html; charset=utf-8")
        handler.send_header("Content-Length", str(len(encoded)))
        handler.end_headers()
        handler.wfile.write(encoded)

    @staticmethod
    def _normalise_name(name: str) -> str:
        return name.lower().rstrip(".")

    @classmethod
    def _host_without_port(cls, value: str) -> str:
        value = value.strip()
        if value.startswith("["):
            end = value.find("]")
            return cls._normalise_name(value[1:end] if end >= 0 else value)
        host, separator, possible_port = value.rpartition(":")
        if separator and possible_port.isdigit():
            value = host
        return cls._normalise_name(value)
