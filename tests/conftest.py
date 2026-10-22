import datetime
import ipaddress
from collections.abc import Callable, Iterator

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from phpscan.certs import parse_cert
from phpscan.models import CertInfo, Evidence, IPResult, PortResult
from testserver import PHPTestServer, PHPWebsite

_KEY = ec.generate_private_key(ec.SECP256R1())


def make_der(cn="test", dns=(), ips=(), serial=1) -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
               .public_key(_KEY.public_key()).serial_number(serial)
               .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=30)))
    sans = [x509.DNSName(d) for d in dns] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return builder.sign(_KEY, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def make_cert(cn="test", dns=(), ips=(), serial=1) -> CertInfo:
    return parse_cert(make_der(cn, dns, ips, serial))


def make_ip(ip, *, cert=None, versions=(), markers=(), ports_state=None, scheme="https") -> IPResult:
    """IPResult with one open port 443 (or the given port states)."""
    r = IPResult(ip=ip, family=ipaddress.ip_address(ip).version)
    if ports_state is not None:
        for port, state in ports_state.items():
            r.ports[port] = PortResult(port=port, state=state)
        return r
    ev = [Evidence("X-Powered-By header", f"https://{ip}:443/", v) for v in versions]
    ev += [Evidence(m, f"https://{ip}:443/", None) for m in markers]
    r.ports[443] = PortResult(port=443, state="open", scheme=scheme, cert=cert, evidence=ev)
    return r


@pytest.fixture
def patched():
    return {(8, 5, 12), (8, 4, 27), (8, 3, 36), (8, 2, 35)}


@pytest.fixture
def php_server() -> Iterator[Callable[..., PHPTestServer]]:
    """Factory for local PHP test servers that are closed after each test."""
    servers: list[PHPTestServer] = []

    def start(
        default: PHPWebsite | None = None,
        *,
        vhosts: dict[str, PHPWebsite] | None = None,
        tls: bool = False,
        ip: str = "127.0.0.1",
    ) -> PHPTestServer:
        server = PHPTestServer(default, vhosts=vhosts, tls=tls, ip=ip).start()
        servers.append(server)
        return server

    yield start

    for server in reversed(servers):
        server.close()
