"""Self-signed certificates for the mock server (generated at startup, never written outside a temp dir)."""
from __future__ import annotations

import datetime
import ipaddress
import os
import ssl
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def make_cert_files(directory: str, stem: str, cn: str, dns: list[str], ips: list[str]) -> tuple[str, str]:
    """Write <stem>.pem / <stem>.key into `directory` and return their paths."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    sans = [x509.DNSName(d) for d in dns] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    builder = (x509.CertificateBuilder()
               .subject_name(name).issuer_name(name)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(minutes=5))
               .not_valid_after(now + datetime.timedelta(days=7)))
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    cert = builder.sign(key, hashes.SHA256())
    cert_path = os.path.join(directory, f"{stem}.pem")
    key_path = os.path.join(directory, f"{stem}.key")
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    return cert_path, key_path


class CertStore:
    """Default certificate plus per-SNI-name certificates, exposed as one server SSLContext."""

    def __init__(self, default_cn: str, default_dns: list[str], default_ips: list[str],
                 sni_certs: dict[str, list[str]]):
        self._tmp = tempfile.TemporaryDirectory(prefix="php-mock-certs-")
        d = self._tmp.name
        self.default_ctx = self._ctx(*make_cert_files(d, "default", default_cn, default_dns, default_ips))
        self.sni_ctx: dict[str, ssl.SSLContext] = {}
        for i, (name, extra_dns) in enumerate(sni_certs.items()):
            self.sni_ctx[name] = self._ctx(*make_cert_files(d, f"sni{i}", name, [name, *extra_dns], []))
        self.default_ctx.sni_callback = self._on_sni

    @staticmethod
    def _ctx(cert: str, key: str) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        return ctx

    def _on_sni(self, sslsock, server_name, _ctx):
        # Remember the requested name so request handlers can see it.
        sslsock.sni_name = server_name
        if server_name in self.sni_ctx:
            sslsock.context = self.sni_ctx[server_name]
        return None

    def close(self) -> None:
        self._tmp.cleanup()
