"""TLS certificate retrieval (verification disabled) and parsing."""
from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl

from cryptography import x509
from cryptography.x509.oid import NameOID

from .models import CertInfo


def insecure_context() -> ssl.SSLContext:
    """Accept any certificate and, as far as the local OpenSSL allows, old protocols/ciphers.

    The hosts in scope run outdated software, so old TLS setups are expected.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pass
    return ctx


def fetch_cert(ip: str, port: int, timeout: float, sni: str | None = None) -> CertInfo:
    """Do a TLS handshake and return the peer certificate. Raises OSError/ssl.SSLError on failure.

    Without `sni` no SNI is sent (the ssl module never sends IP addresses as SNI),
    so the server presents its default certificate.
    """
    ctx = insecure_context()
    with socket.create_connection((ip, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=sni or ip) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise ssl.SSLError("no certificate presented")
    return parse_cert(der)


def parse_cert(der: bytes) -> CertInfo:
    cert = x509.load_der_x509_certificate(der)
    san_dns: list[str] = []
    san_ips: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        san_dns = [n.lower().rstrip(".") for n in san.get_values_for_type(x509.DNSName)]
        san_ips = [ipaddress.ip_address(a).compressed for a in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass
    cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cn = str(cns[0].value) if cns else None
    return CertInfo(
        sha256=hashlib.sha256(der).hexdigest(),
        subject_cn=cn,
        san_dns=san_dns,
        san_ips=san_ips,
        issuer=cert.issuer.rfc4514_string(),
        not_after=cert.not_valid_after_utc.isoformat(),
        self_signed=cert.issuer == cert.subject,
    )


def cert_names(cert: CertInfo) -> list[str]:
    """DNS names of the certificate; falls back to a hostname-like CN when there is no SAN."""
    names = list(cert.san_dns)
    if not names and cert.subject_cn and "." in cert.subject_cn and " " not in cert.subject_cn:
        try:
            ipaddress.ip_address(cert.subject_cn)
        except ValueError:
            names.append(cert.subject_cn.lower().rstrip("."))
    return names


def cert_covers(cert: CertInfo, hostname: str) -> bool:
    """RFC 6125 style match, wildcard only in the left-most label."""
    hostname = hostname.lower().rstrip(".")
    for pattern in cert_names(cert):
        if pattern == hostname:
            return True
        if pattern.startswith("*.") and "." in hostname:
            if hostname.split(".", 1)[1] == pattern[2:]:
                return True
    return False


def cert_has_ip(cert: CertInfo, ip: str) -> bool:
    return ipaddress.ip_address(ip).compressed in cert.san_ips
