"""Data structures shared across the scanner."""
from __future__ import annotations

from dataclasses import dataclass, field

# Status values, ordered from worst to best for aggregation.
UNPATCHED = "unpatched"
UNKNOWN = "unknown"
PATCHED = "patched"
OFFLINE = "offline"
STATUS_RANK = {UNPATCHED: 0, UNKNOWN: 1, PATCHED: 2, OFFLINE: 3}


@dataclass
class Evidence:
    source: str              # e.g. "X-Powered-By", "Server", "phpinfo", "cookie PHPSESSID"
    location: str            # e.g. "https://[2001:db8::1]:443/info.php (Host: www.example.com)"
    version: str | None      # full version string as seen, e.g. "8.2.12-1+deb12u1"


@dataclass
class CertInfo:
    sha256: str
    subject_cn: str | None
    san_dns: list[str]
    san_ips: list[str]
    issuer: str
    not_after: str
    self_signed: bool


@dataclass
class PortResult:
    port: int
    state: str               # "open", "closed" (refused), "timeout", "error"
    scheme: str | None = None  # "https" / "http" once an HTTP service answered
    cert: CertInfo | None = None
    error: str | None = None
    evidence: list[Evidence] = field(default_factory=list)
    vhosts_checked: list[str] = field(default_factory=list)


@dataclass
class IPResult:
    ip: str
    family: int              # 4 or 6
    ports: dict[int, PortResult] = field(default_factory=dict)
    ptr: list[str] = field(default_factory=list)
    confirmed_names: list[str] = field(default_factory=list)  # names that resolve to this IP and are covered by its cert
    cert_match: str = "n/a"  # "san", "dns", "no", "n/a"
    status: str = OFFLINE
    status_reason: str = ""

    @property
    def http_ports(self) -> list[PortResult]:
        return [p for p in self.ports.values() if p.scheme]

    @property
    def certs(self) -> list[CertInfo]:
        seen: dict[str, CertInfo] = {}
        for p in self.ports.values():
            if p.cert:
                seen.setdefault(p.cert.sha256, p.cert)
        return list(seen.values())

    @property
    def evidence(self) -> list[Evidence]:
        return [e for p in self.ports.values() for e in p.evidence]


@dataclass
class HostGroup:
    name: str
    members: list[IPResult]
    reason: str = ""         # why the IPs were grouped
    status: str = OFFLINE
