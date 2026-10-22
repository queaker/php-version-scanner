"""Cached forward (A/AAAA) and reverse (PTR) lookups."""
from __future__ import annotations

import ipaddress
import threading

import dns.exception
import dns.resolver
import dns.reversename


class Resolver:
    def __init__(self, timeout: float = 5.0):
        self._res = dns.resolver.Resolver()
        self._res.lifetime = timeout
        self._fwd: dict[str, set[str]] = {}
        self._rev: dict[str, list[str]] = {}
        self._lock = threading.Lock()

    def forward(self, name: str) -> set[str]:
        """All A and AAAA addresses of `name` (compressed form)."""
        name = name.lower().rstrip(".")
        with self._lock:
            if name in self._fwd:
                return self._fwd[name]
        addrs: set[str] = set()
        if not name.startswith("*."):
            for rtype in ("A", "AAAA"):
                try:
                    for r in self._res.resolve(name, rtype):
                        addrs.add(ipaddress.ip_address(r.to_text()).compressed)
                except (dns.exception.DNSException, ValueError):
                    pass
        with self._lock:
            self._fwd[name] = addrs
        return addrs

    def reverse(self, ip: str) -> list[str]:
        with self._lock:
            if ip in self._rev:
                return self._rev[ip]
        names: list[str] = []
        try:
            for r in self._res.resolve(dns.reversename.from_address(ip), "PTR"):
                names.append(r.to_text().lower().rstrip("."))
        except dns.exception.DNSException:
            pass
        with self._lock:
            self._rev[ip] = names
        return names


class StaticResolver(Resolver):
    """Resolver backed by fixed tables (tests, offline runs)."""

    def __init__(self, forward: dict[str, set[str]] | None = None, reverse: dict[str, list[str]] | None = None):
        self._fwd_table = {k.lower(): {ipaddress.ip_address(a).compressed for a in v} for k, v in (forward or {}).items()}
        self._rev_table = reverse or {}

    def forward(self, name: str) -> set[str]:
        return self._fwd_table.get(name.lower().rstrip("."), set())

    def reverse(self, ip: str) -> list[str]:
        return self._rev_table.get(ip, [])
