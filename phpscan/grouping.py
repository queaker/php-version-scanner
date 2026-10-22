"""Host identity: certificate ↔ IP matching and IPv4/IPv6 grouping.

Two addresses are grouped only when both signals agree:
  1. they present the same certificate (SHA-256 fingerprint), and
  2. a name covered by that certificate (SAN/CN name, or a PTR name the cert
     covers) has an A record for the IPv4 and an AAAA record for the IPv6 address.
A shared certificate alone is not enough (wildcard and shared certs are common).
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Callable, Iterable
from concurrent.futures import Executor

from .certs import cert_covers, cert_has_ip, cert_names
from .dnsutil import Resolver
from .models import CertInfo, HostGroup, IPResult


def _concrete(names: Iterable[str]) -> set[str]:
    return {n for n in names if not n.startswith("*.")}


def cert_candidate_names(cert: CertInfo, ptr_names: Iterable[str]) -> set[str]:
    """Resolvable names for a cert: its non-wildcard names plus PTR names it covers."""
    names = _concrete(cert_names(cert))
    names |= {n for n in ptr_names if cert_covers(cert, n)}
    return names


def prefetch_dns(results: list[IPResult], resolver: Resolver, executor: Executor | None = None) -> None:
    """Warm the resolver cache in parallel (PTR first, then forward lookups of candidate names)."""
    run: Callable = executor.map if executor else map
    list(run(resolver.reverse, [r.ip for r in results]))
    names: set[str] = set()
    for r in results:
        ptr = resolver.reverse(r.ip)
        for cert in r.certs:
            names |= cert_candidate_names(cert, ptr)
    list(run(resolver.forward, sorted(names)))


def annotate_identity(results: list[IPResult], resolver: Resolver) -> None:
    """Fill ptr, confirmed_names and cert_match on every IPResult."""
    for r in results:
        r.ptr = resolver.reverse(r.ip)
        confirmed: set[str] = set()
        for cert in r.certs:
            for name in cert_candidate_names(cert, r.ptr):
                if r.ip in resolver.forward(name):
                    confirmed.add(name)
        r.confirmed_names = sorted(confirmed, key=lambda n: (len(n), n))
        if not r.certs:
            r.cert_match = "n/a"
        elif any(cert_has_ip(c, r.ip) for c in r.certs):
            r.cert_match = "san"
        elif confirmed:
            r.cert_match = "dns"
        else:
            r.cert_match = "no"


class _UnionFind:
    def __init__(self, items: Iterable[str]):
        self.parent = {i: i for i in items}

    def find(self, x: str) -> str:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def _ip_sort_key(ip: str):
    addr = ipaddress.ip_address(ip)
    return addr.version, addr


def group_hosts(results: list[IPResult], resolver: Resolver) -> tuple[list[HostGroup], list[str]]:
    """Group IPv4/IPv6 addresses of the same host. Returns (groups, notes).

    Call annotate_identity() first. Every IPResult ends up in exactly one group;
    ungrouped addresses form single-member groups.
    """
    by_ip = {r.ip: r for r in results}
    uf = _UnionFind(by_ip)
    group_names: dict[frozenset[str], set[str]] = defaultdict(set)  # pair -> confirming names
    pair_reasons: list[tuple[str, str, str, str]] = []              # (v4, v6, name, fingerprint)

    certs_by_fp: dict[str, CertInfo] = {}
    ips_by_fp: dict[str, set[str]] = defaultdict(set)
    for r in results:
        for c in r.certs:
            certs_by_fp[c.sha256] = c
            ips_by_fp[c.sha256].add(r.ip)

    for fp, ips in ips_by_fp.items():
        v4s = [ip for ip in ips if by_ip[ip].family == 4]
        v6s = [ip for ip in ips if by_ip[ip].family == 6]
        cert = certs_by_fp[fp]
        for a in v4s:
            for b in v6s:
                names = cert_candidate_names(cert, by_ip[a].ptr + by_ip[b].ptr)
                hits = sorted((n for n in names if a in resolver.forward(n) and b in resolver.forward(n)),
                              key=lambda n: (len(n), n))
                if hits:
                    uf.union(a, b)
                    group_names[frozenset((a, b))].update(hits)
                    pair_reasons.append((a, b, hits[0], fp))

    # Assemble groups.
    members: dict[str, list[IPResult]] = defaultdict(list)
    for ip in sorted(by_ip, key=_ip_sort_key):
        members[uf.find(ip)].append(by_ip[ip])

    groups: list[HostGroup] = []
    for root, rs in members.items():
        ips = {r.ip for r in rs}
        if len(rs) > 1:
            names = set().union(*(n for pair, n in group_names.items() if pair <= ips))
            name = min(names, key=lambda n: (len(n), n))
            reasons = [f"{a} + {b}: same cert {fp[:16]}…, {n} → A/AAAA"
                       for a, b, n, fp in pair_reasons if a in ips]
            groups.append(HostGroup(name=name, members=rs, reason="; ".join(reasons)))
        else:
            r = rs[0]
            name = (r.confirmed_names or r.ptr or [r.ip])[0]
            groups.append(HostGroup(name=name, members=rs))

    return groups, _possible_same_host_notes(results, uf, ips_by_fp, by_ip, resolver)


def _possible_same_host_notes(results, uf, ips_by_fp, by_ip, resolver) -> list[str]:
    """Pairs where only one of the two grouping signals is present."""
    notes: list[str] = []
    seen: set[frozenset[str]] = set()

    # Signal 1 only: same certificate on IPv4 and IPv6, but no DNS name confirms it.
    for fp, ips in sorted(ips_by_fp.items()):
        v4s = sorted((ip for ip in ips if by_ip[ip].family == 4), key=_ip_sort_key)
        v6s = sorted((ip for ip in ips if by_ip[ip].family == 6), key=_ip_sort_key)
        if not v4s or not v6s:
            continue
        unmatched = [(a, b) for a in v4s for b in v6s if uf.find(a) != uf.find(b)]
        if not unmatched:
            continue
        if len(ips) > 6:
            notes.append(f"Certificate {fp[:16]}… is shared by {len(ips)} addresses "
                         f"({len(v4s)} IPv4, {len(v6s)} IPv6) without DNS confirmation; "
                         "likely a shared/wildcard certificate, not grouped.")
            continue
        for a, b in unmatched:
            seen.add(frozenset((a, b)))
            notes.append(f"{a} and {b} present the same certificate ({fp[:16]}…) "
                         "but no certificate name resolves to both; not grouped.")

    # Signal 2 only: a name resolves to both addresses, but the certificates differ or are missing.
    ips_by_name: dict[str, set[str]] = defaultdict(set)
    for r in results:
        for n in set(r.confirmed_names) | set(r.ptr):
            ips_by_name[n].add(r.ip)
    for name, ips in sorted(ips_by_name.items()):
        fwd = resolver.forward(name)
        candidates = sorted((ips | {ip for ip in fwd if ip in by_ip}), key=_ip_sort_key)
        v4s = [ip for ip in candidates if by_ip[ip].family == 4]
        v6s = [ip for ip in candidates if by_ip[ip].family == 6]
        for a in v4s:
            for b in v6s:
                pair = frozenset((a, b))
                if uf.find(a) == uf.find(b) or pair in seen:
                    continue
                if a in fwd and b in fwd:
                    seen.add(pair)
                    notes.append(f"{name} resolves to {a} and {b}, but their certificates "
                                 "differ or are missing; not grouped.")
    return notes
