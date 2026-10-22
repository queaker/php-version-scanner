"""Command line entry point.

Phases:
  1. probe every (IP, port) with probe.scan_port
  2. DNS: PTR + forward lookups, certificate ↔ IP matching
  3. vhost pass: probe.scan_vhost for forward-confirmed names
  4. status, IPv4/IPv6 grouping, report
"""
from __future__ import annotations

import argparse
import ipaddress
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from . import probe
from .detect import load_patched
from .dnsutil import Resolver
from .grouping import annotate_identity, group_hosts, prefetch_dns
from .models import Evidence, IPResult, PortResult
from .report import render_json, render_markdown
from .status import apply_group_status, apply_ip_status

MAX_EXPANDED_NETWORK = 4096


class ProbeNotImplemented(RuntimeError):
    pass


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def read_hosts(path: str, first_only: bool = False) -> list[str]:
    """One IP or CIDR per line; '#' comments; duplicates removed; invalid lines skipped with a warning.

    With `first_only`, stop after the first valid entry (blank, comment and invalid lines are skipped).
    """
    hosts: list[str] = []
    seen: set[str] = set()
    with open(path, encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                if "/" in line:
                    net = ipaddress.ip_network(line, strict=False)
                    if net.num_addresses > MAX_EXPANDED_NETWORK:
                        log(f"warning: {path}:{lineno}: {line} has more than {MAX_EXPANDED_NETWORK} addresses, skipped")
                        continue
                    addrs = list(net.hosts()) or [net.network_address]
                else:
                    addrs = [ipaddress.ip_address(line)]
            except ValueError:
                log(f"warning: {path}:{lineno}: not an IP address: {line!r}, skipped")
                continue
            for a in addrs:
                if a.compressed not in seen:
                    seen.add(a.compressed)
                    hosts.append(a.compressed)
            if first_only:
                break
    return hosts


def parse_ports(text: str) -> list[int]:
    ports = sorted({int(p) for p in text.split(",") if p.strip()})
    if not ports or any(not 0 < p < 65536 for p in ports):
        raise argparse.ArgumentTypeError(f"invalid port list: {text}")
    return ports


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="phpscan", description="Scan hosts for their PHP version and patch status.")
    ap.add_argument("--hosts", default="hosts.txt", help="file with one IPv4/IPv6 address or CIDR per line")
    ap.add_argument("--versions", default="php-versions.txt", help="file with patched PHP versions")
    ap.add_argument("-o", "--output", help="write the Markdown report here (default: stdout)")
    ap.add_argument("--json", help="also write all evidence as JSON to this file")
    ap.add_argument("--ports", type=parse_ports, default=list(probe.DEFAULT_PORTS),
                    help="comma-separated ports (default: 80,443,8080,8443)")
    ap.add_argument("--workers", type=int, default=32, help="parallel probes (default: 32)")
    ap.add_argument("--timeout", type=float, default=5.0, help="network timeout in seconds (default: 5)")
    ap.add_argument("--dns-timeout", type=float, default=5.0, help="DNS timeout in seconds (default: 5)")
    ap.add_argument("--no-phpinfo-probe", action="store_true", help="do not request common phpinfo() paths")
    ap.add_argument("--no-vhost-pass", action="store_true", help="do not re-probe with certificate host names")
    ap.add_argument("--first-only", action="store_true",
                    help="only scan the first entry of the hosts file (quick test run)")
    ap.add_argument("--max-vhosts", type=int, default=5,
                    help="max host names per IP for the vhost pass (default: 5)")
    ap.add_argument("-v", "--verbose", action="store_true", help="log every probe result")
    return ap


class Progress:
    def __init__(self, label: str, total: int, verbose: bool):
        self.label, self.total, self.verbose = label, total, verbose
        self.done = 0
        self._lock = threading.Lock()

    def step(self, detail: str = "") -> None:
        with self._lock:
            self.done += 1
            if self.verbose and detail:
                log(f"  [{self.done}/{self.total}] {detail}")
            elif self.done == self.total or self.done % max(1, self.total // 20) == 0:
                log(f"  {self.label}: {self.done}/{self.total}")


def _scan_port(ip: str, port: int, cfg: probe.Config) -> PortResult:
    try:
        return probe.scan_port(ip, port, cfg)
    except NotImplementedError as exc:
        raise ProbeNotImplemented from exc
    except Exception as exc:  # a probe bug must not abort the whole scan
        return PortResult(port=port, state="error", error=f"probe failed: {exc!r}")


def _scan_vhost(ip: str, pr: PortResult, name: str, cfg: probe.Config) -> list[Evidence]:
    try:
        return probe.scan_vhost(ip, pr, name, cfg)
    except NotImplementedError as exc:
        raise ProbeNotImplemented from exc
    except Exception as exc:
        log(f"warning: vhost probe {name} on {ip}:{pr.port} failed: {exc!r}")
        return []


def run(args: argparse.Namespace, resolver: Resolver | None = None) -> int:
    hosts = read_hosts(args.hosts, first_only=args.first_only)
    patched = load_patched(args.versions)
    if not hosts:
        log("error: no valid hosts")
        return 2
    patched_display = [".".join(map(str, v)) for v in sorted(patched, reverse=True)]
    cfg = probe.Config(timeout=args.timeout, phpinfo_probe=not args.no_phpinfo_probe)
    resolver = resolver or Resolver(timeout=args.dns_timeout)
    started = datetime.now()

    results = {ip: IPResult(ip=ip, family=ipaddress.ip_address(ip).version) for ip in hosts}
    log(f"Scanning {len(hosts)} addresses on ports {', '.join(map(str, args.ports))} "
        f"with {args.workers} workers")

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        # Phase 1: ports
        progress = Progress("ports", len(hosts) * len(args.ports), args.verbose)
        futures = {pool.submit(_scan_port, ip, port, cfg): ip for ip in hosts for port in args.ports}
        try:
            for fut in as_completed(futures):
                pr = fut.result()
                results[futures[fut]].ports[pr.port] = pr
                progress.step(f"{futures[fut]}:{pr.port} {pr.state} {pr.scheme or ''} "
                              f"{len(pr.evidence)} evidence {pr.error or ''}".rstrip())
        except ProbeNotImplemented:
            for f in futures:
                f.cancel()
            log("error: phpscan/probe.py is not implemented yet (see docs/probe-interface.md)")
            return 3

        # Phase 2: DNS + certificate matching
        log("Resolving PTR and certificate names")
        ordered = [results[ip] for ip in hosts]
        prefetch_dns(ordered, resolver, pool)
        annotate_identity(ordered, resolver)

        # Phase 3: vhost pass
        if not args.no_vhost_pass:
            jobs = [(r, pr, name) for r in ordered for name in r.confirmed_names[:args.max_vhosts]
                    for pr in r.ports.values() if pr.scheme]
            if jobs:
                progress = Progress("vhosts", len(jobs), args.verbose)
                vfutures = {pool.submit(_scan_vhost, r.ip, pr, name, cfg): (r, pr, name) for r, pr, name in jobs}
                try:
                    for fut in as_completed(vfutures):
                        r, pr, name = vfutures[fut]
                        evidence = fut.result()
                        pr.evidence.extend(evidence)  # merged here, single-threaded
                        pr.vhosts_checked.append(name)
                        progress.step(f"{r.ip}:{pr.port} Host {name}: {len(evidence)} evidence")
                except ProbeNotImplemented:
                    for f in vfutures:
                        f.cancel()
                    log("error: probe.scan_vhost is not implemented yet (use --no-vhost-pass to skip)")
                    return 3

    # Phase 4: status, grouping, report
    for r in results.values():
        apply_ip_status(r, patched)
    groups, notes = group_hosts(list(results.values()), resolver)
    for g in groups:
        apply_group_status(g)
    finished = datetime.now()

    meta = dict(started=started, finished=finished, ports=args.ports,
                versions_file=args.versions, patched_display=patched_display)
    markdown = render_markdown(groups, notes, **meta)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(markdown)
        log(f"Report written to {args.output}")
    else:
        sys.stdout.write(markdown)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(render_json(groups, notes, **meta))
        log(f"JSON written to {args.json}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except (OSError, ValueError) as exc:
        log(f"error: {exc}")
        return 2
    except KeyboardInterrupt:
        log("interrupted")
        return 130
