"""Patch status per IP and per host group."""
from __future__ import annotations

from .detect import is_patched, parse_version
from .models import OFFLINE, PATCHED, STATUS_RANK, UNKNOWN, UNPATCHED, HostGroup, IPResult


def detected_versions(r: IPResult) -> list[str]:
    """Distinct full version strings found on the IP, sorted by upstream version."""
    versions = {e.version for e in r.evidence if e.version}
    return sorted(versions, key=lambda v: (parse_version(v) or ((0, 0, 0), ""), v))


def ip_status(r: IPResult, patched: set[tuple[int, int, int]]) -> tuple[str, str]:
    """Return (status, human-readable reason) for one IP."""
    open_ports = [p for p in r.ports.values() if p.state == "open"]
    if not open_ports:
        states = sorted({p.state for p in r.ports.values()})
        if states == ["closed"]:
            return OFFLINE, "all ports refused the connection (host up, no web service)"
        return OFFLINE, "no port reachable (" + ", ".join(states) + ")"

    versions = detected_versions(r)
    if versions:
        bad = [v for v in versions if not is_patched(v, patched)]
        if bad:
            return UNPATCHED, "version(s) not in patched list: " + ", ".join(bad)
        return PATCHED, "all detected versions are in the patched list"

    if not r.http_ports:
        return UNKNOWN, "port(s) open but no HTTP answer"
    if r.evidence:
        return UNKNOWN, "PHP detected, version hidden"
    return UNKNOWN, "no PHP markers found"


def apply_ip_status(r: IPResult, patched: set[tuple[int, int, int]]) -> None:
    r.status, r.status_reason = ip_status(r, patched)


def group_status(g: HostGroup) -> str:
    """Worst status of the members. Offline members only count when all are offline."""
    return min((m.status for m in g.members), key=STATUS_RANK.__getitem__)


def apply_group_status(g: HostGroup) -> None:
    g.status = group_status(g)


def is_inconsistent(g: HostGroup) -> bool:
    """True when reachable members disagree on status or on the detected versions."""
    online = [m for m in g.members if m.status != OFFLINE]
    if len(online) < 2:
        return False
    if len({m.status for m in online}) > 1:
        return True
    return len({tuple(detected_versions(m)) for m in online}) > 1
