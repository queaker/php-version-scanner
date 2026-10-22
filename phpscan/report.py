"""Markdown and JSON output."""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import asdict
from datetime import datetime

from .certs import cert_names
from .models import STATUS_RANK, HostGroup
from .status import detected_versions, is_inconsistent

CERT_MATCH_LABEL = {"san": "✅ IP in SAN", "dns": "✅ via DNS", "no": "❌ mismatch", "n/a": "— (no TLS)"}
MAX_NAMES = 4
MAX_EVIDENCE = 4


def md_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def _cell(items: list[str], limit: int | None = None) -> str:
    if not items:
        return "—"
    shown = items if limit is None or len(items) <= limit else items[:limit] + [f"(+{len(items) - limit} more)"]
    return "<br>".join(md_escape(i) for i in shown)


def _cert_names(g: HostGroup) -> list[str]:
    names: list[str] = []
    for m in g.members:
        for c in m.certs:
            for n in cert_names(c):
                if n not in names:
                    names.append(n)
    return names


def _open_ports(g: HostGroup) -> list[str]:
    per_ip = {}
    for m in g.members:
        per_ip[m.ip] = [f"{p.port}/{p.scheme or 'tcp'}" for p in sorted(m.ports.values(), key=lambda p: p.port)
                        if p.state == "open"]
    distinct = {tuple(v) for v in per_ip.values() if v}
    if len(g.members) > 1 and len(distinct) > 1:
        return [f"{ip}: {', '.join(v) or 'none'}" for ip, v in per_ip.items()]
    return sorted({p for v in per_ip.values() for p in v}, key=lambda s: int(s.split("/")[0]))


def _evidence(g: HostGroup) -> list[str]:
    ports_by_source: dict[str, set[int]] = defaultdict(set)
    for m in g.members:
        for p in m.ports.values():
            for e in p.evidence:
                ports_by_source[e.source].add(p.port)
    # Versioned sources first.
    versioned = {e.source for m in g.members for e in m.evidence if e.version}
    items = [f"{src} ({', '.join(map(str, sorted(ports)))})"
             for src, ports in sorted(ports_by_source.items(), key=lambda kv: (kv[0] not in versioned, kv[0]))]
    if not items:
        reasons = []
        for m in g.members:
            r = m.status_reason if len(g.members) == 1 else f"{m.ip}: {m.status_reason}"
            if r not in reasons:
                reasons.append(r)
        items = reasons
    return items


def _versions(g: HostGroup) -> list[str]:
    out: list[str] = []
    for m in g.members:
        for v in detected_versions(m):
            if v not in out:
                out.append(v)
    return out


def render_markdown(groups: list[HostGroup], notes: list[str], *, started: datetime, finished: datetime,
                    ports: list[int], versions_file: str, patched_display: list[str]) -> str:
    rows = sorted(groups, key=lambda g: (STATUS_RANK[g.status], g.name))
    lines = [
        "# PHP Patch Status",
        "",
        f"Scan: {started:%Y-%m-%d %H:%M:%S} – {finished:%H:%M:%S} · Ports: {', '.join(map(str, ports))} · "
        f"Patched versions ({md_escape(versions_file)}): {', '.join(patched_display)}",
        "",
        "| Host / Group | IPs | Cert matches IP | Cert names | Open ports | PHP version(s) | Evidence | Status |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for g in rows:
        status = g.status + (" ⚠ inconsistent" if is_inconsistent(g) else "")
        lines.append("| " + " | ".join([
            md_escape(g.name),
            _cell([m.ip for m in g.members]),
            _cell([CERT_MATCH_LABEL[m.cert_match] for m in g.members]),
            _cell(_cert_names(g), MAX_NAMES),
            _cell(_open_ports(g)),
            _cell(_versions(g)),
            _cell(_evidence(g), MAX_EVIDENCE),
            f"**{status}**",
        ]) + " |")

    host_counts = Counter(g.status for g in groups)
    ip_counts = Counter(m.status for g in groups for m in g.members)
    lines += ["", "## Summary", "", "| Status | Hosts / groups | IPs |", "|---|---|---|"]
    for st in sorted(STATUS_RANK, key=STATUS_RANK.__getitem__):
        lines.append(f"| {st} | {host_counts.get(st, 0)} | {ip_counts.get(st, 0)} |")
    lines.append(f"| **total** | {len(groups)} | {sum(ip_counts.values())} |")

    grouped = [g for g in groups if len(g.members) > 1]
    if grouped:
        lines += ["", "## Grouped IPv4/IPv6 hosts", ""]
        lines += [f"- **{md_escape(g.name)}**: {md_escape(g.reason)}" for g in sorted(grouped, key=lambda g: g.name)]
    if notes:
        lines += ["", "## Possible same host (not grouped)", ""]
        lines += [f"- {md_escape(n)}" for n in notes]
    inconsistent = [g for g in groups if is_inconsistent(g)]
    if inconsistent:
        lines += ["", "## Inconsistent groups", ""]
        for g in inconsistent:
            detail = "; ".join(f"{m.ip}: {m.status} ({', '.join(detected_versions(m)) or 'no version'})"
                               for m in g.members)
            lines.append(f"- **{md_escape(g.name)}**: {md_escape(detail)}")
    return "\n".join(lines) + "\n"


def render_json(groups: list[HostGroup], notes: list[str], **meta) -> str:
    data = {
        "meta": {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in meta.items()},
        "groups": [dict(asdict(g), inconsistent=is_inconsistent(g)) for g in groups],
        "notes": notes,
    }
    return json.dumps(data, indent=2, default=str)
