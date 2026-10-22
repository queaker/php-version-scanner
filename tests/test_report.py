from datetime import datetime

from conftest import make_cert, make_ip

from phpscan.models import HostGroup
from phpscan.report import md_escape, render_json, render_markdown
from phpscan.status import apply_group_status, apply_ip_status

META = dict(started=datetime(2026, 10, 22, 10, 0), finished=datetime(2026, 10, 22, 10, 5),
            ports=[80, 443, 8080, 8443], versions_file="php-versions.txt", patched_display=["8.5.12"])


def _groups(patched):
    cert = make_cert(dns=["web01.example.com"], ips=["192.0.2.10"])
    a = make_ip("192.0.2.10", cert=cert, versions=["8.2.35"])
    a.cert_match = "san"
    b = make_ip("2001:db8::10", cert=cert, versions=["8.2.35"])
    b.cert_match = "dns"
    c = make_ip("192.0.2.20", versions=["7.4.33-1+deb11u5"])
    d = make_ip("192.0.2.30", ports_state={80: "timeout"})
    groups = [HostGroup("web01.example.com", [a, b], reason="same cert"), HostGroup("192.0.2.20", [c]),
              HostGroup("192.0.2.30", [d])]
    for g in groups:
        for m in g.members:
            apply_ip_status(m, patched)
        apply_group_status(g)
    return groups


def test_markdown_table(patched):
    md = render_markdown(_groups(patched), ["note | with pipe"], **META)
    rows = [l for l in md.splitlines() if l.startswith("| ") and "Host / Group" not in l and "Status |" not in l]
    table = [r for r in rows if r.count("|") >= 9 and not r.startswith("| Status")]
    # Sorted: unpatched, patched, offline
    assert table[0].startswith("| 192.0.2.20 ") and table[0].endswith("**unpatched** |")
    assert table[1].startswith("| web01.example.com | 192.0.2.10<br>2001:db8::10 | ✅ IP in SAN<br>✅ via DNS")
    assert "**patched**" in table[1]
    assert "**offline**" in table[2]
    assert "note \\| with pipe" in md
    assert "| unpatched | 1 | 1 |" in md and "| **total** | 3 | 4 |" in md


def test_md_escape():
    assert md_escape("a|b\nc") == "a\\|b c"


def test_json(patched):
    import json
    data = json.loads(render_json(_groups(patched), [], **META))
    assert data["groups"][0]["members"][0]["ip"] == "192.0.2.10"
    assert data["meta"]["started"].startswith("2026-10-22")
