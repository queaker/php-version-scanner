from conftest import make_ip

from phpscan.models import HostGroup
from phpscan.status import apply_group_status, apply_ip_status, ip_status, is_inconsistent


def test_ip_statuses(patched):
    assert ip_status(make_ip("192.0.2.1", versions=["8.2.35"]), patched)[0] == "patched"
    assert ip_status(make_ip("192.0.2.1", versions=["8.2.3"]), patched)[0] == "unpatched"
    assert ip_status(make_ip("192.0.2.1", versions=["8.2.35", "7.4.33"]), patched)[0] == "unpatched"
    assert ip_status(make_ip("192.0.2.1", markers=["cookie PHPSESSID"]), patched) == \
        ("unknown", "PHP detected, version hidden")
    assert ip_status(make_ip("192.0.2.1"), patched) == ("unknown", "no PHP markers found")
    assert ip_status(make_ip("192.0.2.1", scheme=None), patched)[0] == "unknown"


def test_offline(patched):
    st, reason = ip_status(make_ip("192.0.2.1", ports_state={80: "closed", 443: "closed"}), patched)
    assert st == "offline" and "refused" in reason
    st, reason = ip_status(make_ip("192.0.2.1", ports_state={80: "timeout", 443: "closed"}), patched)
    assert st == "offline" and "timeout" in reason


def _group(patched, *members):
    for m in members:
        apply_ip_status(m, patched)
    g = HostGroup(name="x", members=list(members))
    apply_group_status(g)
    return g


def test_group_worst_wins_offline_ignored(patched):
    g = _group(patched, make_ip("192.0.2.1", versions=["8.2.35"]),
               make_ip("2001:db8::1", ports_state={443: "timeout"}))
    assert g.status == "patched" and not is_inconsistent(g)

    g = _group(patched, make_ip("192.0.2.1", versions=["8.2.35"]), make_ip("2001:db8::1", versions=["8.1.0"]))
    assert g.status == "unpatched" and is_inconsistent(g)

    g = _group(patched, make_ip("192.0.2.1", ports_state={443: "timeout"}),
               make_ip("2001:db8::1", ports_state={443: "closed"}))
    assert g.status == "offline"
